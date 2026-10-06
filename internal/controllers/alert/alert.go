// Package alert is the controller of Alert managed resources. The external resource of an Alert is
// its HyperDX alert and the single-tile dashboard the alert evaluates, both named after the
// Alert's metadata.name.
//
// Every poll interval each Alert is one pass: its spec is pushed to HyperDX, the live state
// (OK/ALERT/PENDING) is mirrored to its status, and a pass that finds it ALERT is one firing,
// handed to the incident writer off the reconcile, unless the Alert is paused
// (krateo.io/paused: "true"). A finalizer removes the HyperDX alert and dashboard before the Alert
// is deleted.
package alert

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	prevent "github.com/krateo-platformops/plumbing/kubeutil/event"
	"github.com/krateo-platformops/plumbing/kubeutil/eventrecorder"
	prv1 "github.com/krateo-platformops/provider-runtime/apis/common/v1"
	"github.com/krateo-platformops/provider-runtime/pkg/logging"
	"github.com/krateo-platformops/provider-runtime/pkg/meta"
	"github.com/krateo-platformops/provider-runtime/pkg/ratelimiter"
	"github.com/krateo-platformops/provider-runtime/pkg/reconciler"
	"github.com/krateo-platformops/provider-runtime/pkg/resource"

	"github.com/krateo-platformops/alert-provider/apis/alert/v1alpha1"
	"github.com/krateo-platformops/alert-provider/internal/compare"
	"github.com/krateo-platformops/alert-provider/internal/controllers/common/option"
	"github.com/krateo-platformops/alert-provider/internal/httpx"
	"github.com/krateo-platformops/alert-provider/internal/hyperdx"
	"github.com/krateo-platformops/alert-provider/internal/incident"
	"github.com/krateo-platformops/alert-provider/internal/pyfmt"
)

// Finalizer guards each Alert so its HyperDX alert and dashboard are removed before it is deleted.
const Finalizer = "observability.krateo.io/hyperdx-cleanup"

var errNotAlert = errors.New("managed resource is not an Alert")

// Options configure the Alert controller.
type Options struct {
	Controller option.ControllerOptions
	// HyperDX is the HyperDX API the alerts are pushed to.
	HyperDX func() *hyperdx.Client
	// Webhook names the shared generic webhook, the HyperDX alerts' channel, and where it posts.
	WebhookName, WebhookTarget string
	// Writer writes the incidents of the firings, under FiringContext: a firing outlives its
	// reconcile, since a new incident's RCA takes minutes.
	Writer        *incident.Writer
	FiringContext context.Context
}

// Setup adds the Alert controller to the manager.
//
// One Alert reconciles at a time: a recreated webhook resets every Alert, and a HyperDX alert two
// Alerts claim is released by one of them, each of which assumes no other Alert is mid-push.
func Setup(mgr ctrl.Manager, o Options) error {
	name := reconciler.ControllerName(v1alpha1.AlertGroupKind)
	log := o.Controller.Logger.WithValues("controller", name)

	recorder, err := eventrecorder.Create(context.Background(), mgr.GetConfig(), name, nil)
	if err != nil {
		return fmt.Errorf("failed to create event recorder: %w", err)
	}

	f := &firings{interval: o.Controller.PollInterval, fire: o.Writer.Fire, ctx: o.FiringContext,
		hdx: o.HyperDX, log: log, last: map[types.UID]time.Time{}, run: func(f func()) { go f() }}
	c := &connector{
		kube:    mgr.GetClient(),
		hdx:     o.HyperDX,
		webhook: &webhook{kube: mgr.GetClient(), name: o.WebhookName, target: o.WebhookTarget, ttl: o.Controller.PollInterval, log: log},
		firings: f,
		log:     log,
	}
	r := reconciler.NewReconciler(mgr,
		resource.ManagedKind(v1alpha1.AlertGroupVersionKind),
		reconciler.WithExternalConnecter(c),
		reconciler.WithFinalizer(resource.NewAPIFinalizer(mgr.GetClient(), Finalizer)),
		reconciler.WithPollInterval(o.Controller.PollInterval),
		reconciler.WithLogger(log),
		reconciler.WithRecorder(prevent.NewAPIRecorder(recorder)),
		// No warning Events: the seeded reconcile-error alert counts CannotObserveExternalResource
		// Events cluster-wide, so a HyperDX outage would make this controller fire on itself. The
		// error is in the Synced condition, status.phase and the logs.
		reconciler.WithThrottledRecorder(prevent.NewNopRecorder()),
		reconciler.WithTimeout(o.Controller.Timeout),
	)

	opts := o.Controller.ForControllerRuntime()
	opts.MaxConcurrentReconciles = 1
	return ctrl.NewControllerManagedBy(mgr).
		Named(name).
		WithOptions(opts).
		For(&v1alpha1.Alert{}, builder.WithPredicates(changed)).
		Complete(ratelimiter.New(name, r, o.Controller.GlobalRateLimiter))
}

// changed lets through what a person changes: the spec, the annotations and the deletion. The
// reconcile's own status writes change lastSyncedAt every pass and would otherwise requeue it at
// once, forever.
var changed = predicate.Funcs{
	UpdateFunc: func(e event.UpdateEvent) bool {
		o, n := e.ObjectOld, e.ObjectNew
		if o.GetGeneration() != n.GetGeneration() || !o.GetDeletionTimestamp().Equal(n.GetDeletionTimestamp()) {
			return true
		}
		oa, na := o.(*v1alpha1.Alert), n.(*v1alpha1.Alert)
		if len(oa.Annotations) != len(na.Annotations) {
			return true
		}
		for k, v := range oa.Annotations {
			if na.Annotations[k] != v {
				return true
			}
		}
		return false
	},
}

type connector struct {
	kube    client.Client
	hdx     func() *hyperdx.Client
	webhook *webhook
	firings *firings
	log     logging.Logger
}

// Connect opens a pass: a new HyperDX client, so the pass reads the dashboards afresh, and the
// HyperDX source and shared webhook every alert uses.
func (c *connector) Connect(ctx context.Context, mg resource.Managed) (reconciler.ExternalClient, error) {
	a, ok := mg.(*v1alpha1.Alert)
	if !ok {
		return nil, errNotAlert
	}
	e := &external{kube: c.kube, hdx: c.hdx(), firings: c.firings, log: c.log.WithValues("alert", a.Namespace+"/"+a.Name)}
	if meta.WasDeleted(a) {
		return e, nil // removing the HyperDX objects needs neither
	}
	source, webhookID, err := c.webhook.ensure(ctx, e.hdx, a)
	if err != nil {
		return nil, err
	}
	e.source, e.webhookID = source, webhookID
	return e, nil
}

// plan is what Observe found for Update to act on. A new external serves each reconcile.
type plan struct {
	// invalid is why the threshold is refused; nothing is pushed.
	invalid string
	// deleteShared is a HyperDX alert several Alerts claimed and none is named after: it is
	// deleted, so it stops evaluating one Alert's `where` for another.
	deleteShared string
	// create means no HyperDX alert is this Alert's yet.
	create bool
	taken  map[string]bool // tiles other alerts evaluate, never reused for a new one
	// alertID, dashboardID and tileID are the live alert's, which name the tile it evaluates.
	alertID, dashboardID, tileID string
	where                        bool     // the tile's where differs from spec.where
	drift                        []string // the alert fields that differ from the spec
}

func (p plan) String() string {
	var parts []string
	if p.deleteShared != "" {
		parts = append(parts, "delete shared HyperDX alert "+p.deleteShared)
	}
	if p.create {
		parts = append(parts, "create the HyperDX dashboard and alert")
	}
	if p.where {
		parts = append(parts, "push where")
	}
	if len(p.drift) > 0 {
		parts = append(parts, "push "+strings.Join(p.drift, ", "))
	}
	return strings.Join(parts, "; ")
}

type external struct {
	kube      client.Client
	hdx       *hyperdx.Client
	firings   *firings
	log       logging.Logger
	source    map[string]any
	webhookID string
	plan      plan
}

func fields(spec v1alpha1.AlertSpec) hyperdx.AlertFields {
	f := hyperdx.AlertFields{Interval: spec.Interval, Threshold: threshold(spec),
		ThresholdType: spec.ThresholdType, Message: spec.Message}
	if f.Interval == "" {
		f.Interval = "5m"
	}
	if f.ThresholdType == "" {
		f.ThresholdType = "above"
	}
	return f
}

func now() string { return pyfmt.Isoformat(time.Now()) }

// failed records a failed pass. A HyperDX HTTP error leaves the status as it was; any other error
// is phase Error.
func failed(a *v1alpha1.Alert, err error) error {
	if httpx.Code(err) == 0 {
		a.Status.Phase, a.Status.Error, a.Status.LastSyncedAt = v1alpha1.PhaseError, pyfmt.Cut(err.Error(), 300), now()
	}
	return err
}

// specDrift records a push that failed: the live alert does not match the Alert. The state is
// still mirrored, so a firing alert stays visible.
func specDrift(a *v1alpha1.Alert, log logging.Logger, err error) error {
	a.Status.Phase, a.Status.Error, a.Status.LastSyncedAt = v1alpha1.PhaseSpecDrift, pyfmt.Cut(err.Error(), 300), now()
	log.Info(fmt.Sprintf("[reconciler] Alert %s: spec push failed, phase=SpecDrift (%s)", a.Name, err))
	return err
}

// Observe finds the Alert's HyperDX alert, mirrors its state to the status and plans the push.
// The HyperDX alert is found by the status id, else by its name, so a status that lost its id, or
// a create cut short, adopts its own alert instead of creating a second one. Observe therefore
// never reports it missing: that would arm provider-runtime's create handshake, under which an
// interrupted create blocks the Alert until a person clears an annotation. A missing alert is
// created by Update.
//
// A pass that finds the alert ALERT fires it, here, since it is the one step every pass runs.
func (e *external) Observe(ctx context.Context, mg resource.Managed) (reconciler.ExternalObservation, error) {
	a, ok := mg.(*v1alpha1.Alert)
	if !ok {
		return reconciler.ExternalObservation{}, errNotAlert
	}
	if meta.WasDeleted(a) {
		return reconciler.ExternalObservation{ResourceExists: a.Status.HyperdxAlertID != "" || a.Status.HyperdxDashboardID != ""}, nil
	}

	// A tautological threshold is refused, on an existing alert too: the comparison has one
	// possible outcome, so the alert cannot signal anything. The existing alert is not deleted:
	// refusing to keep pushing stops the damage.
	// It is written by Update: a status Observe sets is lost when provider-runtime then adds the
	// finalizer to a new Alert, which reloads the object.
	if why := Tautology(threshold(a.Spec), a.Spec.ThresholdType); why != "" {
		if a.Status.Phase == v1alpha1.PhaseInvalid && a.Status.Error == why {
			a.Status.LastSyncedAt = now()
			return reconciler.ExternalObservation{ResourceExists: true, ResourceUpToDate: true}, nil
		}
		e.plan.invalid = why
		return reconciler.ExternalObservation{ResourceExists: true, ResourceUpToDate: false, Diff: "refused: " + why}, nil
	}

	live, err := e.hdx.ListAlerts(ctx)
	if err != nil {
		return reconciler.ExternalObservation{}, failed(a, err)
	}
	byID := map[string]map[string]any{}
	for _, l := range live {
		byID[hyperdx.ID(l)] = l
	}
	if err := e.release(ctx, a, byID); err != nil {
		return reconciler.ExternalObservation{}, err
	}

	var alert map[string]any
	if id := a.Status.HyperdxAlertID; id != "" {
		alert = byID[id]
	}
	if alert == nil {
		for _, l := range live {
			if l["name"] == a.Name && hyperdx.ID(l) != e.plan.deleteShared {
				alert = l
				break
			}
		}
	}
	if alert == nil {
		e.plan.create = true
		e.plan.taken = map[string]bool{}
		for _, l := range live {
			if t, ok := l["tileId"].(string); ok && hyperdx.ID(l) != e.plan.deleteShared {
				e.plan.taken[t] = true
			}
		}
		return reconciler.ExternalObservation{ResourceExists: true, ResourceUpToDate: false, Diff: e.plan.String()}, nil
	}

	st := "OK"
	if v, ok := alert["state"]; ok {
		st = ""
		if v != nil {
			st = pyfmt.Str(v)
		}
	}
	// Both ids come from the live alert: it is authoritative about which tile it reads, and a
	// status dashboard id paired with the live tile id describes a tile that is not on that
	// dashboard. The status is the fallback for an alert that carries no dashboard.
	e.plan.alertID = hyperdx.ID(alert)
	e.plan.dashboardID, _ = alert["dashboardId"].(string)
	e.plan.tileID, _ = alert["tileId"].(string)
	if e.plan.dashboardID == "" {
		e.plan.dashboardID = a.Status.HyperdxDashboardID
	}
	a.Status.OkSince = OkSince(a.Status, st, now())
	a.Status.HyperdxAlertID = e.plan.alertID
	if d, _ := alert["dashboardId"].(string); d != "" {
		a.Status.HyperdxDashboardID = d
	}
	a.Status.State, a.Status.LastSyncedAt = st, now()
	a.SetConditions(prv1.Available())

	// `where` first: it decides what is counted, so pushing a threshold against a stale filter
	// would briefly evaluate the new bound over the old query.
	if e.plan.dashboardID != "" {
		liveWhere, found, err := e.hdx.TileWhere(ctx, e.plan.dashboardID)
		if err != nil {
			e.firings.start(a, e.source, st)
			return reconciler.ExternalObservation{}, specDrift(a, e.log, err)
		}
		e.plan.where = found && liveWhere != a.Spec.Where
	}
	e.plan.drift = hyperdx.AlertDrift(alert, a.Name, fields(a.Spec))

	e.firings.start(a, e.source, st)
	if e.plan.deleteShared != "" || e.plan.where || len(e.plan.drift) > 0 {
		return reconciler.ExternalObservation{ResourceExists: true, ResourceUpToDate: false, Diff: e.plan.String()}, nil
	}
	// An empty error clears a SpecDrift's message once the spec matches.
	a.Status.Phase, a.Status.Error = v1alpha1.PhaseSynced, ""
	return reconciler.ExternalObservation{ResourceExists: true, ResourceUpToDate: true}, nil
}

// release leaves a HyperDX alert several Alerts claim to the Alert it is named after, if any. Any
// other claimant drops the id and creates its own alert in this pass; a shared alert named after
// none of them is deleted (by Update), so it stops evaluating one Alert's `where` for another.
func (e *external) release(ctx context.Context, a *v1alpha1.Alert, byID map[string]map[string]any) error {
	id := a.Status.HyperdxAlertID
	if id == "" {
		return nil
	}
	var all v1alpha1.AlertList
	if err := e.kube.List(ctx, &all, client.InNamespace(a.Namespace)); err != nil {
		return err
	}
	claimants := []string{a.Name}
	for i := range all.Items {
		o := &all.Items[i]
		if o.UID != a.UID && !meta.WasDeleted(o) && o.Status.HyperdxAlertID == id {
			claimants = append(claimants, o.Name)
		}
	}
	if len(claimants) < 2 {
		return nil
	}
	alertName, _ := byID[id]["name"].(string)
	owner := ""
	for _, n := range claimants {
		if n == alertName {
			owner = n
			break
		}
	}
	if owner == a.Name {
		return nil
	}
	if owner == "" && byID[id] != nil {
		e.plan.deleteShared = id
		delete(byID, id)
	}
	a.Status.HyperdxAlertID, a.Status.Phase = "", v1alpha1.PhasePending
	e.log.Info(fmt.Sprintf("[reconciler] Alert %s: released shared hyperdx %s", a.Name, id))
	return nil
}

// Create is never called: Observe never reports the HyperDX alert missing (see Observe).
func (e *external) Create(ctx context.Context, mg resource.Managed) error {
	return nil
}

// Update deletes a shared alert, creates the dashboard and alert or pushes the spec onto them.
func (e *external) Update(ctx context.Context, mg resource.Managed) error {
	a, ok := mg.(*v1alpha1.Alert)
	if !ok {
		return errNotAlert
	}
	if why := e.plan.invalid; why != "" {
		a.Status.Phase, a.Status.Error, a.Status.LastSyncedAt = v1alpha1.PhaseInvalid, why, now()
		e.log.Info(fmt.Sprintf("[reconciler] Alert %s refused: %s", a.Name, why))
		return nil
	}
	if id := e.plan.deleteShared; id != "" {
		if err := e.hdx.DeleteAlert(ctx, id); err != nil {
			return err
		}
	}
	if e.plan.create {
		return e.create(ctx, a)
	}
	return e.push(ctx, a)
}

// create makes the dashboard tile, then an alert on it named after the Alert.
func (e *external) create(ctx context.Context, a *v1alpha1.Alert) error {
	dash, tile, err := e.hdx.EnsureDashboardTile(ctx, "krateo-alert-"+a.Name, e.source, a.Spec.Where, e.plan.taken)
	if err != nil {
		return failed(a, err)
	}
	res, err := e.hdx.EnsureAlert(ctx, a.Name, dash, tile, e.webhookID, fields(a.Spec))
	if err != nil {
		return failed(a, err)
	}
	st := pyfmt.Str(res["state"])
	a.Status.HyperdxAlertID, a.Status.HyperdxDashboardID = pyfmt.Str(res["id"]), dash
	a.Status.OkSince = OkSince(a.Status, st, now())
	a.Status.State, a.Status.Phase, a.Status.LastSyncedAt = st, v1alpha1.PhaseSynced, now()
	a.SetConditions(prv1.Available())
	e.log.Info(fmt.Sprintf("[reconciler] synced Alert %s -> hyperdx %s (%s)", a.Name, a.Status.HyperdxAlertID, st))
	e.firings.start(a, e.source, st)
	return nil
}

// push puts the spec onto the live alert where they disagree. The spec spans two objects:
// threshold, thresholdType, interval and message live on the alert, `where` on the dashboard tile.
// The alert's name is pushed too: it ties the HyperDX alert to its Alert.
func (e *external) push(ctx context.Context, a *v1alpha1.Alert) error {
	tile := e.plan.tileID
	if tile == "" {
		tile = "count"
	}
	var changed []string
	if e.plan.where {
		if err := e.hdx.UpdateDashboardTile(ctx, e.plan.dashboardID, "krateo-alert-"+a.Name, e.source, a.Spec.Where, tile); err != nil {
			return specDrift(a, e.log, err)
		}
		changed = append(changed, "where")
	}
	if len(e.plan.drift) > 0 {
		if _, err := e.hdx.UpdateAlert(ctx, e.plan.alertID, a.Name, e.plan.dashboardID, tile, e.webhookID, fields(a.Spec)); err != nil {
			return specDrift(a, e.log, err)
		}
		changed = append(changed, e.plan.drift...)
	}
	a.Status.Phase, a.Status.Error, a.Status.LastSyncedAt = v1alpha1.PhaseSynced, "", now()
	if len(changed) > 0 {
		e.log.Info(fmt.Sprintf("[reconciler] Alert %s: pushed %s to hyperdx %s", a.Name, strings.Join(changed, ", "), e.plan.alertID))
	}
	return nil
}

// Delete removes the HyperDX alert and dashboard, best-effort: a failure still lets the Alert go,
// so a delete is never wedged on HyperDX.
func (e *external) Delete(ctx context.Context, mg resource.Managed) error {
	a, ok := mg.(*v1alpha1.Alert)
	if !ok {
		return errNotAlert
	}
	if id := a.Status.HyperdxAlertID; id != "" {
		_ = e.hdx.DeleteAlert(ctx, id)
	}
	if id := a.Status.HyperdxDashboardID; id != "" {
		_ = e.hdx.DeleteDashboard(ctx, id)
	}
	a.Status.HyperdxAlertID, a.Status.HyperdxDashboardID = "", ""
	e.firings.forget(a.UID)
	e.log.Info(fmt.Sprintf("[reconciler] finalized Alert %s (removed HyperDX alert+dashboard)", a.Name))
	return nil
}

// firings hands an Alert's firings to the incident writer: one per poll interval while the
// HyperDX alert is ALERT. Reconciles the poll did not schedule (a spec edit, an error's retry)
// fire nothing, so an alert fires once a pass as it always has.
type firings struct {
	interval time.Duration
	fire     func(context.Context, incident.Alert, incident.Records)
	ctx      context.Context
	hdx      func() *hyperdx.Client
	log      logging.Logger
	// run runs a firing; off the reconcile, in its own goroutine.
	run func(func())

	mu   sync.Mutex
	last map[types.UID]time.Time
}

// fire starts the incident writer on a firing, off the reconcile: a comparison takes seconds, a
// new incident's RCA minutes. Its records are the alert's `where` rows in source, one line per
// distinct record.
func (f *firings) start(a *v1alpha1.Alert, source map[string]any, state string) {
	if state != "ALERT" {
		return
	}
	f.mu.Lock()
	if t, ok := f.last[a.UID]; ok && time.Since(t) < f.interval {
		f.mu.Unlock()
		return
	}
	f.last[a.UID] = time.Now()
	f.mu.Unlock()
	if a.Paused() {
		f.log.Info(fmt.Sprintf("[reconciler] Alert %s is paused; firing skipped", a.Name))
		return
	}
	alert := incident.Alert{Namespace: a.Namespace, Alert: compare.Alert{
		Name: a.Name, DisplayName: a.Spec.DisplayName, Where: a.Spec.Where, Interval: a.Spec.Interval,
		Threshold: pyfmt.NumberStr(threshold(a.Spec)), ThresholdType: a.Spec.ThresholdType, Message: a.Spec.Message,
	}}
	hdx, sourceID := f.hdx(), hyperdx.ID(source)
	records := func(ctx context.Context, where string, seconds int) ([]compare.Row, error) {
		return hdx.RecordCounts(ctx, sourceID, where, seconds, compare.RowGroup)
	}
	f.run(func() { f.fire(f.ctx, alert, records) })
}

func (f *firings) forget(uid types.UID) {
	f.mu.Lock()
	delete(f.last, uid)
	f.mu.Unlock()
}
