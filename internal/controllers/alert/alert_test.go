package alert

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/krateo-platformops/provider-runtime/pkg/logging"
	"github.com/krateo-platformops/provider-runtime/pkg/meta"
	"github.com/krateo-platformops/provider-runtime/pkg/resource"

	"github.com/krateo-platformops/alert-provider/apis"
	"github.com/krateo-platformops/alert-provider/apis/alert/v1alpha1"
	"github.com/krateo-platformops/alert-provider/internal/compare"
	"github.com/krateo-platformops/alert-provider/internal/golden"
	"github.com/krateo-platformops/alert-provider/internal/hyperdx"
	"github.com/krateo-platformops/alert-provider/internal/hyperdx/hyperdxtest"
	"github.com/krateo-platformops/alert-provider/internal/incident"
)

const (
	ns      = "krateo-system"
	display = "Krateo — composition reconcile errors"
	k       = "krateo-composition-reconcile-error"
	s       = "sre-krateo-composition-reconcile-error"
)

var ctx = context.Background()

func alertCR(name, where string, status v1alpha1.AlertStatus) *v1alpha1.Alert {
	return &v1alpha1.Alert{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, UID: types.UID("uid-" + name)},
		Spec: v1alpha1.AlertSpec{DisplayName: display, Where: where, Interval: "15m", Threshold: "2",
			ThresholdType: "above", Message: "m"},
		Status: status,
	}
}

// harness runs the Alert controller's passes the way provider-runtime's reconciler drives its
// ExternalClient, over a fake apiserver and a fake HyperDX.
type harness struct {
	t     *testing.T
	kube  client.Client
	api   *hyperdxtest.API
	conn  *connector
	fired []string
}

func newHarness(t *testing.T, alerts ...*v1alpha1.Alert) *harness {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := apis.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	b := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(&v1alpha1.Alert{})
	for _, a := range alerts {
		b = b.WithObjects(a)
	}
	kube := b.Build()
	api := hyperdxtest.New()
	t.Cleanup(api.Close)
	h := &harness{t: t, kube: kube, api: api}
	hdx := func() *hyperdx.Client { return hyperdx.New(api.URL, "k") }
	log := logging.NewNopLogger()
	h.conn = &connector{
		kube:    kube,
		hdx:     hdx,
		webhook: &webhook{kube: kube, name: "krateo-alert-provider", target: "http://x/webhook", log: log},
		firings: &firings{hdx: hdx, log: log, ctx: ctx, last: map[types.UID]time.Time{},
			run:  func(f func()) { f() },
			fire: func(_ context.Context, a incident.Alert, _ incident.Records) { h.fired = append(h.fired, a.Name) }},
		log: log,
	}
	return h
}

// reconcile is one reconcile of the Alert, in provider-runtime's order: connect, observe, then
// delete or add the finalizer and update, and the status write that closes every reconcile.
func (h *harness) reconcile(name string) error {
	a := &v1alpha1.Alert{}
	if err := h.kube.Get(ctx, types.NamespacedName{Namespace: ns, Name: name}, a); err != nil {
		return err
	}
	ext, err := h.conn.Connect(ctx, a)
	if err != nil {
		return err
	}
	persist := func(err error) error {
		if uerr := h.kube.Status().Update(ctx, a); uerr != nil {
			h.t.Fatalf("status update: %v", uerr)
		}
		return err
	}
	obs, err := ext.Observe(ctx, a)
	if err != nil {
		return persist(err)
	}
	fin := resource.NewAPIFinalizer(h.kube, Finalizer)
	if meta.WasDeleted(a) {
		if obs.ResourceExists {
			return persist(ext.Delete(ctx, a))
		}
		return fin.RemoveFinalizer(ctx, a)
	}
	if err := fin.AddFinalizer(ctx, a); err != nil {
		return err
	}
	if !obs.ResourceExists {
		h.t.Fatal("Observe reported the HyperDX alert missing")
	}
	if !obs.ResourceUpToDate {
		return persist(ext.Update(ctx, a))
	}
	return persist(nil)
}

// pass reconciles every Alert once, in name order.
func (h *harness) pass(n int) {
	for range n {
		var l v1alpha1.AlertList
		if err := h.kube.List(ctx, &l); err != nil {
			h.t.Fatal(err)
		}
		sort.Slice(l.Items, func(i, j int) bool { return l.Items[i].Name < l.Items[j].Name })
		for _, a := range l.Items {
			_ = h.reconcile(a.Name)
		}
	}
}

func (h *harness) get(name string) *v1alpha1.Alert {
	a := &v1alpha1.Alert{}
	if err := h.kube.Get(ctx, types.NamespacedName{Namespace: ns, Name: name}, a); err != nil {
		h.t.Fatal(err)
	}
	return a
}

func (h *harness) status(name string) v1alpha1.AlertStatus { return h.get(name).Status }

func (h *harness) edit(name string, fn func(*v1alpha1.Alert)) {
	a := h.get(name)
	fn(a)
	if err := h.kube.Update(ctx, a); err != nil {
		h.t.Fatal(err)
	}
}

func (h *harness) editStatus(name string, fn func(*v1alpha1.AlertStatus)) {
	a := h.get(name)
	fn(&a.Status)
	if err := h.kube.Status().Update(ctx, a); err != nil {
		h.t.Fatal(err)
	}
}

func (h *harness) byName() map[string]map[string]any {
	out := map[string]map[string]any{}
	for _, a := range h.api.All("alerts") {
		out[a["name"].(string)] = a
	}
	return out
}

// seedAlert is a pre-existing alert on the reconcile's own webhook, as on a running cluster.
func (h *harness) seedAlert(dashboard, alertName, where string) string {
	c := hyperdx.New(h.api.URL, "k")
	wid, _, _ := c.EnsureWebhook(ctx, "krateo-alert-provider", "http://x/webhook", "")
	dash, tile, _ := c.EnsureDashboardTile(ctx, dashboard, map[string]any{"id": "src-1"}, where, nil)
	a, _ := c.EnsureAlert(ctx, alertName, dash, tile, wid, hyperdx.AlertFields{Interval: "15m", Threshold: json.Number("2"),
		ThresholdType: "above", Message: "m"})
	return a["id"].(string)
}

func nonWebhookWrites(api *hyperdxtest.API) []hyperdxtest.Write {
	out := []hyperdxtest.Write{}
	for _, w := range api.Writes() {
		if w.Kind != "webhooks" {
			out = append(out, w)
		}
	}
	return out
}

func eq(t *testing.T, what string, got, want any) {
	t.Helper()
	if d := golden.Diff(want, got); d != "" {
		t.Errorf("%s (-want +got):\n%s", what, d)
	}
}

// --- one Alert is one HyperDX alert ---

func TestTwoAlertsWithOneDisplayNameGetTwoHyperDXAlerts(t *testing.T) {
	h := newHarness(t, alertCR(k, "where-k", v1alpha1.AlertStatus{}), alertCR(s, "where-s", v1alpha1.AlertStatus{}))
	h.pass(2)
	by := h.byName()
	eq(t, "names", len(by), 2)
	eq(t, "k id", h.status(k).HyperdxAlertID, by[k]["id"])
	eq(t, "s id", h.status(s).HyperdxAlertID, by[s]["id"])
	if by[k]["tileId"] == by[s]["tileId"] {
		t.Error("one tile for two alerts")
	}
	eq(t, "k where", h.api.WhereOf(by[k]), "where-k")
	eq(t, "s where", h.api.WhereOf(by[s]), "where-s")
}

func TestThePairIsStableNoWriteAfterItConverges(t *testing.T) {
	h := newHarness(t, alertCR(k, "where-k", v1alpha1.AlertStatus{}), alertCR(s, "where-s", v1alpha1.AlertStatus{}))
	h.pass(2)
	ids := len(h.api.All("alerts"))
	h.api.ClearWrites()
	h.pass(3)
	eq(t, "writes", nonWebhookWrites(h.api), []hyperdxtest.Write{})
	eq(t, "alerts", len(h.api.All("alerts")), ids)
	eq(t, "phases", []string{h.status(k).Phase, h.status(s).Phase}, []string{"Synced", "Synced"})
	eq(t, "ready", string(h.get(k).GetCondition("Ready").Status), "True")
}

func TestASharedLegacyAlertIsReleasedAndEachAlertGetsItsOwn(t *testing.T) {
	h := newHarness(t)
	legacy := h.seedAlert("krateo-alert-"+s, display, "where-s")
	for _, a := range []*v1alpha1.Alert{alertCR(k, "where-k", v1alpha1.AlertStatus{HyperdxAlertID: legacy}),
		alertCR(s, "where-s", v1alpha1.AlertStatus{HyperdxAlertID: legacy})} {
		if err := h.kube.Create(ctx, a); err != nil {
			t.Fatal(err)
		}
		h.editStatus(a.Name, func(st *v1alpha1.AlertStatus) { st.HyperdxAlertID = legacy })
	}
	h.pass(2)
	if h.api.Get("alerts", legacy) != nil {
		t.Error("the shared legacy alert was kept")
	}
	by := h.byName()
	eq(t, "count", len(by), 2)
	eq(t, "k where", h.api.WhereOf(by[k]), "where-k")
	eq(t, "s where", h.api.WhereOf(by[s]), "where-s")
	h.api.ClearWrites()
	h.pass(2)
	eq(t, "writes", nonWebhookWrites(h.api), []hyperdxtest.Write{})
}

func TestASharedAlertAlreadyNamedAfterOneAlertStaysWithIt(t *testing.T) {
	h := newHarness(t)
	owned := h.seedAlert("krateo-alert-"+k, k, "where-k")
	for _, a := range []*v1alpha1.Alert{alertCR(k, "where-k", v1alpha1.AlertStatus{}), alertCR(s, "where-s", v1alpha1.AlertStatus{})} {
		if err := h.kube.Create(ctx, a); err != nil {
			t.Fatal(err)
		}
		h.editStatus(a.Name, func(st *v1alpha1.AlertStatus) { st.HyperdxAlertID = owned })
	}
	h.pass(2)
	eq(t, "k", h.status(k).HyperdxAlertID, owned)
	if h.status(s).HyperdxAlertID == owned {
		t.Error("s kept k's alert")
	}
	eq(t, "s name", h.api.Get("alerts", h.status(s).HyperdxAlertID)["name"], s)
}

func TestALegacyAlertWithOneClaimantIsRenamedInPlace(t *testing.T) {
	h := newHarness(t)
	legacy := h.seedAlert("krateo-alert-"+k, display, "where-k")
	if err := h.kube.Create(ctx, alertCR(k, "where-k", v1alpha1.AlertStatus{})); err != nil {
		t.Fatal(err)
	}
	h.editStatus(k, func(st *v1alpha1.AlertStatus) { st.HyperdxAlertID = legacy })
	h.pass(1)
	all := h.api.All("alerts")
	eq(t, "ids", []any{len(all), all[0]["id"], all[0]["name"]}, []any{1, legacy, k})
}

func TestALostStatusIDAdoptsTheAlertNamedAfterTheAlert(t *testing.T) {
	h := newHarness(t, alertCR(k, "where-k", v1alpha1.AlertStatus{}))
	h.pass(1)
	first := h.status(k).HyperdxAlertID
	h.editStatus(k, func(st *v1alpha1.AlertStatus) { st.HyperdxAlertID = "" })
	h.pass(1)
	eq(t, "id", h.status(k).HyperdxAlertID, first)
	eq(t, "alerts", len(h.api.All("alerts")), 1)
}

func TestAWhereEditKeepsTheAlert(t *testing.T) {
	h := newHarness(t, alertCR(k, "where-k", v1alpha1.AlertStatus{}))
	h.pass(1)
	aid := h.status(k).HyperdxAlertID
	h.edit(k, func(a *v1alpha1.Alert) { a.Spec.Where = "where-k2" })
	h.pass(1)
	live := h.api.Get("alerts", aid)
	if live == nil {
		t.Fatal("the where edit deleted the alert")
	}
	eq(t, "where", h.api.WhereOf(live), "where-k2")
	eq(t, "id", h.status(k).HyperdxAlertID, aid)
}

func TestANewAlertNeverReusesATileAnotherAlertEvaluates(t *testing.T) {
	h := newHarness(t, alertCR(k, "where-k", v1alpha1.AlertStatus{}))
	h.pass(1)
	kAlert := h.api.Get("alerts", h.status(k).HyperdxAlertID)
	h.api.Set("dashboards", kAlert["dashboardId"].(string), map[string]any{"name": "krateo-alert-" + s})
	if err := h.kube.Create(ctx, alertCR(s, "where-s", v1alpha1.AlertStatus{})); err != nil {
		t.Fatal(err)
	}
	h.pass(1)
	sAlert := h.api.Get("alerts", h.status(s).HyperdxAlertID)
	if sAlert["tileId"] == kAlert["tileId"] {
		t.Error("the new alert reused k's tile")
	}
	eq(t, "k where", h.api.WhereOf(h.api.Get("alerts", kAlert["id"].(string))), "where-k")
}

// --- the spec push ---

func TestPushesACorrectedThreshold(t *testing.T) {
	h := newHarness(t, alertCR(k, "w", v1alpha1.AlertStatus{}))
	h.pass(1)
	id := h.status(k).HyperdxAlertID
	h.api.Set("alerts", id, map[string]any{"threshold": 0})
	h.api.ClearWrites()
	h.pass(1)
	eq(t, "writes", nonWebhookWrites(h.api), []hyperdxtest.Write{hyperdxtest.W("PUT", "alerts", id)})
	eq(t, "threshold", h.api.Get("alerts", id)["threshold"], 2)
	eq(t, "phase", h.status(k).Phase, "Synced")
}

func TestPushesAChangedWhereToTheDashboardTile(t *testing.T) {
	h := newHarness(t, alertCR(k, "old", v1alpha1.AlertStatus{}))
	h.pass(1)
	st := h.status(k)
	h.edit(k, func(a *v1alpha1.Alert) { a.Spec.Where = "new" })
	h.api.ClearWrites()
	h.pass(1)
	eq(t, "writes", nonWebhookWrites(h.api), []hyperdxtest.Write{hyperdxtest.W("PUT", "dashboards", st.HyperdxDashboardID)})
	eq(t, "where", h.api.WhereOf(h.api.Get("alerts", st.HyperdxAlertID)), "new")
}

func TestDoesNotReportSyncedWhenThePushFailed(t *testing.T) {
	h := newHarness(t, alertCR(k, "w", v1alpha1.AlertStatus{}))
	h.pass(1)
	id := h.status(k).HyperdxAlertID
	h.api.Set("alerts", id, map[string]any{"threshold": 0, "state": "ALERT"})
	h.api.Fail = func(method, kind, _ string) int {
		if method == "PUT" && kind == "alerts" {
			return 400
		}
		return 0
	}
	h.pass(1)
	st := h.status(k)
	eq(t, "phase", st.Phase, "SpecDrift")
	if !strings.HasPrefix(st.Error, "400 Client Error: Bad Request for url: ") {
		t.Errorf("error %q", st.Error)
	}
	eq(t, "state", st.State, "ALERT") // the live state is mirrored even when the push failed
	h.api.Fail = nil
	h.pass(1)
	st = h.status(k)
	eq(t, "recovered", []string{st.Phase, st.Error}, []string{"Synced", ""})
}

func TestPushesWhereToTheDashboardTheAlertActuallyReads(t *testing.T) {
	h := newHarness(t, alertCR(k, "old", v1alpha1.AlertStatus{}))
	h.pass(1)
	st := h.status(k)
	h.editStatus(k, func(s *v1alpha1.AlertStatus) { s.HyperdxDashboardID = "stale-dash" })
	h.edit(k, func(a *v1alpha1.Alert) { a.Spec.Where = "new" })
	h.api.ClearWrites()
	h.pass(1)
	eq(t, "writes", nonWebhookWrites(h.api), []hyperdxtest.Write{hyperdxtest.W("PUT", "dashboards", st.HyperdxDashboardID)})
	eq(t, "status dashboard", h.status(k).HyperdxDashboardID, st.HyperdxDashboardID)
}

func TestFallsBackToTheStatusDashboardWhenTheAlertCarriesNone(t *testing.T) {
	h := newHarness(t, alertCR(k, "old", v1alpha1.AlertStatus{}))
	h.pass(1)
	st := h.status(k)
	live := h.api.Get("alerts", st.HyperdxAlertID)
	delete(live, "dashboardId")
	h.api.Put("alerts", live)
	h.edit(k, func(a *v1alpha1.Alert) { a.Spec.Where = "new" })
	h.api.ClearWrites()
	h.pass(1)
	w := nonWebhookWrites(h.api)
	eq(t, "dashboard push", w[0], hyperdxtest.W("PUT", "dashboards", st.HyperdxDashboardID))
}

// --- refused thresholds ---

func TestRefusesATautologyAndSaysWhatToChange(t *testing.T) {
	cr := alertCR(k, "w", v1alpha1.AlertStatus{})
	cr.Spec.Threshold = "0"
	h := newHarness(t, cr)
	h.pass(1)
	st := h.status(k)
	eq(t, "phase", st.Phase, "Invalid")
	if !strings.Contains(st.Error, "Use 1") {
		t.Errorf("error %q", st.Error)
	}
	eq(t, "writes", nonWebhookWrites(h.api), []hyperdxtest.Write{}) // refused before touching HyperDX alerts
	eq(t, "fired", h.fired, []string(nil))
}

func TestRefusingDoesNotDeleteAnAlertThatAlreadyExists(t *testing.T) {
	h := newHarness(t, alertCR(k, "w", v1alpha1.AlertStatus{}))
	h.pass(1)
	id := h.status(k).HyperdxAlertID
	h.edit(k, func(a *v1alpha1.Alert) { a.Spec.Threshold = "0" })
	h.pass(1)
	if h.api.Get("alerts", id) == nil {
		t.Error("the alert was deleted")
	}
}

// --- okSince ---

func TestOkSinceRule(t *testing.T) {
	now := "2026-09-25T10:00:00+00:00"
	eq(t, "turning OK", OkSince(v1alpha1.AlertStatus{State: "ALERT"}, "OK", now), now)
	eq(t, "staying OK", OkSince(v1alpha1.AlertStatus{State: "OK", OkSince: "t0"}, "OK", now), "t0")
	eq(t, "OK, no stamp", OkSince(v1alpha1.AlertStatus{State: "OK"}, "OK", now), now)
	eq(t, "not OK", OkSince(v1alpha1.AlertStatus{State: "OK", OkSince: "t0"}, "ALERT", now), "")
	eq(t, "an old stamp", OkSince(v1alpha1.AlertStatus{State: "ALERT", OkSince: "t0"}, "OK", now), now)
}

func TestOkSinceIsWrittenWithState(t *testing.T) {
	h := newHarness(t, alertCR(k, "w", v1alpha1.AlertStatus{}))
	h.pass(1) // the create path
	first := h.status(k)
	if first.State != "OK" || first.OkSince == "" {
		t.Fatalf("create: %+v", first)
	}
	h.pass(1) // the synced path keeps it
	eq(t, "kept", h.status(k).OkSince, first.OkSince)
	h.api.Set("alerts", first.HyperdxAlertID, map[string]any{"state": "ALERT", "threshold": 0})
	h.api.Fail = func(method, kind, _ string) int {
		if method == "PUT" {
			return 500
		}
		return 0
	}
	h.pass(1) // the spec-drift path clears it
	st := h.status(k)
	eq(t, "drift", []string{st.Phase, st.State, st.OkSince}, []string{"SpecDrift", "ALERT", ""})
}

// --- firings ---

func TestOnlyTheAlertingAlertsFire(t *testing.T) {
	h := newHarness(t, alertCR(k, "where-k", v1alpha1.AlertStatus{}), alertCR(s, "where-s", v1alpha1.AlertStatus{}))
	h.pass(1) // creates both HyperDX alerts, OK
	eq(t, "fired", h.fired, []string(nil))
	h.api.Set("alerts", h.status(s).HyperdxAlertID, map[string]any{"state": "ALERT"})
	h.pass(2)
	eq(t, "fired", h.fired, []string{s, s})
	eq(t, "state", h.status(s).State, "ALERT")
}

func TestAnAlertFiresOncePerPollInterval(t *testing.T) {
	h := newHarness(t, alertCR(k, "w", v1alpha1.AlertStatus{}))
	h.conn.firings.interval = time.Hour
	h.pass(1)
	h.api.Set("alerts", h.status(k).HyperdxAlertID, map[string]any{"state": "ALERT"})
	h.pass(3) // reconciles the poll did not schedule: a spec edit, an error's retry
	eq(t, "fired", h.fired, []string{k})
	h.conn.firings.last[types.UID("uid-"+k)] = time.Now().Add(-2 * time.Hour)
	h.pass(1)
	eq(t, "next interval", h.fired, []string{k, k})
}

func (h *harness) alerting(annotations map[string]string) {
	h.pass(1)
	h.edit(k, func(a *v1alpha1.Alert) { a.Annotations = annotations })
	h.api.Set("alerts", h.status(k).HyperdxAlertID, map[string]any{"state": "ALERT"})
}

func TestAPausedAlertIsMirroredButDoesNotFire(t *testing.T) {
	h := newHarness(t, alertCR(k, "w", v1alpha1.AlertStatus{}))
	h.alerting(map[string]string{"krateo.io/paused": "true"})
	h.pass(1)
	st := h.status(k)
	eq(t, "paused", []any{h.fired, st.State, st.Phase}, []any{nil, "ALERT", "Synced"})
}

func TestAPausedAlertStillGetsItsSpecPushed(t *testing.T) {
	h := newHarness(t, alertCR(k, "w", v1alpha1.AlertStatus{}))
	h.alerting(map[string]string{"krateo.io/paused": "true"})
	h.edit(k, func(a *v1alpha1.Alert) { a.Spec.Threshold = "5" })
	h.pass(1)
	eq(t, "threshold", h.api.Get("alerts", h.status(k).HyperdxAlertID)["threshold"], 5)
	eq(t, "fired", h.fired, []string(nil))
	eq(t, "annotation kept", h.get(k).Annotations["krateo.io/paused"], "true")
}

func TestOnlyTruePauses(t *testing.T) {
	h := newHarness(t, alertCR(k, "w", v1alpha1.AlertStatus{}))
	h.alerting(map[string]string{"krateo.io/paused": "false"})
	h.pass(1)
	eq(t, "fired", h.fired, []string{k})
}

func TestResumingFiresOnTheNextPass(t *testing.T) {
	h := newHarness(t, alertCR(k, "w", v1alpha1.AlertStatus{}))
	h.alerting(map[string]string{"krateo.io/paused": "true"})
	h.pass(1)
	h.edit(k, func(a *v1alpha1.Alert) { a.Annotations = nil })
	h.pass(1)
	eq(t, "fired", h.fired, []string{k})
}

func TestAFiringCarriesTheAlertsSpec(t *testing.T) {
	h := newHarness(t, alertCR(k, "where-k", v1alpha1.AlertStatus{}))
	var got incident.Alert
	h.conn.firings.fire = func(_ context.Context, a incident.Alert, _ incident.Records) { got = a }
	h.pass(1)
	h.api.Set("alerts", h.status(k).HyperdxAlertID, map[string]any{"state": "ALERT"})
	h.pass(1)
	eq(t, "alert", got, incident.Alert{Namespace: ns, Alert: compareAlert(k, "where-k")})
}

// --- the webhook, deletion ---

func TestARecreatedWebhookRebuildsEveryAlertOnIt(t *testing.T) {
	h := newHarness(t, alertCR(k, "where-k", v1alpha1.AlertStatus{}), alertCR(s, "where-s", v1alpha1.AlertStatus{}))
	h.pass(1)
	old := []string{h.status(k).HyperdxAlertID, h.status(s).HyperdxAlertID}
	for _, w := range h.api.All("webhooks") {
		h.api.Delete("webhooks", w["id"].(string))
	}
	h.pass(1)
	hooks := h.api.All("webhooks")
	eq(t, "webhooks", len(hooks), 1)
	for _, id := range old {
		if h.api.Get("alerts", id) != nil {
			t.Errorf("alert %s on the dead webhook was kept", id)
		}
	}
	h.pass(1)
	by := h.byName()
	for _, n := range []string{k, s} {
		eq(t, n+" channel", by[n]["channel"].(map[string]any)["webhookId"], hooks[0]["id"])
		eq(t, n+" phase", h.status(n).Phase, "Synced")
	}
}

func TestADeletedAlertRemovesItsHyperDXAlertAndDashboard(t *testing.T) {
	h := newHarness(t, alertCR(k, "w", v1alpha1.AlertStatus{}))
	h.pass(1)
	st := h.status(k)
	eq(t, "finalizer", h.get(k).Finalizers, []string{Finalizer})
	if err := h.kube.Delete(ctx, h.get(k)); err != nil {
		t.Fatal(err)
	}
	h.pass(2)
	if h.api.Get("alerts", st.HyperdxAlertID) != nil || h.api.Get("dashboards", st.HyperdxDashboardID) != nil {
		t.Error("the HyperDX objects were kept")
	}
	var l v1alpha1.AlertList
	_ = h.kube.List(ctx, &l)
	eq(t, "alerts", len(l.Items), 0)
}

func TestADeleteIsNotWedgedOnHyperDX(t *testing.T) {
	h := newHarness(t, alertCR(k, "w", v1alpha1.AlertStatus{}))
	h.pass(1)
	h.api.Fail = func(string, string, string) int { return 500 }
	if err := h.kube.Delete(ctx, h.get(k)); err != nil {
		t.Fatal(err)
	}
	h.pass(2)
	var l v1alpha1.AlertList
	_ = h.kube.List(ctx, &l)
	eq(t, "alerts", len(l.Items), 0)
}

// --- the pause annotation and provider-runtime ---

func TestProviderRuntimeDoesNotSeeThePause(t *testing.T) {
	a := alertCR(k, "w", v1alpha1.AlertStatus{})
	a.Annotations = map[string]string{"krateo.io/paused": "true", "x": "y"}
	if meta.IsPaused(a) {
		t.Error("provider-runtime sees the pause and would skip the whole reconcile")
	}
	if !a.Paused() {
		t.Error("the Alert does not see its own pause")
	}
	meta.SetExternalCreatePending(a, time.Now())
	meta.RemoveAnnotations(a, "x")
	eq(t, "kept", a.Annotations["krateo.io/paused"], "true")
	if _, ok := a.Annotations["x"]; ok {
		t.Error("x was not removed")
	}
	b := alertCR(k, "w", v1alpha1.AlertStatus{})
	meta.AddAnnotations(b, map[string]string{"z": "1"})
	eq(t, "no pause", b.Annotations, map[string]string{"z": "1"})
}

func compareAlert(name, where string) compare.Alert {
	return compare.Alert{Name: name, DisplayName: display, Where: where, Interval: "15m", Threshold: "2",
		ThresholdType: "above", Message: "m"}
}
