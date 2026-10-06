package alert

import (
	"context"
	"fmt"
	"sync"
	"time"

	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/krateo-platformops/provider-runtime/pkg/logging"
	"github.com/krateo-platformops/provider-runtime/pkg/meta"

	"github.com/krateo-platformops/alert-troubleshooter/apis/alert/v1alpha1"
	"github.com/krateo-platformops/alert-troubleshooter/internal/hyperdx"
)

// webhook is what every Alert's pass shares: the HyperDX source the alerts count and the generic
// webhook they notify, read and ensured at most once per poll interval.
type webhook struct {
	kube         client.Client
	name, target string
	ttl          time.Duration
	log          logging.Logger

	mu     sync.Mutex
	at     time.Time
	source map[string]any
	id     string
}

// ensure returns the source and the webhook id. A webhook it has to create has a new id, so
// alerts referencing the old one would notify a dead channel: it then deletes the HyperDX alerts
// the Alerts manage and resets their status, so they rebuild on this webhook. a, the Alert this
// pass is for, is reset in memory, since its reconcile writes its status.
func (w *webhook) ensure(ctx context.Context, hdx *hyperdx.Client, a *v1alpha1.Alert) (map[string]any, string, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.at.IsZero() && time.Since(w.at) < w.ttl {
		return w.source, w.id, nil
	}
	source, err := hdx.FirstSource(ctx)
	if err != nil {
		return nil, "", err
	}
	id, created, err := hdx.EnsureWebhook(ctx, w.name, w.target, "Krateo alert-provider: the HyperDX alerts' channel")
	if err != nil {
		return nil, "", err
	}
	if created {
		if err := w.reset(ctx, hdx, a); err != nil {
			return nil, "", err
		}
	}
	w.at, w.source, w.id = time.Now(), source, id
	return source, id, nil
}

func (w *webhook) reset(ctx context.Context, hdx *hyperdx.Client, a *v1alpha1.Alert) error {
	var all v1alpha1.AlertList
	if err := w.kube.List(ctx, &all, client.InNamespace(a.Namespace)); err != nil {
		return err
	}
	var active []*v1alpha1.Alert
	managed := map[string]bool{}
	for i := range all.Items {
		o := &all.Items[i]
		if o.UID == a.UID {
			o = a
		}
		if meta.WasDeleted(o) {
			continue
		}
		active = append(active, o)
		if id := o.Status.HyperdxAlertID; id != "" {
			managed[id] = true
		}
	}
	live, err := hdx.ListAlerts(ctx)
	if err != nil {
		return err
	}
	for _, l := range live {
		if managed[hyperdx.ID(l)] {
			_ = hdx.DeleteAlert(ctx, hyperdx.ID(l))
		}
	}
	for _, o := range active {
		if o == a {
			a.Status.HyperdxAlertID, a.Status.Phase = "", v1alpha1.PhasePending
			continue
		}
		patch := client.RawPatch(types.MergePatchType, []byte(`{"status":{"hyperdxAlertId":null,"phase":"Pending"}}`))
		if err := w.kube.Status().Patch(ctx, o, patch); err != nil {
			return err
		}
	}
	w.log.Info(fmt.Sprintf("[reconciler] webhook %s was recreated: %d Alerts rebuild their HyperDX alerts on it", w.name, len(active)))
	return nil
}
