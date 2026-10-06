package alert

import (
	"context"
	"fmt"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/krateo-platformops/provider-runtime/pkg/logging"

	"github.com/krateo-platformops/alert-troubleshooter/apis/alert/v1alpha1"
	"github.com/krateo-platformops/alert-troubleshooter/internal/pyfmt"
)

// Seeder creates the default Alerts, once per start, retrying every Interval until the Alert CRD
// is established. The composition ships the defaults here rather than as chart CRs: Helm cannot
// validate a CR before its CRD is installed in the same pass.
type Seeder struct {
	// Reader lists the Alerts past the cache, which may not have started.
	Reader    client.Reader
	Client    client.Client
	Namespace string
	// Defaults is a JSON array of Alert specs, each with its name.
	Defaults string
	Interval time.Duration
	Log      logging.Logger
}

// Start seeds the defaults; it implements manager.Runnable.
func (s *Seeder) Start(ctx context.Context) error {
	for !s.seed(ctx) {
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(s.Interval):
		}
	}
	return nil
}

// seed creates the default Alerts that are absent. It returns true once done, or with nothing to
// seed, and false when the Alert CRD is not established yet, so the caller retries.
func (s *Seeder) seed(ctx context.Context) bool {
	if s.Defaults == "" {
		return true
	}
	v, err := pyfmt.Decode([]byte(s.Defaults))
	defaults, ok := v.([]any)
	if err != nil || !ok {
		if err == nil {
			err = fmt.Errorf("not a JSON array")
		}
		s.Log.Info(fmt.Sprintf("[reconciler] bad DEFAULT_ALERTS_JSON (%s); skipping seed", err))
		return true
	}
	var list v1alpha1.AlertList
	if err := s.Reader.List(ctx, &list, client.InNamespace(s.Namespace)); err != nil {
		s.Log.Info(fmt.Sprintf("[reconciler] seed: Alert CRD not ready (%s); retrying", pyfmt.Cut(err.Error(), 80)))
		return false
	}
	existing := map[string]bool{}
	for _, a := range list.Items {
		existing[a.Name] = true
	}
	for _, d := range defaults {
		m, _ := d.(map[string]any)
		name, _ := m["name"].(string)
		if name == "" || existing[name] {
			continue
		}
		spec := map[string]any{}
		for k, v := range m {
			if k != "name" {
				spec[k] = v
			}
		}
		u := &unstructured.Unstructured{Object: map[string]any{
			"apiVersion": v1alpha1.SchemeGroupVersion.String(), "kind": v1alpha1.AlertKind,
			"metadata": map[string]any{"name": name, "namespace": s.Namespace},
			"spec":     spec,
		}}
		if err := s.Client.Create(ctx, u); err != nil { // one bad seed does not block the rest
			s.Log.Info(fmt.Sprintf("[reconciler] seed %s failed: %s", name, pyfmt.Cut(err.Error(), 120)))
			continue
		}
		s.Log.Info(fmt.Sprintf("[reconciler] seeded default Alert %s", name))
	}
	return true
}
