package incident

import (
	"context"
	"encoding/json"
	"errors"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/krateo-platformops/alert-provider/internal/pyfmt"
)

// The Incident contract (incident-controller apis/incident/v1alpha1).
var (
	IncidentGVK     = schema.GroupVersionKind{Group: "observability.krateo.io", Version: "v1alpha1", Kind: "Incident"}
	incidentListGVK = IncidentGVK.GroupVersion().WithKind("IncidentList")
)

// Kube reads and writes Incidents. Objects are JSON values decoded with pyfmt.Decode. Errors carry
// the apiserver's status code (see code).
type Kube interface {
	Get(ctx context.Context, namespace, name string) (map[string]any, error)
	// List returns the Incidents in namespace that match the label selector.
	List(ctx context.Context, namespace, selector string) ([]map[string]any, error)
	Create(ctx context.Context, obj map[string]any) (map[string]any, error)
	// PatchStatus merges patch into the Incident's status subresource. A patch whose
	// metadata.resourceVersion is set is conditioned on it.
	PatchStatus(ctx context.Context, namespace, name string, patch map[string]any) error
}

// code is the apiserver status code of err, or 0.
func code(err error) int {
	var s apierrors.APIStatus
	if errors.As(err, &s) {
		return int(s.Status().Code)
	}
	return 0
}

// NewKube returns a Kube that reads past any cache, with reader, and writes with c.
func NewKube(reader client.Reader, c client.Client) Kube {
	return &kube{reader: reader, client: c}
}

type kube struct {
	reader client.Reader
	client client.Client
}

func decode(obj map[string]any) (map[string]any, error) {
	b, err := json.Marshal(obj)
	if err != nil {
		return nil, err
	}
	v, err := pyfmt.Decode(b)
	if err != nil {
		return nil, err
	}
	m, _ := v.(map[string]any)
	return m, nil
}

func (k *kube) Get(ctx context.Context, namespace, name string) (map[string]any, error) {
	u := &unstructured.Unstructured{}
	u.SetGroupVersionKind(IncidentGVK)
	if err := k.reader.Get(ctx, types.NamespacedName{Namespace: namespace, Name: name}, u); err != nil {
		return nil, err
	}
	return decode(u.Object)
}

func (k *kube) List(ctx context.Context, namespace, selector string) ([]map[string]any, error) {
	sel, err := labels.Parse(selector)
	if err != nil {
		return nil, err
	}
	l := &unstructured.UnstructuredList{}
	l.SetGroupVersionKind(incidentListGVK)
	if err := k.reader.List(ctx, l, client.InNamespace(namespace), client.MatchingLabelsSelector{Selector: sel}); err != nil {
		return nil, err
	}
	out := make([]map[string]any, 0, len(l.Items))
	for i := range l.Items {
		m, err := decode(l.Items[i].Object)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, nil
}

func (k *kube) Create(ctx context.Context, obj map[string]any) (map[string]any, error) {
	b, err := json.Marshal(obj)
	if err != nil {
		return nil, err
	}
	u := &unstructured.Unstructured{}
	if err := u.UnmarshalJSON(b); err != nil {
		return nil, err
	}
	if err := k.client.Create(ctx, u); err != nil {
		return nil, err
	}
	return decode(u.Object)
}

func (k *kube) PatchStatus(ctx context.Context, namespace, name string, patch map[string]any) error {
	b, err := json.Marshal(patch)
	if err != nil {
		return err
	}
	u := &unstructured.Unstructured{}
	u.SetGroupVersionKind(IncidentGVK)
	u.SetNamespace(namespace)
	u.SetName(name)
	return k.client.Status().Patch(ctx, u, client.RawPatch(types.MergePatchType, b))
}
