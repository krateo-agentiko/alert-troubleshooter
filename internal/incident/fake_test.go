package incident

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/krateo-platformops/alert-troubleshooter/internal/pyfmt"
)

var incidentsGR = schema.GroupResource{Group: "observability.krateo.io", Resource: "incidents"}

// fakeKube is an in-memory apiserver for Incidents, with the rules the writer depends on:
//   - a create of an existing name is 409 AlreadyExists, and a create ignores status;
//   - a patch whose body carries metadata.resourceVersion is conditioned on it (409 on a mismatch);
//   - a status patch merges status only (null deletes) and bumps the resourceVersion;
//   - the CRD's state rules: Resolved can only become Closed, and Closed is final (422).
type fakeKube struct {
	mu        sync.Mutex
	incidents map[string]map[string]any // namespace/name -> object
	order     []string
	calls     []call
	rv        int
	// beforePatch is a concurrent write just before a status patch lands; beforeCreate a concurrent
	// create just before a create lands. Both run unlocked.
	beforePatch  func(ns, name string)
	beforeCreate func(ns, name string)
	// fail, when set, fails every call.
	fail error
}

type call struct {
	method, ns, name string
	body             map[string]any
}

func newFakeKube() *fakeKube { return &fakeKube{incidents: map[string]map[string]any{}} }

// clone is a JSON round trip, as the apiserver gives.
func clone(v map[string]any) map[string]any {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	out, err := pyfmt.Decode(b)
	if err != nil {
		panic(err)
	}
	return out.(map[string]any)
}

func (f *fakeKube) bump(obj map[string]any) {
	f.rv++
	obj["metadata"].(map[string]any)["resourceVersion"] = fmt.Sprint(f.rv)
}

type seed struct {
	state, rootCause, created, completed string
	firings                              int
}

// put seeds an Incident as the apiserver would hold it. Past Analyzing it carries the RCA's
// completedAt, s.completed or else now.
func (f *fakeKube) put(ns, name, alert string, s seed) map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	if s.firings == 0 {
		s.firings = 1
	}
	if s.created == "" {
		s.created = "2026-09-25T10:00:00Z"
	}
	st := map[string]any{"firings": s.firings}
	if s.state != "" {
		st["state"] = s.state
	}
	if s.rootCause != "" {
		st["rootCause"] = map[string]any{"statement": s.rootCause}
	}
	if s.state != "" && s.state != "Analyzing" {
		if s.completed == "" {
			s.completed = pyfmt.Isoformat(time.Now())
		}
		st["completedAt"] = s.completed
	}
	obj := map[string]any{
		"metadata": map[string]any{"name": name, "namespace": ns, "creationTimestamp": s.created,
			"labels": map[string]any{LabelAlert: alert}},
		"spec":   map[string]any{"alertRef": map[string]any{"name": alert, "namespace": ns}},
		"status": st,
	}
	f.bump(obj)
	f.store(ns+"/"+name, obj)
	return clone(obj)
}

func (f *fakeKube) store(key string, obj map[string]any) {
	if _, ok := f.incidents[key]; !ok {
		f.order = append(f.order, key)
	}
	f.incidents[key] = obj
}

func merge(into, patch map[string]any) {
	for k, v := range patch {
		switch {
		case v == nil:
			delete(into, k)
		case isMap(v) && isMap(into[k]):
			merge(into[k].(map[string]any), v.(map[string]any))
		default:
			into[k] = clone(map[string]any{"v": v})["v"]
		}
	}
}

func isMap(v any) bool {
	_, ok := v.(map[string]any)
	return ok
}

// writeStatus is a write by another client (the controller, a human).
func (f *fakeKube) writeStatus(ns, name string, st map[string]any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	obj := f.incidents[ns+"/"+name]
	if obj["status"] == nil {
		obj["status"] = map[string]any{}
	}
	merge(obj["status"].(map[string]any), st)
	f.bump(obj)
}

func (f *fakeKube) record(method, ns, name string, body map[string]any) {
	if body != nil {
		body = clone(body)
	}
	f.calls = append(f.calls, call{method, ns, name, body})
}

func (f *fakeKube) Get(_ context.Context, ns, name string) (map[string]any, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("GET", ns, name, nil)
	if f.fail != nil {
		return nil, f.fail
	}
	obj, ok := f.incidents[ns+"/"+name]
	if !ok {
		return nil, apierrors.NewNotFound(incidentsGR, name)
	}
	return clone(obj), nil
}

func (f *fakeKube) List(_ context.Context, ns, selector string) ([]map[string]any, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("LIST", ns, selector, nil)
	if f.fail != nil {
		return nil, f.fail
	}
	key, value, hasValue := strings.Cut(selector, "=")
	var out []map[string]any
	for _, k := range f.order {
		obj := f.incidents[k]
		meta := obj["metadata"].(map[string]any)
		labels, _ := meta["labels"].(map[string]any)
		v, ok := labels[key]
		if meta["namespace"] == ns && ok && (!hasValue || v == value) {
			out = append(out, clone(obj))
		}
	}
	return out, nil
}

func (f *fakeKube) Create(_ context.Context, obj map[string]any) (map[string]any, error) {
	meta := obj["metadata"].(map[string]any)
	ns, name := meta["namespace"].(string), meta["name"].(string)
	if f.beforeCreate != nil {
		f.beforeCreate(ns, name)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("POST", ns, name, obj)
	if f.fail != nil {
		return nil, f.fail
	}
	if _, ok := f.incidents[ns+"/"+name]; ok {
		return nil, apierrors.NewAlreadyExists(incidentsGR, name)
	}
	o := clone(obj)
	delete(o, "status")
	o["metadata"].(map[string]any)["creationTimestamp"] = fmt.Sprintf("2026-09-25T12:00:%02dZ", len(f.incidents))
	f.bump(o)
	f.store(ns+"/"+name, o)
	return clone(o), nil
}

func (f *fakeKube) PatchStatus(_ context.Context, ns, name string, patch map[string]any) error {
	if f.beforePatch != nil {
		f.beforePatch(ns, name)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("PATCH", ns, name, patch)
	if f.fail != nil {
		return f.fail
	}
	obj, ok := f.incidents[ns+"/"+name]
	if !ok {
		return apierrors.NewNotFound(incidentsGR, name)
	}
	meta := obj["metadata"].(map[string]any)
	if pm, ok := patch["metadata"].(map[string]any); ok {
		if want, ok := pm["resourceVersion"]; ok && want != nil && want != meta["resourceVersion"] {
			return apierrors.NewConflict(incidentsGR, name, fmt.Errorf("the object has been modified"))
		}
	}
	st, _ := obj["status"].(map[string]any)
	old, _ := st["state"].(string)
	body, _ := patch["status"].(map[string]any)
	next := old
	if s, ok := body["state"].(string); ok {
		next = s
	}
	if old == "Closed" && next != "Closed" || old == "Resolved" && next != "Resolved" && next != "Closed" {
		return apierrors.NewInvalid(schema.GroupKind{Group: "observability.krateo.io", Kind: "Incident"}, name, nil)
	}
	if st == nil {
		st = map[string]any{}
		obj["status"] = st
	}
	merge(st, body)
	f.bump(obj)
	return nil
}

// only is the one Incident in ns.
func (f *fakeKube) only(ns string) map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	var found []map[string]any
	for _, k := range f.order {
		if strings.HasPrefix(k, ns+"/") {
			found = append(found, f.incidents[k])
		}
	}
	if len(found) != 1 {
		panic(fmt.Sprintf("%d incidents in %s", len(found), ns))
	}
	return clone(found[0])
}

func (f *fakeKube) get(ns, name string) map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	return clone(f.incidents[ns+"/"+name])
}

func (f *fakeKube) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.incidents)
}

func (f *fakeKube) clear() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.incidents, f.order = map[string]map[string]any{}, nil
}

// statusWrites are the status bodies of every patch, in order.
func (f *fakeKube) statusWrites() []map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []map[string]any
	for _, c := range f.calls {
		if c.method == "PATCH" {
			st, _ := c.body["status"].(map[string]any)
			out = append(out, st)
		}
	}
	return out
}
