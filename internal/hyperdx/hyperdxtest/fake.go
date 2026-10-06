// Package hyperdxtest is an in-memory HyperDX /api/v2 for tests. It keeps the two behaviours the
// alert reconcile hinges on: a dashboard PUT keeps a tile id only if it already exists, and
// deletes the alerts on a replaced tile.
package hyperdxtest

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
)

// Write is one write the API took: its method, the resource kind and the id, if any.
type Write struct{ Method, Kind, ID string }

// API is the fake HyperDX.
type API struct {
	*httptest.Server

	mu         sync.Mutex
	stores     map[string]*store // webhooks, dashboards, alerts
	writes     []Write
	n          int
	series     []any
	seriesReqs []map[string]any
	// Fail, when it returns a status code, answers the request with it.
	Fail func(method, kind, id string) int
}

type store struct {
	order []string
	docs  map[string]map[string]any
}

func (s *store) put(id string, doc map[string]any) {
	if _, ok := s.docs[id]; !ok {
		s.order = append(s.order, id)
	}
	s.docs[id] = doc
}

func (s *store) del(id string) {
	delete(s.docs, id)
	for i, o := range s.order {
		if o == id {
			s.order = append(s.order[:i], s.order[i+1:]...)
			break
		}
	}
}

// New starts the fake.
func New() *API {
	a := &API{stores: map[string]*store{}}
	for _, k := range []string{"webhooks", "dashboards", "alerts"} {
		a.stores[k] = &store{docs: map[string]map[string]any{}}
	}
	a.Server = httptest.NewServer(http.HandlerFunc(a.serve))
	return a
}

func clone(v any) any {
	b, _ := json.Marshal(v)
	var out any
	_ = json.Unmarshal(b, &out)
	return out
}

func (a *API) id() string {
	a.n++
	return fmt.Sprintf("oid%04d", a.n)
}

func (a *API) newTiles(tiles any, existing map[string]bool) []any {
	var out []any
	l, _ := tiles.([]any)
	for _, t := range l {
		tm := clone(t).(map[string]any)
		if id, _ := tm["id"].(string); !existing[id] {
			tm["id"] = a.id()
		}
		out = append(out, tm)
	}
	return out
}

func (a *API) serve(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/") // api, v2, kind[, id]
	kind, id := parts[2], ""
	if len(parts) > 3 {
		id = parts[3]
	}
	if r.Method != http.MethodGet {
		a.writes = append(a.writes, Write{r.Method, kind, id})
	}
	if a.Fail != nil {
		if code := a.Fail(r.Method, kind, id); code != 0 {
			w.WriteHeader(code)
			return
		}
	}
	var body map[string]any
	_ = json.NewDecoder(r.Body).Decode(&body)
	reply := func(v any) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	}
	switch kind {
	case "sources":
		reply([]any{map[string]any{"id": "src-1"}})
		return
	case "charts":
		a.seriesReqs = append(a.seriesReqs, body)
		reply(map[string]any{"data": a.series})
		return
	}
	s := a.stores[kind]
	switch {
	case r.Method == http.MethodGet:
		out := []any{}
		for _, o := range s.order {
			out = append(out, clone(s.docs[o]))
		}
		reply(map[string]any{"data": out})
	case r.Method == http.MethodPost:
		doc := clone(body).(map[string]any)
		doc["id"] = a.id()
		if kind == "dashboards" {
			doc["tiles"] = a.newTiles(doc["tiles"], nil)
		}
		if kind == "alerts" {
			doc["state"] = "OK"
		}
		s.put(doc["id"].(string), doc)
		reply(map[string]any{"data": clone(doc)})
	case s.docs[id] == nil:
		w.WriteHeader(http.StatusNotFound)
	case r.Method == http.MethodDelete:
		s.del(id)
	case r.Method == http.MethodPut:
		doc := clone(body).(map[string]any)
		doc["id"] = id
		if kind == "dashboards" {
			old := map[string]bool{}
			for _, t := range s.docs[id]["tiles"].([]any) {
				old[t.(map[string]any)["id"].(string)] = true
			}
			doc["tiles"] = a.newTiles(doc["tiles"], old)
			kept := map[string]bool{}
			for _, t := range doc["tiles"].([]any) {
				kept[t.(map[string]any)["id"].(string)] = true
			}
			alerts := a.stores["alerts"]
			for _, aid := range append([]string{}, alerts.order...) {
				al := alerts.docs[aid]
				if al["dashboardId"] == id && old[fmt.Sprint(al["tileId"])] && !kept[fmt.Sprint(al["tileId"])] {
					alerts.del(aid)
				}
			}
		}
		if kind == "alerts" {
			state, ok := s.docs[id]["state"]
			if !ok {
				state = "OK"
			}
			doc["state"] = state
		}
		s.put(id, doc)
		reply(map[string]any{"data": clone(doc)})
	}
}

// Writes are the writes so far; ClearWrites forgets them.
func (a *API) Writes() []Write {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]Write{}, a.writes...)
}

func (a *API) ClearWrites() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.writes = nil
}

// Get is a copy of a stored document, nil when absent.
func (a *API) Get(kind, id string) map[string]any {
	a.mu.Lock()
	defer a.mu.Unlock()
	if d := a.stores[kind].docs[id]; d != nil {
		return clone(d).(map[string]any)
	}
	return nil
}

// All are the stored documents of kind, in creation order.
func (a *API) All(kind string) []map[string]any {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []map[string]any
	for _, id := range a.stores[kind].order {
		out = append(out, clone(a.stores[kind].docs[id]).(map[string]any))
	}
	return out
}

// Set changes fields of a stored document, as HyperDX itself or a person would.
func (a *API) Set(kind, id string, fields map[string]any) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for k, v := range fields {
		a.stores[kind].docs[id][k] = v
	}
}

// Put stores a document as is.
func (a *API) Put(kind string, doc map[string]any) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.stores[kind].put(doc["id"].(string), clone(doc).(map[string]any))
}

// Delete removes a stored document.
func (a *API) Delete(kind, id string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.stores[kind].del(id)
}

// SetSeries is what /api/v2/charts/series answers; SeriesRequests are the bodies it was sent.
func (a *API) SetSeries(buckets []any) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.series = buckets
}

func (a *API) SeriesRequests() []map[string]any {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.seriesReqs
}

// WhereOf is the `where` the tile an alert evaluates holds.
func (a *API) WhereOf(alert map[string]any) string {
	d := a.Get("dashboards", alert["dashboardId"].(string))
	for _, t := range d["tiles"].([]any) {
		tm := t.(map[string]any)
		if tm["id"] == alert["tileId"] {
			return tm["config"].(map[string]any)["select"].([]any)[0].(map[string]any)["where"].(string)
		}
	}
	return ""
}

// W is a Write.
func W(method, kind, id string) Write { return Write{Method: method, Kind: kind, ID: id} }
