// Package hyperdx is a client of HyperDX's external API v2 (Bearer auth, port 8000): the calls go
// to the Express backend (krateo-clickstack-api.krateo-system.svc:8000) with the user.accessKey
// that the bootstrap Job writes into the hyperdx-api-token Secret.
//
// API shape notes:
//   - every collection endpoint returns {"data": [...], "meta": {...}}; unwrap normalises it;
//   - resources carry "id" (not "_id"), across alerts, webhooks, sources and dashboards;
//   - a dashboard tile config is {sourceId, select: [{aggFn, where}], displayType, ...}.
package hyperdx

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/krateo-platformops/alert-troubleshooter/internal/compare"
	"github.com/krateo-platformops/alert-troubleshooter/internal/httpx"
	"github.com/krateo-platformops/alert-troubleshooter/internal/pyfmt"
)

// DefaultWebhookBody is the generic webhook's body. A generic webhook body can use only {{title}},
// {{body}}, {{link}}, {{state}}, {{startTime}}, {{endTime}} and {{eventId}} (a hash); there is no
// alert id. {{title}} is a state emoji plus the HyperDX alert name, which is its Alert CR's
// metadata.name. {{state}} is ALERT on a firing and OK on a resolve. The provider only logs a
// notification: the reconcile fires alerts.
const DefaultWebhookBody = `{"alertName":"{{title}}","state":"{{state}}","source":"hyperdx-alert"}`

// granularities are the charts/series bucket sizes, in seconds.
var granularities = []struct {
	name    string
	seconds int
}{{"30s", 30}, {"1m", 60}, {"5m", 300}, {"10m", 600}, {"15m", 900}, {"30m", 1800},
	{"1h", 3600}, {"2h", 7200}, {"6h", 21600}, {"12h", 43200}, {"1d", 86400},
	{"2d", 172800}, {"7d", 604800}, {"30d", 2592000}}

// Client calls one HyperDX. Its dashboard list is cached for its lifetime: a new Client serves
// each reconcile, so a `where` comparison never reads an answer from an earlier one.
type Client struct {
	url        string
	key        string
	http       *http.Client
	dashboards []map[string]any
	cached     bool
}

// New returns a client of the HyperDX API at url.
func New(url, accessKey string) *Client {
	return &Client{url: strings.TrimRight(url, "/"), key: accessKey, http: &http.Client{Timeout: 30 * time.Second}}
}

func unwrap(v any) any {
	if m, ok := v.(map[string]any); ok {
		if d, ok := m["data"]; ok {
			return d
		}
	}
	return v
}

func (c *Client) req(ctx context.Context, method, path string, body any) (any, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rd = bytes.NewReader(b)
	}
	url := c.url + path
	r, err := http.NewRequestWithContext(ctx, method, url, rd)
	if err != nil {
		return nil, err
	}
	r.Header.Set("Authorization", "Bearer "+c.key)
	r.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if err := httpx.Check(resp); err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, nil
	}
	v, err := pyfmt.Decode(data)
	if err != nil {
		return nil, err
	}
	return unwrap(v), nil
}

func maps(v any) []map[string]any {
	l, _ := v.([]any)
	out := make([]map[string]any, 0, len(l))
	for _, x := range l {
		if m, ok := x.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

// ID is a resource's "id" as a string.
func ID(m map[string]any) string {
	s, _ := m["id"].(string)
	return s
}

// FirstSource is the first HyperDX source: the logs the alerts count.
func (c *Client) FirstSource(ctx context.Context) (map[string]any, error) {
	v, err := c.req(ctx, http.MethodGet, "/api/v2/sources", nil)
	if err != nil {
		return nil, err
	}
	srcs := maps(v)
	if len(srcs) == 0 {
		return nil, fmt.Errorf("no HyperDX sources configured")
	}
	return srcs[0], nil
}

// RecordCounts are the records matching where (SQL) over the last seconds, grouped by the groupBy
// expression, the most frequent first. The buckets are the coarsest that cover the window, so each
// group comes back in at most two.
func (c *Client) RecordCounts(ctx context.Context, sourceID, where string, seconds int, groupBy string) ([]compare.Row, error) {
	end := time.Now().UnixMilli()
	granularity := granularities[len(granularities)-1].name
	for _, g := range granularities {
		if g.seconds >= seconds {
			granularity = g.name
			break
		}
	}
	v, err := c.req(ctx, http.MethodPost, "/api/v2/charts/series", map[string]any{
		"startTime": end - int64(seconds)*1000, "endTime": end, "granularity": granularity,
		"series": []any{map[string]any{"sourceId": sourceID, "aggFn": "count", "where": where,
			"whereLanguage": "sql", "groupBy": []string{groupBy}}}})
	if err != nil {
		return nil, err
	}
	counts := map[string]int{}
	for _, b := range maps(v) { // one per (time bucket, group)
		group := ""
		if g, ok := b["group"].([]any); ok && len(g) > 0 {
			if s, ok := g[0].(string); ok {
				group = s
			} else if g[0] != nil {
				group = pyfmt.Str(g[0])
			}
		}
		n := 0
		if pyfmt.Truthy(b["series_0.data"]) {
			if f, ok := pyfmt.Float(b["series_0.data"]); ok {
				n = int(f)
			}
		}
		counts[group] += n
	}
	rows := make([]compare.Row, 0, len(counts))
	for g, n := range counts {
		rows = append(rows, compare.Row{Record: g, Count: n})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Count != rows[j].Count {
			return rows[i].Count > rows[j].Count
		}
		return rows[i].Record < rows[j].Record
	})
	return rows, nil
}

// EnsureWebhook ensures a generic webhook named name exists and sends DefaultWebhookBody. It
// returns the webhook's id and whether it was created. An existing webhook whose body differs is
// updated in place (PUT keeps its id, so its alerts keep notifying it); only a new webhook, whose
// alerts must be re-pointed, is created. The URL is not compared: the API redacts it.
func (c *Client) EnsureWebhook(ctx context.Context, name, targetURL, description string) (string, bool, error) {
	if description == "" {
		description = name
	}
	doc := map[string]any{"name": name, "service": "generic", "url": targetURL,
		"description": description, "body": DefaultWebhookBody}
	v, err := c.req(ctx, http.MethodGet, "/api/v2/webhooks", nil)
	if err != nil {
		return "", false, err
	}
	for _, w := range maps(v) {
		if w["name"] == name {
			if w["body"] != DefaultWebhookBody {
				if _, err := c.req(ctx, http.MethodPut, "/api/v2/webhooks/"+ID(w), doc); err != nil {
					return "", false, err
				}
			}
			return ID(w), false, nil
		}
	}
	created, err := c.req(ctx, http.MethodPost, "/api/v2/webhooks", doc)
	if err != nil {
		return "", false, err
	}
	m, _ := created.(map[string]any)
	return ID(m), true, nil
}

// ListDashboards are the dashboards, read once per Client (see Client).
func (c *Client) ListDashboards(ctx context.Context) ([]map[string]any, error) {
	if !c.cached {
		v, err := c.req(ctx, http.MethodGet, "/api/v2/dashboards", nil)
		if err != nil {
			return nil, err
		}
		c.dashboards, c.cached = maps(v), true
	}
	return c.dashboards, nil
}

func (c *Client) invalidate() {
	c.dashboards, c.cached = nil, false
}

// tileFor is the single count-over-time tile, as both create and update send it. A create mints a
// new tile id whatever is sent. An update must send the live tile's id: an unknown id makes HyperDX
// mint a new tile, drop the old one and delete every alert on it.
func tileFor(name string, source map[string]any, where, tileID string) map[string]any {
	return map[string]any{
		"id": tileID, "x": 0, "y": 0, "w": 6, "h": 3,
		"name": name,
		"config": map[string]any{
			"displayType": "line",
			"sourceId":    source["id"],
			"asRatio":     false,
			"fillNulls":   true,
			// whereLanguage "sql" is load-bearing: omitted, HyperDX maps the series to lucene and
			// the SQL filter becomes a full-text search that matches its own text.
			"select": []any{map[string]any{"aggFn": "count", "where": where, "whereLanguage": "sql"}},
		},
	}
}

func tiles(d map[string]any) []map[string]any {
	return maps(d["tiles"])
}

// TileWhere is the `where` the dashboard's tile evaluates, and false when the dashboard is gone.
// spec.where lands on the dashboard tile, not the alert, which is why a where edit needs its own
// comparison and its own push.
func (c *Client) TileWhere(ctx context.Context, dashboardID string) (string, bool, error) {
	ds, err := c.ListDashboards(ctx)
	if err != nil {
		return "", false, err
	}
	for _, d := range ds {
		if ID(d) != dashboardID {
			continue
		}
		t := tiles(d)
		if len(t) == 0 {
			return "", false, nil
		}
		cfg, _ := t[0]["config"].(map[string]any)
		sel := maps(cfg["select"])
		if len(sel) == 0 {
			return "", true, nil
		}
		w, ok := sel[0]["where"]
		if !ok {
			return "", true, nil
		}
		if w == nil {
			return "", false, nil
		}
		return pyfmt.Str(w), true, nil
	}
	return "", false, nil
}

// UpdateDashboardTile PUTs the dashboard so its tile tileID evaluates where. tileID is the id the
// alert evaluates: the API keeps a tile id only if it already exists, and any other id replaces the
// tile, which deletes the alerts on the replaced one.
func (c *Client) UpdateDashboardTile(ctx context.Context, dashboardID, name string, source map[string]any, where, tileID string) error {
	_, err := c.req(ctx, http.MethodPut, "/api/v2/dashboards/"+dashboardID,
		map[string]any{"name": name, "tags": []any{}, "tiles": []any{tileFor(name, source, where, tileID)}})
	c.invalidate()
	return err
}

// EnsureDashboardTile ensures a single-tile dashboard named name with a count-over-time line chart
// and returns its id and its tile's. A dashboard whose tile id is in taken (a tile another alert
// already evaluates) is not reused, so two alerts never share one `where`.
func (c *Client) EnsureDashboardTile(ctx context.Context, name string, source map[string]any, where string, taken map[string]bool) (string, string, error) {
	ds, err := c.ListDashboards(ctx)
	if err != nil {
		return "", "", err
	}
	for _, d := range ds {
		if t := tiles(d); d["name"] == name && len(t) > 0 && !taken[ID(t[0])] {
			return ID(d), ID(t[0]), nil
		}
	}
	v, err := c.req(ctx, http.MethodPost, "/api/v2/dashboards",
		map[string]any{"name": name, "tags": []any{}, "tiles": []any{tileFor(name, source, where, "count")}})
	c.invalidate()
	if err != nil {
		return "", "", err
	}
	d, _ := v.(map[string]any)
	t := tiles(d)
	if len(t) == 0 {
		return "", "", fmt.Errorf("the created dashboard has no tile")
	}
	return ID(d), ID(t[0]), nil
}

// ListAlerts are the live alerts.
func (c *Client) ListAlerts(ctx context.Context) ([]map[string]any, error) {
	v, err := c.req(ctx, http.MethodGet, "/api/v2/alerts", nil)
	if err != nil {
		return nil, err
	}
	return maps(v), nil
}

// AlertFields are the fields an Alert CR owns on its HyperDX alert. where is not one: it lives on
// the dashboard tile.
type AlertFields struct {
	Interval      string
	Threshold     any
	ThresholdType string
	Message       string
}

// mutable are the alert fields a CR may change after creation.
var mutable = []string{"interval", "threshold", "thresholdType", "message"}

// alertBody is the alert document as both POST and PUT take it: PUT is a full replace validated
// against the same schema as POST, so one builder keeps the two from drifting.
func alertBody(name, dashboardID, tileID, webhookID string, f AlertFields) map[string]any {
	message := f.Message
	if message == "" {
		message = name + " threshold crossed — incident-agent will auto-triage."
	}
	return map[string]any{
		"name":          name,
		"source":        "tile",
		"dashboardId":   dashboardID,
		"tileId":        tileID,
		"interval":      f.Interval,
		"threshold":     f.Threshold,
		"thresholdType": f.ThresholdType,
		"channel":       map[string]any{"type": "webhook", "webhookId": webhookID},
		"message":       message,
	}
}

// AlertDrift are the mutable fields and the name that differ between the live alert and the CR,
// sorted. They are compared as strings: the API returns threshold as a number and a CR may carry
// it as either, and 1 != "1" would be a drift corrected on every pass, forever. The name also
// seeds the default message, so an empty message compares equal to the live one.
func AlertDrift(live map[string]any, name string, f AlertFields) []string {
	body := alertBody(name, "", "", "", f)
	var out []string
	for _, field := range append(append([]string{}, mutable...), "name") {
		if pyfmt.Str(live[field]) != pyfmt.Str(body[field]) {
			out = append(out, field)
		}
	}
	sort.Strings(out)
	return out
}

func idState(v any, fallbackID string) map[string]any {
	m, _ := v.(map[string]any)
	id, ok := m["id"]
	if !ok {
		id = fallbackID
	}
	state, ok := m["state"]
	if !ok {
		state = "OK"
	}
	return map[string]any{"id": id, "state": state}
}

// UpdateAlert PUTs the alert. It returns {id, state}.
func (c *Client) UpdateAlert(ctx context.Context, alertID, name, dashboardID, tileID, webhookID string, f AlertFields) (map[string]any, error) {
	v, err := c.req(ctx, http.MethodPut, "/api/v2/alerts/"+alertID, alertBody(name, dashboardID, tileID, webhookID, f))
	if err != nil {
		return nil, err
	}
	return idState(v, alertID), nil
}

// EnsureAlert creates the tile alert, or reconciles the one already carrying this name. name is
// the Alert CR's metadata.name, unique per namespace, so one name is one CR. It returns {id, state}.
func (c *Client) EnsureAlert(ctx context.Context, name, dashboardID, tileID, webhookID string, f AlertFields) (map[string]any, error) {
	alerts, err := c.ListAlerts(ctx)
	if err != nil {
		return nil, err
	}
	for _, a := range alerts {
		if a["name"] == name {
			if len(AlertDrift(a, name, f)) == 0 {
				return idState(a, ID(a)), nil
			}
			return c.UpdateAlert(ctx, ID(a), name, dashboardID, tileID, webhookID, f)
		}
	}
	v, err := c.req(ctx, http.MethodPost, "/api/v2/alerts", alertBody(name, dashboardID, tileID, webhookID, f))
	if err != nil {
		return nil, err
	}
	m, _ := v.(map[string]any)
	return idState(m, ID(m)), nil
}

// DeleteAlert deletes the alert.
func (c *Client) DeleteAlert(ctx context.Context, id string) error {
	_, err := c.req(ctx, http.MethodDelete, "/api/v2/alerts/"+id, nil)
	return err
}

// DeleteDashboard deletes the dashboard.
func (c *Client) DeleteDashboard(ctx context.Context, id string) error {
	_, err := c.req(ctx, http.MethodDelete, "/api/v2/dashboards/"+id, nil)
	return err
}
