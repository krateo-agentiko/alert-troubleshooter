package hyperdx_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/krateo-platformops/alert-provider/internal/compare"
	"github.com/krateo-platformops/alert-provider/internal/golden"
	"github.com/krateo-platformops/alert-provider/internal/hyperdx"
	"github.com/krateo-platformops/alert-provider/internal/hyperdx/hyperdxtest"
)

var ctx = context.Background()

func client(t *testing.T) (*hyperdx.Client, *hyperdxtest.API) {
	api := hyperdxtest.New()
	t.Cleanup(api.Close)
	return hyperdx.New(api.URL, "k"), api
}

func eq(t *testing.T, what string, got, want any) {
	t.Helper()
	if d := golden.Diff(want, got); d != "" {
		t.Errorf("%s (-want +got):\n%s", what, d)
	}
}

func writes(api *hyperdxtest.API, methods ...string) []hyperdxtest.Write {
	out := []hyperdxtest.Write{}
	for _, w := range api.Writes() {
		for _, m := range methods {
			if w.Method == m {
				out = append(out, w)
			}
		}
	}
	return out
}

var fields = hyperdx.AlertFields{Interval: "5m", Threshold: json.Number("1"), ThresholdType: "above", Message: "m"}

func TestTheWebhookBodyCarriesTheTitleAndTheRealState(t *testing.T) {
	for _, want := range []string{`"alertName":"{{title}}"`, `"state":"{{state}}"`} {
		if !strings.Contains(hyperdx.DefaultWebhookBody, want) {
			t.Errorf("body lacks %s", want)
		}
	}
}

func TestAnExistingWebhookWithAnOldBodyIsUpdatedInPlace(t *testing.T) {
	c, api := client(t)
	api.Put("webhooks", map[string]any{"id": "w1", "name": "krateo-alert-provider", "service": "generic", "url": "http://x/****",
		"body": `{"alertName":"{{title}}","state":"ALERT","source":"hyperdx-alert"}`})
	id, created, err := c.EnsureWebhook(ctx, "krateo-alert-provider", "http://x/webhook", "")
	eq(t, "ensure", []any{id, created, err}, []any{"w1", false, nil})
	eq(t, "body", api.Get("webhooks", "w1")["body"], hyperdx.DefaultWebhookBody)
	eq(t, "writes", api.Writes(), []hyperdxtest.Write{hyperdxtest.W("PUT", "webhooks", "w1")})
	api.ClearWrites()
	id, created, _ = c.EnsureWebhook(ctx, "krateo-alert-provider", "http://x/webhook", "")
	eq(t, "again", []any{id, created, len(api.Writes())}, []any{"w1", false, 0})
}

func TestAMissingWebhookIsCreated(t *testing.T) {
	c, api := client(t)
	id, created, err := c.EnsureWebhook(ctx, "krateo-alert-provider", "http://x/webhook", "d")
	if err != nil || !created {
		t.Fatalf("created %v err %v", created, err)
	}
	w := api.Get("webhooks", id)
	eq(t, "webhook", w, map[string]any{"id": id, "name": "krateo-alert-provider", "service": "generic",
		"url": "http://x/webhook", "description": "d", "body": hyperdx.DefaultWebhookBody})
}

func TestUpdatesANameMatchedAlertWhoseThresholdDrifted(t *testing.T) {
	c, api := client(t)
	api.Put("alerts", map[string]any{"id": "h1", "name": "my-alert", "state": "ALERT", "interval": "5m", "threshold": 0,
		"thresholdType": "above", "message": "m"})
	out, err := c.EnsureAlert(ctx, "my-alert", "d1", "count", "hook", fields)
	eq(t, "out", []any{out["id"], err}, []any{"h1", nil})
	eq(t, "writes", api.Writes(), []hyperdxtest.Write{hyperdxtest.W("PUT", "alerts", "h1")})
	eq(t, "threshold", api.Get("alerts", "h1")["threshold"], 1)
}

func TestDoesNotWriteWhenTheNameMatchAlreadyAgrees(t *testing.T) {
	c, api := client(t)
	api.Put("alerts", map[string]any{"id": "h1", "name": "my-alert", "state": "OK", "interval": "5m", "threshold": 1,
		"thresholdType": "above", "message": "m"})
	_, _ = c.EnsureAlert(ctx, "my-alert", "d1", "count", "hook", fields)
	eq(t, "writes", len(api.Writes()), 0)
}

func TestComparesAsStringsSo1AndQuoted1AreNotPerpetualDrift(t *testing.T) {
	c, api := client(t)
	api.Put("alerts", map[string]any{"id": "h1", "name": "my-alert", "state": "OK", "interval": "5m", "threshold": 1,
		"thresholdType": "above", "message": "m"})
	f := fields
	f.Threshold = "1"
	_, _ = c.EnsureAlert(ctx, "my-alert", "d1", "count", "hook", f)
	eq(t, "writes", len(api.Writes()), 0)
}

func TestStillCreatesWhenNoAlertCarriesTheName(t *testing.T) {
	c, api := client(t)
	out, err := c.EnsureAlert(ctx, "my-alert", "d1", "count", "hook", fields)
	if err != nil {
		t.Fatal(err)
	}
	eq(t, "writes", api.Writes(), []hyperdxtest.Write{hyperdxtest.W("POST", "alerts", "")})
	a := api.Get("alerts", out["id"].(string))
	eq(t, "alert", a, map[string]any{"id": out["id"], "name": "my-alert", "source": "tile", "dashboardId": "d1",
		"tileId": "count", "interval": "5m", "threshold": 1, "thresholdType": "above",
		"channel": map[string]any{"type": "webhook", "webhookId": "hook"}, "message": "m", "state": "OK"})
}

func TestAnEmptyMessageIsTheDefault(t *testing.T) {
	c, api := client(t)
	f := fields
	f.Message = ""
	out, _ := c.EnsureAlert(ctx, "my-alert", "d1", "count", "hook", f)
	eq(t, "message", api.Get("alerts", out["id"].(string))["message"], "my-alert threshold crossed — incident-agent will auto-triage.")
}

func TestCreatesTheDashboardWhenNoneCarriesTheName(t *testing.T) {
	c, api := client(t)
	dash, tile, err := c.EnsureDashboardTile(ctx, "krateo-alert-x", map[string]any{"id": "src-1"}, "ServiceName = 'x'", nil)
	if err != nil {
		t.Fatal(err)
	}
	d := api.Get("dashboards", dash)
	eq(t, "dashboard", d, map[string]any{"id": dash, "name": "krateo-alert-x", "tags": []any{}, "tiles": []any{map[string]any{
		"id": tile, "x": 0, "y": 0, "w": 6, "h": 3, "name": "krateo-alert-x",
		"config": map[string]any{"displayType": "line", "sourceId": "src-1", "asRatio": false, "fillNulls": true,
			// whereLanguage sql is load-bearing: omitted, the SQL filter becomes a full-text search
			"select": []any{map[string]any{"aggFn": "count", "where": "ServiceName = 'x'", "whereLanguage": "sql"}}}}}})
}

func TestReusesAnExistingDashboardWithoutPosting(t *testing.T) {
	c, api := client(t)
	api.Put("dashboards", map[string]any{"id": "d1", "name": "krateo-alert-x", "tiles": []any{map[string]any{"id": "t1"}}})
	dash, tile, _ := c.EnsureDashboardTile(ctx, "krateo-alert-x", map[string]any{"id": "src-1"}, "", nil)
	eq(t, "ids", []any{dash, tile}, []any{"d1", "t1"})
	eq(t, "writes", len(api.Writes()), 0)
}

func TestATakenTileIsNeverReused(t *testing.T) {
	c, api := client(t)
	api.Put("dashboards", map[string]any{"id": "d1", "name": "krateo-alert-x", "tiles": []any{map[string]any{"id": "t1"}}})
	dash, _, _ := c.EnsureDashboardTile(ctx, "krateo-alert-x", map[string]any{"id": "src-1"}, "", map[string]bool{"t1": true})
	if dash == "d1" {
		t.Error("reused a taken tile")
	}
}

func TestCreateAndUpdateBuildTheSameTile(t *testing.T) {
	c, api := client(t)
	dash, tile, _ := c.EnsureDashboardTile(ctx, "krateo-alert-x", map[string]any{"id": "src-1"}, "a = 1", nil)
	created := api.Get("dashboards", dash)
	if err := c.UpdateDashboardTile(ctx, dash, "krateo-alert-x", map[string]any{"id": "src-1"}, "a = 1", tile); err != nil {
		t.Fatal(err)
	}
	eq(t, "tile", api.Get("dashboards", dash), created)
}

func TestTileWhereReadsTheTileAndMissesAGoneDashboard(t *testing.T) {
	c, _ := client(t)
	dash, _, _ := c.EnsureDashboardTile(ctx, "krateo-alert-x", map[string]any{"id": "src-1"}, "a = 1", nil)
	w, found, err := c.TileWhere(ctx, dash)
	eq(t, "live", []any{w, found, err}, []any{"a = 1", true, nil})
	_, found, _ = c.TileWhere(ctx, "nope")
	eq(t, "gone", found, false)
}

func TestBucketsAreSummedPerGroupMostFrequentFirst(t *testing.T) {
	c, api := client(t)
	api.SetSeries([]any{map[string]any{"group": []any{"b"}, "series_0.data": "2"}, map[string]any{"group": []any{"a"}, "series_0.data": "1"},
		map[string]any{"group": []any{"a"}, "series_0.data": 4}})
	rows, err := c.RecordCounts(ctx, "src", "x = 1", 300, "g")
	eq(t, "rows", []any{rows, err}, []any{[]compare.Row{{Record: "a", Count: 5}, {Record: "b", Count: 2}}, nil})
	body := api.SeriesRequests()[0]
	end, _ := body["endTime"].(float64)
	start, _ := body["startTime"].(float64)
	eq(t, "window", end-start, 300000)
	eq(t, "granularity", body["granularity"], "5m")
	eq(t, "series", body["series"], []any{map[string]any{"sourceId": "src", "aggFn": "count", "where": "x = 1",
		"whereLanguage": "sql", "groupBy": []any{"g"}}})
}

func TestAnHTTPErrorSaysWhatRequestsSaid(t *testing.T) {
	c, api := client(t)
	api.Fail = func(string, string, string) int { return 400 }
	_, err := c.ListAlerts(ctx)
	if err == nil || err.Error() != "400 Client Error: Bad Request for url: "+api.URL+"/api/v2/alerts" {
		t.Fatalf("err %v", err)
	}
}
