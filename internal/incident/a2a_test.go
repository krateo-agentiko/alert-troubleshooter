package incident

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/krateo-platformops/alert-troubleshooter/internal/golden"
)

// TestAnalyzeMatchesPython replays the streams hack/golden/generate.py fed Python's a2a_analyze:
// both kagent runtimes' real RCAs, and snapshot, delta and noise streams.
func TestAnalyzeMatchesPython(t *testing.T) {
	for i, c := range golden.Load(t, "testdata/a2a.json.gz") {
		var lines []string
		for _, l := range c["lines"].([]any) {
			lines = append(lines, l.(string))
		}
		var request map[string]any
		var headers http.Header
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			headers = r.Header
			_ = json.NewDecoder(r.Body).Decode(&request)
			w.Header().Set("Content-Type", "text/event-stream")
			for _, l := range lines {
				fmt.Fprintf(w, "%s\n", l)
			}
		}))
		a := &A2A{URL: srv.URL, Timeout: 5 * time.Second, JWT: func(context.Context) string { return "jwt" }}
		text, ledger, err := a.Analyze(context.Background(), "prompt", "ctx")
		srv.Close()
		if err != nil {
			t.Fatalf("case %d: %v", i, err)
		}
		if text != c["text"] {
			t.Errorf("case %d: text\n got %q\nwant %q", i, text, c["text"])
		}
		var got []map[string]any
		for _, r := range ledger {
			got = append(got, map[string]any{"name": r.Name, "payload": r.Payload, "failed": r.Failed})
		}
		if got == nil {
			got = []map[string]any{}
		}
		if d := golden.Diff(c["ledger"], got); d != "" {
			t.Errorf("case %d: ledger (-python +go):\n%s", i, d)
		}
		msg := request["params"].(map[string]any)["message"].(map[string]any)
		if request["method"] != "message/stream" || msg["contextId"] != "ctx" || msg["role"] != "user" ||
			msg["parts"].([]any)[0].(map[string]any)["text"] != "prompt" {
			t.Errorf("case %d: request %v", i, request)
		}
		if headers.Get("Authorization") != "Bearer jwt" || headers.Get("Accept") != "text/event-stream" {
			t.Errorf("case %d: headers %v", i, headers)
		}
	}
}

func TestAnIdleStreamTimesOut(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "data: {}\n")
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	defer srv.Close()
	a := &A2A{URL: srv.URL, Timeout: 200 * time.Millisecond, JWT: func(context.Context) string { return "" }}
	_, _, err := a.Analyze(context.Background(), "p", "")
	if err == nil || !strings.Contains(err.Error(), "read timed out") {
		t.Fatalf("err %v", err)
	}
}

func TestAnHTTPErrorFailsTheAnalysis(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()
	a := &A2A{URL: srv.URL, Timeout: time.Second, JWT: func(context.Context) string { return "" }}
	if _, _, err := a.Analyze(context.Background(), "p", ""); err == nil || !strings.HasPrefix(err.Error(), "502 Server Error: Bad Gateway for url: ") {
		t.Fatalf("err %v", err)
	}
}
