package incident

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/krateo-platformops/alert-troubleshooter/internal/httpx"
	"github.com/krateo-platformops/alert-troubleshooter/internal/pyfmt"
	"github.com/krateo-platformops/alert-troubleshooter/internal/report"
)

// A2A calls the RCA agent (incident-agent) with JSON-RPC message/stream.
type A2A struct {
	URL string
	// Timeout bounds the connection and every wait for the stream's next bytes, not the whole
	// call: an RCA streams for minutes.
	Timeout time.Duration
	// JWT is the service JWT the call presents; the agentgateway authenticates it and the agent
	// propagates it to its gated MCP tools and sub-agents.
	JWT func(context.Context) string
}

var a2aHTTP = &http.Client{}

// Analyze is the agent's answer and the tool results its tools actually returned. contextID names
// the kagent thread, the incident's own. The ledger is the ground truth report.Parse bounds
// confidence by, rather than the model's account of its own evidence.
func (a *A2A) Analyze(ctx context.Context, prompt, contextID string) (string, []report.ToolResult, error) {
	message := map[string]any{"kind": "message", "messageId": uuid.NewString(), "role": "user",
		"parts": []any{map[string]any{"kind": "text", "text": prompt}}}
	if contextID != "" {
		message["contextId"] = contextID
	}
	body, err := json.Marshal(map[string]any{"id": 1, "jsonrpc": "2.0", "method": "message/stream",
		"params": map[string]any{"message": message}})
	if err != nil {
		return "", nil, err
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var idle atomic.Bool
	timer := time.AfterFunc(a.Timeout, func() { idle.Store(true); cancel() })
	defer timer.Stop()
	timedOut := func(err error) error {
		if idle.Load() {
			return fmt.Errorf("%s: read timed out (read timeout=%s)", a.URL, a.Timeout)
		}
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.URL, bytes.NewReader(body))
	if err != nil {
		return "", nil, err
	}
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("Content-Type", "application/json")
	if jwt := a.JWT(ctx); jwt != "" {
		req.Header.Set("Authorization", "Bearer "+jwt)
	}
	resp, err := a2aHTTP.Do(req)
	if err != nil {
		return "", nil, timedOut(err)
	}
	defer resp.Body.Close()
	if err := httpx.Check(resp); err != nil {
		return "", nil, err
	}

	out := ""
	var ledger []report.ToolResult
	seen := map[[2]string]bool{}
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 64*1024), 64*1024*1024)
	for sc.Scan() {
		timer.Reset(a.Timeout)
		raw := sc.Text()
		if !strings.HasPrefix(raw, "data:") {
			continue
		}
		v, err := pyfmt.Decode([]byte(pyfmt.Strip(raw[len("data:"):])))
		if err != nil {
			continue
		}
		payload, _ := v.(map[string]any)
		result, _ := payload["result"].(map[string]any)
		status, _ := result["status"].(map[string]any)
		msg, _ := status["message"].(map[string]any)
		if !pyfmt.Truthy(msg) {
			msg, _ = result["message"].(map[string]any)
		}
		if msg["role"] != "agent" {
			continue
		}
		parts, _ := msg["parts"].([]any)
		// Collected before the text check below: a message carrying only tool results has no text
		// at all, and those are the very events that record a denial. The stream re-sends
		// cumulative snapshots, so they are de-duplicated by (name, payload).
		for _, tr := range toolResults(parts) {
			key := [2]string{tr.Name, tr.Payload}
			if !seen[key] {
				seen[key] = true
				ledger = append(ledger, tr)
			}
		}
		var text strings.Builder
		for _, p := range parts {
			pm, _ := p.(map[string]any)
			if t, ok := pm["text"].(string); ok && pm["kind"] == "text" && t != "" {
				text.WriteString(t)
			}
		}
		t := text.String()
		if t == "" {
			continue
		}
		// kagent's A2A stream re-sends cumulative snapshots of the message (and repeats the final
		// one). Replace when the new text extends what is already there (a snapshot), skip an
		// exact-duplicate tail, else append (a delta).
		if strings.HasPrefix(t, out) {
			out = t
		} else if !strings.HasSuffix(out, t) {
			out += t
		}
	}
	if err := sc.Err(); err != nil {
		return "", nil, timedOut(err)
	}
	return pyfmt.Strip(out), ledger, nil
}

// partType is a DataPart's ADK type (function_call, function_response, …). Both kagent runtimes
// put it in the part's metadata, not its data: the Go runtime as adk_type, the Python one as
// kagent_type.
func partType(part map[string]any) string {
	meta, ok := part["metadata"].(map[string]any)
	if !ok {
		return ""
	}
	for _, k := range []string{"adk_type", "kagent_type"} {
		if pyfmt.Truthy(meta[k]) {
			return pyfmt.Str(meta[k])
		}
	}
	return ""
}

// resultText is the text a tool returned. The Go runtime wraps it as {output} or {error}; the
// Python runtime passes the MCP result through as {content: [{type, text}], isError}.
func resultText(resp any) string {
	switch x := resp.(type) {
	case string:
		return x
	case map[string]any:
		if content, ok := x["content"].([]any); ok {
			var texts []string
			for _, c := range content {
				if cm, ok := c.(map[string]any); ok {
					if t, ok := cm["text"].(string); ok {
						texts = append(texts, t)
					}
				}
			}
			if len(texts) > 0 {
				return strings.Join(texts, "\n")
			}
		}
		for _, k := range []string{"error", "output", "result"} {
			switch v := x[k].(type) {
			case string:
				return v
			case map[string]any:
				return resultText(v)
			}
		}
	}
	return pyfmt.Dumps(resp)
}

// toolResults are the tool results in one A2A message. kagent mirrors every non-partial ADK event
// onto the status stream, so each tool result arrives as a DataPart typed function_response whose
// data is the GenAI FunctionResponse, {id, name, response}. kagent's exact part shape has changed
// before, so anything unrecognised yields nothing and the report degrades to model-declared
// retrieval.
func toolResults(parts []any) []report.ToolResult {
	var out []report.ToolResult
	for _, p := range parts {
		pm, ok := p.(map[string]any)
		if !ok {
			continue
		}
		data, ok := pm["data"].(map[string]any)
		if !ok || partType(pm) != "function_response" {
			continue
		}
		resp := data["response"]
		// Failed says the call errored, which tells a refusal the analyzer suffered from one it is
		// reporting. The runtimes flag it differently (error vs isError).
		failed := false
		if rm, ok := resp.(map[string]any); ok {
			failed = pyfmt.Truthy(rm["error"]) || pyfmt.Truthy(rm["isError"])
		}
		name := ""
		if pyfmt.Truthy(data["name"]) {
			name = pyfmt.Str(data["name"])
		}
		out = append(out, report.ToolResult{Name: name, Payload: resultText(resp), Failed: failed})
	}
	return out
}
