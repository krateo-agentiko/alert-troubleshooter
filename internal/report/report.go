// Package report is the Incident's structured-investigation contract with the RCA agent
// (incident-agent). It owns both sides of the contract so they cannot drift:
//
//   - Instructions, appended to the RCA prompt, requires the agent to end its answer with one
//     fenced ```json block matching the v2 status fields.
//   - Parse defensively extracts and sanitizes that block into the Incident's status fields. It
//     never fails: a malformed or missing block degrades to a prose-only (v1) report.
//
// Sanitizing rules:
//   - unknown keys are dropped; wrong-typed values are coerced when safe, else dropped;
//   - sources[].type outside the enum falls back to "object" (evidence is kept, never lost);
//   - reasoningTrace[].evidenceRefs are validated against len(sources): out-of-bounds and non-int
//     indices are dropped (the step is kept: a step may lose a bad citation);
//   - steps are renumbered 1..N in the order given (the agent's order is authoritative);
//   - rootCause.confidence normalizes number-or-string to a "0.00"-style decimal string in [0,1];
//   - howToFix is precondition, apply and verify or nothing, plus an optional rollback and
//     applyAction (see howToFix);
//   - confidence is then bounded by the evidence that was actually retrieved (see policy.go).
package report

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"strings"

	"github.com/krateo-platformops/alert-provider/internal/pyfmt"
)

// Instructions are appended to the RCA prompt.
//
//go:embed instructions.txt
var Instructions string

var sourceTypes = []string{"logs", "events", "metrics", "object"}

// StatusKeys are the parsed keys the writer puts under the Incident's status. Parse also returns
// "evidence" (the retrieval ledger behind the confidence cap), which the Incident does not store:
// its operator-facing sentence is already in the prose and missingContext.
var StatusKeys = []string{"analyzedResources", "sources", "missingContext", "assumptions",
	"reasoningTrace", "rootCause", "howToFix"}

// status.howToFix: bash scripts. The incident controller runs precondition and verify in a
// read-only sandbox (exit 0 = the incident is gone, 1 = it holds, anything else = unknown); a human
// runs apply, and rollback to undo it.
var howToFixScripts = []string{"precondition", "apply", "verify"}

const (
	howToFixRollback = "rollback"
	scriptMaxChars   = 16384
	// status.howToFix.applyAction: apply as one Kubernetes API write, when it is one. The portal's
	// Apply button sends it as the clicking user, then marks the incident applied.
	howToFixAction = "applyAction"
)

var actionVerbs = []string{"patch", "create", "delete"}

// Deleting one of these takes everything under it along (the scripts' rule, too).
var actionNeverDelete = []string{"namespaces", "nodes", "customresourcedefinitions"}

// The patterns end in `\n?$` because Python's `$` also matches before a final newline.
var (
	// A Krateo composition's version is its chart's, dashed: composition.krateo.io/v1-12-36.
	apiVersionRE = regexp.MustCompile(`^([a-z0-9]([-a-z0-9.]*[a-z0-9])?/)?v[0-9]+((alpha|beta)[0-9]+|(-[0-9]+)+)?\n?$`)
	resourceRE   = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?\n?$`)
	nameRE       = regexp.MustCompile(`^[a-z0-9]([-a-z0-9.]*[a-z0-9])?\n?$`)
)

// Fence lines (```lang or bare ```), walked as sequential open/close pairs. A single pairing regex
// mis-pairs when a non-json block precedes (a ```yaml example's closing fence looks like a bare
// opener and swallows the prose up to the real ```json opener). The walker pairs fences in order
// and yields only blocks whose opener language is json or blank.
var fenceLineRE = regexp.MustCompile("(?m)^```([A-Za-z0-9_-]*)[ \t]*\r?$")

// ToolResult is one tool result the writer lifted off the A2A stream: the tool's name, the text it
// returned, and whether the call itself errored.
type ToolResult struct {
	Name    string
	Payload string
	Failed  bool
}

type block struct {
	lang       string
	start, end int
	body       string
}

// fencedBlocks are the properly paired fenced blocks, in document order.
func fencedBlocks(text string) []block {
	fences := fenceLineRE.FindAllStringSubmatchIndex(text, -1)
	var out []block
	for i := 0; i+1 < len(fences); i += 2 {
		opener, closer := fences[i], fences[i+1]
		out = append(out, block{
			lang:  strings.ToLower(text[opener[2]:opener[3]]),
			start: opener[0],
			end:   closer[1],
			body:  strings.Trim(text[opener[1]:closer[0]], "\n"),
		})
	}
	return out
}

// str is a string, or false. Scalars are coerced; containers are rejected.
func str(v any, limit int) (string, bool) {
	switch x := v.(type) {
	case string:
		x = pyfmt.Strip(x)
		if x == "" {
			return "", false
		}
		return pyfmt.Cut(x, limit), true
	case json.Number:
		return pyfmt.NumberStr(x), true
	}
	return "", false
}

func s(v any) (string, bool) { return str(v, 4096) }

func strList(v any, limit int) []string {
	l, ok := v.([]any)
	if !ok {
		return nil
	}
	var out []string
	for _, x := range head(l, limit) {
		if s, ok := s(x); ok {
			out = append(out, s)
		}
	}
	return out
}

func head[T any](l []T, n int) []T {
	if len(l) > n {
		return l[:n]
	}
	return l
}

// obj picks the named string fields off a dict; nil unless at least one is present.
func obj(v any, fields ...string) map[string]any {
	m, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	out := map[string]any{}
	for _, f := range fields {
		if s, ok := s(m[f]); ok {
			out[f] = s
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func objList(v any, fields ...string) []map[string]any {
	l, ok := v.([]any)
	if !ok {
		return nil
	}
	var out []map[string]any
	for _, x := range head(l, 64) {
		if o := obj(x, fields...); o != nil {
			out = append(out, o)
		}
	}
	return out
}

// pyMax and pyMin are Python's max(a, b) and min(a, b), NaN included.
func pyMax(a, b float64) float64 {
	if b > a {
		return b
	}
	return a
}

func pyMin(a, b float64) float64 {
	if b < a {
		return b
	}
	return a
}

// confidence is a number-or-string in 0..1 as a clamped decimal string ("0.85"), else false.
func confidence(v any) (string, bool) {
	var f float64
	switch x := v.(type) {
	case string:
		var ok bool
		if f, ok = pyfmt.Float(pyfmt.Strip(x)); !ok {
			return "", false
		}
	case json.Number:
		var ok bool
		if f, ok = pyfmt.Float(x); !ok {
			return "", false
		}
	case float64:
		f = x
	default:
		return "", false
	}
	return formatConfidence(f), true
}

func formatConfidence(f float64) string {
	c := pyMin(pyMax(f, 0), 1)
	if math.IsNaN(c) {
		return "nan"
	}
	out := strings.TrimRight(strings.TrimRight(fmt.Sprintf("%.2f", c), "0"), ".")
	if out == "" {
		return "0"
	}
	return out
}

func sources(v any) []map[string]any {
	l, ok := v.([]any)
	if !ok {
		return nil
	}
	var out []map[string]any
	for _, x := range head(l, 64) {
		o := obj(x, "ref", "excerpt")
		if o == nil {
			continue
		}
		t, _ := s(x.(map[string]any)["type"])
		if contains(sourceTypes, t) {
			o["type"] = t
		} else {
			o["type"] = "object" // keep the evidence, sane the enum
		}
		out = append(out, o)
	}
	return out
}

// trace keeps the ordered steps that have a statement, drops out-of-bounds evidenceRefs and
// renumbers the steps 1..N in the given order (the order is the trace).
func trace(v any, nSources int) []map[string]any {
	l, ok := v.([]any)
	if !ok {
		return nil
	}
	var out []map[string]any
	for _, x := range head(l, 64) {
		m, ok := x.(map[string]any)
		if !ok {
			continue
		}
		stmt, ok := s(m["statement"])
		if !ok {
			continue
		}
		good := []int{}
		if refs, ok := m["evidenceRefs"].([]any); ok {
			for _, r := range head(refs, 32) {
				n, ok := r.(json.Number)
				if !ok {
					continue
				}
				var i int
				if pyfmt.IsInt(n) {
					v, err := n.Int64()
					if err != nil {
						continue
					}
					i = int(v)
				} else {
					f, err := n.Float64()
					if err != nil || math.IsInf(f, 0) || f != math.Trunc(f) {
						continue
					}
					i = int(f)
				}
				if 0 <= i && i < nSources {
					good = append(good, i)
				}
			}
		}
		out = append(out, map[string]any{"step": len(out) + 1, "statement": stmt, "evidenceRefs": good})
	}
	return out
}

func rootCause(v any) map[string]any {
	o := obj(v, "statement", "category")
	if o == nil || o["statement"] == nil {
		return nil
	}
	if c, ok := confidence(v.(map[string]any)["confidence"]); ok {
		o["confidence"] = c
	}
	return o
}

// script is the script, or why it is unusable. A list of lines is joined. A script over
// scriptMaxChars is rejected, never truncated: a cut script is a different script.
func script(v any) (string, string) {
	if l, ok := v.([]any); ok && len(l) > 0 {
		lines := make([]string, 0, len(l))
		for _, x := range l {
			s, ok := x.(string)
			if !ok {
				lines = nil
				break
			}
			lines = append(lines, s)
		}
		if lines != nil {
			v = strings.Join(lines, "\n")
		}
	}
	x, ok := v.(string)
	if !ok || pyfmt.Strip(x) == "" {
		return "", "missing"
	}
	x = pyfmt.Strip(x)
	if pyfmt.Len(x) > scriptMaxChars {
		return "", fmt.Sprintf("over %d characters", scriptMaxChars)
	}
	return x + "\n", ""
}

func isEmptyDict(v any) bool {
	m, ok := v.(map[string]any)
	return ok && len(m) == 0
}

// applyAction is the applyAction, nil and "" when there is none, or nil and why it is unusable.
func applyAction(v any) (map[string]any, string) {
	if v == nil || isEmptyDict(v) {
		return nil, ""
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, "not an object"
	}
	verb, _ := m["verb"].(string)
	if _, isStr := m["verb"].(string); !isStr || !contains(actionVerbs, verb) {
		return nil, fmt.Sprintf("verb %s is not one of %s", pyfmt.Repr(m["verb"]), strings.Join(actionVerbs, ", "))
	}
	out := map[string]any{"verb": verb}
	for _, f := range []struct {
		key     string
		pattern *regexp.Regexp
		limit   int
	}{{"apiVersion", apiVersionRE, 128}, {"resource", resourceRE, 63}, {"name", nameRE, 253}} {
		val, ok := m[f.key].(string)
		if !ok || pyfmt.Len(val) > f.limit || !f.pattern.MatchString(val) {
			return nil, "bad " + f.key
		}
		out[f.key] = val
	}
	if ns, present := m["namespace"]; present && ns != nil && ns != "" {
		nss, ok := ns.(string)
		if !ok || pyfmt.Len(nss) > 63 || !resourceRE.MatchString(nss) {
			return nil, "bad namespace"
		}
		out["namespace"] = nss
	}
	payload := m["payload"]
	if verb == "delete" {
		if contains(actionNeverDelete, out["resource"].(string)) {
			return nil, "it deletes " + out["resource"].(string)
		}
		if payload != nil && !isEmptyDict(payload) {
			return nil, "a delete takes no payload"
		}
		return out, ""
	}
	p, ok := payload.(map[string]any)
	if !ok || len(p) == 0 {
		return nil, "no payload"
	}
	if len(pyfmt.Dumps(p)) > scriptMaxChars {
		return nil, fmt.Sprintf("payload over %d characters", scriptMaxChars)
	}
	if verb == "create" {
		meta, ok := p["metadata"].(map[string]any)
		if !ok {
			meta = map[string]any{}
		}
		// Python's meta.get("namespace", out.get("namespace")) != out.get("namespace").
		var want any
		if ns, ok := out["namespace"]; ok {
			want = ns
		}
		got := want
		if ns, ok := meta["namespace"]; ok {
			got = ns
		}
		_, kindIsStr := p["kind"].(string)
		if !eqStr(p["apiVersion"], out["apiVersion"]) || !kindIsStr || !eqStr(meta["name"], out["name"]) ||
			!(got == nil && want == nil || eqStr(got, want)) {
			return nil, "the payload's apiVersion, kind or metadata does not match the target"
		}
	}
	out["payload"] = p
	return out, ""
}

// howToFix holds all three howToFixScripts or is nil: the controller needs precondition and verify
// to move the incident, and the human needs apply, so a partial set is dropped whole and the rest
// of the report is kept. Rollback and applyAction are each kept when usable and otherwise left out
// alone, since the fix works without them; notes holds the missingContext line for each one left
// out. Other keys are dropped.
func howToFix(v any) (map[string]any, []string, []string) {
	if v == nil {
		return nil, []string{"none returned"}, nil
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, []string{"not an object"}, nil
	}
	out := map[string]any{}
	var problems []string
	for _, k := range howToFixScripts {
		sc, why := script(m[k])
		if why != "" {
			problems = append(problems, k+" "+why)
		} else {
			out[k] = sc
		}
	}
	if len(problems) > 0 {
		return nil, problems, nil
	}
	var notes []string
	if rb, why := script(m[howToFixRollback]); why != "" {
		notes = append(notes, noRollbackNote(why))
	} else {
		out[howToFixRollback] = rb
	}
	if action, why := applyAction(m[howToFixAction]); why != "" {
		notes = append(notes, noActionNote(why))
	} else if action != nil {
		out[howToFixAction] = action
	}
	return out, nil, notes
}

// noActionNote is the missingContext line for an applyAction that was left out.
func noActionNote(why string) string {
	return fmt.Sprintf("No usable applyAction (%s): the portal offers no Apply button, so run the apply script.", why)
}

// noFixNote is the missingContext line for a report whose howToFix was dropped.
func noFixNote(problems []string) string {
	return fmt.Sprintf("No usable howToFix (%s): the incident has no scripts to check or fix it.", strings.Join(problems, "; "))
}

// noRollbackNote is the missingContext line for a howToFix without a rollback.
func noRollbackNote(why string) string {
	return fmt.Sprintf("No usable rollback (%s): undoing apply is left to whoever runs it.", why)
}

type candidate struct {
	block block
	data  map[string]any
}

// candidateBlocks are the json or blank-language fenced blocks that parse as a JSON object naming
// at least one status key, the last first.
func candidateBlocks(text string) []candidate {
	var out []candidate
	blocks := fencedBlocks(text)
	for i := len(blocks) - 1; i >= 0; i-- {
		b := blocks[i]
		if b.lang != "" && b.lang != "json" {
			continue
		}
		v, err := pyfmt.Decode([]byte(b.body))
		if err != nil {
			continue
		}
		data, ok := v.(map[string]any)
		if !ok {
			continue
		}
		for _, k := range StatusKeys {
			if _, ok := data[k]; ok {
				out = append(out, candidate{block: b, data: data})
				break
			}
		}
	}
	return out
}

// Parse returns the prose and the v2 status fields of the agent's raw answer. The fields are empty
// when no valid structured block exists (v1 fallback); the prose is the answer with the block
// stripped, or the whole answer on fallback.
//
// ledger is the writer's ground truth about what the agent's tool calls returned, lifted off the
// A2A stream. When present it overrides what the model says about its own retrieval: a model that
// never mentions having been denied is the case the evidence policy exists for.
func Parse(text string, ledger []ToolResult) (string, map[string]any) {
	text = pyfmt.Strip(text)
	for _, c := range candidateBlocks(text) {
		data := c.data
		srcs := sources(data["sources"])
		fix, fixProblems, fixNotes := howToFix(data["howToFix"])
		v2 := map[string]any{}
		set := func(k string, v any, ok bool) {
			if ok {
				v2[k] = v
			}
		}
		ar := objList(data["analyzedResources"], "gvr", "name", "namespace", "whatWasRead")
		set("analyzedResources", ar, len(ar) > 0)
		set("sources", srcs, len(srcs) > 0)
		mc := strList(data["missingContext"], 64)
		set("missingContext", mc, len(mc) > 0)
		as := strList(data["assumptions"], 64)
		set("assumptions", as, len(as) > 0)
		tr := trace(data["reasoningTrace"], len(srcs))
		set("reasoningTrace", tr, len(tr) > 0)
		rc := rootCause(data["rootCause"])
		set("rootCause", rc, rc != nil)
		set("howToFix", fix, fix != nil)
		if len(v2) == 0 {
			continue // a JSON block with the right keys but no usable content: keep looking
		}
		prose := pyfmt.Strip(text[:c.block.start] + text[c.block.end:])
		if prose == "" { // the agent answered JSON only; keep the report readable
			if stmt, _ := rc["statement"].(string); stmt != "" {
				prose = stmt
			} else {
				prose = text
			}
		}
		prose = applyEvidencePolicy(prose, v2, buildRetrievalLedger(data["retrieval"], mc, ledger))
		// A root cause without usable scripts leaves the incident with nothing to check; the gaps
		// list is what the operator reads, so say why there.
		current, _ := v2["missingContext"].([]string)
		if len(fixProblems) > 0 && v2["rootCause"] != nil {
			v2["missingContext"] = append(head(current, 63), noFixNote(fixProblems))
		} else if len(fixNotes) > 0 {
			v2["missingContext"] = append(head(current, 64-len(fixNotes)), fixNotes...)
		}
		return prose, v2
	}
	// The fallback stays byte-identical: the writer tells an empty answer by an empty prose and no
	// fields, and a banner here would make an empty A2A reply look like a result.
	return text, map[string]any{}
}

// eqStr is Python's a == b where both must be strings to be equal.
func eqStr(a, b any) bool {
	as, ok := a.(string)
	bs, ok2 := b.(string)
	return ok && ok2 && as == bs
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}
