package report

// Evidence policy: the published confidence must reflect the evidence that was actually retrieved.
//
// An analysis that cannot read the cluster and says so is useful. One that cannot read the cluster
// and reports 0.97 spends the operator's trust on a conclusion drawn from a fraction of the
// intended evidence. The number is model-authored, and a prompt is a promise the model can break
// silently, so the ceiling the prompt states is also enforced here, on whatever the model returns.

import (
	"regexp"
	"sort"
	"strings"

	"github.com/krateo-platformops/alert-provider/internal/pyfmt"
)

var (
	retrievalOutcomes = []string{"success", "denied", "empty", "errored"}
	evidenceClasses   = []string{"k8s", "logs", "metrics", "repo", "other"}
)

// A depended-on source that came back denied (or errored) is an unknown, and an unknown bounds the
// ceiling rather than silently shrinking the evidence base. "success" and "empty" impose no
// ceiling: "there are no matching pods" is a real finding, which is why denied and empty must not
// collapse into the same absent section.
var confidenceCeiling = map[string]float64{"denied": 0.40, "errored": 0.60}

const noEvidenceCeiling = 0.20 // nothing cited and nothing read: no sources, no analyzed resources

// analyzerIdentity is the analyzer's own identity as it appears in an apiserver refusal ("User
// \"system:serviceaccount:krateo-system:krateo-alert-provider\" cannot list …"). It tells a denial
// the analyzer hit from one it is reporting on (see selfDenial).
const analyzerIdentity = "krateo-alert-provider"

var classLabel = map[string]string{"k8s": "k8s reads", "logs": "log queries", "metrics": "metrics reads",
	"repo": "repository reads", "other": "some reads"}

// A cited source was, by definition, retrieved: its type maps back to an evidence class.
var sourceTypeClass = map[string]string{"logs": "logs", "events": "k8s", "metrics": "metrics", "object": "k8s"}

var (
	denialRE = regexp.MustCompile(`(?i)\bforbidden\b|\bcannot (?:get|list|watch|create|patch|delete)\b` +
		`|\b403\b|rbac: access denied|permission denied|not authori[sz]ed` +
		`|\bunauthorized\b|is not allowed\b`)
	emptyRE = regexp.MustCompile(`(?i)\bno (?:matching|results|rows|records|such)\b|returned 0 rows` +
		`|\b0 rows\b|empty result|no items`)
	errorRE = regexp.MustCompile(`(?i)no healthy backend|timed out|timeout|connection refused` +
		`|\b(?:500|502|503|504)\b|internal server error|tool (?:call )?failed`)
	// Who a refusal names. `User "system:serviceaccount:ns:name"` gives the whole colon-joined subject.
	subjectRE = regexp.MustCompile(`(?i)user\s+"?([^"\s]+)`)
	// First-person phrasing: an unattributed refusal is the analyzer speaking about itself.
	selfRefRE = regexp.MustCompile(`(?i)\b(?:i|we)\s+(?:could ?n[o']?t|cannot|can't|was|were|am|are)\b` +
		`|\bunable to\b|\bwas denied\b|\bno (?:access|permission)\b` +
		`|\bcould not (?:read|list|get|query|access|retrieve|inspect|see)\b`)

	textK8sRE  = regexp.MustCompile(`\bk8s\b|kube|kubectl|pod|deployment|namespace|event|composition|resource|secret|node|service`)
	textLogsRE = regexp.MustCompile(`\blogs?\b|clickhouse|otel|hyperdx|query|trace`)
	textRepoRE = regexp.MustCompile(`\bgit\b|repo`)
	toolLogsRE = regexp.MustCompile(`clickhouse|otel|hyperdx|log|query|sql`)
)

func subjects(text string) []string {
	var out []string
	for _, m := range subjectRE.FindAllStringSubmatch(text, -1) {
		out = append(out, m[1])
	}
	return out
}

// selfDenial says text reports a refusal the analyzer hit, not one it is reporting on. A real,
// grounded RCA can have a third party's RBAC failure as its subject ("services is forbidden: User
// \"system:serviceaccount:krateo-system:installers-v0-2-219\" cannot list resource services"); a
// naive grep for forbidden would cap exactly the reports that work. So a free-text refusal counts
// as the analyzer's only when it names the analyzer, or names nobody and is in the first person.
func selfDenial(text string) bool {
	if !denialRE.MatchString(text) {
		return false
	}
	if subs := subjects(text); len(subs) > 0 {
		for _, sub := range subs {
			if strings.Contains(strings.ToLower(sub), analyzerIdentity) {
				return true
			}
		}
		return false
	}
	return selfRefRE.MatchString(text)
}

// classifyOutcome is the retrieval outcome a tool result, or a free-text description of one,
// reports. A successful read can return a refusal (listing events hands back somebody else's
// "… is forbidden"), so denial goes through selfDenial.
func classifyOutcome(text string) string {
	switch {
	case selfDenial(text):
		return "denied"
	case errorRE.MatchString(text):
		return "errored"
	case emptyRE.MatchString(text):
		return "empty"
	}
	return "success"
}

// textClass is a best-effort evidence class for a free-text retrieval failure. It drives the
// banner's wording only, never a ceiling.
func textClass(text string) string {
	s := strings.ToLower(text)
	switch {
	case textK8sRE.MatchString(s):
		return "k8s"
	case textLogsRE.MatchString(s):
		return "logs"
	case strings.Contains(s, "metric"):
		return "metrics"
	case textRepoRE.MatchString(s):
		return "repo"
	}
	return "other"
}

func toolClass(name string) string {
	n := strings.ToLower(name)
	switch {
	case strings.HasPrefix(n, "k8s_") || strings.Contains(n, "kube") || strings.Contains(n, "kubectl"):
		return "k8s"
	case toolLogsRE.MatchString(n):
		return "logs"
	case strings.Contains(n, "metric") || strings.Contains(n, "prometheus"):
		return "metrics"
	case strings.Contains(n, "git") || strings.Contains(n, "repo"):
		return "repo"
	}
	return "other"
}

// entry is one retrieval: an evidence class, the read's scope, its outcome and, for anything but a
// success, what came back. Scope is empty when absent; HasDetail says Detail is present, even
// empty (a failed tool call that returned nothing).
type entry struct {
	Source, Scope, Outcome, Detail string
	HasDetail                      bool
}

func (e entry) value() map[string]any {
	m := map[string]any{"source": e.Source, "outcome": e.Outcome}
	if e.Scope != "" {
		m["scope"] = e.Scope
	}
	if e.HasDetail {
		m["detail"] = e.Detail
	}
	return m
}

// declaredRetrieval is the model-declared retrieval ledger: [{source, scope, outcome, detail}].
func declaredRetrieval(v any) []entry {
	l, ok := v.([]any)
	if !ok {
		return nil
	}
	var out []entry
	for _, x := range head(l, 64) {
		m, ok := x.(map[string]any)
		if !ok {
			continue
		}
		o := obj(x, "source", "scope", "detail")
		get := func(k string) string {
			v, _ := o[k].(string)
			return v
		}
		e := entry{Scope: get("scope"), Detail: get("detail")}
		_, e.HasDetail = o["detail"]
		src := strings.ToLower(get("source"))
		if contains(evidenceClasses, src) {
			e.Source = src
		} else {
			e.Source = textClass(src + " " + e.Scope + " " + e.Detail)
		}
		oc, _ := s(m["outcome"])
		oc = strings.ToLower(oc)
		// An outcome that is not recognised must not quietly become "success": that is the silent
		// shrink this policy exists to stop. Re-derive it from the words instead.
		if contains(retrievalOutcomes, oc) {
			e.Outcome = oc
		} else {
			e.Outcome = classifyOutcome(oc + " " + e.Detail)
		}
		out = append(out, e)
	}
	return out
}

// toolSuccessOutcome is the outcome of a tool call the runtime did not flag as failed. Its text is
// data (a pod's `timeout=1s` probe, an Incident whose prompt quotes "Forbidden: cannot list pods"),
// so only a refusal that names the analyzer itself, or an empty result, moves it off success.
func toolSuccessOutcome(text string) string {
	if denialRE.MatchString(text) {
		for _, sub := range subjects(text) {
			if strings.Contains(strings.ToLower(sub), analyzerIdentity) {
				return "denied"
			}
		}
	}
	if emptyRE.MatchString(text) {
		return "empty"
	}
	return "success"
}

// fromToolLedger is the ground truth: the tool results lifted off the A2A stream. Failed means the
// call itself returned an error payload, so a refusal in it is unambiguously the analyzer's.
func fromToolLedger(ledger []ToolResult) []entry {
	var out []entry
	for _, t := range head(ledger, 64) {
		name, ok := str(t.Name, 128)
		if !ok {
			name = "tool"
		}
		payload, _ := str(t.Payload, 2048)
		var outcome string
		switch {
		case t.Failed && denialRE.MatchString(payload):
			outcome = "denied"
		case t.Failed:
			outcome = "errored"
		default:
			outcome = toolSuccessOutcome(payload)
		}
		e := entry{Source: toolClass(name), Scope: name, Outcome: outcome}
		if outcome != "success" { // a success needs no explanation; keep the CR status small
			e.Detail, e.HasDetail = pyfmt.Cut(payload, 512), true
		}
		out = append(out, e)
	}
	return out
}

// buildRetrievalLedger is one ledger of what the analysis got back, from three signals that cannot
// all be gamed at once: the model-declared "retrieval" entries; missingContext lines that read as
// a refusal or an empty result the analyzer itself hit; and the tool-result ledger off the A2A
// stream, the one layer a model cannot opt out of by omitting a field. Entries are unioned and the
// worst outcome per class governs, so a later signal can only add a constraint, never lift one.
func buildRetrievalLedger(declared any, missingContext []string, ledger []ToolResult) []entry {
	all := declaredRetrieval(declared)
	for _, line := range missingContext {
		if line, ok := s(line); ok {
			if outcome := classifyOutcome(line); outcome != "success" {
				all = append(all, entry{Source: textClass(line), Scope: "reported in missingContext",
					Outcome: outcome, Detail: pyfmt.Cut(line, 512), HasDetail: true})
			}
		}
	}
	all = append(all, fromToolLedger(ledger)...)
	seen := map[[3]string]bool{}
	var out []entry
	for _, e := range all {
		key := [3]string{e.Source, e.Scope, e.Outcome}
		if !seen[key] {
			seen[key] = true
			out = append(out, e)
		}
	}
	return head(out, 32)
}

var outcomeRank = map[string]int{"success": 0, "empty": 1, "errored": 2, "denied": 3}

// worstByClass is the outcome that governs each evidence class: the worst one seen, with one
// exception. A denial governs even beside a success: a class read twice, once fine and once
// refused, still misses whatever the refused read held. An error governs only when no call in its
// class succeeded ("success" or "empty"): one failed exploratory call among reads that worked
// leaves nothing the analysis depended on missing.
func worstByClass(ledger []entry) map[string]string {
	seen := map[string][]string{}
	var order []string
	for _, e := range ledger {
		c := e.Source
		if c == "" {
			c = "other"
		}
		if _, ok := seen[c]; !ok {
			order = append(order, c)
		}
		o := e.Outcome
		if o == "" {
			o = "success"
		}
		seen[c] = append(seen[c], o)
	}
	worst := map[string]string{}
	for _, c := range order {
		outcomes := seen[c]
		succeeded := false
		for _, o := range outcomes {
			if o == "success" || o == "empty" {
				succeeded = true
			}
		}
		for _, o := range outcomes {
			if succeeded && o == "errored" {
				continue
			}
			cur, ok := worst[c]
			if !ok {
				cur = "success"
			}
			if outcomeRank[o] >= outcomeRank[cur] {
				worst[c] = o
			}
		}
	}
	return worst
}

// retrievedClasses are the classes the analysis did get evidence from: ledger successes, plus
// anything it cites (a cited source was retrieved), minus any class a refusal or an error left
// incomplete, so the banner never says "based on k8s reads" about reads that were refused.
func retrievedClasses(v2 map[string]any, worst map[string]string) map[string]bool {
	got := map[string]bool{}
	for c, o := range worst {
		if o == "success" || o == "empty" {
			got[c] = true
		}
	}
	srcs, _ := v2["sources"].([]map[string]any)
	for _, src := range srcs {
		t, _ := src["type"].(string)
		if c, ok := sourceTypeClass[t]; ok {
			got[c] = true
		} else {
			got["k8s"] = true
		}
	}
	if v2["analyzedResources"] != nil {
		got["k8s"] = true
	}
	for c, o := range worst {
		if _, capped := confidenceCeiling[o]; capped {
			delete(got, c)
		}
	}
	return got
}

func labels(classes []string) string {
	sort.Strings(classes)
	l := make([]string, len(classes))
	for i, c := range classes {
		if lb, ok := classLabel[c]; ok {
			l[i] = lb
		} else {
			l[i] = classLabel["other"]
		}
	}
	if len(l) == 1 {
		return l[0]
	}
	return strings.Join(l[:len(l)-1], ", ") + " and " + l[len(l)-1]
}

// gapStatement is the operator-facing sentence: what was missing, and what the analysis therefore
// rests on, e.g. "k8s reads unavailable (Forbidden); analysis based on log queries only".
func gapStatement(worst map[string]string, retrieved map[string]bool, noEvidence bool) string {
	var missing []string
	for _, p := range []struct{ outcome, phrase string }{
		{"denied", "unavailable (Forbidden)"}, {"errored", "failed"}, {"empty", "returned no data"},
	} {
		var classes []string
		for c, o := range worst {
			if o == p.outcome {
				classes = append(classes, c)
			}
		}
		if len(classes) > 0 {
			missing = append(missing, labels(classes)+" "+p.phrase)
		}
	}
	if noEvidence && len(missing) == 0 {
		missing = append(missing, "no evidence source was read")
	}
	if len(missing) == 0 {
		return "all depended-on sources returned data"
	}
	if len(retrieved) > 0 {
		var classes []string
		for c := range retrieved {
			classes = append(classes, c)
		}
		missing = append(missing, "analysis based on "+labels(classes)+" only")
	} else {
		missing = append(missing, "no evidence was retrieved")
	}
	return strings.Join(missing, "; ")
}

// applyEvidencePolicy bounds the reported confidence by the evidence actually retrieved and says
// so in the report. It returns the prose and changes v2 in place:
//   - caps rootCause.confidence at the ceiling each class's governing outcome allows; the declared
//     value is kept under evidence.declaredConfidence, never quietly replaced;
//   - records evidence.{coverage,statement,retrieval}, so "denied" and "empty" stay apart;
//   - prepends a degraded-analysis banner to the prose and repeats it as the first missingContext
//     entry: the portal does not render the raw model confidence, so the capped number alone
//     would be invisible.
//
// It only ever lowers a declared confidence, and never invents one the model did not state.
func applyEvidencePolicy(prose string, v2 map[string]any, ledger []entry) string {
	root, _ := v2["rootCause"].(map[string]any)
	if root == nil {
		return prose // nothing concluded: no claim to qualify
	}
	worst := worstByClass(ledger)
	// "No k8s evidence" must not by itself cap: a self-referential telemetry-loop alert is
	// legitimately concluded from log records plus the Alert CR. Only an observed denial or error
	// moves the number; plain absence moves the coverage label. Cite nothing at all, though, and
	// there is no analysis to be confident about.
	anySuccess := false
	for _, e := range ledger {
		if e.Outcome == "success" {
			anySuccess = true
		}
	}
	noEvidence := v2["sources"] == nil && v2["analyzedResources"] == nil && !anySuccess
	var ceilings []float64
	denied, partial := false, false
	for _, o := range worst {
		if c, ok := confidenceCeiling[o]; ok {
			ceilings = append(ceilings, c)
		}
		denied = denied || o == "denied"
		partial = partial || o == "errored" || o == "empty"
	}
	if noEvidence {
		ceilings = append(ceilings, noEvidenceCeiling)
	}
	if len(ceilings) == 0 && len(ledger) == 0 {
		return prose // nothing to bound and nothing to record: byte-identical to before
	}
	retrieved := retrievedClasses(v2, worst)
	statement := gapStatement(worst, retrieved, noEvidence)
	coverage := "complete"
	switch {
	case noEvidence:
		coverage = "unavailable"
	case denied:
		coverage = "degraded"
	case partial:
		coverage = "partial"
	}
	evidence := map[string]any{"coverage": coverage, "statement": statement}
	if len(ceilings) > 0 {
		ceiling := ceilings[0]
		for _, c := range ceilings[1:] {
			ceiling = pyMin(ceiling, c)
		}
		declared, hasDeclared := root["confidence"].(string)
		bounded := ""
		// Compare floats: a declared 1.0 formats to "1", which sorts below "0.5" as a string.
		if f, ok := pyfmt.Float(declared); hasDeclared && ok && f > ceiling {
			bounded = formatConfidence(ceiling)
			root["confidence"] = bounded
			evidence["declaredConfidence"] = declared
		}
		evidence["confidenceCap"] = formatConfidence(ceiling)
		note := "> ⚠︎ **Degraded analysis** — " + statement + "."
		if bounded != "" {
			note += " Confidence bounded to " + bounded + " (the analysis declared " + declared + ")."
		}
		if prose != "" {
			prose = note + "\n\n" + prose
		} else {
			prose = note
		}
		gap := pyfmt.Upper1(statement)
		mc, _ := v2["missingContext"].([]string)
		if !contains(mc, gap) {
			v2["missingContext"] = append([]string{gap}, head(mc, 63)...)
		}
	}
	retrieval := make([]map[string]any, len(ledger))
	for i, e := range ledger {
		retrieval[i] = e.value()
	}
	evidence["retrieval"] = retrieval
	v2["evidence"] = evidence
	return prose
}
