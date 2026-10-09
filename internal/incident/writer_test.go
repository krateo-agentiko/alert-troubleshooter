package incident

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	apierrors "k8s.io/apimachinery/pkg/api/errors"

	"github.com/krateo-platformops/provider-runtime/pkg/logging"

	"github.com/krateo-platformops/alert-provider/internal/compare"
	"github.com/krateo-platformops/alert-provider/internal/golden"
	"github.com/krateo-platformops/alert-provider/internal/report"
)

const (
	ns        = "krateo-system"
	alertName = "cd-not-ready"
	hold      = 1800 * time.Second
)

var how = map[string]any{
	"precondition": "#!/usr/bin/env bash\n# holds while fireworksapp is not Ready\nexit 1\n",
	"apply":        "#!/usr/bin/env bash\n# pin chart 1.1.10\ntrue\n",
	"verify":       "#!/usr/bin/env bash\n# fixed once Ready\nexit 0\n",
}

func block(fix any) map[string]any {
	return map[string]any{
		"sources":   []any{map[string]any{"type": "object", "ref": "cd/fireworksapp", "excerpt": "Ready=False"}},
		"rootCause": map[string]any{"statement": "chart 1.1.9 is missing", "confidence": 0.8, "category": "config"},
		"howToFix":  fix,
	}
}

func answer(b map[string]any) string {
	j, _ := json.Marshal(b)
	return "## Root cause\nchart 1.1.9 is missing\n\n```json\n" + string(j) + "\n```"
}

func ago(d time.Duration) string {
	return time.Now().UTC().Add(-d).Format("2006-01-02T15:04:05Z")
}

// writerCase is a Writer over a fakeKube, with the RCA and the comparison stubbed.
type writerCase struct {
	t    *testing.T
	kube *fakeKube
	w    *Writer
	log  *logLines

	mu sync.Mutex
	// rca are the RCA calls (prompt, contextID); answer is what the RCA returns, or rcaErr;
	// duringRCA runs inside it.
	rca       [][2]string
	answer    string
	rcaErr    error
	duringRCA func()
	// compared are the comparison calls; match is the incident it names ("" none), or matchErr.
	compared [][]string
	prompts  []string
	match    string
	matchErr error
	slow     func()
	// records are the alert's current records, or recordsErr; reads are its reads.
	records    []compare.Row
	recordsErr error
	reads      []string
}

func newCase(t *testing.T) *writerCase {
	c := &writerCase{t: t, kube: newFakeKube(), log: &logLines{}, answer: answer(block(how)),
		records: []compare.Row{{Record: "Pod cd/fireworksapp-1: BackOff", Count: 3}}}
	c.w = newWriter(Config{Namespace: ns, MaxConcurrentAnalyses: 2, FailedAnalysisHold: hold, MaxCandidates: compare.DefaultMaxCandidates},
		c.kube, c.analyze, c.compare, c.log)
	return c
}

func (c *writerCase) analyze(_ context.Context, prompt, contextID string) (string, []report.ToolResult, error) {
	c.mu.Lock()
	c.rca = append(c.rca, [2]string{prompt, contextID})
	during := c.duringRCA
	c.mu.Unlock()
	if during != nil {
		during()
	}
	return c.answer, nil, c.rcaErr
}

func (c *writerCase) compare(_ context.Context, prompt string, names []string) (string, string, error) {
	c.mu.Lock()
	c.compared = append(c.compared, names)
	c.prompts = append(c.prompts, prompt)
	slow := c.slow
	c.mu.Unlock()
	if slow != nil {
		slow()
	}
	return c.match, "stub", c.matchErr
}

func (c *writerCase) recordsOf(_ context.Context, where string, seconds int) ([]compare.Row, error) {
	c.reads = append(c.reads, fmt.Sprintf("%s|%d", where, seconds))
	return c.records, c.recordsErr
}

type fireOpt struct {
	alert, ns, where, interval string
}

func (c *writerCase) fire(o fireOpt) {
	if o.alert == "" {
		o.alert = alertName
	}
	if o.ns == "" {
		o.ns = ns
	}
	if o.where == "" {
		o.where = "Body LIKE '%x%'"
	}
	c.w.Fire(context.Background(), Alert{Namespace: o.ns, Alert: compare.Alert{
		Name: o.alert, DisplayName: "CompositionDefinition not ready", Where: o.where, Interval: o.interval, Threshold: "1"}},
		c.recordsOf)
}

// analyzed is an open incident of the alert with an analysis, which a firing is compared with.
func (c *writerCase) analyzed(name, created, state string) {
	if created == "" {
		created = "2026-09-25T10:00:00Z"
	}
	if state == "" {
		state = "Open"
	}
	c.kube.put(ns, name, alertName, seed{state: state, created: created, rootCause: "the cause of " + name})
}

func st(obj map[string]any) map[string]any { return obj["status"].(map[string]any) }

// logLines is a logger that keeps every Info message.
type logLines struct {
	mu    sync.Mutex
	lines []string
}

func (l *logLines) Info(msg string, _ ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, msg)
}
func (l *logLines) Debug(string, ...any)             {}
func (l *logLines) Warn(string, ...any)              {}
func (l *logLines) Error(error, string, ...any)      {}
func (l *logLines) WithValues(...any) logging.Logger { return l }
func (l *logLines) WithName(string) logging.Logger   { return l }

// took is how many firings the incident name covered.
func (c *writerCase) took(name string) int {
	c.log.mu.Lock()
	defer c.log.mu.Unlock()
	n := 0
	for _, l := range c.log.lines {
		if strings.HasPrefix(l, "[incident] "+ns+"/"+name+": covers the firing") {
			n++
		}
	}
	return n
}

func eq(t *testing.T, what string, got, want any) {
	t.Helper()
	if d := golden.Diff(want, got); d != "" {
		t.Errorf("%s (-want +got):\n%s", what, d)
	}
}

func TestIncidentName(t *testing.T) {
	at := time.Date(2026, 9, 25, 14, 0, 5, 0, time.UTC)
	eq(t, "name", IncidentName(alertName, at), "cd-not-ready-20260925-140005")
}

func TestAFirstFiringOpensAnIncidentAndWritesItsAnalysis(t *testing.T) {
	c := newCase(t)
	c.fire(fireOpt{})
	inc := c.kube.only(ns)
	meta := inc["metadata"].(map[string]any)
	name := meta["name"].(string)
	if !regexp.MustCompile(`^cd-not-ready-\d{8}-\d{6}$`).MatchString(name) {
		t.Errorf("name %q", name)
	}
	eq(t, "labels", meta["labels"], map[string]any{LabelAlert: alertName})
	spec := inc["spec"].(map[string]any)
	eq(t, "alertRef", spec["alertRef"], map[string]any{"name": alertName, "namespace": ns})
	eq(t, "trigger", spec["trigger"], "alert")
	if !strings.Contains(spec["prompt"].(string), "`Body LIKE '%x%'`") {
		t.Errorf("prompt %q", spec["prompt"])
	}
	s := st(inc)
	eq(t, "state", s["state"], "Open")
	eq(t, "howToFix", s["howToFix"], how)
	eq(t, "rootCause", s["rootCause"].(map[string]any)["statement"], "chart 1.1.9 is missing")
	if !strings.HasPrefix(s["report"].(string), "## Root cause") {
		t.Errorf("report %q", s["report"])
	}
	for _, k := range []string{"completedAt"} {
		if _, ok := s[k]; !ok {
			t.Errorf("no %s", k)
		}
	}
	for _, k := range []string{"error", "evidence", "firings", "lastFiredAt"} { // the Incident CRD has none of the last three
		if _, ok := s[k]; ok {
			t.Errorf("%s set: %v", k, s[k])
		}
	}
	eq(t, "rca", c.rca, [][2]string{{spec["prompt"].(string), uuid.NewSHA1(uuid.NameSpaceDNS, []byte(name)).String()}})
}

func TestItIsAnalyzingUntilTheAnalysisIsWritten(t *testing.T) {
	c := newCase(t)
	c.fire(fireOpt{})
	w := c.kube.statusWrites()
	first, last := w[0], w[len(w)-1]
	eq(t, "first", first, map[string]any{"state": "Analyzing"})
	eq(t, "last state", last["state"], "Open")
	if _, ok := last["howToFix"]; !ok { // Open and its scripts land in one write
		t.Error("no howToFix in the last write")
	}
}

func TestTheIncidentLivesInTheAlertsNamespace(t *testing.T) {
	c := newCase(t)
	c.fire(fireOpt{ns: "team-a"})
	eq(t, "namespace", c.kube.only("team-a")["spec"].(map[string]any)["alertRef"].(map[string]any)["namespace"], "team-a")
}

func TestAnAlertNameOver63CharactersOpensNothing(t *testing.T) {
	c := newCase(t)
	c.fire(fireOpt{alert: strings.Repeat("a", 64)})
	eq(t, "incidents", c.kube.count(), 0)
	eq(t, "rca", len(c.rca), 0)
}

func TestAWebhookNotificationOpensNothing(t *testing.T) {
	c := newCase(t)
	Process(logging.NewNopLogger(), map[string]any{"alertName": "🚨 " + alertName, "state": "ALERT"})
	eq(t, "calls", len(c.kube.calls), 0)
}

func TestTheSameProblemIsCoveredByItsIncidentAndWritesNothing(t *testing.T) {
	c := newCase(t)
	for i, state := range []string{"Open", "Verifying"} {
		c.kube.clear()
		c.analyzed(alertName+"-x", "", state)
		c.match = alertName + "-x"
		c.fire(fireOpt{})
		eq(t, "covered", c.took(alertName+"-x"), i+1)
		eq(t, "state", st(c.kube.only(ns))["state"], state)
	}
	eq(t, "status writes", len(c.kube.statusWrites()), 0)
	eq(t, "rca", len(c.rca), 0)
}

func TestADifferentProblemOpensASecondIncident(t *testing.T) {
	c := newCase(t)
	c.analyzed(alertName+"-x", "", "")
	c.fire(fireOpt{})
	eq(t, "compared", c.compared, [][]string{{alertName + "-x"}})
	eq(t, "incidents", c.kube.count(), 2)
	eq(t, "rca", len(c.rca), 1)
	eq(t, "covered", c.took(alertName+"-x"), 0)
}

func TestAllOpenIncidentsAreComparedInOneCallAndTheMatchTakesTheFiring(t *testing.T) {
	c := newCase(t)
	c.analyzed(alertName+"-old", "2026-09-25T08:00:00Z", "")
	c.analyzed(alertName+"-mid", "2026-09-25T09:00:00Z", "")
	c.analyzed(alertName+"-new", "2026-09-25T10:00:00Z", "")
	c.match = alertName + "-mid"
	c.fire(fireOpt{})
	eq(t, "compared", c.compared, [][]string{{alertName + "-new", alertName + "-mid", alertName + "-old"}})
	eq(t, "mid", c.took(alertName+"-mid"), 1)
	eq(t, "old", c.took(alertName+"-old"), 0)
}

func TestTheComparisonSeesTheAlertItsRecordsAndTheIncident(t *testing.T) {
	c := newCase(t)
	c.analyzed(alertName+"-x", "", "")
	c.fire(fireOpt{where: "Body LIKE '%boom%'", interval: "15m"})
	p := c.prompts[0]
	for _, want := range []string{"`Body LIKE '%boom%'`", "- 3× Pod cd/fireworksapp-1: BackOff", "the cause of " + alertName + "-x"} {
		if !strings.Contains(p, want) {
			t.Errorf("prompt lacks %q", want)
		}
	}
	eq(t, "reads", c.reads, []string{"Body LIKE '%boom%'|900"})
}

func TestOnlyTheNewestCandidatesAreCompared(t *testing.T) {
	c := newCase(t)
	max := compare.DefaultMaxCandidates
	for n := range max + 2 {
		c.analyzed(fmt.Sprintf("%s-%02d", alertName, n), fmt.Sprintf("2026-09-25T10:%02d:00Z", n), "")
	}
	c.fire(fireOpt{})
	names := c.compared[0]
	eq(t, "len", len(names), max)
	eq(t, "first", names[0], fmt.Sprintf("%s-%02d", alertName, max+1))
	for _, n := range names {
		if n == alertName+"-00" {
			t.Error("the oldest was compared")
		}
	}
}

func TestUnreadableRecordsAreNoVerdict(t *testing.T) {
	c := newCase(t)
	c.analyzed(alertName+"-x", "", "")
	c.recordsErr = errors.New("HyperDX is down")
	c.fire(fireOpt{})
	eq(t, "compared", len(c.compared), 0)
	eq(t, "rca", len(c.rca), 0)
	eq(t, "covered", c.took(alertName+"-x"), 0)
}

func TestNoMatchingRecordsAreNoVerdict(t *testing.T) {
	c := newCase(t)
	c.analyzed(alertName+"-x", "", "")
	c.records = nil
	c.fire(fireOpt{})
	eq(t, "compared", len(c.compared), 0)
	eq(t, "rca", len(c.rca), 0)
	eq(t, "incidents", c.kube.count(), 1)
	eq(t, "covered", c.took(alertName+"-x"), 0)
}

func TestNoMatchingRecordsAreStillCoveredByAnIncidentWithoutAnAnalysis(t *testing.T) {
	c := newCase(t)
	c.analyzed(alertName+"-x", "2026-09-25T09:00:00Z", "")
	c.kube.put(ns, alertName+"-a", alertName, seed{state: "Analyzing"})
	c.records = nil
	c.fire(fireOpt{})
	eq(t, "compared", len(c.compared), 0)
	eq(t, "covered", c.took(alertName+"-a"), 1)
	eq(t, "incidents", c.kube.count(), 2)
}

func TestRecordsAreNotReadWithNothingToCompare(t *testing.T) {
	c := newCase(t)
	c.fire(fireOpt{})
	eq(t, "reads", len(c.reads), 0)
	eq(t, "rca", len(c.rca), 1)
}

func TestAnIncidentWithoutAnAnalysisTakesTheFiringUncompared(t *testing.T) {
	c := newCase(t)
	for i, state := range []string{"Analyzing", "Open", "Verifying"} {
		c.kube.clear()
		c.kube.put(ns, alertName+"-x", alertName, seed{state: state})
		c.fire(fireOpt{})
		eq(t, state, c.took(alertName+"-x"), i+1)
	}
	eq(t, "compared", len(c.compared), 0)
	eq(t, "rca", len(c.rca), 0)
}

func TestAFailedRCAWithErrorProseTakesTheFiringUncompared(t *testing.T) {
	c := newCase(t)
	c.kube.put(ns, alertName+"-x", alertName, seed{state: "Open"})
	c.kube.writeStatus(ns, alertName+"-x", map[string]any{"report": "LLM error: 429 Too Many Requests",
		"error": "The analysis returned no structured block, so the incident has no scripts to check or fix it."})
	c.fire(fireOpt{})
	eq(t, "covered", c.took(alertName+"-x"), 1)
	eq(t, "compared", len(c.compared), 0)
	eq(t, "rca", len(c.rca), 0)
}

func TestAFailedRCAStopsTakingFiringsAfterTheHold(t *testing.T) {
	c := newCase(t)
	c.kube.put(ns, alertName+"-x", alertName, seed{state: "Open", completed: ago(hold + time.Minute)})
	c.kube.writeStatus(ns, alertName+"-x", map[string]any{"error": "The analysis failed: 429"})
	c.fire(fireOpt{})
	x := st(c.kube.get(ns, alertName+"-x"))
	eq(t, "covered", c.took(alertName+"-x"), 0)
	eq(t, "state", x["state"], "Open")
	eq(t, "incidents", c.kube.count(), 2)
	eq(t, "rca", len(c.rca), 1)
}

func TestAFailedRCAInsideTheHoldStillTakesTheFiring(t *testing.T) {
	c := newCase(t)
	c.kube.put(ns, alertName+"-x", alertName, seed{state: "Open", completed: ago(hold - time.Minute)})
	c.kube.writeStatus(ns, alertName+"-x", map[string]any{"error": "The analysis failed: 429"})
	c.fire(fireOpt{})
	eq(t, "covered", c.took(alertName+"-x"), 1)
	eq(t, "rca", len(c.rca), 0)
}

func TestAnIncidentStillAnalyzingTakesFiringsPastTheHold(t *testing.T) {
	c := newCase(t)
	c.kube.put(ns, alertName+"-x", alertName, seed{state: "Analyzing", created: ago(hold + time.Minute)})
	c.fire(fireOpt{})
	eq(t, "covered", c.took(alertName+"-x"), 1)
	eq(t, "rca", len(c.rca), 0)
}

func TestTheHoldCountsFromCreationWithoutCompletedAt(t *testing.T) {
	old := map[string]any{"metadata": map[string]any{"creationTimestamp": ago(hold + time.Minute)},
		"status": map[string]any{"state": "Open", "error": "The analysis failed: 429"}}
	now := time.Now()
	if holdsFirings(old, now, hold) {
		t.Error("held past the hold")
	}
	if !holdsFirings(old, now, hold+10*time.Minute) {
		t.Error("did not hold inside a longer hold")
	}
}

func TestAnEqualAnalyzedIncidentTakesTheFiringBeforeAnAnalyzingOne(t *testing.T) {
	c := newCase(t)
	c.analyzed(alertName+"-x", "2026-09-25T09:00:00Z", "")
	c.kube.put(ns, alertName+"-y", alertName, seed{state: "Analyzing", created: "2026-09-25T10:00:00Z"})
	c.match = alertName + "-x"
	c.fire(fireOpt{})
	eq(t, "x", c.took(alertName+"-x"), 1)
	eq(t, "y", c.took(alertName+"-y"), 0)
}

func TestADifferentProblemWaitsOnAnIncidentStillAnalyzing(t *testing.T) {
	c := newCase(t)
	c.analyzed(alertName+"-x", "2026-09-25T09:00:00Z", "")
	c.kube.put(ns, alertName+"-y", alertName, seed{state: "Analyzing", created: "2026-09-25T10:00:00Z"})
	c.fire(fireOpt{})
	eq(t, "y", c.took(alertName+"-y"), 1)
	eq(t, "incidents", c.kube.count(), 2)
	eq(t, "rca", len(c.rca), 0)
}

func TestNoVerdictOpensNothingAndCoversNothing(t *testing.T) {
	c := newCase(t)
	c.analyzed(alertName+"-x", "", "")
	c.matchErr = &compare.NoVerdict{Reason: "rate-limited"}
	c.fire(fireOpt{})
	eq(t, "covered", c.took(alertName+"-x"), 0)
	eq(t, "rca", len(c.rca), 0)
}

func TestAnEvaluationStillRunningSkipsTheAlertsNextFiring(t *testing.T) {
	c := newCase(t)
	c.analyzed(alertName+"-x", "", "")
	c.match = alertName + "-x"
	c.slow = func() {
		c.mu.Lock()
		c.slow = nil
		c.mu.Unlock()
		c.fire(fireOpt{}) // the next pass, while this comparison runs
	}
	c.fire(fireOpt{})
	eq(t, "covered", c.took(alertName+"-x"), 1)
	eq(t, "firing", len(c.w.firing), 0)
}

func TestAnEndedIncidentDoesNotCoverANewFiringOpensOne(t *testing.T) {
	c := newCase(t)
	c.kube.put(ns, alertName+"-resolved", alertName, seed{state: "Resolved"})
	c.kube.writeStatus(ns, alertName+"-resolved", map[string]any{"resolution": map[string]any{"by": "verify", "at": ago(time.Hour)}})
	c.kube.put(ns, alertName+"-closed", alertName, seed{state: "Closed"})
	c.fire(fireOpt{})
	eq(t, "incidents", c.kube.count(), 3)
	eq(t, "rca", len(c.rca), 1)
	eq(t, "compared", len(c.compared), 0)
	eq(t, "resolved", c.took(alertName+"-resolved"), 0)
}

func TestAnotherAlertsIncidentDoesNotCover(t *testing.T) {
	c := newCase(t)
	c.kube.put(ns, "other-x", "other", seed{state: "Open"})
	c.fire(fireOpt{})
	eq(t, "incidents", c.kube.count(), 2)
}

func TestTheNewestUnanalyzedIncidentCovers(t *testing.T) {
	c := newCase(t)
	c.kube.put(ns, alertName+"-old", alertName, seed{state: "Open", created: "2026-09-25T09:00:00Z"})
	c.kube.put(ns, alertName+"-new", alertName, seed{state: "Open", created: "2026-09-25T10:00:00Z"})
	c.fire(fireOpt{})
	eq(t, "new", c.took(alertName+"-new"), 1)
	eq(t, "old", c.took(alertName+"-old"), 0)
}

func TestAConcurrentCreateCoversTheFiring(t *testing.T) {
	c := newCase(t)
	c.kube.beforeCreate = func(n, name string) {
		if c.kube.count() == 0 {
			c.kube.put(n, name, alertName, seed{state: "Analyzing"})
		}
	}
	c.fire(fireOpt{})
	name := c.kube.only(ns)["metadata"].(map[string]any)["name"].(string)
	eq(t, "covered", c.took(name), 1)
	eq(t, "rca", len(c.rca), 0)
}

func TestAnAPIServerFailureLosesTheFiringNotTheCaller(t *testing.T) {
	c := newCase(t)
	c.kube.fail = apierrors.NewInternalError(errors.New("down"))
	c.fire(fireOpt{}) // does not panic
	eq(t, "rca", len(c.rca), 0)
}

// --- the Resolved grace window ---

func (c *writerCase) ended(name, state string, since time.Duration, created string) {
	if created == "" {
		created = "2026-09-25T10:00:00Z"
	}
	c.kube.put(ns, name, alertName, seed{state: state, created: created})
	by := "user"
	if state == "Resolved" {
		by = "verify"
	}
	c.kube.writeStatus(ns, name, map[string]any{"resolution": map[string]any{"by": by, "at": ago(since)}})
}

func TestInsideTheWindowTheResolvedIncidentCoversTheFiring(t *testing.T) {
	c := newCase(t)
	c.ended(alertName+"-r", "Resolved", time.Minute, "")
	c.fire(fireOpt{})
	s := st(c.kube.only(ns))
	eq(t, "state", s["state"], "Resolved")
	eq(t, "covered", c.took(alertName+"-r"), 1)
	eq(t, "rca", len(c.rca), 0)
}

func TestOutsideTheWindowANewIncidentOpens(t *testing.T) {
	c := newCase(t)
	c.ended(alertName+"-r", "Resolved", 10*time.Minute, "")
	c.fire(fireOpt{})
	eq(t, "incidents", c.kube.count(), 2)
	eq(t, "rca", len(c.rca), 1)
}

func TestAClosedIncidentNeverTakesAFiring(t *testing.T) {
	c := newCase(t)
	c.ended(alertName+"-c", "Closed", 10*time.Second, "")
	c.fire(fireOpt{})
	eq(t, "incidents", c.kube.count(), 2)
	eq(t, "closed", c.took(alertName+"-c"), 0)
}

func TestOnlyTheLatestIncidentGivesGrace(t *testing.T) {
	c := newCase(t)
	c.ended(alertName+"-r", "Resolved", 30*time.Second, "2026-09-25T09:00:00Z")
	c.ended(alertName+"-c", "Closed", 10*time.Second, "2026-09-25T10:00:00Z")
	c.fire(fireOpt{})
	eq(t, "incidents", c.kube.count(), 3)
}

func TestAnOpenIncidentTakesPrecedence(t *testing.T) {
	c := newCase(t)
	c.kube.put(ns, alertName+"-o", alertName, seed{state: "Open", created: "2026-09-25T09:00:00Z"})
	c.ended(alertName+"-r", "Resolved", 10*time.Second, "2026-09-25T10:00:00Z")
	c.fire(fireOpt{})
	eq(t, "o", c.took(alertName+"-o"), 1)
	eq(t, "r", c.took(alertName+"-r"), 0)
}

func TestADifferentProblemInsideTheWindowIsCoveredByTheResolvedIncident(t *testing.T) {
	c := newCase(t)
	c.analyzed(alertName+"-o", "2026-09-25T09:00:00Z", "")
	c.ended(alertName+"-r", "Resolved", 10*time.Second, "2026-09-25T10:00:00Z")
	c.fire(fireOpt{})
	eq(t, "compared", c.compared, [][]string{{alertName + "-o"}})
	eq(t, "r", c.took(alertName+"-r"), 1)
	eq(t, "incidents", c.kube.count(), 2)
	eq(t, "rca", len(c.rca), 0)
}

func TestNoVerdictInsideTheWindowIsCoveredByTheResolvedIncident(t *testing.T) {
	c := newCase(t)
	c.analyzed(alertName+"-o", "2026-09-25T09:00:00Z", "")
	c.ended(alertName+"-r", "Resolved", 10*time.Second, "2026-09-25T10:00:00Z")
	c.matchErr = &compare.NoVerdict{Reason: "rate-limited"}
	c.fire(fireOpt{})
	eq(t, "r", c.took(alertName+"-r"), 1)
}

func TestTheWindowIsTheAlertsInterval(t *testing.T) {
	for _, tc := range []struct {
		interval string
		since    time.Duration
		counted  bool
	}{{"15m", 600 * time.Second, true}, {"1m", 90 * time.Second, false}, {"", 200 * time.Second, true}, {"weird", 400 * time.Second, false}} {
		c := newCase(t)
		c.ended(alertName+"-r", "Resolved", tc.since, "")
		c.fire(fireOpt{interval: tc.interval})
		eq(t, tc.interval, c.kube.count() == 1, tc.counted)
	}
}

func TestTheBoundaryIsExclusive(t *testing.T) {
	resolved := time.Date(2026, 9, 25, 14, 0, 0, 0, time.UTC)
	inc := map[string]any{"metadata": map[string]any{"name": "r", "creationTimestamp": "t"},
		"status": map[string]any{"state": "Resolved", "resolution": map[string]any{"by": "verify", "at": "2026-09-25T14:00:00Z"}}}
	grace := 300 * time.Second
	if !resolvedWithin(inc, resolved.Add(299*time.Second), grace) {
		t.Error("299 s is inside")
	}
	if resolvedWithin(inc, resolved.Add(300*time.Second), grace) {
		t.Error("300 s is outside")
	}
	for _, broken := range []map[string]any{{}, {"by": "verify"}, {"by": "verify", "at": "not a time"}} {
		inc["status"].(map[string]any)["resolution"] = broken
		if resolvedWithin(inc, resolved, grace) {
			t.Errorf("%v is within", broken)
		}
	}
}

// --- the analysis ---

func TestAtMostMaxConcurrentAnalysesRCAsRunAtOnce(t *testing.T) {
	c := newCase(t)
	var mu sync.Mutex
	running, peak := 0, 0
	c.w.analyze = func(context.Context, string, string) (string, []report.ToolResult, error) {
		mu.Lock()
		running++
		peak = max(peak, running)
		mu.Unlock()
		time.Sleep(50 * time.Millisecond)
		mu.Lock()
		running--
		mu.Unlock()
		return answer(block(how)), nil, nil
	}
	var wg sync.WaitGroup
	for i := range 5 {
		name := fmt.Sprintf("%s-%d", alertName, i)
		c.kube.put(ns, name, alertName, seed{state: "Analyzing"})
		wg.Add(1)
		go func() { defer wg.Done(); c.w.RunAnalysis(context.Background(), ns, name, "p") }()
	}
	wg.Wait()
	eq(t, "peak", peak, 2)
}

func TestAFailedRCAOpensTheIncidentWithTheError(t *testing.T) {
	c := newCase(t)
	c.rcaErr = errors.New("A2A timed out")
	c.fire(fireOpt{})
	s := st(c.kube.only(ns))
	eq(t, "state", s["state"], "Open")
	if !strings.Contains(s["error"].(string), "A2A timed out") {
		t.Errorf("error %q", s["error"])
	}
	for _, k := range []string{"howToFix", "report"} {
		if _, ok := s[k]; ok {
			t.Errorf("%s set", k)
		}
	}
}

func TestAnEmptyAnswerIsAnError(t *testing.T) {
	c := newCase(t)
	c.answer = ""
	c.fire(fireOpt{})
	s := st(c.kube.only(ns))
	eq(t, "status", []any{s["state"], s["error"]}, []any{"Open", "The analysis returned no output."})
}

func TestAnUnstructuredAnswerKeepsItsProse(t *testing.T) {
	c := newCase(t)
	c.answer = "The composition is broken."
	c.fire(fireOpt{})
	s := st(c.kube.only(ns))
	eq(t, "report", s["report"], "The composition is broken.")
	if !strings.Contains(s["error"].(string), "no structured block") {
		t.Errorf("error %q", s["error"])
	}
	if _, ok := s["howToFix"]; ok {
		t.Error("howToFix set")
	}
}

func TestAnUnusableHowToFixIsAnErrorAndAGap(t *testing.T) {
	c := newCase(t)
	c.answer = answer(block(map[string]any{"precondition": how["precondition"]}))
	c.fire(fireOpt{})
	s := st(c.kube.only(ns))
	if !strings.Contains(s["error"].(string), "no usable howToFix") {
		t.Errorf("error %q", s["error"])
	}
	mc := s["missingContext"].([]any)
	if !strings.HasPrefix(mc[len(mc)-1].(string), "No usable howToFix (apply missing") {
		t.Errorf("missingContext %v", mc)
	}
}

func TestClosedWhileAnalyzingStaysClosedAndGetsTheAnalysis(t *testing.T) {
	c := newCase(t)
	c.duringRCA = func() {
		name := c.kube.only(ns)["metadata"].(map[string]any)["name"].(string)
		c.kube.writeStatus(ns, name, map[string]any{"state": "Closed", "resolution": map[string]any{"by": "user", "at": "t"}})
	}
	c.fire(fireOpt{})
	s := st(c.kube.only(ns))
	eq(t, "state", s["state"], "Closed")
	eq(t, "howToFix", s["howToFix"], how)
}

func TestClosedBetweenTheRereadAndTheWrite(t *testing.T) {
	c := newCase(t)
	patches := 0
	c.kube.beforePatch = func(n, name string) {
		patches++
		if patches == 2 { // the analysis write, after the Analyzing one
			c.kube.writeStatus(n, name, map[string]any{"state": "Closed"})
		}
	}
	c.fire(fireOpt{})
	s := st(c.kube.only(ns))
	eq(t, "state", s["state"], "Closed")
	eq(t, "howToFix", s["howToFix"], how)
	w := c.kube.statusWrites()
	if _, ok := w[len(w)-1]["state"]; ok {
		t.Error("the last write carries a state")
	}
}

func TestAnIncidentAHumanMovedOnKeepsItsState(t *testing.T) {
	c := newCase(t)
	c.duringRCA = func() {
		name := c.kube.only(ns)["metadata"].(map[string]any)["name"].(string)
		c.kube.writeStatus(ns, name, map[string]any{"state": "Verifying"})
	}
	c.fire(fireOpt{})
	s := st(c.kube.only(ns))
	eq(t, "state", s["state"], "Verifying")
	eq(t, "howToFix", s["howToFix"], how)
}

// --- recovery after a restart ---

func TestIncidentsARestartLeftAnalyzingAreOpenedWithTheReason(t *testing.T) {
	c := newCase(t)
	c.kube.put(ns, "a-1", "a", seed{state: "Analyzing"})
	c.kube.put(ns, "b-1", "b", seed{}) // no state: its first write never landed
	c.kube.put(ns, "c-1", "c", seed{state: "Open"})
	c.w.RecoverInterrupted(context.Background())
	a, b, cc := st(c.kube.get(ns, "a-1")), st(c.kube.get(ns, "b-1")), st(c.kube.get(ns, "c-1"))
	eq(t, "a", []any{a["state"], a["error"]}, []any{"Open", Interrupted})
	eq(t, "b", b["state"], "Open")
	if _, ok := a["completedAt"]; !ok { // the failed-RCA hold counts from here
		t.Error("no completedAt")
	}
	if _, ok := cc["error"]; ok {
		t.Error("an Open incident was touched")
	}
}

func TestALateAnalysisClearsTheInterruption(t *testing.T) {
	c := newCase(t)
	c.duringRCA = func() { c.w.RecoverInterrupted(context.Background()) }
	c.fire(fireOpt{})
	s := st(c.kube.only(ns))
	eq(t, "state", s["state"], "Open")
	if _, ok := s["error"]; ok {
		t.Errorf("error %v", s["error"])
	}
	eq(t, "howToFix", s["howToFix"], how)
}

func TestNoIncidentCRDIsNotAnError(t *testing.T) {
	c := newCase(t)
	c.kube.fail = apierrors.NewNotFound(incidentsGR, "")
	c.w.RecoverInterrupted(context.Background()) // does not panic
}

// --- each Alert labels its own incidents ---

func TestTwoSameDisplayNameAlertsGetTwoIncidents(t *testing.T) {
	c := newCase(t)
	c.answer = "analysis"
	const display = "Krateo — composition reconcile errors"
	for _, a := range []struct{ name, where string }{{"krateo-composition-reconcile-error", "where-k"}, {"sre-krateo-composition-reconcile-error", "where-s"}} {
		c.w.Fire(context.Background(), Alert{Namespace: ns, Alert: compare.Alert{Name: a.name, DisplayName: display, Where: a.where, Threshold: "2"}}, c.recordsOf)
	}
	eq(t, "incidents", c.kube.count(), 2)
	for _, a := range []struct{ name, where string }{{"krateo-composition-reconcile-error", "where-k"}, {"sre-krateo-composition-reconcile-error", "where-s"}} {
		items, _ := c.kube.List(context.Background(), ns, LabelAlert+"="+a.name)
		eq(t, a.name, len(items), 1)
		p := items[0]["spec"].(map[string]any)["prompt"].(string)
		if !strings.Contains(p, "`"+a.where+"`") || !strings.Contains(p, display) {
			t.Errorf("prompt %q", p)
		}
	}
	if c.rca[0][1] == c.rca[1][1] {
		t.Error("one kagent thread for two incidents")
	}
}

func TestALookAlikeAlertsIncidentNeverCoversAFiring(t *testing.T) {
	c := newCase(t)
	c.answer = "analysis"
	c.kube.put(ns, "krateo-platform-crashloop-x", "krateo-platform-crashloop", seed{state: "Open"})
	c.w.Fire(context.Background(), Alert{Namespace: ns, Alert: compare.Alert{Name: "sre-pod-crashloop", DisplayName: "Pod crash-looping", Where: "where-cluster", Threshold: "2"}}, c.recordsOf)
	eq(t, "incidents", c.kube.count(), 2)
	eq(t, "look-alike", c.took("krateo-platform-crashloop-x"), 0)
}
