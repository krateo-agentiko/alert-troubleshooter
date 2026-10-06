// Package incident turns a firing alert into Incidents, each with a root-cause analysis.
//
// The Alert reconcile mirrors every Alert's HyperDX state about every 60 s and calls Fire for each
// one that is ALERT. Fire counts the firing on an incident that covers it (see pick) or opens a
// new one: it creates the Incident in state Analyzing, runs the incident-agent RCA over A2A, and
// writes the analysis with its howToFix scripts in state Open. An alert therefore has any number
// of incidents, one per problem. From Open on, the incident controller runs the scripts and moves
// the Incident.
package incident

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/krateo-platformops/provider-runtime/pkg/logging"

	"github.com/krateo-platformops/alert-provider/internal/compare"
	"github.com/krateo-platformops/alert-provider/internal/pyfmt"
	"github.com/krateo-platformops/alert-provider/internal/report"
)

const (
	// LabelAlert carries the Alert's metadata.name, so it is at most 63 characters.
	LabelAlert = "observability.krateo.io/alert"
	// writeAttempts is how often a conditioned status write is retried on a 409.
	writeAttempts = 5
)

// Interrupted is the error of an incident a restart left without its analysis.
const Interrupted = "The analysis was interrupted: the alert-provider restarted before it finished."

// intervalSeconds maps Alert spec.interval to the lookback window HyperDX counts the `where` rows
// over.
var intervalSeconds = map[string]int{"1m": 60, "5m": 300, "15m": 900, "30m": 1800, "1h": 3600,
	"6h": 21600, "12h": 43200, "1d": 86400}

// IntervalSeconds is spec.interval in seconds; 5m when unset or unknown.
func IntervalSeconds(interval string) int {
	if s, ok := intervalSeconds[interval]; ok {
		return s
	}
	return 300
}

// Alert is the firing Alert CR.
type Alert struct {
	compare.Alert
	Namespace string
}

// Records returns the alert's current records: the rows matching where over the last seconds.
type Records func(ctx context.Context, where string, seconds int) ([]compare.Row, error)

// Config configures a Writer.
type Config struct {
	// Namespace holds the Alerts and their Incidents.
	Namespace string
	// MaxConcurrentAnalyses is how many RCAs run at once. One RCA reads up to ~1M input tokens a
	// minute, so alerts that fire together (a startup, one fault behind several alerts) would
	// otherwise exhaust the model's per-minute quota and fail every RCA at once. A new incident
	// waits, Analyzing, for a free slot.
	MaxConcurrentAnalyses int
	// FailedAnalysisHold is how long an incident whose RCA failed keeps taking its alert's
	// firings, from the failure (status.completedAt). Past it, a firing nothing else covers opens a
	// new incident and RCA.
	FailedAnalysisHold time.Duration
	// MaxCandidates is how many of an alert's newest open, analyzed incidents one comparison weighs.
	MaxCandidates int
}

// Writer writes the Incidents of firing alerts.
type Writer struct {
	cfg  Config
	kube Kube
	// analyze runs the RCA; compare is the comparison model.
	analyze func(ctx context.Context, prompt, contextID string) (string, []report.ToolResult, error)
	compare func(ctx context.Context, prompt string, names []string) (string, string, error)
	log     logging.Logger
	now     func() time.Time

	slots  chan struct{}
	mu     sync.Mutex
	firing map[string]bool // namespace/alert pairs with an evaluation in progress
}

// NewWriter returns a Writer.
func NewWriter(cfg Config, kube Kube, a2a *A2A, comparer *Comparer, log logging.Logger) *Writer {
	return newWriter(cfg, kube, a2a.Analyze, comparer.Compare, log)
}

func newWriter(cfg Config, kube Kube,
	analyze func(ctx context.Context, prompt, contextID string) (string, []report.ToolResult, error),
	cmp func(ctx context.Context, prompt string, names []string) (string, string, error),
	log logging.Logger) *Writer {
	if cfg.MaxConcurrentAnalyses < 1 {
		cfg.MaxConcurrentAnalyses = 1
	}
	if cfg.MaxCandidates < 1 {
		cfg.MaxCandidates = 1
	}
	return &Writer{cfg: cfg, kube: kube, analyze: analyze, compare: cmp, log: log,
		now:    func() time.Time { return time.Now().UTC() },
		slots:  make(chan struct{}, cfg.MaxConcurrentAnalyses),
		firing: map[string]bool{}}
}

// IncidentName is <alert>-<yyyymmdd-hhmmss> of the opening firing, in UTC.
func IncidentName(alert string, at time.Time) string {
	return alert + "-" + at.UTC().Format("20060102-150405")
}

// contextID is the incident's own kagent thread: every RCA starts from an empty conversation.
func contextID(name string) string {
	return uuid.NewSHA1(uuid.NameSpaceDNS, []byte(name)).String()
}

func metadata(obj map[string]any) map[string]any {
	m, _ := obj["metadata"].(map[string]any)
	return m
}

func status(obj map[string]any) map[string]any {
	m, _ := obj["status"].(map[string]any)
	return m
}

func str(m map[string]any, key string) string {
	s, _ := m[key].(string)
	return s
}

// state is status.state, and false when it is unset (Python's None).
func state(obj map[string]any) (string, bool) {
	v, ok := status(obj)["state"]
	if !ok || v == nil {
		return "", false
	}
	return pyfmt.Str(v), true
}

func ended(obj map[string]any) bool {
	s, _ := state(obj)
	return s == "Resolved" || s == "Closed"
}

func analyzingOrUnset(obj map[string]any) bool {
	s, ok := state(obj)
	return !ok || s == "Analyzing"
}

// sortKey orders incidents by (creationTimestamp, name).
func sortKey(obj map[string]any) [2]string {
	m := metadata(obj)
	return [2]string{str(m, "creationTimestamp"), str(m, "name")}
}

func less(a, b [2]string) bool {
	if a[0] != b[0] {
		return a[0] < b[0]
	}
	return a[1] < b[1]
}

// newest is the incident with the greatest (creationTimestamp, name), the first of equals.
func newest(items []map[string]any) map[string]any {
	var out map[string]any
	for _, i := range items {
		if out == nil || less(sortKey(out), sortKey(i)) {
			out = i
		}
	}
	return out
}

func timestamp(v any) (time.Time, bool) {
	if !pyfmt.Truthy(v) {
		return time.Time{}, false
	}
	return pyfmt.ParseTime(pyfmt.Str(v))
}

// resolvedWithin says incident is Resolved less than grace before at.
func resolvedWithin(incident map[string]any, at time.Time, grace time.Duration) bool {
	if s, _ := state(incident); s != "Resolved" {
		return false
	}
	res, _ := status(incident)["resolution"].(map[string]any)
	resolved, ok := timestamp(res["at"])
	return ok && at.Sub(resolved) < grace
}

// holdsFirings says an open incident without an analysis takes its alert's firings at at: always
// while its RCA runs, and for hold after the RCA failed, counted from status.completedAt, else
// from its creation.
func holdsFirings(incident map[string]any, at time.Time, hold time.Duration) bool {
	if analyzingOrUnset(incident) {
		return true
	}
	since, ok := timestamp(status(incident)["completedAt"])
	if !ok {
		since, ok = timestamp(metadata(incident)["creationTimestamp"])
	}
	return !ok || at.Sub(since) < hold
}

func (w *Writer) alertIncidents(ctx context.Context, ns, alert string) ([]map[string]any, error) {
	return w.kube.List(ctx, ns, LabelAlert+"="+alert)
}

// pick is the incident a firing at at counts on, or nil to open a new one. In order:
//  1. the open incident (any state but Resolved and Closed) with an analysis that one LLM call
//     names as the cause of the alert's current records, among the newest MaxCandidates;
//  2. the newest open incident without an analysis: one still Analyzing, or one whose RCA failed
//     less than FailedAnalysisHold ago. There is nothing to compare with, and a new incident would
//     rerun the analysis. Past the hold, a failed incident takes no more firings, so a new
//     incident gets a fresh RCA;
//  3. the alert's latest incident when it is Resolved less than grace (one spec.interval) ago: a
//     `where` alert keeps counting rows from before the fix for its lookback window, and those
//     belong to the incident the fix resolved. A Closed incident never takes a firing.
//
// rows returns the alert's current records; it is called only when there is an incident to
// compare with. It returns a compare.NoVerdict when the comparison gave no verdict and nothing
// above covers the firing: whether it is a new problem is then unknown, so nothing opens.
func (w *Writer) pick(ctx context.Context, alert Alert, ns string, items []map[string]any, at time.Time,
	grace time.Duration, rows func() ([]compare.Row, error)) (map[string]any, error) {
	var open []map[string]any
	for _, i := range items {
		if !ended(i) {
			open = append(open, i)
		}
	}
	sort.SliceStable(open, func(a, b int) bool { return less(sortKey(open[b]), sortKey(open[a])) })
	var noVerdict error
	var candidates []map[string]any
	for _, i := range open {
		if compare.Comparable(i) && len(candidates) < w.cfg.MaxCandidates {
			candidates = append(candidates, i)
		}
	}
	if len(candidates) > 0 {
		names := make([]string, len(candidates))
		byName := map[string]map[string]any{}
		for i, c := range candidates {
			names[i] = str(metadata(c), "name")
			byName[names[i]] = c
		}
		match, reason, err := func() (string, string, error) {
			r, err := rows()
			if err != nil {
				return "", "", err
			}
			return w.compare(ctx, compare.Prompt(alert.Alert, candidates, r), names)
		}()
		if err != nil {
			w.log.Info(fmt.Sprintf("[compare] %s/%s vs %d incidents: no verdict (%s)", ns, alert.Name, len(candidates), err))
			noVerdict = err
		} else {
			shown := match
			if shown == "" {
				shown = "none"
			}
			w.log.Info(fmt.Sprintf("[compare] %s/%s vs %d incidents: %s (%s)", ns, alert.Name, len(candidates), shown, reason))
			if match != "" {
				return byName[match], nil
			}
		}
	}
	for _, i := range open {
		if !compare.Comparable(i) && holdsFirings(i, at, w.cfg.FailedAnalysisHold) {
			return i, nil
		}
	}
	if latest := newest(items); latest != nil && resolvedWithin(latest, at, grace) {
		return latest, nil
	}
	return nil, noVerdict
}

// patchStatus merges status into the Incident's status, conditioned on the resourceVersion it was
// read at: the controller writes the same status, so a 409 means re-read and retry.
func (w *Writer) patchStatus(ctx context.Context, ns string, incident map[string]any, st map[string]any) error {
	m := metadata(incident)
	return w.kube.PatchStatus(ctx, ns, str(m, "name"), map[string]any{
		"metadata": map[string]any{"resourceVersion": m["resourceVersion"]}, "status": st})
}

func firings(st map[string]any) int {
	v := st["firings"]
	if !pyfmt.Truthy(v) {
		return 0
	}
	if f, ok := pyfmt.Float(v); ok {
		return int(f)
	}
	n, _ := strconv.Atoi(pyfmt.Str(v))
	return n
}

// countOn adds one firing and lastFiredAt to incident name, and nothing else, re-read on a lost
// race.
func (w *Writer) countOn(ctx context.Context, ns, name, now string) error {
	for range writeAttempts {
		incident, err := w.kube.Get(ctx, ns, name)
		if err != nil {
			return err
		}
		st := status(incident)
		if err := w.patchStatus(ctx, ns, incident, map[string]any{"firings": firings(st) + 1, "lastFiredAt": now}); err != nil {
			if code(err) == 409 {
				continue
			}
			return err
		}
		shown, ok := state(incident)
		if !ok || shown == "" {
			shown = "new"
		}
		w.log.Info(fmt.Sprintf("[incident] %s/%s: firing counted (%s)", ns, name, shown))
		return nil
	}
	return fmt.Errorf("incident %s/%s: no firing write succeeded in %d attempts", ns, name, writeAttempts)
}

// openOrCount is one firing: it counts it on the incident pick chooses, or creates one. It returns
// the new Incident, or nil when the firing was counted on an existing one.
func (w *Writer) openOrCount(ctx context.Context, ns string, alert Alert, prompt string, at time.Time,
	grace time.Duration, rows func() ([]compare.Row, error)) (map[string]any, error) {
	now := pyfmt.Isoformat(at)
	items, err := w.alertIncidents(ctx, ns, alert.Name)
	if err != nil {
		return nil, err
	}
	target, err := w.pick(ctx, alert, ns, items, at, grace, rows)
	if err != nil {
		return nil, err
	}
	if target != nil {
		return nil, w.countOn(ctx, ns, str(metadata(target), "name"), now)
	}
	name := IncidentName(alert.Name, at)
	created, err := w.kube.Create(ctx, map[string]any{
		"apiVersion": IncidentGVK.GroupVersion().String(), "kind": IncidentGVK.Kind,
		"metadata": map[string]any{"name": name, "namespace": ns, "labels": map[string]any{LabelAlert: alert.Name}},
		"spec": map[string]any{"alertRef": map[string]any{"name": alert.Name, "namespace": ns}, "trigger": "alert",
			"prompt": prompt, "triggeredAt": now}})
	if err != nil {
		if code(err) != 409 {
			return nil, err
		}
		return nil, w.countOn(ctx, ns, name, now) // a concurrent firing created it this second
	}
	// Unconditioned: the controller may already have touched the new object, and no other writer
	// sets these fields yet.
	if err := w.kube.PatchStatus(ctx, ns, name, map[string]any{
		"status": map[string]any{"state": "Analyzing", "firings": 1, "lastFiredAt": now}}); err != nil {
		return nil, err
	}
	w.log.Info(fmt.Sprintf("[incident] %s/%s: opened", ns, name))
	return created, nil
}

// finish writes the analysis. An incident still Analyzing becomes Open; in any other state (a
// human closed it, or applied a fix, while it was analyzing) the analysis is written without a
// state, since Closed is final and the controller owns the rest.
func (w *Writer) finish(ctx context.Context, ns, name string, st map[string]any) error {
	for range writeAttempts {
		incident, err := w.kube.Get(ctx, ns, name)
		if err != nil {
			return err
		}
		body := make(map[string]any, len(st)+1)
		for k, v := range st {
			body[k] = v
		}
		if analyzingOrUnset(incident) {
			body["state"] = "Open"
		}
		if err := w.patchStatus(ctx, ns, incident, body); err != nil {
			if code(err) != 409 {
				return err
			}
			continue
		}
		return nil
	}
	return fmt.Errorf("incident %s/%s: no status write succeeded in %d attempts", ns, name, writeAttempts)
}

// RecoverInterrupted opens every incident a restart left Analyzing (or before its first status
// write), with the reason in error. An Analyzing incident takes every firing of its alert that no
// analyzed incident covers, and is never checked. Open with error, it says why it has no scripts
// and can be closed, and the next firing then opens a fresh one. An analysis still running in
// another replica overwrites error when it finishes.
func (w *Writer) RecoverInterrupted(ctx context.Context) {
	ns := w.cfg.Namespace
	items, err := w.kube.List(ctx, ns, LabelAlert)
	if err != nil { // no Incident CRD yet, or no apiserver: nothing to recover
		w.log.Info(fmt.Sprintf("[incident] recovery skipped (%s)", err))
		return
	}
	for _, incident := range items {
		if !analyzingOrUnset(incident) {
			continue
		}
		name := str(metadata(incident), "name")
		if err := w.patchStatus(ctx, ns, incident, map[string]any{"state": "Open", "error": Interrupted,
			"completedAt": pyfmt.Isoformat(w.now())}); err != nil { // a 409 means another writer moved it
			w.log.Info(fmt.Sprintf("[incident] %s/%s: recovery skipped (%s)", ns, name, err))
			continue
		}
		w.log.Info(fmt.Sprintf("[incident] %s/%s: interrupted, opened", ns, name))
	}
}

// Fire is one evaluation of a firing Alert, from its reconcile (about every 60 s). The firing
// counts on the incident pick chooses, or opens a new one whose RCA then runs in this call. The
// alert's name keys the incidents and their label, its namespace holds them, spec.interval is the
// Resolved grace window and the lookback of its records. One evaluation per alert runs at a time:
// while one is still comparing, the alert's next firing is skipped.
func (w *Writer) Fire(ctx context.Context, alert Alert, records Records) {
	if pyfmt.Len(alert.Name) > 63 {
		w.log.Info(fmt.Sprintf("[incident] alert %s: a name over 63 characters cannot label an Incident; skipping", pyfmt.Repr(alert.Name)))
		return
	}
	ns := alert.Namespace
	if ns == "" {
		ns = w.cfg.Namespace
	}
	key := ns + "/" + alert.Name
	w.mu.Lock()
	if w.firing[key] {
		w.mu.Unlock()
		w.log.Info(fmt.Sprintf("[incident] alert %s: the previous evaluation is still running; skipping this firing", key))
		return
	}
	w.firing[key] = true
	w.mu.Unlock()

	name := alert.DisplayName
	if name == "" {
		name = alert.Name
	}
	prompt := BuildPrompt(name, "ALERT", alert.Where, alert.Message)
	grace := IntervalSeconds(alert.Interval)
	rows := func() ([]compare.Row, error) {
		found, err := records(ctx, alert.Where, grace)
		if err != nil { // without the records there is no comparison
			return nil, &compare.NoVerdict{Reason: "the alert's records are unreadable: " + pyfmt.Cut(err.Error(), 200)}
		}
		// HyperDX's ALERT is from its last evaluation; by now the window can hold no row, and a
		// comparison over no records names no incident, which would open a duplicate.
		if len(found) == 0 {
			return nil, &compare.NoVerdict{Reason: "no record matches the alert now"}
		}
		return found, nil
	}
	created, err := w.openOrCount(ctx, ns, alert, prompt, w.now(), time.Duration(grace)*time.Second, rows)
	w.mu.Lock()
	delete(w.firing, key)
	w.mu.Unlock()
	switch {
	case compare.IsNoVerdict(err):
		w.log.Info(fmt.Sprintf("[incident] alert %s: no comparison verdict (%s); the next pass retries", key, err))
		return
	case err != nil: // a failed write loses this firing, not the next one
		w.log.Info(fmt.Sprintf("[err] alert %s: firing not recorded (%s)", key, err))
		return
	}
	if created != nil {
		w.RunAnalysis(ctx, ns, str(metadata(created), "name"), prompt)
	}
}

// RunAnalysis is the RCA of a new incident, then its one status write: the analysis and state
// Open. error says why an incident has no howToFix: the call failed, the answer was empty or
// unstructured, or its scripts were unusable. It is cleared when howToFix is written.
func (w *Writer) RunAnalysis(ctx context.Context, ns, name, prompt string) {
	st := map[string]any{}
	func() {
		w.slots <- struct{}{}
		raw, ledger, err := w.analyze(ctx, prompt, contextID(name))
		<-w.slots
		if err != nil { // a failed RCA still opens the incident
			st["error"] = "The analysis failed: " + pyfmt.Cut(err.Error(), 500)
			return
		}
		w.log.Info(fmt.Sprintf("[a2a] %s/%s: %d chars, %d tool results", ns, name, pyfmt.Len(raw), len(ledger)))
		prose, v2 := report.Parse(raw, ledger)
		if pyfmt.Strip(prose) != "" {
			st["report"] = prose
		}
		for _, k := range report.StatusKeys {
			if v, ok := v2[k]; ok {
				st[k] = v
			}
		}
		_, hasFix := v2["howToFix"]
		switch {
		case hasFix:
			st["error"] = nil
		case pyfmt.Strip(prose) == "" && len(v2) == 0:
			st["error"] = "The analysis returned no output."
		case len(v2) == 0:
			st["error"] = "The analysis returned no structured block, so the incident has no scripts to check or fix it."
		default:
			st["error"] = "The analysis returned no usable howToFix, so the incident has no scripts to check or fix it."
		}
	}()
	st["completedAt"] = pyfmt.Isoformat(w.now())
	if err := w.finish(ctx, ns, name, st); err != nil { // RecoverInterrupted opens it after a restart
		w.log.Info(fmt.Sprintf("[err] incident %s/%s: analysis not written (%s)", ns, name, err))
		return
	}
	fix := "no"
	if st["howToFix"] != nil {
		fix = "yes"
	}
	w.log.Info(fmt.Sprintf("[ok] incident %s/%s: analysis written (howToFix=%s)", ns, name, fix))
}
