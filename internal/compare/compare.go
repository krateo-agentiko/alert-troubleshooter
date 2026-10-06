// Package compare is the incident comparison: which open Incident of an alert, if any, covers the
// alert's firing now? The writer asks it once per firing (about every 60 s while an alert fires),
// in one LLM call over all the alert's open, analyzed incidents. This package owns both sides of
// that exchange so they cannot drift:
//
//   - System and Prompt: the alert, the records it matches now, and each incident's root cause and
//     howToFix scripts;
//   - ParseVerdict: the answer's {"match": <incident number> | null, "reason": str} object, or
//     ErrNoVerdict.
//
// Incidents are numbered in the prompt, not named: the gateway's PhoneNumber guard masks the
// timestamp in an incident's name, so the model could not repeat it.
package compare

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/krateo-platformops/alert-provider/internal/pyfmt"
)

const (
	// DefaultMaxCandidates is how many of the newest open incidents one comparison weighs; older
	// ones never take a firing through the comparison.
	DefaultMaxCandidates = 50
	maxRows              = 20 // record groups quoted, the most frequent first
	rowChars             = 300
	descriptionChars     = 1000
	scriptChars          = 1500
	reasonChars          = 300
)

var scripts = []string{"precondition", "apply", "verify"}

// RowGroup is one HyperDX groupBy expression: a line per distinct record, naming its object. A k8s
// event names its involvedObject, reason and message; any other log only its service and pod, so
// the groups stay as few as the pods. HyperDX nulls a group whose expression holds `[` or `=`,
// hence arrayElement and equals.
const RowGroup = "if(equals(arrayElement(ResourceAttributes, 'telemetry.source'), 'k8s-events'), " +
	"concat(JSONExtractString(Body, 'object', 'involvedObject', 'kind'), ' ', " +
	"JSONExtractString(Body, 'object', 'involvedObject', 'namespace'), '/', " +
	"JSONExtractString(Body, 'object', 'involvedObject', 'name'), ': ', " +
	"JSONExtractString(Body, 'object', 'reason'), ' ', " +
	"JSONExtractString(Body, 'object', 'message')), " +
	"concat(ServiceName, ' ', arrayElement(ResourceAttributes, 'k8s.namespace.name'), '/', " +
	"arrayElement(ResourceAttributes, 'k8s.pod.name')))"

// System is the comparison's system message.
const System = "You deduplicate incidents of a Kubernetes platform's alerts. Given the log records an " +
	"alert matches now and its open incidents, name the incident whose root cause produces " +
	"those records, or none."

// NoVerdict is no usable answer: the call failed or was rate-limited, or it carried no verdict
// object.
type NoVerdict struct{ Reason string }

func (e *NoVerdict) Error() string { return e.Reason }

// IsNoVerdict says err is, or wraps, a NoVerdict.
func IsNoVerdict(err error) bool {
	var nv *NoVerdict
	return errors.As(err, &nv)
}

// Row is one distinct record the alert matches now and how many times it occurs.
type Row struct {
	Record string
	Count  int
}

// Alert is what the prompt says about the alert.
type Alert struct {
	Name          string
	DisplayName   string
	Where         string
	Interval      string
	Threshold     string // its Python str(); "1" when unset
	ThresholdType string
	Message       string
}

func status(incident map[string]any) map[string]any {
	st, _ := incident["status"].(map[string]any)
	return st
}

// Comparable says an open incident has an analysis to compare a firing with: a root cause, or a
// report from an analysis that did not fail. An incident still Analyzing has neither, and a failed
// one (error set, no root cause) holds at most the failure's text in report.
func Comparable(incident map[string]any) bool {
	st := status(incident)
	if st["state"] == "Analyzing" {
		return false
	}
	rc, _ := st["rootCause"].(map[string]any)
	if pyfmt.Truthy(rc["statement"]) {
		return true
	}
	report, _ := st["report"].(string)
	return !pyfmt.Truthy(st["error"]) && pyfmt.Strip(report) != ""
}

// cut is Python's str(text or "").strip(), cut at limit characters with a marker.
func cut(text any, limit int) string {
	s := ""
	if pyfmt.Truthy(text) {
		s = pyfmt.Str(text)
	}
	s = pyfmt.Strip(s)
	if pyfmt.Len(s) <= limit {
		return s
	}
	return pyfmt.Cut(s, limit) + " …(truncated)"
}

func get(m map[string]any, key, fallback string) string {
	if v, ok := m[key]; ok {
		return pyfmt.Str(v)
	}
	return fallback
}

func incidentBlock(number int, incident map[string]any) string {
	meta, _ := incident["metadata"].(map[string]any)
	st := status(incident)
	rc, _ := st["rootCause"].(map[string]any)
	var cause any = rc["statement"]
	if !pyfmt.Truthy(cause) {
		cause = st["report"]
	}
	lines := []string{
		fmt.Sprintf("### Incident %d (%s, opened %s)", number, get(st, "state", "?"), get(meta, "creationTimestamp", "?")),
		"Root cause: " + cut(cause, descriptionChars),
	}
	how, _ := st["howToFix"].(map[string]any)
	for _, sc := range scripts {
		text, _ := how[sc].(string)
		if pyfmt.Strip(text) == "" {
			continue
		}
		lines = append(lines, fmt.Sprintf("%s:\n```bash\n%s\n```", sc, cut(text, scriptChars)))
	}
	return strings.Join(lines, "\n")
}

func rowsText(rows []Row) string {
	if len(rows) == 0 {
		return "No record matches now."
	}
	var lines []string
	for i, r := range rows {
		if i == maxRows {
			break
		}
		lines = append(lines, fmt.Sprintf("- %d× %s", r.Count, cut(r.Record, rowChars)))
	}
	if len(rows) > maxRows {
		lines = append(lines, fmt.Sprintf("- … and %d more distinct records", len(rows)-maxRows))
	}
	return strings.Join(lines, "\n")
}

// Prompt is the user message for one firing: incidents are the open, analyzed ones, newest first;
// rows are the alert's records, the most frequent first. Generic: one prompt serves every alert.
func Prompt(a Alert, incidents []map[string]any, rows []Row) string {
	intent := ""
	if a.Message != "" {
		intent = " Its intent: " + a.Message + "."
	}
	name := a.DisplayName
	if name == "" {
		name = a.Name
	}
	interval, thresholdType := a.Interval, a.ThresholdType
	if interval == "" {
		interval = "5m"
	}
	if thresholdType == "" {
		thresholdType = "above"
	}
	blocks := make([]string, len(incidents))
	for i, inc := range incidents {
		blocks[i] = incidentBlock(i+1, inc)
	}
	return fmt.Sprintf("Alert \"%s\" counts the log records matching `%s` over the last %s and fires "+
		"when that count is %s %s.%s\n\n", name, a.Where, interval, thresholdType, a.Threshold, intent) +
		"It fires now. The records it matches, by count:\n" + rowsText(rows) + "\n\n" +
		"Its open incidents, newest first:\n\n" +
		strings.Join(blocks, "\n\n") +
		"\n\nAnswer with only a JSON object: " +
		`{"match": <incident number>, "reason": "<one sentence>"}. "match" is the newest incident ` +
		"whose root cause produces any of these records, or null when none of them does."
}

var fenced = regexp.MustCompile("(?s)```(?:json)?[ \t]*\r?\n(.*?)\r?\n?```")

// ParseVerdict reads the answer's last fenced block, or the whole answer, that is a JSON object
// whose "match" is null or the number of one of names, in prompt order. It returns the matched
// name ("" for none of them) and the reason, or a NoVerdict, never a guess.
func ParseVerdict(text string, names []string) (string, string, error) {
	text = pyfmt.Strip(text)
	var bodies []string
	matches := fenced.FindAllStringSubmatch(text, -1)
	for i := len(matches) - 1; i >= 0; i-- {
		bodies = append(bodies, matches[i][1])
	}
	bodies = append(bodies, text)
	for _, body := range bodies {
		v, err := pyfmt.Decode([]byte(body))
		if err != nil {
			continue
		}
		data, ok := v.(map[string]any)
		if !ok {
			continue
		}
		match, ok := data["match"]
		if !ok {
			continue
		}
		if match == nil {
			return "", cut(data["reason"], reasonChars), nil
		}
		if n, ok := match.(json.Number); ok && pyfmt.IsInt(n) {
			if i, err := strconv.Atoi(pyfmt.NumberStr(n)); err == nil && 1 <= i && i <= len(names) {
				return names[i-1], cut(data["reason"], reasonChars), nil
			}
		}
	}
	return "", "", &NoVerdict{Reason: `the answer has no {"match": <an incident number> | null} object`}
}
