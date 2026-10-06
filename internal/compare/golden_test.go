package compare

import (
	"testing"

	"github.com/krateo-platformops/alert-troubleshooter/internal/golden"
	"github.com/krateo-platformops/alert-troubleshooter/internal/pyfmt"
)

// alertOf is the Alert the reconcile passes for a CR, read as Python's prompt reads it.
func alertOf(cr map[string]any) Alert {
	meta, _ := cr["metadata"].(map[string]any)
	spec, _ := cr["spec"].(map[string]any)
	str := func(k string) string {
		if v, ok := spec[k]; ok && pyfmt.Truthy(v) {
			return pyfmt.Str(v)
		}
		return ""
	}
	a := Alert{Name: meta["name"].(string), DisplayName: str("displayName"), Interval: str("interval"),
		ThresholdType: str("thresholdType"), Message: str("message"), Threshold: "1"}
	if v, ok := spec["where"]; ok {
		a.Where = pyfmt.Str(v)
	}
	if v, ok := spec["threshold"]; ok {
		a.Threshold = pyfmt.Str(v)
	}
	return a
}

func TestPromptMatchesPython(t *testing.T) {
	for i, c := range golden.Load(t, "testdata/prompt.json.gz") {
		var incidents []map[string]any
		for _, inc := range c["incidents"].([]any) {
			incidents = append(incidents, inc.(map[string]any))
		}
		var rows []Row
		for _, r := range c["rows"].([]any) {
			pair := r.([]any)
			n, _ := pair[1].(interface{ Int64() (int64, error) }).Int64()
			rows = append(rows, Row{Record: pair[0].(string), Count: int(n)})
		}
		if got := Prompt(alertOf(c["alert"].(map[string]any)), incidents, rows); got != c["prompt"] {
			t.Errorf("case %d:\n got %q\nwant %q", i, got, c["prompt"])
		}
	}
}

func TestVerdictMatchesPython(t *testing.T) {
	for i, c := range golden.Load(t, "testdata/verdict.json") {
		var names []string
		for _, n := range c["names"].([]any) {
			names = append(names, n.(string))
		}
		match, reason, err := ParseVerdict(c["text"].(string), names)
		if want, ok := c["error"]; ok {
			if err == nil || err.Error() != want {
				t.Errorf("case %d (%q): err %v, want %q", i, c["text"], err, want)
			}
			continue
		}
		wantMatch, _ := c["match"].(string)
		if err != nil || match != wantMatch || reason != c["reason"] {
			t.Errorf("case %d (%q): got (%q, %q, %v), want (%q, %q)", i, c["text"], match, reason, err, wantMatch, c["reason"])
		}
	}
}
