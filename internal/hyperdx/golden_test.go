package hyperdx

import (
	"testing"

	"github.com/krateo-platformops/alert-troubleshooter/internal/golden"
)

func TestAlertDriftMatchesPython(t *testing.T) {
	for i, c := range golden.Load(t, "testdata/drift.json") {
		want := c["want"].(map[string]any)
		f := AlertFields{Interval: want["interval"].(string), Threshold: want["threshold"],
			ThresholdType: want["threshold_type"].(string), Message: want["message"].(string)}
		got := AlertDrift(c["live"].(map[string]any), c["name"].(string), f)
		if got == nil {
			got = []string{}
		}
		if d := golden.Diff(c["drift"], got); d != "" {
			t.Errorf("case %d %v (-python +go):\n%s", i, c["live"], d)
		}
	}
}
