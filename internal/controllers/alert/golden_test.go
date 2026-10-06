package alert

import (
	"testing"

	"github.com/krateo-platformops/alert-provider/internal/golden"
)

func TestTautologyMatchesPython(t *testing.T) {
	for i, c := range golden.Load(t, "testdata/tautology.json") {
		tt, _ := c["thresholdType"].(string)
		if got := Tautology(c["threshold"], tt); got != c["why"] {
			t.Errorf("case %d (%v %v):\n got %q\nwant %q", i, c["threshold"], c["thresholdType"], got, c["why"])
		}
	}
}
