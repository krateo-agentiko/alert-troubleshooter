package alert

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/krateo-platformops/alert-troubleshooter/apis/alert/v1alpha1"
	"github.com/krateo-platformops/alert-troubleshooter/internal/pyfmt"
)

// Tautology is why the alert can never change state, or "" if it can.
//
// A count is never negative. Every alert here counts rows over a window, so the value compared is
// an integer >= 0, and some threshold/type pairs are decided before any data is read:
//
//	above 0            value >= 0   always true: fires forever, on an empty cluster too.
//	below 0            value <  0   never true: silently cannot fire, which is worse, since it
//	                                looks armed and is not.
//	below_or_equal -1  value <= -1  never true, same shape.
//
// This is not a heuristic about whether an alert is useful. It is arithmetic: the comparison has
// one possible outcome, so the alert carries no information either way. It has cost real money
// twice: a catalogue shipped 25 alerts at `above 0` and every one fired permanently, each firing
// launching an RCA, and an Autopilot-authored alert reached run 72 the same way.
//
// It returns a sentence for the status, since an operator reading phase: Invalid needs to know
// which field to change and to what.
func Tautology(threshold any, thresholdType string) string {
	value, ok := pyfmt.Float(threshold)
	if !ok {
		return "" // not a number: the CRD's own typing owns that, not this
	}
	shown := pyfmt.Str(threshold)
	kind := thresholdType
	if kind == "" {
		kind = "above"
	}
	switch strings.ToLower(kind) {
	case "above":
		if value <= 0 {
			return fmt.Sprintf("thresholdType 'above' means value >= %s, and a count is never negative — "+
				"this fires on every evaluation including an empty result. Use 1 to mean 'at least one'.", shown)
		}
	case "below":
		if value <= 0 {
			return fmt.Sprintf("thresholdType 'below' means value < %s, which a count can never satisfy — "+
				"this can never fire. Use 1 to mean 'none in this window'.", shown)
		}
	case "below_or_equal":
		if value < 0 {
			return fmt.Sprintf("thresholdType 'below_or_equal' means value <= %s, which a count can never "+
				"satisfy — this can never fire. Use 0 to mean 'none in this window'.", shown)
		}
	}
	return ""
}

// OkSince is status.okSince for an Alert whose live state is now state: the time the alert last
// turned OK, kept while it stays OK; an OK alert with none gets now. Empty in every other state.
// Display-only: nothing reads it to close or resolve anything.
func OkSince(st v1alpha1.AlertStatus, state, now string) string {
	if state != "OK" {
		return ""
	}
	if st.State == "OK" && st.OkSince != "" {
		return st.OkSince
	}
	return now
}

// threshold is spec.threshold, 1 when unset.
func threshold(spec v1alpha1.AlertSpec) json.Number {
	if spec.Threshold == "" {
		return "1"
	}
	return spec.Threshold
}
