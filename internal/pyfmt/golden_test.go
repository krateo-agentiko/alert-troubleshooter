package pyfmt_test

import (
	"encoding/json"
	"testing"

	"github.com/krateo-platformops/alert-provider/internal/golden"
	"github.com/krateo-platformops/alert-provider/internal/pyfmt"
)

func TestMatchesPython(t *testing.T) {
	for _, group := range golden.Load(t, "testdata/pyfmt.json") {
		for _, f := range group["floats"].([]any) {
			c := f.(map[string]any)
			v, _ := c["f"].(json.Number).Float64()
			if got := pyfmt.FloatRepr(v); got != c["repr"] {
				t.Errorf("repr(%v): got %q, want %q", c["f"], got, c["repr"])
			}
		}
		for _, d := range group["dumps"].([]any) {
			c := d.(map[string]any)
			if got := pyfmt.Dumps(c["v"]); got != c["dumps"] {
				t.Errorf("dumps(%v): got %q, want %q", c["v"], got, c["dumps"])
			}
			if want, ok := c["str"].(string); ok {
				if got := pyfmt.Str(c["v"]); got != want {
					t.Errorf("str(%v): got %q, want %q", c["v"], got, want)
				}
			}
		}
		for _, s := range group["strip"].([]any) {
			c := s.(map[string]any)
			if got := pyfmt.Strip(c["s"].(string)); got != c["strip"] {
				t.Errorf("strip(%q): got %q, want %q", c["s"], got, c["strip"])
			}
		}
	}
}
