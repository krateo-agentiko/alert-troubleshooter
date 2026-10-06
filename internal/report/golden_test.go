package report

import (
	"testing"

	"github.com/krateo-platformops/alert-provider/internal/golden"
)

// TestParseMatchesPython holds Parse to the Python implementation's output on the inputs its test
// suite passed and on seeded random ones (hack/golden/generate.py).
func TestParseMatchesPython(t *testing.T) {
	for i, c := range golden.Load(t, "testdata/parse.json.gz") {
		text, _ := c["text"].(string)
		var ledger []ToolResult
		if l, ok := c["ledger"].([]any); ok {
			for _, e := range l {
				m := e.(map[string]any)
				name, _ := m["name"].(string)
				payload, _ := m["payload"].(string)
				failed, _ := m["failed"].(bool)
				ledger = append(ledger, ToolResult{Name: name, Payload: payload, Failed: failed})
			}
		}
		prose, v2 := Parse(text, ledger)
		if prose != c["prose"] {
			t.Errorf("case %d: prose\n got %q\nwant %q\ntext %q", i, prose, c["prose"], text)
		}
		if d := golden.Diff(c["v2"], v2); d != "" {
			t.Errorf("case %d: fields (-python +go):\n%s\ntext %q", i, d, text)
		}
	}
}
