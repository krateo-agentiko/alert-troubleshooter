package incident

import (
	"testing"

	"github.com/krateo-platformops/alert-provider/internal/golden"
)

func TestBuildPromptMatchesPython(t *testing.T) {
	for i, c := range golden.Load(t, "testdata/rca_prompt.json") {
		args := c["args"].([]any)
		s := func(i int) string {
			if i >= len(args) {
				return ""
			}
			v, _ := args[i].(string)
			return v
		}
		if got := BuildPrompt(s(0), s(1), s(2), s(3)); got != c["prompt"] {
			t.Errorf("case %d %v:\n got %q\nwant %q", i, args, got, c["prompt"])
		}
	}
}

func TestToolResultsMatchPython(t *testing.T) {
	for i, c := range golden.Load(t, "testdata/tool_results.json") {
		var got []map[string]any
		for _, r := range toolResults(c["parts"].([]any)) {
			got = append(got, map[string]any{"name": r.Name, "payload": r.Payload, "failed": r.Failed})
		}
		if got == nil {
			got = []map[string]any{}
		}
		if d := golden.Diff(c["results"], got); d != "" {
			t.Errorf("case %d (-python +go):\n%s", i, d)
		}
	}
}
