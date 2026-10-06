// Package golden loads the corpora hack/golden/generate.py recorded from the Python
// implementation, and compares JSON values the way they land in a CR: by their decoded value.
package golden

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/krateo-platformops/alert-provider/internal/pyfmt"
)

// Load reads a corpus, gzipped when its name ends in .gz, with numbers as json.Number.
func Load(t *testing.T, path string) []map[string]any {
	t.Helper()
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	if strings.HasSuffix(path, ".gz") {
		r, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		if data, err = io.ReadAll(r); err != nil {
			t.Fatal(err)
		}
	}
	v, err := pyfmt.Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	var out []map[string]any
	for _, c := range v.([]any) {
		out = append(out, c.(map[string]any))
	}
	return out
}

// Diff is the difference between two JSON values, "" when they are equal as decoded JSON.
func Diff(want, got any) string {
	return cmp.Diff(normalize(want), normalize(got))
}

func normalize(v any) any {
	b, err := json.Marshal(v)
	if err != nil {
		return err.Error()
	}
	var out any
	_ = json.Unmarshal(b, &out)
	return out
}
