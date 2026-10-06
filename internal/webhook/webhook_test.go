package webhook

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/krateo-platformops/provider-runtime/pkg/logging"
)

func TestTheHTTPSurface(t *testing.T) {
	h := Handler(logging.NewNopLogger())
	for _, c := range []struct {
		method, path, body string
		code               int
		reply              string
	}{
		{"GET", "/healthz", "", 200, "ok"},
		{"GET", "/", "", 404, ""},
		// any path: HyperDX may deliver to a redacted /****
		{"POST", "/****", `{"alertName":"🚨 a","state":"ALERT"}`, 202, "accepted"},
		{"POST", "/webhook", "not json", 202, "accepted"},
		{"POST", "/webhook", "", 202, "accepted"},
		{"PUT", "/webhook", "", 501, ""},
	} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(c.method, c.path, strings.NewReader(c.body)))
		if w.Code != c.code || (c.reply != "" && w.Body.String() != c.reply) {
			t.Errorf("%s %s: %d %q", c.method, c.path, w.Code, w.Body.String())
		}
	}
}
