// Package webhook serves the HyperDX webhook and the health probe on one port.
package webhook

import (
	"context"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/krateo-platformops/provider-runtime/pkg/logging"

	"github.com/krateo-platformops/alert-provider/internal/incident"
	"github.com/krateo-platformops/alert-provider/internal/pyfmt"
)

// Handler answers GET /healthz with 200 and any POST, on any path, as a HyperDX notification: 202
// after logging it. HyperDX redacts the webhook URL path to /**** in its API and may deliver to a
// redacted path, so the path is not checked.
func Handler(log logging.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			if r.URL.Path == "/healthz" {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("ok"))
				return
			}
			w.WriteHeader(http.StatusNotFound)
		case http.MethodPost:
			raw, _ := io.ReadAll(r.Body)
			if len(raw) == 0 {
				raw = []byte("{}")
			}
			payload, err := pyfmt.Decode(raw)
			if err != nil {
				payload = map[string]any{"raw": string(raw)}
			}
			incident.Process(log, payload)
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte("accepted"))
		default:
			http.Error(w, "Unsupported method ("+r.Method+")", http.StatusNotImplemented)
		}
	})
}

// Serve serves Handler on addr until ctx is done.
func Serve(ctx context.Context, addr string, log logging.Logger) error {
	srv := &http.Server{Addr: addr, Handler: Handler(log), ReadHeaderTimeout: 30 * time.Second}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
	}()
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
