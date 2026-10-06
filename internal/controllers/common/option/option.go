// Package option holds the options shared by the controllers.
package option

import (
	"time"

	"github.com/krateo-platformops/provider-runtime/pkg/controller"
)

// ControllerOptions extends the provider-runtime controller options with the per-reconcile timeout.
type ControllerOptions struct {
	controller.Options

	// Timeout for each reconcile.
	Timeout time.Duration
}
