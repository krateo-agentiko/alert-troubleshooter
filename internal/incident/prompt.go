package incident

import (
	"fmt"
	"strings"

	"github.com/krateo-platformops/provider-runtime/pkg/logging"

	"github.com/krateo-platformops/alert-troubleshooter/internal/pyfmt"
	"github.com/krateo-platformops/alert-troubleshooter/internal/report"
)

// BuildPrompt is the RCA prompt. The user message carries the incident; the agent's system prompt
// carries the method. The method therefore lives in one place, so the A2A URL must point at an
// agent whose prompt carries it (incident-agent does; a bare generalist does not).
func BuildPrompt(alertName, alertState, where, message string) string {
	scope := ""
	if where != "" {
		scope = "\n\nIt fired on log records matching `" + where + "`"
		if message != "" {
			scope += " — intent: " + message
		}
		scope += ". That query is your entry point, and the workload those rows name is what you diagnose."
	}
	return fmt.Sprintf("The HyperDX alert \"%s\" has fired (state %s) on this Krateo PlatformOps cluster.", alertName, alertState) +
		scope +
		"\n\nRoot-cause it: the single most likely cause, the composition or component affected, and how to fix it." +
		report.Instructions
}

// Process logs a HyperDX notification. It opens nothing: the reconcile mirrors every alert's state
// on each pass and fires the firing ones, so a notification would only fire twice. The webhook
// exists because a HyperDX alert needs a channel; the body is hyperdx.DefaultWebhookBody.
func Process(log logging.Logger, payload any) {
	p, _ := payload.(map[string]any)
	title := ""
	alert, _ := p["alert"].(map[string]any)
	for _, v := range []any{p["alertName"], p["title"], p["name"], alert["name"]} {
		if pyfmt.Truthy(v) {
			title = pyfmt.Str(v)
			break
		}
	}
	state := ""
	for _, v := range []any{p["state"], p["status"]} {
		if pyfmt.Truthy(v) {
			state = strings.ToUpper(pyfmt.Str(v))
			break
		}
	}
	if state == "" {
		state = "?"
	}
	log.Info(fmt.Sprintf("[webhook] %s %s: the reconciler evaluates it on its next pass", pyfmt.Repr(title), state))
}
