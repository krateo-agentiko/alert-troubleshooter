// Command alert-provider turns a firing Krateo observability Alert into Incidents, each with an
// incident-agent root-cause analysis. It reconciles every Alert with HyperDX, writes the Incidents
// of the firing ones, and acknowledges HyperDX's webhook. `alert-provider bootstrap` provisions
// the HyperDX API keys into a Secret, as the installer's Job.
//
// Its configuration is the environment the chart sets (see helm/alert-provider).
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"github.com/krateo-platformops/provider-runtime/pkg/controller"
	"github.com/krateo-platformops/provider-runtime/pkg/logging"
	"github.com/krateo-platformops/provider-runtime/pkg/ratelimiter"

	"github.com/krateo-platformops/alert-troubleshooter/apis"
	"github.com/krateo-platformops/alert-troubleshooter/internal/bootstrap"
	"github.com/krateo-platformops/alert-troubleshooter/internal/compare"
	"github.com/krateo-platformops/alert-troubleshooter/internal/controllers/alert"
	"github.com/krateo-platformops/alert-troubleshooter/internal/controllers/common/option"
	"github.com/krateo-platformops/alert-troubleshooter/internal/hyperdx"
	"github.com/krateo-platformops/alert-troubleshooter/internal/incident"
	"github.com/krateo-platformops/alert-troubleshooter/internal/webhook"
)

const serviceName = "krateo-alert-provider"

func getenv(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return fallback
}

// envInt is an integer setting, at least min; an unparsable one stops the process.
func envInt(key string, fallback, min int) int {
	n, err := strconv.Atoi(strings.TrimSpace(getenv(key, strconv.Itoa(fallback))))
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %s\n", key, err)
		os.Exit(1)
	}
	if n < min {
		return min
	}
	return n
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "bootstrap" {
		os.Exit(runBootstrap())
	}
	debug := flag.Bool("debug", getenv("ALERT_PROVIDER_DEBUG", "") == "true", "Run with debug logging.")
	flag.Parse()

	level := slog.LevelInfo
	if *debug {
		level = slog.LevelDebug
	}
	handler := logging.NewOTelJSONHandler(level, os.Stderr, logging.ServiceNameAttr(serviceName)...)
	log := logging.NewSlogLogger(*slog.New(handler))
	ctrl.SetLogger(logr.FromSlogHandler(handler))

	if err := run(log); err != nil {
		log.Error(err, "alert-provider stopped")
		os.Exit(1)
	}
}

func run(log logging.Logger) error {
	namespace := getenv("NAMESPACE", "krateo-system")
	interval := time.Duration(envInt("RECONCILE_INTERVAL", 60, 0)) * time.Second
	a2a := &incident.A2A{
		URL:     getenv("AUTOPILOT_A2A_URL", "http://incident-agent.krateo-system.svc:8080/"),
		Timeout: time.Duration(envInt("A2A_TIMEOUT", 180, 0)) * time.Second,
	}
	jwt := &incident.ServiceJWT{URL: getenv("AUTHN_URL", ""), TokenFile: getenv("AUTHN_TOKEN_FILE", "/var/run/secrets/authn/token"), Log: log}
	a2a.JWT = jwt.Get
	writerConfig := incident.Config{
		Namespace:             namespace,
		MaxConcurrentAnalyses: envInt("MAX_CONCURRENT_ANALYSES", 2, 1),
		FailedAnalysisHold:    time.Duration(envInt("FAILED_ANALYSIS_HOLD", 1800, 0)) * time.Second,
		MaxCandidates:         envInt("MAX_COMPARE_CANDIDATES", compare.DefaultMaxCandidates, 1),
	}
	compareModelConfig := getenv("COMPARE_MODEL_CONFIG", "gemini-flash")
	compareTimeout := time.Duration(envInt("COMPARE_TIMEOUT", 60, 0)) * time.Second
	apiURL := getenv("HYPERDX_API_URL", "http://krateo-clickstack-api.krateo-system.svc:8000")
	accessKey := getenv("HYPERDX_ACCESS_KEY", "")
	addr := ":" + getenv("PORT", "8080")

	cfg, err := ctrl.GetConfig()
	if err != nil {
		return fmt.Errorf("cannot get API server rest config: %w", err)
	}
	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		// The Role is namespaced: the Alerts are cached in the release namespace only.
		Cache:                  cache.Options{DefaultNamespaces: map[string]cache.Config{namespace: {}}},
		Metrics:                metricsserver.Options{BindAddress: "0"},
		HealthProbeBindAddress: "0",
	})
	if err != nil {
		return fmt.Errorf("cannot create controller manager: %w", err)
	}
	if err := apis.AddToScheme(mgr.GetScheme()); err != nil {
		return fmt.Errorf("cannot add APIs to scheme: %w", err)
	}

	comparer := &incident.Comparer{Reader: mgr.GetAPIReader(), Namespace: namespace, ModelConfig: compareModelConfig,
		Timeout: compareTimeout, JWT: jwt.Get}
	writer := incident.NewWriter(writerConfig, incident.NewKube(mgr.GetAPIReader(), mgr.GetClient()), a2a, comparer, log)

	ctx := ctrl.SetupSignalHandler()
	// Before any firing can open an incident, so only incidents a previous process left are swept.
	writer.RecoverInterrupted(ctx)

	reconcilerEnabled := strings.ToLower(getenv("RECONCILER_ENABLED", "true")) == "true"
	switch {
	case !reconcilerEnabled:
		log.Info("[reconciler] RECONCILER_ENABLED is not true — reconciler disabled")
	case accessKey == "":
		log.Info("[reconciler] HYPERDX_ACCESS_KEY unset — reconciler disabled")
	default:
		hdx := func() *hyperdx.Client { return hyperdx.New(apiURL, accessKey) }
		if err := alert.Setup(mgr, alert.Options{
			Controller: option.ControllerOptions{
				Options: controller.Options{
					Logger:       log,
					PollInterval: interval,
					// A token bucket: provider-runtime consults it on every reconcile, not only
					// after an error, so a failure back-off here would delay every pass.
					GlobalRateLimiter: ratelimiter.NewGlobal(20),
				},
				Timeout: 2 * time.Minute,
			},
			HyperDX:       hdx,
			WebhookName:   getenv("WEBHOOK_NAME", "krateo-alert-provider"),
			WebhookTarget: getenv("WEBHOOK_TARGET_URL", "http://krateo-alert-provider.krateo-system.svc:8080/webhook"),
			Writer:        writer,
			FiringContext: ctx,
		}); err != nil {
			return fmt.Errorf("cannot set up the Alert controller: %w", err)
		}
		if err := mgr.Add(&alert.Seeder{Reader: mgr.GetAPIReader(), Client: mgr.GetClient(), Namespace: namespace,
			Defaults: getenv("DEFAULT_ALERTS_JSON", ""), Interval: interval, Log: log}); err != nil {
			return err
		}
		log.Info("[reconciler] started", "interval", interval.String(), "api", apiURL)
	}

	errs := make(chan error, 1)
	go func() { errs <- webhook.Serve(ctx, addr, log) }()
	log.Info(fmt.Sprintf("krateo-alert-provider listening on %s → RCA %s, compare ModelConfig %s/%s", addr, a2a.URL, namespace, compareModelConfig))
	go func() { errs <- mgr.Start(ctx) }()
	select {
	case err := <-errs:
		return err
	case <-ctx.Done():
		return nil
	}
}

func runBootstrap() int {
	logf := func(format string, args ...any) { fmt.Fprintf(os.Stdout, format+"\n", args...) }
	required := func(key string) string {
		v, ok := os.LookupEnv(key)
		if !ok {
			fmt.Fprintf(os.Stderr, "%s is not set\n", key)
			os.Exit(1)
		}
		return v
	}
	cfg := bootstrap.Config{
		URL:        required("HYPERDX_URL"),
		Email:      required("HYPERDX_ADMIN_EMAIL"),
		Password:   required("HYPERDX_ADMIN_PASSWORD"),
		Namespace:  getenv("NAMESPACE", "krateo-system"),
		SecretName: getenv("SECRET_NAME", "hyperdx-api-token"),
		Tries:      30,
		Wait:       5 * time.Second,
		Logf:       logf,
	}
	rc, err := ctrl.GetConfig()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	kube, err := kubernetes.NewForConfig(rc)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := bootstrap.Run(context.Background(), cfg, kube); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}
