package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/InteractionLabs/traversal-connector/connector-lib/capability"
	"github.com/InteractionLabs/traversal-connector/connector-lib/logging"
	"github.com/InteractionLabs/traversal-connector/connector-lib/telemetry"
	"github.com/InteractionLabs/traversal-connector/internal/client"
	"github.com/InteractionLabs/traversal-connector/internal/config"
	"github.com/InteractionLabs/traversal-connector/internal/pipeserver"
	"github.com/InteractionLabs/traversal-connector/internal/redact"
	"github.com/InteractionLabs/traversal-connector/internal/router"
)

const (
	shutdownContextTimeout = 5 * time.Second
	readHeaderTimeout      = 5 * time.Second
)

func main() {
	cfg, loadErr := config.Load()
	if loadErr != nil {
		slog.Error("failed to load config", "error", loadErr)
		os.Exit(1)
	}
	// Reuse the control-plane mTLS credentials for the OTLP exporters. Nil when
	// no client cert/key is configured, leaving exporters on their default
	// transport.
	otlpTLS, tlsErr := config.BuildClientTLSConfig(&cfg)
	if tlsErr != nil {
		slog.Error("failed to build OTLP mTLS config", "error", tlsErr)
		os.Exit(1)
	}
	flush, err := setupTelemetry(&cfg, otlpTLS)
	defer flush()
	if err != nil {
		slog.Error("failed to initialize telemetry", "error", err)
		return
	}
	// Emitted here rather than where the opt-out is read, so the one line saying
	// this deployment is unobservable lands on the same stream, in the same
	// format, as everything an operator reads after it.
	if cfg.DisableTelemetry {
		slog.Warn(
			"telemetry export disabled by TRAVERSAL_DISABLE_TELEMETRY; " +
				"Traversal cannot diagnose issues in this deployment",
		)
	}

	ctx, cancel := signal.NotifyContext(
		context.Background(),
		os.Interrupt, syscall.SIGTERM, syscall.SIGHUP,
	)
	defer cancel()

	redactor, err := startRedaction(ctx, &cfg)
	if err != nil {
		slog.Error("refusing to start unredacted", "error", err)
		os.Exit(1)
	}

	// Probes answer with the tunnels' readiness, so the handler reads them
	// once New has returned.
	var tunnels *pipeserver.Tunnels
	tunnels, err = pipeserver.New(&cfg, redactor,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			router.Readiness(tunnels).ServeHTTP(w, r)
		}))
	if err != nil {
		slog.ErrorContext(ctx, "tunnels cannot start", "error", err)
		os.Exit(1)
	}
	done := tunnels.Start(ctx)

	slog.InfoContext(ctx, "traversal connector service starting",
		"controller_logical_url", cfg.TraversalControllerURL,
		"controller_logical_authority", logicalAuthority(cfg.TraversalControllerURL),
		"controller_effective_address", effectiveAddress(
			cfg.TraversalControllerConnectTo, cfg.TraversalControllerURL,
		),
		"tunnels", tunnels.Count,
		"env", cfg.EnvName)

	if err = client.CheckConnectivity(&cfg); err != nil {
		slog.Error("connectivity test failed", "error", err)
	}

	defer serveProbes(&cfg, tunnels)()
	<-done
	slog.InfoContext(ctx, "traversal connector service shutting down")
}

// setupTelemetry starts log, metric and trace export over otlpTLS, and
// returns what flushes them at exit. Local runs log text; others log JSON to
// stdout, and to OTLP when its endpoint is set.
func setupTelemetry(cfg *config.Config, otlpTLS *tls.Config) (flush func(), err error) {
	var localLogs slog.Handler
	if cfg.EnvLevel.IsDev() {
		localLogs = logging.NewTextHandler(os.Stdout)
	}
	flushTelemetry, err := telemetry.Setup(context.Background(), telemetry.Config{
		ServiceName:     cfg.OTELServiceName,
		Env:             cfg.EnvName,
		Protocol:        cfg.OTLPProtocol,
		LogsEndpoint:    cfg.OTLPLogsEndpoint,
		MetricsEndpoint: cfg.OTLPMetricsEndpoint,
		TracesEndpoint:  cfg.OTLPTracesEndpoint,
		TLS:             otlpTLS,
		// EGRESS_PROXY_URL, the exporters' forward proxy: used only when
		// mTLS is configured and the endpoint is TLS.
		EgressProxy: parseOTLPEgressProxyURL(cfg.EgressProxyURL),
		ConnectTo:   cfg.OTLPConnectTo,
		Fallback:    localLogs,
	})
	return func() { flushTelemetry(shutdownContextTimeout) }, err
}

// startRedaction loads the redaction rules, from a local file or Traversal's
// config endpoint, and keeps them current until ctx is done. A connector
// whose first load fails must not start: it would forward unredacted.
func startRedaction(ctx context.Context, cfg *config.Config) (*redact.Redactor, error) {
	redactor := redact.NewRedactor()
	switch {
	case cfg.RedactionRulesFile != nil:
		loader := redact.NewFileLoader(
			*cfg.RedactionRulesFile, redactor, cfg.RedactionReloadInterval,
		)
		if err := loader.LoadInitial(); err != nil {
			return nil, fmt.Errorf("local redaction rules: %w", err)
		}
		go func() {
			if err := loader.Run(ctx); err != nil {
				slog.Error("local redaction reload failed; exiting", "error", err)
				os.Exit(1)
			}
		}()
	case cfg.ConfigEnabled:
		httpClient, err := client.NewConfigHTTPClient(cfg)
		if err != nil {
			return nil, fmt.Errorf("config transport: %w", err)
		}
		endpoint, err := cfg.ConfigURL()
		if err != nil {
			return nil, fmt.Errorf("config endpoint: %w", err)
		}
		loader, err := redact.NewRemoteLoader(
			httpClient,
			endpoint,
			redactor,
			cfg.ConfigRefreshInterval,
		)
		if raw := os.Getenv("TRAVERSAL_CONFIG_KEYS"); err == nil && raw != "" {
			// Installed keys: only configs Traversal signed for this
			// connector apply. A bundle that does not parse refuses to start,
			// rather than running with unsigned configs.
			keys, keysErr := capability.ParseKeys([]byte(config.DecodePEM(raw)))
			if keysErr != nil {
				return nil, fmt.Errorf("TRAVERSAL_CONFIG_KEYS: %w", keysErr)
			}
			loader.RequireSignature(cfg.ConnectorID, keys)
		}
		if err == nil {
			err = loader.LoadInitial(ctx)
		}
		if err != nil {
			return nil, fmt.Errorf("initial remote config: %w", err)
		}
		go loader.Run(ctx)
	}
	return redactor, nil
}

// serveProbes serves /healthz and /readyz on HTTP_PORT, and returns what
// shuts the server down.
func serveProbes(cfg *config.Config, tunnels router.Tunnels) (shutdown func()) {
	srv := &http.Server{
		Addr:              ":" + cfg.HTTPPort,
		Handler:           router.NewRouter(*cfg, tunnels),
		ReadHeaderTimeout: readHeaderTimeout,
	}
	go func() {
		slog.Info("HTTP server starting", "port", cfg.HTTPPort)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("HTTP server error", "error", err)
		}
	}()
	return func() {
		ctx, cancel := context.WithTimeout(context.Background(), shutdownContextTimeout)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			slog.Error("failed to shutdown HTTP server", "error", err)
		}
	}
}

func effectiveAddress(connectTo, logicalURL string) string {
	if connectTo != "" {
		return connectTo
	}
	return logicalAuthority(logicalURL)
}

func logicalAuthority(logicalURL string) string {
	parsed, err := url.Parse(logicalURL)
	if err != nil {
		return ""
	}
	return parsed.Host
}

// parseOTLPEgressProxyURL parses cfg.EgressProxyURL for use by the OTLP
// exporters. An invalid value is logged and ignored — the exporters then
// dial directly. A nil input (proxy not configured) returns nil.
func parseOTLPEgressProxyURL(raw *string) *url.URL {
	if raw == nil {
		return nil
	}
	parsed, err := url.Parse(*raw)
	if err != nil {
		slog.Error(
			"invalid EGRESS_PROXY_URL for OTLP, exporters will dial direct",
			"egress_proxy_url", *raw, "error", err,
		)
		return nil
	}
	return parsed
}
