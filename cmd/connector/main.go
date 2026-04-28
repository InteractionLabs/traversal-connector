package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/InteractionLabs/traversal-connector/internal/client"
	"github.com/InteractionLabs/traversal-connector/internal/config"
	"github.com/InteractionLabs/traversal-connector/internal/logging"
	"github.com/InteractionLabs/traversal-connector/internal/redact"
	"github.com/InteractionLabs/traversal-connector/internal/router"
	"github.com/InteractionLabs/traversal-connector/internal/telemetry"
)

const (
	shutdownContextTimeout = 5 * time.Second
	readHeaderTimeout      = 5 * time.Second
)

func main() {
	cfg, loadErr := config.Load()
	if loadErr != nil {
		slog.Error("failed to load config", "err", loadErr)
		os.Exit(1)
	}

	// --- Logging ---
	// OTLP logs endpoint set → fanout (stdout JSON + OTLP)
	// Non-local              → stdout JSON
	// Local                  → pretty text
	switch {
	case cfg.OTLPLogsEndpoint != "":
		logger, shutdownLogs, logErr := telemetry.InitLogging(
			context.Background(),
			cfg.OTELServiceName,
			cfg.OTLPLogsEndpoint,
			cfg.OTLPProtocol,
			cfg.EnvName,
		)
		if logErr != nil {
			slog.Error("failed to initialize OTLP log export",
				"err", logErr)
			return
		}
		if shutdownLogs != nil {
			defer func() {
				ctx, cancel := context.WithTimeout(
					context.Background(), shutdownContextTimeout,
				)
				defer cancel()
				if err := shutdownLogs(ctx); err != nil {
					slog.ErrorContext(ctx,
						"failed to shutdown log exporter",
						"err", err)
				}
			}()
		}
		slog.SetDefault(logger)
	case !cfg.EnvLevel.IsDev():
		slog.SetDefault(slog.New(
			slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
				AddSource: true,
			}),
		))
	default:
		slog.SetDefault(slog.New(logging.NewTextHandler(os.Stdout)))
	}

	// --- Metrics ---
	shutdownMetrics, err := telemetry.InitMetrics(
		context.Background(),
		cfg.OTELServiceName,
		cfg.OTLPMetricsEndpoint,
		cfg.OTLPProtocol,
		cfg.EnvName,
	)
	if err != nil {
		slog.Error("failed to initialize metrics", "err", err)
		return
	}
	if shutdownMetrics != nil {
		defer func() {
			ctx, cancel := context.WithTimeout(
				context.Background(), shutdownContextTimeout,
			)
			defer cancel()
			if shutdownErr := shutdownMetrics(ctx); shutdownErr != nil {
				slog.ErrorContext(ctx,
					"failed to shutdown metrics", "err", shutdownErr)
			}
		}()
	}

	if err = telemetry.StartRuntimeMetricsCollector(); err != nil {
		slog.Error("failed to start runtime metrics collector",
			"err", err)
		return
	}

	// --- Tracing ---
	shutdownTracing, err := telemetry.InitTracing(
		context.Background(),
		cfg.OTELServiceName,
		cfg.OTLPTracesEndpoint,
		cfg.OTLPProtocol,
		cfg.EnvName,
	)
	if err != nil {
		slog.Error("failed to initialize tracing", "err", err)
		return
	}
	if shutdownTracing != nil {
		defer func() {
			ctx, cancel := context.WithTimeout(
				context.Background(), shutdownContextTimeout,
			)
			defer cancel()
			if shutdownErr := shutdownTracing(ctx); shutdownErr != nil {
				slog.ErrorContext(ctx,
					"failed to shutdown tracing", "err", shutdownErr)
			}
		}()
	}

	// --- Application ---
	ctx, cancel := signal.NotifyContext(
		context.Background(),
		os.Interrupt, syscall.SIGTERM, syscall.SIGHUP,
	)
	defer cancel()

	redactor := redact.NewRedactor()
	if cfg.RedactionRulesFile != nil {
		loader := redact.NewFileLoader(*cfg.RedactionRulesFile, redactor)
		if err = loader.LoadInitial(); err != nil {
			slog.Error("failed to load redaction rules", "err", err)
			return
		}
		go loader.Run(ctx)
	}

	cm, err := client.NewConnectionManager(&cfg, redactor)
	if err != nil {
		slog.Error("failed to create connection manager", "err", err)
		return
	}

	slog.InfoContext(ctx, "traversal connector service starting",
		"traversal_controller_url", cfg.TraversalControllerURL,
		"max_tunnels", cfg.MaxTunnelsAllowed,
		"env", cfg.EnvName)

	// Run a TLS connectivity test (equivalent to grpcurl -insecure -cert -key ... list).
	if err = client.TestConnectivity(&cfg); err != nil {
		slog.Error("connectivity test failed", "err", err)
	}

	// Start HTTP server for health and readiness endpoints.
	ginRouter := router.NewRouter(cfg, cm)
	srv := &http.Server{
		Addr:              ":" + cfg.HTTPPort,
		Handler:           ginRouter,
		ReadHeaderTimeout: readHeaderTimeout,
	}
	go func() {
		slog.Info("HTTP server starting", "port", cfg.HTTPPort)
		if serveErr := srv.ListenAndServe(); serveErr != nil &&
			serveErr != http.ErrServerClosed {
			slog.Error("HTTP server error", "err", serveErr)
		}
	}()
	defer func() {
		shutdownCtx, shutdownCancel := context.WithTimeout(
			context.Background(), shutdownContextTimeout,
		)
		defer shutdownCancel()
		if shutdownErr := srv.Shutdown(shutdownCtx); shutdownErr != nil {
			slog.Error("failed to shutdown HTTP server",
				"err", shutdownErr)
		}
	}()

	if err = cm.Run(ctx); err != nil {
		slog.ErrorContext(ctx,
			"connection manager exited with error", "err", err)
	}

	slog.InfoContext(ctx, "traversal connector service shutting down")
}
