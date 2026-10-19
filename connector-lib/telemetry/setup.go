// Package telemetry bootstraps OpenTelemetry for a service: OTLP logs,
// metrics and traces, over gRPC or HTTP, optionally with mutual TLS, a
// forward proxy or a fixed dial address. The connector uses it, and it is
// the core go-traversal's pkg/telemetry copies.
package telemetry

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net/url"
	"os"
	"sync"
	"time"
)

// Config says where a service's telemetry goes. An empty endpoint disables
// that signal's export; traces are still generated, for log correlation.
type Config struct {
	ServiceName string
	// Env names the deployment, as service.namespace and
	// deployment.environment.
	Env string
	// Protocol is OTEL_EXPORTER_OTLP_PROTOCOL: "grpc" or "http/protobuf"
	// select gRPC, anything else HTTP.
	Protocol                                      string
	LogsEndpoint, MetricsEndpoint, TracesEndpoint string
	// TLS, if set, is the exporters' client TLS, for mutual TLS to TLS
	// endpoints; EgressProxy, if set, is the forward proxy they reach TLS
	// endpoints through; ConnectTo, if set, is the address they dial
	// instead of the endpoint's.
	TLS         *tls.Config
	EgressProxy *url.URL
	ConnectTo   string
	// Fallback handles logs when LogsEndpoint is empty. Nil is JSON on
	// stdout.
	Fallback slog.Handler
}

// Setup starts the exporters cfg names and installs them as the global
// providers and the default slog logger, then Go runtime metrics. The
// returned flush is never nil, even with an error: defer it at once. It
// drains every exporter started at once, all within timeout.
func Setup(ctx context.Context, cfg Config) (flush func(timeout time.Duration), err error) {
	var shutdowns []func(context.Context) error
	flush = func(timeout time.Duration) { flushAll(shutdowns, timeout) }

	if cfg.LogsEndpoint == "" {
		handler := cfg.Fallback
		if handler == nil {
			handler = slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{AddSource: true})
		}
		slog.SetDefault(slog.New(handler))
	} else {
		logger, shutdown, logErr := InitLogging(ctx, cfg.ServiceName, cfg.LogsEndpoint,
			cfg.Protocol, cfg.Env, cfg.TLS, cfg.EgressProxy, cfg.ConnectTo)
		if logErr != nil {
			return flush, logErr
		}
		shutdowns = append(shutdowns, shutdown)
		slog.SetDefault(logger)
	}
	shutdown, err := InitMetrics(ctx, cfg.ServiceName, cfg.MetricsEndpoint, cfg.Protocol,
		cfg.Env, cfg.TLS, cfg.EgressProxy, cfg.ConnectTo)
	if err != nil {
		return flush, err
	}
	if shutdown != nil {
		shutdowns = append(shutdowns, shutdown)
	}
	if err := StartRuntimeMetricsCollector(); err != nil {
		return flush, err
	}
	shutdown, err = InitTracing(ctx, cfg.ServiceName, cfg.TracesEndpoint, cfg.Protocol,
		cfg.Env, cfg.TLS, cfg.EgressProxy, cfg.ConnectTo)
	if err != nil {
		return flush, err
	}
	shutdowns = append(shutdowns, shutdown)
	return flush, nil
}

// flushAll drains every exporter at once under one timeout, so together they
// add one timeout, not one each, to a stopping pod's budget. A flush error is
// logged to the default logger, which may be the exporter being drained.
func flushAll(shutdowns []func(context.Context) error, timeout time.Duration) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	var wg sync.WaitGroup
	for _, shutdown := range shutdowns {
		wg.Go(func() {
			if err := shutdown(ctx); err != nil {
				slog.ErrorContext(ctx, "failed to flush telemetry", "error", err)
			}
		})
	}
	wg.Wait()
}
