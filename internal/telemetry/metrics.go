package telemetry

import (
	"context"
	"crypto/tls"
	"log/slog"
	"time"

	"go.opentelemetry.io/contrib/instrumentation/runtime"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/sdk/metric"
	"google.golang.org/grpc/credentials"
)

// InitMetrics initializes the OpenTelemetry metrics pipeline.
// The protocol parameter controls the exporter type:
//
//	"grpc" or "http/protobuf" → gRPC exporter
//	"http/json" or ""         → HTTP exporter (default)
//
// When tlsConfig is non-nil, it is used for the exporter transport
// (e.g. for mTLS to the OTLP endpoint). When nil, the default
// transport is used (insecure for non-TLS endpoints, system roots
// otherwise).
func InitMetrics(
	ctx context.Context,
	serviceName, otlpEndpoint, protocol, envName string,
	tlsConfig *tls.Config,
) (func(context.Context) error, error) {
	if otlpEndpoint == "" {
		slog.InfoContext(ctx,
			"skipping metrics initialization — no endpoint configured")
		//nolint:nilnil // intentional for optional init.
		return nil, nil
	}

	slog.InfoContext(ctx, "initializing OTLP metrics export",
		"otlp_endpoint", otlpEndpoint,
		"protocol", protocol,
		"service_name", serviceName,
		"env", envName,
		"mtls", tlsConfig != nil)

	res, err := NewResource(ctx, serviceName, envName)
	if err != nil {
		slog.ErrorContext(ctx, "failed to create OTLP resource",
			"error", err)
		return nil, err
	}

	var exporter metric.Exporter
	if IsGRPCProtocol(protocol) {
		exporter, err = newGRPCMetricsExporter(
			ctx, otlpEndpoint, tlsConfig,
		)
	} else {
		exporter, err = newHTTPMetricsExporter(
			ctx, otlpEndpoint, tlsConfig,
		)
	}
	if err != nil {
		slog.ErrorContext(ctx,
			"failed to create OTLP metrics exporter",
			"otlp_endpoint", otlpEndpoint,
			"protocol", protocol,
			"error", err)
		return nil, err
	}

	slog.InfoContext(ctx,
		"OTLP metrics exporter created, "+
			"setting up meter provider")

	meterProvider := metric.NewMeterProvider(
		metric.WithResource(res),
		metric.WithReader(
			metric.NewPeriodicReader(
				exporter,
				metric.WithInterval(10*time.Second),
			),
		),
	)

	otel.SetMeterProvider(meterProvider)

	slog.InfoContext(ctx,
		"metrics initialized — metrics are being exported",
		"otlp_endpoint", otlpEndpoint,
		"protocol", protocol,
		"env", envName,
		"service_name", serviceName)

	return meterProvider.Shutdown, nil
}

func newGRPCMetricsExporter(
	ctx context.Context, endpoint string, tlsConfig *tls.Config,
) (metric.Exporter, error) {
	ep := ParseOTLPEndpoint(endpoint)
	slog.InfoContext(ctx, "creating gRPC metrics exporter",
		"host", ep.Host, "tls", ep.TLS, "mtls", tlsConfig != nil)

	opts := []otlpmetricgrpc.Option{
		otlpmetricgrpc.WithEndpoint(ep.Host),
	}
	switch {
	case tlsConfig != nil && ep.TLS:
		opts = append(opts,
			otlpmetricgrpc.WithTLSCredentials(
				credentials.NewTLS(tlsConfig),
			),
		)
	case !ep.TLS:
		opts = append(opts, otlpmetricgrpc.WithInsecure())
	}

	return otlpmetricgrpc.New(ctx, opts...)
}

func newHTTPMetricsExporter(
	ctx context.Context, endpoint string, tlsConfig *tls.Config,
) (metric.Exporter, error) {
	ep := ParseOTLPEndpoint(endpoint)
	slog.InfoContext(ctx, "creating HTTP metrics exporter",
		"host", ep.Host, "path", ep.Path, "tls", ep.TLS,
		"mtls", tlsConfig != nil)

	opts := []otlpmetrichttp.Option{
		otlpmetrichttp.WithEndpoint(ep.Host),
	}
	if ep.Path != "" {
		opts = append(opts,
			otlpmetrichttp.WithURLPath(ep.Path),
		)
	}
	switch {
	case tlsConfig != nil && ep.TLS:
		opts = append(opts,
			otlpmetrichttp.WithTLSClientConfig(tlsConfig),
		)
	case ep.TLS:
		opts = append(opts,
			otlpmetrichttp.WithTLSClientConfig(InsecureTLS()),
		)
	default:
		opts = append(opts, otlpmetrichttp.WithInsecure())
	}

	return otlpmetrichttp.New(ctx, opts...)
}

// StartRuntimeMetricsCollector starts collecting Go runtime metrics.
func StartRuntimeMetricsCollector() error {
	return runtime.Start(
		runtime.WithMinimumReadMemStatsInterval(time.Second),
	)
}
