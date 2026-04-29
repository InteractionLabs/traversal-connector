package telemetry

import (
	"context"
	"crypto/tls"
	"log/slog"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"google.golang.org/grpc/credentials"
)

// InitTracing initializes the OpenTelemetry tracing pipeline.
// The protocol parameter controls the exporter type:
//
//	"grpc" or "http/protobuf" → gRPC exporter
//	"http/json" or ""         → HTTP exporter (default)
//
// When tlsConfig is non-nil, it is used for the exporter transport
// (e.g. for mTLS to the OTLP endpoint). When nil, the default
// transport is used (insecure for non-TLS endpoints, system roots
// otherwise).
func InitTracing(
	ctx context.Context,
	serviceName, otlpEndpoint, protocol, envName string,
	tlsConfig *tls.Config,
) (func(context.Context) error, error) {
	res, err := NewResource(ctx, serviceName, envName)
	if err != nil {
		slog.ErrorContext(ctx, "failed to create OTLP resource",
			"error", err)
		return nil, err
	}

	opts := []sdktrace.TracerProviderOption{
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
	}

	if otlpEndpoint != "" {
		slog.InfoContext(ctx, "initializing OTLP tracing export",
			"otlp_endpoint", otlpEndpoint,
			"protocol", protocol,
			"service_name", serviceName,
			"env", envName,
			"mtls", tlsConfig != nil)

		var exporter sdktrace.SpanExporter
		if IsGRPCProtocol(protocol) {
			exporter, err = newGRPCTraceExporter(
				ctx, otlpEndpoint, tlsConfig,
			)
		} else {
			exporter, err = newHTTPTraceExporter(
				ctx, otlpEndpoint, tlsConfig,
			)
		}
		if err != nil {
			slog.ErrorContext(ctx,
				"failed to create OTLP trace exporter",
				"otlp_endpoint", otlpEndpoint,
				"protocol", protocol,
				"error", err)
			return nil, err
		}

		opts = append(opts, sdktrace.WithBatcher(exporter))
	} else {
		slog.InfoContext(ctx,
			"no OTLP endpoint configured — "+
				"traces will be generated for log correlation "+
				"but not exported")
	}

	traceProvider := sdktrace.NewTracerProvider(opts...)

	otel.SetTracerProvider(traceProvider)

	otel.SetTextMapPropagator(
		propagation.NewCompositeTextMapPropagator(
			propagation.TraceContext{},
			propagation.Baggage{},
		),
	)

	slog.InfoContext(ctx,
		"tracing initialized",
		"otlp_endpoint", otlpEndpoint,
		"protocol", protocol,
		"env", envName,
		"service_name", serviceName,
		"exporting", otlpEndpoint != "")

	return traceProvider.Shutdown, nil
}

func newGRPCTraceExporter(
	ctx context.Context, endpoint string, tlsConfig *tls.Config,
) (sdktrace.SpanExporter, error) {
	ep := ParseOTLPEndpoint(endpoint)
	slog.InfoContext(ctx, "creating gRPC trace exporter",
		"host", ep.Host, "tls", ep.TLS, "mtls", tlsConfig != nil)

	opts := []otlptracegrpc.Option{
		otlptracegrpc.WithEndpoint(ep.Host),
	}
	switch {
	case tlsConfig != nil && ep.TLS:
		opts = append(opts,
			otlptracegrpc.WithTLSCredentials(
				credentials.NewTLS(tlsConfig),
			),
		)
	case !ep.TLS:
		opts = append(opts, otlptracegrpc.WithInsecure())
	}

	return otlptracegrpc.New(ctx, opts...)
}

func newHTTPTraceExporter(
	ctx context.Context, endpoint string, tlsConfig *tls.Config,
) (sdktrace.SpanExporter, error) {
	ep := ParseOTLPEndpoint(endpoint)
	slog.InfoContext(ctx, "creating HTTP trace exporter",
		"host", ep.Host, "path", ep.Path, "tls", ep.TLS,
		"mtls", tlsConfig != nil)

	opts := []otlptracehttp.Option{
		otlptracehttp.WithEndpoint(ep.Host),
	}
	if ep.Path != "" {
		opts = append(opts,
			otlptracehttp.WithURLPath(ep.Path),
		)
	}
	switch {
	case tlsConfig != nil && ep.TLS:
		opts = append(opts,
			otlptracehttp.WithTLSClientConfig(tlsConfig),
		)
	case ep.TLS:
		opts = append(opts,
			otlptracehttp.WithTLSClientConfig(InsecureTLS()),
		)
	default:
		opts = append(opts, otlptracehttp.WithInsecure())
	}

	return otlptracehttp.New(ctx, opts...)
}
