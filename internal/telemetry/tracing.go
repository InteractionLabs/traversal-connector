package telemetry

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net/http"
	"net/url"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"google.golang.org/grpc"
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
//
// When egressProxyURL is non-nil and the endpoint is TLS, exporter traffic
// is routed through the given HTTP forward proxy via CONNECT (gRPC) or
// http.ProxyURL (HTTP). The proxy is ignored for cleartext endpoints.
func InitTracing(
	ctx context.Context,
	serviceName, otlpEndpoint, protocol, envName string,
	tlsConfig *tls.Config,
	egressProxyURL *url.URL,
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
		transport := planOTLPTransport(otlpEndpoint, tlsConfig, egressProxyURL)
		slog.InfoContext(ctx, "initializing OTLP tracing export",
			"otlp_endpoint", otlpEndpoint,
			"protocol", protocol,
			"service_name", serviceName,
			"env", envName,
			slog.Group("transport", transport.LogFields()...),
		)

		var exporter sdktrace.SpanExporter
		if IsGRPCProtocol(protocol) {
			exporter, err = newGRPCTraceExporter(ctx, transport)
		} else {
			exporter, err = newHTTPTraceExporter(ctx, transport)
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
	ctx context.Context, t otlpTransport,
) (sdktrace.SpanExporter, error) {
	slog.InfoContext(ctx, "creating gRPC trace exporter",
		slog.Group("transport", t.LogFields()...))

	opts := []otlptracegrpc.Option{otlptracegrpc.WithEndpoint(t.Host)}
	if t.UseMTLS() {
		opts = append(opts,
			otlptracegrpc.WithTLSCredentials(
				credentials.NewTLS(t.TLSConfig),
			),
		)
	} else {
		opts = append(opts, otlptracegrpc.WithInsecure())
	}
	if t.UseProxy() {
		opts = append(opts,
			otlptracegrpc.WithDialOption(
				grpc.WithContextDialer(httpConnectDialer(t.EgressProxyURL)),
			),
		)
	}

	return otlptracegrpc.New(ctx, opts...)
}

func newHTTPTraceExporter(
	ctx context.Context, t otlpTransport,
) (sdktrace.SpanExporter, error) {
	slog.InfoContext(ctx, "creating HTTP trace exporter",
		slog.Group("transport", t.LogFields()...))

	opts := []otlptracehttp.Option{otlptracehttp.WithEndpoint(t.Host)}
	if t.Path != "" {
		opts = append(opts, otlptracehttp.WithURLPath(t.Path))
	}
	if t.UseMTLS() {
		opts = append(opts,
			otlptracehttp.WithTLSClientConfig(t.TLSConfig),
		)
	} else {
		opts = append(opts, otlptracehttp.WithInsecure())
	}
	if t.UseProxy() {
		opts = append(opts,
			otlptracehttp.WithProxy(http.ProxyURL(t.EgressProxyURL)),
		)
	}

	return otlptracehttp.New(ctx, opts...)
}
