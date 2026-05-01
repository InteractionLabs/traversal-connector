package telemetry

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"go.opentelemetry.io/contrib/instrumentation/runtime"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/sdk/metric"
	"google.golang.org/grpc"
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
//
// When internetProxyURL is non-nil and the endpoint is TLS, exporter traffic
// is routed through the given HTTP forward proxy.
func InitMetrics(
	ctx context.Context,
	serviceName, otlpEndpoint, protocol, envName string,
	tlsConfig *tls.Config,
	internetProxyURL *url.URL,
) (func(context.Context) error, error) {
	if otlpEndpoint == "" {
		slog.InfoContext(ctx,
			"skipping metrics initialization — no endpoint configured")
		//nolint:nilnil // intentional for optional init.
		return nil, nil
	}

	transport := planOTLPTransport(otlpEndpoint, tlsConfig, internetProxyURL)
	slog.InfoContext(ctx, "initializing OTLP metrics export",
		append([]any{
			"otlp_endpoint", otlpEndpoint,
			"protocol", protocol,
			"service_name", serviceName,
			"env", envName,
		}, transport.LogFields()...)...)

	res, err := NewResource(ctx, serviceName, envName)
	if err != nil {
		slog.ErrorContext(ctx, "failed to create OTLP resource",
			"error", err)
		return nil, err
	}

	var exporter metric.Exporter
	if IsGRPCProtocol(protocol) {
		exporter, err = newGRPCMetricsExporter(ctx, transport)
	} else {
		exporter, err = newHTTPMetricsExporter(ctx, transport)
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
	ctx context.Context, t otlpTransport,
) (metric.Exporter, error) {
	slog.InfoContext(ctx, "creating gRPC metrics exporter", t.LogFields()...)

	opts := []otlpmetricgrpc.Option{otlpmetricgrpc.WithEndpoint(t.Host)}
	switch {
	case t.UseMTLS():
		opts = append(opts,
			otlpmetricgrpc.WithTLSCredentials(
				credentials.NewTLS(t.TLSConfig),
			),
		)
	case t.UseInsecure():
		opts = append(opts, otlpmetricgrpc.WithInsecure())
	}
	if t.UseProxy() {
		opts = append(opts,
			otlpmetricgrpc.WithDialOption(
				grpc.WithContextDialer(httpConnectDialer(t.InternetProxyURL)),
			),
		)
	}

	return otlpmetricgrpc.New(ctx, opts...)
}

func newHTTPMetricsExporter(
	ctx context.Context, t otlpTransport,
) (metric.Exporter, error) {
	slog.InfoContext(ctx, "creating HTTP metrics exporter", t.LogFields()...)

	opts := []otlpmetrichttp.Option{otlpmetrichttp.WithEndpoint(t.Host)}
	if t.Path != "" {
		opts = append(opts, otlpmetrichttp.WithURLPath(t.Path))
	}
	switch {
	case t.UseMTLS():
		opts = append(opts,
			otlpmetrichttp.WithTLSClientConfig(t.TLSConfig),
		)
	case t.TLS:
		opts = append(opts,
			otlpmetrichttp.WithTLSClientConfig(InsecureTLS()),
		)
	default:
		opts = append(opts, otlpmetrichttp.WithInsecure())
	}
	if t.UseProxy() {
		opts = append(opts,
			otlpmetrichttp.WithProxy(http.ProxyURL(t.InternetProxyURL)),
		)
	}

	return otlpmetrichttp.New(ctx, opts...)
}

// StartRuntimeMetricsCollector starts collecting Go runtime metrics.
func StartRuntimeMetricsCollector() error {
	return runtime.Start(
		runtime.WithMinimumReadMemStatsInterval(time.Second),
	)
}
