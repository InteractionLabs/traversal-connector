package telemetry

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net/http"
	"net/url"

	"go.opentelemetry.io/contrib/bridges/otelslog"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	"go.opentelemetry.io/otel/log/global"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// InitLogging initializes an OTLP log exporter and returns an slog.Logger
// that ships records to the OTLP endpoint, along with a shutdown function to
// flush logs. This is the otlp log sink: records go to the endpoint only, so
// the caller is responsible for any stdout/file destination in other sinks.
//
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
// is routed through the given HTTP forward proxy.
func InitLogging(
	ctx context.Context,
	serviceName, otlpEndpoint, protocol, envName string,
	tlsConfig *tls.Config,
	egressProxyURL *url.URL,
) (*slog.Logger, func(context.Context) error, error) {
	if otlpEndpoint == "" {
		return nil, nil, errors.New(
			"OTLP logs endpoint is required for the otlp log sink",
		)
	}

	transport := planOTLPTransport(otlpEndpoint, tlsConfig, egressProxyURL)
	slog.InfoContext(ctx, "initializing OTLP log export",
		"otlp_endpoint", otlpEndpoint,
		"protocol", protocol,
		"service_name", serviceName,
		"env", envName,
		slog.Group("transport", transport.LogFields()...),
	)

	res, err := NewResource(ctx, serviceName, envName)
	if err != nil {
		slog.ErrorContext(ctx, "failed to create OTLP resource",
			"error", err)
		return nil, nil, err
	}

	var exporter sdklog.Exporter
	if IsGRPCProtocol(protocol) {
		exporter, err = newGRPCLogExporter(ctx, transport)
	} else {
		exporter, err = newHTTPLogExporter(ctx, transport)
	}
	if err != nil {
		slog.ErrorContext(ctx,
			"failed to create OTLP log exporter",
			"otlp_endpoint", otlpEndpoint,
			"protocol", protocol,
			"error", err)
		return nil, nil, err
	}

	slog.InfoContext(ctx,
		"OTLP log exporter created, setting up logger provider")

	loggerProvider := sdklog.NewLoggerProvider(
		sdklog.WithResource(res),
		sdklog.WithProcessor(
			sdklog.NewBatchProcessor(exporter),
		),
	)

	global.SetLoggerProvider(loggerProvider)
	slog.InfoContext(ctx, "global OTel LoggerProvider set")

	logger := slog.New(otelslog.NewHandler(serviceName))

	slog.InfoContext(ctx,
		"OTLP log export active — logs are being shipped",
		"otlp_endpoint", otlpEndpoint,
		"protocol", protocol,
		"env", envName,
		"service_name", serviceName)

	return logger, loggerProvider.Shutdown, nil
}

func newGRPCLogExporter(
	ctx context.Context, t otlpTransport,
) (sdklog.Exporter, error) {
	slog.InfoContext(ctx, "creating gRPC log exporter",
		slog.Group("transport", t.LogFields()...))

	opts := []otlploggrpc.Option{otlploggrpc.WithEndpoint(t.Host)}
	if t.UseMTLS() {
		opts = append(opts,
			otlploggrpc.WithTLSCredentials(
				credentials.NewTLS(t.TLSConfig),
			),
		)
	} else {
		opts = append(opts, otlploggrpc.WithInsecure())
	}
	if t.UseProxy() {
		opts = append(opts,
			otlploggrpc.WithDialOption(
				grpc.WithContextDialer(httpConnectDialer(t.EgressProxyURL)),
			),
		)
	}

	return otlploggrpc.New(ctx, opts...)
}

func newHTTPLogExporter(
	ctx context.Context, t otlpTransport,
) (sdklog.Exporter, error) {
	slog.InfoContext(ctx, "creating HTTP log exporter",
		slog.Group("transport", t.LogFields()...))

	opts := []otlploghttp.Option{otlploghttp.WithEndpoint(t.Host)}
	if t.Path != "" {
		opts = append(opts, otlploghttp.WithURLPath(t.Path))
	}
	if t.UseMTLS() {
		opts = append(opts,
			otlploghttp.WithTLSClientConfig(t.TLSConfig),
		)
	} else {
		opts = append(opts, otlploghttp.WithInsecure())
	}
	if t.UseProxy() {
		opts = append(opts,
			otlploghttp.WithProxy(http.ProxyURL(t.EgressProxyURL)),
		)
	}

	return otlploghttp.New(ctx, opts...)
}
