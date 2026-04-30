package telemetry

import (
	"context"
	"crypto/tls"
	"log/slog"
	"os"

	"go.opentelemetry.io/contrib/bridges/otelslog"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	"go.opentelemetry.io/otel/log/global"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	"google.golang.org/grpc/credentials"
)

// InitLogging initializes an OTLP log exporter and returns a
// multi-handler slog.Logger that writes to both stdout (JSON) and
// the OTLP endpoint. Returns a shutdown function to flush logs.
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
func InitLogging(
	ctx context.Context,
	serviceName, otlpEndpoint, protocol, envName string,
	tlsConfig *tls.Config,
) (*slog.Logger, func(context.Context) error, error) {
	jsonHandler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		AddSource: true,
	})

	if otlpEndpoint == "" {
		slog.InfoContext(ctx,
			"skipping OTLP log export — no endpoint configured")
		return slog.New(jsonHandler), nil, nil
	}

	slog.InfoContext(ctx, "initializing OTLP log export",
		"otlp_endpoint", otlpEndpoint,
		"protocol", protocol,
		"service_name", serviceName,
		"env", envName,
		"mtls", tlsConfig != nil)

	res, err := NewResource(ctx, serviceName, envName)
	if err != nil {
		slog.ErrorContext(ctx, "failed to create OTLP resource",
			"error", err)
		return nil, nil, err
	}

	var exporter sdklog.Exporter
	if IsGRPCProtocol(protocol) {
		exporter, err = newGRPCLogExporter(ctx, otlpEndpoint, tlsConfig)
	} else {
		exporter, err = newHTTPLogExporter(ctx, otlpEndpoint, tlsConfig)
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

	otelHandler := otelslog.NewHandler(serviceName)

	multiHandler := &fanoutHandler{
		handlers: []slog.Handler{jsonHandler, otelHandler},
	}

	logger := slog.New(multiHandler)

	slog.InfoContext(ctx,
		"OTLP log export active — logs are being shipped",
		"otlp_endpoint", otlpEndpoint,
		"protocol", protocol,
		"env", envName,
		"service_name", serviceName)

	return logger, loggerProvider.Shutdown, nil
}

func newGRPCLogExporter(
	ctx context.Context, endpoint string, tlsConfig *tls.Config,
) (sdklog.Exporter, error) {
	ep := ParseOTLPEndpoint(endpoint)
	slog.InfoContext(ctx, "creating gRPC log exporter",
		"host", ep.Host, "tls", ep.TLS, "mtls", tlsConfig != nil)

	opts := []otlploggrpc.Option{
		otlploggrpc.WithEndpoint(ep.Host),
	}
	switch {
	case tlsConfig != nil && ep.TLS:
		opts = append(opts,
			otlploggrpc.WithTLSCredentials(
				credentials.NewTLS(tlsConfig),
			),
		)
	case !ep.TLS:
		opts = append(opts, otlploggrpc.WithInsecure())
	}

	return otlploggrpc.New(ctx, opts...)
}

func newHTTPLogExporter(
	ctx context.Context, endpoint string, tlsConfig *tls.Config,
) (sdklog.Exporter, error) {
	ep := ParseOTLPEndpoint(endpoint)
	slog.InfoContext(ctx, "creating HTTP log exporter",
		"host", ep.Host, "path", ep.Path, "tls", ep.TLS,
		"mtls", tlsConfig != nil)

	opts := []otlploghttp.Option{
		otlploghttp.WithEndpoint(ep.Host),
	}
	if ep.Path != "" {
		opts = append(opts, otlploghttp.WithURLPath(ep.Path))
	}
	switch {
	case tlsConfig != nil && ep.TLS:
		opts = append(opts,
			otlploghttp.WithTLSClientConfig(tlsConfig),
		)
	case ep.TLS:
		opts = append(opts,
			otlploghttp.WithTLSClientConfig(InsecureTLS()),
		)
	default:
		opts = append(opts, otlploghttp.WithInsecure())
	}

	return otlploghttp.New(ctx, opts...)
}

// fanoutHandler sends every log record to multiple slog.Handlers.
type fanoutHandler struct {
	handlers []slog.Handler
}

func (f *fanoutHandler) Enabled(
	ctx context.Context, level slog.Level,
) bool {
	for _, h := range f.handlers {
		if h.Enabled(ctx, level) {
			return true
		}
	}
	return false
}

func (f *fanoutHandler) Handle(
	ctx context.Context, record slog.Record,
) error {
	for _, h := range f.handlers {
		if h.Enabled(ctx, record.Level) {
			if err := h.Handle(ctx, record); err != nil {
				return err
			}
		}
	}
	return nil
}

func (f *fanoutHandler) WithAttrs(
	attrs []slog.Attr,
) slog.Handler {
	handlers := make([]slog.Handler, len(f.handlers))
	for i, h := range f.handlers {
		handlers[i] = h.WithAttrs(attrs)
	}
	return &fanoutHandler{handlers: handlers}
}

func (f *fanoutHandler) WithGroup(name string) slog.Handler {
	handlers := make([]slog.Handler, len(f.handlers))
	for i, h := range f.handlers {
		handlers[i] = h.WithGroup(name)
	}
	return &fanoutHandler{handlers: handlers}
}
