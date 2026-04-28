package telemetry

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net/url"
	"os"
	"strings"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
)

const (
	// OTLPProtocolGRPC selects the gRPC OTLP exporter.
	OTLPProtocolGRPC = "grpc"
	// OTLPProtocolHTTPProtobuf selects the gRPC OTLP exporter
	// (same transport as "grpc").
	OTLPProtocolHTTPProtobuf = "http/protobuf"
	// OTLPProtocolHTTPJSON selects the HTTP/JSON OTLP exporter.
	OTLPProtocolHTTPJSON = "http/json"
)

// IsGRPCProtocol returns true when the OTLP protocol value indicates
// that the gRPC exporter should be used ("grpc" or "http/protobuf").
// When false (including empty / "http/json"), the HTTP exporter is used.
func IsGRPCProtocol(protocol string) bool {
	return protocol == OTLPProtocolGRPC ||
		protocol == OTLPProtocolHTTPProtobuf
}

// OTLPEndpoint holds the parsed components of an OTLP endpoint URL
// that HTTP exporters need (host, path, TLS flag).
type OTLPEndpoint struct {
	// Host is the host or host:port for the exporter.
	Host string
	// Path is the URL path (e.g. "/ot/v1/logs"). Empty for default.
	Path string
	// TLS indicates whether the endpoint uses HTTPS.
	TLS bool
}

// ParseOTLPEndpoint splits a full OTLP URL into host, path, and TLS
// flag. Accepts full URLs and bare host:port.
//
// Examples:
//
//	"https://otel.example.com/ot/v1/logs" → {Host: "otel.example.com", Path: "/ot/v1/logs", TLS: true}
//	"http://localhost:4318/v1/metrics" → {Host: "localhost:4318", Path: "/v1/metrics", TLS: false}
//	"localhost:4318"                   → {Host: "localhost:4318", Path: "", TLS: false}
func ParseOTLPEndpoint(raw string) OTLPEndpoint {
	if !strings.Contains(raw, "://") {
		return OTLPEndpoint{Host: raw}
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return OTLPEndpoint{Host: raw}
	}
	return OTLPEndpoint{
		Host: u.Host,
		Path: u.Path,
		TLS:  u.Scheme == "https",
	}
}

// InsecureTLS returns a TLS config with verification disabled,
// for use with internal endpoints that have self-signed certs.
//
//nolint:gosec // InsecureSkipVerify intentional for internal endpoints.
func InsecureTLS() *tls.Config {
	return &tls.Config{InsecureSkipVerify: true}
}

// NewResource builds an OTel resource with standard service metadata.
// Additional attributes can be injected by the operator via the
// OTEL_RESOURCE_ATTRIBUTES environment variable (OpenTelemetry standard),
// which is merged into the resource automatically.
func NewResource(
	ctx context.Context,
	serviceName, envName string,
) (*resource.Resource, error) {
	hostname, err := os.Hostname()
	if err != nil {
		slog.WarnContext(ctx, "failed to get hostname",
			"error", err)
		hostname = "unknown"
	}

	attrs := []attribute.KeyValue{
		semconv.ServiceNameKey.String(serviceName),
		semconv.ServiceNamespaceKey.String(envName),
		semconv.ServiceInstanceIDKey.String(hostname),
		semconv.DeploymentEnvironmentKey.String(envName),
	}

	slog.InfoContext(ctx, "building OTLP resource",
		"service.name", serviceName,
		"service.namespace", envName,
		"service.instance.id", hostname,
		"deployment.environment", envName,
		"total_attributes", len(attrs))

	return resource.New(ctx,
		resource.WithAttributes(attrs...),
		resource.WithFromEnv(),
	)
}
