package telemetry

import (
	"context"
	"crypto/tls"
	"net/url"
	"testing"

	"github.com/google/go-cmp/cmp"
	"go.opentelemetry.io/otel/attribute"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
)

func TestParseOTLPEndpoint(t *testing.T) {
	tests := []struct {
		name     string
		raw      string
		expected OTLPEndpoint
	}{
		{
			name:     "https with path",
			raw:      "https://otel.example.com/ot/v1/logs",
			expected: OTLPEndpoint{Host: "otel.example.com", Path: "/ot/v1/logs", TLS: true},
		},
		{
			name:     "https with port and path",
			raw:      "https://otel.example.com:443/ot/v1/logs",
			expected: OTLPEndpoint{Host: "otel.example.com:443", Path: "/ot/v1/logs", TLS: true},
		},
		{
			name:     "https no path",
			raw:      "https://collector.example.com",
			expected: OTLPEndpoint{Host: "collector.example.com", Path: "", TLS: true},
		},
		{
			name:     "http with port and path",
			raw:      "http://localhost:4318/v1/metrics",
			expected: OTLPEndpoint{Host: "localhost:4318", Path: "/v1/metrics", TLS: false},
		},
		{
			name:     "http no path",
			raw:      "http://localhost:4318",
			expected: OTLPEndpoint{Host: "localhost:4318", Path: "", TLS: false},
		},
		{
			name:     "bare host:port",
			raw:      "localhost:4318",
			expected: OTLPEndpoint{Host: "localhost:4318", Path: "", TLS: false},
		},
		{
			name:     "bare host only",
			raw:      "collector",
			expected: OTLPEndpoint{Host: "collector", Path: "", TLS: false},
		},
		{
			name:     "empty string",
			raw:      "",
			expected: OTLPEndpoint{Host: "", Path: "", TLS: false},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseOTLPEndpoint(tt.raw)
			if diff := cmp.Diff(tt.expected, got); diff != "" {
				t.Errorf(
					"ParseOTLPEndpoint(%q) mismatch (-want +got):\n%s",
					tt.raw, diff,
				)
			}
		})
	}
}

func TestIsGRPCProtocol(t *testing.T) {
	tests := []struct {
		protocol string
		expected bool
	}{
		{"grpc", true},
		{"http/protobuf", true},
		{"http/json", false},
		{"", false},
		{"unknown", false},
	}

	for _, tt := range tests {
		t.Run(tt.protocol, func(t *testing.T) {
			got := IsGRPCProtocol(tt.protocol)
			if got != tt.expected {
				t.Errorf(
					"IsGRPCProtocol(%q) = %v, want %v",
					tt.protocol, got, tt.expected,
				)
			}
		})
	}
}

func TestInsecureTLS(t *testing.T) {
	cfg := InsecureTLS()
	if cfg == nil {
		t.Fatal("InsecureTLS() returned nil")
	}
	if !cfg.InsecureSkipVerify {
		t.Error("InsecureSkipVerify should be true")
	}
}

func TestNewResource(t *testing.T) {
	// Ensure OTEL_RESOURCE_ATTRIBUTES does not leak between tests.
	t.Setenv("OTEL_RESOURCE_ATTRIBUTES", "")

	res, err := NewResource(context.Background(), "traversal-connector", "production")
	if err != nil {
		t.Fatalf("NewResource() error: %v", err)
	}

	attrs := res.Attributes()

	assertAttr(t, attrs, semconv.ServiceNameKey, "traversal-connector")
	assertAttr(t, attrs, semconv.DeploymentEnvironmentKey, "production")
	assertAttr(t, attrs, semconv.ServiceNamespaceKey, "production")

	// service.instance.id should be non-empty (hostname fallback).
	found := false
	for _, a := range attrs {
		if a.Key == semconv.ServiceInstanceIDKey {
			if a.Value.AsString() == "" {
				t.Error("service.instance.id should not be empty")
			}
			found = true
		}
	}
	if !found {
		t.Error("service.instance.id attribute missing")
	}
}

// TestNewResource_MergesOTELResourceAttributes verifies that custom attributes
// injected via the OTel-standard OTEL_RESOURCE_ATTRIBUTES env var are merged
// into the resource. This is the extensibility hook operators use to attach
// compliance IDs, team names, or any other site-specific metadata.
func TestNewResource_MergesOTELResourceAttributes(t *testing.T) {
	t.Setenv("OTEL_RESOURCE_ATTRIBUTES",
		"service.car.id=600003050,compliance.owner=finance")

	res, err := NewResource(context.Background(), "traversal-connector", "production")
	if err != nil {
		t.Fatalf("NewResource() error: %v", err)
	}

	attrs := res.Attributes()

	if !hasAttrKey(attrs, "service.car.id") {
		t.Error("expected service.car.id from OTEL_RESOURCE_ATTRIBUTES, not found")
	}
	if !hasAttrKey(attrs, "compliance.owner") {
		t.Error("expected compliance.owner from OTEL_RESOURCE_ATTRIBUTES, not found")
	}
}

func assertAttr(
	t *testing.T,
	attrs []attribute.KeyValue,
	key attribute.Key,
	wantVal string,
) {
	t.Helper()
	for _, a := range attrs {
		if a.Key == key {
			if got := a.Value.AsString(); got != wantVal {
				t.Errorf("attr %s = %q, want %q",
					key, got, wantVal)
			}
			return
		}
	}
	t.Errorf("attr %s not found", key)
}

func hasAttrKey(
	attrs []attribute.KeyValue, key string,
) bool {
	for _, a := range attrs {
		if string(a.Key) == key {
			return true
		}
	}
	return false
}

func TestPlanOTLPTransport(t *testing.T) {
	mtls := &tls.Config{MinVersion: tls.VersionTLS12}
	proxy, _ := url.Parse("http://proxy.example.com:3128")

	tests := []struct {
		name        string
		endpoint    string
		tlsConfig   *tls.Config
		proxyURL    *url.URL
		wantMTLS    bool
		wantProxy   bool
		wantInsec   bool
		wantHost    string
		wantPath    string
		wantTLSFlag bool
	}{
		{
			name:        "mtls https endpoint with proxy",
			endpoint:    "https://relay.example.com:443",
			tlsConfig:   mtls,
			proxyURL:    proxy,
			wantMTLS:    true,
			wantProxy:   true,
			wantInsec:   false,
			wantHost:    "relay.example.com:443",
			wantTLSFlag: true,
		},
		{
			name:        "mtls https endpoint without proxy",
			endpoint:    "https://relay.example.com:443",
			tlsConfig:   mtls,
			wantMTLS:    true,
			wantProxy:   false,
			wantInsec:   false,
			wantTLSFlag: true,
		},
		{
			name:      "mtls config but cleartext endpoint — no mtls, no proxy",
			endpoint:  "http://localhost:4317",
			tlsConfig: mtls,
			proxyURL:  proxy,
			wantMTLS:  false,
			wantProxy: false,
			wantInsec: true,
		},
		{
			name:        "https endpoint without mtls config",
			endpoint:    "https://relay.example.com",
			wantMTLS:    false,
			wantProxy:   false,
			wantInsec:   false,
			wantTLSFlag: true,
		},
		{
			name:      "cleartext endpoint, nothing extra",
			endpoint:  "localhost:4317",
			wantInsec: true,
		},
		{
			name:        "https endpoint with path",
			endpoint:    "https://otel.example.com/v1/logs",
			tlsConfig:   mtls,
			wantMTLS:    true,
			wantHost:    "otel.example.com",
			wantPath:    "/v1/logs",
			wantTLSFlag: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plan := planOTLPTransport(tt.endpoint, tt.tlsConfig, tt.proxyURL)
			if got := plan.UseMTLS(); got != tt.wantMTLS {
				t.Errorf("UseMTLS() = %v, want %v", got, tt.wantMTLS)
			}
			if got := plan.UseProxy(); got != tt.wantProxy {
				t.Errorf("UseProxy() = %v, want %v", got, tt.wantProxy)
			}
			if got := plan.UseInsecure(); got != tt.wantInsec {
				t.Errorf("UseInsecure() = %v, want %v", got, tt.wantInsec)
			}
			if tt.wantHost != "" && plan.Host != tt.wantHost {
				t.Errorf("Host = %q, want %q", plan.Host, tt.wantHost)
			}
			if tt.wantPath != "" && plan.Path != tt.wantPath {
				t.Errorf("Path = %q, want %q", plan.Path, tt.wantPath)
			}
			if plan.TLS != tt.wantTLSFlag {
				t.Errorf("TLS = %v, want %v", plan.TLS, tt.wantTLSFlag)
			}
		})
	}
}
