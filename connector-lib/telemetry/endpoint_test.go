package telemetry

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"go.opentelemetry.io/otel/attribute"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
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

func TestOverrideHTTPClientDisablesAmbientProxyAndPreservesTLS(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13, ServerName: "logical.example"}
	plan := planOTLPTransport(
		"https://logical.example/v1/logs", tlsConfig, nil, "127.0.0.1:4318",
	)
	client := plan.overrideHTTPClient()
	if client == nil || client.Timeout != 10*time.Second {
		t.Fatalf("override client = %#v", client)
	}
	transport := client.Transport.(*http.Transport)
	if transport.Proxy != nil {
		t.Fatal("override transport must ignore ambient proxy variables")
	}
	if transport.DialContext == nil {
		t.Fatal("override transport has no fixed dialer")
	}
	if transport.TLSClientConfig == tlsConfig {
		t.Fatal("TLS config was not cloned")
	}
	if got := transport.TLSClientConfig.ServerName; got != "logical.example" {
		t.Fatalf("TLS ServerName = %q", got)
	}
}

func TestPlanOTLPTransportRetainsLogicalEndpointWithConnectToOverride(t *testing.T) {
	plan := planOTLPTransport(
		"https://telemetry.example:4317/custom/v1/traces",
		&tls.Config{MinVersion: tls.VersionTLS12}, nil,
		"telemetry-istio.traversal-gateways.svc.cluster.local:443",
	)
	if plan.Host != "telemetry.example:4317" || plan.Path != "/custom/v1/traces" {
		t.Fatalf("logical endpoint changed: %+v", plan)
	}
	if plan.ConnectTo != "telemetry-istio.traversal-gateways.svc.cluster.local:443" {
		t.Fatalf("ConnectTo = %q", plan.ConnectTo)
	}
	if len(plan.grpcDialOptions()) != 1 || plan.overrideHTTPClient() == nil {
		t.Fatal("override was not applied to both gRPC and HTTP transports")
	}
}

func TestGRPCDialOptionsPreserveLogicalAuthority(t *testing.T) {
	tests := []struct {
		name              string
		target            func(string) string
		connectTo         func(string) string
		expectedAuthority func(string) string
	}{
		{
			name:              "override dials fixed address",
			target:            func(string) string { return "passthrough:///logical-telemetry.invalid:4317" },
			connectTo:         func(address string) string { return address },
			expectedAuthority: func(string) string { return "logical-telemetry.invalid:4317" },
		},
		{
			name:              "absent override dials endpoint",
			target:            func(address string) string { return address },
			connectTo:         func(string) string { return "" },
			expectedAuthority: func(address string) string { return address },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("listen: %v", err)
			}
			t.Cleanup(func() { _ = listener.Close() })

			authority := make(chan string, 1)
			server := grpc.NewServer(grpc.UnaryInterceptor(
				func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
					md, _ := metadata.FromIncomingContext(ctx)
					authority <- md.Get(":authority")[0]
					return handler(ctx, req)
				},
			))
			healthpb.RegisterHealthServer(server, health.NewServer())
			go func() { _ = server.Serve(listener) }()
			t.Cleanup(server.Stop)

			address := listener.Addr().String()
			plan := otlpTransport{ConnectTo: tt.connectTo(address)}
			opts := []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}
			opts = append(opts, plan.grpcDialOptions()...)
			conn, err := grpc.NewClient(tt.target(address), opts...)
			if err != nil {
				t.Fatalf("new gRPC client: %v", err)
			}
			t.Cleanup(func() { _ = conn.Close() })

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if _, err := healthpb.NewHealthClient(conn).Check(ctx, &healthpb.HealthCheckRequest{}); err != nil {
				t.Fatalf("health check: %v", err)
			}
			if got := <-authority; got != tt.expectedAuthority(address) {
				t.Errorf("authority = %q, want %q", got, tt.expectedAuthority(address))
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
		name           string
		endpoint       string
		tlsConfig      *tls.Config
		egressProxyURL *url.URL
		wantMTLS       bool
		wantProxy      bool
		wantHost       string
		wantPath       string
	}{
		{
			name:           "mtls https endpoint with proxy",
			endpoint:       "https://example.traversal.com:443",
			tlsConfig:      mtls,
			egressProxyURL: proxy,
			wantMTLS:       true,
			wantProxy:      true,
			wantHost:       "example.traversal.com:443",
		},
		{
			name:      "mtls https endpoint without proxy",
			endpoint:  "https://example.traversal.com:443",
			tlsConfig: mtls,
			wantMTLS:  true,
			wantProxy: false,
		},
		{
			// planOTLPTransport drops mTLS material and proxy for
			// cleartext endpoints — invariant relied on by every
			// exporter constructor.
			name:           "mtls config but cleartext endpoint — material dropped",
			endpoint:       "http://localhost:4317",
			tlsConfig:      mtls,
			egressProxyURL: proxy,
			wantMTLS:       false,
			wantProxy:      false,
		},
		{
			name:      "cleartext endpoint, nothing extra",
			endpoint:  "localhost:4317",
			wantMTLS:  false,
			wantProxy: false,
		},
		{
			name:      "https endpoint with path",
			endpoint:  "https://otel.example.com/v1/logs",
			tlsConfig: mtls,
			wantMTLS:  true,
			wantHost:  "otel.example.com",
			wantPath:  "/v1/logs",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plan := planOTLPTransport(tt.endpoint, tt.tlsConfig, tt.egressProxyURL, "")
			if got := plan.UseMTLS(); got != tt.wantMTLS {
				t.Errorf("UseMTLS() = %v, want %v", got, tt.wantMTLS)
			}
			if got := plan.UseProxy(); got != tt.wantProxy {
				t.Errorf("UseProxy() = %v, want %v", got, tt.wantProxy)
			}
			if tt.wantHost != "" && plan.Host != tt.wantHost {
				t.Errorf("Host = %q, want %q", plan.Host, tt.wantHost)
			}
			if tt.wantPath != "" && plan.Path != tt.wantPath {
				t.Errorf("Path = %q, want %q", plan.Path, tt.wantPath)
			}
		})
	}
}
