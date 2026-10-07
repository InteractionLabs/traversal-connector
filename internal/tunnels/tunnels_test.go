package tunnels

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/InteractionLabs/traversal-connector/internal/telemetry"
)

const (
	testConnector = "11111111-2222-4333-8444-555555555555"
	testTenant    = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
)

func certWithURIs(t *testing.T, uris ...string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "connector"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	for _, u := range uris {
		parsed, err := url.Parse(u)
		if err != nil {
			t.Fatal(err)
		}
		tmpl.URIs = append(tmpl.URIs, parsed)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestIdentityFromCertificate(t *testing.T) {
	scoped := "spiffe://traversal.com/tenant/" + testTenant + "/acme/connector/" + testConnector
	id, err := IdentityFromCertificate(certWithURIs(t, scoped), testConnector)
	if err != nil || id != (Identity{ConnectorID: testConnector, TenantID: testTenant}) {
		t.Fatalf("got %+v, %v", id, err)
	}

	tenantOnly := "spiffe://traversal.com/tenant/" + testTenant + "/acme"
	if _, err := IdentityFromCertificate(certWithURIs(t, tenantOnly), testConnector); !errors.Is(
		err, ErrNoConnectorIdentity) {
		t.Fatalf("tenant-only certificate: %v", err)
	}
	other := "spiffe://traversal.com/tenant/" + testTenant +
		"/acme/connector/99999999-2222-4333-8444-555555555555"
	if _, err := IdentityFromCertificate(certWithURIs(t, other), testConnector); err == nil {
		t.Fatal("accepted a certificate for another connector")
	}
	if _, err := IdentityFromCertificate([]byte("not pem"), testConnector); err == nil {
		t.Fatal("accepted garbage")
	}
}

// bootstrapOf reads the Envoy configuration m writes.
func bootstrapOf(t *testing.T, m *Manager) map[string]any {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(m.cfg.Dir, bootstrapFile))
	if err != nil {
		t.Fatal(err)
	}
	var b map[string]any
	if err := json.Unmarshal(data, &b); err != nil {
		t.Fatal(err)
	}
	return b
}

// staticResource returns the one static listener or cluster named name.
func staticResource(t *testing.T, b map[string]any, kind, name string) map[string]any {
	t.Helper()
	var found map[string]any
	for _, r := range b["static_resources"].(map[string]any)[kind].([]any) {
		if res := r.(map[string]any); res["name"] == name {
			if found != nil {
				t.Fatalf("two %s named %s", kind, name)
			}
			found = res
		}
	}
	if found == nil {
		t.Fatalf("no %s named %s", kind, name)
	}
	return found
}

// testConfig is a valid Config.
func testConfig(t *testing.T) Config {
	t.Helper()
	return Config{
		Identity:    Identity{ConnectorID: testConnector, TenantID: testTenant},
		Dir:         t.TempDir(),
		EnvoyPath:   "envoy",
		CoreAddress: "127.0.0.1:9100",
		MaxPipes:    200,
		Tunnels:     2,
		Endpoint:    "edge.traversal.com",
		CertPEM:     []byte("cert"),
		KeyPEM:      []byte("key"),
		CAPEM:       []byte("ca"),
	}
}

func newTestManager(t *testing.T, mutate ...func(*Config)) *Manager {
	t.Helper()
	cfg := testConfig(t)
	for _, f := range mutate {
		f(&cfg)
	}
	m, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.envoy.writeBootstrap(); err != nil {
		t.Fatal(err)
	}
	return m
}

// The connector holds its tunnels to one endpoint, the controller's host on
// 443: one listener, one tunnel per worker, and a cluster that sends the
// controller's host as SNI, verifies it, and offers the tunnel ALPN first.
func TestBootstrapHoldsTunnelsToTheControllerHost(t *testing.T) {
	b := bootstrapOf(t, newTestManager(t))
	if len(b["static_resources"].(map[string]any)["listeners"].([]any)) != 1 {
		t.Fatal("want exactly one listener")
	}
	if _, dynamic := b["dynamic_resources"]; dynamic {
		t.Fatal("the configuration is static; nothing should be watched")
	}
	listener := staticResource(t, b, "listeners", tunnelListener)
	addr := listener["address"].(map[string]any)["socket_address"].(map[string]any)["address"]
	want := "rc://" + testConnector + ":" + testTenant + ":" + testTenant + "@tunnels:1"
	if addr != want {
		t.Fatalf("listener address %v, want %v", addr, want)
	}
	// A GOAWAY from the tunnel endpoint must dial the replacement before
	// the draining tunnel closes.
	filter := listener["filter_chains"].([]any)[0].(map[string]any)["filters"].([]any)[0].(map[string]any)
	hcm := filter["typed_config"].(map[string]any)
	if filter["name"] != "envoy.filters.network.reverse_tunnel_drain_aware_http_connection_manager" ||
		hcm["enable_drain_with_goaway"] != true {
		t.Fatalf(
			"tunnel listener filter %v, drain with GOAWAY %v",
			filter["name"],
			hcm["enable_drain_with_goaway"],
		)
	}
	inner := hcm["hcm_config"].(map[string]any)
	if inner["stream_idle_timeout"] != "0s" {
		t.Fatalf("pipes HCM %v", inner)
	}
	// An idle tunnel must never be closed for idling: Envoy's default
	// closes a connection with no streams after an hour.
	if common, _ := inner["common_http_protocol_options"].(map[string]any); common["idle_timeout"] != "0s" {
		t.Fatalf("tunnel idle timeout %v, want 0s", inner["common_http_protocol_options"])
	}

	cluster := staticResource(t, b, "clusters", tunnelCluster)
	got, _ := json.Marshal(cluster["load_assignment"])
	if !strings.Contains(string(got), `"address":"edge.traversal.com","port_value":443`) {
		t.Fatalf("load assignment %s", got)
	}
	tls := cluster["transport_socket"].(map[string]any)["typed_config"].(map[string]any)
	if tls["sni"] != "edge.traversal.com" {
		t.Fatalf("SNI %v", tls["sni"])
	}
	common := tls["common_tls_context"].(map[string]any)
	if alpn, _ := json.Marshal(common["alpn_protocols"]); string(alpn) !=
		`["x-traversal-tunnel","h2"]` {
		t.Fatalf("ALPN %s", alpn)
	}
	san, _ := json.Marshal(common["validation_context"])
	if !strings.Contains(string(san), `"matcher":{"exact":"edge.traversal.com"}`) {
		t.Fatalf("validation context %s", san)
	}
}

// ConnectTo moves only where the connector dials; SNI and the certificate
// check still name the controller's host.
func TestConnectToOverridesOnlyTheDialAddress(t *testing.T) {
	b := bootstrapOf(t, newTestManager(t, func(c *Config) {
		c.ConnectTo = "vpce-123.example.internal:8443"
	}))
	cluster := staticResource(t, b, "clusters", tunnelCluster)
	got, _ := json.Marshal(cluster["load_assignment"])
	if !strings.Contains(string(got), `"address":"vpce-123.example.internal","port_value":8443`) {
		t.Fatalf("load assignment %s", got)
	}
	tls := cluster["transport_socket"].(map[string]any)["typed_config"].(map[string]any)
	if tls["sni"] != "edge.traversal.com" {
		t.Fatalf("SNI %v after connect-to", tls["sni"])
	}
}

func TestNewRejectsBadTunnelSettings(t *testing.T) {
	for name, mutate := range map[string]func(*Config){
		"no endpoint":        func(c *Config) { c.Endpoint = "" },
		"uppercase endpoint": func(c *Config) { c.Endpoint = "Edge.traversal.com" },
		"endpoint with port": func(c *Config) { c.Endpoint = "edge.traversal.com:443" },
		"no tunnels":         func(c *Config) { c.Tunnels = 0 },
		"too many tunnels":   func(c *Config) { c.Tunnels = MaxTunnels + 1 },
		"bad connect-to":     func(c *Config) { c.ConnectTo = "vpce.example.internal" },
	} {
		t.Run(name, func(t *testing.T) {
			cfg := testConfig(t)
			mutate(&cfg)
			if _, err := New(cfg); err == nil {
				t.Fatal("accepted invalid tunnel settings")
			}
		})
	}
}

func TestStatusGraceLetsLegacyServe(t *testing.T) {
	m := newTestManager(t)
	m.cfg.ReadyGrace = time.Millisecond
	m.admin = newAdmin(1) // nothing listens: Envoy "is not answering"
	time.Sleep(5 * time.Millisecond)
	if ready, why := m.Status(context.Background()); !ready {
		t.Fatalf("not ready after the grace with no tunnel ever up: %s", why)
	}
	m.everConnected.Store(true)
	if ready, _ := m.Status(context.Background()); ready {
		t.Fatal("ready without tunnels after tunnels had connected")
	}
	m.draining.Store(true)
	if ready, why := m.Status(context.Background()); ready || why != "draining" {
		t.Fatalf("draining: %v %q", ready, why)
	}
}

func TestBootstrapNamesTheConnector(t *testing.T) {
	m := newTestManager(t)
	data, err := os.ReadFile(filepath.Join(m.cfg.Dir, bootstrapFile))
	if err != nil {
		t.Fatal(err)
	}
	var b struct {
		Node struct{ ID, Cluster string } `json:"node"`
	}
	if err := json.Unmarshal(data, &b); err != nil {
		t.Fatal(err)
	}
	if b.Node.ID != testConnector || b.Node.Cluster != testTenant {
		t.Fatalf("node %+v", b.Node)
	}
}

// Readiness follows Envoy's tunnel gauges for the tunnel endpoint.
func TestStatusFollowsTheTunnelGauge(t *testing.T) {
	connected := "0"
	stats := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(
			"downstream_reverse_connection.worker_0.cluster.tunnels.connected: 0\n" +
				"downstream_reverse_connection.worker_1.cluster.tunnels.connected: " +
				connected + "\n"))
	}))
	defer stats.Close()
	m := newTestManager(t)
	m.admin = admin{base: stats.URL, client: stats.Client()}
	if ready, why := m.Status(context.Background()); ready ||
		why != "no tunnel to edge.traversal.com" {
		t.Fatalf("no tunnel: %v %q", ready, why)
	}
	connected = "1"
	if ready, why := m.Status(context.Background()); !ready {
		t.Fatalf("one worker's tunnel up: %q", why)
	}
}

// The tunnels gauge reads Envoy's tunnel gauges for the endpoint at each
// collection.
func TestTunnelsGaugeReportsEnvoysTunnels(t *testing.T) {
	stats := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(
			"downstream_reverse_connection.worker_0.cluster.tunnels.connected: 1\n" +
				"downstream_reverse_connection.worker_1.cluster.tunnels.connected: 1\n" +
				"downstream_reverse_connection.worker_1.cluster.other.connected: 5\n"))
	}))
	defer stats.Close()
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() { _ = provider.Shutdown(context.Background()) })
	m := newTestManager(t, func(c *Config) { c.MeterProvider = provider })
	m.admin = admin{base: stats.URL, client: stats.Client()}

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatal(err)
	}
	var got []int64
	for _, sm := range rm.ScopeMetrics {
		for _, metric := range sm.Metrics {
			if metric.Name == telemetry.MetricRawTunnelsActive {
				for _, dp := range metric.Data.(metricdata.Gauge[int64]).DataPoints {
					got = append(got, dp.Value)
				}
			}
		}
	}
	if len(got) != 1 || got[0] != 2 {
		t.Fatalf("tunnels gauge %v, want [2]", got)
	}
}
