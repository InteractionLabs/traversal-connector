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
	"strconv"
	"strings"
	"sync/atomic"
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
	return certWith(t, nil, uris...)
}

// certWith is a self-signed certificate with the given extended key usage
// and URI SANs.
func certWith(t *testing.T, eku []x509.ExtKeyUsage, uris ...string) []byte {
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
		ExtKeyUsage:  eku,
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

const (
	orgSAN       = "spiffe://traversal.com/tenant/" + testTenant + "/acme"
	connectorSAN = orgSAN + "/connector/" + testConnector
)

// An org-scoped certificate, the production shape, binds the tenant from
// its SAN and takes the connector ID from TRAVERSAL_CONNECTOR_ID. A
// connector-scoped certificate binds the same identity, and must name it.
func TestIdentityFromCertificate(t *testing.T) {
	want := Identity{ConnectorID: testConnector, TenantID: testTenant}
	for name, san := range map[string]string{"org-scoped": orgSAN, "connector-scoped": connectorSAN} {
		t.Run(name, func(t *testing.T) {
			id, err := IdentityFromCertificate(certWithURIs(t, san), testConnector)
			if err != nil || id != want {
				t.Fatalf("got %+v, %v; want %+v", id, err, want)
			}
		})
	}
	// Another connector of the same org shares the org-scoped certificate:
	// the known within-org limit.
	sibling := "99999999-2222-4333-8444-555555555555"
	id, err := IdentityFromCertificate(certWithURIs(t, orgSAN), sibling)
	if err != nil || id != (Identity{ConnectorID: sibling, TenantID: testTenant}) {
		t.Fatalf("sibling connector: %+v, %v", id, err)
	}
}

func TestIdentityRefusesCertificatesThatCannotHoldTunnels(t *testing.T) {
	for name, san := range map[string]string{
		"another connector":   orgSAN + "/connector/99999999-2222-4333-8444-555555555555",
		"processor":           orgSAN + "/processor/" + testConnector,
		"non-Traversal":       "spiffe://example.com/tenant/" + testTenant + "/acme",
		"not SPIFFE":          "https://traversal.com/tenant/" + testTenant + "/acme",
		"no org name":         "spiffe://traversal.com/tenant/" + testTenant,
		"malformed org UUID":  "spiffe://traversal.com/tenant/not-a-uuid/acme",
		"upper-case org UUID": "spiffe://traversal.com/tenant/" + strings.ToUpper(testTenant) + "/acme",
		"unknown workload":    orgSAN + "/agent/" + testConnector,
		"malformed connector": orgSAN + "/connector/not-a-uuid",
	} {
		t.Run(name, func(t *testing.T) {
			if id, err := IdentityFromCertificate(certWithURIs(t, san), testConnector); err == nil {
				t.Fatalf("accepted %s as %+v", san, id)
			}
		})
	}
	if _, err := IdentityFromCertificate([]byte("not pem"), testConnector); err == nil {
		t.Fatal("accepted garbage")
	}
}

// T-Envoy routes by the connector ID as a lower-case canonical UUID, so
// any other form is refused before the certificate is read.
func TestIdentityRequiresACanonicalConnectorID(t *testing.T) {
	for _, id := range []string{
		"", "connector-1", strings.ToUpper(testTenant),
		"{" + testConnector + "}", strings.ReplaceAll(testConnector, "-", ""),
	} {
		t.Run(id, func(t *testing.T) {
			for _, san := range []string{orgSAN, orgSAN + "/connector/" + id} {
				if got, err := IdentityFromCertificate(certWithURIs(t, san), id); err == nil {
					t.Fatalf("accepted connector ID %q with %s as %+v", id, san, got)
				}
			}
		})
	}
}

// An org-scoped certificate, as production issues, carries through to
// Envoy: the tunnel claims the certificate's org and the configured
// connector, and New accepts it for the data leg's inner TLS.
func TestOrgScopedCertificateBootstrap(t *testing.T) {
	const org = "cccccccc-dddd-4eee-8fff-000000000000"
	cert := certWith(t, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		"spiffe://traversal.com/tenant/"+org+"/acme")
	id, err := IdentityFromCertificate(cert, testConnector)
	if err != nil {
		t.Fatal(err)
	}
	m := newTestManager(t, func(c *Config) { c.Identity, c.CertPEM = id, cert })
	b := bootstrapOf(t, m)
	socket := staticResource(t, b, "listeners", tunnelListener)["address"].(map[string]any)
	addr := socket["socket_address"].(map[string]any)["address"]
	if want := "rc://" + testConnector + ":" + org + ":" + org + "@tunnels:1"; addr != want {
		t.Fatalf("listener address %v, want %v", addr, want)
	}
	if node := b["node"].(map[string]any); node["id"] != testConnector || node["cluster"] != org {
		t.Fatalf("node %v", node)
	}
	if _, ok := tunnelChain(t, b)["transport_socket"]; !ok {
		t.Fatal("no inner TLS with an org-scoped certificate")
	}
}

// The tunnel endpoint reads the first URI SAN only. A certificate with more
// than one could pass here and be refused there, so it is refused here,
// whichever order the SANs are in.
func TestIdentityRequiresExactlyOneURISAN(t *testing.T) {
	other := "spiffe://example.com/workload"
	for name, uris := range map[string][]string{
		"scoped first":      {connectorSAN, other},
		"scoped second":     {other, connectorSAN},
		"scoped twice":      {connectorSAN, connectorSAN},
		"org and connector": {orgSAN, connectorSAN},
		"two orgs":          {orgSAN, "spiffe://traversal.com/tenant/" + testConnector + "/other"},
	} {
		t.Run(name, func(t *testing.T) {
			if id, err := IdentityFromCertificate(certWithURIs(t, uris...), testConnector); err == nil {
				t.Fatalf("accepted %d URI SANs as %+v", len(uris), id)
			}
		})
	}
	if _, err := IdentityFromCertificate(certWithURIs(t), testConnector); !errors.Is(
		err, ErrNoTenantIdentity) {
		t.Fatalf("no URI SAN: %v", err)
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
		CertPEM:     certWithURIs(t),
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

// tunnelChain returns the tunnel listener's filter chain.
func tunnelChain(t *testing.T, b map[string]any) map[string]any {
	t.Helper()
	chains := staticResource(t, b, "listeners", tunnelListener)["filter_chains"].([]any)
	if len(chains) != 1 {
		t.Fatalf("want one tunnel filter chain, got %d", len(chains))
	}
	return chains[0].(map[string]any)
}

// By default each tunnel's data leg runs its own TLS 1.3, the connector as
// the server: it presents the dial's client certificate and requires the
// tunnel endpoint's, signed by the dial's roots and naming the controller's
// host. Without it Envoy carries pipes in cleartext once the dial's TLS
// session is dropped.
func TestBootstrapRequiresInnerTLSByDefault(t *testing.T) {
	m := newTestManager(t)
	socket, ok := tunnelChain(t, bootstrapOf(t, m))["transport_socket"].(map[string]any)
	if !ok {
		t.Fatal("the tunnel listener has no transport socket: the data leg is cleartext")
	}
	tls := socket["typed_config"].(map[string]any)
	if socket["name"] != "envoy.transport_sockets.tls" ||
		tls["@type"] != "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3."+
			"DownstreamTlsContext" ||
		tls["require_client_certificate"] != true {
		t.Fatalf("inner TLS %v", socket)
	}
	common := tls["common_tls_context"].(map[string]any)
	params, _ := json.Marshal(common["tls_params"])
	if string(params) != `{"tls_maximum_protocol_version":"TLSv1_3",`+
		`"tls_minimum_protocol_version":"TLSv1_3"}` {
		t.Fatalf("TLS versions %s", params)
	}
	if alpn, _ := json.Marshal(common["alpn_protocols"]); string(alpn) != `["h2"]` {
		t.Fatalf("ALPN %s", alpn)
	}
	certs, _ := json.Marshal(common["tls_certificates"])
	want, _ := json.Marshal([]any{map[string]any{
		"certificate_chain": map[string]any{"filename": filepath.Join(m.cfg.Dir, certFile)},
		"private_key":       map[string]any{"filename": filepath.Join(m.cfg.Dir, keyFile)},
	}})
	if string(certs) != string(want) {
		t.Fatalf("certificates %s, want %s", certs, want)
	}
	validation, _ := json.Marshal(common["validation_context"])
	want, _ = json.Marshal(map[string]any{
		"trusted_ca": map[string]any{"filename": filepath.Join(m.cfg.Dir, caFile)},
		"match_typed_subject_alt_names": []any{map[string]any{
			"san_type": "DNS", "matcher": map[string]any{"exact": "edge.traversal.com"},
		}},
	})
	if string(validation) != string(want) {
		t.Fatalf("validation context %s, want %s", validation, want)
	}
}

// Disabled inner TLS leaves the tunnel listener with no transport socket,
// for tunnel endpoints that do not speak it yet.
func TestBootstrapWithInnerTLSDisabled(t *testing.T) {
	b := bootstrapOf(t, newTestManager(t, func(c *Config) { c.InnerTLS = InnerTLSDisabled }))
	if socket, ok := tunnelChain(t, b)["transport_socket"]; ok {
		t.Fatalf("inner TLS disabled, but the tunnel listener has %v", socket)
	}
}

// Inner TLS makes the connector a TLS server, so a certificate restricted
// to clientAuth cannot serve it: New says so and names the fix. A
// certificate with no extended key usage, or with serverAuth, can.
func TestInnerTLSNeedsAServerCapableCertificate(t *testing.T) {
	clientOnly := certWith(t, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	_, err := New(func() Config { c := testConfig(t); c.CertPEM = clientOnly; return c }())
	if !errors.Is(err, ErrCertificateNotForServers) ||
		!strings.Contains(err.Error(), "serverAuth") ||
		!strings.Contains(err.Error(), "TRAVERSAL_TUNNEL_INNER_TLS=disabled") {
		t.Fatalf("clientAuth-only certificate: %v", err)
	}
	for name, eku := range map[string][]x509.ExtKeyUsage{
		"no extended key usage": nil,
		"client and server":     {x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		"any":                   {x509.ExtKeyUsageAny},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := testConfig(t)
			cfg.CertPEM = certWith(t, eku)
			if _, err := New(cfg); err != nil {
				t.Fatal(err)
			}
		})
	}
	t.Run("not checked with inner TLS disabled", func(t *testing.T) {
		cfg := testConfig(t)
		cfg.CertPEM, cfg.InnerTLS = clientOnly, InnerTLSDisabled
		if _, err := New(cfg); err != nil {
			t.Fatal(err)
		}
	})
}

func TestParseInnerTLS(t *testing.T) {
	for in, want := range map[string]InnerTLS{
		"required": InnerTLSRequired, "disabled": InnerTLSDisabled,
	} {
		if got, err := ParseInnerTLS(in); err != nil || got != want || got.String() != in {
			t.Fatalf("%q: got %v, %v", in, got, err)
		}
	}
	for _, in := range []string{"", "Required", "off", "true"} {
		if _, err := ParseInnerTLS(in); err == nil {
			t.Fatalf("accepted %q", in)
		}
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
	m.draining.Store(true)
	if ready, why := m.Status(context.Background()); ready || why != "draining" {
		t.Fatalf("draining: %v %q", ready, why)
	}
}

// Tunnels that just dropped keep the connector unready, briefly; tunnels
// down for longer than the grace no longer do.
func TestStatusToleratesTunnelsDownPastTheGrace(t *testing.T) {
	var connected atomic.Value
	connected.Store("1")
	stats := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("downstream_reverse_connection.worker_0.cluster.tunnels.connected: " +
			connected.Load().(string) + "\n"))
	}))
	defer stats.Close()
	m := newTestManager(t)
	m.cfg.ReadyGrace = 50 * time.Millisecond
	m.admin = admin{base: stats.URL, client: stats.Client()}
	if ready, why := m.Status(context.Background()); !ready {
		t.Fatalf("not ready with a tunnel up: %s", why)
	}
	time.Sleep(60 * time.Millisecond) // the grace counts from the drop, not startup
	connected.Store("0")
	if ready, why := m.Status(context.Background()); ready {
		t.Fatalf("ready with the tunnels just dropped: %s", why)
	}
	time.Sleep(60 * time.Millisecond)
	if ready, why := m.Status(context.Background()); !ready {
		t.Fatalf("still unready after the tunnels were down past the grace: %s", why)
	}
	connected.Store("1")
	if ready, why := m.Status(context.Background()); !ready || why != "" {
		t.Fatalf("tunnels back: %v %q", ready, why)
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

// Envoy drains immediately: every tunnel gets GOAWAY when the drain starts,
// not spread over Envoy's 600 s default, which would leave tunnel endpoints
// routing pipes to a connector already refusing them.
func TestEnvoyDrainsImmediately(t *testing.T) {
	args := strings.Join(envoyArgs("/run/envoy.json", 2), " ")
	for _, want := range []string{
		"--drain-strategy immediate",
		"--drain-time-s " + strconv.Itoa(int(envoyDrainTime/time.Second)),
		"--concurrency 2",
		"--config-path /run/envoy.json",
	} {
		if !strings.Contains(args, want) {
			t.Errorf("envoy args %q lack %q", args, want)
		}
	}
	if envoyDrainTime <= 0 || envoyDrainTime >= 30*time.Second {
		t.Errorf("drain time %s must be positive and inside the pod's 30 s grace", envoyDrainTime)
	}
}
