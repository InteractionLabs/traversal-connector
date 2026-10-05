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

func TestDiscoveryValidation(t *testing.T) {
	valid := Discovery{
		Cell:     "0",
		Address:  "tunnels.traversal.com:443",
		Replicas: []string{"t-envoy-0.tunnels.traversal.com", "t-envoy-1.tunnels.traversal.com"},
	}
	if err := valid.validate(); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Discovery){
		"no port":          func(d *Discovery) { d.Address = "tunnels.traversal.com" },
		"bad port":         func(d *Discovery) { d.Address = "tunnels.traversal.com:0" },
		"uppercase name":   func(d *Discovery) { d.Replicas[0] = "T-envoy-0.tunnels.traversal.com" },
		"single label":     func(d *Discovery) { d.Replicas[0] = "t-envoy-0" },
		"repeated replica": func(d *Discovery) { d.Replicas[1] = "t-envoy-0.other.com" },
		"reserved name":    func(d *Discovery) { d.Replicas[0] = "core.tunnels.traversal.com" },
		"injection":        func(d *Discovery) { d.Replicas[0] = "a:b@c.tunnels.traversal.com" },
		"too many": func(d *Discovery) {
			d.Replicas = nil
			for i := range maxReplicas + 1 {
				d.Replicas = append(d.Replicas, "t-envoy-"+strings.Repeat("x", i%3+1)+
					string(rune('a'+i%26))+string(rune('a'+i/26))+".tunnels.traversal.com")
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			d := valid
			d.Replicas = append([]string{}, valid.Replicas...)
			mutate(&d)
			if err := d.validate(); err == nil {
				t.Fatal("accepted an invalid discovery answer")
			}
		})
	}
}

func TestFetchDiscovery(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/tunnels/"+testConnector {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(Discovery{
			Cell:    "0",
			Address: "tunnels.traversal.com:443",
			Replicas: []string{
				"t-envoy-1.tunnels.traversal.com",
				"t-envoy-0.tunnels.traversal.com",
			},
		})
	}))
	defer srv.Close()
	d, err := fetchDiscovery(
		context.Background(),
		srv.Client(),
		srv.URL+"/v1/tunnels/"+testConnector,
	)
	if err != nil {
		t.Fatal(err)
	}
	if d.Replicas[0] != "t-envoy-0.tunnels.traversal.com" {
		t.Fatalf("replicas not sorted: %v", d.Replicas)
	}
	if _, err := fetchDiscovery(context.Background(), srv.Client(), srv.URL+"/other"); err == nil {
		t.Fatal("accepted a 404")
	}
}

func readResources(t *testing.T, path string) []map[string]any {
	t.Helper()
	data, err := os.ReadFile(path) //nolint:gosec // test temp dir
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Resources []map[string]any `json:"resources"`
	}
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatal(err)
	}
	return file.Resources
}

func newTestManager(t *testing.T) *Manager {
	t.Helper()
	m, err := New(Config{
		Identity:        Identity{ConnectorID: testConnector, TenantID: testTenant},
		Dir:             t.TempDir(),
		EnvoyPath:       "envoy",
		CoreAddress:     "127.0.0.1:9100",
		MaxPipes:        200,
		PerReplica:      2,
		DiscoveryURL:    "https://edge.example.com/v1/tunnels/" + testConnector,
		DiscoveryClient: http.DefaultClient,
		CertPEM:         []byte("cert"),
		KeyPEM:          []byte("key"),
		CAPEM:           []byte("ca"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.envoy.writeBootstrap(); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestApplyWritesOneListenerAndClusterPerReplica(t *testing.T) {
	m := newTestManager(t)
	err := m.apply(Discovery{
		Cell:     "0",
		Address:  "tunnels.traversal.com:443",
		Replicas: []string{"t-envoy-0.tunnels.traversal.com", "t-envoy-1.tunnels.traversal.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	listeners := readResources(t, m.envoy.path(listenersFile))
	clusters := readResources(t, m.envoy.path(clustersFile))
	if len(listeners) != 2 || len(clusters) != 2 {
		t.Fatalf("%d listeners, %d clusters", len(listeners), len(clusters))
	}
	addr := listeners[1]["address"].(map[string]any)["socket_address"].(map[string]any)["address"]
	want := "rc://" + testConnector + ":" + testTenant + ":" + testTenant + "@t-envoy-1:1"
	if addr != want {
		t.Fatalf("listener address %v, want %v", addr, want)
	}
	tls := clusters[1]["transport_socket"].(map[string]any)["typed_config"].(map[string]any)
	if tls["sni"] != "t-envoy-1.tunnels.traversal.com" {
		t.Fatalf("cluster SNI %v", tls["sni"])
	}

	// Removing a replica leaves the other replica's listener untouched.
	before, _ := json.Marshal(listeners[0])
	if err := m.apply(Discovery{
		Cell:     "0",
		Address:  "tunnels.traversal.com:443",
		Replicas: []string{"t-envoy-0.tunnels.traversal.com"},
	}); err != nil {
		t.Fatal(err)
	}
	listeners = readResources(t, m.envoy.path(listenersFile))
	after, _ := json.Marshal(listeners[0])
	if len(listeners) != 1 || string(before) != string(after) {
		t.Fatalf("remaining listener changed:\n%s\n%s", before, after)
	}
	// The removed replica's cluster outlives its listener by one poll, so
	// Envoy never sees a listener naming a cluster it lacks.
	if n := len(readResources(t, m.envoy.path(clustersFile))); n != 2 {
		t.Fatalf("%d clusters right after scale-down, want the stale one kept", n)
	}
	if err := m.apply(Discovery{
		Cell:     "0",
		Address:  "tunnels.traversal.com:443",
		Replicas: []string{"t-envoy-0.tunnels.traversal.com"},
	}); err != nil {
		t.Fatal(err)
	}
	if n := len(readResources(t, m.envoy.path(clustersFile))); n != 1 {
		t.Fatalf("%d clusters after the next poll, want the stale one pruned", n)
	}
}

func TestConnectToOverridesTheEntryPoint(t *testing.T) {
	m := newTestManager(t)
	m.cfg.ConnectTo = "vpce-123.example.internal:8443"
	if err := m.apply(Discovery{
		Cell:     "0",
		Address:  "tunnels.traversal.com:443",
		Replicas: []string{"t-envoy-0.tunnels.traversal.com"},
	}); err != nil {
		t.Fatal(err)
	}
	clusters := readResources(t, m.envoy.path(clustersFile))
	got, _ := json.Marshal(clusters[0]["load_assignment"])
	if !strings.Contains(string(got), `"vpce-123.example.internal"`) ||
		!strings.Contains(string(got), "8443") {
		t.Fatalf("load assignment %s", got)
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
