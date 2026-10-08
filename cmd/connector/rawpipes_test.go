package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http2"

	"github.com/InteractionLabs/traversal-connector/connector-lib/capability"
	"github.com/InteractionLabs/traversal-connector/connector-lib/capability/capabilitytest"
	pb "github.com/InteractionLabs/traversal-connector/connector-lib/gen/connector/v1"
	"github.com/InteractionLabs/traversal-connector/internal/config"
	"github.com/InteractionLabs/traversal-connector/internal/redact"
	"github.com/InteractionLabs/traversal-connector/internal/tunnels"
)

const (
	testConnector = "11111111-2222-4333-8444-555555555555"
	testTenant    = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
)

// testCA is a CA that signs both the connector's certificate and the fake
// tunnel gateway's.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  string
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &testCA{cert: cert, key: key,
		pem: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))}
}

// leaf issues a certificate from the CA, PEM.
func (ca *testCA) leaf(t *testing.T, tmpl *x509.Certificate) (cert, key string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl.SerialNumber = big.NewInt(time.Now().UnixNano())
	tmpl.NotBefore, tmpl.NotAfter = time.Now().Add(-time.Hour), time.Now().Add(time.Hour)
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &priv.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
}

// connectorLeaf is an org-scoped connector certificate, the shape
// production issues: client auth only.
func (ca *testCA) connectorLeaf(t *testing.T) (cert, key string) {
	t.Helper()
	san, _ := url.Parse("spiffe://traversal.com/tenant/" + testTenant + "/acme")
	return ca.leaf(t, &x509.Certificate{
		Subject:     pkix.Name{CommonName: "connector"},
		URIs:        []*url.URL{san},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
}

// rawPipesConfig is a config that can hold tunnels to endpoint, with a
// capability key.
func rawPipesConfig(t *testing.T, ca *testCA, endpoint string) *config.Config {
	t.Helper()
	capabilityKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert, key := ca.connectorLeaf(t)
	return &config.Config{
		TraversalControllerURL: "https://edge.traversal.test",
		ConnectorID:            testConnector,
		TLSCert:                &cert,
		TLSKey:                 &key,
		TLSCA:                  &ca.pem,
		RawPipes: config.RawPipes{
			Enabled:          true,
			MaxPipes:         10,
			CapabilityIssuer: "traversal-raw-tunnel/test",
			CapabilityKeys:   map[string]*ecdsa.PublicKey{"test": &capabilityKey.PublicKey},
			TunnelCount:      1,
			TunnelsConnectTo: endpoint,
		},
	}
}

// A raw pipe setup failure disables raw pipes only: startRawPipes reports
// no raw pipe side, and main carries on with the legacy transport.
func TestRawPipeSetupFailureLeavesLegacyRunning(t *testing.T) {
	ca := newTestCA(t)
	for name, mutate := range map[string]func(cfg *config.Config){
		"pipe server": func(cfg *config.Config) {
			cfg.RawPipes.CapabilityKeys = nil // the verifier needs a key
		},
		"tunnels": func(cfg *config.Config) {
			cfg.RawPipes.TunnelsConnectTo = "no-port" // not host:port
		},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := rawPipesConfig(t, ca, "127.0.0.1:1")
			// Otherwise the test passes for the wrong reason: a connector
			// that cannot hold tunnels never reaches the step under test.
			if _, err := tunnelConfig(cfg); err != nil {
				t.Fatalf("the base config cannot hold tunnels: %v", err)
			}
			mutate(cfg)
			if raw := startRawPipes(context.Background(), cfg, discardStatus, redact.NewRedactor()); raw != nil {
				t.Fatal("raw pipes started from a config that cannot run them")
			}
		})
	}
}

// fakeGateway is a tunnel gateway: it accepts tunnels, reads the preface,
// and is the HTTP/2 client on each.
type fakeGateway struct {
	ln      net.Listener
	tunnels chan *http2.ClientConn
	names   chan string
}

func newFakeGateway(t *testing.T, ca *testCA) *fakeGateway {
	t.Helper()
	cert, key := ca.leaf(t, &x509.Certificate{
		Subject:     pkix.Name{CommonName: "edge.traversal.test"},
		DNSNames:    []string{"edge.traversal.test"},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	pair, err := tls.X509KeyPair([]byte(cert), []byte(key))
	if err != nil {
		t.Fatal(err)
	}
	clients := x509.NewCertPool()
	clients.AddCert(ca.cert)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{pair},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clients,
		NextProtos:   []string{tunnels.ALPN},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	g := &fakeGateway{ln: ln, tunnels: make(chan *http2.ClientConn, 4), names: make(chan string, 4)}
	go func() {
		for {
			nc, err := ln.Accept()
			if err != nil {
				return
			}
			go g.serve(t, nc)
		}
	}()
	return g
}

func (g *fakeGateway) serve(t *testing.T, nc net.Conn) {
	// Byte by byte, so nothing of the HTTP/2 that follows is consumed.
	var line []byte
	for {
		b, err := readByte(nc)
		if err != nil {
			return
		}
		if b == '\n' {
			break
		}
		line = append(line, b)
	}
	g.names <- string(line)
	cc, err := (&http2.Transport{}).NewClientConn(nc)
	if err != nil {
		t.Error(err)
		return
	}
	g.tunnels <- cc
}

func readByte(r io.Reader) (byte, error) {
	var b [1]byte
	_, err := io.ReadFull(r, b[:])
	return b[0], err
}

// A connector dials its tunnel, names itself, and serves pipes on it; a
// drain request from the gateway makes it dial a replacement at once while
// the old tunnel stays up.
func TestTunnelServesPipesAndReplacesOnDrain(t *testing.T) {
	ca := newTestCA(t)
	gw := newFakeGateway(t, ca)
	cfg := rawPipesConfig(t, ca, gw.ln.Addr().String())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	raw := startRawPipes(ctx, cfg, discardStatus, redact.NewRedactor())
	if raw == nil {
		t.Fatal("raw pipes did not start")
	}
	t.Cleanup(func() { raw.stopTransport(); <-raw.tunnelsDone })

	if name := <-gw.names; name != tunnels.Preface+" "+testConnector {
		t.Fatalf("preface %q", name)
	}
	cc := <-gw.tunnels

	// A pipe without a capability is refused by the connector, over the
	// tunnel: the tunnel carries pipes.
	req, err := http.NewRequest(http.MethodConnect, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host, req.URL.Host = "db.internal:5432", "db.internal:5432"
	resp, err := cc.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized ||
		!strings.Contains(resp.Header.Get("X-Traversal-Reason"), "invalid_capability") {
		t.Fatalf("got %d %q, want 401 invalid_capability",
			resp.StatusCode, resp.Header.Get("X-Traversal-Reason"))
	}
	waitReady(t, raw)

	// The gateway asks for a replacement: a second tunnel arrives at once.
	drain, err := http.NewRequest(tunnels.DrainMethod, "http://tunnel/", nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp, err = cc.RoundTrip(drain); err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	select {
	case <-gw.names:
	case <-time.After(5 * time.Second):
		t.Fatal("no replacement tunnel after a drain request")
	}
	if !cc.State().Closed && !cc.CanTakeNewRequest() {
		t.Fatal("the drained tunnel stopped serving before the gateway closed it")
	}
}

func waitReady(t *testing.T, raw *rawPipes) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if ok, _ := raw.readiness()(context.Background()); ok {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("not ready with a tunnel up")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// With no gateway to reach, readiness waits for the grace period, then lets
// the connector serve the legacy transport only.
func TestReadinessWithoutTunnels(t *testing.T) {
	ca := newTestCA(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close() // nothing listens: every dial is refused
	tunnelCfg, err := tunnelConfig(rawPipesConfig(t, ca, addr))
	if err != nil {
		t.Fatal(err)
	}
	tunnelCfg.ReadyGrace = 200 * time.Millisecond
	tunnelCfg.Server = noServer{}
	m, err := tunnels.New(tunnelCfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = m.Run(ctx) }()
	if ok, why := m.Status(ctx); ok || !strings.Contains(why, "no tunnel") {
		t.Fatalf("ready without tunnels: %v %q", ok, why)
	}
	time.Sleep(300 * time.Millisecond)
	if ok, why := m.Status(ctx); !ok || !strings.Contains(why, "legacy transport only") {
		t.Fatalf("not ready after the grace: %v %q", ok, why)
	}
}

type noServer struct{}

func (noServer) ServeConn(net.Conn, func()) {}

func discardStatus(func() *pb.RawPipesStatus) {}

// With capability roots, the connector trusts a capability certified for the
// controller host it dials, and refuses one certified for any other: that is
// what keeps one environment's capabilities out of another's connectors.
func TestCapabilityRootsBindTheControllerHost(t *testing.T) {
	now := time.Now()
	rootKey := capabilitytest.Key("connector test capability root")
	envKey := capabilitytest.Key("connector test environment key")
	root, err := capabilitytest.NewRoot(rootKey, now.Add(-time.Hour), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{TraversalControllerURL: "https://Edge.Dev.Traversal.com:443/connect"}
	cfg.RawPipes.CapabilityRoots = []*x509.Certificate{root.Certificate}
	verifier, err := newCapabilityVerifier(cfg)
	if err != nil {
		t.Fatal(err)
	}
	claims := capability.Claims{
		Issuer: capability.IssuerPrefix + "dev", Audience: capability.Audience,
		Subject: capabilitySubject, OrganizationID: testTenant, IntegrationID: "i",
		ConnectorID: testConnector, Host: "db.internal", Port: 5432,
		Mode: capability.ModePassthrough, ConsumerID: "c", TrafficClass: "standard",
		SessionID: "s", JTI: "j", IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Minute).Unix(),
	}
	want := capability.Expected{
		ConnectorID: testConnector, Host: "db.internal", Port: 5432,
		Mode: pb.RawPipeMode_RAW_PIPE_MODE_PASSTHROUGH,
	}
	for host, ok := range map[string]bool{"edge.dev.traversal.com": true, "edge.prod.traversal.com": false} {
		cert, err := root.Issue(capabilitytest.EnvironmentCert{
			Key: &envKey.PublicKey, Issuer: capability.IssuerURIPrefix + "dev",
			Hosts: []string{host}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		})
		if err != nil {
			t.Fatal(err)
		}
		claims.JTI = host
		token, err := capabilitytest.SignChained(envKey, "dev", [][]byte{cert}, claims)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := verifier.Verify(token, want); (err == nil) != ok {
			t.Errorf("certificate for %s: verify = %v, want accepted %v", host, err, ok)
		}
	}
}
