package rawclient

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/InteractionLabs/traversal-connector/connector-lib/dialpolicy"
	pb "github.com/InteractionLabs/traversal-connector/connector-lib/gen/connector/v1"
	"github.com/InteractionLabs/traversal-connector/connector-lib/gen/connector/v1/connectorconnect"
	"github.com/InteractionLabs/traversal-connector/connector-lib/rawtunnel"
	"github.com/InteractionLabs/traversal-connector/internal/client"
	"github.com/InteractionLabs/traversal-connector/internal/config"
	"github.com/InteractionLabs/traversal-connector/internal/redact"
)

func startManager(t *testing.T, cfg *config.Config, policy *dialpolicy.Policy) *Manager {
	t.Helper()
	m, err := newManager(cfg, redact.NewRedactor(), func() (
		connectorconnect.ConnectorServiceClient, func(), error,
	) {
		return client.NewIsolatedClient(cfg)
	}, discardLogs(), policy)
	if err != nil {
		t.Fatal(err)
	}
	m.backoff.initial = 5 * time.Millisecond
	m.backoff.max = 20 * time.Millisecond
	m.Start()
	return m
}

func recvMux(t *testing.T, ctrl *muxCtrl) *rawtunnel.Mux {
	t.Helper()
	select {
	case mux := <-ctrl.ready:
		return mux
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for a raw tunnel")
		return nil
	}
}

func TestDisabledManagerDoesNotDial(t *testing.T) {
	cfg := baseConfig("http://127.0.0.1:1")
	cfg.RawTunnel.Enabled = false
	m, err := newManager(cfg, nil, func() (
		connectorconnect.ConnectorServiceClient, func(), error,
	) {
		t.Fatal("disabled manager dialed")
		return nil, nil, nil
	}, discardLogs(), nil)
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	m.Start()
	m.Shutdown()
	m.Shutdown()
	if time.Since(started) > time.Second {
		t.Fatalf("disabled shutdown took %s", time.Since(started))
	}
}

func TestRawTunnelsUseSeparateConnections(t *testing.T) {
	ctrl := newMuxCtrl()
	srv := serveH2C(t, ctrl)
	t.Cleanup(srv.close)
	cfg := baseConfig(srv.url)
	cfg.RawTunnel.MaxTunnels = 2
	m := startManager(t, cfg, nil)
	t.Cleanup(m.Shutdown)

	waitFor(t, 3*time.Second, func() bool {
		active, _ := m.snapshot()
		return active == 2
	})
	ports := map[string]bool{}
	for {
		select {
		case addr := <-srv.remotes:
			_, port, err := net.SplitHostPort(addr)
			if err != nil {
				t.Fatal(err)
			}
			ports[port] = true
		default:
			if len(ports) < 2 {
				t.Fatalf("raw tunnels shared a connection: %v", ports)
			}
			return
		}
	}
}

func TestIsolatedClientSpeaksTLS(t *testing.T) {
	certPEM, keyPEM := serverCert(t)
	ctrl := newMuxCtrl()
	path, handler := connectorconnect.NewConnectorServiceHandler(ctrl)
	mux := http.NewServeMux()
	mux.Handle(path, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), respKey{}, w)
		handler.ServeHTTP(w, r.WithContext(ctx))
	}))
	pair, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		t.Fatal(err)
	}
	var protocols http.Protocols
	protocols.SetHTTP2(true)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{
		Handler: mux, Protocols: &protocols, ReadHeaderTimeout: time.Second,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{pair},
			MinVersion:   tls.VersionTLS12,
			NextProtos:   []string{"h2"},
		},
	}
	go func() { _ = srv.Serve(tls.NewListener(ln, srv.TLSConfig)) }()
	t.Cleanup(func() { _ = srv.Close() })

	cfg := baseConfig("https://" + ln.Addr().String())
	cfg.TLSCert = &certPEM
	cfg.TLSKey = &keyPEM
	cfg.TLSCA = &certPEM
	m := startManager(t, cfg, nil)
	t.Cleanup(m.Shutdown)
	recvMux(t, ctrl)
	waitFor(t, 3*time.Second, func() bool {
		active, _ := m.snapshot()
		return active == 1
	})
}

func serverCert(t *testing.T) (string, string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(
		rand.Reader, template, template, &priv.PublicKey, priv,
	)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	return certPEM, keyPEM
}

func TestUnansweredPingDoesNotDropTheTunnel(t *testing.T) {
	ctrl := &pingCtrl{pings: make(chan struct{}, 4)}
	srv := serveH2C(t, ctrl)
	t.Cleanup(srv.close)
	cfg := baseConfig(srv.url)
	cfg.RawTunnel.PingInterval = 20 * time.Millisecond
	m := startManager(t, cfg, nil)
	t.Cleanup(m.Shutdown)
	for range 2 {
		select {
		case <-ctrl.pings:
		case <-time.After(2 * time.Second):
			t.Fatal("tunnel ended before two unanswered pings")
		}
	}
	if active, _ := m.snapshot(); active != 1 {
		t.Fatalf("active tunnels = %d after unanswered pings", active)
	}
}

func TestIncompatibleRawHelloLeavesLegacyTunnelUp(t *testing.T) {
	bad := &badVersionCtrl{calls: make(chan struct{}, 8)}
	srv := serveH2C(t, bad)
	t.Cleanup(srv.close)
	cfg := baseConfig(srv.url)
	cm, err := client.NewConnectionManager(cfg, redact.NewRedactor())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = cm.Run(ctx) }()
	waitFor(t, 3*time.Second, func() bool { return cm.ActiveCount() == 1 })

	m := startManager(t, cfg, nil)
	t.Cleanup(m.Shutdown)
	for range 2 {
		select {
		case <-bad.calls:
		case <-time.After(2 * time.Second):
			t.Fatal("raw tunnel did not retry an incompatible hello")
		}
	}
	if got := cm.ActiveCount(); got != 1 {
		t.Fatalf("legacy tunnels = %d, want 1", got)
	}
}

func TestIdleRotationReplacesWithoutBackoff(t *testing.T) {
	ctrl := newMuxCtrl()
	srv := serveH2C(t, ctrl)
	t.Cleanup(srv.close)
	cfg := baseConfig(srv.url)
	cfg.RawTunnel.MaxTunnels = 1
	m, err := newManager(cfg, redact.NewRedactor(), func() (
		connectorconnect.ConnectorServiceClient, func(), error,
	) {
		return client.NewIsolatedClient(cfg)
	}, discardLogs(), nil)
	if err != nil {
		t.Fatal(err)
	}
	m.backoff.initial = 30 * time.Second
	m.backoff.max = 30 * time.Second
	m.Start()
	t.Cleanup(m.Shutdown)

	first := recvMux(t, ctrl)
	first.Drain(pb.RawDrainReason_RAW_DRAIN_REASON_ROTATION)
	first.Close(pb.RawCloseReason_RAW_CLOSE_REASON_TUNNEL_LOST)
	started := time.Now()
	_ = recvMux(t, ctrl)
	if time.Since(started) > 2*time.Second {
		t.Fatalf("replacement waited %s, want the reconnect backoff skipped", time.Since(started))
	}
}
