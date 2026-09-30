package rawclient

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/InteractionLabs/traversal-connector/connector-lib/dialpolicy"
	pb "github.com/InteractionLabs/traversal-connector/connector-lib/gen/connector/v1"
	"github.com/InteractionLabs/traversal-connector/connector-lib/gen/connector/v1/connectorconnect"
	"github.com/InteractionLabs/traversal-connector/connector-lib/rawtunnel"
	"github.com/InteractionLabs/traversal-connector/internal/client"
	"github.com/InteractionLabs/traversal-connector/internal/config"
	"github.com/InteractionLabs/traversal-connector/internal/env"
	"github.com/InteractionLabs/traversal-connector/internal/redact"
	"github.com/InteractionLabs/traversal-connector/internal/router"
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

func recvMux(t *testing.T, ready <-chan *rawtunnel.Mux) *rawtunnel.Mux {
	t.Helper()
	select {
	case mux := <-ready:
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
		active, _, _, _ := m.snapshot()
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
		ReadTimeout: time.Hour,
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
	recvMux(t, ctrl.ready)
	waitFor(t, 3*time.Second, func() bool {
		active, _, _, _ := m.snapshot()
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
	ctrl := &pingCtrl{}
	srv := serveH2C(t, ctrl)
	t.Cleanup(srv.close)
	cfg := baseConfig(srv.url)
	cfg.RawTunnel.PingInterval = 20 * time.Millisecond
	m := startManager(t, cfg, nil)
	t.Cleanup(m.Shutdown)
	waitFor(t, 2*time.Second, func() bool {
		active, _, _, _ := m.snapshot()
		return active == 1
	})
	// The HTTP/2 stack answers the ping. A second tunnel would mean the slot
	// treated that exchange as a dead peer and reconnected.
	time.Sleep(1500 * time.Millisecond)
	if active, _, _, _ := m.snapshot(); active != 1 {
		t.Fatalf("active tunnels = %d after an unanswered ping", active)
	}
	if got := ctrl.tunnels.Load(); got != 1 {
		t.Fatalf("raw tunnels opened = %d, want 1", got)
	}
}

func TestIncompatibleRawHelloLeavesLegacyTunnelUp(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("legacy-ok"))
	}))
	t.Cleanup(upstream.Close)

	probe := make(chan struct{})
	ctrl := &legacyServingCtrl{
		upstreamURL:    upstream.URL,
		wantConcurrent: 7,
		probe:          probe,
		result:         make(chan legacyProbeResult, 1),
		rawCalls:       make(chan struct{}, 8),
	}
	srv := serveH2C(t, ctrl)
	t.Cleanup(srv.close)
	cfg := baseConfig(srv.url)
	cfg.MaxConcurrentRequests = 7
	cm, err := client.NewConnectionManager(cfg, redact.NewRedactor())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = cm.Run(ctx) }()
	waitFor(t, 3*time.Second, func() bool { return cm.ActiveCount() == 1 })
	assertReady(t, cm, 1)

	m := startManager(t, cfg, nil)
	t.Cleanup(m.Shutdown)
	for range 2 {
		select {
		case <-ctrl.rawCalls:
		case <-time.After(2 * time.Second):
			t.Fatal("raw tunnel did not retry an incompatible hello")
		}
	}
	if got := cm.ActiveCount(); got != 1 {
		t.Fatalf("legacy tunnels = %d, want 1", got)
	}
	close(probe)
	assertLegacyProbe(t, ctrl, "legacy-ok", 7)
	assertReady(t, cm, 1)
}

func TestLegacyServesWithRawDisabled(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("raw-off"))
	}))
	t.Cleanup(upstream.Close)

	ctrl := &legacyServingCtrl{
		upstreamURL:    upstream.URL,
		wantConcurrent: 5,
		result:         make(chan legacyProbeResult, 1),
	}
	srv := serveH2C(t, ctrl)
	t.Cleanup(srv.close)
	cfg := baseConfig(srv.url)
	cfg.RawTunnel.Enabled = false
	cfg.MaxConcurrentRequests = 5
	cm, err := client.NewConnectionManager(cfg, redact.NewRedactor())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = cm.Run(ctx) }()
	waitFor(t, 3*time.Second, func() bool { return cm.ActiveCount() == 1 })
	assertReady(t, cm, 1)

	m := startManager(t, cfg, nil)
	t.Cleanup(m.Shutdown)
	time.Sleep(100 * time.Millisecond)
	if active, draining, _, _ := m.snapshot(); active != 0 || draining != 0 {
		t.Fatalf("disabled raw manager opened tunnels: active=%d draining=%d", active, draining)
	}
	assertLegacyProbe(t, ctrl, "raw-off", 5)
	assertReady(t, cm, 1)
}

func TestLegacyServesWhileRawTunnelDraining(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("while-draining"))
	}))
	t.Cleanup(upstream.Close)

	probe := make(chan struct{})
	ctrl := &legacyServingCtrl{
		upstreamURL:    upstream.URL,
		wantConcurrent: 4,
		probe:          probe,
		result:         make(chan legacyProbeResult, 1),
		rawReady:       make(chan *rawtunnel.Mux, 8),
	}
	srv := serveH2C(t, ctrl)
	t.Cleanup(srv.close)
	cfg := baseConfig(srv.url)
	cfg.MaxConcurrentRequests = 4
	cm, err := client.NewConnectionManager(cfg, redact.NewRedactor())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = cm.Run(ctx) }()
	waitFor(t, 3*time.Second, func() bool { return cm.ActiveCount() == 1 })

	ln := listen(t)
	m := startManager(t, cfg, dialLocal(t, ln))
	t.Cleanup(m.Shutdown)
	var first *rawtunnel.Mux
	select {
	case first = <-ctrl.rawReady:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for a raw tunnel")
	}
	// An empty drained tunnel is closed locally. A live pipe is what keeps
	// the session draining while the legacy tunnel continues to serve.
	pipe, _, _ := holdPipe(t, first, ln, "jti-hold-drain")
	first.Drain(pb.RawDrainReason_RAW_DRAIN_REASON_ROTATION)
	select {
	case <-ctrl.rawReady:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for replacement raw tunnel")
	}
	waitFor(t, 2*time.Second, func() bool {
		active, draining, _, _ := m.snapshot()
		return active == 1 && draining == 1
	})
	if got := cm.ActiveCount(); got != 1 {
		t.Fatalf("legacy tunnels = %d, want 1", got)
	}
	close(probe)
	assertLegacyProbe(t, ctrl, "while-draining", 4)
	assertReady(t, cm, 1)
	select {
	case <-pipe.Done():
		t.Fatal("drain closed the live pipe")
	default:
	}
}

func assertLegacyProbe(
	t *testing.T, ctrl *legacyServingCtrl, wantBody string, wantConcurrent int32,
) {
	t.Helper()
	select {
	case got := <-ctrl.result:
		if got.err != nil {
			t.Fatal(got.err)
		}
		if got.status != http.StatusOK {
			t.Fatalf("legacy http status = %d, want %d", got.status, http.StatusOK)
		}
		if got.body != wantBody {
			t.Fatalf("legacy http body = %q, want %q", got.body, wantBody)
		}
		if got.concurrent != wantConcurrent {
			t.Fatalf(
				"MaxConcurrentRequests = %d, want %d",
				got.concurrent, wantConcurrent,
			)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for legacy probe")
	}
}

func assertReady(t *testing.T, cm *client.ConnectionManager, wantTunnels int) {
	t.Helper()
	cfg := config.Config{
		EnvLevel:        env.EnvLevelDevelopment,
		OTELServiceName: "test",
	}
	r := router.NewRouter(cfg, cm)
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)
	resp, err := http.Get(srv.URL + "/readyz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("readyz status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	var body struct {
		Status        string `json:"status"`
		ActiveTunnels int    `json:"active_tunnels"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.Status != "ready" || body.ActiveTunnels != wantTunnels {
		t.Fatalf("readyz body = %+v, want ready with %d tunnels", body, wantTunnels)
	}
}

func TestRotationKeepsThePipeAndOpensAReplacement(t *testing.T) {
	ctrl := newMuxCtrl()
	srv := serveH2C(t, ctrl)
	t.Cleanup(srv.close)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	var dials int
	policy := directPolicy(t,
		func(context.Context, string, string) ([]netip.Addr, error) {
			return []netip.Addr{checkedAddr()}, nil
		},
		countDialer(&dials, ln.Addr().String()),
	)
	_ = policy
	cfg := baseConfig(srv.url)
	m := startManager(t, cfg, policy)
	t.Cleanup(m.Shutdown)

	first := recvMux(t, ctrl.ready)
	dstCh := acceptOne(ln)
	pipe, peer := openPipe(t, first, sign(t, "jti-rotate"))
	dst := <-dstCh
	t.Cleanup(func() { _ = dst.Close() })

	first.Drain(pb.RawDrainReason_RAW_DRAIN_REASON_ROTATION)
	second := recvMux(t, ctrl.ready)
	waitFor(t, 2*time.Second, func() bool {
		active, draining, _, _ := m.snapshot()
		return active == 1 && draining == 1
	})
	if _, err := first.Open(
		sign(t, "jti-late"), testHost, testPort,
		pb.RawPipeMode_RAW_PIPE_MODE_PASSTHROUGH,
	); !errors.Is(err, rawtunnel.ErrDraining) {
		t.Fatalf("open on draining tunnel: %v", err)
	}
	if _, err := peer.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	_ = dst.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 4)
	if _, err := io.ReadFull(dst, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("rotation cut the pipe: %v %q", err, buf)
	}
	select {
	case <-pipe.Done():
		t.Fatal("rotation closed the pipe")
	default:
	}
	if second == nil {
		t.Fatal("replacement tunnel missing")
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

	first := recvMux(t, ctrl.ready)
	first.Drain(pb.RawDrainReason_RAW_DRAIN_REASON_ROTATION)
	first.Close(pb.RawCloseReason_RAW_CLOSE_REASON_TUNNEL_LOST)
	started := time.Now()
	_ = recvMux(t, ctrl.ready)
	if time.Since(started) > 2*time.Second {
		t.Fatalf("replacement waited %s, want the reconnect backoff skipped", time.Since(started))
	}
}

// TestRepeatedDrainKeepsSessionsBounded is the race-tested regression for
// controller-driven rotation that keeps each drained stream open: without a
// session bound and local empty-drain retirement, MaxTunnels=1 grew to
// sessions=7 active=1 draining=6 after six rotations.
func TestRepeatedDrainKeepsSessionsBounded(t *testing.T) {
	ctrl := newStickyDrainCtrl()
	srv := serveH2C(t, ctrl)
	t.Cleanup(srv.close)
	cfg := baseConfig(srv.url)
	cfg.RawTunnel.MaxTunnels = 1
	cfg.RawTunnel.ShutdownGrace = 200 * time.Millisecond
	cfg.RawTunnel.RotationDeadline = 200 * time.Millisecond
	m := startManager(t, cfg, nil)
	t.Cleanup(m.Shutdown)

	bound := 2 // sessionBound = 2 * MaxTunnels
	first := recvMux(t, ctrl.ready)
	for i := range 6 {
		first.Drain(pb.RawDrainReason_RAW_DRAIN_REASON_ROTATION)
		next := recvMux(t, ctrl.ready)
		waitFor(t, 3*time.Second, func() bool {
			active, draining, sessions, connecting := m.snapshot()
			total := active + draining + connecting
			return active == 1 && draining == 0 && connecting == 0 &&
				sessions == 1 && total <= bound &&
				int64(ctrl.live.Load()) <= int64(bound)
		})
		active, draining, sessions, connecting := m.snapshot()
		total := active + draining + connecting
		if total > bound || sessions > bound {
			t.Fatalf(
				"rotation %d: active=%d draining=%d connecting=%d sessions=%d (bound %d)",
				i+1, active, draining, connecting, sessions, bound,
			)
		}
		if live := int64(ctrl.live.Load()); live > int64(bound) {
			t.Fatalf("rotation %d: controller still has %d live streams", i+1, live)
		}
		first = next
	}
	active, draining, sessions, connecting := m.snapshot()
	if active != 1 || draining != 0 || connecting != 0 || sessions != 1 {
		t.Fatalf(
			"final: active=%d draining=%d connecting=%d sessions=%d",
			active, draining, connecting, sessions,
		)
	}
	if live := int64(ctrl.live.Load()); live > int64(bound) {
		t.Fatalf("final live streams = %d, want <= %d", live, bound)
	}
}

func TestRepeatedRotationWithALivePipeStaysBounded(t *testing.T) {
	ctrl := newStickyDrainCtrl()
	srv := serveH2C(t, ctrl)
	t.Cleanup(srv.close)
	ln := listen(t)
	cfg := baseConfig(srv.url)
	cfg.RawTunnel.MaxTunnels = 1
	cfg.RawTunnel.ShutdownGrace = 40 * time.Millisecond
	cfg.RawTunnel.RotationDeadline = time.Hour
	m := startManager(t, cfg, dialLocal(t, ln))
	t.Cleanup(m.Shutdown)

	dstCh := acceptOne(ln)
	current := recvMux(t, ctrl.ready)
	pipe, _ := openPipe(t, current, sign(t, "jti-held"))
	dst := <-dstCh
	t.Cleanup(func() { _ = dst.Close() })

	bound := 2 // sessionBound = 2 * MaxTunnels
	for i := range 4 {
		current.Drain(pb.RawDrainReason_RAW_DRAIN_REASON_ROTATION)
		current = recvMux(t, ctrl.ready)
		waitFor(t, 3*time.Second, func() bool {
			active, draining, sessions, connecting := m.snapshot()
			return active == 1 && connecting == 0 &&
				sessions <= bound && active+draining+connecting <= bound
		})
		select {
		case <-pipe.Done():
			t.Fatalf("rotation %d closed the live pipe", i+1)
		default:
		}
		active, draining, sessions, connecting := m.snapshot()
		if active+draining+connecting > bound || sessions > bound {
			t.Fatalf(
				"rotation %d: active=%d draining=%d connecting=%d sessions=%d",
				i+1, active, draining, connecting, sessions,
			)
		}
	}
}

// stickyDrainCtrl speaks the mux and leaves drained streams open until the
// connector retires them. That is the unbounded-accumulation case.
type stickyDrainCtrl struct {
	connectorconnect.UnimplementedConnectorServiceHandler
	ready chan *rawtunnel.Mux
	live  atomic.Int32
}

func newStickyDrainCtrl() *stickyDrainCtrl {
	return &stickyDrainCtrl{ready: make(chan *rawtunnel.Mux, 8)}
}

func (c *stickyDrainCtrl) RawTunnel(
	ctx context.Context,
	stream *connect.BidiStream[pb.RawTunnelChunk, pb.RawTunnelChunk],
) error {
	c.live.Add(1)
	defer c.live.Add(-1)
	return runController(ctx, stream, c.ready, time.Hour)
}

func (c *stickyDrainCtrl) Tunnel(
	_ context.Context,
	stream *connect.BidiStream[pb.ConnectorMessage, pb.ControllerMessage],
) error {
	for {
		if _, err := stream.Receive(); err != nil {
			return nil
		}
	}
}

func TestDrainKeepsHalfClosedSlowAndSilentPipes(t *testing.T) {
	ctrl := newMuxCtrl()
	srv := serveH2C(t, ctrl)
	t.Cleanup(srv.close)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	policy := directPolicy(t,
		func(context.Context, string, string) ([]netip.Addr, error) {
			return []netip.Addr{checkedAddr()}, nil
		},
		func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, ln.Addr().String())
		},
	)
	cfg := baseConfig(srv.url)
	m := startManager(t, cfg, policy)
	t.Cleanup(m.Shutdown)
	mux := recvMux(t, ctrl.ready)
	halfPipe, halfPeer, halfDst := holdPipe(t, mux, ln, "jti-half")
	if err := halfPeer.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	_ = halfDst.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := halfDst.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("half-close before drain: %v", err)
	}
	silentPipe, _, _ := holdPipe(t, mux, ln, "jti-silent")
	slowPipe, _, slowDst := holdPipe(t, mux, ln, "jti-slow")
	go func() { _, _ = slowDst.Write(bytes.Repeat([]byte("x"), 300<<10)) }()

	mux.Drain(pb.RawDrainReason_RAW_DRAIN_REASON_ROTATION)
	replacement := recvMux(t, ctrl.ready)
	waitFor(t, 2*time.Second, func() bool {
		active, draining, _, _ := m.snapshot()
		return active == 1 && draining == 1
	})
	next := acceptOne(ln)
	opened, err := replacement.Open(
		sign(t, "jti-new"), testHost, testPort,
		pb.RawPipeMode_RAW_PIPE_MODE_PASSTHROUGH,
	)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	if err := opened.WaitOpened(ctx); err != nil {
		t.Fatalf("replacement open: %v", err)
	}
	<-next
	for _, pipe := range []*rawtunnel.Pipe{halfPipe, silentPipe, slowPipe} {
		select {
		case <-pipe.Done():
			t.Fatal("drain closed a live pipe")
		default:
		}
	}
}

func holdPipe(
	t *testing.T, mux *rawtunnel.Mux, ln net.Listener, jti string,
) (*rawtunnel.Pipe, *net.TCPConn, *net.TCPConn) {
	t.Helper()
	dstCh := acceptOne(ln)
	pipe, peer := openPipe(t, mux, sign(t, jti))
	dst := (<-dstCh).(*net.TCPConn)
	t.Cleanup(func() {
		_ = peer.Close()
		_ = dst.Close()
	})
	return pipe, peer, dst
}

func acceptOne(ln net.Listener) <-chan net.Conn {
	ch := make(chan net.Conn, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		ch <- conn
	}()
	return ch
}
