package rawpipes

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http2"

	"github.com/InteractionLabs/traversal-connector/connector-lib/capability"
	"github.com/InteractionLabs/traversal-connector/connector-lib/capability/capabilitytest"
	"github.com/InteractionLabs/traversal-connector/connector-lib/halfconn"
	"github.com/InteractionLabs/traversal-connector/connector-lib/rawpipe"
)

const connector = "6f1c0a52-8d3e-4b7a-9c21-5e4f3a2b1d00"

// loopback dials every destination at addr, standing in for dialpolicy,
// which refuses loopback.
type loopback string

func (a loopback) Dial(
	ctx context.Context,
	_ string,
	_ uint16,
) (halfconn.Conn, string, error) {
	c, err := (&net.Dialer{}).DialContext(ctx, "tcp", string(a))
	if err != nil {
		return nil, "", rawpipe.Errorf(rawpipe.DialFailed, "%v", err)
	}
	return c.(*net.TCPConn), string(a), nil //nolint:forcetypeassert // tcp
}

// echo upper-cases what it reads until EOF, then closes.
func echo(t *testing.T) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			b, _ := io.ReadAll(c)
			_, _ = c.Write([]byte(strings.ToUpper(string(b))))
			_ = c.Close()
		}
	}()
	return ln.Addr().String()
}

// testMetrics are the raw pipe metrics on the global meter, a no-op in tests.
func testMetrics(t *testing.T) *metrics {
	t.Helper()
	m, err := newMetrics()
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// controller listens for a tunnel and points tunnels at itself. accept takes
// the tunnel, checks its preface reports the tunnels' connector and trust,
// and returns an HTTP/2 client on it, as the edge controller does.
func controller(t *testing.T, tunnels *Tunnels) (accept func() *http2.ClientConn) {
	srv := httptest.NewTLSServer(nil)
	t.Cleanup(srv.Close)
	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	ln, err := tls.Listen("tcp", "127.0.0.1:0",
		&tls.Config{Certificates: srv.TLS.Certificates, NextProtos: []string{rawpipe.ALPN}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	tunnels.Addr = ln.Addr().String()
	tunnels.TLS = &tls.Config{
		RootCAs:    roots,
		ServerName: "example.com",
		NextProtos: []string{rawpipe.ALPN},
	}
	return func() *http2.ClientConn {
		c, err := ln.Accept()
		if err != nil {
			t.Fatal(err)
		}
		line, err := bufio.NewReader(c).ReadString('\n')
		id, roots, kids, ok := rawpipe.ParsePreface(line)
		if err != nil || !ok || id != connector || !slices.Equal(roots, tunnels.Roots) ||
			!slices.Equal(kids, tunnels.Kids) {
			t.Fatalf("preface %q: %v", line, err)
		}
		cc, err := (&http2.Transport{}).NewClientConn(c)
		if err != nil {
			t.Fatal(err)
		}
		return cc
	}
}

// open opens a pipe, sending body and then closing the caller's end once
// hold is closed. It returns the status, the refusal reason, and the
// destination's bytes.
func open(
	t *testing.T,
	cc *http2.ClientConn,
	token, body string,
	hold <-chan struct{},
) (int, string, io.ReadCloser) {
	pr, pw := io.Pipe()
	req, _ := http.NewRequest(http.MethodConnect, "https://db.internal:5432", pr)
	req.Host = "db.internal:5432"
	req.Header.Set(rawpipe.HeaderCapability, token)
	go func() {
		_, _ = pw.Write([]byte(body))
		if hold != nil {
			<-hold
		}
		_ = pw.Close()
	}()
	resp, err := cc.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp.StatusCode, resp.Header.Get(rawpipe.HeaderReason), resp.Body
}

func read(r io.Reader) string { b, _ := io.ReadAll(r); return string(b) }

func TestPipes(t *testing.T) {
	key := capabilitytest.Key("rawpipes")
	verifier, err := capability.NewVerifier(capability.VerifierConfig{
		Issuer: "traversal-raw-tunnel/test", Subject: "integration-proxy",
		Keys: map[string]*ecdsa.PublicKey{"k": &key.PublicKey},
	})
	if err != nil {
		t.Fatal(err)
	}
	tunnels := &Tunnels{ConnectorID: connector, Count: 1, Kids: []string{"k"}, Server: &Server{
		ConnectorID: connector, Verifier: verifier, Policy: loopback(echo(t)), MaxPipes: 4,
		metrics: testMetrics(t),
	}}
	accept := controller(t, tunnels)
	ctx, cancel := context.WithCancel(t.Context())
	done := tunnels.Start(ctx)
	cc := accept()

	token := func() string {
		tok, err := capability.Sign(key, "k",
			capabilitytest.Claims("traversal-raw-tunnel/test", connector, "db.internal", 5432))
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	if status, _, body := open(t, cc, token(), "ping", nil); status != 200 || read(body) != "PING" {
		t.Fatalf("pipe: %d", status)
	}
	if status, reason, _ := open(t, cc, "bogus", "", nil); status != 401 ||
		reason != string(rawpipe.InvalidCapability) {
		t.Fatalf("bad capability: %d %s", status, reason)
	}
	if ok, _ := tunnels.Ready(ctx); !ok {
		t.Fatal("not ready with a tunnel up")
	}
	// The customer's switch: tunnels stay, raw TCP is refused before any dial.
	tunnels.Server.RefuseTCP = true
	if status, reason, _ := open(t, cc, token(), "", nil); status != 403 ||
		reason != string(rawpipe.TCPRefused) {
		t.Fatalf("refused: %d %s", status, reason)
	}
	tunnels.Server.RefuseTCP = false
	// A raw pipe to a host redaction rules cover is refused before any dial.
	tunnels.Server.RequiresInspection = func(h string) bool { return h == "db.internal" }
	if status, reason, _ := open(t, cc, token(), "", nil); status != 403 ||
		reason != string(rawpipe.InspectionRequired) {
		t.Fatalf("redacted host: %d %s", status, reason)
	}
	tunnels.Server.RequiresInspection = nil

	// A draining connector refuses new pipes and lets open ones finish.
	hold := make(chan struct{})
	_, _, held := open(t, cc, token(), "held", hold)
	cancel()
	for !tunnels.Server.pipes.Draining() {
		time.Sleep(time.Millisecond)
	}
	if status, reason, _ := open(t, cc, token(), "", nil); status != 503 ||
		reason != string(rawpipe.Draining) {
		t.Fatalf("draining: %d %s", status, reason)
	}
	close(hold)
	if got := read(held); got != "HELD" {
		t.Fatalf("held pipe: %q", got)
	}
	<-done
}

// TestRedial: a tunnel the edge controller drops is redialed, and a drain
// request gets a replacement at once while the old tunnel stays open.
func TestRedial(t *testing.T) {
	tunnels := &Tunnels{ConnectorID: connector, Count: 1,
		Server: &Server{ConnectorID: connector, metrics: testMetrics(t)}}
	accept := controller(t, tunnels)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	tunnels.Start(ctx)
	next := func(within time.Duration) *http2.ClientConn {
		t.Helper()
		got := make(chan *http2.ClientConn, 1)
		go func() { got <- accept() }()
		select {
		case cc := <-got:
			return cc
		case <-time.After(within):
			t.Fatalf("no tunnel within %v", within)
			return nil
		}
	}
	first := next(5 * time.Second)
	_ = first.Close() // the edge controller drops the tunnel
	second := next(5 * time.Second)

	req, _ := http.NewRequest(rawpipe.DrainMethod, "http://tunnel/", http.NoBody)
	resp, err := second.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	next(500 * time.Millisecond) // the replacement comes without backoff
	if !second.CanTakeNewRequest() {
		t.Error("the replaced tunnel closed before the edge controller closed it")
	}
}

// TestRedialBackoff: redial waits double from 0.5-1 s and stay within
// 15-30 s once capped.
func TestRedialBackoff(t *testing.T) {
	for range 200 {
		b := redialBackoff()
		lo := 500 * time.Millisecond
		for range 10 {
			hi := 2 * lo
			if wait := b.NextBackOff(); wait < lo || wait > hi {
				t.Fatalf("wait %v, want %v to %v", wait, lo, hi)
			}
			lo = min(2*lo, 15*time.Second)
		}
	}
}

// TestTunnelServerLimits: the tunnel advertises the connector's pipe limit
// per tunnel (so opens past it are capacity refusals, not open timeouts),
// and pings a quiet tunnel so a dead far end is found.
func TestTunnelServerLimits(t *testing.T) {
	s := &Server{MaxPipes: 4000}
	h := s.h2(2)
	if h.MaxConcurrentStreams < 2000 || h.MaxConcurrentStreams > 2100 {
		t.Errorf("MaxConcurrentStreams = %d for 4000 pipes over 2 tunnels", h.MaxConcurrentStreams)
	}
	if h.ReadIdleTimeout == 0 || h.PingTimeout == 0 {
		t.Error("no read-idle ping: a tunnel to a dead controller would be held forever")
	}
	if h.MaxUploadBufferPerStream > 1<<20 {
		t.Errorf("per-stream window %d: a stalled pipe holds too much", h.MaxUploadBufferPerStream)
	}
}

// TestReadyAfterFirstTunnel: once a tunnel has been up, losing tunnels (a
// controller rollout) does not make the connector unready.
func TestReadyAfterFirstTunnel(t *testing.T) {
	tunnels := &Tunnels{}
	tunnels.downAt.Store(time.Now().UnixNano())
	if ok, _ := tunnels.Ready(t.Context()); ok {
		t.Error("ready before any tunnel")
	}
	tunnels.everUp.Store(true)
	if ok, _ := tunnels.Ready(t.Context()); !ok {
		t.Error("unready after tunnels flapped")
	}
}

// TestNotReadyAtStart: a connector is unready from the moment Start returns
// until a tunnel is up, even before any dial has run.
func TestNotReadyAtStart(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	unreachable := ln.Addr().String()
	_ = ln.Close()
	tunnels := &Tunnels{ConnectorID: connector, Count: 1, Addr: unreachable, TLS: &tls.Config{},
		Server: &Server{ConnectorID: connector, metrics: testMetrics(t)}}
	ctx, cancel := context.WithCancel(t.Context())
	done := tunnels.Start(ctx)
	ready, _ := tunnels.Ready(ctx)
	cancel()
	<-done
	if ready {
		t.Fatal("ready with no tunnel, right after Start")
	}
}
