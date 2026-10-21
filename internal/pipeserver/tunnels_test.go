package pipeserver

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/InteractionLabs/traversal-connector/connector-lib/rawpipe"
)

// TestRedial: a tunnel the edge controller drops is redialed, and a drain
// request gets a replacement at once while the old tunnel stays open.
func TestRedial(t *testing.T) {
	tunnels := &Tunnels{ConnectorID: connector, Count: 1,
		Server: &Server{ConnectorID: connector, metrics: testMetrics(t)}}
	accept := controller(t, tunnels)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	tunnels.Start(ctx)
	next := func(within time.Duration) *http.ClientConn { return nextTunnel(t, accept, within) }
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
	if second.Available() == 0 {
		t.Error("the replaced tunnel closed before the edge controller closed it")
	}
}

// TestRedialAfterReplacements: replacements the edge controller asks for do
// not grow the redial backoff, so a tunnel that then fails is redialed after
// the initial 0.5-1 s, not the 4-8 s three earlier waits would have grown it to.
func TestRedialAfterReplacements(t *testing.T) {
	tunnels := &Tunnels{ConnectorID: connector, Count: 1,
		Server: &Server{ConnectorID: connector, metrics: testMetrics(t)}}
	accept := controller(t, tunnels)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	tunnels.Start(ctx)
	cc := nextTunnel(t, accept, 5*time.Second)
	for range 3 {
		req, _ := http.NewRequest(rawpipe.DrainMethod, "http://tunnel/", http.NoBody)
		resp, err := cc.RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		cc = nextTunnel(t, accept, 500*time.Millisecond)
	}
	_ = cc.Close() // a genuine failure
	nextTunnel(t, accept, 1500*time.Millisecond)
}

// nextTunnel is the next tunnel accept takes, failing t if none comes within.
func nextTunnel(
	t *testing.T,
	accept func() *http.ClientConn,
	within time.Duration,
) *http.ClientConn {
	t.Helper()
	got := make(chan *http.ClientConn, 1)
	go func() { got <- accept() }()
	select {
	case cc := <-got:
		return cc
	case <-time.After(within):
		t.Fatalf("no tunnel within %v", within)
		return nil
	}
}

// TestReady: a connector is unready until its first tunnel, and losing
// tunnels after that (a controller rollout) does not make it unready.
func TestReady(t *testing.T) {
	tunnels := &Tunnels{}
	if tunnels.Ready(t.Context()) == nil {
		t.Error("ready before any tunnel")
	}
	tunnels.everUp.Store(true)
	if err := tunnels.Ready(t.Context()); err != nil {
		t.Error("unready after tunnels flapped")
	}
}

// TestTunnelThroughProxy: with EGRESS_PROXY_URL, a tunnel reaches the
// controller host through the proxy's CONNECT, with the proxy's credentials,
// and TLS (the tunnel ALPN included) runs end to end inside it.
func TestTunnelThroughProxy(t *testing.T) {
	tunnels := &Tunnels{ConnectorID: connector, Count: 1,
		Server: &Server{ConnectorID: connector, metrics: testMetrics(t)}}
	accept := controller(t, tunnels)
	target := tunnels.Addr
	tunnels.Addr = "edge.example.com:443" // only the proxy can reach it
	var mu sync.Mutex
	var connects []string
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		connects = append(connects, r.Method+" "+r.Host+" "+r.Header.Get("Proxy-Authorization"))
		mu.Unlock()
		up, err := net.Dial("tcp", target)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusOK)
		c, buf, err := http.NewResponseController(w).Hijack()
		if err != nil {
			_ = up.Close()
			return
		}
		_ = buf.Flush()
		go func() { _, _ = io.Copy(up, c); _ = up.Close() }()
		_, _ = io.Copy(c, up)
		_ = c.Close()
	}))
	defer proxy.Close()
	tunnels.Proxy, _ = url.Parse("http://u:pw@" + proxy.Listener.Addr().String())
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	tunnels.Start(ctx)
	nextTunnel(t, accept, 5*time.Second)
	mu.Lock()
	defer mu.Unlock()
	if want := "CONNECT edge.example.com:443 Basic " + base64Of("u:pw"); len(connects) == 0 ||
		connects[0] != want {
		t.Fatalf("proxy saw %q, want %q", connects, want)
	}
}
