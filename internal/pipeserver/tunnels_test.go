package pipeserver

import (
	"context"
	"net/http"
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
	next := func(within time.Duration) *http.ClientConn {
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
