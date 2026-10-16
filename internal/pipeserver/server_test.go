package pipeserver

import (
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/InteractionLabs/traversal-connector/connector-lib/rawpipe"
)

// TestPipeRefusals: an open is refused before any TLS or dial for a bad
// capability, the probe name on another port, and while draining.
func TestPipeRefusals(t *testing.T) {
	h := newHarness(t, nil, nil, "127.0.0.1:1")
	refusal := func(authority, token string) rawpipe.Reason {
		t.Helper()
		_, err := rawpipe.Connect(t.Context(), h.cc, "tunnel", authority,
			http.Header{rawpipe.HeaderCapability: {token}}, 5*time.Second)
		r, ok := errors.AsType[*rawpipe.Refusal](err)
		if !ok {
			t.Fatalf("%s: %v, want a refusal", authority, err)
		}
		return r.Reason
	}
	if r := refusal("db.internal:443", "bogus"); r != rawpipe.InvalidCapability {
		t.Errorf("bad capability: %s", r)
	}
	if r := refusal(rawpipe.ProbeHost+":80", h.token(rawpipe.ProbeHost, 80)); r != rawpipe.WrongDestination {
		t.Errorf("probe host on port 80: %s", r)
	}
	h.tunnels.Server.pipes.Drain()
	if r := refusal("db.internal:443", h.token("db.internal", 443)); r != rawpipe.Draining {
		t.Errorf("draining: %s", r)
	}
}

// TestTunnelServerLimits: the tunnel advertises the connector's pipe limit
// per tunnel (so opens past it are capacity refusals, not open timeouts),
// and pings a quiet tunnel so a dead far end is found.
func TestTunnelServerLimits(t *testing.T) {
	s := &Server{MaxPipes: 4000, Tunnels: 2}
	h := s.h2()
	if h.MaxConcurrentStreams < 2000 || h.MaxConcurrentStreams > 2100 {
		t.Errorf("MaxConcurrentStreams = %d for 4000 pipes over 2 tunnels", h.MaxConcurrentStreams)
	}
	if h.SendPingTimeout == 0 || h.PingTimeout == 0 {
		t.Error("no read-idle ping: a tunnel to a dead controller would be held forever")
	}
	if h.MaxReceiveBufferPerStream > 1<<20 {
		t.Errorf("per-stream window %d: a stalled pipe holds too much", h.MaxReceiveBufferPerStream)
	}
}
