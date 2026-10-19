package pipeserver

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"go.opentelemetry.io/otel"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/InteractionLabs/traversal-connector/connector-lib/rawpipe"
	"github.com/InteractionLabs/traversal-connector/internal/telemetry"
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

// captureOpens installs a collectable meter provider for the test; it must
// run before newMetrics. The returned func is the raw_pipe_open_total count
// with outcome o.
func captureOpens(t *testing.T) (opens func(o string) int64) {
	t.Helper()
	reader := sdkmetric.NewManualReader()
	previous := otel.GetMeterProvider()
	otel.SetMeterProvider(sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader)))
	t.Cleanup(func() { otel.SetMeterProvider(previous) })
	return func(o string) int64 {
		t.Helper()
		var rm metricdata.ResourceMetrics
		if err := reader.Collect(context.Background(), &rm); err != nil {
			t.Fatal(err)
		}
		var n int64
		for _, scope := range rm.ScopeMetrics {
			for _, m := range scope.Metrics {
				sum, ok := m.Data.(metricdata.Sum[int64])
				if m.Name != telemetry.MetricRawPipeOpenTotal || !ok {
					continue
				}
				for _, p := range sum.DataPoints {
					if v, _ := p.Attributes.Value("outcome"); v.AsString() == o {
						n += p.Value
					}
				}
			}
		}
		return n
	}
}

// TestAcceptFailedCounted: a pipe admitted but whose stream cannot be
// accepted (here a ResponseRecorder, which cannot run full duplex) is counted
// as accept_failed, and frees its slot.
func TestAcceptFailedCounted(t *testing.T) {
	opens := captureOpens(t)
	h := newHarness(t, nil, nil, "127.0.0.1:1")
	s := &Server{ConnectorID: connector, Verifier: h.tunnels.Server.Verifier, MaxPipes: 1,
		metrics: testMetrics(t)}
	req := httptest.NewRequest(http.MethodConnect, "https://db.internal:443", http.NoBody)
	req.Host = "db.internal:443"
	req.Header.Set(rawpipe.HeaderCapability, h.token("db.internal", 443))
	s.serve(httptest.NewRecorder(), req)
	if got := opens("accept_failed"); got != 1 {
		t.Errorf("accept_failed opens = %d, want 1", got)
	}
	if got := opens("opened"); got != 0 {
		t.Errorf("opened opens = %d, want 0", got)
	}
	if !s.pipes.Add(s.MaxPipes) {
		t.Error("the failed pipe still holds its slot")
	}
	s.pipes.Done()
}
