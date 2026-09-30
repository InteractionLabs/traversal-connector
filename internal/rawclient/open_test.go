package rawclient

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"log/slog"

	"github.com/InteractionLabs/traversal-connector/connector-lib/capability"
	"github.com/InteractionLabs/traversal-connector/connector-lib/capability/capabilitytest"
	"github.com/InteractionLabs/traversal-connector/connector-lib/dialpolicy"
	pb "github.com/InteractionLabs/traversal-connector/connector-lib/gen/connector/v1"
	"github.com/InteractionLabs/traversal-connector/connector-lib/gen/connector/v1/connectorconnect"
	"github.com/InteractionLabs/traversal-connector/connector-lib/rawtunnel"
	"github.com/InteractionLabs/traversal-connector/internal/client"
	"github.com/InteractionLabs/traversal-connector/internal/config"
	"github.com/InteractionLabs/traversal-connector/internal/redact"
	"github.com/InteractionLabs/traversal-connector/internal/telemetry"
)

func TestBadCapabilityDoesNotDial(t *testing.T) {
	reason := refuseOpen(t, "not-a-token", directPolicy(t, nil, neverDial(t)))
	if reason != pb.RawOpenFailureReason_RAW_OPEN_FAILURE_REASON_INVALID_CAPABILITY {
		t.Fatalf("reason %s", reason)
	}
}

func TestForbiddenAddressDoesNotDial(t *testing.T) {
	policy := directPolicy(t,
		func(context.Context, string, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
		},
		neverDial(t),
	)
	reason := refuseOpen(t, sign(t, "jti-forbidden"), policy)
	if reason != pb.RawOpenFailureReason_RAW_OPEN_FAILURE_REASON_FORBIDDEN_ADDRESS {
		t.Fatalf("reason %s", reason)
	}
}

func TestInspectionRequiredDoesNotDial(t *testing.T) {
	policy, err := dialpolicy.New(dialpolicy.Config{
		RequiresInspection: func(string, uint16) bool { return true },
		DialContext:        neverDial(t),
		LookupNetIP: func(context.Context, string, string) ([]netip.Addr, error) {
			t.Error("lookup ran")
			return nil, errors.New("lookup")
		},
		Proxy: func(string, uint16) (*url.URL, error) { return nil, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	reason := refuseOpen(t, sign(t, "jti-inspect"), policy)
	if reason != pb.RawOpenFailureReason_RAW_OPEN_FAILURE_REASON_INSPECTION_REQUIRED {
		t.Fatalf("reason %s", reason)
	}
}

func TestRedactionRulesRefuseBeforeDial(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.toml")
	rules := "version = \"v1\"\n[[rules]]\nname = \"email\"\ntype = \"regex\"\n" +
		"pattern = '[A-Za-z0-9._%+\\-]+@[A-Za-z0-9.\\-]+\\.[A-Za-z]{2,}'\n" +
		"replacement = \"[REDACTED_EMAIL]\"\n"
	if err := os.WriteFile(path, []byte(rules), 0o600); err != nil {
		t.Fatal(err)
	}
	redactor := redact.NewRedactor()
	if err := redact.NewFileLoader(path, redactor, time.Second).LoadInitial(); err != nil {
		t.Fatal(err)
	}
	policy, err := newPolicy(baseConfig("http://127.0.0.1:9"), redactor)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = policy.Dial(t.Context(), testHost, testPort)
	var refusal *dialpolicy.Refusal
	if !errors.As(err, &refusal) ||
		refusal.OpenFailureReason() !=
			pb.RawOpenFailureReason_RAW_OPEN_FAILURE_REASON_INSPECTION_REQUIRED {
		t.Fatalf("dial = %v, want inspection_required", err)
	}
}

func TestPipeRelaysBytesAndHalfCloses(t *testing.T) {
	ctrl, m, ln := running(t, nil, nil)
	t.Cleanup(m.Shutdown)
	dstCh := acceptOne(ln)
	token := sign(t, "jti-bytes")
	pipe, peer := openPipe(t, recvMux(t, ctrl.ready), token)
	dst := <-dstCh
	t.Cleanup(func() { _ = dst.Close() })

	if _, err := peer.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	_ = dst.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(dst, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("to target: %v %q", err, buf)
	}
	if _, err := dst.Write([]byte("pong")); err != nil {
		t.Fatal(err)
	}
	_ = peer.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(peer, buf); err != nil || string(buf) != "pong" {
		t.Fatalf("from target: %v %q", err, buf)
	}
	if err := peer.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	_ = dst.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := dst.Read(buf); !errors.Is(err, io.EOF) {
		t.Fatalf("half-close: %v", err)
	}
	if _, err := dst.Write([]byte("more")); err != nil {
		t.Fatal(err)
	}
	_ = peer.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(peer, buf); err != nil || string(buf) != "more" {
		t.Fatalf("reverse after half-close: %v %q", err, buf)
	}
	_ = dst.Close()
	_ = peer.Close()
	select {
	case <-pipe.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("pipe did not finish")
	}
}

func TestResetClosesTheTarget(t *testing.T) {
	ctrl, m, ln := running(t, nil, nil)
	t.Cleanup(m.Shutdown)
	dstCh := acceptOne(ln)
	pipe, _ := openPipe(t, recvMux(t, ctrl.ready), sign(t, "jti-reset"))
	dst := <-dstCh
	pipe.Reset(pb.RawCloseReason_RAW_CLOSE_REASON_CANCELLED)
	_ = dst.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1)
	if _, err := dst.Read(buf); err == nil {
		t.Fatal("target stayed open after reset")
	}
}

func TestPodCapacityRefusesBeforeDial(t *testing.T) {
	ln := listen(t)
	var dials atomic.Int32
	policy := countingPolicy(t, ln, &dials)
	ctrl, m, _ := running(t, policy, func(cfg *config.Config) {
		cfg.RawTunnel.MaxPipesPerPod = 1
	})
	t.Cleanup(m.Shutdown)
	mux := recvMux(t, ctrl.ready)
	dstCh := acceptOne(ln)
	if _, err := openHeld(t, mux, sign(t, "jti-cap-1")); err != nil {
		t.Fatal(err)
	}
	<-dstCh
	reason := openRefusal(t, mux, sign(t, "jti-cap-2"))
	if reason != pb.RawOpenFailureReason_RAW_OPEN_FAILURE_REASON_CAPACITY {
		t.Fatalf("reason %s", reason)
	}
	if got := dials.Load(); got != 1 {
		t.Fatalf("dials = %d, want 1", got)
	}
}

// TestCapacityRefusalsDoNotConsumeJTI fills the pod, receives capacity
// refusals on the same jti, drains the held pipe, and checks the open budget
// is unchanged: capacity checks run before Verify consumes a use.
func TestCapacityRefusalsDoNotConsumeJTI(t *testing.T) {
	ln := listen(t)
	var dials atomic.Int32
	policy := countingPolicy(t, ln, &dials)
	ctrl, m, _ := running(t, policy, func(cfg *config.Config) {
		cfg.RawTunnel.MaxPipesPerPod = 1
	})
	t.Cleanup(m.Shutdown)
	mux := recvMux(t, ctrl.ready)
	token := sign(t, "jti-budget")
	held, err := openHeld(t, mux, token)
	if err != nil {
		t.Fatal(err)
	}
	for range 8 {
		if reason := openRefusal(t, mux, token); reason !=
			pb.RawOpenFailureReason_RAW_OPEN_FAILURE_REASON_CAPACITY {
			t.Fatalf("reason %s", reason)
		}
	}
	held.Reset(pb.RawCloseReason_RAW_CLOSE_REASON_CANCELLED)
	select {
	case <-held.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("held pipe did not finish")
	}
	waitSlots(t, m, 0)
	// One use was spent on the held pipe; capacity refusals must not have
	// spent any. The remaining budget is MaxOpensPerToken - 1.
	for i := range capabilityOpens() - 1 {
		pipe, peer := openPipe(t, mux, token)
		_ = peer.Close()
		pipe.Reset(pb.RawCloseReason_RAW_CLOSE_REASON_CANCELLED)
		select {
		case <-pipe.Done():
		case <-time.After(2 * time.Second):
			t.Fatalf("pipe %d did not finish", i)
		}
		waitSlots(t, m, 0)
	}
	if reason := openRefusal(t, mux, token); reason !=
		pb.RawOpenFailureReason_RAW_OPEN_FAILURE_REASON_CAPABILITY_EXHAUSTED {
		t.Fatalf("reason %s after exhausting remaining budget", reason)
	}
}

func waitSlots(t *testing.T, m *Manager, want int) {
	t.Helper()
	waitFor(t, 2*time.Second, func() bool {
		slots := m.opener.pipes
		slots.mu.Lock()
		defer slots.mu.Unlock()
		return slots.n == want
	})
}

func TestOpenDialTimeout(t *testing.T) {
	policy := directPolicy(t,
		func(context.Context, string, string) ([]netip.Addr, error) {
			return []netip.Addr{checkedAddr()}, nil
		},
		func(ctx context.Context, _, _ string) (net.Conn, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		},
	)
	ctrl, m, _ := running(t, policy, func(cfg *config.Config) {
		cfg.RawTunnel.OpenTimeout = 50 * time.Millisecond
	})
	t.Cleanup(m.Shutdown)
	started := time.Now()
	reason := openRefusal(t, recvMux(t, ctrl.ready), sign(t, "jti-dial-timeout"))
	if reason != pb.RawOpenFailureReason_RAW_OPEN_FAILURE_REASON_OPEN_TIMEOUT {
		t.Fatalf("reason %s", reason)
	}
	if d := time.Since(started); d > 2*time.Second {
		t.Fatalf("dial timeout took %s", d)
	}
}

func TestCapabilityExhaustedDoesNotDial(t *testing.T) {
	ln := listen(t)
	var dials atomic.Int32
	policy := countingPolicy(t, ln, &dials)
	ctrl, m, _ := running(t, policy, nil)
	t.Cleanup(m.Shutdown)
	mux := recvMux(t, ctrl.ready)
	for range capabilityOpens() {
		pipe, peer := openPipe(t, mux, sign(t, "same-jti"))
		_ = peer.Close()
		pipe.Reset(pb.RawCloseReason_RAW_CLOSE_REASON_CANCELLED)
		select {
		case <-pipe.Done():
		case <-time.After(2 * time.Second):
			t.Fatal("pipe did not finish")
		}
	}
	reason := openRefusal(t, mux, sign(t, "same-jti"))
	if reason != pb.RawOpenFailureReason_RAW_OPEN_FAILURE_REASON_CAPABILITY_EXHAUSTED {
		t.Fatalf("reason %s", reason)
	}
	if got := dials.Load(); int(got) != capabilityOpens() {
		t.Fatalf("dials = %d, want %d", got, capabilityOpens())
	}
}

func TestRotationDeadlineClosesALivePipe(t *testing.T) {
	ctrl, m, ln := running(t, nil, func(cfg *config.Config) {
		cfg.RawTunnel.ShutdownGrace = time.Hour
		cfg.RawTunnel.RotationDeadline = 40 * time.Millisecond
	})
	t.Cleanup(m.Shutdown)
	dstCh := acceptOne(ln)
	mux := recvMux(t, ctrl.ready)
	pipe, _ := openPipe(t, mux, sign(t, "jti-rotate"))
	dst := <-dstCh
	t.Cleanup(func() { _ = dst.Close() })
	mux.Drain(pb.RawDrainReason_RAW_DRAIN_REASON_ROTATION)
	select {
	case <-pipe.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("rotation left the pipe open")
	}
	if got := pipe.Result().Reason; got !=
		pb.RawCloseReason_RAW_CLOSE_REASON_ROTATION_DEADLINE {
		t.Fatalf("reason %s", got)
	}
}

func TestLivePipeOutlivesShutdownGrace(t *testing.T) {
	ctrl, m, ln := running(t, nil, func(cfg *config.Config) {
		cfg.RawTunnel.ShutdownGrace = 40 * time.Millisecond
		cfg.RawTunnel.RotationDeadline = time.Hour
	})
	t.Cleanup(m.Shutdown)
	dstCh := acceptOne(ln)
	mux := recvMux(t, ctrl.ready)
	pipe, _ := openPipe(t, mux, sign(t, "jti-grace"))
	dst := <-dstCh
	t.Cleanup(func() { _ = dst.Close() })
	mux.Drain(pb.RawDrainReason_RAW_DRAIN_REASON_ROTATION)
	select {
	case <-pipe.Done():
		t.Fatal("rotation closed the pipe on the shutdown grace")
	case <-time.After(200 * time.Millisecond):
	}
}

func TestShutdownClosesPipesWithConnectorTerminating(t *testing.T) {
	ctrl, m, ln := running(t, nil, func(cfg *config.Config) {
		cfg.RawTunnel.ShutdownGrace = 40 * time.Millisecond
	})
	var once sync.Once
	t.Cleanup(func() { once.Do(m.Shutdown) })
	dstCh := acceptOne(ln)
	pipe, _ := openPipe(t, recvMux(t, ctrl.ready), sign(t, "jti-shutdown"))
	dst := <-dstCh
	t.Cleanup(func() { _ = dst.Close() })
	once.Do(m.Shutdown)
	select {
	case <-pipe.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("shutdown left the pipe open")
	}
	if got := pipe.Result().Reason; got !=
		pb.RawCloseReason_RAW_CLOSE_REASON_CONNECTOR_TERMINATING {
		t.Fatalf("reason %s", got)
	}
}

func TestAuditOmitsTheCapability(t *testing.T) {
	logger, buf := jsonLogger()
	ctrl := newMuxCtrl()
	srv := serveH2C(t, ctrl)
	t.Cleanup(srv.close)
	ln := listen(t)
	token := sign(t, "jti-audit")
	cfg := baseConfig(srv.url)
	policy := directPolicy(t,
		func(context.Context, string, string) ([]netip.Addr, error) {
			return []netip.Addr{checkedAddr()}, nil
		},
		func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, ln.Addr().String())
		},
	)
	m := startLogged(t, cfg, policy, logger)
	var once sync.Once
	stop := func() { once.Do(m.Shutdown) }
	t.Cleanup(stop)
	dstCh := acceptOne(ln)
	pipe, peer := openPipe(t, recvMux(t, ctrl.ready), token)
	dst := <-dstCh
	_ = dst.Close()
	_ = peer.Close()
	select {
	case <-pipe.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("pipe did not finish")
	}
	// Shutdown waits until the close record is written.
	stop()
	text := buf.String()
	if strings.Contains(text, token) {
		t.Fatal("audit log contains the capability")
	}
	for _, want := range []string{
		"connector-1", "jti-audit", "session-1", "org-1", testHost,
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("audit log missing %s: %s", want, text)
		}
	}
}

func TestMetricsUseBoundedLabels(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	prev := otel.GetMeterProvider()
	otel.SetMeterProvider(provider)
	t.Cleanup(func() { otel.SetMeterProvider(prev) })

	ctrl, m, _ := running(t, directPolicy(t, nil, neverDial(t)), nil)
	t.Cleanup(m.Shutdown)
	mux := recvMux(t, ctrl.ready)
	if reason := openRefusal(t, mux, "not-a-token"); reason !=
		pb.RawOpenFailureReason_RAW_OPEN_FAILURE_REASON_INVALID_CAPABILITY {
		t.Fatalf("reason %s", reason)
	}
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(t.Context(), &rm); err != nil {
		t.Fatal(err)
	}
	opens := sumPoints(t, rm, telemetry.MetricRawOpensTotal)
	if len(opens) == 0 {
		t.Fatal("no open metric")
	}
	var refused bool
	for _, point := range opens {
		for _, attr := range point.Attributes.ToSlice() {
			switch attr.Key {
			case "host", "jti", "pipe_id", "destination", "capability":
				t.Fatalf("unbounded label %s", attr.Key)
			}
			if attr.Key == "reason" &&
				attr.Value.String() == pb.RawOpenFailureReason_RAW_OPEN_FAILURE_REASON_INVALID_CAPABILITY.String() {
				refused = true
			}
		}
	}
	if !refused {
		t.Fatal("refused open was not counted")
	}
	if !hasPoint(sumPoints(t, rm, telemetry.MetricRawCapabilityRejectionsTotal),
		attribute.String("code", string(capability.CodeMalformed))) {
		t.Fatal("capability rejection was not counted by code")
	}
	if !hasPoint(sumPoints(t, rm, telemetry.MetricRawKeyLoadsTotal),
		attribute.String("slot", "current"), attribute.String("result", "loaded")) {
		t.Fatal("current key load was not counted")
	}
	if active := gauge(t, rm, telemetry.MetricRawTunnelsActive); active != 1 {
		t.Fatalf("active tunnels = %d, want 1", active)
	}
}

// TestKeyRotation walks a signing-key rotation through configuration alone:
// the next key is trusted alongside the current one, then the current key is
// retired and its capabilities stop opening pipes.
func TestKeyRotation(t *testing.T) {
	const nextKid = "k2"
	nextKey := capabilitytest.Key("raw-connector-test: next")
	signWith := func(key *ecdsa.PrivateKey, kid, jti string) string {
		token, err := capabilitytest.Sign(key, kid, testClaims(jti))
		if err != nil {
			t.Fatal(err)
		}
		return token
	}
	admit := func(mux *rawtunnel.Mux, token string) {
		_, peer := openPipe(t, mux, token)
		_ = peer.Close()
	}

	ctrl, m, _ := running(t, nil, func(cfg *config.Config) {
		cfg.RawTunnel.NextKeyID = nextKid
		cfg.RawTunnel.NextPublicKeyPEM = publicPEM(nextKey)
	})
	mux := recvMux(t, ctrl.ready)
	admit(mux, sign(t, "overlap-current"))
	admit(mux, signWith(nextKey, nextKid, "overlap-next"))
	m.Shutdown()

	ctrl, m, _ = running(t, nil, func(cfg *config.Config) {
		cfg.RawTunnel.CurrentKeyID = nextKid
		cfg.RawTunnel.CurrentPublicKeyPEM = publicPEM(nextKey)
	})
	t.Cleanup(m.Shutdown)
	mux = recvMux(t, ctrl.ready)
	if reason := openRefusal(t, mux, sign(t, "retired-current")); reason !=
		pb.RawOpenFailureReason_RAW_OPEN_FAILURE_REASON_UNKNOWN_KEY {
		t.Fatalf("retired key reason %s, want unknown_key", reason)
	}
	admit(mux, signWith(nextKey, nextKid, "retired-next"))
}

func refuseOpen(t *testing.T, token string, policy *dialpolicy.Policy) pb.RawOpenFailureReason {
	t.Helper()
	ctrl, m, _ := running(t, policy, nil)
	t.Cleanup(m.Shutdown)
	pipe, err := recvMux(t, ctrl.ready).Open(
		token, testHost, testPort, pb.RawPipeMode_RAW_PIPE_MODE_PASSTHROUGH,
	)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	err = pipe.WaitOpened(ctx)
	var openErr *rawtunnel.OpenError
	if !errors.As(err, &openErr) {
		t.Fatalf("WaitOpened = %v, want a refusal", err)
	}
	return openErr.Reason
}

func running(
	t *testing.T,
	policy *dialpolicy.Policy,
	tweak func(*config.Config),
) (*muxCtrl, *Manager, net.Listener) {
	t.Helper()
	ctrl := newMuxCtrl()
	srv := serveH2C(t, ctrl)
	t.Cleanup(srv.close)
	ln := listen(t)
	if policy == nil {
		policy = dialLocal(t, ln)
	}
	cfg := baseConfig(srv.url)
	if tweak != nil {
		tweak(cfg)
	}
	return ctrl, startManager(t, cfg, policy), ln
}

func listen(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	return ln
}

func dialLocal(t *testing.T, ln net.Listener) *dialpolicy.Policy {
	t.Helper()
	return directPolicy(t,
		func(context.Context, string, string) ([]netip.Addr, error) {
			return []netip.Addr{checkedAddr()}, nil
		},
		func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, ln.Addr().String())
		},
	)
}

func countingPolicy(t *testing.T, ln net.Listener, dials *atomic.Int32) *dialpolicy.Policy {
	t.Helper()
	return directPolicy(t,
		func(context.Context, string, string) ([]netip.Addr, error) {
			return []netip.Addr{checkedAddr()}, nil
		},
		func(ctx context.Context, network, _ string) (net.Conn, error) {
			dials.Add(1)
			var d net.Dialer
			return d.DialContext(ctx, network, ln.Addr().String())
		},
	)
}

func capabilityOpens() int { return capability.MaxOpensPerToken }

func openHeld(t *testing.T, mux *rawtunnel.Mux, token string) (*rawtunnel.Pipe, error) {
	t.Helper()
	pipe, peer := openPipe(t, mux, token)
	t.Cleanup(func() { _ = peer.Close() })
	return pipe, nil
}

func openRefusal(
	t *testing.T, mux *rawtunnel.Mux, token string,
) pb.RawOpenFailureReason {
	t.Helper()
	pipe, err := mux.Open(
		token, testHost, testPort, pb.RawPipeMode_RAW_PIPE_MODE_PASSTHROUGH,
	)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	err = pipe.WaitOpened(ctx)
	var openErr *rawtunnel.OpenError
	if !errors.As(err, &openErr) {
		t.Fatalf("WaitOpened = %v, want a refusal", err)
	}
	return openErr.Reason
}

func TestCancelledDialIsNotAuditedAsDialFailure(t *testing.T) {
	for _, tc := range []struct {
		name string
		end  func(*rawtunnel.Mux, *rawtunnel.Pipe, *Manager)
	}{
		{
			name: "reset",
			end: func(_ *rawtunnel.Mux, pipe *rawtunnel.Pipe, _ *Manager) {
				pipe.Reset(pb.RawCloseReason_RAW_CLOSE_REASON_CANCELLED)
			},
		},
		{
			name: "tunnel-lost",
			end: func(mux *rawtunnel.Mux, _ *rawtunnel.Pipe, _ *Manager) {
				mux.Close(pb.RawCloseReason_RAW_CLOSE_REASON_TUNNEL_LOST)
			},
		},
		{
			name: "shutdown",
			end: func(_ *rawtunnel.Mux, _ *rawtunnel.Pipe, m *Manager) {
				m.Shutdown()
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logger, buf := jsonLogger()
			ctrl := newMuxCtrl()
			srv := serveH2C(t, ctrl)
			t.Cleanup(srv.close)
			var dialOnce sync.Once
			started := make(chan struct{})
			policy := directPolicy(t,
				func(context.Context, string, string) ([]netip.Addr, error) {
					return []netip.Addr{checkedAddr()}, nil
				},
				func(ctx context.Context, _, _ string) (net.Conn, error) {
					dialOnce.Do(func() { close(started) })
					<-ctx.Done()
					return nil, ctx.Err()
				},
			)
			cfg := baseConfig(srv.url)
			cfg.RawTunnel.ShutdownGrace = 40 * time.Millisecond
			m := startLogged(t, cfg, policy, logger)
			var shutdownOnce sync.Once
			t.Cleanup(func() { shutdownOnce.Do(m.Shutdown) })
			mux := recvMux(t, ctrl.ready)
			pipe, err := mux.Open(
				sign(t, "jti-cancel-"+tc.name), testHost, testPort,
				pb.RawPipeMode_RAW_PIPE_MODE_PASSTHROUGH,
			)
			if err != nil {
				t.Fatal(err)
			}
			select {
			case <-started:
			case <-time.After(2 * time.Second):
				t.Fatal("dial did not start")
			}
			tc.end(mux, pipe, m)
			select {
			case <-pipe.Done():
			case <-time.After(3 * time.Second):
				t.Fatal("pipe did not finish")
			}
			text := buf.String()
			if strings.Contains(text, "DIAL_FAILED") ||
				strings.Contains(text, `"outcome":"refused"`) {
				t.Fatalf("cancelled dial was audited as a refusal: %s", text)
			}
		})
	}
}

func startLogged(
	t *testing.T, cfg *config.Config, policy *dialpolicy.Policy, logger *slog.Logger,
) *Manager {
	t.Helper()
	m, err := newManager(cfg, redact.NewRedactor(), func() (
		connectorconnect.ConnectorServiceClient, func(), error,
	) {
		return client.NewIsolatedClient(cfg)
	}, logger, policy)
	if err != nil {
		t.Fatal(err)
	}
	m.Start()
	return m
}

func sumPoints(
	t *testing.T, rm metricdata.ResourceMetrics, name string,
) []metricdata.DataPoint[int64] {
	t.Helper()
	for _, scope := range rm.ScopeMetrics {
		for _, metric := range scope.Metrics {
			if metric.Name != name {
				continue
			}
			sum, ok := metric.Data.(metricdata.Sum[int64])
			if !ok {
				t.Fatalf("%s data %T", name, metric.Data)
			}
			return sum.DataPoints
		}
	}
	return nil
}

func hasPoint(points []metricdata.DataPoint[int64], want ...attribute.KeyValue) bool {
	for _, point := range points {
		matched := true
		for _, kv := range want {
			if got, ok := point.Attributes.Value(kv.Key); !ok || got != kv.Value {
				matched = false
			}
		}
		if matched && point.Value > 0 {
			return true
		}
	}
	return false
}

func gauge(t *testing.T, rm metricdata.ResourceMetrics, name string) int64 {
	t.Helper()
	points := sumPoints(t, rm, name)
	if len(points) != 1 {
		t.Fatalf("%s points = %d", name, len(points))
	}
	return points[0].Value
}

func TestTCPPortDoesNotTruncate(t *testing.T) {
	if _, ok := tcpPort(&pb.RawOpen{Port: 70_000}); ok {
		t.Fatal("accepted a port that does not fit in 16 bits")
	}
	if _, ok := tcpPort(&pb.RawOpen{Port: 0}); ok {
		t.Fatal("accepted port 0")
	}
	got, ok := tcpPort(&pb.RawOpen{Port: 443})
	if !ok || got != 443 {
		t.Fatalf("port = %d, ok = %v", got, ok)
	}
}

func TestResetMetricsSentAndReceived(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	prev := otel.GetMeterProvider()
	otel.SetMeterProvider(provider)
	t.Cleanup(func() { otel.SetMeterProvider(prev) })

	ctrl, m, ln := running(t, nil, nil)
	t.Cleanup(m.Shutdown)
	mux := recvMux(t, ctrl.ready)

	dstCh := acceptOne(ln)
	received, _ := openPipe(t, mux, sign(t, "jti-reset-recv"))
	<-dstCh
	received.Reset(pb.RawCloseReason_RAW_CLOSE_REASON_CANCELLED)
	select {
	case <-received.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("received reset pipe did not finish")
	}

	dstCh = acceptOne(ln)
	sent, peer := openPipe(t, mux, sign(t, "jti-reset-sent"))
	dst := <-dstCh
	if tc, ok := dst.(*net.TCPConn); ok {
		_ = tc.SetLinger(0)
	}
	_ = dst.Close()
	_, _ = peer.Write([]byte("x"))
	select {
	case <-sent.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("sent reset pipe did not finish")
	}

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(t.Context(), &rm); err != nil {
		t.Fatal(err)
	}
	points := sumPoints(t, rm, telemetry.MetricRawResetsTotal)
	if len(points) == 0 {
		t.Fatal("no reset metric")
	}
	var sawSent, sawReceived bool
	for _, point := range points {
		var origin, reason string
		for _, attr := range point.Attributes.ToSlice() {
			switch attr.Key {
			case "host", "jti", "pipe_id", "destination", "capability":
				t.Fatalf("unbounded label %s", attr.Key)
			case "origin":
				origin = attr.Value.String()
			case "reason":
				reason = attr.Value.String()
			case "phase":
				if attr.Value.String() != "open" && attr.Value.String() != "opening" {
					t.Fatalf("phase %q", attr.Value.String())
				}
			}
		}
		if point.Value < 1 {
			continue
		}
		switch origin {
		case "received":
			sawReceived = true
			if reason != pb.RawCloseReason_RAW_CLOSE_REASON_CANCELLED.String() {
				t.Fatalf("received reason %s", reason)
			}
		case "sent":
			sawSent = true
		default:
			t.Fatalf("origin %q", origin)
		}
	}
	if !sawReceived {
		t.Fatal("missing received reset metric")
	}
	if !sawSent {
		t.Fatal("missing sent reset metric")
	}
}
