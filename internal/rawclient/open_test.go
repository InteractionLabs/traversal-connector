package rawclient

import (
	"context"
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
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"log/slog"

	"github.com/InteractionLabs/traversal-connector/connector-lib/capability"
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
	pipe, peer := openPipe(t, recvMux(t, ctrl), token)
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
	pipe, _ := openPipe(t, recvMux(t, ctrl), sign(t, "jti-reset"))
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
	mux := recvMux(t, ctrl)
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

func TestCapabilityExhaustedDoesNotDial(t *testing.T) {
	ln := listen(t)
	var dials atomic.Int32
	policy := countingPolicy(t, ln, &dials)
	ctrl, m, _ := running(t, policy, nil)
	t.Cleanup(m.Shutdown)
	mux := recvMux(t, ctrl)
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
	pipe, peer := openPipe(t, recvMux(t, ctrl), token)
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
	mux := recvMux(t, ctrl)
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
	if active := gauge(t, rm, telemetry.MetricRawTunnelsActive); active != 1 {
		t.Fatalf("active tunnels = %d, want 1", active)
	}
}

func refuseOpen(t *testing.T, token string, policy *dialpolicy.Policy) pb.RawOpenFailureReason {
	t.Helper()
	ctrl, m, _ := running(t, policy, nil)
	t.Cleanup(m.Shutdown)
	pipe, err := recvMux(t, ctrl).Open(
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

func gauge(t *testing.T, rm metricdata.ResourceMetrics, name string) int64 {
	t.Helper()
	points := sumPoints(t, rm, name)
	if len(points) != 1 {
		t.Fatalf("%s points = %d", name, len(points))
	}
	return points[0].Value
}
