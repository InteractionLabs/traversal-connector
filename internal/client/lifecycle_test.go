package client

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/InteractionLabs/traversal-connector/internal/config"
	"github.com/InteractionLabs/traversal-connector/internal/telemetry"
)

func TestClassifyTunnelExit_CapacityExhausted(t *testing.T) {
	err := connect.NewError(
		connect.CodeResourceExhausted,
		errors.New("tunnel capacity exceeded: 10/10"),
	)

	if got := classifyTunnelExit(err); got != tunnelExitCapacityExhausted {
		t.Errorf("classifyTunnelExit() = %q, want %q", got, tunnelExitCapacityExhausted)
	}
}

func TestClassifyTunnelExit_WrappedCapacityExhausted(t *testing.T) {
	inner := connect.NewError(
		connect.CodeResourceExhausted,
		errors.New("tunnel capacity exceeded"),
	)
	wrapped := fmt.Errorf("failed to establish tunnel connection: %w", inner)

	if got := classifyTunnelExit(wrapped); got != tunnelExitCapacityExhausted {
		t.Errorf("classifyTunnelExit() = %q, want %q", got, tunnelExitCapacityExhausted)
	}
}

func TestClassifyTunnelExit_MessageSizeResourceExhausted(t *testing.T) {
	err := connect.NewError(
		connect.CodeResourceExhausted,
		errors.New("message size exceeds configured read maximum"),
	)

	if got := classifyTunnelExit(err); got != tunnelExitResourceExhausted {
		t.Errorf("classifyTunnelExit() = %q, want %q", got, tunnelExitResourceExhausted)
	}
}

func TestClassifyTunnelExit_OtherConnectCode(t *testing.T) {
	codes := []connect.Code{
		connect.CodeInternal,
		connect.CodeUnavailable,
		connect.CodePermissionDenied,
		connect.CodeUnknown,
	}

	for _, code := range codes {
		err := connect.NewError(code, errors.New("some error"))
		if got := classifyTunnelExit(err); got != tunnelExitConnectionError {
			t.Errorf("classifyTunnelExit(%v) = %q, want %q",
				code, got, tunnelExitConnectionError)
		}
	}
}

func TestClassifyTunnelExit_NonConnectError(t *testing.T) {
	err := errors.New("plain network error")
	if got := classifyTunnelExit(err); got != tunnelExitConnectionError {
		t.Errorf("classifyTunnelExit() = %q, want %q", got, tunnelExitConnectionError)
	}
}

func TestClassifyTunnelExit_CleanClose(t *testing.T) {
	if got := classifyTunnelExit(nil); got != tunnelExitCleanClose {
		t.Errorf("classifyTunnelExit(nil) = %q, want %q", got, tunnelExitCleanClose)
	}
}

func TestRun_ReconnectsOnDrop(t *testing.T) {
	metrics, err := initConnectionMetrics()
	if err != nil {
		t.Fatalf("initConnectionMetrics: %v", err)
	}

	cm := &ConnectionManager{
		config: &config.Config{
			MaxTunnelsAllowed: 1,
			// Long interval so the slot's own retry — not a capacity wait —
			// is what drives the reconnect.
			ReconnectInterval: time.Hour,
			MaxBackoffDelay:   30 * time.Second,
		},
		connections: make([]*StreamConnection, 0),
		metrics:     metrics,
	}

	reconnected := make(chan struct{})
	var callCount atomic.Int32

	cm.tunnelFunc = func(ctx context.Context) error {
		if callCount.Add(1) == 1 {
			// First call: simulate a dropped connection.
			return errors.New("connection dropped")
		}
		// Second call: reconnect succeeded — signal and hold until shutdown.
		close(reconnected)
		<-ctx.Done()
		return nil
	}

	// Timeout must exceed the initial backoff (1s) but need not be much longer.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	go func() { _ = cm.Run(ctx) }()

	select {
	case <-reconnected:
		// Reconnect happened after backoff delay.
	case <-ctx.Done():
		t.Fatal("timed out waiting for reconnect after tunnel drop")
	}
}

func TestRun_BacksOffAfterShortCleanCloseThenReconnects(t *testing.T) {
	metrics, err := initConnectionMetrics()
	if err != nil {
		t.Fatalf("initConnectionMetrics: %v", err)
	}

	cm := &ConnectionManager{
		config: &config.Config{
			MaxTunnelsAllowed: 1,
			ReconnectInterval: time.Hour,
			MaxBackoffDelay:   50 * time.Millisecond,
		},
		connections: make([]*StreamConnection, 0),
		metrics:     metrics,
	}

	firstClose := make(chan struct{})
	reconnected := make(chan struct{})
	var callCount atomic.Int32
	cm.tunnelFunc = func(ctx context.Context) error {
		if callCount.Add(1) == 1 {
			close(firstClose)
			return nil
		}
		close(reconnected)
		<-ctx.Done()
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go func() { _ = cm.Run(ctx) }()

	select {
	case <-firstClose:
	case <-ctx.Done():
		t.Fatal("timed out waiting for initial clean close")
	}

	select {
	case <-reconnected:
		t.Fatal("reconnected immediately after a short-lived clean close")
	case <-time.After(20 * time.Millisecond):
	}

	select {
	case <-reconnected:
	case <-ctx.Done():
		t.Fatal("timed out waiting for reconnect after clean control plane close")
	}
}

func TestRecordReconnect_IncludesReasonAndConnectCode(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	previous := otel.GetMeterProvider()
	otel.SetMeterProvider(provider)
	t.Cleanup(func() {
		otel.SetMeterProvider(previous)
		_ = provider.Shutdown(context.Background())
	})

	metrics, err := initConnectionMetrics()
	if err != nil {
		t.Fatalf("initConnectionMetrics: %v", err)
	}
	metrics.recordReconnect(
		context.Background(),
		tunnelExitResourceExhausted,
		connect.NewError(
			connect.CodeResourceExhausted,
			errors.New("message size exceeds configured read maximum"),
		),
	)

	var collected metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &collected); err != nil {
		t.Fatalf("collect metrics: %v", err)
	}

	for _, scope := range collected.ScopeMetrics {
		for _, recorded := range scope.Metrics {
			if recorded.Name != telemetry.MetricReconnectsTotal {
				continue
			}
			sum, ok := recorded.Data.(metricdata.Sum[int64])
			if !ok {
				t.Fatalf("metric data = %T, want Sum[int64]", recorded.Data)
			}
			for _, point := range sum.DataPoints {
				reason, hasReason := point.Attributes.Value(attribute.Key(attrReconnectReason))
				code, hasCode := point.Attributes.Value(attribute.Key(attrConnectCode))
				if hasReason && reason.AsString() == string(tunnelExitResourceExhausted) &&
					hasCode && code.AsString() == connect.CodeResourceExhausted.String() &&
					point.Value == 1 {
					return
				}
			}
		}
	}
	t.Fatal("reconnect metric missing expected reason and Connect code")
}

func TestRun_DoesNotExceedDesiredWorkersWhileConnecting(t *testing.T) {
	metrics, err := initConnectionMetrics()
	if err != nil {
		t.Fatalf("initConnectionMetrics: %v", err)
	}

	const desired = 3
	cm := &ConnectionManager{
		config: &config.Config{
			MaxTunnelsAllowed: desired,
			// Short enough that a reconciler-style top-up would fire many times
			// during the sleep below if one still existed.
			ReconnectInterval: 5 * time.Millisecond,
		},
		connections: make([]*StreamConnection, 0),
		metrics:     metrics,
	}

	// Every slot blocks in "connecting" without ever registering a connection,
	// so nothing observable reports the slot as filled.
	var calls atomic.Int32
	cm.tunnelFunc = func(ctx context.Context) error {
		calls.Add(1)
		<-ctx.Done()
		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = cm.Run(ctx)
	}()

	time.Sleep(50 * time.Millisecond)
	if got := calls.Load(); got != desired {
		t.Fatalf("tunnel workers started = %d, want %d", got, desired)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("connection manager did not stop")
	}
}

func TestRun_RetriesOnReconnectIntervalAfterCapacityError(t *testing.T) {
	metrics, err := initConnectionMetrics()
	if err != nil {
		t.Fatalf("initConnectionMetrics: %v", err)
	}

	cm := &ConnectionManager{
		config: &config.Config{
			MaxTunnelsAllowed: 1,
			ReconnectInterval: 10 * time.Millisecond,
		},
		connections: make([]*StreamConnection, 0),
		metrics:     metrics,
	}

	// A capacity rejection must not retire the slot, and must not advance the
	// backoff — the retry is paced by ReconnectInterval, well under the 1s
	// initial backoff the timeout below would otherwise not accommodate.
	retried := make(chan struct{})
	var calls atomic.Int32
	cm.tunnelFunc = func(ctx context.Context) error {
		if calls.Add(1) == 1 {
			return connect.NewError(
				connect.CodeResourceExhausted,
				errors.New("tunnel capacity exceeded: 10/10"),
			)
		}
		close(retried)
		<-ctx.Done()
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	go func() { _ = cm.Run(ctx) }()

	select {
	case <-retried:
	case <-ctx.Done():
		t.Fatal("timed out waiting for retry after capacity error")
	}
}

func TestTunnelBackoff_IncreasesOnRepeatedFailures(t *testing.T) {
	const maxDelay = 30 * time.Second
	backoff := tunnelBackoff{max: maxDelay}

	// Each call advances the base by 2×.
	// Returned values include jitter so we check ranges:
	//   call N returns: base_N + rand[0, base_N/2) — capped at maxDelay.
	d1 := backoff.next() // base=1s → delay in [1s, 1.5s)
	d2 := backoff.next() // base=2s → delay in [2s, 3s)
	d3 := backoff.next() // base=4s → delay in [4s, 6s)

	if d1 < backoffInitial || d1 >= backoffInitial*3/2 {
		t.Errorf("d1 out of range [%v, %v): %v", backoffInitial, backoffInitial*3/2, d1)
	}
	if d2 < backoffInitial*2 || d2 >= backoffInitial*3 {
		t.Errorf("d2 out of range [%v, %v): %v", backoffInitial*2, backoffInitial*3, d2)
	}
	if d3 < backoffInitial*4 || d3 >= backoffInitial*6 {
		t.Errorf("d3 out of range [%v, %v): %v", backoffInitial*4, backoffInitial*6, d3)
	}

	// Drive the base to the cap; all delays must be ≤ maxDelay.
	for range 10 {
		d := backoff.next()
		if d > maxDelay {
			t.Errorf("delay %v exceeds maxDelay %v", d, maxDelay)
		}
	}

	// Reset and verify it starts in the initial range again.
	backoff.reset()
	dAfterReset := backoff.next()
	if dAfterReset < backoffInitial || dAfterReset >= backoffInitial*3/2 {
		t.Errorf(
			"after reset: delay %v not in initial range [%v, %v)",
			dAfterReset,
			backoffInitial,
			backoffInitial*3/2,
		)
	}
}

func TestTunnelBackoff_RespectsConfiguredMax(t *testing.T) {
	const maxDelay = 1500 * time.Millisecond
	backoff := tunnelBackoff{max: maxDelay}

	for range 10 {
		if delay := backoff.next(); delay > maxDelay {
			t.Fatalf("delay %v exceeds configured maximum %v", delay, maxDelay)
		}
	}
}

func TestTunnelBackoff_MaxBelowInitialFallsBackSafely(t *testing.T) {
	for _, maxDelay := range []time.Duration{0, -time.Second, time.Nanosecond} {
		backoff := tunnelBackoff{max: maxDelay}
		for range 3 {
			if delay := backoff.next(); delay < backoffInitial {
				t.Fatalf("max %v produced unsafe delay %v", maxDelay, delay)
			}
		}
	}
}

func TestTunnelBackoff_IsIndependentPerSlot(t *testing.T) {
	const maxDelay = 30 * time.Second
	first := tunnelBackoff{max: maxDelay}
	second := tunnelBackoff{max: maxDelay}

	for range 5 {
		first.next()
	}

	delay := second.next()
	if delay < backoffInitial || delay >= backoffInitial*3/2 {
		t.Fatalf(
			"second slot's first delay %v not in initial range [%v, %v)",
			delay,
			backoffInitial,
			backoffInitial*3/2,
		)
	}
}

func TestActiveCount(t *testing.T) {
	cm := &ConnectionManager{
		connections: make([]*StreamConnection, 0),
	}

	if cm.ActiveCount() != 0 {
		t.Errorf("expected 0, got %d", cm.ActiveCount())
	}

	cm.connections = append(cm.connections, &StreamConnection{})
	cm.connections = append(cm.connections, &StreamConnection{})

	if cm.ActiveCount() != 2 {
		t.Errorf("expected 2, got %d", cm.ActiveCount())
	}
}
