package client

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/InteractionLabs/traversal-connector/internal/config"
)

func TestIsCapacityError_ResourceExhausted(t *testing.T) {
	err := connect.NewError(
		connect.CodeResourceExhausted,
		errors.New("tunnel capacity exceeded: 10/10"),
	)

	if !isCapacityError(err) {
		t.Error("expected isCapacityError to return true for ResourceExhausted")
	}
}

func TestIsCapacityError_WrappedResourceExhausted(t *testing.T) {
	inner := connect.NewError(
		connect.CodeResourceExhausted,
		errors.New("tunnel capacity exceeded"),
	)
	wrapped := fmt.Errorf("failed to establish tunnel connection: %w", inner)

	if !isCapacityError(wrapped) {
		t.Error("expected isCapacityError to return true for wrapped ResourceExhausted")
	}
}

func TestIsCapacityError_OtherConnectCode(t *testing.T) {
	codes := []connect.Code{
		connect.CodeInternal,
		connect.CodeUnavailable,
		connect.CodePermissionDenied,
		connect.CodeUnknown,
	}

	for _, code := range codes {
		err := connect.NewError(code, errors.New("some error"))
		if isCapacityError(err) {
			t.Errorf("expected isCapacityError to return false for code %v", code)
		}
	}
}

func TestIsCapacityError_NonConnectError(t *testing.T) {
	err := errors.New("plain network error")
	if isCapacityError(err) {
		t.Error("expected isCapacityError to return false for plain error")
	}
}

func TestIsCapacityError_NilError(t *testing.T) {
	if isCapacityError(nil) {
		t.Error("expected isCapacityError to return false for nil error")
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

func TestRun_ReconnectsOnCleanControllerClose(t *testing.T) {
	metrics, err := initConnectionMetrics()
	if err != nil {
		t.Fatalf("initConnectionMetrics: %v", err)
	}

	cm := &ConnectionManager{
		config: &config.Config{
			MaxTunnelsAllowed: 1,
			ReconnectInterval: time.Hour,
		},
		connections: make([]*StreamConnection, 0),
		metrics:     metrics,
	}

	reconnected := make(chan struct{})
	var callCount atomic.Int32
	cm.tunnelFunc = func(ctx context.Context) error {
		if callCount.Add(1) == 1 {
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
	case <-reconnected:
	case <-ctx.Done():
		t.Fatal("timed out waiting for reconnect after clean controller close")
	}
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

func TestRun_BackoffIncreasesOnRepeatedFailures(t *testing.T) {
	cm := &ConnectionManager{}

	// Drive nextBackoff directly. Each call advances the base by 2×.
	// Returned values include jitter so we check ranges:
	//   call N returns: base_N + rand[0, base_N/2) — capped at backoffMax.
	d1 := cm.nextBackoff() // base=1s → delay in [1s, 1.5s)
	d2 := cm.nextBackoff() // base=2s → delay in [2s, 3s)
	d3 := cm.nextBackoff() // base=4s → delay in [4s, 6s)

	if d1 < backoffInitial || d1 >= backoffInitial*3/2 {
		t.Errorf("d1 out of range [%v, %v): %v", backoffInitial, backoffInitial*3/2, d1)
	}
	if d2 < backoffInitial*2 || d2 >= backoffInitial*3 {
		t.Errorf("d2 out of range [%v, %v): %v", backoffInitial*2, backoffInitial*3, d2)
	}
	if d3 < backoffInitial*4 || d3 >= backoffInitial*6 {
		t.Errorf("d3 out of range [%v, %v): %v", backoffInitial*4, backoffInitial*6, d3)
	}

	// Drive the base to the cap; all delays must be ≤ backoffMax.
	for range 10 {
		d := cm.nextBackoff()
		if d > backoffMax {
			t.Errorf("delay %v exceeds backoffMax %v", d, backoffMax)
		}
	}

	// Reset and verify it starts in the initial range again.
	cm.resetBackoff()
	dAfterReset := cm.nextBackoff()
	if dAfterReset < backoffInitial || dAfterReset >= backoffInitial*3/2 {
		t.Errorf(
			"after reset: delay %v not in initial range [%v, %v)",
			dAfterReset,
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
