package client

import (
	"context"
	"log/slog"
	"math/rand/v2"
	"sync"
	"time"

	"connectrpc.com/connect"
)

const (
	backoffInitial = 1 * time.Second
	// A tunnel that ran longer than this is considered healthy; its failure
	// resets the backoff rather than advancing it.
	backoffResetThreshold = 30 * time.Second
)

type tunnelBackoff struct {
	current time.Duration
	max     time.Duration
}

// Run manages the full lifecycle of tunnel connections to the Traversal control plane.
// It launches exactly MaxTunnelsAllowed tunnel slots, each of which owns one
// tunnel for the lifetime of the process and reconnects on its own.
// It blocks until ctx is canceled and all tunnel goroutines have exited.
func (cm *ConnectionManager) Run(ctx context.Context) error {
	var wg sync.WaitGroup

	for range cm.config.MaxTunnelsAllowed {
		wg.Go(func() { cm.runTunnelSlot(ctx) })
	}

	// Block until shutdown signal.
	<-ctx.Done()

	slog.InfoContext(ctx, "waiting for tunnel goroutines to finish")
	wg.Wait()

	return nil
}

// runTunnelSlot owns a single tunnel slot for the lifetime of the process. It
// keeps one tunnel open, reconnecting after a drop until ctx is canceled.
// Because the slot never yields to a reconciler, the number of in-flight
// connection attempts can never exceed MaxTunnelsAllowed — including while a
// slot is still dialing or waiting out a backoff delay.
func (cm *ConnectionManager) runTunnelSlot(ctx context.Context) {
	backoff := tunnelBackoff{max: cm.config.MaxBackoffDelay}

	for ctx.Err() == nil {
		start := time.Now()
		err := cm.tunnelFunc(ctx)

		if ctx.Err() != nil {
			return
		}

		switch {
		case err == nil:
			// The control plane can cleanly close a stream to request reconnect.
			backoff.reset()

		case isCapacityError(err):
			// Reaching the control plane proves connectivity has recovered, so
			// capacity retries should not inherit earlier connection failures.
			backoff.reset()

			// The control plane is full. Hold the slot and retry on the reconnect
			// interval rather than advancing the backoff, since this is a
			// transient property of the fleet and not a fault of this tunnel.
			slog.WarnContext(ctx, "control plane at capacity, tunnel not opened",
				"active_tunnels", cm.ActiveCount(),
				"max_tunnels", cm.config.MaxTunnelsAllowed)
			if !sleepOrDone(ctx, cm.config.ReconnectInterval) {
				return
			}

		default:
			// Unexpected drop.
			slog.ErrorContext(ctx, "tunnel exited with error", "error", err)

			if time.Since(start) >= backoffResetThreshold {
				// Tunnel was healthy before it dropped — reset backoff and reconnect immediately.
				backoff.reset()
			} else {
				// Short-lived failure — back off before reconnecting.
				delay := backoff.next()
				slog.InfoContext(ctx, "backing off before reconnect", "delay", delay)
				if !sleepOrDone(ctx, delay) {
					return
				}
			}
		}

		cm.metrics.reconnectsTotal.Add(ctx, 1)
	}
}

// ActiveCount returns the current number of active tunnel connections.
func (cm *ConnectionManager) ActiveCount() int {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return len(cm.connections)
}

// isCapacityError returns true if the error is a ResourceExhausted gRPC error
// from the control plane, indicating the server has reached its tunnel limit.
func isCapacityError(err error) bool {
	return connect.CodeOf(err) == connect.CodeResourceExhausted
}

// nextBackoff returns the current backoff duration with up to 50% added jitter,
// then advances the base for the next failure (doubling, capped at max).
func (b *tunnelBackoff) next() time.Duration {
	if b.current == 0 {
		b.current = backoffInitial
	}
	jitter := rand.N(b.current / 2) //nolint:gosec
	d := min(b.current+jitter, b.max)
	b.current = min(b.current*2, b.max)
	return d
}

// reset resets the backoff to its initial state.
func (b *tunnelBackoff) reset() {
	b.current = 0
}
