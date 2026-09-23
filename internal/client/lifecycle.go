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
	backoffMax     = 30 * time.Second
	// A tunnel that ran longer than this is considered healthy; its failure
	// resets the backoff rather than advancing it.
	backoffResetThreshold = backoffMax
)

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

// runTunnelSlot owns a single tunnel slot for the lifetime of the process,
// keeping one tunnel open and reconnecting after it ends until ctx is canceled.
// Because a slot dials only on its own goroutine and never hands the work to a
// reconciler, in-flight connection attempts can never exceed MaxTunnelsAllowed
// — including while a slot is still dialing or waiting out a backoff delay.
func (cm *ConnectionManager) runTunnelSlot(ctx context.Context) {
	for ctx.Err() == nil {
		start := time.Now()
		err := cm.tunnelFunc(ctx)

		if ctx.Err() != nil {
			return
		}

		cm.metrics.reconnectsTotal.Add(ctx, 1)

		switch {
		case err == nil:
			// The controller closed the tunnel for reconnect. Reset the backoff
			// if the tunnel was long-lived, then reconnect on the same interval
			// the rebalance ticker used to provide.
			if time.Since(start) >= backoffResetThreshold {
				cm.resetBackoff()
			}
			if !sleepOrDone(ctx, cm.config.ReconnectInterval) {
				return
			}

		case isCapacityError(err):
			// The controller is full. Hold the slot and retry; it frees up as
			// other connectors' tunnels close.
			slog.WarnContext(ctx, "controller at capacity, tunnel not opened",
				"active_tunnels", cm.ActiveCount(),
				"max_tunnels", cm.config.MaxTunnelsAllowed)
			if !sleepOrDone(ctx, cm.nextBackoff()) {
				return
			}

		default:
			// Unexpected drop.
			slog.ErrorContext(ctx, "tunnel exited with error", "error", err)

			if time.Since(start) >= backoffResetThreshold {
				// Tunnel was healthy before it dropped — reset backoff and reconnect immediately.
				cm.resetBackoff()
			} else {
				// Short-lived failure — back off before reconnecting.
				delay := cm.nextBackoff()
				slog.InfoContext(ctx, "backing off before reconnect", "delay", delay)
				if !sleepOrDone(ctx, delay) {
					return
				}
			}
		}
	}
}

// sleepOrDone waits for d, returning false if ctx was canceled first.
func sleepOrDone(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()

	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}

// ActiveCount returns the current number of active tunnel connections.
func (cm *ConnectionManager) ActiveCount() int {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return len(cm.connections)
}

// isCapacityError returns true if the error is a ResourceExhausted gRPC error
// from the controller, indicating the server has reached its tunnel limit.
func isCapacityError(err error) bool {
	return connect.CodeOf(err) == connect.CodeResourceExhausted
}

// nextBackoff returns the current backoff duration with up to 50% added jitter,
// then advances the base for the next failure (doubling, capped at backoffMax).
func (cm *ConnectionManager) nextBackoff() time.Duration {
	cm.backoffMu.Lock()
	defer cm.backoffMu.Unlock()
	if cm.backoff == 0 {
		cm.backoff = backoffInitial
	}
	jitter := rand.N(cm.backoff / 2) //nolint:gosec
	d := min(cm.backoff+jitter, backoffMax)
	cm.backoff = min(cm.backoff*2, backoffMax)
	return d
}

// resetBackoff resets the backoff to its initial state.
func (cm *ConnectionManager) resetBackoff() {
	cm.backoffMu.Lock()
	defer cm.backoffMu.Unlock()
	cm.backoff = 0
}
