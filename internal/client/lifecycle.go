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
// It opens up to MaxTunnelsAllowed tunnels concurrently, supervises them, and
// periodically tops up to the desired count on a ReconnectInterval tick.
// It blocks until ctx is canceled and all tunnel goroutines have exited.
func (cm *ConnectionManager) Run(ctx context.Context) error {
	var wg sync.WaitGroup

	// Buffered so goroutines never block signaling a drop.
	reconnectCh := make(chan struct{}, cm.config.MaxTunnelsAllowed)

	// Initial startup: open up to MaxTunnelsAllowed tunnels.
	cm.openTunnels(ctx, &wg, reconnectCh, cm.config.MaxTunnelsAllowed)

	// Rebalance on both a periodic tick and an immediate signal from a dropped tunnel.
	ticker := time.NewTicker(cm.config.ReconnectInterval)
	defer ticker.Stop()

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-reconnectCh:
				cm.rebalance(ctx, &wg, reconnectCh)
			case <-ticker.C:
				cm.rebalance(ctx, &wg, reconnectCh)
			}
		}
	}()

	// Block until shutdown signal.
	<-ctx.Done()

	slog.InfoContext(ctx, "waiting for tunnel goroutines to finish")
	wg.Wait()

	return nil
}

// openTunnels launches count tunnel goroutines concurrently. Each goroutine
// calls RunTunnel which handles its own connection lifecycle (add/remove from
// cm.connections). Errors such as capacity limits (ResourceExhausted) are
// logged by the goroutine and do not crash the process — the rebalance ticker
// will attempt to top up later.
func (cm *ConnectionManager) openTunnels(
	ctx context.Context,
	wg *sync.WaitGroup,
	reconnectCh chan struct{},
	count int,
) {
	for range count {
		if ctx.Err() != nil {
			return
		}

		wg.Go(func() {
			start := time.Now()
			err := cm.tunnelFunc(ctx)

			if err == nil || ctx.Err() != nil {
				// Clean shutdown. Reset backoff if the tunnel was long-lived.
				if time.Since(start) >= backoffResetThreshold {
					cm.resetBackoff()
				}
				return
			}

			if isCapacityError(err) {
				slog.WarnContext(ctx, "controller at capacity, tunnel not opened",
					"active_tunnels", cm.ActiveCount(),
					"max_tunnels", cm.config.MaxTunnelsAllowed)
				return
			}

			// Unexpected drop.
			slog.ErrorContext(ctx, "tunnel exited with error", "error", err)

			if time.Since(start) >= backoffResetThreshold {
				// Tunnel was healthy before it dropped — reset backoff and reconnect immediately.
				cm.resetBackoff()
			} else {
				// Short-lived failure — back off before reconnecting.
				delay := cm.nextBackoff()
				slog.InfoContext(ctx, "backing off before reconnect", "delay", delay)
				select {
				case <-time.After(delay):
				case <-ctx.Done():
					return
				}
			}

			select {
			case reconnectCh <- struct{}{}:
			default:
			}
		})
	}
}

// rebalance checks the current tunnel count and opens new tunnels to reach
// MaxTunnelsAllowed. It is called periodically by the Run loop.
func (cm *ConnectionManager) rebalance(
	ctx context.Context,
	wg *sync.WaitGroup,
	reconnectCh chan struct{},
) {
	current := cm.ActiveCount()
	desired := cm.config.MaxTunnelsAllowed

	if current >= desired {
		slog.DebugContext(ctx, "rebalance: tunnel count at desired level",
			"current", current,
			"desired", desired)
		return
	}

	deficit := desired - current
	cm.metrics.reconnectsTotal.Add(ctx, int64(deficit))
	slog.InfoContext(ctx, "rebalance: topping up tunnels",
		"current", current,
		"desired", desired,
		"opening", deficit)

	cm.openTunnels(ctx, wg, reconnectCh, deficit)
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
