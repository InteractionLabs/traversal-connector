package client

import (
	"context"
	"errors"
	"log/slog"
	"math/rand/v2"
	"strings"
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

type tunnelExitReason string

const (
	tunnelExitCleanClose        tunnelExitReason = "clean_close"
	tunnelExitCapacityExhausted tunnelExitReason = "capacity_exhausted"
	tunnelExitResourceExhausted tunnelExitReason = "resource_exhausted"
	tunnelExitConnectionError   tunnelExitReason = "connection_error"

	tunnelCapacityErrorPrefix = "tunnel capacity exceeded"
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

		reason := classifyTunnelExit(err)
		switch reason {
		case tunnelExitCleanClose:
			if time.Since(start) >= backoffResetThreshold {
				// A long-lived tunnel was healthy before the control plane
				// requested a reconnect, so reconnect immediately.
				backoff.reset()
			} else {
				// Repeated short-lived clean closes must not create a hot loop.
				delay := backoff.next()
				slog.InfoContext(ctx, "short-lived tunnel closed cleanly; backing off",
					"reason", reason,
					"delay", delay)
				if !sleepOrDone(ctx, delay) {
					return
				}
			}

		case tunnelExitCapacityExhausted:
			// Reaching the control plane proves connectivity has recovered, so
			// capacity retries should not inherit earlier connection failures.
			backoff.reset()

			// The control plane is full. Hold the slot and retry on the reconnect
			// interval rather than advancing the backoff, since this is a
			// transient property of the fleet and not a fault of this tunnel.
			slog.WarnContext(ctx, "control plane at capacity, tunnel not opened",
				"reason", reason,
				"connect_code", connect.CodeOf(err),
				"active_tunnels", cm.ActiveCount(),
				"max_tunnels", cm.config.MaxTunnelsAllowed)
			if !sleepOrDone(ctx, cm.config.ReconnectInterval) {
				return
			}

		default:
			slog.ErrorContext(ctx, "tunnel exited with error",
				"reason", reason,
				"connect_code", connect.CodeOf(err),
				"error", err)

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

		cm.metrics.recordReconnect(ctx, reason, err)
	}
}

// ActiveCount returns the current number of active tunnel connections.
func (cm *ConnectionManager) ActiveCount() int {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return len(cm.connections)
}

// classifyTunnelExit separates control-plane capacity rejections from other
// ResourceExhausted errors, including ConnectRPC's local message-size limits.
func classifyTunnelExit(err error) tunnelExitReason {
	if err == nil {
		return tunnelExitCleanClose
	}
	if connect.CodeOf(err) != connect.CodeResourceExhausted {
		return tunnelExitConnectionError
	}

	var connectErr *connect.Error
	if errors.As(err, &connectErr) &&
		strings.HasPrefix(connectErr.Message(), tunnelCapacityErrorPrefix) {
		return tunnelExitCapacityExhausted
	}
	return tunnelExitResourceExhausted
}

// nextBackoff returns the current backoff duration with up to 50% added jitter,
// then advances the base for the next failure (doubling, capped at max).
func (b *tunnelBackoff) next() time.Duration {
	maxDelay := b.max
	if maxDelay < backoffInitial {
		// Config.Load rejects this, but keep the lifecycle safe for tests and
		// package-local callers that construct Config directly.
		maxDelay = backoffInitial
	}
	if b.current <= 0 {
		b.current = min(backoffInitial, maxDelay)
	}

	var jitter time.Duration
	if jitterLimit := b.current / 2; jitterLimit > 0 {
		jitter = rand.N(jitterLimit) //nolint:gosec
	}
	d := min(b.current+jitter, maxDelay)
	b.current = min(b.current*2, maxDelay)
	return d
}

// reset resets the backoff to its initial state.
func (b *tunnelBackoff) reset() {
	b.current = 0
}
