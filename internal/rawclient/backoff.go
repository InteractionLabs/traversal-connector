package rawclient

import (
	"context"
	"math/rand/v2"
	"sync"
	"time"
)

const (
	backoffInitial = time.Second
	backoffMax     = 30 * time.Second
	// A tunnel that stayed up this long was healthy. Its end resets the
	// backoff instead of treating the drop as another failure in a storm.
	backoffResetAfter = backoffMax
)

// backoff is the raw-tunnel reconnect delay. It is deliberately not the legacy
// tunnel backoff: a raw controller that is down must not slow legacy reconnects,
// and a legacy failure must not slow raw ones.
type backoff struct {
	mu      sync.Mutex
	current time.Duration
	initial time.Duration
	max     time.Duration
}

func newBackoff() backoff {
	return backoff{initial: backoffInitial, max: backoffMax}
}

func (b *backoff) next() time.Duration {
	b.mu.Lock()
	defer b.mu.Unlock()
	initial, limit := b.initial, b.max
	if initial <= 0 {
		initial = backoffInitial
	}
	if limit <= 0 {
		limit = backoffMax
	}
	if b.current == 0 {
		b.current = initial
	}
	var jitter time.Duration
	if half := b.current / 2; half > 0 {
		jitter = rand.N(half) //nolint:gosec // reconnect jitter is not a security boundary
	}
	delay := min(b.current+jitter, limit)
	b.current = min(b.current*2, limit)
	return delay
}

func (b *backoff) reset() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.current = 0
}

func sleep(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}
