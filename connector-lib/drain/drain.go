// Package drain counts work in flight, such as open pipes or requests, so a
// stopping server can refuse new work and wait for the rest to finish.
//
// It is not a sync.WaitGroup: a WaitGroup cannot say how many are in
// flight, bound them, or be waited on with a deadline, and Add after Wait
// has begun is a misuse rather than an expected race (work already on its
// way as a drain starts).
package drain

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
)

// Tracker counts work in flight. Its zero value is ready to use, idle and
// not draining. It is safe for concurrent use.
type Tracker struct {
	draining atomic.Bool

	mu sync.Mutex
	n  int
	// idle is closed while n is zero; nil means closed, so the zero value
	// is idle.
	idle chan struct{}
}

// Add counts one more in flight unless limit (if positive) are already, and
// reports whether it did. Each successful Add needs one Done. Add admits
// work while draining too: whether to refuse it then is the caller's
// choice (Draining).
func (t *Tracker) Add(limit int) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if limit > 0 && t.n >= limit {
		return false
	}
	if t.n == 0 {
		t.idle = make(chan struct{})
	}
	t.n++
	return true
}

// Done ends one Add.
func (t *Tracker) Done() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.n == 0 {
		panic("drain: Done without Add")
	}
	if t.n--; t.n == 0 {
		close(t.idle)
	}
}

// InFlight is how many are in flight.
func (t *Tracker) InFlight() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.n
}

// Drain marks the tracker draining, from now on.
func (t *Tracker) Drain() { t.draining.Store(true) }

// Draining reports whether Drain was called.
func (t *Tracker) Draining() bool { return t.draining.Load() }

// Wait returns nil once nothing is in flight, or an error saying how many
// still are once ctx is done. Work added after Wait returns is not waited
// for.
func (t *Tracker) Wait(ctx context.Context) error {
	for {
		t.mu.Lock()
		n, idle := t.n, t.idle
		t.mu.Unlock()
		if n == 0 {
			return nil
		}
		select {
		case <-idle:
			// Work may have arrived since: look again.
		case <-ctx.Done():
			return fmt.Errorf("%d still in flight: %w", t.InFlight(), ctx.Err())
		}
	}
}
