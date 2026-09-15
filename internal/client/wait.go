package client

import (
	"context"
	"time"
)

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
