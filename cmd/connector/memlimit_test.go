package main

import (
	"math"
	"runtime/debug"
	"testing"
)

// TestMemoryLimit: the soft memory limit is 90% of the container's limit,
// read from TRAVERSAL_MEMORY_LIMIT_BYTES as the chart renders it; with no
// limit, an unparseable one, or GOMEMLIMIT set, Go's own is left alone.
func TestMemoryLimit(t *testing.T) {
	const unset = int64(math.MaxInt64)
	for _, c := range []struct {
		name, bytes, gomemlimit string
		want                    int64
	}{
		{"a 4Gi limit", "4294967296", "", 3865470566},
		{"no limit", "", "", unset},
		{"zero", "0", "", unset},
		{"not a number", "4Gi", "", unset},
		{"GOMEMLIMIT wins", "4294967296", "1GiB", unset},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv("TRAVERSAL_MEMORY_LIMIT_BYTES", c.bytes)
			t.Setenv("GOMEMLIMIT", c.gomemlimit)
			previous := debug.SetMemoryLimit(unset)
			t.Cleanup(func() { debug.SetMemoryLimit(previous) })
			setMemoryLimit()
			if got := debug.SetMemoryLimit(-1); got != c.want {
				t.Errorf("memory limit %d, want %d", got, c.want)
			}
		})
	}
}
