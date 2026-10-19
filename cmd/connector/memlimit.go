package main

import (
	"log/slog"
	"os"
	"runtime/debug"
	"strconv"
)

// memoryLimitShare is the part of the container's memory limit the Go
// runtime aims to stay under, leaving headroom for memory it does not manage
// (stacks, cgo, the kernel's page cache) before the kernel kills the pod.
const memoryLimitShare = 0.9

// setMemoryLimit sets Go's soft memory limit to memoryLimitShare of
// TRAVERSAL_MEMORY_LIMIT_BYTES, the container's memory limit as the chart
// renders it from the downward API. The downward API cannot scale a value, so
// GOMEMLIMIT cannot be rendered directly. Unset, not a positive integer, or
// with GOMEMLIMIT set (which Go has already applied), Go's default stays.
func setMemoryLimit() {
	raw := os.Getenv("TRAVERSAL_MEMORY_LIMIT_BYTES")
	if raw == "" || os.Getenv("GOMEMLIMIT") != "" {
		return
	}
	limit, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || limit <= 0 {
		slog.Warn("TRAVERSAL_MEMORY_LIMIT_BYTES is not a byte count; "+
			"leaving Go's memory limit unset", "value", raw)
		return
	}
	soft := int64(float64(limit) * memoryLimitShare)
	debug.SetMemoryLimit(soft)
	slog.Info("Go memory limit set from the container's", "limit_bytes", limit,
		"soft_limit_bytes", soft)
}
