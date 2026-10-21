package redact

import (
	"slices"
	"testing"
)

// TestLatencyPerByteBucketsResolveRegexThroughput guards against the buckets
// drifting back toward the SDK defaults, whose lowest boundary (5 ms/byte) is
// far above real per-byte regex cost and puts every measurement in one bucket.
func TestLatencyPerByteBucketsResolveRegexThroughput(t *testing.T) {
	if !slices.IsSorted(latencyPerByteBucketsMs) {
		t.Fatalf("buckets must be sorted ascending: %v", latencyPerByteBucketsMs)
	}
	// 1e-6 ms/byte is 1 GB/s, typical for a simple regex on a large body.
	const typical = 1e-6
	first, last := latencyPerByteBucketsMs[0], latencyPerByteBucketsMs[len(latencyPerByteBucketsMs)-1]
	if first >= typical || last <= typical {
		t.Fatalf("buckets [%v, %v] must bracket %v ms/byte", first, last, typical)
	}
}
