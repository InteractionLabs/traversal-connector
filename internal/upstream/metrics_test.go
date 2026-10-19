package upstream

import (
	"slices"
	"testing"

	"github.com/InteractionLabs/traversal-connector/internal/config"
)

// TestUpstreamLatencyBucketsCoverRequestTimeout guards against the histogram
// ceiling drifting below the default request timeout, which would collapse
// slow requests into +Inf and flatten p95/p99 on the connector-health dashboard.
func TestUpstreamLatencyBucketsCoverRequestTimeout(t *testing.T) {
	if !slices.IsSorted(upstreamLatencyBucketsMs) {
		t.Fatalf("buckets must be sorted ascending: %v", upstreamLatencyBucketsMs)
	}
	got := upstreamLatencyBucketsMs[len(upstreamLatencyBucketsMs)-1]
	want := float64(config.DefaultRequestTimeout.Milliseconds())
	if got != want {
		t.Fatalf("highest finite bucket = %vms, want %vms (DefaultRequestTimeout)", got, want)
	}
}
