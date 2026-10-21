package executor

import (
	"slices"
	"testing"

	"github.com/InteractionLabs/traversal-connector/internal/config"
)

// TestUpstreamLatencyBucketsCoverRequestTimeout guards against the histogram
// ceiling drifting below the default request timeout, which would collapse
// slow requests into +Inf and flatten p95/p99.
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

// TestBodySizeBucketsCoverBodyLimits guards against the size buckets losing
// the default wire and decoded body limits, which would blur how close bodies
// get to being rejected.
func TestBodySizeBucketsCoverBodyLimits(t *testing.T) {
	if !slices.IsSorted(bodySizeBucketsBytes) {
		t.Fatalf("buckets must be sorted ascending: %v", bodySizeBucketsBytes)
	}
	limits := map[string]float64{
		"DefaultBodySizeMB":        config.DefaultBodySizeMB * bytesPerMB,
		"DefaultDecodedBodySizeMB": config.DefaultDecodedBodySizeMB * bytesPerMB,
	}
	for name, limit := range limits {
		if !slices.Contains(bodySizeBucketsBytes, limit) {
			t.Errorf("buckets %v lack %v bytes (%s)", bodySizeBucketsBytes, limit, name)
		}
	}
}
