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
	wireLimit := float64(config.DefaultBodySizeMB * bytesPerKB * kbPerMB)
	if !slices.Contains(bodySizeBucketsBytes, wireLimit) {
		t.Fatalf("buckets %v lack %v bytes (DefaultBodySizeMB)", bodySizeBucketsBytes, wireLimit)
	}
	got := bodySizeBucketsBytes[len(bodySizeBucketsBytes)-1]
	want := float64(config.DefaultDecodedBodySizeMB * bytesPerKB * kbPerMB)
	if got != want {
		t.Fatalf("highest finite bucket = %v bytes, want %v (DefaultDecodedBodySizeMB)", got, want)
	}
}
