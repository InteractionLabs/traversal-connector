package client

import (
	"slices"
	"testing"

	"github.com/InteractionLabs/traversal-connector/internal/config"
)

// TestResponseSendWaitBucketsCoverRequestTimeout guards against the histogram
// ceiling drifting below the default request timeout, which would collapse a
// backed-up send queue into +Inf and flatten p95/p99.
func TestResponseSendWaitBucketsCoverRequestTimeout(t *testing.T) {
	if !slices.IsSorted(responseSendWaitBucketsMs) {
		t.Fatalf("buckets must be sorted ascending: %v", responseSendWaitBucketsMs)
	}
	got := responseSendWaitBucketsMs[len(responseSendWaitBucketsMs)-1]
	want := float64(config.DefaultRequestTimeout.Milliseconds())
	if got != want {
		t.Fatalf("highest finite bucket = %vms, want %vms (DefaultRequestTimeout)", got, want)
	}
}
