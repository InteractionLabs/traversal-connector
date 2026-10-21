package telemetry

import (
	"context"
	"testing"
)

func TestRequestIDRoundTrip(t *testing.T) {
	if got := RequestIDFromContext(context.Background()); got != "" {
		t.Errorf("RequestIDFromContext(empty) = %q, want \"\"", got)
	}
	ctx := WithRequestID(context.Background(), "req-42")
	if got := RequestIDFromContext(ctx); got != "req-42" {
		t.Errorf("RequestIDFromContext() = %q, want %q", got, "req-42")
	}
}
