package telemetry

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"go.opentelemetry.io/otel"
)

// TestSetupWithoutEndpoints: with no endpoint, logs go to the fallback
// handler, nothing exports, and flush is safe to call.
func TestSetupWithoutEndpoints(t *testing.T) {
	prev := slog.Default()
	t.Cleanup(func() { slog.SetDefault(prev) })
	var out bytes.Buffer
	flush, err := Setup(context.Background(), Config{
		ServiceName: "test", Env: "test", Fallback: slog.NewTextHandler(&out, nil),
	})
	if err != nil || flush == nil {
		t.Fatalf("Setup: %v, nil flush %v", err, flush == nil)
	}
	defer flush(time.Second)
	slog.Info("hello from the fallback")
	if !strings.Contains(out.String(), "hello from the fallback") {
		t.Fatalf("fallback handler got %q", out.String())
	}
}

// TestSetupFlushExports: flush drains a started exporter: metrics reach
// their OTLP/HTTP endpoint when flush runs, not only on the next interval.
func TestSetupFlushExports(t *testing.T) {
	prev := slog.Default()
	t.Cleanup(func() { slog.SetDefault(prev) })
	got := make(chan string, 8)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got <- r.URL.Path
	}))
	defer srv.Close()
	flush, err := Setup(context.Background(), Config{
		ServiceName: "test", MetricsEndpoint: srv.URL + "/v1/metrics",
		Fallback: slog.NewTextHandler(&bytes.Buffer{}, nil),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := NewObservableGauge(otel.Meter("test"), "test.flushed", func() int64 { return 1 }); err != nil {
		t.Fatal(err)
	}
	flush(5 * time.Second)
	select {
	case path := <-got:
		if path != "/v1/metrics" {
			t.Fatalf("export to %q", path)
		}
	default:
		t.Fatal("flush exported no metrics")
	}
}

// TestFlushSharesOneDeadline: exporters that each take the whole timeout
// flush in about one timeout, not one each, so a stopping pod's budget holds,
// and every one of them runs.
func TestFlushSharesOneDeadline(t *testing.T) {
	var ran atomic.Int32
	stall := func(ctx context.Context) error {
		<-ctx.Done()
		ran.Add(1)
		return ctx.Err()
	}
	start := time.Now()
	flushAll([]func(context.Context) error{stall, stall, stall}, 200*time.Millisecond)
	if elapsed := time.Since(start); elapsed > 400*time.Millisecond {
		t.Errorf("flush took %v for a 200ms timeout", elapsed)
	}
	if ran.Load() != 3 {
		t.Errorf("%d of 3 exporters flushed", ran.Load())
	}
}
