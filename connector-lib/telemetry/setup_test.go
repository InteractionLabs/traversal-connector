package telemetry

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
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
