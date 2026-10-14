package telemetry

import (
	"context"
	"sync/atomic"
	"testing"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

// TestNewObservableGauge: each collection reads the value then, through a
// real SDK reader.
func TestNewObservableGauge(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	meter := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader)).Meter("test")
	var v atomic.Int64
	if err := NewObservableGauge(meter, "test.gauge", v.Load); err != nil {
		t.Fatal(err)
	}
	for _, want := range []int64{3, 7} {
		v.Store(want)
		var rm metricdata.ResourceMetrics
		if err := reader.Collect(context.Background(), &rm); err != nil {
			t.Fatal(err)
		}
		g, ok := rm.ScopeMetrics[0].Metrics[0].Data.(metricdata.Gauge[int64])
		if !ok || len(g.DataPoints) != 1 || g.DataPoints[0].Value != want {
			t.Fatalf("collected %+v, want one point of %d", rm.ScopeMetrics[0].Metrics[0], want)
		}
	}
}
