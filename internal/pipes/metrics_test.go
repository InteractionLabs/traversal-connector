package pipes

import (
	"context"
	"io"
	"net/http"
	"testing"
	"time"

	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/InteractionLabs/traversal-connector/connector-lib/capability"
	"github.com/InteractionLabs/traversal-connector/internal/telemetry"
)

// sum adds up every data point of the named counter or up-down counter whose
// attributes include want.
func sum(
	t *testing.T,
	rm metricdata.ResourceMetrics,
	name string,
	want ...attribute.KeyValue,
) int64 {
	t.Helper()
	var total int64
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != name {
				continue
			}
			data, ok := m.Data.(metricdata.Sum[int64])
			if !ok {
				t.Fatalf("%s is %T, not an int64 sum", name, m.Data)
			}
			for _, dp := range data.DataPoints {
				if hasAll(dp.Attributes, want) {
					total += dp.Value
				}
			}
		}
	}
	return total
}

// histogramCount is how many values the named histogram recorded with want.
func histogramCount(rm metricdata.ResourceMetrics, name string, want ...attribute.KeyValue) uint64 {
	var total uint64
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != name {
				continue
			}
			switch data := m.Data.(type) {
			case metricdata.Histogram[int64]:
				for _, dp := range data.DataPoints {
					if hasAll(dp.Attributes, want) {
						total += dp.Count
					}
				}
			case metricdata.Histogram[float64]:
				for _, dp := range data.DataPoints {
					if hasAll(dp.Attributes, want) {
						total += dp.Count
					}
				}
			}
		}
	}
	return total
}

func hasAll(set attribute.Set, want []attribute.KeyValue) bool {
	for _, kv := range want {
		if v, ok := set.Value(kv.Key); !ok || v != kv.Value {
			return false
		}
	}
	return true
}

// Real pipes through the server: one completes, one is refused for its
// capability, one is cut for idling, then the server drains.
func TestMetricsCountPipesFromOpenToClose(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() { _ = provider.Shutdown(context.Background()) })
	h := newHarness(t, harnessConfig{meters: provider, idleTimeout: 300 * time.Millisecond})

	done := h.open("db.internal", 5432)
	doneDst := h.accept()
	if _, err := done.body.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	_ = done.body.Close()
	if got, err := io.ReadAll(doneDst); err != nil || string(got) != "hello" {
		t.Fatalf("destination read %q, %v", got, err)
	}
	_ = doneDst.CloseWrite()
	_, _ = io.ReadAll(done.resp.Body)
	_ = doneDst.Close()

	wrong, err := h.connect(capability.CanonicalAuthority("db.internal", 5432),
		capabilityFor(t, "other.internal", 5432))
	if err != nil {
		t.Fatal(err)
	}
	_ = wrong.resp.Body.Close()
	if wrong.resp.StatusCode == http.StatusOK {
		t.Fatal("opened a pipe to a destination its capability does not name")
	}

	idle := h.open("db.internal", 5432)
	idleDst := h.accept()
	defer func() { _ = idleDst.Close() }()
	if _, err := io.ReadAll(idle.resp.Body); err == nil {
		t.Fatal("the idle pipe ended cleanly")
	}
	h.server.Drain()
	h.server.Drain() // counted once

	var rm metricdata.ResourceMetrics
	deadline := time.Now().Add(5 * time.Second)
	for {
		if err := reader.Collect(context.Background(), &rm); err != nil {
			t.Fatal(err)
		}
		if sum(t, rm, telemetry.MetricRawPipeClosesTotal) == 2 || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	str := attribute.String
	for _, c := range []struct {
		name  string
		attrs []attribute.KeyValue
		want  int64
	}{
		{telemetry.MetricRawOpensTotal, []attribute.KeyValue{str(attrResult, "opened")}, 2},
		{telemetry.MetricRawOpensTotal, []attribute.KeyValue{
			str(attrResult, "refused"), str(attrReason, "wrong_destination"),
		}, 1},
		{telemetry.MetricRawCapabilityVerificationsTotal, []attribute.KeyValue{
			str(attrResult, "accepted"),
		}, 2},
		{telemetry.MetricRawCapabilityVerificationsTotal, []attribute.KeyValue{
			str(attrResult, "rejected"),
		}, 1},
		{telemetry.MetricRawCapabilityRejectionsTotal, []attribute.KeyValue{
			str(attrCode, string(capability.CodeWrongDestination)),
		}, 1},
		{telemetry.MetricRawPipeClosesTotal, []attribute.KeyValue{str(attrReason, "completed")}, 1},
		{telemetry.MetricRawPipeClosesTotal, []attribute.KeyValue{str(attrReason, "idle_timeout")}, 1},
		{telemetry.MetricRawResetsTotal, []attribute.KeyValue{str(attrOrigin, "connector")}, 1},
		{telemetry.MetricRawResetsTotal, nil, 1},
		{telemetry.MetricRawPipesActive, nil, 0},
		{telemetry.MetricRawDrainsTotal, nil, 1},
		{telemetry.MetricRawKeyLoadsTotal, nil, 1},
	} {
		if got := sum(t, rm, c.name, c.attrs...); got != c.want {
			t.Errorf("%s%v = %d, want %d", c.name, c.attrs, got, c.want)
		}
	}
	if n := histogramCount(rm, telemetry.MetricRawPipeBytes, str(attrDirection, "sent")); n != 2 {
		t.Errorf("bytes sent recorded %d times, want 2", n)
	}
	if n := histogramCount(rm, telemetry.MetricRawPipeDuration); n != 2 {
		t.Errorf("duration recorded %d times, want 2", n)
	}
}
