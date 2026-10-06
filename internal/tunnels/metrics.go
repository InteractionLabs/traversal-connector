package tunnels

import (
	"context"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/metric"

	"github.com/InteractionLabs/traversal-connector/internal/telemetry"
)

// InstrumentationName is the OTel meter name for the tunnels.
const InstrumentationName = "traversal-connector/tunnels"

// statsTimeout bounds one read of Envoy's tunnel gauges for metrics.
const statsTimeout = time.Second

// registerMetrics reports how many tunnels Envoy holds, read from Envoy's own
// gauges at each collection. A collection Envoy does not answer reports
// nothing rather than a guess.
func (m *Manager) registerMetrics(provider metric.MeterProvider) error {
	if provider == nil {
		provider = otel.GetMeterProvider()
	}
	_, err := provider.Meter(InstrumentationName).Int64ObservableGauge(
		telemetry.MetricRawTunnelsActive,
		metric.WithDescription("Tunnels the connector holds to Traversal's tunnel endpoint"),
		metric.WithInt64Callback(func(ctx context.Context, o metric.Int64Observer) error {
			ctx, cancel := context.WithTimeout(ctx, statsTimeout)
			defer cancel()
			if up, err := m.admin.tunnels(ctx); err == nil {
				o.Observe(int64(up))
			}
			return nil
		}),
	)
	return err
}
