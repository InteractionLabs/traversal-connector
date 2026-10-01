package rawclient

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	pb "github.com/InteractionLabs/traversal-connector/connector-lib/gen/connector/v1"
	"github.com/InteractionLabs/traversal-connector/internal/telemetry"
)

// rawMetrics are the raw-tunnel instruments. Labels are enums, never a host,
// a token, a jti, or a pipe id.
type rawMetrics struct {
	tunnelsActive   metric.Int64UpDownCounter
	tunnelsDraining metric.Int64UpDownCounter
	controlDrops    metric.Int64Counter
	drains          metric.Int64Counter
	reconnects      metric.Int64Counter
}

func newRawMetrics() (*rawMetrics, error) {
	meter := otel.Meter("traversal-connector/raw")
	m := &rawMetrics{}
	var err error
	m.tunnelsActive, err = meter.Int64UpDownCounter(
		telemetry.MetricRawTunnelsActive,
		metric.WithDescription("Raw tunnels that are accepting new pipes"),
	)
	if err != nil {
		return nil, fmt.Errorf("raw tunnels active: %w", err)
	}
	m.tunnelsDraining, err = meter.Int64UpDownCounter(
		telemetry.MetricRawTunnelsDraining,
		metric.WithDescription(
			"Raw tunnels that stay open only until their current pipes end",
		),
	)
	if err != nil {
		return nil, fmt.Errorf("raw tunnels draining: %w", err)
	}
	m.controlDrops, err = meter.Int64Counter(
		telemetry.MetricRawControlRecordsDroppedTotal,
		metric.WithDescription(
			"Connector control records dropped because the send buffer was full",
		),
	)
	if err != nil {
		return nil, fmt.Errorf("raw control drops: %w", err)
	}
	m.drains, err = meter.Int64Counter(
		telemetry.MetricRawDrainsTotal,
		metric.WithDescription("Raw tunnels that stopped accepting new pipes"),
	)
	if err != nil {
		return nil, fmt.Errorf("raw drains: %w", err)
	}
	m.reconnects, err = meter.Int64Counter(
		telemetry.MetricRawReconnectsTotal,
		metric.WithDescription(
			"Raw tunnel reconnect attempts after a failed open or drop",
		),
	)
	if err != nil {
		return nil, fmt.Errorf("raw reconnects: %w", err)
	}
	return m, nil
}

func (m *rawMetrics) addActive(n int64) {
	m.tunnelsActive.Add(context.Background(), n)
}

func (m *rawMetrics) addDraining(n int64) {
	m.tunnelsDraining.Add(context.Background(), n)
}

func (m *rawMetrics) controlDrop() {
	m.controlDrops.Add(context.Background(), 1)
}

func (m *rawMetrics) drain(reason pb.RawDrainReason) {
	m.drains.Add(context.Background(), 1,
		metric.WithAttributes(attribute.String("reason", reason.String())))
}

func (m *rawMetrics) reconnect() { m.reconnects.Add(context.Background(), 1) }
