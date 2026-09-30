package rawclient

import (
	"context"
	"fmt"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	pb "github.com/InteractionLabs/traversal-connector/connector-lib/gen/connector/v1"
	"github.com/InteractionLabs/traversal-connector/internal/telemetry"
)

// rawMetrics are the raw-tunnel instruments. Labels are enums or directions,
// never a host, a token, a jti, or a pipe id.
type rawMetrics struct {
	tunnelsActive   metric.Int64UpDownCounter
	tunnelsDraining metric.Int64UpDownCounter
	pipesActive     metric.Int64UpDownCounter
	opens           metric.Int64Counter
	closes          metric.Int64Counter
	bytes           metric.Int64Histogram
	duration        metric.Float64Histogram
	controlDrops    metric.Int64Counter
	halfCloses      metric.Int64Counter
	drains          metric.Int64Counter
	reconnects      metric.Int64Counter
	resets          metric.Int64Counter
	clockSkew       metric.Float64Histogram
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
	m.pipesActive, err = meter.Int64UpDownCounter(
		telemetry.MetricRawPipesActive,
		metric.WithDescription("Raw pipes with an open destination socket"),
	)
	if err != nil {
		return nil, fmt.Errorf("raw pipes active: %w", err)
	}
	m.opens, err = meter.Int64Counter(
		telemetry.MetricRawOpensTotal,
		metric.WithDescription("Raw pipe opens admitted or refused"),
	)
	if err != nil {
		return nil, fmt.Errorf("raw opens: %w", err)
	}
	m.closes, err = meter.Int64Counter(
		telemetry.MetricRawPipeClosesTotal,
		metric.WithDescription("Raw pipes that finished, by close reason"),
	)
	if err != nil {
		return nil, fmt.Errorf("raw closes: %w", err)
	}
	m.bytes, err = meter.Int64Histogram(
		telemetry.MetricRawPipeBytes,
		metric.WithDescription("Bytes relayed on a raw pipe, by direction"),
		metric.WithUnit("By"),
		metric.WithExplicitBucketBoundaries(
			1<<10, 64<<10, 1<<20, 16<<20, 256<<20, 1<<30, 8<<30,
		),
	)
	if err != nil {
		return nil, fmt.Errorf("raw bytes: %w", err)
	}
	m.duration, err = meter.Float64Histogram(
		telemetry.MetricRawPipeDuration,
		metric.WithDescription("How long a raw pipe was open"),
		metric.WithUnit("s"),
		metric.WithExplicitBucketBoundaries(0.1, 1, 10, 60, 600, 3600, 14400),
	)
	if err != nil {
		return nil, fmt.Errorf("raw duration: %w", err)
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
	m.halfCloses, err = meter.Int64Counter(
		telemetry.MetricRawHalfClosesTotal,
		metric.WithDescription("Directional half-closes on raw pipes"),
	)
	if err != nil {
		return nil, fmt.Errorf("raw half-closes: %w", err)
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
	m.resets, err = meter.Int64Counter(
		telemetry.MetricRawResetsTotal,
		metric.WithDescription(
			"Raw pipe RESET frames sent or received, by origin and reason",
		),
	)
	if err != nil {
		return nil, fmt.Errorf("raw resets: %w", err)
	}
	m.clockSkew, err = meter.Float64Histogram(
		telemetry.MetricRawClockSkew,
		metric.WithDescription(
			"How far the capability signer's clock was ahead of this connector",
		),
		metric.WithUnit("s"),
		metric.WithExplicitBucketBoundaries(-30, -5, -1, 0, 1, 5, 30),
	)
	if err != nil {
		return nil, fmt.Errorf("raw clock skew: %w", err)
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

func (m *rawMetrics) addPipe(n int64) {
	m.pipesActive.Add(context.Background(), n)
}

func (m *rawMetrics) admitted() {
	m.opens.Add(context.Background(), 1,
		metric.WithAttributes(attribute.String("result", "admitted")))
}

func (m *rawMetrics) refused(reason pb.RawOpenFailureReason) {
	m.opens.Add(context.Background(), 1,
		metric.WithAttributes(
			attribute.String("result", "refused"),
			attribute.String("reason", reason.String()),
		))
}

func (m *rawMetrics) closed(
	reason pb.RawCloseReason, sent, received int64, d time.Duration,
) {
	ctx := context.Background()
	m.closes.Add(ctx, 1, metric.WithAttributes(attribute.String("reason", reason.String())))
	m.bytes.Record(ctx, sent, metric.WithAttributes(attribute.String("direction", "sent")))
	m.bytes.Record(ctx, received, metric.WithAttributes(attribute.String("direction", "received")))
	m.duration.Record(ctx, d.Seconds())
}

func (m *rawMetrics) halfClose() { m.halfCloses.Add(context.Background(), 1) }

func (m *rawMetrics) drain(reason pb.RawDrainReason) {
	m.drains.Add(context.Background(), 1,
		metric.WithAttributes(attribute.String("reason", reason.String())))
}

func (m *rawMetrics) reconnect() { m.reconnects.Add(context.Background(), 1) }

func (m *rawMetrics) reset(origin, phase string, reason pb.RawCloseReason) {
	m.resets.Add(context.Background(), 1, metric.WithAttributes(
		attribute.String("origin", origin),
		attribute.String("phase", phase),
		attribute.String("reason", reason.String()),
	))
}

func (m *rawMetrics) skew(d time.Duration) {
	m.clockSkew.Record(context.Background(), d.Seconds())
}
