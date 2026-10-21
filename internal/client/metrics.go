package client

import (
	"fmt"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/metric"

	"github.com/InteractionLabs/traversal-connector/connector-lib/connector"
	"github.com/InteractionLabs/traversal-connector/internal/telemetry"
)

// responseSendWaitBucketsMs are the send queue wait histogram boundaries in
// milliseconds. They match the upstream latency buckets, ending at
// config.DefaultRequestTimeout (60s), so a backed-up queue stays visible
// instead of all landing in +Inf above the SDK default ceiling of 10s.
var responseSendWaitBucketsMs = []float64{
	5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000,
	10000, 15000, 20000, 30000, 45000, 60000,
}

// connectionMetrics holds all OTel metrics for the connection manager.
type connectionMetrics struct {
	streamsActive           metric.Int64UpDownCounter
	reconnectsTotal         metric.Int64Counter
	concurrentRequests      metric.Int64UpDownCounter
	responseSendWaitLatency metric.Float64Histogram
}

// initConnectionMetrics initializes metrics for the connection manager.
func initConnectionMetrics() (*connectionMetrics, error) {
	meter := otel.Meter(InstrumentationName)

	streamsActive, err := meter.Int64UpDownCounter(
		telemetry.MetricStreamsActive,
		metric.WithDescription(
			"Current number of active gRPC streams to the controller",
		),
	)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to create streams active counter: %w", err,
		)
	}

	reconnectsTotal, err := meter.Int64Counter(
		telemetry.MetricReconnectsTotal,
		metric.WithDescription(
			"Total number of tunnel reconnection attempts",
		),
	)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to create reconnects counter: %w", err,
		)
	}

	concurrentRequests, err := meter.Int64UpDownCounter(
		telemetry.MetricConcurrentRequests,
		metric.WithDescription(
			"Current number of active upstream HTTP requests being processed",
		),
	)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to create concurrent requests counter: %w", err,
		)
	}

	responseSendWaitLatency, err := meter.Float64Histogram(
		telemetry.MetricResponseSendWaitLatency,
		metric.WithDescription(
			"Time a response waits in the send queue before stream write",
		),
		metric.WithUnit(connector.UnitMilliseconds),
		metric.WithExplicitBucketBoundaries(responseSendWaitBucketsMs...),
	)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to create response send wait latency histogram: %w", err,
		)
	}

	return &connectionMetrics{
		streamsActive:           streamsActive,
		reconnectsTotal:         reconnectsTotal,
		concurrentRequests:      concurrentRequests,
		responseSendWaitLatency: responseSendWaitLatency,
	}, nil
}
