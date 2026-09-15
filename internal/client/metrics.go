package client

import (
	"context"
	"fmt"

	"connectrpc.com/connect"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/InteractionLabs/traversal-connector/connector-lib/connector"
	"github.com/InteractionLabs/traversal-connector/internal/telemetry"
)

const (
	attrReconnectReason = "reconnect_reason"
	attrConnectCode     = "connect_code"
)

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
			"Current number of active gRPC streams to the control plane",
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

func (m *connectionMetrics) recordReconnect(
	ctx context.Context,
	reason tunnelExitReason,
	err error,
) {
	attrs := []attribute.KeyValue{
		attribute.String(attrReconnectReason, string(reason)),
	}
	if err != nil {
		attrs = append(attrs, attribute.String(attrConnectCode, connect.CodeOf(err).String()))
	}
	m.reconnectsTotal.Add(ctx, 1, metric.WithAttributes(attrs...))
}
