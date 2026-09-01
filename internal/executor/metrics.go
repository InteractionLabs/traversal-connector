package executor

import (
	"fmt"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/metric"

	"github.com/InteractionLabs/traversal-connector/connector-lib/connector"
	"github.com/InteractionLabs/traversal-connector/internal/telemetry"
)

// Metric attribute keys for the HTTP executor.
const (
	attrContentEncoding = "content_encoding"
	attrRefusalReason   = "refusal_reason"
)

// executorMetrics holds all OTel metrics for the HTTP executor.
type executorMetrics struct {
	upstreamRequestsTotal         metric.Int64Counter
	upstreamLatency               metric.Float64Histogram
	upstreamRequestBodySizeBytes  metric.Int64Histogram
	upstreamResponseBodySizeBytes metric.Int64Histogram
	requestBodySizeLimitHit       metric.Int64Counter
	responseContentEncoding       metric.Int64Counter
	responseRefusals              metric.Int64Counter
	decodedResponseBodySizeBytes  metric.Int64Histogram
}

// initExecutorMetrics initializes metrics for the HTTP executor.
func initExecutorMetrics() (*executorMetrics, error) {
	meter := otel.Meter(InstrumentationName)

	upstreamRequestsTotal, err := meter.Int64Counter(
		telemetry.MetricUpstreamRequestsTotal,
		metric.WithDescription(
			"Total number of upstream HTTP requests executed",
		),
	)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to create upstream requests counter: %w", err,
		)
	}

	upstreamLatency, err := meter.Float64Histogram(
		telemetry.MetricUpstreamLatency,
		metric.WithDescription(
			"Latency of upstream HTTP requests in milliseconds",
		),
		metric.WithUnit(connector.UnitMilliseconds),
	)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to create upstream latency histogram: %w", err,
		)
	}

	upstreamRequestBodySizeBytes, err := meter.Int64Histogram(
		telemetry.MetricUpstreamRequestBodySize,
		metric.WithDescription(
			"Size of upstream HTTP request bodies in bytes",
		),
		metric.WithUnit(connector.UnitBytes),
	)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to create upstream request body size histogram: %w", err,
		)
	}

	upstreamResponseBodySizeBytes, err := meter.Int64Histogram(
		telemetry.MetricUpstreamResponseBodySize,
		metric.WithDescription(
			"Size of upstream HTTP response bodies in bytes",
		),
		metric.WithUnit(connector.UnitBytes),
	)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to create upstream response body size histogram: %w", err,
		)
	}

	requestBodySizeLimitHit, err := meter.Int64Counter(
		telemetry.MetricRequestBodySizeLimitHitConnector,
		metric.WithDescription(
			"Requests rejected because the body exceeded the size limit",
		),
	)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to create request body size limit hit counter: %w", err,
		)
	}

	responseContentEncoding, err := meter.Int64Counter(
		telemetry.MetricResponseContentEncodingTotal,
		metric.WithDescription(
			"Upstream responses by content encoding, per target host",
		),
	)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to create response content encoding counter: %w", err,
		)
	}

	responseRefusals, err := meter.Int64Counter(
		telemetry.MetricResponseRefusalsTotal,
		metric.WithDescription(
			"Responses dropped rather than forwarded unredacted, by reason",
		),
	)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to create response refusals counter: %w", err,
		)
	}

	decodedResponseBodySizeBytes, err := meter.Int64Histogram(
		telemetry.MetricDecodedResponseBodySize,
		metric.WithDescription(
			"Size of upstream HTTP response bodies after decoding, in bytes",
		),
		metric.WithUnit(connector.UnitBytes),
	)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to create decoded response body size histogram: %w", err,
		)
	}

	return &executorMetrics{
		upstreamRequestsTotal:         upstreamRequestsTotal,
		upstreamLatency:               upstreamLatency,
		upstreamRequestBodySizeBytes:  upstreamRequestBodySizeBytes,
		upstreamResponseBodySizeBytes: upstreamResponseBodySizeBytes,
		requestBodySizeLimitHit:       requestBodySizeLimitHit,
		responseContentEncoding:       responseContentEncoding,
		responseRefusals:              responseRefusals,
		decodedResponseBodySizeBytes:  decodedResponseBodySizeBytes,
	}, nil
}
