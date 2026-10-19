package upstream

import (
	"context"
	"errors"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/InteractionLabs/traversal-connector/connector-lib/connector"
	"github.com/InteractionLabs/traversal-connector/internal/telemetry"
)

const (
	attrContentEncoding = "content_encoding"
	attrRefusalReason   = "refusal_reason"
)

// upstreamLatencyBucketsMs are the upstream latency histogram boundaries in
// milliseconds. The highest finite bucket matches config.DefaultRequestTimeout
// (60s) so slow and timed-out requests stay visible instead of all landing in
// +Inf above the SDK default ceiling of 10s.
var upstreamLatencyBucketsMs = []float64{
	5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000,
	10000, 15000, 20000, 30000, 45000, 60000,
}

type metrics struct {
	requests    metric.Int64Counter
	latency     metric.Float64Histogram
	encodings   metric.Int64Counter
	refusals    metric.Int64Counter
	decodedSize metric.Int64Histogram
}

func newMetrics() (*metrics, error) {
	meter := otel.Meter(InstrumentationName)
	var m metrics
	var errs [5]error
	m.requests, errs[0] = meter.Int64Counter(telemetry.MetricUpstreamRequestsTotal,
		metric.WithDescription("Upstream HTTP requests, by status"))
	m.latency, errs[1] = meter.Float64Histogram(telemetry.MetricUpstreamLatency,
		metric.WithDescription("Time to an upstream response's headers"),
		metric.WithUnit(connector.UnitMilliseconds),
		metric.WithExplicitBucketBoundaries(upstreamLatencyBucketsMs...))
	m.encodings, errs[2] = meter.Int64Counter(telemetry.MetricResponseContentEncodingTotal,
		metric.WithDescription("Upstream responses by content encoding, per target host"))
	m.refusals, errs[3] = meter.Int64Counter(telemetry.MetricResponseRefusalsTotal,
		metric.WithDescription("Responses dropped rather than forwarded unredacted, by reason"))
	m.decodedSize, errs[4] = meter.Int64Histogram(telemetry.MetricDecodedResponseBodySize,
		metric.WithDescription("Size of upstream response bodies after decoding, in bytes"),
		metric.WithUnit(connector.UnitBytes))
	return &m, errors.Join(errs[:]...)
}

func (m *metrics) requested(ctx context.Context, target, status string, start time.Time) {
	attrs := metric.WithAttributes(attribute.String(connector.AttrStatus, status),
		attribute.String(connector.AttrTargetHost, target))
	m.requests.Add(ctx, 1, attrs)
	m.latency.Record(ctx, float64(time.Since(start).Milliseconds()), attrs)
}
