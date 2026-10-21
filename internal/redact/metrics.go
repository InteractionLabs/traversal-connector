package redact

import (
	"fmt"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/metric"

	"github.com/InteractionLabs/traversal-connector/internal/telemetry"
)

const (
	instrumentationName = "traversal-connector/redact"
	attrRuleName        = "redaction_rule"
)

// latencyPerByteBucketsMs are the per-byte redaction latency histogram
// boundaries in ms/byte, spanning about 10 GB/s to 1 MB/s of regex
// throughput. The SDK default buckets start at 5 ms/byte, so they would put
// every measurement in one bucket.
var latencyPerByteBucketsMs = []float64{
	1e-7, 2.5e-7, 5e-7, 1e-6, 2.5e-6, 5e-6,
	1e-5, 2.5e-5, 5e-5, 1e-4, 2.5e-4, 5e-4, 1e-3,
}

type redactorMetrics struct {
	latencyPerByte metric.Float64Histogram
	hitsTotal      metric.Int64Counter
}

func initRedactorMetrics() (*redactorMetrics, error) {
	meter := otel.Meter(instrumentationName)

	latencyPerByte, err := meter.Float64Histogram(
		telemetry.MetricRedactionLatencyPerByte,
		metric.WithDescription("Per-rule redaction latency per input byte"),
		metric.WithUnit("ms/By"),
		metric.WithExplicitBucketBoundaries(latencyPerByteBucketsMs...),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create redaction latency per byte histogram: %w", err)
	}

	hitsTotal, err := meter.Int64Counter(
		telemetry.MetricRedactionHitsTotal,
		metric.WithDescription("Redactions applied, counted per rule"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create redaction hits counter: %w", err)
	}

	return &redactorMetrics{latencyPerByte: latencyPerByte, hitsTotal: hitsTotal}, nil
}
