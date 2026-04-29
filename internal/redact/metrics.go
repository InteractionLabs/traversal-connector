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

type redactorMetrics struct {
	latencyPerByte metric.Float64Histogram
}

func initRedactorMetrics() (*redactorMetrics, error) {
	meter := otel.Meter(instrumentationName)

	latencyPerByte, err := meter.Float64Histogram(
		telemetry.MetricRedactionLatencyPerByte,
		metric.WithDescription("Per-rule redaction latency per input byte"),
		metric.WithUnit("ms/By"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create redaction latency per byte histogram: %w", err)
	}

	return &redactorMetrics{latencyPerByte: latencyPerByte}, nil
}
