package pipes

import (
	"context"
	"errors"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/InteractionLabs/traversal-connector/connector-lib/capability"
	pb "github.com/InteractionLabs/traversal-connector/connector-lib/gen/connector/v1"
	"github.com/InteractionLabs/traversal-connector/internal/telemetry"
)

// InstrumentationName is the OTel meter name for the pipe server.
const InstrumentationName = "traversal-connector/pipes"

// Metric attribute keys. Every value is from a closed set (an enum, a
// capability code, a direction, or an origin), never a host, a token, a jti,
// or a pipe id.
const (
	attrResult    = "result"
	attrReason    = "reason"
	attrCode      = "code"
	attrDirection = "direction"
	attrOrigin    = "origin"
)

// pipeMetrics are the pipe server's instruments.
type pipeMetrics struct {
	active        metric.Int64UpDownCounter
	opens         metric.Int64Counter
	closes        metric.Int64Counter
	bytes         metric.Int64Histogram
	duration      metric.Float64Histogram
	resets        metric.Int64Counter
	drains        metric.Int64Counter
	verifications metric.Int64Counter
	rejections    metric.Int64Counter
	keyLoads      metric.Int64Counter
}

func newPipeMetrics(provider metric.MeterProvider) (*pipeMetrics, error) {
	if provider == nil {
		provider = otel.GetMeterProvider()
	}
	meter := provider.Meter(InstrumentationName)
	m := &pipeMetrics{}
	var errs [10]error
	m.active, errs[0] = meter.Int64UpDownCounter(telemetry.MetricRawPipesActive,
		metric.WithDescription("Raw pipes open now"))
	m.opens, errs[1] = meter.Int64Counter(telemetry.MetricRawOpensTotal,
		metric.WithDescription("Raw pipe opens, by result and refusal reason"))
	m.closes, errs[2] = meter.Int64Counter(telemetry.MetricRawPipeClosesTotal,
		metric.WithDescription("Raw pipes that ended, by close reason"))
	m.bytes, errs[3] = meter.Int64Histogram(telemetry.MetricRawPipeBytes,
		metric.WithDescription("Bytes a raw pipe carried, by direction"),
		metric.WithUnit("By"),
		metric.WithExplicitBucketBoundaries(1<<10, 64<<10, 1<<20, 16<<20, 256<<20, 1<<30, 8<<30))
	m.duration, errs[4] = meter.Float64Histogram(telemetry.MetricRawPipeDuration,
		metric.WithDescription("How long a raw pipe was open"),
		metric.WithUnit("s"),
		metric.WithExplicitBucketBoundaries(0.1, 1, 10, 60, 600, 3600, 14400))
	m.resets, errs[5] = meter.Int64Counter(telemetry.MetricRawResetsTotal,
		metric.WithDescription("Raw pipes that ended in a reset, by which side reset them"))
	m.drains, errs[6] = meter.Int64Counter(telemetry.MetricRawDrainsTotal,
		metric.WithDescription("Times the pipe server began refusing new pipes to drain"))
	m.verifications, errs[7] = meter.Int64Counter(
		telemetry.MetricRawCapabilityVerificationsTotal,
		metric.WithDescription("Capabilities checked, by result"))
	m.rejections, errs[8] = meter.Int64Counter(telemetry.MetricRawCapabilityRejectionsTotal,
		metric.WithDescription("Capabilities that failed verification, by code"))
	m.keyLoads, errs[9] = meter.Int64Counter(telemetry.MetricRawKeyLoadsTotal,
		metric.WithDescription("Trusted capability public keys loaded at startup"))
	if err := errors.Join(errs[:]...); err != nil {
		return nil, err
	}
	return m, nil
}

func (m *pipeMetrics) refused(reason pb.RawOpenFailureReason) {
	m.opens.Add(context.Background(), 1, metric.WithAttributes(
		attribute.String(attrResult, "refused"),
		attribute.String(attrReason, ReasonName(reason)),
	))
}

func (m *pipeMetrics) opened() {
	ctx := context.Background()
	m.opens.Add(ctx, 1, metric.WithAttributes(attribute.String(attrResult, "opened")))
	m.active.Add(ctx, 1)
}

func (m *pipeMetrics) verified() {
	m.verifications.Add(context.Background(), 1,
		metric.WithAttributes(attribute.String(attrResult, "accepted")))
}

func (m *pipeMetrics) rejected(code capability.Code) {
	ctx := context.Background()
	m.verifications.Add(ctx, 1, metric.WithAttributes(attribute.String(attrResult, "rejected")))
	m.rejections.Add(ctx, 1, metric.WithAttributes(attribute.String(attrCode, string(code))))
}

// closed records a pipe that opened and has now ended.
func (m *pipeMetrics) closed(r spliceResult, d time.Duration) {
	ctx := context.Background()
	m.active.Add(ctx, -1)
	m.closes.Add(ctx, 1, metric.WithAttributes(
		attribute.String(attrReason, closeReasonName(r.outcome.closeReason()))))
	m.bytes.Record(ctx, r.sent, metric.WithAttributes(attribute.String(attrDirection, "sent")))
	m.bytes.Record(ctx, r.received,
		metric.WithAttributes(attribute.String(attrDirection, "received")))
	m.duration.Record(ctx, d.Seconds())
	if origin := r.outcome.resetOrigin(); origin != "" {
		m.resets.Add(ctx, 1, metric.WithAttributes(attribute.String(attrOrigin, origin)))
	}
}

func (m *pipeMetrics) drained() { m.drains.Add(context.Background(), 1) }

func (m *pipeMetrics) keysLoaded(n int) { m.keyLoads.Add(context.Background(), int64(n)) }

// closeReason is how an outcome reads in the shared close vocabulary.
func (o outcome) closeReason() pb.RawCloseReason {
	switch o {
	case outcomeCompleted:
		return pb.RawCloseReason_RAW_CLOSE_REASON_COMPLETED
	case outcomeCallerAborted:
		return pb.RawCloseReason_RAW_CLOSE_REASON_CANCELLED
	case outcomeUpstreamAborted:
		return pb.RawCloseReason_RAW_CLOSE_REASON_UPSTREAM_ERROR
	case outcomeMaxLifetime:
		return pb.RawCloseReason_RAW_CLOSE_REASON_MAX_LIFETIME
	case outcomeIdleTimeout:
		return pb.RawCloseReason_RAW_CLOSE_REASON_IDLE_TIMEOUT
	case outcomeTunnelUnavailable:
		return pb.RawCloseReason_RAW_CLOSE_REASON_TUNNEL_LOST
	default:
		return pb.RawCloseReason_RAW_CLOSE_REASON_UNSPECIFIED
	}
}

// resetOrigin is which side reset a pipe that ended in a reset: the caller,
// the destination, or the connector enforcing a limit. It is "" for a pipe
// that completed or lost its tunnel.
func (o outcome) resetOrigin() string {
	switch o {
	case outcomeCallerAborted:
		return "caller"
	case outcomeUpstreamAborted:
		return "destination"
	case outcomeMaxLifetime, outcomeIdleTimeout:
		return "connector"
	default:
		return ""
	}
}

// closeReasonName is a close reason as a metric value: the enum name,
// lower-cased, without its prefix, like ReasonName.
func closeReasonName(r pb.RawCloseReason) string {
	return lowerName(r.String(), "RAW_CLOSE_REASON_")
}
