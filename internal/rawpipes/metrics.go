package rawpipes

import (
	"context"
	"errors"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/InteractionLabs/traversal-connector/connector-lib/halfconn"
	"github.com/InteractionLabs/traversal-connector/connector-lib/rawpipe"
	"github.com/InteractionLabs/traversal-connector/internal/telemetry"
)

// InstrumentationName is the OTel meter name for raw pipes.
const InstrumentationName = "traversal-connector/rawpipes"

// metrics are the raw pipe side's measurements. Labels are closed sets: the
// rawpipe refusal reasons, the pipe outcomes, and a few dial results.
type metrics struct {
	tunnelsUp metric.Int64UpDownCounter
	dials     metric.Int64Counter
	opens     metric.Int64Counter
	pipes     metric.Int64UpDownCounter
	ends      metric.Int64Counter
	bytes     metric.Int64Counter
}

func newMetrics() (*metrics, error) {
	meter := otel.Meter(InstrumentationName)
	var m metrics
	var errs [6]error
	m.tunnelsUp, errs[0] = meter.Int64UpDownCounter(telemetry.MetricRawTunnelsUp,
		metric.WithDescription("Raw-pipe tunnels to Traversal held now"))
	m.dials, errs[1] = meter.Int64Counter(telemetry.MetricRawTunnelDialTotal,
		metric.WithDescription("Raw-pipe tunnel dials, by result"))
	m.opens, errs[2] = meter.Int64Counter(telemetry.MetricRawPipeOpenTotal,
		metric.WithDescription("Raw pipe opens, by outcome: opened or the refusal reason"))
	m.pipes, errs[3] = meter.Int64UpDownCounter(telemetry.MetricRawPipes,
		metric.WithDescription("Raw pipes open now"))
	m.ends, errs[4] = meter.Int64Counter(telemetry.MetricRawPipeEndTotal,
		metric.WithDescription("Raw pipes ended, by outcome"))
	m.bytes, errs[5] = meter.Int64Counter(telemetry.MetricRawPipeBytes, metric.WithUnit("By"),
		metric.WithDescription("Raw pipe bytes, by direction"))
	return &m, errors.Join(errs[:]...)
}

// observeTrust reports the capability trust the connector has loaded, one
// series per root fingerprint and per kid, so the fleet's trust can be read
// before a signing change relies on it.
func observeTrust(t trust) error {
	_, err := otel.Meter(InstrumentationName).Int64ObservableGauge(
		telemetry.MetricCapabilityTrust,
		metric.WithDescription("Capability roots (by fingerprint) and pinned kids loaded; always 1"),
		metric.WithInt64Callback(func(_ context.Context, o metric.Int64Observer) error {
			for kind, ids := range map[string][]string{"root": t.roots, "kid": t.kids} {
				for _, id := range ids {
					o.Observe(1, metric.WithAttributes(attribute.String("kind", kind),
						attribute.String("id", id)))
				}
			}
			return nil
		}))
	return err
}

func outcome(o string) metric.MeasurementOption {
	return metric.WithAttributes(attribute.String("outcome", o))
}

func (m *metrics) tunnel(delta int64) { m.tunnelsUp.Add(context.Background(), delta) }

// dialed records a dial: connected, replaced (the edge controller asked for
// a new tunnel), or failed.
func (m *metrics) dialed(result string) {
	m.dials.Add(context.Background(), 1, outcome(result))
}

func (m *metrics) opened(reason rawpipe.Reason) {
	o := "opened"
	if reason != "" {
		o = string(reason)
	}
	m.opens.Add(context.Background(), 1, outcome(o))
}

func (m *metrics) pipe(delta int64) { m.pipes.Add(context.Background(), delta) }

func (m *metrics) ended(sent, received int64, o halfconn.Outcome) {
	ctx := context.Background()
	m.ends.Add(ctx, 1, outcome(string(o)))
	m.bytes.Add(ctx, sent, metric.WithAttributes(attribute.String("direction", "sent")))
	m.bytes.Add(ctx, received, metric.WithAttributes(attribute.String("direction", "received")))
}
