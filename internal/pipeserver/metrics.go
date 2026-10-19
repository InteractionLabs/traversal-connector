package pipeserver

import (
	"context"
	"errors"
	"net/netip"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/InteractionLabs/traversal-connector/connector-lib/capability"
	"github.com/InteractionLabs/traversal-connector/connector-lib/halfconn"
	"github.com/InteractionLabs/traversal-connector/connector-lib/rawpipe"
	"github.com/InteractionLabs/traversal-connector/internal/telemetry"
	"github.com/InteractionLabs/traversal-connector/internal/upstream"
)

// InstrumentationName is the OTel meter name for raw pipes.
const InstrumentationName = "traversal-connector/pipeserver"

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
		metric.WithDescription(
			"Raw pipe opens, by outcome: opened, the refusal reason, or accept_failed"))
	m.pipes, errs[3] = meter.Int64UpDownCounter(telemetry.MetricRawPipes,
		metric.WithDescription("Raw pipes open now"))
	m.ends, errs[4] = meter.Int64Counter(telemetry.MetricRawPipeEndTotal,
		metric.WithDescription("Raw pipes ended, by outcome"))
	m.bytes, errs[5] = meter.Int64Counter(telemetry.MetricRawPipeBytes, metric.WithUnit("By"),
		metric.WithDescription("Raw pipe bytes, by direction"))
	return &m, errors.Join(errs[:]...)
}

// countProxyDials wraps dial, which reaches destinations through the egress
// proxy, to count each dial handed to the proxy in
// connector.egress_proxy_unresolved_dial_total by target_kind: hostname, which
// the proxy resolves past the connector's address floor, or ip. A dial the
// dial policy refuses never reaches the proxy and is not counted.
func countProxyDials(dial upstream.Dialer) (upstream.Dialer, error) {
	dials, err := otel.Meter(InstrumentationName).Int64Counter(
		telemetry.MetricEgressProxyUnresolvedDialTotal,
		metric.WithDescription("Dials handed to the egress proxy, by target_kind: "+
			"hostname (the proxy resolves it) or ip"))
	if err != nil {
		return nil, err
	}
	hostname, ip := metric.WithAttributes(attribute.String("target_kind", "hostname")),
		metric.WithAttributes(attribute.String("target_kind", "ip"))
	return func(ctx context.Context, host string, port uint16) (halfconn.Conn, string, error) {
		conn, via, err := dial(ctx, host, port)
		if rawpipe.ReasonOf(err, "") != rawpipe.ForbiddenAddress {
			kind := hostname
			if _, parseErr := netip.ParseAddr(host); parseErr == nil {
				kind = ip
			}
			dials.Add(ctx, 1, kind)
		}
		return conn, via, err
	}, nil
}

// observeTrust reports the capability trust the connector has loaded, one
// series per root fingerprint and per kid, so the fleet's trust can be read
// before a signing change relies on it.
func observeTrust(t capability.Loaded) error {
	_, err := otel.Meter(InstrumentationName).Int64ObservableGauge(
		telemetry.MetricCapabilityTrust,
		metric.WithDescription("Capability roots (by fingerprint) and pinned kids loaded; always 1"),
		metric.WithInt64Callback(func(_ context.Context, o metric.Int64Observer) error {
			for kind, ids := range map[string][]string{"root": t.Roots, "kid": t.Kids} {
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

// acceptFailed records the open of a pipe admitted whose stream could not be
// accepted, so no refusal reason reached the edge controller.
func (m *metrics) acceptFailed() {
	m.opens.Add(context.Background(), 1, outcome("accept_failed"))
}

func (m *metrics) ended(sent, received int64, o halfconn.Outcome) {
	ctx := context.Background()
	m.ends.Add(ctx, 1, outcome(string(o)))
	m.bytes.Add(ctx, sent, metric.WithAttributes(attribute.String("direction", "sent")))
	m.bytes.Add(ctx, received, metric.WithAttributes(attribute.String("direction", "received")))
}
