package telemetry

import (
	"context"

	"go.opentelemetry.io/otel/metric"
)

// NewObservableGauge reports value() as gauge name at every collection: one
// series, read when the reader asks rather than recorded as it changes, for
// a value that is a state (a count held elsewhere, a certificate's life).
func NewObservableGauge(
	meter metric.Meter,
	name string,
	value func() int64,
	opts ...metric.Int64ObservableGaugeOption,
) error {
	_, err := meter.Int64ObservableGauge(name, append(opts,
		metric.WithInt64Callback(func(_ context.Context, o metric.Int64Observer) error {
			o.Observe(value())
			return nil
		}))...)
	return err
}
