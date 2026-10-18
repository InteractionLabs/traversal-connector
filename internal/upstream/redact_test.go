package upstream

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/InteractionLabs/traversal-connector/connector-lib/rawpipe"
	"github.com/InteractionLabs/traversal-connector/internal/config"
	"github.com/InteractionLabs/traversal-connector/internal/redact"
	"github.com/InteractionLabs/traversal-connector/internal/telemetry"
)

// TestRefusalReasons: each way a covered response cannot be redacted is
// refused as redaction_unsupported and counted under its own reason, which
// operators alert on.
func TestRefusalReasons(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	previous := otel.GetMeterProvider()
	otel.SetMeterProvider(sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader)))
	t.Cleanup(func() { otel.SetMeterProvider(previous) })
	r := redact.NewRedactor()
	if err := r.Update(&redact.RulesFile{Version: "v1", Rules: []redact.Rule{
		{Name: "email", Type: "regex", Pattern: `[a-z]+@[a-z.]+`},
	}}); err != nil {
		t.Fatal(err)
	}
	client, err := New(
		&config.Config{RequestTimeout: 50 * time.Millisecond, MaxResponseBodySizeMB: 1,
			MaxDecodedResponseBodySizeMB: 1},
		r,
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	endless, _ := io.Pipe()
	for _, c := range []struct {
		reason, contentType, encoding string
		body                          io.Reader
	}{
		{refusalNoEnd, "text/plain", "", endless},
		{refusalBodyTooLarge, "text/plain", "", strings.NewReader(strings.Repeat("a", 2<<20))},
		{refusalUnsupportedEncoding, "text/plain", "zstd", strings.NewReader("x")},
		{refusalDecodeFailed, "text/plain", "gzip", strings.NewReader("not gzip")},
		{refusalUnredactable, "application/grpc", "", strings.NewReader("x")},
	} {
		h := http.Header{"Content-Type": {c.contentType}}
		if c.encoding != "" {
			h.Set("Content-Encoding", c.encoding)
		}
		rc, ok := c.body.(io.ReadCloser)
		if !ok {
			rc = io.NopCloser(c.body)
		}
		resp := &http.Response{StatusCode: 200, Header: h, Body: rc}
		err := client.respond(context.Background(), resp, "h:443", "h", true)
		_ = resp.Body.Close()
		if rawpipe.ReasonOf(err, "") != rawpipe.RedactionUnsupported {
			t.Errorf("%s: %v, want redaction_unsupported", c.reason, err)
		}
		if n := refusals(t, reader, c.reason); n != 1 {
			t.Errorf("%s counted %d times", c.reason, n)
		}
	}
}

func refusals(t *testing.T, reader *sdkmetric.ManualReader, reason string) int64 {
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatal(err)
	}
	var n int64
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if sum, ok := m.Data.(metricdata.Sum[int64]); ok &&
				m.Name == telemetry.MetricResponseRefusalsTotal {
				for _, p := range sum.DataPoints {
					if v, _ := p.Attributes.Value(attrRefusalReason); v == attribute.StringValue(
						reason,
					) {
						n += p.Value
					}
				}
			}
		}
	}
	return n
}

// TestBufferedLimitsAreFinite: a client configured with no body limits still
// bounds the responses it buffers to redact; a request body, which streams,
// stays unlimited.
func TestBufferedLimitsAreFinite(t *testing.T) {
	client, err := New(&config.Config{}, redact.NewRedactor(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if client.maxRequest != 0 {
		t.Errorf("request limit %d, want none", client.maxRequest)
	}
	if want := int64(config.DefaultBodySizeMB) << 20; client.maxBody != want {
		t.Errorf("buffered response limit %d, want %d", client.maxBody, want)
	}
	if want := int64(config.DefaultDecodedBodySizeMB) << 20; client.maxDecoded != want {
		t.Errorf("decoded response limit %d, want %d", client.maxDecoded, want)
	}
}
