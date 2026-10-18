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
		err := client.respond(context.Background(), resp, time.Now(), "h:443", "h", true)
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

// TestRedactionConcurrency: with TRAVERSAL_REDACTION_MAX_CONCURRENT at 1, a
// covered response holds the connector's one slot until its redacted body is
// closed. A second one waits for it and is served once it comes free; one
// that waits past its request timeout is refused for capacity, counted, and
// sent nothing of its body. Every slot is given back.
func TestRedactionConcurrency(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	previous := otel.GetMeterProvider()
	otel.SetMeterProvider(sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader)))
	t.Cleanup(func() { otel.SetMeterProvider(previous) })
	r := redact.NewRedactor()
	if err := r.Update(&redact.RulesFile{Version: "v1", Rules: []redact.Rule{
		{Name: "email", Type: "regex", Pattern: `[a-z]+@[a-z.]+`, Replacement: "[REDACTED]"},
	}}); err != nil {
		t.Fatal(err)
	}
	const timeout = 200 * time.Millisecond
	client, err := New(&config.Config{RequestTimeout: timeout, MaxConcurrentRedactions: 1},
		r, nil)
	if err != nil {
		t.Fatal(err)
	}
	body := func() io.ReadCloser {
		return io.NopCloser(strings.NewReader("contact user@example.com"))
	}
	text := func() http.Header { return http.Header{"Content-Type": {"text/plain"}} }
	respond := func(resp *http.Response) error {
		return client.respond(context.Background(), resp, time.Now(), "h:443", "h", true)
	}
	served := func(resp *http.Response) {
		t.Helper()
		body, _ := io.ReadAll(resp.Body)
		if err := resp.Body.Close(); err != nil {
			t.Fatal(err)
		}
		if string(body) != "contact [REDACTED]" {
			t.Fatalf("served %q", body)
		}
	}

	first := &http.Response{StatusCode: 200, Header: text(), Body: body()}
	if err := respond(first); err != nil {
		t.Fatal(err)
	}
	// The slot is full, and stays so past the second's timeout.
	refused := &http.Response{StatusCode: 200, Header: text(), Body: body()}
	err = respond(refused)
	_ = refused.Body.Close()
	if rawpipe.ReasonOf(err, "") != rawpipe.Capacity {
		t.Fatalf("a response past its wait: %v, want capacity", err)
	}
	if strings.Contains(err.Error(), "user@example.com") {
		t.Fatalf("the refusal carries the body: %v", err)
	}
	if n := refusals(t, reader, refusalCapacity); n != 1 {
		t.Fatalf("capacity refusals counted %d times", n)
	}

	// A second response waits for the slot, and is served once it is free.
	waiting := &http.Response{StatusCode: 200, Header: text(), Body: body()}
	done := make(chan error, 1)
	go func() { done <- respond(waiting) }()
	select {
	case err := <-done:
		t.Fatalf("a second response did not wait for the slot: %v", err)
	case <-time.After(timeout / 4):
	}
	served(first)
	if err := <-done; err != nil {
		t.Fatalf("the waiting response, once the slot came free: %v", err)
	}
	served(waiting)
	if n := len(client.redactions); n != 0 {
		t.Fatalf("%d redaction slots still held", n)
	}
}
