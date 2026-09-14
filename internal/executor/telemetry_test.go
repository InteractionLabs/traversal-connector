package executor

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/InteractionLabs/traversal-connector/connector-lib/connector"
	pb "github.com/InteractionLabs/traversal-connector/connector-lib/gen/connector/v1"
	"github.com/InteractionLabs/traversal-connector/internal/redact"
)

// queryCanary appears only inside a request's query string, so finding it
// anywhere in exported telemetry names a path that carries caller data.
// Asserting on its absence is what makes these tests meaningful: asserting that
// the host is present would still pass while a second copy of the URL travelled
// somewhere else.
const queryCanary = "canary-7f2c9ab41d"

// canaryURL builds a request target whose path and query both hold the canary.
func canaryURL(base string) string {
	return base + "/orders/" + queryCanary + "?token=" + queryCanary
}

// captureSpans routes the executor's spans into a recorder. The tracer is
// replaced directly rather than through the global provider so tests stay
// independent of each other.
func captureSpans(t *testing.T, exec *Executor) *tracetest.SpanRecorder {
	t.Helper()
	recorder := tracetest.NewSpanRecorder()
	provider := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder))
	t.Cleanup(func() {
		if err := provider.Shutdown(context.Background()); err != nil {
			t.Errorf("shutting down span provider: %v", err)
		}
	})
	exec.tracer = provider.Tracer("test")
	return recorder
}

// spanText renders everything a span carries off the process: its name, its
// attributes, and its events. RecordError reports through an event, so a span's
// attributes alone would not show an error message.
func spanText(spans []sdktrace.ReadOnlySpan) string {
	var text strings.Builder
	for _, span := range spans {
		text.WriteString(span.Name())
		for _, attr := range span.Attributes() {
			text.WriteString(" " + string(attr.Key) + "=" + attr.Value.String())
		}
		text.WriteString(" status=" + span.Status().Description)
		for _, event := range span.Events() {
			text.WriteString(" event:" + event.Name)
			for _, attr := range event.Attributes {
				text.WriteString(" " + string(attr.Key) + "=" + attr.Value.String())
			}
		}
		text.WriteString("\n")
	}
	return text.String()
}

// logCapture keeps every record emitted while it is installed. The OTLP log
// exporter is fed from these same records, so what lands here is what would be
// shipped.
type logCapture struct {
	mu      sync.Mutex
	records []string
}

func (c *logCapture) Enabled(context.Context, slog.Level) bool { return true }

func (c *logCapture) Handle(_ context.Context, record slog.Record) error {
	text := record.Message
	record.Attrs(func(attr slog.Attr) bool {
		text += " " + attr.Key + "=" + attr.Value.Resolve().String()
		return true
	})

	c.mu.Lock()
	defer c.mu.Unlock()
	c.records = append(c.records, text)
	return nil
}

func (c *logCapture) WithAttrs([]slog.Attr) slog.Handler { return c }

func (c *logCapture) WithGroup(string) slog.Handler { return c }

func (c *logCapture) text() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return strings.Join(c.records, "\n")
}

// captureLogs redirects the default logger, which is what the package-level slog
// calls under test write to.
func captureLogs(t *testing.T) *logCapture {
	t.Helper()
	capture := &logCapture{}
	previous := slog.Default()
	slog.SetDefault(slog.New(capture))
	t.Cleanup(func() { slog.SetDefault(previous) })
	return capture
}

func assertNoCanary(t *testing.T, subject, text string) {
	t.Helper()
	if strings.Contains(text, queryCanary) {
		t.Errorf("%s carries the request path or query:\n%s", subject, text)
	}
}

func assertHasTargetHost(t *testing.T, spans []sdktrace.ReadOnlySpan) {
	t.Helper()
	if len(spans) == 0 {
		t.Fatal("no spans recorded")
	}
	for _, span := range spans {
		for _, attr := range span.Attributes() {
			if string(attr.Key) == connector.AttrTargetHost && attr.Value.String() != "" {
				return
			}
		}
	}
	t.Errorf("no span names the destination host:\n%s", spanText(spans))
}

func TestExecute_SuccessKeepsRequestPathOutOfTelemetry(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer server.Close()

	exec := newTestExecutor(t, 5*time.Second, 32)
	spans := captureSpans(t, exec)
	logs := captureLogs(t)

	if _, err := exec.Execute(context.Background(), &pb.HttpRequest{
		Method: "GET",
		Url:    canaryURL(server.URL),
	}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	assertNoCanary(t, "span", spanText(spans.Ended()))
	assertNoCanary(t, "log", logs.text())
	assertHasTargetHost(t, spans.Ended())
}

// An unreachable upstream is the case that matters most: the transport reports
// the failure with the whole URL inside its own message, and an operator reads
// exactly these records.
func TestExecute_UnreachableUpstreamKeepsRequestPathOutOfTelemetry(t *testing.T) {
	exec := newTestExecutor(t, 2*time.Second, 32)
	spans := captureSpans(t, exec)
	logs := captureLogs(t)

	// Port 1 refuses the connection, so the transport fails before any exchange.
	_, err := exec.Execute(context.Background(), &pb.HttpRequest{
		Method: "GET",
		Url:    canaryURL("http://127.0.0.1:1"),
	})
	if err == nil {
		t.Fatal("expected an error from an unreachable upstream")
	}

	assertNoCanary(t, "span", spanText(spans.Ended()))
	assertNoCanary(t, "log", logs.text())
	assertHasTargetHost(t, spans.Ended())

	// The control plane issued this URL, so its own copy of the failure keeps it.
	if !strings.Contains(err.Error(), queryCanary) {
		t.Errorf("returned error no longer names the requested URL: %v", err)
	}
}

func TestExecute_TimeoutKeepsRequestPathOutOfTelemetry(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(500 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	exec := newTestExecutor(t, 100*time.Millisecond, 32)
	spans := captureSpans(t, exec)
	logs := captureLogs(t)

	_, err := exec.Execute(context.Background(), &pb.HttpRequest{
		Method: "GET",
		Url:    canaryURL(server.URL),
	})
	if err == nil {
		t.Fatal("expected a timeout error")
	}

	assertNoCanary(t, "span", spanText(spans.Ended()))
	assertNoCanary(t, "log", logs.text())
}

// A target that url.Parse rejects is reported as a *url.Error too, and its
// message quotes the URL in escaped form rather than verbatim.
func TestExecute_UnparseableURLKeepsRequestPathOutOfTelemetry(t *testing.T) {
	exec := newTestExecutor(t, 5*time.Second, 32)
	spans := captureSpans(t, exec)
	logs := captureLogs(t)

	_, err := exec.Execute(context.Background(), &pb.HttpRequest{
		Method: "GET",
		Url:    "http://127.0.0.1:1/\x7f?token=" + queryCanary,
	})
	if err == nil {
		t.Fatal("expected an error for an unparseable URL")
	}

	assertNoCanary(t, "span", spanText(spans.Ended()))
	assertNoCanary(t, "log", logs.text())
}

// A refused response reports through errors the connector builds itself, on the
// span and in the log. They carry no URL today and are reduced anyway, so a
// later change that routes a URL-bearing error through here cannot quietly
// undo this.
func TestExecute_RefusedResponseKeepsRequestPathOutOfTelemetry(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Encoding", "br")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"email":"someone@example.com"}`))
	}))
	defer server.Close()

	exec := newExecutor(t, responseTestConfig(), newRedactor(t, emailRule()))
	spans := captureSpans(t, exec)
	logs := captureLogs(t)

	// A coding the connector cannot decode cannot be scanned, so it is dropped.
	_, err := exec.Execute(context.Background(), &pb.HttpRequest{
		Method: "GET",
		Url:    canaryURL(server.URL),
	})
	if err == nil {
		t.Fatal("expected an unscannable response to be refused")
	}

	assertNoCanary(t, "span", spanText(spans.Ended()))
	assertNoCanary(t, "log", logs.text())
}

// The per-field redaction path reports a body it could not parse. Whether such a
// response is forwarded or dropped is decided elsewhere, so only the exported
// records are asserted here.
//
// The rule has to be a structured one: the per-field pass filters to those, and
// with none in scope it returns before ever parsing the body.
func TestExecute_UnparseableJSONBodyKeepsRequestPathOutOfTelemetry(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"email": "someone@example.com"`))
	}))
	defer server.Close()

	exec := newExecutor(t, responseTestConfig(), newRedactor(t, redact.Rule{
		Name:         "email",
		Type:         "regex-structured-data",
		Pattern:      emailPattern,
		Replacement:  "[REDACTED]",
		RedactFields: []string{"email"},
	}))
	spans := captureSpans(t, exec)
	logs := captureLogs(t)

	_, _ = exec.Execute(context.Background(), &pb.HttpRequest{
		Method: "GET",
		Url:    canaryURL(server.URL),
	})

	// Absence proves nothing about a branch that never ran, so confirm the parse
	// failure was reported before reading anything into the assertions below.
	//
	// Either report will do. Warning and applying the byte-level rules alone, and
	// dropping the response outright, are both honest answers to a body that
	// cannot be parsed, and which one the connector gives is decided elsewhere.
	// Accepting only one would pin this test to the mechanism in place when it was
	// written rather than to the invariant it exists for.
	reports := []string{
		"structured rules skipped", // warned, remaining rules applied
		"reason=malformed_json",    // refused, response dropped
	}
	logText := logs.text()
	reported := slices.ContainsFunc(reports, func(report string) bool {
		return strings.Contains(logText, report)
	})
	if !reported {
		t.Fatalf("per-field parse failure went unreported as any of %q, "+
			"so this test is vacuous:\n%s", reports, logText)
	}

	assertNoCanary(t, "span", spanText(spans.Ended()))
	assertNoCanary(t, "log", logs.text())
}

func TestExecute_BodyTooLargeKeepsRequestPathOutOfTelemetry(t *testing.T) {
	exec := newTestExecutor(t, 5*time.Second, 1)
	spans := captureSpans(t, exec)
	logs := captureLogs(t)

	_, err := exec.Execute(context.Background(), &pb.HttpRequest{
		Method: "POST",
		Url:    canaryURL("https://example.com"),
		Body:   make([]byte, 1024*1024+1),
	})
	if err == nil {
		t.Fatal("expected a body size error")
	}

	assertNoCanary(t, "span", spanText(spans.Ended()))
	assertNoCanary(t, "log", logs.text())
}
