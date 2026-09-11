package client

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/InteractionLabs/traversal-connector/connector-lib/connector"
	pb "github.com/InteractionLabs/traversal-connector/connector-lib/gen/connector/v1"
	"github.com/InteractionLabs/traversal-connector/internal/config"
	"github.com/InteractionLabs/traversal-connector/internal/executor"
	"github.com/InteractionLabs/traversal-connector/internal/redact"
)

// queryCanary appears only inside a request's path and query, so finding it
// anywhere in exported telemetry names a path that carries caller data.
const queryCanary = "canary-3e5d80fa2c"

func canaryURL(base string) string {
	return base + "/orders/" + queryCanary + "?token=" + queryCanary
}

// newTelemetryTestManager builds a manager whose spans are recorded and whose
// executor is real, so a request travels the same path it does in production.
func newTelemetryTestManager(
	t *testing.T,
	timeout time.Duration,
) (*ConnectionManager, *tracetest.SpanRecorder) {
	t.Helper()

	cfg := &config.Config{
		MaxConcurrentRequests: 10,
		RequestTimeout:        timeout,
		MaxRequestBodySizeMB:  32,
	}
	exec, err := executor.NewExecutor(cfg, redact.NewRedactor())
	if err != nil {
		t.Fatalf("NewExecutor() failed: %v", err)
	}

	recorder := tracetest.NewSpanRecorder()
	provider := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder))
	t.Cleanup(func() {
		if err := provider.Shutdown(context.Background()); err != nil {
			t.Errorf("shutting down span provider: %v", err)
		}
	})

	return &ConnectionManager{
		config:   cfg,
		executor: exec,
		tracer:   provider.Tracer("test"),
		hostname: "test-host",
	}, recorder
}

// spanText renders everything a span carries off the process. RecordError
// reports through an event, so attributes alone would not show an error message.
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

// assertCorrelatable checks the span still names both the destination and the
// request it belongs to. Stripping the URL must not leave a span nothing can be
// traced back to.
func assertCorrelatable(t *testing.T, spans []sdktrace.ReadOnlySpan, requestID string) {
	t.Helper()
	if len(spans) == 0 {
		t.Fatal("no spans recorded")
	}

	found := map[string]string{}
	for _, span := range spans {
		for _, attr := range span.Attributes() {
			found[string(attr.Key)] = attr.Value.String()
		}
	}

	if got := found[connector.AttrTargetHost]; got == "" || got == "unknown" {
		t.Errorf("span does not name the destination host, got %q", got)
	}
	if got := found[connector.AttrRequestID]; got != requestID {
		t.Errorf("span request id = %q, want %q", got, requestID)
	}
}

func TestHandleMessage_HTTPRequestSuccessKeepsRequestPathOutOfTelemetry(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	const reqID = "req-success"
	cm, spans := newTelemetryTestManager(t, 5*time.Second)
	logs := captureLogs(t)
	sender := &mockSender{}

	msg := &pb.ControllerMessage{
		RequestId: reqID,
		Message: &pb.ControllerMessage_HttpRequest{
			HttpRequest: &pb.HttpRequest{
				Method: "GET",
				Url:    canaryURL(server.URL),
			},
		},
	}

	if err := cm.handleMessage(context.Background(), sender, uuid.New(), msg); err != nil {
		t.Fatalf("handleMessage() = %v", err)
	}

	assertNoCanary(t, "span", spanText(spans.Ended()))
	assertNoCanary(t, "log", logs.text())
	assertCorrelatable(t, spans.Ended(), reqID)
}

// The transport reports an unreachable upstream with the whole URL inside its
// own message, and this is the record an operator actually reads.
func TestHandleMessage_HTTPRequestFailureKeepsRequestPathOutOfTelemetry(t *testing.T) {
	const reqID = "req-unreachable"
	cm, spans := newTelemetryTestManager(t, 2*time.Second)
	logs := captureLogs(t)
	sender := &mockSender{}

	// Port 1 refuses the connection, so the transport fails before any exchange.
	msg := &pb.ControllerMessage{
		RequestId: reqID,
		Message: &pb.ControllerMessage_HttpRequest{
			HttpRequest: &pb.HttpRequest{
				Method: "GET",
				Url:    canaryURL("http://127.0.0.1:1"),
			},
		},
	}

	if err := cm.handleMessage(context.Background(), sender, uuid.New(), msg); err != nil {
		t.Fatalf("handleMessage() = %v", err)
	}

	assertNoCanary(t, "span", spanText(spans.Ended()))
	assertNoCanary(t, "log", logs.text())
	assertCorrelatable(t, spans.Ended(), reqID)

	// The control plane issued this URL, so the reply it receives still names it.
	errResp := sender.sent.GetErrorResponse()
	if errResp == nil {
		t.Fatalf("expected an ErrorResponse, got %T", sender.sent.Message)
	}
	if !strings.Contains(errResp.Message, queryCanary) {
		t.Errorf("tunnel error no longer names the requested URL: %q", errResp.Message)
	}
}

func TestHandleMessage_InvalidHTTPRequestKeepsRequestPathOutOfTelemetry(t *testing.T) {
	const reqID = "req-invalid"
	cm, spans := newTelemetryTestManager(t, 5*time.Second)
	logs := captureLogs(t)
	sender := &mockSender{}

	// A relative target fails the request's own URI constraint before execution.
	msg := &pb.ControllerMessage{
		RequestId: reqID,
		Message: &pb.ControllerMessage_HttpRequest{
			HttpRequest: &pb.HttpRequest{
				Method: "GET",
				Url:    "/orders/" + queryCanary + "?token=" + queryCanary,
			},
		},
	}

	if err := cm.handleMessage(context.Background(), sender, uuid.New(), msg); err != nil {
		t.Fatalf("handleMessage() = %v", err)
	}

	if sender.sent.GetErrorResponse() == nil {
		t.Fatalf("expected an ErrorResponse, got %T", sender.sent.Message)
	}

	assertNoCanary(t, "span", spanText(spans.Ended()))
	assertNoCanary(t, "log", logs.text())
}
