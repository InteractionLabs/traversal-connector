package client

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"google.golang.org/protobuf/proto"

	"github.com/InteractionLabs/traversal-connector/connector-lib/connector"
	pb "github.com/InteractionLabs/traversal-connector/connector-lib/gen/connector/v1"
	"github.com/InteractionLabs/traversal-connector/internal/config"
	"github.com/InteractionLabs/traversal-connector/internal/executor"
	"github.com/InteractionLabs/traversal-connector/internal/redact"
	"github.com/InteractionLabs/traversal-connector/internal/telemetry"
)

// queryCanary appears only inside a request's path and query, so finding it
// anywhere in exported telemetry names a path that carries caller data.
const queryCanary = "canary-3e5d80fa2c"

func canaryURL(base string) string {
	return base + "/orders/" + queryCanary + "?token=" + queryCanary
}

// hostOf returns the authority a test server was bound to, which is what
// telemetry is expected to name.
func hostOf(t *testing.T, rawURL string) string {
	t.Helper()
	parsed, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parsing test server URL %q: %v", rawURL, err)
	}
	return parsed.Host
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
		// Pinned so these tests keep asserting the default keeps paths out.
		LogRequestDetails: telemetry.RequestDetailsOff,
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

// assertLogsCorrelatable checks the log stream still ties records back to one
// request. Records emitted below this layer correlate through the span context
// the bridge attaches; the identifier is asserted here because it is what an
// operator searches on.
func assertLogsCorrelatable(t *testing.T, logs *logCapture, requestID, targetHost string) {
	t.Helper()
	text := logs.text()
	if !strings.Contains(text, requestID) {
		t.Errorf("no log record names the request id %q:\n%s", requestID, text)
	}
	if !strings.Contains(text, targetHost) {
		t.Errorf("no log record names the destination host %q:\n%s", targetHost, text)
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
	assertLogsCorrelatable(t, logs, reqID, hostOf(t, server.URL))
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
	assertLogsCorrelatable(t, logs, reqID, "127.0.0.1:1")

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

// Every line logged while serving one request names its request id, including
// the executor's, which read it from the context.
func TestHandleMessage_EveryRequestLineCarriesRequestID(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	for name, base := range map[string]string{
		"success":     server.URL,
		"unreachable": "http://127.0.0.1:1",
	} {
		t.Run(name, func(t *testing.T) {
			const reqID = "req-every-line"
			cm, _ := newTelemetryTestManager(t, 2*time.Second)
			logs := captureLogs(t)

			msg := &pb.ControllerMessage{
				RequestId: reqID,
				Message: &pb.ControllerMessage_HttpRequest{
					HttpRequest: &pb.HttpRequest{Method: "GET", Url: canaryURL(base)},
				},
			}
			if err := cm.handleMessage(context.Background(), &mockSender{}, uuid.New(), msg); err != nil {
				t.Fatalf("handleMessage() = %v", err)
			}

			logs.mu.Lock()
			records := slices.Clone(logs.records)
			logs.mu.Unlock()
			// Header helpers in connector-lib log without request context, so
			// only the handler's and executor's own lines are checked.
			perRequest := []string{"received http request", "executing upstream",
				"upstream request", "sending error response"}
			checked := 0
			for _, record := range records {
				if !slices.ContainsFunc(perRequest, func(prefix string) bool {
					return strings.HasPrefix(record, prefix)
				}) {
					continue
				}
				checked++
				if !strings.Contains(record, "request_id="+reqID) ||
					!strings.Contains(record, "method=GET") {
					t.Errorf("record lacks request_id or method:\n%s", record)
				}
			}
			if checked < 3 {
				t.Errorf("expected handler and executor records, got:\n%s", logs.text())
			}
			assertNoCanary(t, "log", logs.text())
		})
	}
}

func TestHandleMessage_RequestDetailsFullOnHandlerLines(t *testing.T) {
	const reqID = "req-invalid-full"
	cm, _ := newTelemetryTestManager(t, 5*time.Second)
	cfg := *cm.config
	cfg.LogRequestDetails = telemetry.RequestDetailsFull
	exec, err := executor.NewExecutor(&cfg, redact.NewRedactor())
	if err != nil {
		t.Fatalf("NewExecutor() failed: %v", err)
	}
	cm.executor = exec
	logs := captureLogs(t)

	// A relative target fails validation, so only handler lines are logged.
	msg := &pb.ControllerMessage{
		RequestId: reqID,
		Message: &pb.ControllerMessage_HttpRequest{
			HttpRequest: &pb.HttpRequest{
				Method: "GET",
				Url:    "/orders/" + queryCanary + "?token=" + queryCanary,
			},
		},
	}
	if err := cm.handleMessage(context.Background(), &mockSender{}, uuid.New(), msg); err != nil {
		t.Fatalf("handleMessage() = %v", err)
	}

	text := logs.text()
	for _, want := range []string{
		"received invalid http request",
		"request_id=" + reqID,
		"target_path=/orders/" + queryCanary,
		"query_keys=[token]",
		"target_query=token=" + queryCanary,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("log lacks %q:\n%s", want, text)
		}
	}
}

type failingSender struct{}

func (failingSender) Send(*pb.ConnectorMessage) error {
	return errors.New("envelope too large")
}

func TestResponseSender_SendFailureLogsResponseSize(t *testing.T) {
	logs := captureLogs(t)
	ss := newResponseSender(failingSender{}, 1, nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		ss.run(ctx)
		close(done)
	}()

	msg := &pb.ConnectorMessage{
		RequestId: "req-oversized",
		Message: &pb.ConnectorMessage_HttpResponse{
			HttpResponse: &pb.HttpResponse{HttpStatus: 200, Body: make([]byte, 4096)},
		},
	}
	if err := ss.Send(msg); err != nil {
		t.Fatalf("Send() = %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for !strings.Contains(logs.text(), "stream send failed") && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done

	text := logs.text()
	for _, want := range []string{
		"request_id=req-oversized",
		"response_size=" + strconv.Itoa(proto.Size(msg)),
		"response_body_size=4096",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("log lacks %q:\n%s", want, text)
		}
	}
}
