package executor

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"

	"github.com/InteractionLabs/traversal-connector/connector-lib/connector"
	pb "github.com/InteractionLabs/traversal-connector/connector-lib/gen/connector/v1"
	"github.com/InteractionLabs/traversal-connector/internal/config"
	"github.com/InteractionLabs/traversal-connector/internal/redact"
	"github.com/InteractionLabs/traversal-connector/internal/telemetry"
)

const (
	// InstrumentationName is the OTel tracer name for the HTTP executor.
	InstrumentationName = "traversal-connector/executor"

	bytesPerKB = 1024
	kbPerMB    = 1024
)

// Executor handles executing HTTP requests against upstream services
// within the customer network on behalf of the Traversal control plane.
type Executor struct {
	client                  *http.Client
	maxRequestBodySizeBytes int64
	tracer                  trace.Tracer
	metrics                 *executorMetrics
	redactor                *redact.Redactor
}

// NewExecutor creates a new HTTP executor with the given configuration.
func NewExecutor(cfg *config.Config, r *redact.Redactor) (*Executor, error) {
	metrics, err := initExecutorMetrics()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize executor metrics: %w", err)
	}

	// gosec G402 flags any tls.Config where InsecureSkipVerify could be true at
	// runtime — there is no way to set this field conditionally without triggering
	// the rule. Skipping verification is intentional and explicitly opt-in via
	// UPSTREAM_TLS_VERIFY=false; the secure default is true (always verify).
	tlsConfig := &tls.Config{
		InsecureSkipVerify: !cfg.UpstreamTLSVerify, //nolint:gosec
	}

	// If a custom CA is provided, use it for validating upstream certificates
	if cfg.UpstreamTLSCA != nil && *cfg.UpstreamTLSCA != "" {
		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM([]byte(*cfg.UpstreamTLSCA)) {
			return nil, errors.New("failed to parse upstream CA certificate")
		}
		tlsConfig.RootCAs = caCertPool
	}

	httpClient := &http.Client{
		Timeout: cfg.RequestTimeout,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	return &Executor{
		client:                  httpClient,
		maxRequestBodySizeBytes: cfg.MaxRequestBodySizeMB * bytesPerKB * kbPerMB,
		tracer:                  otel.Tracer(InstrumentationName),
		metrics:                 metrics,
		redactor:                r,
	}, nil
}

// Execute converts a protobuf HttpRequest into a real HTTP request, executes it
// against the upstream service, and returns the response as a protobuf HttpResponse.
// On failure (invalid URL, network error, timeout, etc.) it returns an error.
func (e *Executor) Execute(
	ctx context.Context,
	protoReq *pb.HttpRequest,
) (*pb.HttpResponse, error) {
	startTime := time.Now()

	targetHost := hostFromURL(protoReq.Url)
	requestStatus := connector.StatusError
	defer func() {
		duration := float64(
			time.Since(startTime).Milliseconds(),
		)
		attrs := metric.WithAttributes(
			attribute.String(connector.AttrStatus, requestStatus),
			attribute.String(connector.AttrTargetHost, targetHost),
		)
		e.metrics.upstreamRequestsTotal.Add(ctx, 1, attrs)
		e.metrics.upstreamLatency.Record(ctx, duration, attrs)
	}()

	ctx, span := e.tracer.Start(ctx, telemetry.SpanExecutorUpstreamHTTP,
		trace.WithAttributes(
			attribute.String(connector.AttrTargetHost, targetHost),
			attribute.String(connector.AttrMethod, protoReq.Method),
		),
	)
	defer span.End()

	// Record request body size.
	e.metrics.upstreamRequestBodySizeBytes.Record(ctx, int64(len(protoReq.Body)),
		metric.WithAttributes(attribute.String(connector.AttrTargetHost, targetHost)))

	slog.DebugContext(ctx, "executing upstream HTTP request",
		"method", protoReq.Method,
		"target_host", targetHost)

	// Validate the target URL.
	if err := connector.ValidateTargetURL(protoReq.Url); err != nil {
		span.RecordError(err)
		slog.ErrorContext(ctx, "upstream request failed: invalid URL",
			"error", err,
			"url", protoReq.Url)
		return nil, fmt.Errorf("invalid target URL: %w", err)
	}

	// Enforce request body size limit.
	if e.maxRequestBodySizeBytes > 0 && int64(len(protoReq.Body)) > e.maxRequestBodySizeBytes {
		bodySizeErr := fmt.Errorf(
			"body size %d exceeds limit %d",
			len(protoReq.Body),
			e.maxRequestBodySizeBytes,
		)
		span.RecordError(bodySizeErr)
		e.metrics.requestBodySizeLimitHit.Add(ctx, 1)
		slog.WarnContext(ctx, "upstream request failed: body too large",
			"body_size", len(protoReq.Body),
			"max_size", e.maxRequestBodySizeBytes,
			"url", protoReq.Url)
		return nil, fmt.Errorf(
			"request body size %d exceeds limit %d",
			len(protoReq.Body),
			e.maxRequestBodySizeBytes,
		)
	}

	// Build the HTTP request body.
	var body io.Reader
	if len(protoReq.Body) > 0 {
		body = bytes.NewReader(protoReq.Body)
	}

	httpReq, err := http.NewRequestWithContext(ctx, protoReq.Method, protoReq.Url, body)
	if err != nil {
		span.RecordError(err)
		slog.ErrorContext(ctx, "upstream request failed: cannot create request",
			"error", err,
			"url", protoReq.Url)
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	// Convert protobuf headers to HTTP headers, filtering hop-by-hop.
	filtered := connector.FilterHopByHopHeaders(protoReq.Headers)
	httpHeaders := connector.ProtoToHTTPHeaders(filtered)
	httpReq.Header = httpHeaders

	// Execute the HTTP request.
	resp, err := e.client.Do(httpReq)
	if err != nil {
		span.RecordError(err)
		duration := time.Since(startTime)
		slog.ErrorContext(ctx, "upstream request failed",
			"error", err,
			"target_host", targetHost,
			"duration_ms", duration.Milliseconds())
		return nil, fmt.Errorf("upstream request failed: %w", err)
	}
	defer resp.Body.Close()

	// Read the response body.
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		span.RecordError(err)
		duration := time.Since(startTime)
		slog.ErrorContext(ctx, "upstream request failed: cannot read response body",
			"error", err,
			"target_host", targetHost,
			"duration_ms", duration.Milliseconds())
		return nil, fmt.Errorf("failed to read upstream response body: %w", err)
	}

	// Apply redaction rules to the response body before it leaves the customer network.
	respBody = e.redactor.Apply(respBody)

	// Convert response headers to protobuf, filtering hop-by-hop.
	respHeaders := connector.HTTPToProtoHeaders(resp.Header)
	respHeaders = connector.FilterHopByHopHeaders(respHeaders)

	// Record response body size.
	e.metrics.upstreamResponseBodySizeBytes.Record(ctx, int64(len(respBody)),
		metric.WithAttributes(attribute.String(connector.AttrTargetHost, targetHost)))

	requestStatus = connector.StatusSuccess
	span.SetAttributes(attribute.Int(connector.AttrHTTPStatusCode, resp.StatusCode))

	duration := time.Since(startTime)
	slog.InfoContext(ctx, "upstream request completed",
		"target_host", targetHost,
		"status", resp.StatusCode,
		"duration_ms", duration.Milliseconds(),
		"response_body_size", len(respBody))

	return &pb.HttpResponse{
		HttpStatus: int32( //nolint:gosec // HTTP status codes are always in the int32 range
			resp.StatusCode,
		),
		Headers: respHeaders,
		Body:    respBody,
	}, nil
}
