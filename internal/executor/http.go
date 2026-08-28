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
	"mime"
	"net/http"
	"strconv"
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

	headerContentLength   = "Content-Length"
	headerContentType     = "Content-Type"
	headerContentEncoding = "Content-Encoding"
	headerAcceptRanges    = "Accept-Ranges"
	// headerRedacted tells the SaaS side that the body it received is not the
	// body the upstream sent.
	headerRedacted = "X-Traversal-Redacted"
)

// Reasons a response was dropped rather than forwarded. The set is closed so the
// refusal counter stays cheap to alert on.
const (
	refusalUnsupportedEncoding = "unsupported_encoding"
	refusalPartialContent      = "partial_content"
	refusalBodyTooLarge        = "body_too_large"
	refusalDecodedTooLarge     = "decoded_too_large"
	refusalDecodeFailed        = "decode_failed"
)

// Executor handles executing HTTP requests against upstream services
// within the customer network on behalf of the Traversal control plane.
type Executor struct {
	client                          *http.Client
	maxRequestBodySizeBytes         int64
	maxResponseBodySizeBytes        int64
	maxDecodedResponseBodySizeBytes int64
	tracer                          trace.Tracer
	metrics                         *executorMetrics
	redactor                        *redact.Redactor
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
		client:                   httpClient,
		maxRequestBodySizeBytes:  cfg.MaxRequestBodySizeMB * bytesPerKB * kbPerMB,
		maxResponseBodySizeBytes: cfg.MaxResponseBodySizeMB * bytesPerKB * kbPerMB,
		maxDecodedResponseBodySizeBytes: cfg.MaxDecodedResponseBodySizeMB *
			bytesPerKB * kbPerMB,
		tracer:   otel.Tracer(InstrumentationName),
		metrics:  metrics,
		redactor: r,
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

	protoResp, err := e.buildResponse(ctx, resp, protoReq.Url, targetHost)
	if err != nil {
		span.RecordError(err)
		return nil, err
	}

	// Record response body size.
	e.metrics.upstreamResponseBodySizeBytes.Record(ctx, int64(len(protoResp.Body)),
		metric.WithAttributes(attribute.String(connector.AttrTargetHost, targetHost)))

	requestStatus = connector.StatusSuccess
	span.SetAttributes(attribute.Int(connector.AttrHTTPStatusCode, resp.StatusCode))

	duration := time.Since(startTime)
	slog.InfoContext(ctx, "upstream request completed",
		"target_host", targetHost,
		"status", resp.StatusCode,
		"duration_ms", duration.Milliseconds(),
		"response_body_size", len(protoResp.Body))

	return protoResp, nil
}

// buildResponse turns an upstream response into the one that leaves the customer
// network.
//
// The connector forwards the caller's Accept-Encoding unchanged, so Go's
// transport does not decompress on its own and the body arrives in whatever
// coding the upstream chose. Redacting it therefore means decoding it here:
// a regex over a deflate stream matches nothing and would ship the plaintext
// out intact.
//
// Every decision is made against what the upstream actually returned rather
// than what the request predicted, and a body the connector cannot scan is
// dropped rather than forwarded.
func (e *Executor) buildResponse(
	ctx context.Context,
	resp *http.Response,
	targetURL string,
	targetHost string,
) (*pb.HttpResponse, error) {
	body, err := readLimited(resp.Body, e.maxResponseBodySizeBytes)
	if err != nil {
		if errors.Is(err, errBodyTooLarge) {
			return nil, e.refuse(ctx, targetHost, refusalBodyTooLarge,
				connector.ErrorCodeUpstreamError,
				fmt.Errorf("upstream response body exceeds %d bytes",
					e.maxResponseBodySizeBytes))
		}
		slog.ErrorContext(ctx, "upstream request failed: cannot read response body",
			"error", err,
			"target_host", targetHost)
		return nil, fmt.Errorf("failed to read upstream response body: %w", err)
	}

	// Recorded before the rules check so the metric answers what the whole fleet
	// receives, including from hosts nothing redacts today.
	coding := classifyContentCoding(resp.Header.Values(headerContentEncoding))
	e.metrics.responseContentEncoding.Add(ctx, 1, metric.WithAttributes(
		attribute.String(connector.AttrTargetHost, targetHost),
		attribute.String(attrContentEncoding, string(coding)),
	))

	redactHost := hostnameFromURL(targetURL)
	if !e.redactor.HasRulesForHost(redactHost) {
		// Nothing to scan, so nothing is decoded or re-encoded and the feature
		// costs a host with no rules only the classification above.
		return finalizeResponse(resp, body, responseDisposition{}), nil
	}

	// A rule applies, so a range request against this host would be refused
	// below. Stop advertising a capability the connector no longer honors.
	resp.Header.Del(headerAcceptRanges)

	// 204, 304, and a HEAD reply carry no body, so there is nothing to decode
	// and nothing that could leak.
	if len(body) == 0 {
		return finalizeResponse(resp, body, responseDisposition{}), nil
	}

	// A pattern straddling a chunk boundary is invisible to both halves, so a
	// partial body cannot be redacted soundly.
	if resp.StatusCode == http.StatusPartialContent {
		return nil, e.refuse(ctx, targetHost, refusalPartialContent,
			connector.ErrorCodeUpstreamError,
			errors.New("partial response cannot be redacted"))
	}

	if !coding.canDecode() {
		return nil, e.refuse(ctx, targetHost, refusalUnsupportedEncoding,
			connector.ErrorCodeUnsupportedEncoding,
			fmt.Errorf("response content encoding %q cannot be redacted",
				resp.Header.Get(headerContentEncoding)))
	}

	plaintext := body
	if coding == codingGzip {
		plaintext, err = decodeGzip(body, e.maxDecodedResponseBodySizeBytes)
		if err != nil {
			reason := refusalDecodeFailed
			if errors.Is(err, errBodyTooLarge) {
				reason = refusalDecodedTooLarge
			}
			return nil, e.refuse(ctx, targetHost, reason,
				connector.ErrorCodeUpstreamError, err)
		}
		e.metrics.decodedResponseBodySizeBytes.Record(ctx, int64(len(plaintext)),
			metric.WithAttributes(attribute.String(connector.AttrTargetHost, targetHost)))
	}

	redacted, changed := e.redactBody(
		ctx, redactHost, resp.Header.Get(headerContentType), plaintext, targetHost,
	)

	finalBody := redacted
	if coding == codingGzip {
		if finalBody, err = encodeGzip(redacted); err != nil {
			return nil, fmt.Errorf("failed to re-encode upstream response body: %w", err)
		}
		// Normalizes a header the upstream may have spelled with different case.
		resp.Header.Set(headerContentEncoding, string(codingGzip))
	}

	return finalizeResponse(resp, finalBody, responseDisposition{
		redacted: changed,
		// Compared against the bytes that arrived, so this covers every way the
		// connector can move a representation without redacting anything: a gzip
		// re-encode, and a JSON body the upstream pretty-printed that comes back
		// re-serialized.
		representationChanged: !bytes.Equal(finalBody, body),
	}), nil
}

// responseDisposition records what the connector did to a body. The two facts
// are independent, and each governs different headers.
type responseDisposition struct {
	// redacted is true when a rule matched and content was removed.
	redacted bool
	// representationChanged is true when the bytes leaving differ from the bytes
	// that arrived, whether or not anything was redacted.
	representationChanged bool
}

// finalizeResponse rewrites the headers the connector invalidated and converts
// the response for the tunnel.
func finalizeResponse(
	resp *http.Response,
	body []byte,
	disposition responseDisposition,
) *pb.HttpResponse {
	if disposition.redacted {
		resp.Header.Set(headerRedacted, "true")
	}

	// Derived from the slice that becomes the body, so the header and the bytes
	// cannot disagree. A bodyless response keeps whatever the upstream sent: a
	// HEAD reply legitimately describes a body it does not carry, while 204 and
	// 304 send no length to preserve.
	if len(body) > 0 {
		resp.Header.Set(headerContentLength, strconv.Itoa(len(body)))
	}

	headers := connector.HTTPToProtoHeaders(resp.Header)
	headers = connector.FilterHopByHopHeaders(headers)
	// Keyed on the representation rather than on redaction: a validator the
	// upstream computed over its own bytes is stale the moment those bytes change,
	// whatever the reason.
	if disposition.representationChanged {
		headers = connector.FilterContentDependentHeaders(headers)
	}

	return &pb.HttpResponse{
		HttpStatus: int32( //nolint:gosec // HTTP status codes are always in the int32 range
			resp.StatusCode,
		),
		Headers: headers,
		Body:    body,
	}
}

// redactBody applies the redaction rules to a decoded body and reports whether
// any of them changed it.
//
// Structured (regex-structured-data) rules fire per-field via ApplyJSON — only
// when the Content-Type is JSON and the body parses. If either fails, structured
// rules are skipped, because their field filters cannot be honored on raw bytes.
// Legacy byte-level "regex" rules always fire via Apply, regardless of content
// type.
func (e *Executor) redactBody(
	ctx context.Context,
	redactHost string,
	contentType string,
	body []byte,
	targetHost string,
) ([]byte, bool) {
	changed := false
	if isJSONContentType(contentType) {
		redacted, jsonChanged, err := e.redactor.ApplyJSON(ctx, redactHost, body)
		if err == nil {
			body = redacted
			changed = jsonChanged
		} else {
			slog.WarnContext(ctx, "JSON response body could not be parsed for per-field redaction; structured rules skipped, byte-level rules still applied",
				"error", err, "target_host", targetHost)
		}
	}

	redacted, byteChanged := e.redactor.Apply(ctx, redactHost, body)
	return redacted, changed || byteChanged
}

// refuse drops a response the connector cannot scan, rather than forwarding a
// body it could not redact. There is no degraded mode: forwarding unscanned
// content is the defect this path exists to prevent.
//
// The reason rides on a counter separate from the encoding metric, so an
// operator can alert on refusals without watching ordinary traffic.
func (e *Executor) refuse(
	ctx context.Context,
	targetHost string,
	reason string,
	code connector.ErrorCode,
	err error,
) error {
	e.metrics.responseRefusals.Add(ctx, 1, metric.WithAttributes(
		attribute.String(connector.AttrTargetHost, targetHost),
		attribute.String(attrRefusalReason, reason),
	))
	slog.ErrorContext(ctx, "upstream response dropped: body could not be redacted",
		"target_host", targetHost,
		"reason", reason,
		"error", err)
	return connector.NewCodedError(code, err)
}

// isJSONContentType reports whether the given Content-Type header indicates a
// JSON payload. Handles charset parameters (e.g. "application/json; charset=utf-8")
// and the "+json" structured-syntax suffix (RFC 6839, e.g. "application/ld+json").
func isJSONContentType(header string) bool {
	if header == "" {
		return false
	}
	mediaType, _, err := mime.ParseMediaType(header)
	if err != nil {
		return false
	}
	if mediaType == "application/json" || mediaType == "text/json" {
		return true
	}
	// "+json" structured-syntax suffix, e.g. application/ld+json, application/hal+json.
	return len(mediaType) > 5 && mediaType[len(mediaType)-5:] == "+json"
}
