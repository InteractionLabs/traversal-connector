package connector

// ErrorCode represents a typed error code used on the wire between connector
// and controller.
type ErrorCode string

// Error codes that travel over the wire between connector and controller,
// or that the shared connector validation helpers emit.
//
// Upstream-prefixed codes describe failures of the upstream service the
// connector was forwarding to; non-Upstream codes describe failures the
// connector itself observed before or after the upstream call. The controller
// uses these to pick an HTTP status for the original caller — the suggested
// mapping is in the comment next to each code.
const (
	// ErrorCodeUpstreamError is the legacy catch-all and should not be emitted
	// by new code paths. It is retained so older controllers continue to
	// understand connector responses; new failures should use one of the more
	// specific codes below.
	ErrorCodeUpstreamError ErrorCode = "UPSTREAM_ERROR"

	// ErrorCodeUpstreamTimeout indicates the connector's deadline fired while
	// waiting on the upstream service. Maps to HTTP 504.
	ErrorCodeUpstreamTimeout ErrorCode = "UPSTREAM_TIMEOUT"
	// ErrorCodeUpstreamUnavailable indicates the connector could not establish
	// or complete a connection to the upstream (DNS, TCP, TLS). Maps to HTTP 502.
	ErrorCodeUpstreamUnavailable ErrorCode = "UPSTREAM_UNAVAILABLE"
	// ErrorCodeUpstreamAborted indicates the upstream accepted the request but
	// closed the connection mid-response (broken pipe, unexpected EOF, reset).
	// Maps to HTTP 502.
	ErrorCodeUpstreamAborted ErrorCode = "UPSTREAM_ABORTED"

	// ErrorCodeInvalidRequest indicates the caller sent a malformed request
	// (bad URL, failed proto validation). Maps to HTTP 400.
	ErrorCodeInvalidRequest ErrorCode = "INVALID_REQUEST"
	// ErrorCodeRequestTooLarge indicates the request body exceeded the
	// connector's configured limit. Maps to HTTP 413.
	ErrorCodeRequestTooLarge ErrorCode = "REQUEST_TOO_LARGE"
	// ErrorCodeClientCanceled indicates the controller cancelled the request
	// before the upstream returned. Maps to HTTP 499 (or no response).
	ErrorCodeClientCanceled ErrorCode = "CLIENT_CANCELED"

	// ErrorCodeUnsupported indicates the controller asked for a feature this
	// connector version does not implement. Maps to HTTP 501.
	ErrorCodeUnsupported ErrorCode = "UNSUPPORTED"
	// ErrorCodeInternal indicates a bug in the connector itself — not an
	// upstream problem. Maps to HTTP 500.
	ErrorCodeInternal ErrorCode = "INTERNAL"

	ErrorCodeMissingTargetURL ErrorCode = "MISSING_TARGET_URL"
)

// HTTP headers that should be filtered (hop-by-hop).
var HopByHopHeaders = map[string]bool{
	"connection":          true,
	"proxy-connection":    true,
	"keep-alive":          true,
	"proxy-authenticate":  true,
	"proxy-authorization": true,
	"te":                  true,
	"trailer":             true,
	"transfer-encoding":   true,
	"upgrade":             true,
}

// OpenTelemetry attribute keys shared by connector and controller.
const (
	AttrRequestID      = "request_id"
	AttrTargetHost     = "target_host"
	AttrMethod         = "method"
	AttrHTTPStatusCode = "http.status_code"
)

// Metric units.
const (
	UnitMilliseconds = "ms"
	UnitBytes        = "bytes"
)

// Metric attribute values shared by connector and controller.
const (
	AttrStatus    = "status"
	StatusSuccess = "success"
	StatusError   = "error"
)
