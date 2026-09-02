package connector

import "errors"

// ErrorCode represents a typed error code used on the wire between connector
// and controller.
type ErrorCode string

// Error codes that travel over the wire between connector and controller,
// or that the shared connector validation helpers emit.
const (
	ErrorCodeUpstreamError       ErrorCode = "UPSTREAM_ERROR"
	ErrorCodeMissingTargetURL    ErrorCode = "MISSING_TARGET_URL"
	ErrorCodeUnsupportedEncoding ErrorCode = "UNSUPPORTED_ENCODING"
)

// CodedError attaches an ErrorCode to an error so the code survives the trip to
// the controller. Without it every failure arrives as ErrorCodeUpstreamError,
// which cannot distinguish a deliberate refusal from a timeout or a dropped
// connection.
type CodedError struct {
	Code ErrorCode
	Err  error
}

func (e *CodedError) Error() string { return e.Err.Error() }

func (e *CodedError) Unwrap() error { return e.Err }

// NewCodedError wraps err with code.
func NewCodedError(code ErrorCode, err error) error {
	return &CodedError{Code: code, Err: err}
}

// ErrorCodeFor returns the code err carries, falling back to
// ErrorCodeUpstreamError. Keeping the fallback here means a new code becomes
// visible on the wire by being wrapped at the point of failure, with no
// matching change at the transport layer.
func ErrorCodeFor(err error) ErrorCode {
	var coded *CodedError
	if errors.As(err, &coded) {
		return coded.Code
	}
	return ErrorCodeUpstreamError
}

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

// Response headers that describe a specific representation of a body and that
// the connector cannot regenerate after redaction rewrites it. A header belongs
// here when it is a function of bytes the connector no longer holds, or a name
// assigned by an authority the connector is not.
//
// Content-Length and Content-Encoding are excluded because the connector writes
// both correctly from what it produced. Content-Range is excluded because a
// partial response never reaches redaction. The digest family is included even
// though it is computable: nothing in the stack verifies it, so re-deriving the
// RFC 9530 structured-field encoding buys nothing. Last-Modified travels with
// ETag because stripping only ETag lets a client fall back to
// If-Modified-Since and reach the same stale copy.
var ContentDependentHeaders = map[string]bool{
	"etag":           true,
	"last-modified":  true,
	"content-md5":    true,
	"digest":         true,
	"content-digest": true,
	"repr-digest":    true,
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
