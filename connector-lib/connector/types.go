package connector

// ErrorCode represents a typed error code used on the wire between connector
// and controller.
type ErrorCode string

// Error codes that travel over the wire between connector and controller,
// or that the shared connector validation helpers emit.
const (
	ErrorCodeUpstreamError    ErrorCode = "UPSTREAM_ERROR"
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
