package telemetry

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"go.opentelemetry.io/otel/attribute"

	"github.com/InteractionLabs/traversal-connector/connector-lib/connector"
	pb "github.com/InteractionLabs/traversal-connector/connector-lib/gen/connector/v1"
)

// RequestDetailLevel selects how much of a request's caller-supplied content
// the connector attaches to its per-request log lines.
//
// HostFromURL and SanitizeError hold that everything after a URL's authority is
// supplied by the caller and stays out of telemetry. That remains the default.
// The levels above it are an explicit operator decision to trade some of that
// for being able to tell which query produced a failure.
type RequestDetailLevel string

const (
	// RequestDetailsOff exports nothing beyond the always-on fields: request id,
	// method, request body size, and timeout.
	RequestDetailsOff RequestDetailLevel = "off"
	// RequestDetailsPath adds the URL path and the names (not values) of the
	// query parameters.
	RequestDetailsPath RequestDetailLevel = "path"
	// RequestDetailsFull adds the raw query string and an excerpt of the
	// request body.
	RequestDetailsFull RequestDetailLevel = "full"
)

// ParseRequestDetailLevel reads a LOG_REQUEST_DETAILS value. Matching is
// case-insensitive and ignores surrounding whitespace, and empty means off. An
// unrecognized value yields off and false, so a typo can never widen what is
// exported.
func ParseRequestDetailLevel(raw string) (RequestDetailLevel, bool) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", string(RequestDetailsOff):
		return RequestDetailsOff, true
	case string(RequestDetailsPath):
		return RequestDetailsPath, true
	case string(RequestDetailsFull):
		return RequestDetailsFull, true
	}
	return RequestDetailsOff, false
}

func (l RequestDetailLevel) includesPath() bool {
	return l == RequestDetailsPath || l == RequestDetailsFull
}

func (l RequestDetailLevel) includesContent() bool {
	return l == RequestDetailsFull
}

// Bounds on what one log line may carry. A single request must not be able to
// turn its own failure report into a multi-megabyte record.
const (
	// DefaultRequestBodyExcerptBytes is the default LOG_REQUEST_BODY_MAX_BYTES.
	DefaultRequestBodyExcerptBytes = 2048
	// MaxRequestBodyExcerptBytes is the largest excerpt LOG_REQUEST_BODY_MAX_BYTES
	// may ask for.
	MaxRequestBodyExcerptBytes = 64 * 1024

	maxLoggedPathBytes     = 512
	maxLoggedQueryBytes    = 4096
	maxLoggedQueryKeys     = 64
	maxLoggedQueryKeyBytes = 128
	unknownPath            = unknownTarget
)

// Field names carried by per-request log lines. They are flat, like
// target_host, so they can be searched the same way.
const (
	LogKeyRequestID          = connector.AttrRequestID
	LogKeyMethod             = connector.AttrMethod
	LogKeyRequestBodySize    = "request_body_size"
	LogKeyTimeoutSeconds     = "timeout_seconds"
	LogKeyTargetPath         = "target_path"
	LogKeyQueryKeys          = "query_keys"
	LogKeyTargetQuery        = "target_query"
	LogKeyRequestBodyExcerpt = "request_body_excerpt"
)

// ScrubFunc rewrites caller-supplied text for host before it is logged, for
// instance by applying that host's redaction rules. host is the request
// hostname with the port stripped.
type ScrubFunc func(host string, text []byte) []byte

// RequestLogPolicy decides which request details reach the log. The zero value
// is RequestDetailsOff with no excerpt and no scrubbing.
type RequestLogPolicy struct {
	level        RequestDetailLevel
	bodyMaxBytes int
	timeout      time.Duration
	scrub        ScrubFunc
}

// NewRequestLogPolicy builds a policy. bodyMaxBytes <= 0 disables the body
// excerpt, and timeout <= 0 omits timeout_seconds. scrub may be nil.
func NewRequestLogPolicy(
	level RequestDetailLevel,
	bodyMaxBytes int,
	timeout time.Duration,
	scrub ScrubFunc,
) RequestLogPolicy {
	return RequestLogPolicy{
		level:        level,
		bodyMaxBytes: min(bodyMaxBytes, MaxRequestBodyExcerptBytes),
		timeout:      timeout,
		scrub:        scrub,
	}
}

// Level reports the policy's detail level.
func (p RequestLogPolicy) Level() RequestDetailLevel {
	if p.level == "" {
		return RequestDetailsOff
	}
	return p.level
}

// RequestDetails is what a policy allows the log to say about one request.
// Build it once per request and attach LogAttrs to every line about it, so the
// lines agree with each other.
type RequestDetails struct {
	requestID   string
	method      string
	bodySize    int
	timeout     time.Duration
	hasPath     bool
	path        string
	queryKeys   []string
	hasQuery    bool
	query       string
	hasExcerpt  bool
	bodyExcerpt string
}

// Describe reduces req to what the policy allows the log to say about it.
//
// No URL is ever emitted whole: the host travels separately as target_host, and
// the path and query are read off the parse, so embedded credentials are
// dropped. Headers are never read.
func (p RequestLogPolicy) Describe(requestID string, req *pb.HttpRequest) RequestDetails {
	d := RequestDetails{
		requestID: requestID,
		method:    req.GetMethod(),
		bodySize:  len(req.GetBody()),
		timeout:   p.timeout,
	}
	level := p.Level()
	if !level.includesPath() {
		return d
	}

	d.hasPath = true
	parsed, err := url.Parse(req.GetUrl())
	if err != nil {
		d.path = unknownPath
		return d
	}
	host := parsed.Hostname()

	d.path = parsed.EscapedPath()
	if d.path == "" {
		d.path = "/"
	}
	d.path = truncateText(string(p.scrubText(host, []byte(d.path))), maxLoggedPathBytes,
		len(d.path))
	d.queryKeys = queryKeys(parsed.RawQuery)

	if !level.includesContent() {
		return d
	}
	if parsed.RawQuery != "" {
		d.hasQuery = true
		d.query = truncateText(
			string(p.scrubText(host, []byte(parsed.RawQuery))),
			maxLoggedQueryBytes, len(parsed.RawQuery),
		)
	}
	if body := req.GetBody(); len(body) > 0 && p.bodyMaxBytes > 0 {
		d.hasExcerpt = true
		d.bodyExcerpt = p.bodyExcerpt(host, body)
	}
	return d
}

// LogAttrs returns the details as slog attributes, ready to append to a call's
// arguments.
func (d RequestDetails) LogAttrs() []any {
	attrs := make([]any, 0, 8)
	if d.requestID != "" {
		attrs = append(attrs, slog.String(LogKeyRequestID, d.requestID))
	}
	attrs = append(attrs,
		slog.String(LogKeyMethod, d.method),
		slog.Int(LogKeyRequestBodySize, d.bodySize),
	)
	if d.timeout > 0 {
		attrs = append(attrs, slog.Float64(LogKeyTimeoutSeconds, d.timeout.Seconds()))
	}
	if d.hasPath {
		attrs = append(attrs, slog.String(LogKeyTargetPath, d.path))
		if len(d.queryKeys) > 0 {
			attrs = append(attrs, slog.Any(LogKeyQueryKeys, d.queryKeys))
		}
	}
	if d.hasQuery {
		attrs = append(attrs, slog.String(LogKeyTargetQuery, d.query))
	}
	if d.hasExcerpt {
		attrs = append(attrs, slog.String(LogKeyRequestBodyExcerpt, d.bodyExcerpt))
	}
	return attrs
}

// SpanAttrs returns the opt-in details as span attributes. The always-on fields
// are left out because the spans already carry request id and method under
// their own keys. The body excerpt is left out too: it is the bulkiest field,
// span attribute limits would cut it unpredictably, and the log already has it.
func (d RequestDetails) SpanAttrs() []attribute.KeyValue {
	var attrs []attribute.KeyValue
	if d.hasPath {
		attrs = append(attrs, attribute.String(LogKeyTargetPath, d.path))
		if len(d.queryKeys) > 0 {
			attrs = append(attrs, attribute.StringSlice(LogKeyQueryKeys, d.queryKeys))
		}
	}
	if d.hasQuery {
		attrs = append(attrs, attribute.String(LogKeyTargetQuery, d.query))
	}
	return attrs
}

func (p RequestLogPolicy) scrubText(host string, text []byte) []byte {
	if p.scrub == nil {
		return text
	}
	return p.scrub(host, text)
}

// bodyExcerpt returns the leading bytes of body as text, or a marker when they
// are not text.
//
// Scrubbing runs over a window twice the excerpt length, so a pattern that
// straddles the cut still matches as long as it fits in the window. A match
// longer than that can leave a fragment at the end of the excerpt.
func (p RequestLogPolicy) bodyExcerpt(host string, body []byte) string {
	window := trimPartialRune(body[:min(len(body), 2*p.bodyMaxBytes)])
	if !isLoggableText(window) {
		return fmt.Sprintf("<binary %d bytes>", len(body))
	}
	scrubbed := string(p.scrubText(host, window))
	if len(window) < len(body) && len(scrubbed) <= p.bodyMaxBytes {
		// The window is shorter than the body, so the excerpt is truncated
		// even when scrubbing left it under the limit.
		return scrubbed + truncationMarker(len(body))
	}
	return truncateText(scrubbed, p.bodyMaxBytes, len(body))
}

// queryKeys returns the sorted, de-duplicated parameter names of rawQuery.
// Values are never returned. A malformed query yields whatever names parsed.
func queryKeys(rawQuery string) []string {
	if rawQuery == "" {
		return nil
	}
	values, _ := url.ParseQuery(rawQuery)
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, truncateText(key, maxLoggedQueryKeyBytes, len(key)))
	}
	slices.Sort(keys)
	keys = slices.Compact(keys)
	if len(keys) > maxLoggedQueryKeys {
		extra := len(keys) - maxLoggedQueryKeys
		keys = append(keys[:maxLoggedQueryKeys], fmt.Sprintf("<%d more>", extra))
	}
	return keys
}

// truncateText cuts s to at most limit bytes on a rune boundary and appends a
// marker naming total, the size of the original. It returns s unchanged when it
// already fits.
func truncateText(s string, limit, total int) string {
	if len(s) <= limit {
		return s
	}
	return string(trimPartialRune([]byte(s[:limit]))) + truncationMarker(total)
}

func truncationMarker(total int) string {
	return fmt.Sprintf("...<truncated, %d bytes total>", total)
}

// trimPartialRune drops an incomplete UTF-8 sequence left at the end of b by a
// cut, so cutting text does not make it look like binary.
func trimPartialRune(b []byte) []byte {
	for i := 1; i < utf8.UTFMax && i <= len(b); i++ {
		start := len(b) - i
		if utf8.RuneStart(b[start]) {
			if !utf8.FullRune(b[start:]) {
				return b[:start]
			}
			return b
		}
	}
	return b
}

// isLoggableText reports whether b is valid UTF-8 without control characters
// other than tab, newline, and carriage return. Protobuf and compressed bodies
// (Prometheus remote read, for one) fail this and are logged as a size.
func isLoggableText(b []byte) bool {
	if !utf8.Valid(b) {
		return false
	}
	for _, c := range b {
		if (c < 0x20 && c != '\t' && c != '\n' && c != '\r') || c == 0x7f {
			return false
		}
	}
	return true
}

// requestIDKey carries the controller-assigned request id from the tunnel
// handler to the executor.
type requestIDKey struct{}

// ContextWithRequestID returns ctx carrying the controller-assigned id of the
// request being served, so lines logged below the tunnel handler can name it.
func ContextWithRequestID(ctx context.Context, requestID string) context.Context {
	return context.WithValue(ctx, requestIDKey{}, requestID)
}

// RequestIDFromContext returns the id set by ContextWithRequestID, or "".
func RequestIDFromContext(ctx context.Context) string {
	id, _ := ctx.Value(requestIDKey{}).(string)
	return id
}
