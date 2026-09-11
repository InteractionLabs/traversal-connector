package telemetry

import (
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// unknownTarget stands in for a URL that does not parse or names no host.
// A fixed value keeps a malformed target from opening its own metric series,
// and keeps text that could not be understood from passing through intact.
const unknownTarget = "unknown"

// HostFromURL reduces a raw URL to the "host" or "host:port" naming the
// destination. Only the authority describes where a request went; everything
// after it is supplied by the caller, so the authority is the whole of what
// telemetry may attribute a request to.
func HostFromURL(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Host == "" {
		return unknownTarget
	}
	return parsed.Host
}

// SanitizeError returns a copy of err whose message carries only the origin of
// any request URL it embeds, making it fit to attach to a span or a log record.
//
// Go reports both a failed request and an unparseable URL as a *url.Error, whose
// message quotes the entire URL it was given. Every error wrapping one inherits
// that text, so a request target reaches telemetry through the message alone
// even when no attribute names it. Dropping URL-valued attributes is therefore
// not sufficient by itself.
//
// Every error handed to a span or a log record while serving a request goes
// through here, including the many that cannot embed a URL today. The rule holds
// without exception on purpose: an error's origin is free to change, and an
// exception carved out for one call site is invisible to whoever later routes a
// URL-bearing error into it.
//
// Applying the rule everywhere is not the same as a guarantee, and the limit is
// worth knowing. Reduction reaches a URL only where the tree still holds it in a
// *url.Error. A URL that an error type formats into a message of its own, or one
// flattened into plain text by a %v wrap that leaves no *url.Error behind,
// survives. Those are the two shapes to check when adding an error to this path.
//
// Errors travelling back to the control plane are deliberately left untouched:
// it issued the URL, so shortening its copy costs diagnosis and withholds
// nothing.
func SanitizeError(err error) error {
	if err == nil {
		return nil
	}
	message := err.Error()
	for _, requestURL := range requestURLsIn(err) {
		origin := originOf(requestURL)
		// url.Error renders its URL with %q, so a target holding a control
		// character reaches the message escaped and never matches its own raw
		// bytes. Both spellings are substituted, quoted form first so the
		// unquoted pass cannot break the quoting it leaves behind.
		message = strings.ReplaceAll(
			message, strconv.Quote(requestURL), strconv.Quote(origin),
		)
		message = strings.ReplaceAll(message, requestURL, origin)
	}
	return errors.New(message)
}

// Name and attribute keys of the event a span carries an error under. The event
// is assembled here rather than delegated, so the conventional spellings are
// named locally.
const (
	eventException       = "exception"
	attrExceptionType    = "exception.type"
	attrExceptionMessage = "exception.message"
)

// RecordError attaches err to span as an exception event whose message is reduced
// by SanitizeError, and hands the reduced copy back for the caller's log record.
//
// Recording and reducing are deliberately the same call. It leaves no shorter
// way to report an error on a span than the correct one, and a bare
// span.RecordError in request handling reads as the anomaly it is.
//
// The event is built here instead of through span.RecordError because that
// helper derives the type attribute by reflecting over whichever error it is
// handed, which for a reduced copy is one and the same wrapper on every failure.
// Naming the original's type costs no message text and keeps a deliberate
// refusal, a timeout and a transport failure apart at a glance, which a host and
// a free-text message cannot recover.
func RecordError(span trace.Span, err error) error {
	if err == nil {
		return nil
	}

	safe := SanitizeError(err)
	span.AddEvent(eventException, trace.WithAttributes(
		attribute.String(attrExceptionType, fmt.Sprintf("%T", err)),
		attribute.String(attrExceptionMessage, safe.Error()),
	))
	return safe
}

// requestURLsIn collects the URL of every *url.Error in err's tree.
//
// The tree is walked structurally rather than with errors.As, which reports only
// the first match and gives no way to resume: a request that fails after a
// redirect nests one target inside another, and joining two failures puts them
// on separate branches. Every node has to be visited for each target to be
// found.
func requestURLsIn(err error) []string {
	if err == nil {
		return nil
	}

	var found []string
	if urlErr, ok := err.(*url.Error); ok && urlErr.URL != "" {
		found = append(found, urlErr.URL)
	}

	switch node := err.(type) {
	case interface{ Unwrap() error }:
		found = append(found, requestURLsIn(node.Unwrap())...)
	case interface{ Unwrap() []error }:
		for _, child := range node.Unwrap() {
			found = append(found, requestURLsIn(child)...)
		}
	}
	return found
}

// originOf reduces a URL to scheme://host, the most an exported message may
// carry. Reading the host back off the parse also drops any embedded
// credentials, which are no more exportable than the path.
func originOf(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Host == "" {
		return unknownTarget
	}
	if parsed.Scheme == "" {
		return parsed.Host
	}
	return parsed.Scheme + "://" + parsed.Host
}
