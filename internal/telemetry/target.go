package telemetry

import (
	"errors"
	"net/url"
	"strconv"
	"strings"
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
