package connector

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	pb "github.com/InteractionLabs/traversal-connector/connector-lib/gen/connector/v1"
	"github.com/InteractionLabs/traversal-connector/internal/iter"
)

// ValidateTargetURL validates the target URL for connector requests.
//
// Outcomes are reported through the returned error alone. The caller holds the
// request's span and its destination attribute, so it is the only layer that can
// record a failure with correlation, and reporting from both places would
// duplicate every validation outcome in the log stream.
func ValidateTargetURL(targetURL string) error {
	if targetURL == "" {
		return fmt.Errorf("validation error: %s", ErrorCodeMissingTargetURL)
	}

	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return fmt.Errorf("validation error: invalid URL format: %w", err)
	}

	// Validate URL scheme
	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return errors.New("validation error: invalid URL scheme, must be http or https")
	}

	// Validate host is present
	if parsedURL.Host == "" {
		return errors.New("validation error: missing host in URL")
	}

	return nil
}

// FilterHopByHopHeaders removes hop-by-hop headers that should not be forwarded.
func FilterHopByHopHeaders(headers []*pb.Header) []*pb.Header {
	return filterHeaders(headers, HopByHopHeaders)
}

// FilterContentDependentHeaders removes the headers that describe a body the
// connector has rewritten, so a client cannot validate a redacted response
// against a fingerprint of the original. See ContentDependentHeaders.
func FilterContentDependentHeaders(headers []*pb.Header) []*pb.Header {
	return filterHeaders(headers, ContentDependentHeaders)
}

// filterHeaders drops every header whose lowercased name is in exclude.
func filterHeaders(headers []*pb.Header, exclude map[string]bool) []*pb.Header {
	if len(headers) == 0 {
		return headers
	}

	filtered := iter.Filter(headers, func(header *pb.Header) bool {
		return !exclude[strings.ToLower(header.Key)]
	})

	slog.Debug(
		"header filtering completed",
		"original_count",
		len(headers),
		"filtered_count",
		len(filtered),
	)
	return filtered
}

// HTTPToProtoHeaders converts Go http.Header to protobuf Header slice.
//
// Each value in a multi-valued header becomes its own Header proto, preserving
// the original header lines verbatim. Joining values with ", " is lossy for
// headers whose values legitimately contain commas (Set-Cookie's Expires date,
// any field that comma-separates internally), so emit them as separate entries
// and let the receiver Add each one.
func HTTPToProtoHeaders(h http.Header) []*pb.Header {
	if len(h) == 0 {
		return nil
	}

	headers := make([]*pb.Header, 0, len(h))
	for _, key := range iter.Keys(h) {
		for _, value := range h[key] {
			headers = append(headers, &pb.Header{Key: key, Value: value})
		}
	}

	slog.Debug("converted HTTP headers to proto", "count", len(headers))
	return headers
}

// ProtoToHTTPHeaders converts protobuf Header slice to Go http.Header.
//
// Each Header proto contributes one value via http.Header.Add. Splitting on
// ", " here would corrupt headers whose values contain commas (e.g. the
// Expires attribute of a Set-Cookie, or the Accept header that the MCP
// streamable-http spec mandates contain both "application/json" and
// "text/event-stream" on a single line).
func ProtoToHTTPHeaders(headers []*pb.Header) http.Header {
	if len(headers) == 0 {
		return make(http.Header)
	}

	httpHeaders := make(http.Header)
	for _, header := range headers {
		if header.Key != "" && header.Value != "" {
			httpHeaders.Add(header.Key, header.Value)
		}
	}

	slog.Debug("converted proto headers to HTTP", "count", len(httpHeaders))
	return httpHeaders
}
