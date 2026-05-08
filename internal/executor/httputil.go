package executor

import (
	"mime"
	"net/http"
	"net/url"
	"strings"

	pb "github.com/InteractionLabs/traversal-connector/connector-lib/gen/connector/v1"
)

// hostFromURL extracts the host (hostname or hostname:port) from a raw
// URL string. It is intended for use as a low-cardinality metric
// attribute. Returns "unknown" if the URL cannot be parsed or has no
// host component.
func hostFromURL(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Host == "" {
		return "unknown"
	}
	return parsed.Host
}

// contentTypeFromGoHeaders extracts and normalises the MIME type from a
// Go http.Header map (e.g. "application/json"), stripping parameters such
// as charset. Returns "unknown" if the header is absent or unparseable.
func contentTypeFromGoHeaders(h http.Header) string {
	raw := h.Get("Content-Type")
	return normaliseMIME(raw)
}

// contentTypeFromProtoHeaders extracts and normalises the MIME type from
// the protobuf repeated-Header slice. Header name matching is
// case-insensitive. Returns "unknown" if the header is absent or
// unparseable.
func contentTypeFromProtoHeaders(headers []*pb.Header) string {
	for _, hdr := range headers {
		if strings.EqualFold(hdr.Key, "Content-Type") {
			return normaliseMIME(hdr.Value)
		}
	}
	return "unknown"
}

// normaliseMIME strips parameters (e.g. "; charset=utf-8") from a raw
// Content-Type value and returns just the media type in lower-case.
// Returns "unknown" if the value is empty or cannot be parsed.
func normaliseMIME(raw string) string {
	if raw == "" {
		return "unknown"
	}
	mediaType, _, err := mime.ParseMediaType(raw)
	if err != nil {
		// Not parseable — return the raw value trimmed and lower-cased so
		// it still shows up in aggregations rather than being silently lost.
		return strings.ToLower(strings.TrimSpace(raw))
	}
	return mediaType
}
