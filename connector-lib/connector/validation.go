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
func ValidateTargetURL(targetURL string) error {
	if targetURL == "" {
		slog.Warn("validation failed: missing target URL")
		return fmt.Errorf("validation error: %s", ErrorCodeMissingTargetURL)
	}

	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		slog.Warn("validation failed: invalid URL format", "error", err)
		return fmt.Errorf("validation error: invalid URL format: %w", err)
	}

	// Validate URL scheme
	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		slog.Warn("validation failed: invalid URL scheme")
		return errors.New("validation error: invalid URL scheme, must be http or https")
	}

	// Validate host is present
	if parsedURL.Host == "" {
		slog.Warn("validation failed: missing host")
		return errors.New("validation error: missing host in URL")
	}

	slog.Debug("URL validation successful", "url", targetURL)
	return nil
}

// FilterHopByHopHeaders removes hop-by-hop headers that should not be forwarded.
func FilterHopByHopHeaders(headers []*pb.Header) []*pb.Header {
	if len(headers) == 0 {
		return headers
	}

	filtered := iter.Filter(headers, func(header *pb.Header) bool {
		return !HopByHopHeaders[strings.ToLower(header.Key)]
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
func HTTPToProtoHeaders(h http.Header) []*pb.Header {
	if len(h) == 0 {
		return nil
	}

	headers := iter.Map(iter.Keys(h), func(key string) *pb.Header {
		return &pb.Header{
			Key:   key,
			Value: strings.Join(h[key], ", "),
		}
	})

	slog.Debug("converted HTTP headers to proto", "count", len(headers))
	return headers
}

// ProtoToHTTPHeaders converts protobuf Header slice to Go http.Header.
func ProtoToHTTPHeaders(headers []*pb.Header) http.Header {
	if len(headers) == 0 {
		return make(http.Header)
	}

	httpHeaders := make(http.Header)
	for _, header := range headers {
		if header.Key != "" && header.Value != "" {
			// Split comma-separated values back into multiple values
			values := strings.SplitSeq(header.Value, ", ")
			for value := range values {
				httpHeaders.Add(header.Key, strings.TrimSpace(value))
			}
		}
	}

	slog.Debug("converted proto headers to HTTP", "count", len(httpHeaders))
	return httpHeaders
}
