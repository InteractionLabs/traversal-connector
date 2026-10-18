package upstream

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/InteractionLabs/traversal-connector/connector-lib/connector"
)

const (
	headerContentLength   = "Content-Length"
	headerContentType     = "Content-Type"
	headerContentEncoding = "Content-Encoding"
	headerAcceptRanges    = "Accept-Ranges"
	// headerRedacted tells Traversal the body is not the one the upstream
	// sent.
	headerRedacted = "X-Traversal-Redacted"
)

// Why a response to a covered host was dropped rather than forwarded. The set
// is closed so the refusal counter stays cheap to alert on.
const (
	refusalUnredactable        = "unredactable_content"
	refusalUnsupportedEncoding = "unsupported_encoding"
	refusalPartialContent      = "partial_content"
	refusalBodyTooLarge        = "body_too_large"
	refusalDecodedTooLarge     = "decoded_too_large"
	refusalDecodeFailed        = "decode_failed"
	refusalNoEnd               = "no_end"
	// refusalMalformedJSON is about the document, not its coding: the body
	// decoded and was not the one JSON document its content type promised.
	refusalMalformedJSON = "malformed_json"
)

// unredactableRequest says why a request to a covered host cannot be
// carried, or "" if it can. Refusing it here, before it is sent, keeps a
// request whose answer would be dropped from having its effect upstream.
func unredactableRequest(r *http.Request) string {
	switch {
	case r.Header.Get("Upgrade") != "":
		return "an upgraded connection cannot be redacted"
	case isGRPC(r.Header.Get(headerContentType)):
		return "gRPC cannot be redacted"
	}
	return ""
}

// respond is ReverseProxy's ModifyResponse. A host no rule covers streams.
// A covered host's response is read whole within the limits, redacted, and
// sent; one that cannot be is refused, never sent as it came.
//
// The caller's Accept-Encoding is forwarded, so Go's transport does not
// decompress and the body comes in the coding the upstream chose: redacting
// means decoding it here, as a pattern over a deflate stream matches nothing.
func (c *Client) respond(
	ctx context.Context, resp *http.Response, target, host string, covered bool,
) error {
	// Only the connector may say it redacted a body; Traversal cannot check.
	resp.Header.Del(headerRedacted)
	coding := classifyContentCoding(resp.Header.Values(headerContentEncoding))
	c.metrics.encodings.Add(ctx, 1, metric.WithAttributes(
		attribute.String(connector.AttrTargetHost, target),
		attribute.String(attrContentEncoding, string(coding))))
	if !covered {
		return nil
	}
	resp.Header.Del(headerAcceptRanges)
	switch mediaType := mediaTypeOf(resp.Header.Get(headerContentType)); {
	case resp.StatusCode == http.StatusSwitchingProtocols || mediaType == "text/event-stream" ||
		isGRPC(mediaType) || !redactable(mediaType):
		_ = resp.Body.Close()
		return c.refuse(ctx, target, refusalUnredactable,
			fmt.Errorf("a %q response cannot be redacted", mediaType))
	case resp.StatusCode == http.StatusPartialContent:
		// A pattern straddling a range boundary is invisible to both halves.
		_ = resp.Body.Close()
		return c.refuse(ctx, target, refusalPartialContent,
			errors.New("a partial response cannot be redacted"))
	}
	body, reason, err := c.read(resp.Body)
	if err != nil {
		return c.refuse(ctx, target, reason, err)
	}
	if len(body) == 0 {
		return replaceBody(resp, body, false, false)
	}
	if !coding.canDecode() {
		return c.refuse(ctx, target, refusalUnsupportedEncoding,
			fmt.Errorf("content encoding %q cannot be redacted",
				resp.Header.Get(headerContentEncoding)))
	}
	plaintext := body
	if coding == codingGzip {
		if plaintext, err = decodeGzip(body, c.maxDecoded); err != nil {
			reason := refusalDecodeFailed
			if errors.Is(err, errBodyTooLarge) {
				reason = refusalDecodedTooLarge
			}
			return c.refuse(ctx, target, reason, err)
		}
		c.metrics.decodedSize.Record(ctx, int64(len(plaintext)),
			metric.WithAttributes(attribute.String(connector.AttrTargetHost, target)))
	}
	// A coding wrapping nothing still puts bytes on the wire, so emptiness is
	// only visible after the decode.
	if len(plaintext) == 0 {
		return replaceBody(resp, body, false, false)
	}
	redacted, changed, err := c.redact(ctx, host, resp.Header.Get(headerContentType), plaintext)
	if err != nil {
		return c.refuse(ctx, target, refusalMalformedJSON, err)
	}
	final := redacted
	if coding == codingGzip {
		if final, err = encodeGzip(redacted); err != nil {
			return fmt.Errorf("re-encode the response: %w", err)
		}
		resp.Header.Set(headerContentEncoding, string(codingGzip))
	}
	// After a gzip re-encode the connector made the bytes, so the upstream's
	// validators no longer describe them even if they happen to match.
	return replaceBody(resp, final, changed, coding == codingGzip || !bytes.Equal(final, body))
}

// read reads a covered response whole, within maxBody and bufferFor. A
// response that does not end in time is a stream, and refused.
func (c *Client) read(body io.ReadCloser) ([]byte, string, error) {
	var timedOut atomic.Bool
	timer := time.AfterFunc(c.bufferFor, func() { timedOut.Store(true); _ = body.Close() })
	defer timer.Stop()
	defer func() { _ = body.Close() }()
	b, err := readLimited(body, c.maxBody)
	switch {
	case timedOut.Load():
		return nil, refusalNoEnd, fmt.Errorf("the response did not end within %v", c.bufferFor)
	case errors.Is(err, errBodyTooLarge):
		return nil, refusalBodyTooLarge, fmt.Errorf("the response exceeds %d bytes", c.maxBody)
	case err != nil:
		return nil, refusalDecodeFailed, err
	}
	return b, "", nil
}

// redact applies the rules to a decoded body. Structured rules run per field
// on JSON only; byte-level rules run on every body. A JSON body that is not
// one document fails when a structured rule is in scope: there is no
// byte-level fallback that would honor its field filters.
func (c *Client) redact(ctx context.Context, host, contentType string, body []byte,
) ([]byte, bool, error) {
	changed := false
	if isJSON(mediaTypeOf(contentType)) {
		var err error
		if body, changed, err = c.redactor.ApplyJSON(ctx, host, body); err != nil {
			return nil, false, err
		}
	}
	body, byteChanged := c.redactor.Apply(ctx, host, body)
	return body, changed || byteChanged, nil
}

// replaceBody sends body in place of the one read. It drops the trailers,
// which would leave unredacted: it runs after the read because Go's transport
// fills resp.Trailer only at the body's end.
func replaceBody(resp *http.Response, body []byte, redacted, representationChanged bool) error {
	resp.Trailer = nil
	resp.Header.Del("Trailer")
	if redacted {
		resp.Header.Set(headerRedacted, "true")
	}
	if representationChanged {
		for h := range connector.ContentDependentHeaders {
			resp.Header.Del(h)
		}
	}
	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.ContentLength = int64(len(body))
	// A HEAD, 204 or 304 keeps the length it describes.
	if len(body) > 0 {
		resp.Header.Set(headerContentLength, strconv.Itoa(len(body)))
	}
	return nil
}

// mediaTypeOf is a Content-Type's media type. A malformed parameter leaves
// the type usable, so it still decides: otherwise an upstream could move a
// JSON body out of per-field redaction by appending one broken parameter.
func mediaTypeOf(contentType string) string {
	mt, _, err := mime.ParseMediaType(contentType)
	if err != nil && !errors.Is(err, mime.ErrInvalidMediaParameter) {
		return ""
	}
	return mt
}

func isJSON(mt string) bool {
	return mt == "application/json" || mt == "text/json" || strings.HasSuffix(mt, "+json")
}

func isGRPC(contentType string) bool {
	return strings.HasPrefix(mediaTypeOf(contentType), "application/grpc")
}

// redactable is a media type whose body the rules can be applied to: text,
// JSON or XML. A response with none is one the legacy transport redacted as
// bytes, so it still is.
func redactable(mt string) bool {
	switch {
	case mt == "", strings.HasPrefix(mt, "text/"), isJSON(mt), strings.HasSuffix(mt, "+xml"):
		return true
	}
	switch mt {
	case "application/xml", "application/javascript", "application/x-www-form-urlencoded",
		"application/yaml", "application/x-ndjson":
		return true
	}
	return false
}
