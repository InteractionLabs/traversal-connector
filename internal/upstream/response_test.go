package upstream

// The response pipeline's regression tests, ported from internal/executor's
// (http_response_test.go and http_test.go, deleted with it in 7f2adc3). Each
// sends a request through Client.Forward to a real destination, as a pipe's
// request arrives, and checks what reaches the caller.

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/InteractionLabs/traversal-connector/connector-lib/halfconn"
	"github.com/InteractionLabs/traversal-connector/connector-lib/rawpipe"
	"github.com/InteractionLabs/traversal-connector/internal/config"
	"github.com/InteractionLabs/traversal-connector/internal/redact"
	"github.com/InteractionLabs/traversal-connector/internal/telemetry"
)

const (
	emailPattern = `[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`
	// covered is the destination the test rules cover; other is one they do not.
	covered = "http://api.internal"
	other   = "http://other.internal"
)

// emailRule redacts any email address anywhere in a body from covered.
func emailRule() redact.Rule {
	return redact.Rule{Name: "email", Type: "regex", Pattern: emailPattern,
		Replacement: "[REDACTED]", Hosts: []string{`api\.internal`}}
}

// structuredEmailRule redacts email addresses per field in a JSON body from
// covered, in fields only if any are given.
func structuredEmailRule(fields ...string) redact.Rule {
	return redact.Rule{Name: "email-fields", Type: "regex-structured-data",
		Pattern: emailPattern, Replacement: "[REDACTED]", RedactFields: fields,
		Hosts: []string{`api\.internal`}}
}

func responseTestConfig() *config.Config {
	return &config.Config{RequestTimeout: 5 * time.Second, MaxRequestBodySizeMB: 32,
		MaxResponseBodySizeMB: 32, MaxDecodedResponseBodySizeMB: 256}
}

func newRedactor(t *testing.T, rules ...redact.Rule) *redact.Redactor {
	t.Helper()
	r := redact.NewRedactor()
	if err := r.Update(&redact.RulesFile{Version: "v1", Rules: rules}); err != nil {
		t.Fatal(err)
	}
	return r
}

// dialTo reaches addr whatever destination it is asked for.
func dialTo(addr string) Dialer {
	return func(ctx context.Context, _ string, _ uint16) (halfconn.Conn, string, error) {
		c, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
		if err != nil {
			return nil, "", err
		}
		return c.(*net.TCPConn), addr, nil //nolint:forcetypeassert // tcp
	}
}

// clientFor serves h as every destination, and is a Client (cfg, or
// responseTestConfig) under rules that reaches it.
func clientFor(t *testing.T, cfg *config.Config, h http.HandlerFunc, rules ...redact.Rule,
) *Client {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	if cfg == nil {
		cfg = responseTestConfig()
	}
	c, err := New(cfg, newRedactor(t, rules...), dialTo(srv.Listener.Addr().String()))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// forward sends method to dest (scheme://host) through c, as a pipe to
// dest's port 80 carries it, with header, and returns the answer.
func forward(
	t *testing.T, c *Client, method, dest string, header http.Header,
) *httptest.ResponseRecorder {
	t.Helper()
	u, err := url.Parse(dest)
	if err != nil {
		t.Fatal(err)
	}
	target := &url.URL{Scheme: u.Scheme, Host: net.JoinHostPort(u.Hostname(), "80")}
	req := httptest.NewRequestWithContext(t.Context(), method, "http://api.internal/", nil)
	req.Host = target.Host
	for k, v := range header {
		req.Header[k] = v
	}
	w := httptest.NewRecorder()
	c.Forward(w, req, target)
	return w
}

func acceptEncoding(coding string) http.Header {
	if coding == "" {
		return nil
	}
	return http.Header{"Accept-Encoding": {coding}}
}

// refused checks that an answer of status, h and b is a refusal as
// redaction_unsupported carrying nothing of the destination's body.
func refused(t *testing.T, status int, h http.Header, b []byte) {
	t.Helper()
	if status != http.StatusBadGateway ||
		h.Get(rawpipe.HeaderReason) != string(rawpipe.RedactionUnsupported) {
		t.Errorf("%d %q %q, want 502 redaction_unsupported", status, h.Get(rawpipe.HeaderReason), b)
	}
	if bytes.Contains(b, []byte("user@example.com")) {
		t.Errorf("the refusal carries the body: %q", b)
	}
}

// captureMetrics collects what Clients made from here on record.
func captureMetrics(t *testing.T) *sdkmetric.ManualReader {
	t.Helper()
	reader := sdkmetric.NewManualReader()
	previous := otel.GetMeterProvider()
	otel.SetMeterProvider(sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader)))
	t.Cleanup(func() { otel.SetMeterProvider(previous) })
	return reader
}

// counted sums counter name's points whose key is value.
func counted(t *testing.T, reader *sdkmetric.ManualReader, name, key, value string) int64 {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatal(err)
	}
	var n int64
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			sum, ok := m.Data.(metricdata.Sum[int64])
			if !ok || m.Name != name {
				continue
			}
			for _, p := range sum.DataPoints {
				if v, _ := p.Attributes.Value(attribute.Key(key)); v == attribute.StringValue(
					value,
				) {
					n += p.Value
				}
			}
		}
	}
	return n
}

func gzipped(t *testing.T, src []byte) []byte {
	t.Helper()
	b, err := encodeGzip(src)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func ungzip(t *testing.T, src []byte) []byte {
	t.Helper()
	r, err := gzip.NewReader(bytes.NewReader(src))
	if err != nil {
		t.Fatalf("not a gzip stream: %v", err)
	}
	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("does not inflate: %v", err)
	}
	return b
}

// serving answers with status, the headers given as name-value pairs, and b.
func serving(status int, b []byte, headers ...string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		for i := 0; i+1 < len(headers); i += 2 {
			w.Header().Set(headers[i], headers[i+1])
		}
		w.WriteHeader(status)
		_, _ = w.Write(b)
	}
}

// gzipServing serves plaintext gzipped, with an ETag: an assertion that a
// validator was stripped proves nothing against a response that had none.
func gzipServing(t *testing.T, contentType string, plaintext []byte) http.HandlerFunc {
	return serving(http.StatusOK, gzipped(t, plaintext), headerContentType, contentType,
		headerContentEncoding, "gzip", "ETag", `"v1"`)
}

// TestGzipRedactedAndReEncoded: a valid gzip body from a covered host is
// decoded, redacted, and sent gzip-encoded again, as the caller negotiated.
func TestGzipRedactedAndReEncoded(t *testing.T) {
	c := clientFor(
		t,
		nil,
		gzipServing(t, "text/plain", []byte("contact user@example.com for help")),
		emailRule(),
	)
	resp := forward(t, c, http.MethodGet, covered, acceptEncoding("gzip"))
	b := resp.Body.Bytes()
	if got := resp.Header().Get(headerContentEncoding); got != "gzip" {
		t.Errorf("Content-Encoding %q, want gzip", got)
	}
	if diff := cmp.Diff("contact [REDACTED] for help", string(ungzip(t, b))); diff != "" {
		t.Errorf("decoded body (-want +got):\n%s", diff)
	}
	if got := resp.Header().Get(headerContentLength); got != strconv.Itoa(len(b)) {
		t.Errorf("Content-Length %q for %d bytes", got, len(b))
	}
	if resp.Header().Get(headerRedacted) != "true" || resp.Header().Get("ETag") != "" {
		t.Errorf("headers %v, want the redaction flag and no ETag", resp.Header())
	}
}

// TestIdentityRedactedInPlace: an uncompressed body is redacted and sent
// without a Content-Encoding.
func TestIdentityRedactedInPlace(t *testing.T) {
	c := clientFor(t, nil, serving(http.StatusOK, []byte("contact user@example.com for help"),
		headerContentType, "text/plain"), emailRule())
	resp := forward(t, c, http.MethodGet, covered, acceptEncoding("identity"))
	if diff := cmp.Diff("contact [REDACTED] for help", resp.Body.String()); diff != "" {
		t.Errorf("body (-want +got):\n%s", diff)
	}
	if got := resp.Header().Get(headerContentEncoding); got != "" {
		t.Errorf("Content-Encoding %q, want none", got)
	}
}

// TestTransportDecodesWhenCallerOmitsAcceptEncoding: with no coding from the
// caller, Go's transport negotiates gzip itself and hands back plaintext,
// which is redacted as identity.
func TestTransportDecodesWhenCallerOmitsAcceptEncoding(t *testing.T) {
	c := clientFor(t, nil, gzipServing(t, "text/plain", []byte("contact user@example.com")),
		emailRule())
	resp := forward(t, c, http.MethodGet, covered, nil)
	if diff := cmp.Diff("contact [REDACTED]", resp.Body.String()); diff != "" {
		t.Errorf("body (-want +got):\n%s", diff)
	}
}

// TestRuleKindsByContentType: structured rules run per field on JSON, with
// their field filters, gzipped or not; byte-level rules run on every body;
// structured rules are skipped on a body that is not JSON.
func TestRuleKindsByContentType(t *testing.T) {
	ssn := redact.Rule{Name: "ssn", Type: "regex", Pattern: `\b\d{3}-\d{2}-\d{4}\b`,
		Replacement: "[SSN]", Hosts: []string{`api\.internal`}}
	for _, c := range []struct {
		name, contentType, body, want string
		gzip                          bool
		rules                         []redact.Rule
	}{
		{"structured, filtered to one field", "application/json; charset=utf-8",
			`{"message":"contact a@b.com","safe":"contact c@d.com"}`,
			`{"message":"contact [REDACTED]","safe":"contact c@d.com"}`, false,
			[]redact.Rule{structuredEmailRule("message")}},
		{"structured, on a gzipped body", "application/json",
			`{"message":"contact a@b.com","safe":"contact c@d.com"}`,
			`{"message":"contact [REDACTED]","safe":"contact c@d.com"}`, true,
			[]redact.Rule{structuredEmailRule("message")}},
		{"structured and byte-level on JSON", "application/json",
			`{"key":"a@b.com","ss":"123-45-6789","not-key":"c@d.com"}`,
			`{"key":"[REDACTED]","not-key":"c@d.com","ss":"[SSN]"}`, false,
			[]redact.Rule{structuredEmailRule("key"), ssn}},
		{"structured skipped on text, byte-level kept", "text/plain",
			"email a@b.com ssn 123-45-6789", "email a@b.com ssn [SSN]", false,
			[]redact.Rule{structuredEmailRule("some-field"), ssn}},
	} {
		t.Run(c.name, func(t *testing.T) {
			wire, coding := []byte(c.body), ""
			if c.gzip {
				wire, coding = gzipped(t, wire), "gzip"
			}
			cl := clientFor(t, nil, serving(http.StatusOK, wire, headerContentType, c.contentType,
				headerContentEncoding, coding), c.rules...)
			got := forward(t, cl, http.MethodGet, covered, acceptEncoding("gzip")).Body.Bytes()
			if c.gzip {
				got = ungzip(t, got)
			}
			if diff := cmp.Diff(c.want, string(got)); diff != "" {
				t.Errorf("body (-want +got):\n%s", diff)
			}
		})
	}
}

// TestUncoveredStreamsUntouched: a host no rule covers gets its response as
// the destination sent it, in a coding the connector cannot decode, with its
// validators and range support, and no redaction flag.
func TestUncoveredStreamsUntouched(t *testing.T) {
	upstream := []byte("contact user@example.com for help")
	c := clientFor(t, nil, serving(http.StatusOK, upstream, headerContentType, "text/plain",
		headerContentEncoding, "zstd", headerAcceptRanges, "bytes", "ETag", `"v1"`), emailRule())
	resp := forward(t, c, http.MethodGet, other, acceptEncoding("zstd"))
	if diff := cmp.Diff(upstream, resp.Body.Bytes()); diff != "" {
		t.Errorf("body (-want +got):\n%s", diff)
	}
	for _, h := range []string{"ETag", headerAcceptRanges} {
		if resp.Header().Get(h) == "" {
			t.Errorf("%s dropped from a host no rule covers", h)
		}
	}
	if resp.Header().Get(headerRedacted) != "" {
		t.Error("an untouched response is flagged as redacted")
	}
}

// TestRefusedResponses: each covered response that cannot be redacted is
// refused, sends nothing of its body, and is counted under its reason.
func TestRefusedResponses(t *testing.T) {
	text := []byte("contact user@example.com")
	truncated := gzipped(t, bytes.Repeat([]byte("contact user@example.com "), 100))
	for _, c := range []struct {
		name, reason string
		status       int
		body         []byte
		headers      []string
		wireMB       int64
		decodedMB    int64
	}{
		{"truncated gzip", refusalDecodeFailed, 200, truncated[:len(truncated)/2],
			[]string{headerContentEncoding, "gzip"}, 0, 0},
		{"decompression bomb", refusalDecodedTooLarge, 200,
			gzipped(t, bytes.Repeat([]byte("a"), 2<<20)), []string{headerContentEncoding, "gzip"}, 0, 1},
		{"stacked encoding", refusalUnsupportedEncoding, 200, truncated,
			[]string{headerContentEncoding, "gzip, br"}, 0, 0},
		{"an encoding nothing decodes", refusalUnsupportedEncoding, 200, text,
			[]string{headerContentEncoding, "zstd"}, 0, 0},
		{"past the wire limit", refusalBodyTooLarge, 200, bytes.Repeat([]byte("a"), 2<<20),
			nil, 1, 0},
		// A pattern straddling a range boundary is invisible to both halves.
		{"partial content", refusalPartialContent, http.StatusPartialContent, text,
			[]string{headerContentType, "text/plain", "Content-Range", "bytes 0-23/100"}, 0, 0},
		// A finite event stream is still one the caller reads as it comes.
		{"an event stream", refusalUnredactable, 200, []byte("data: user@example.com\n\n"),
			[]string{headerContentType, "text/event-stream"}, 0, 0},
		{"binary", refusalUnredactable, 200, text,
			[]string{headerContentType, "application/octet-stream"}, 0, 0},
	} {
		t.Run(c.name, func(t *testing.T) {
			reader := captureMetrics(t)
			cfg := responseTestConfig()
			if c.wireMB > 0 {
				cfg.MaxResponseBodySizeMB = c.wireMB
			}
			if c.decodedMB > 0 {
				cfg.MaxDecodedResponseBodySizeMB = c.decodedMB
			}
			cl := clientFor(t, cfg, serving(c.status, c.body, c.headers...), emailRule())
			resp := forward(t, cl, http.MethodGet, covered, acceptEncoding("gzip"))
			refused(t, resp.Code, resp.Header(), resp.Body.Bytes())
			if n := counted(t, reader, telemetry.MetricResponseRefusalsTotal, attrRefusalReason,
				c.reason); n != 1 {
				t.Errorf("%s counted %d times", c.reason, n)
			}
		})
	}
}

// TestSwitchingProtocolsRefused: a 101 for a covered host is refused
// whatever its content type. A 101 reaches respond only for an Upgrade
// request, which Forward refuses before sending (TestCoveredUpgradeRefused),
// so this calls respond directly.
func TestSwitchingProtocolsRefused(t *testing.T) {
	reader := captureMetrics(t)
	c, err := New(responseTestConfig(), newRedactor(t, emailRule()), nil)
	if err != nil {
		t.Fatal(err)
	}
	resp := &http.Response{StatusCode: http.StatusSwitchingProtocols,
		Header: http.Header{headerContentType: {"text/plain"}, "Upgrade": {"websocket"}},
		Body:   io.NopCloser(strings.NewReader("contact user@example.com"))}
	err = c.respond(context.Background(), resp, time.Now(), "api.internal:80", "api.internal",
		true)
	if rawpipe.ReasonOf(err, "") != rawpipe.RedactionUnsupported {
		t.Fatalf("a 101: %v, want redaction_unsupported", err)
	}
	if n := counted(t, reader, telemetry.MetricResponseRefusalsTotal, attrRefusalReason,
		refusalUnredactable); n != 1 {
		t.Fatalf("unredactable counted %d times", n)
	}
}

// TestCoveredUpgradeRefused: a WebSocket to a covered host is refused before
// it reaches the destination, so it has no effect there, and the caller gets
// no 101. Through a real server, so a 101 could be spliced if one came back.
func TestCoveredUpgradeRefused(t *testing.T) {
	var reached atomic.Bool
	cfg := responseTestConfig()
	cfg.RequestTimeout = 500 * time.Millisecond
	c := clientFor(t, cfg, func(w http.ResponseWriter, _ *http.Request) {
		reached.Store(true)
		conn, rw, err := http.NewResponseController(w).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = io.WriteString(conn, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"+
			"Connection: Upgrade\r\n\r\ncontact user@example.com\n")
		_, _ = rw.ReadString('\n')
	}, emailRule())
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.Forward(w, r, &url.URL{Scheme: "http", Host: "api.internal:80"})
	}))
	t.Cleanup(front.Close)
	conn, err := net.Dial("tcp", front.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_, _ = io.WriteString(conn, "GET / HTTP/1.1\r\nHost: api.internal\r\n"+
		"Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\n"+
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	refused(t, resp.StatusCode, resp.Header, b)
	if reached.Load() {
		t.Fatal("the upgrade reached the covered destination")
	}
}

// TestBodylessResponsesSkipDecode: a 204, a 304 or a HEAD has no body to
// decode, whatever its Content-Encoding says, and a HEAD keeps the length it
// describes.
func TestBodylessResponsesSkipDecode(t *testing.T) {
	for _, c := range []struct {
		name, method, length string
		status               int
	}{
		{"no content", http.MethodGet, "", http.StatusNoContent},
		{"not modified", http.MethodGet, "", http.StatusNotModified},
		{"head", http.MethodHead, "1234", http.StatusOK},
	} {
		t.Run(c.name, func(t *testing.T) {
			headers := []string{headerContentEncoding, "gzip"}
			if c.length != "" {
				headers = append(headers, headerContentLength, c.length)
			}
			cl := clientFor(t, nil, serving(c.status, nil, headers...), emailRule())
			resp := forward(t, cl, c.method, covered, acceptEncoding("gzip"))
			if resp.Code != c.status {
				t.Fatalf("%d, want %d", resp.Code, c.status)
			}
			if b := resp.Body.Bytes(); len(b) != 0 {
				t.Errorf("%d bytes of body", len(b))
			}
			if got := resp.Header().Get(headerContentLength); got != c.length {
				t.Errorf("Content-Length %q, want %q", got, c.length)
			}
		})
	}
}

// TestValidatorsStrippedAfterRewrite: once the connector rewrites a body,
// the destination's validators and digests no longer describe it and are
// dropped, and range support is never advertised for a covered host. The
// redaction flag says only whether a rule matched: a body re-encoded or
// re-serialized with nothing redacted is not flagged.
func TestValidatorsStrippedAfterRewrite(t *testing.T) {
	validators := []string{"ETag", `"v1"`, "Last-Modified", "Wed, 21 Oct 2015 07:28:00 GMT",
		"Content-MD5", "deadbeef", "Repr-Digest", "sha-256=:deadbeef:", headerAcceptRanges, "bytes"}
	for _, c := range []struct {
		name, contentType, coding, body, want string
		rule                                  redact.Rule
		flagged                               bool
	}{
		{"redacted", "text/plain", "", "contact user@example.com for help",
			"contact [REDACTED] for help", emailRule(), true},
		{"gzip re-encoded, nothing matched", "text/plain", "gzip", "nothing sensitive here",
			"nothing sensitive here", emailRule(), false},
		{"JSON re-serialized, nothing matched", "application/json", "", "{\n  \"status\": \"ok\"\n}",
			`{"status":"ok"}`, structuredEmailRule(), false},
	} {
		t.Run(c.name, func(t *testing.T) {
			wire := []byte(c.body)
			if c.coding == "gzip" {
				wire = gzipped(t, wire)
			}
			headers := append([]string{headerContentType, c.contentType,
				headerContentEncoding, c.coding}, validators...)
			cl := clientFor(t, nil, serving(http.StatusOK, wire, headers...), c.rule)
			resp := forward(t, cl, http.MethodGet, covered, acceptEncoding("gzip"))
			got := resp.Body.Bytes()
			if c.coding == "gzip" {
				got = ungzip(t, got)
			}
			if diff := cmp.Diff(c.want, string(got)); diff != "" {
				t.Errorf("body (-want +got):\n%s", diff)
			}
			for i := 0; i < len(validators); i += 2 {
				if v := resp.Header().Get(validators[i]); v != "" {
					t.Errorf("%s: %q kept after a rewrite", validators[i], v)
				}
			}
			if flagged := resp.Header().Get(headerRedacted) == "true"; flagged != c.flagged {
				t.Errorf("flagged %v, want %v", flagged, c.flagged)
			}
		})
	}
}

// TestUnchangedResponseKeepsItsValidators: a covered body no rule matched,
// sent as it came, keeps its validators and carries no flag.
func TestUnchangedResponseKeepsItsValidators(t *testing.T) {
	c := clientFor(t, nil, serving(http.StatusOK, []byte("nothing sensitive here"),
		headerContentType, "text/plain", "ETag", `"v1"`), emailRule())
	resp := forward(t, c, http.MethodGet, covered, acceptEncoding("identity"))
	if got := resp.Header().Get("ETag"); got != `"v1"` {
		t.Errorf("ETag %q, want it kept", got)
	}
	if resp.Header().Get(headerRedacted) != "" {
		t.Error("an unchanged body is flagged as redacted")
	}
}

// TestContentLengthMatchesFinalBody: Content-Length is the length of the
// bytes sent, whether they were forwarded, redacted in place, re-encoded, or
// arrived chunked with no length at all.
func TestContentLengthMatchesFinalBody(t *testing.T) {
	text := []byte("contact user@example.com for help")
	chunked := func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(headerContentType, "text/plain")
		_, _ = w.Write(text[:10])
		w.(http.Flusher).Flush() //nolint:forcetypeassert // httptest
		_, _ = w.Write(text[10:])
	}
	for _, c := range []struct {
		name string
		h    http.HandlerFunc
		dest string
	}{
		{"forwarded untouched", serving(http.StatusOK, text, headerContentType, "text/plain",
			headerContentEncoding, "zstd"), other},
		{"redacted in place", serving(http.StatusOK, text, headerContentType, "text/plain"), covered},
		{"re-encoded", serving(http.StatusOK, gzipped(t, text), headerContentType, "text/plain",
			headerContentEncoding, "gzip"), covered},
		{"chunked", chunked, covered},
	} {
		t.Run(c.name, func(t *testing.T) {
			cl := clientFor(t, nil, c.h, emailRule())
			resp := forward(t, cl, http.MethodGet, c.dest, acceptEncoding("gzip"))
			b := resp.Body.Bytes()
			if got := resp.Header().Get(headerContentLength); got != strconv.Itoa(len(b)) {
				t.Errorf("Content-Length %q for %d bytes", got, len(b))
			}
		})
	}
}

// TestEncodingMetricRecordedOnEveryPath: every response's coding is
// counted, covered or not, served or refused.
func TestEncodingMetricRecordedOnEveryPath(t *testing.T) {
	text := []byte("contact user@example.com")
	for _, c := range []struct {
		name, coding, dest string
		want               contentCoding
		refused            bool
	}{
		{"uncovered, undecodable", "zstd", other, codingZstd, false},
		{"uncovered, identity", "", other, codingIdentity, false},
		{"covered, gzip", "gzip", covered, codingGzip, false},
		{"covered, undecodable", "deflate", covered, codingDeflate, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			wire := text
			if c.coding == "gzip" {
				wire = gzipped(t, text)
			}
			reader := captureMetrics(t)
			cl := clientFor(t, nil, serving(http.StatusOK, wire, headerContentEncoding, c.coding),
				emailRule())
			resp := forward(t, cl, http.MethodGet, c.dest, acceptEncoding("gzip"))
			if (resp.Code == http.StatusBadGateway) != c.refused {
				t.Fatalf("status %d, refused %v", resp.Code, c.refused)
			}
			if n := counted(t, reader, telemetry.MetricResponseContentEncodingTotal,
				attrContentEncoding, string(c.want)); n != 1 {
				t.Errorf("%s counted %d times", c.want, n)
			}
		})
	}
}

// TestUpstreamCannotForgeTheRedactionFlag: the flag says what the connector
// did, which the far side cannot check against the body. One a destination
// sets is dropped on every path, and the connector sets its own only when a
// rule matched.
func TestUpstreamCannotForgeTheRedactionFlag(t *testing.T) {
	for _, c := range []struct {
		name, dest, body string
		status, flags    int
	}{
		{"uncovered", other, "contact user@example.com", http.StatusOK, 0},
		{"covered, nothing matched", covered, "nothing sensitive here", http.StatusOK, 0},
		{"covered, no body", covered, "", http.StatusNoContent, 0},
		{"covered, matched", covered, "contact user@example.com", http.StatusOK, 1},
	} {
		t.Run(c.name, func(t *testing.T) {
			cl := clientFor(
				t,
				nil,
				serving(c.status, []byte(c.body), headerContentType, "text/plain",
					headerRedacted, "true"),
				emailRule(),
			)
			resp := forward(t, cl, http.MethodGet, c.dest, acceptEncoding("identity"))
			if got := len(resp.Header().Values(headerRedacted)); got != c.flags {
				t.Errorf("%d %s, want %d", got, headerRedacted, c.flags)
			}
		})
	}
}

// TestJSONBodyMustBeOneDocument: with a structured rule in scope, a JSON body
// that is not exactly one document is refused as malformed_json, apart from
// the coding reasons; forwarding it would send it shortened or unscanned.
// A malformed parameter on the media type still makes it JSON.
func TestJSONBodyMustBeOneDocument(t *testing.T) {
	for _, c := range []struct {
		name, contentType, body, want string
	}{
		{"one document", "application/json", `{"email":"user@example.com"}`,
			`{"email":"[REDACTED]"}`},
		{"malformed", "application/json", `{"email":"user@example.com"`, ""},
		{"a second document", "application/json",
			`{"email":"user@example.com"} {"email":"other@example.com"}`, ""},
		{"one document, broken parameter", "application/json; charset",
			`{"email":"user@example.com"}`, `{"email":"[REDACTED]"}`},
		{"trailing junk, broken parameter", "application/json; charset",
			`{"email":"user@example.com"} trailing junk`, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			reader := captureMetrics(t)
			cl := clientFor(t, nil, serving(http.StatusOK, []byte(c.body),
				headerContentType, c.contentType), structuredEmailRule())
			resp := forward(t, cl, http.MethodGet, covered, nil)
			malformed := counted(t, reader, telemetry.MetricResponseRefusalsTotal,
				attrRefusalReason, refusalMalformedJSON)
			if c.want != "" {
				if diff := cmp.Diff(c.want, resp.Body.String()); diff != "" {
					t.Errorf("body (-want +got):\n%s", diff)
				}
				if resp.Header().Get(headerRedacted) != "true" || malformed != 0 {
					t.Errorf("flag %q, %d refusals", resp.Header().Get(headerRedacted), malformed)
				}
				return
			}
			refused(t, resp.Code, resp.Header(), resp.Body.Bytes())
			if malformed != 1 {
				t.Errorf("malformed_json counted %d times", malformed)
			}
			for _, reason := range []string{refusalDecodeFailed, refusalUnsupportedEncoding} {
				if n := counted(t, reader, telemetry.MetricResponseRefusalsTotal,
					attrRefusalReason, reason); n != 0 {
					t.Errorf("%s counted %d times", reason, n)
				}
			}
		})
	}
}

// TestEmptyJSONBodyForwardedInEveryCoding: an empty body has nothing to
// redact, so it is sent as it came in either coding; refusing one would turn
// a coding choice into an error. A gzip member wrapping nothing is bytes on
// the wire, so emptiness shows only after the decode.
func TestEmptyJSONBodyForwardedInEveryCoding(t *testing.T) {
	for _, coding := range []string{"", "gzip"} {
		t.Run("coding "+coding, func(t *testing.T) {
			var wire []byte
			if coding == "gzip" {
				wire = gzipped(t, nil)
			}
			cl := clientFor(t, nil, serving(http.StatusOK, wire, headerContentType,
				"application/json", headerContentEncoding, coding), structuredEmailRule())
			resp := forward(t, cl, http.MethodGet, covered, acceptEncoding(coding))
			if resp.Code != http.StatusOK {
				t.Fatalf("status %d", resp.Code)
			}
			if got := resp.Body.Bytes(); !bytes.Equal(got, wire) {
				t.Errorf("%d bytes sent, want the %d that came", len(got), len(wire))
			}
			if resp.Header().Get(headerRedacted) != "" {
				t.Error("an untouched body is flagged as redacted")
			}
		})
	}
}

// TestUnparseableJSONForwardedWhenNoPerFieldRuleApplies: the same mislabeled
// body, where no structured rule needs it parsed, is forwarded: no rules, a
// byte-level rule only, or a structured rule for another host.
func TestUnparseableJSONForwardedWhenNoPerFieldRuleApplies(t *testing.T) {
	const upstream = `{"email":"user@example.com"} trailing junk`
	elsewhere := structuredEmailRule()
	elsewhere.Hosts = []string{`other\.test`}
	for _, c := range []struct {
		name  string
		rules []redact.Rule
		want  string
	}{
		{"no rules", nil, upstream},
		{"a byte-level rule only", []redact.Rule{emailRule()}, `{"email":"[REDACTED]"} trailing junk`},
		{"a structured rule for another host", []redact.Rule{elsewhere}, upstream},
	} {
		t.Run(c.name, func(t *testing.T) {
			cl := clientFor(t, nil, serving(http.StatusOK, []byte(upstream),
				headerContentType, "application/json"), c.rules...)
			resp := forward(t, cl, http.MethodGet, covered, nil)
			if diff := cmp.Diff(c.want, resp.Body.String()); diff != "" {
				t.Errorf("body (-want +got):\n%s", diff)
			}
		})
	}
}

// TestHostSpellingCannotSkipRedaction: every spelling of a covered host
// (case, a trailing dot, the Unicode and IDNA forms) is covered: its gzip
// body is decoded, redacted and re-encoded, flagged, without range support.
func TestHostSpellingCannotSkipRedaction(t *testing.T) {
	for _, c := range []struct {
		pattern string
		dests   []string
	}{
		{`example\.com`, []string{"http://example.com", "http://EXAMPLE.COM",
			"http://Example.Com", "http://example.com.", "http://EXAMPLE.COM."}},
		{`xn--bcher-kva\.example`, []string{"http://bücher.example", "http://BÜCHER.EXAMPLE",
			"http://bücher.example.", "http://xn--bcher-kva.example"}},
	} {
		rule := emailRule()
		rule.Hosts = []string{c.pattern}
		for _, dest := range c.dests {
			t.Run(dest, func(t *testing.T) {
				cl := clientFor(t, nil, serving(http.StatusOK,
					gzipped(t, []byte(`{"message":"contact a@b.com"}`)),
					headerContentType, "application/json", headerContentEncoding, "gzip",
					headerAcceptRanges, "bytes"), rule)
				resp := forward(t, cl, http.MethodGet, dest, acceptEncoding("gzip"))
				want := `{"message":"contact [REDACTED]"}`
				if diff := cmp.Diff(want, string(ungzip(t, resp.Body.Bytes()))); diff != "" {
					t.Errorf("decoded body (-want +got):\n%s", diff)
				}
				if resp.Header().Get(headerRedacted) != "true" ||
					resp.Header().Get(headerAcceptRanges) != "" {
					t.Errorf("headers %v, want the flag and no Accept-Ranges", resp.Header())
				}
			})
		}
	}
}
