package executor

import (
	"bytes"
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/InteractionLabs/traversal-connector/connector-lib/connector"
	pb "github.com/InteractionLabs/traversal-connector/connector-lib/gen/connector/v1"
	"github.com/InteractionLabs/traversal-connector/internal/config"
	"github.com/InteractionLabs/traversal-connector/internal/redact"
	"github.com/InteractionLabs/traversal-connector/internal/telemetry"
)

const emailPattern = `[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`

// emailRule redacts any email address anywhere in the body.
func emailRule() redact.Rule {
	return redact.Rule{
		Name:        "email",
		Type:        "regex",
		Pattern:     emailPattern,
		Replacement: "[REDACTED]",
	}
}

func responseTestConfig() *config.Config {
	return &config.Config{
		RequestTimeout:               5 * time.Second,
		MaxRequestBodySizeMB:         32,
		MaxResponseBodySizeMB:        32,
		MaxDecodedResponseBodySizeMB: 256,
	}
}

// newRedactor compiles rules into a live Redactor. Passing none yields a
// redactor no host matches, which is the "no rules configured" path.
func newRedactor(t *testing.T, rules ...redact.Rule) *redact.Redactor {
	t.Helper()
	r := redact.NewRedactor()
	if err := r.Update(&redact.RulesFile{Version: "v1", Rules: rules}); err != nil {
		t.Fatalf("redactor.Update() error: %v", err)
	}
	return r
}

func newExecutor(t *testing.T, cfg *config.Config, r *redact.Redactor) *Executor {
	t.Helper()
	exec, err := NewExecutor(cfg, r)
	if err != nil {
		t.Fatalf("NewExecutor() failed: %v", err)
	}
	return exec
}

// captureMetrics installs a collectable meter provider for the duration of the
// test. Instruments are created when an executor is constructed, so this has to
// run before newExecutor.
func captureMetrics(t *testing.T) func() metricdata.ResourceMetrics {
	t.Helper()
	reader := sdkmetric.NewManualReader()
	previous := otel.GetMeterProvider()
	otel.SetMeterProvider(sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader)))
	t.Cleanup(func() { otel.SetMeterProvider(previous) })

	return func() metricdata.ResourceMetrics {
		t.Helper()
		var collected metricdata.ResourceMetrics
		if err := reader.Collect(context.Background(), &collected); err != nil {
			t.Fatalf("collect metrics: %v", err)
		}
		return collected
	}
}

// counterValue sums the int64 counter named name across the data points
// carrying every attribute in want.
func counterValue(
	t *testing.T,
	collected metricdata.ResourceMetrics,
	name string,
	want ...attribute.KeyValue,
) int64 {
	t.Helper()
	var total int64
	for _, scope := range collected.ScopeMetrics {
		for _, recorded := range scope.Metrics {
			if recorded.Name != name {
				continue
			}
			sum, ok := recorded.Data.(metricdata.Sum[int64])
			if !ok {
				t.Fatalf("metric %q holds %T, want Sum[int64]", name, recorded.Data)
			}
			for _, point := range sum.DataPoints {
				if hasAttributes(point.Attributes, want) {
					total += point.Value
				}
			}
		}
	}
	return total
}

func hasAttributes(set attribute.Set, want []attribute.KeyValue) bool {
	for _, kv := range want {
		got, ok := set.Value(kv.Key)
		if !ok || got != kv.Value {
			return false
		}
	}
	return true
}

func gzipped(t *testing.T, src []byte) []byte {
	t.Helper()
	encoded, err := encodeGzip(src)
	if err != nil {
		t.Fatalf("encodeGzip() error: %v", err)
	}
	return encoded
}

func ungzip(t *testing.T, src []byte) []byte {
	t.Helper()
	reader, err := gzip.NewReader(bytes.NewReader(src))
	if err != nil {
		t.Fatalf("response body is not a gzip stream: %v", err)
	}
	defer reader.Close()

	decoded, err := readLimited(reader, 0)
	if err != nil {
		t.Fatalf("cannot inflate response body: %v", err)
	}
	return decoded
}

// gzipServer serves body as gzip, echoing back that coding.
func gzipServer(t *testing.T, contentType string, body []byte) *httptest.Server {
	t.Helper()
	encoded := gzipped(t, body)
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(headerContentType, contentType)
		w.Header().Set(headerContentEncoding, "gzip")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(encoded)
	}))
}

// getWithAcceptEncoding mirrors the controller forwarding a caller's negotiated
// coding, which is what stops Go's transport from decompressing on its own.
func getWithAcceptEncoding(url, acceptEncoding string) *pb.HttpRequest {
	req := &pb.HttpRequest{Method: http.MethodGet, Url: url}
	if acceptEncoding != "" {
		req.Headers = []*pb.Header{{Key: "Accept-Encoding", Value: acceptEncoding}}
	}
	return req
}

func TestExecute_GzipResponseRedactedAndReEncoded(t *testing.T) {
	server := gzipServer(t, "text/plain", []byte("contact user@example.com for help"))
	defer server.Close()

	exec := newExecutor(t, responseTestConfig(), newRedactor(t, emailRule()))

	resp, err := exec.Execute(
		context.Background(), getWithAcceptEncoding(server.URL, "gzip"),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	encoding, _ := findHeader(resp.Headers, headerContentEncoding)
	if diff := cmp.Diff("gzip", encoding); diff != "" {
		t.Errorf("Content-Encoding mismatch (-want +got):\n%s", diff)
	}

	want := "contact [REDACTED] for help"
	if diff := cmp.Diff(want, string(ungzip(t, resp.Body))); diff != "" {
		t.Errorf("decoded body mismatch (-want +got):\n%s", diff)
	}
	if bytes.Contains(resp.Body, []byte("user@example.com")) {
		t.Error("the plaintext address survived in the encoded body")
	}
}

func TestExecute_IdentityResponseRedactedInPlace(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(headerContentType, "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("contact user@example.com for help"))
	}))
	defer server.Close()

	exec := newExecutor(t, responseTestConfig(), newRedactor(t, emailRule()))

	resp, err := exec.Execute(
		context.Background(), getWithAcceptEncoding(server.URL, "identity"),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if diff := cmp.Diff("contact [REDACTED] for help", string(resp.Body)); diff != "" {
		t.Errorf("body mismatch (-want +got):\n%s", diff)
	}
	if encoding, ok := findHeader(resp.Headers, headerContentEncoding); ok {
		t.Errorf("Content-Encoding should stay absent, got %q", encoding)
	}
}

func TestExecute_StructuredRuleFiresOnGzipResponse(t *testing.T) {
	const upstream = `{"message":"contact a@b.com","safe":"contact c@d.com"}`
	server := gzipServer(t, "application/json", []byte(upstream))
	defer server.Close()

	exec := newExecutor(t, responseTestConfig(), newRedactor(t, redact.Rule{
		Name:         "email",
		Type:         "regex-structured-data",
		Pattern:      emailPattern,
		Replacement:  "[REDACTED]",
		RedactFields: []string{"message"},
	}))

	resp, err := exec.Execute(
		context.Background(), getWithAcceptEncoding(server.URL, "gzip"),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := `{"message":"contact [REDACTED]","safe":"contact c@d.com"}`
	if diff := cmp.Diff(want, string(ungzip(t, resp.Body))); diff != "" {
		t.Errorf("decoded body mismatch (-want +got):\n%s", diff)
	}
}

func TestExecute_TransportDecodesWhenCallerOmitsAcceptEncoding(t *testing.T) {
	// With no caller coding to forward, Go's transport negotiates gzip itself and
	// hands back plaintext, so the connector sees an identity body.
	server := gzipServer(t, "text/plain", []byte("contact user@example.com"))
	defer server.Close()

	exec := newExecutor(t, responseTestConfig(), newRedactor(t, emailRule()))

	resp, err := exec.Execute(context.Background(), getWithAcceptEncoding(server.URL, ""))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if diff := cmp.Diff("contact [REDACTED]", string(resp.Body)); diff != "" {
		t.Errorf("body mismatch (-want +got):\n%s", diff)
	}
}

func TestExecute_NoRules_UnsupportedEncodingForwardedUntouched(t *testing.T) {
	upstream := []byte("contact user@example.com for help")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(headerContentType, "text/plain")
		w.Header().Set(headerContentEncoding, "zstd")
		w.Header().Set(headerAcceptRanges, "bytes")
		w.Header().Set("ETag", `"v1"`)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(upstream)
	}))
	defer server.Close()

	exec := newExecutor(t, responseTestConfig(), newRedactor(t))

	resp, err := exec.Execute(
		context.Background(), getWithAcceptEncoding(server.URL, "zstd"),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if diff := cmp.Diff(upstream, resp.Body); diff != "" {
		t.Errorf("body mismatch (-want +got):\n%s", diff)
	}
	for _, header := range []string{"ETag", headerAcceptRanges} {
		if _, ok := findHeader(resp.Headers, header); !ok {
			t.Errorf("%s should survive on a host no rule targets", header)
		}
	}
	if _, ok := findHeader(resp.Headers, headerRedacted); ok {
		t.Error("an untouched response should not be flagged as redacted")
	}
}

func TestExecute_Rules_UnsupportedEncodingRefused(t *testing.T) {
	collect := captureMetrics(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(headerContentEncoding, "zstd")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("contact user@example.com"))
	}))
	defer server.Close()

	exec := newExecutor(t, responseTestConfig(), newRedactor(t, emailRule()))

	resp, err := exec.Execute(
		context.Background(), getWithAcceptEncoding(server.URL, "zstd"),
	)
	if err == nil {
		t.Fatalf("expected a refusal, got a response of %d bytes", len(resp.Body))
	}
	if diff := cmp.Diff(
		connector.ErrorCodeUnsupportedEncoding, connector.ErrorCodeFor(err),
	); diff != "" {
		t.Errorf("error code mismatch (-want +got):\n%s", diff)
	}

	refusals := counterValue(t, collect(), telemetry.MetricResponseRefusalsTotal,
		attribute.String(attrRefusalReason, refusalUnsupportedEncoding))
	if diff := cmp.Diff(int64(1), refusals); diff != "" {
		t.Errorf("refusal count mismatch (-want +got):\n%s", diff)
	}
}

func TestExecute_RefusedResponses(t *testing.T) {
	oversized := bytes.Repeat([]byte("a"), 2<<20)
	truncated := gzipped(t, bytes.Repeat([]byte("contact user@example.com "), 100))

	tests := []struct {
		name            string
		contentEncoding string
		body            []byte
		status          int
		decodedLimitMB  int64
		wantReason      string
	}{
		{
			name:            "truncated gzip",
			contentEncoding: "gzip",
			body:            truncated[:len(truncated)/2],
			wantReason:      refusalDecodeFailed,
		},
		{
			name:            "decompression bomb",
			contentEncoding: "gzip",
			body:            nil, // replaced below with a compressed bomb
			decodedLimitMB:  1,
			wantReason:      refusalDecodedTooLarge,
		},
		{
			name:            "stacked encoding",
			contentEncoding: "gzip, br",
			body:            truncated,
			wantReason:      refusalUnsupportedEncoding,
		},
		{
			name:            "partial content",
			contentEncoding: "",
			body:            []byte("contact user@example.com"),
			status:          http.StatusPartialContent,
			wantReason:      refusalPartialContent,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := tt.body
			if body == nil {
				body = gzipped(t, oversized)
			}
			status := tt.status
			if status == 0 {
				status = http.StatusOK
			}

			collect := captureMetrics(t)

			server := httptest.NewServer(
				http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					if tt.contentEncoding != "" {
						w.Header().Set(headerContentEncoding, tt.contentEncoding)
					}
					w.WriteHeader(status)
					_, _ = w.Write(body)
				}),
			)
			defer server.Close()

			cfg := responseTestConfig()
			if tt.decodedLimitMB > 0 {
				cfg.MaxDecodedResponseBodySizeMB = tt.decodedLimitMB
			}
			exec := newExecutor(t, cfg, newRedactor(t, emailRule()))

			resp, err := exec.Execute(
				context.Background(), getWithAcceptEncoding(server.URL, "gzip"),
			)
			if err == nil {
				t.Fatalf("expected a refusal, got a response of %d bytes", len(resp.Body))
			}

			refusals := counterValue(t, collect(), telemetry.MetricResponseRefusalsTotal,
				attribute.String(attrRefusalReason, tt.wantReason))
			if diff := cmp.Diff(int64(1), refusals); diff != "" {
				t.Errorf("refusal count for %q mismatch (-want +got):\n%s", tt.wantReason, diff)
			}
		})
	}
}

func TestExecute_WireLimitRefusesOversizedBody(t *testing.T) {
	collect := captureMetrics(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(bytes.Repeat([]byte("a"), 2<<20))
	}))
	defer server.Close()

	cfg := responseTestConfig()
	cfg.MaxResponseBodySizeMB = 1
	// No rules, to prove the wire ceiling guards memory on every path.
	exec := newExecutor(t, cfg, newRedactor(t))

	if _, err := exec.Execute(
		context.Background(), getWithAcceptEncoding(server.URL, "identity"),
	); err == nil {
		t.Fatal("expected a refusal for a body past the wire limit")
	}

	refusals := counterValue(t, collect(), telemetry.MetricResponseRefusalsTotal,
		attribute.String(attrRefusalReason, refusalBodyTooLarge))
	if diff := cmp.Diff(int64(1), refusals); diff != "" {
		t.Errorf("refusal count mismatch (-want +got):\n%s", diff)
	}
}

func TestExecute_BodylessResponsesSkipDecode(t *testing.T) {
	tests := []struct {
		name              string
		method            string
		status            int
		upstreamLength    string
		wantContentLength string
	}{
		{name: "no content", method: http.MethodGet, status: http.StatusNoContent},
		{name: "not modified", method: http.MethodGet, status: http.StatusNotModified},
		{
			name:              "head keeps the length it describes",
			method:            http.MethodHead,
			status:            http.StatusOK,
			upstreamLength:    "1234",
			wantContentLength: "1234",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(
				http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					// A coding the connector would have to decode, proving it
					// never tries on a body that does not exist.
					w.Header().Set(headerContentEncoding, "gzip")
					if tt.upstreamLength != "" {
						w.Header().Set(headerContentLength, tt.upstreamLength)
					}
					w.WriteHeader(tt.status)
				}),
			)
			defer server.Close()

			exec := newExecutor(t, responseTestConfig(), newRedactor(t, emailRule()))

			resp, err := exec.Execute(context.Background(), &pb.HttpRequest{
				Method:  tt.method,
				Url:     server.URL,
				Headers: []*pb.Header{{Key: "Accept-Encoding", Value: "gzip"}},
			})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(resp.Body) != 0 {
				t.Errorf("expected an empty body, got %d bytes", len(resp.Body))
			}

			got, ok := findHeader(resp.Headers, headerContentLength)
			if tt.wantContentLength == "" {
				if ok {
					t.Errorf("Content-Length should stay absent, got %q", got)
				}
				return
			}
			if diff := cmp.Diff(tt.wantContentLength, got); diff != "" {
				t.Errorf("Content-Length mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestExecute_ContentDependentHeadersStrippedOnMatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(headerContentType, "text/plain")
		w.Header().Set("ETag", `"v1"`)
		w.Header().Set("Last-Modified", "Wed, 21 Oct 2015 07:28:00 GMT")
		w.Header().Set("Content-MD5", "deadbeef")
		w.Header().Set("Repr-Digest", "sha-256=:deadbeef:")
		w.Header().Set(headerAcceptRanges, "bytes")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("contact user@example.com for help"))
	}))
	defer server.Close()

	exec := newExecutor(t, responseTestConfig(), newRedactor(t, emailRule()))

	resp, err := exec.Execute(
		context.Background(), getWithAcceptEncoding(server.URL, "identity"),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, header := range []string{
		"ETag", "Last-Modified", "Content-MD5", "Repr-Digest", headerAcceptRanges,
	} {
		if value, ok := findHeader(resp.Headers, header); ok {
			t.Errorf("%s should be stripped from a redacted response, got %q", header, value)
		}
	}

	flag, ok := findHeader(resp.Headers, headerRedacted)
	if !ok {
		t.Fatal("a changed body should carry the redaction flag")
	}
	if diff := cmp.Diff("true", flag); diff != "" {
		t.Errorf("redaction flag mismatch (-want +got):\n%s", diff)
	}
}

func TestExecute_GzipNoMatchStripsHeadersWithoutFlag(t *testing.T) {
	upstream := []byte("nothing sensitive here")
	server := gzipServer(t, "text/plain", upstream)
	defer server.Close()

	// The rule targets this host but matches nothing in the body.
	exec := newExecutor(t, responseTestConfig(), newRedactor(t, emailRule()))

	resp, err := exec.Execute(
		context.Background(), getWithAcceptEncoding(server.URL, "gzip"),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if diff := cmp.Diff(upstream, ungzip(t, resp.Body)); diff != "" {
		t.Errorf("decoded body mismatch (-want +got):\n%s", diff)
	}
	if _, ok := findHeader(resp.Headers, headerRedacted); ok {
		t.Error("an unchanged body should not carry the redaction flag")
	}
	// The re-encode produced different bytes for the same plaintext, so a
	// fingerprint of the upstream representation no longer describes them.
	if _, ok := findHeader(resp.Headers, "ETag"); ok {
		t.Error("ETag should be stripped from a re-encoded response")
	}
}

func TestExecute_EncodingMetricRecordedOnEveryPath(t *testing.T) {
	tests := []struct {
		name        string
		encoding    string
		rules       []redact.Rule
		wantCoding  contentCoding
		wantRefusal bool
	}{
		{
			name:       "no rules and an encoding nothing can decode",
			encoding:   "zstd",
			wantCoding: codingZstd,
		},
		{
			name:       "no rules and no encoding",
			wantCoding: codingIdentity,
		},
		{
			name:       "rules and gzip",
			encoding:   "gzip",
			rules:      []redact.Rule{emailRule()},
			wantCoding: codingGzip,
		},
		{
			name:        "rules and an encoding nothing can decode",
			encoding:    "deflate",
			rules:       []redact.Rule{emailRule()},
			wantCoding:  codingDeflate,
			wantRefusal: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := []byte("contact user@example.com")
			if tt.wantCoding == codingGzip {
				body = gzipped(t, body)
			}

			collect := captureMetrics(t)

			server := httptest.NewServer(
				http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					if tt.encoding != "" {
						w.Header().Set(headerContentEncoding, tt.encoding)
					}
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write(body)
				}),
			)
			defer server.Close()

			exec := newExecutor(t, responseTestConfig(), newRedactor(t, tt.rules...))

			_, err := exec.Execute(
				context.Background(), getWithAcceptEncoding(server.URL, "gzip"),
			)
			if tt.wantRefusal && err == nil {
				t.Fatal("expected a refusal")
			}
			if !tt.wantRefusal && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			recorded := counterValue(t, collect(),
				telemetry.MetricResponseContentEncodingTotal,
				attribute.String(attrContentEncoding, string(tt.wantCoding)))
			if diff := cmp.Diff(int64(1), recorded); diff != "" {
				t.Errorf("encoding count for %q mismatch (-want +got):\n%s", tt.wantCoding, diff)
			}
		})
	}
}

func TestExecute_ContentLengthMatchesFinalBody(t *testing.T) {
	tests := []struct {
		name     string
		encoding string
		rules    []redact.Rule
	}{
		{name: "forwarded untouched", encoding: "zstd"},
		{name: "redacted in place", rules: []redact.Rule{emailRule()}},
		{name: "re-encoded after redaction", encoding: "gzip", rules: []redact.Rule{emailRule()}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := []byte("contact user@example.com for help")
			if tt.encoding == "gzip" {
				body = gzipped(t, body)
			}

			server := httptest.NewServer(
				http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.Header().Set(headerContentType, "text/plain")
					if tt.encoding != "" {
						w.Header().Set(headerContentEncoding, tt.encoding)
					}
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write(body)
				}),
			)
			defer server.Close()

			exec := newExecutor(t, responseTestConfig(), newRedactor(t, tt.rules...))

			resp, err := exec.Execute(
				context.Background(), getWithAcceptEncoding(server.URL, "gzip"),
			)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			got, ok := findHeader(resp.Headers, headerContentLength)
			if !ok {
				t.Fatal("Content-Length header missing from response")
			}
			if diff := cmp.Diff(strconv.Itoa(len(resp.Body)), got); diff != "" {
				t.Errorf("Content-Length mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestExecute_ReserializedJSONStripsHeadersWithoutFlag(t *testing.T) {
	// The structured path re-serializes the document, so a pretty-printed body
	// comes back with different bytes even when no rule matched. The validators
	// have to go, because they describe the upstream's formatting. The redaction
	// flag must not, because nothing was redacted.
	upstream := "{\n  \"status\": \"ok\"\n}"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(headerContentType, "application/json")
		w.Header().Set("ETag", `"v1"`)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(upstream))
	}))
	defer server.Close()

	exec := newExecutor(t, responseTestConfig(), newRedactor(t, redact.Rule{
		Name:        "email",
		Type:        "regex-structured-data",
		Pattern:     emailPattern,
		Replacement: "[REDACTED]",
	}))

	resp, err := exec.Execute(
		context.Background(), getWithAcceptEncoding(server.URL, "identity"),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if diff := cmp.Diff(`{"status":"ok"}`, string(resp.Body)); diff != "" {
		t.Errorf("body mismatch (-want +got):\n%s", diff)
	}
	if _, ok := findHeader(resp.Headers, headerRedacted); ok {
		t.Error("re-serializing a body is not redaction and must not set the flag")
	}
	if value, ok := findHeader(resp.Headers, "ETag"); ok {
		t.Errorf("ETag no longer describes the body and should be stripped, got %q", value)
	}

	length, ok := findHeader(resp.Headers, headerContentLength)
	if !ok {
		t.Fatal("Content-Length header missing from response")
	}
	if diff := cmp.Diff(strconv.Itoa(len(resp.Body)), length); diff != "" {
		t.Errorf("Content-Length mismatch (-want +got):\n%s", diff)
	}
}

func TestExecute_UnchangedResponseKeepsItsValidators(t *testing.T) {
	// A rule targets the host but matches nothing, and nothing re-encodes the
	// body, so the upstream's own headers still describe the bytes exactly.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(headerContentType, "text/plain")
		w.Header().Set("ETag", `"v1"`)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("nothing sensitive here"))
	}))
	defer server.Close()

	exec := newExecutor(t, responseTestConfig(), newRedactor(t, emailRule()))

	resp, err := exec.Execute(
		context.Background(), getWithAcceptEncoding(server.URL, "identity"),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if value, _ := findHeader(resp.Headers, "ETag"); value != `"v1"` {
		t.Errorf("ETag should survive an untouched body, got %q", value)
	}
	if _, ok := findHeader(resp.Headers, headerRedacted); ok {
		t.Error("an unchanged body should not carry the redaction flag")
	}
}
