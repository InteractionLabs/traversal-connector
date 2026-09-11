package telemetry

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"testing"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func TestHostFromURL(t *testing.T) {
	tests := []struct {
		name   string
		rawURL string
		want   string
	}{
		{
			name:   "full https URL",
			rawURL: "https://httpbin.org/get",
			want:   "httpbin.org",
		},
		{
			name:   "https URL with port",
			rawURL: "https://api.example.com:8443/path",
			want:   "api.example.com:8443",
		},
		{
			name:   "http URL with path and query",
			rawURL: "http://example.com/api/v1?key=value",
			want:   "example.com",
		},
		{ //nolint:gosec // G101: test fixture, intentional userinfo
			name:   "URL with userinfo",
			rawURL: "https://user:pass@host.example.com/path",
			want:   "host.example.com",
		},
		{
			name:   "empty string",
			rawURL: "",
			want:   "unknown",
		},
		{
			name:   "bare path (no host)",
			rawURL: "/just/a/path",
			want:   "unknown",
		},
		{
			name:   "malformed URL",
			rawURL: "://bad",
			want:   "unknown",
		},
		{
			name:   "IP address with port",
			rawURL: "http://192.168.1.1:9090/health",
			want:   "192.168.1.1:9090",
		},
		{
			name:   "localhost",
			rawURL: "http://localhost:8080/test",
			want:   "localhost:8080",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := HostFromURL(tt.rawURL)
			if got != tt.want {
				t.Errorf("HostFromURL(%q) = %q, want %q", tt.rawURL, got, tt.want)
			}
		})
	}
}

func TestSanitizeError_NilStaysNil(t *testing.T) {
	if got := SanitizeError(nil); got != nil {
		t.Errorf("SanitizeError(nil) = %v, want nil", got)
	}
}

func TestSanitizeError(t *testing.T) {
	const canary = "canary-4d81ba07"

	transportErr := &url.Error{
		Op:  "Get",
		URL: "https://api.internal:8443/orders/42?token=" + canary,
		Err: errors.New("dial tcp 10.0.0.5:8443: connect: connection refused"),
	}

	tests := []struct {
		name string
		err  error
		want string
	}{
		{
			name: "error carrying no URL is unchanged",
			err:  errors.New("body size 10 exceeds limit 5"),
			want: "body size 10 exceeds limit 5",
		},
		{
			name: "transport error keeps only the origin",
			err:  transportErr,
			want: `Get "https://api.internal:8443": ` +
				"dial tcp 10.0.0.5:8443: connect: connection refused",
		},
		{
			name: "wrapping does not hide the URL",
			err:  fmt.Errorf("upstream request failed: %w", transportErr),
			want: `upstream request failed: Get "https://api.internal:8443": ` +
				"dial tcp 10.0.0.5:8443: connect: connection refused",
		},
		{
			name: "nested targets are each reduced",
			err: &url.Error{
				Op:  "Get",
				URL: "https://first.internal/a?token=" + canary,
				Err: &url.Error{
					Op:  "Get",
					URL: "https://second.internal/b?token=" + canary,
					Err: errors.New("boom"),
				},
			},
			want: `Get "https://first.internal": ` +
				`Get "https://second.internal": boom`,
		},
		{
			name: "joined errors are each reduced",
			err: errors.Join(
				&url.Error{
					Op:  "Get",
					URL: "https://one.internal/a?token=" + canary,
					Err: errors.New("first"),
				},
				&url.Error{
					Op:  "Get",
					URL: "https://two.internal/b?token=" + canary,
					Err: errors.New("second"),
				},
			),
			want: "Get \"https://one.internal\": first\n" +
				`Get "https://two.internal": second`,
		},
		{
			name: "credentials in the authority are dropped",
			err: &url.Error{
				Op:  "Get",
				URL: "https://user:hunter2@api.internal/a?token=" + canary,
				Err: errors.New("boom"),
			},
			want: `Get "https://api.internal": boom`,
		},
		{
			name: "target that does not parse is replaced wholesale",
			err: &url.Error{
				Op:  "parse",
				URL: "://nope?token=" + canary,
				Err: errors.New("missing protocol scheme"),
			},
			want: `parse "unknown": missing protocol scheme`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SanitizeError(tt.err).Error()
			if got != tt.want {
				t.Errorf("SanitizeError() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRecordError_ReducesOnTheSpanAndInTheReturnedCopy(t *testing.T) {
	const canary = "canary-77bd0e91"

	recorder := tracetest.NewSpanRecorder()
	provider := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder))
	_, span := provider.Tracer("test").Start(context.Background(), "test")

	returned := RecordError(span, &url.Error{
		Op:  "Get",
		URL: "https://api.internal/orders?token=" + canary,
		Err: errors.New("connection refused"),
	})
	span.End()

	if strings.Contains(returned.Error(), canary) {
		t.Errorf("returned copy still carries the query: %v", returned)
	}

	ended := recorder.Ended()
	if len(ended) != 1 {
		t.Fatalf("recorded %d spans, want 1", len(ended))
	}

	recorded := map[string]string{}
	for _, event := range ended[0].Events() {
		if event.Name != eventException {
			continue
		}
		for _, attr := range event.Attributes {
			recorded[string(attr.Key)] = attr.Value.String()
		}
	}
	if len(recorded) == 0 {
		t.Fatal("no exception event was recorded on the span")
	}

	if strings.Contains(recorded[attrExceptionMessage], canary) {
		t.Errorf("span event still carries the query: %q", recorded[attrExceptionMessage])
	}

	// Reducing the message must not cost the class. Every failure would otherwise
	// export the same type and stop being groupable.
	if got := recorded[attrExceptionType]; got != "*url.Error" {
		t.Errorf("exception type = %q, want the original error's class", got)
	}
}

// A URL that url.Parse rejects must not survive by falling through the
// substitution: the error text is the one place its query would otherwise
// remain readable.
func TestSanitizeError_ParseFailureDropsQuery(t *testing.T) {
	const canary = "canary-1a2b3c4d"

	//nolint:staticcheck // SA1007: an unparseable URL is the fixture
	_, err := url.Parse("http://example.com/\x7f?token=" + canary)
	if err == nil {
		t.Fatal("url.Parse accepted a control character, test fixture is stale")
	}

	got := SanitizeError(err).Error()
	if strings.Contains(got, canary) {
		t.Errorf("SanitizeError() = %q, still carries the query", got)
	}
}
