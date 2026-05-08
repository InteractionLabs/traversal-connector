package executor

import (
	"net/http"
	"testing"

	pb "github.com/InteractionLabs/traversal-connector/connector-lib/gen/connector/v1"
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
			got := hostFromURL(tt.rawURL)
			if got != tt.want {
				t.Errorf("hostFromURL(%q) = %q, want %q", tt.rawURL, got, tt.want)
			}
		})
	}
}

func TestNormaliseMIME(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{"json with charset", "application/json; charset=utf-8", "application/json"},
		{"plain json", "application/json", "application/json"},
		{"plain text", "text/plain", "text/plain"},
		{"text with charset", "text/plain; charset=utf-8", "text/plain"},
		{"form encoded", "application/x-www-form-urlencoded", "application/x-www-form-urlencoded"},
		{"multipart", "multipart/form-data; boundary=----FormBoundary", "multipart/form-data"},
		{"empty", "", "unknown"},
		{"unparseable lowercased", "GARBAGE/TYPE STUFF", "garbage/type stuff"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normaliseMIME(tt.raw)
			if got != tt.want {
				t.Errorf("normaliseMIME(%q) = %q, want %q", tt.raw, got, tt.want)
			}
		})
	}
}

func TestContentTypeFromGoHeaders(t *testing.T) {
	tests := []struct {
		name string
		h    http.Header
		want string
	}{
		{
			"json with charset",
			http.Header{"Content-Type": []string{"application/json; charset=utf-8"}},
			"application/json",
		},
		{
			"absent header",
			http.Header{},
			"unknown",
		},
		{
			// net/http always stores headers in canonical form, so in
			// production this case never arises. Test canonical form instead.
			"canonical key",
			http.Header{"Content-Type": []string{"text/plain"}},
			"text/plain",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := contentTypeFromGoHeaders(tt.h)
			if got != tt.want {
				t.Errorf("contentTypeFromGoHeaders() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestContentTypeFromProtoHeaders(t *testing.T) {
	tests := []struct {
		name    string
		headers []*pb.Header
		want    string
	}{
		{
			"json",
			[]*pb.Header{{Key: "Content-Type", Value: "application/json"}},
			"application/json",
		},
		{
			"case-insensitive key",
			[]*pb.Header{{Key: "content-type", Value: "application/json"}},
			"application/json",
		},
		{
			"with charset param",
			[]*pb.Header{{Key: "Content-Type", Value: "application/json; charset=utf-8"}},
			"application/json",
		},
		{
			"absent",
			[]*pb.Header{{Key: "Accept", Value: "application/json"}},
			"unknown",
		},
		{
			"nil slice",
			nil,
			"unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := contentTypeFromProtoHeaders(tt.headers)
			if got != tt.want {
				t.Errorf("contentTypeFromProtoHeaders() = %q, want %q", got, tt.want)
			}
		})
	}
}
