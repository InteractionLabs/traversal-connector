package executor

import "testing"

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
		{
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
