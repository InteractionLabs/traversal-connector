package executor

import "testing"

func TestHostnameFromURL(t *testing.T) {
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
			name:   "port is stripped",
			rawURL: "https://api.example.com:8443/path",
			want:   "api.example.com",
		},
		{ //nolint:gosec // G101: test fixture, intentional userinfo
			name:   "userinfo is stripped",
			rawURL: "https://user:pass@host.example.com/path",
			want:   "host.example.com",
		},
		{
			name:   "IPv6 brackets are stripped",
			rawURL: "http://[2001:db8::1]:9090/health",
			want:   "2001:db8::1",
		},
		{
			name:   "empty string",
			rawURL: "",
			want:   "",
		},
		{
			name:   "bare path (no host)",
			rawURL: "/just/a/path",
			want:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hostnameFromURL(tt.rawURL)
			if got != tt.want {
				t.Errorf("hostnameFromURL(%q) = %q, want %q", tt.rawURL, got, tt.want)
			}
		})
	}
}
