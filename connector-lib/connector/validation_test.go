package connector

import (
	"net/http"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/testing/protocmp"

	pb "github.com/InteractionLabs/traversal-connector/connector-lib/gen/connector/v1"
)

func TestValidateTargetURL(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		wantErr bool
		errMsg  string
	}{
		{
			name:    "valid http URL",
			url:     "http://example.com",
			wantErr: false,
		},
		{
			name:    "valid https URL",
			url:     "https://example.com/path",
			wantErr: false,
		},
		{
			name:    "valid URL with port",
			url:     "https://example.com:8080",
			wantErr: false,
		},
		{
			name:    "empty URL",
			url:     "",
			wantErr: true,
			errMsg:  string(ErrorCodeMissingTargetURL),
		},
		{
			name:    "invalid scheme",
			url:     "ftp://example.com",
			wantErr: true,
			errMsg:  "invalid URL scheme",
		},
		{
			name:    "missing scheme",
			url:     "example.com",
			wantErr: true,
			errMsg:  "invalid URL scheme",
		},
		{
			name:    "invalid URL format",
			url:     "http://[::1:bad",
			wantErr: true,
			errMsg:  "invalid URL format",
		},
		{
			name:    "missing host",
			url:     "http://",
			wantErr: true,
			errMsg:  "missing host",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateTargetURL(tt.url)
			if tt.wantErr {
				if err == nil {
					t.Error("ValidateTargetURL() expected error, got nil")
					return
				}
				if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf(
						"ValidateTargetURL() error = %v, want error containing %v",
						err,
						tt.errMsg,
					)
				}
			} else {
				if err != nil {
					t.Errorf("ValidateTargetURL() error = %v, want nil", err)
				}
			}
		})
	}
}

func TestFilterHopByHopHeaders(t *testing.T) {
	tests := []struct {
		name     string
		headers  []*pb.Header
		expected []*pb.Header
	}{
		{
			name:     "empty headers",
			headers:  []*pb.Header{},
			expected: []*pb.Header{},
		},
		{
			name:     "nil headers",
			headers:  nil,
			expected: nil,
		},
		{
			name: "no hop-by-hop headers",
			headers: []*pb.Header{
				{Key: "Content-Type", Value: "application/json"},
				{Key: "Accept", Value: "application/json"},
			},
			expected: []*pb.Header{
				{Key: "Content-Type", Value: "application/json"},
				{Key: "Accept", Value: "application/json"},
			},
		},
		{
			name: "filter hop-by-hop headers",
			headers: []*pb.Header{
				{Key: "Content-Type", Value: "application/json"},
				{Key: "Connection", Value: "keep-alive"},
				{Key: "Accept", Value: "application/json"},
				{Key: "Transfer-Encoding", Value: "chunked"},
				{Key: "Upgrade", Value: "websocket"},
			},
			expected: []*pb.Header{
				{Key: "Content-Type", Value: "application/json"},
				{Key: "Accept", Value: "application/json"},
			},
		},
		{
			name: "case insensitive filtering",
			headers: []*pb.Header{
				{Key: "Content-Type", Value: "application/json"},
				{Key: "CONNECTION", Value: "keep-alive"},
				{Key: "transfer-encoding", Value: "chunked"},
			},
			expected: []*pb.Header{
				{Key: "Content-Type", Value: "application/json"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FilterHopByHopHeaders(tt.headers)
			if diff := cmp.Diff(tt.expected, result, protocmp.Transform()); diff != "" {
				t.Errorf("FilterHopByHopHeaders() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestHTTPToProtoHeaders(t *testing.T) {
	tests := []struct {
		name     string
		headers  http.Header
		expected []*pb.Header
	}{
		{
			name:     "empty headers",
			headers:  http.Header{},
			expected: nil,
		},
		{
			name:     "nil headers",
			headers:  nil,
			expected: nil,
		},
		{
			name: "single value headers",
			headers: http.Header{
				"Content-Type": []string{"application/json"},
				"Accept":       []string{"application/json"},
			},
			expected: []*pb.Header{
				{Key: "Accept", Value: "application/json"},
				{Key: "Content-Type", Value: "application/json"},
			},
		},
		{
			name: "multi-value headers",
			headers: http.Header{
				"Accept":        []string{"application/json", "text/html"},
				"Cache-Control": []string{"no-cache", "must-revalidate"},
			},
			expected: []*pb.Header{
				{Key: "Accept", Value: "application/json, text/html"},
				{Key: "Cache-Control", Value: "no-cache, must-revalidate"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := HTTPToProtoHeaders(tt.headers)
			// Sort both slices for comparison since map iteration order is not guaranteed
			if len(result) > 0 && len(tt.expected) > 0 {
				// Simple comparison - check if we have the expected headers
				resultMap := make(map[string]string)
				for _, h := range result {
					resultMap[h.Key] = h.Value
				}
				expectedMap := make(map[string]string)
				for _, h := range tt.expected {
					expectedMap[h.Key] = h.Value
				}
				if diff := cmp.Diff(expectedMap, resultMap); diff != "" {
					t.Errorf("HTTPToProtoHeaders() mismatch (-want +got):\n%s", diff)
				}
			} else if diff := cmp.Diff(len(tt.expected), len(result)); diff != "" {
				t.Errorf("HTTPToProtoHeaders() length mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestProtoToHTTPHeaders(t *testing.T) {
	tests := []struct {
		name     string
		headers  []*pb.Header
		expected http.Header
	}{
		{
			name:     "empty headers",
			headers:  []*pb.Header{},
			expected: http.Header{},
		},
		{
			name:     "nil headers",
			headers:  nil,
			expected: http.Header{},
		},
		{
			name: "single value headers",
			headers: []*pb.Header{
				{Key: "Content-Type", Value: "application/json"},
				{Key: "Accept", Value: "application/json"},
			},
			expected: http.Header{
				"Content-Type": []string{"application/json"},
				"Accept":       []string{"application/json"},
			},
		},
		{
			name: "multi-value headers",
			headers: []*pb.Header{
				{Key: "Accept", Value: "application/json, text/html"},
				{Key: "Cache-Control", Value: "no-cache, must-revalidate"},
			},
			expected: http.Header{
				"Accept":        []string{"application/json", "text/html"},
				"Cache-Control": []string{"no-cache", "must-revalidate"},
			},
		},
		{
			name: "empty key or value",
			headers: []*pb.Header{
				{Key: "Content-Type", Value: "application/json"},
				{Key: "", Value: "ignored"},
				{Key: "Accept", Value: ""},
			},
			expected: http.Header{
				"Content-Type": []string{"application/json"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ProtoToHTTPHeaders(tt.headers)
			if diff := cmp.Diff(tt.expected, result); diff != "" {
				t.Errorf("ProtoToHTTPHeaders() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestHeaderConversionRoundTrip(t *testing.T) {
	original := http.Header{
		"Content-Type":  []string{"application/json"},
		"Accept":        []string{"application/json", "text/html"},
		"Cache-Control": []string{"no-cache"},
	}

	// Convert to proto and back
	proto := HTTPToProtoHeaders(original)
	result := ProtoToHTTPHeaders(proto)

	if diff := cmp.Diff(original, result); diff != "" {
		t.Errorf("Round-trip conversion mismatch (-want +got):\n%s", diff)
	}
}
