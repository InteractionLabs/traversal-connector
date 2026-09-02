package connector

import (
	"errors"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/testing/protocmp"

	pb "github.com/InteractionLabs/traversal-connector/connector-lib/gen/connector/v1"
)

func TestFilterContentDependentHeaders(t *testing.T) {
	tests := []struct {
		name     string
		headers  []*pb.Header
		expected []*pb.Header
	}{
		{
			name:     "nil headers",
			headers:  nil,
			expected: nil,
		},
		{
			name: "headers the connector can regenerate survive",
			headers: []*pb.Header{
				{Key: "Content-Type", Value: "application/json"},
				{Key: "Content-Length", Value: "42"},
				{Key: "Content-Encoding", Value: "gzip"},
			},
			expected: []*pb.Header{
				{Key: "Content-Type", Value: "application/json"},
				{Key: "Content-Length", Value: "42"},
				{Key: "Content-Encoding", Value: "gzip"},
			},
		},
		{
			name: "validators and digests are dropped",
			headers: []*pb.Header{
				{Key: "Content-Type", Value: "text/plain"},
				{Key: "ETag", Value: `"v1"`},
				{Key: "Last-Modified", Value: "Wed, 21 Oct 2015 07:28:00 GMT"},
				{Key: "Content-MD5", Value: "deadbeef"},
				{Key: "Digest", Value: "sha-256=deadbeef"},
				{Key: "Content-Digest", Value: "sha-256=:deadbeef:"},
				{Key: "Repr-Digest", Value: "sha-256=:deadbeef:"},
			},
			expected: []*pb.Header{
				{Key: "Content-Type", Value: "text/plain"},
			},
		},
		{
			name: "case insensitive filtering",
			headers: []*pb.Header{
				{Key: "ETAG", Value: `"v1"`},
				{Key: "last-modified", Value: "Wed, 21 Oct 2015 07:28:00 GMT"},
				{Key: "Accept-Ranges", Value: "bytes"},
			},
			expected: []*pb.Header{
				{Key: "Accept-Ranges", Value: "bytes"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FilterContentDependentHeaders(tt.headers)
			if diff := cmp.Diff(tt.expected, result, protocmp.Transform()); diff != "" {
				t.Errorf("FilterContentDependentHeaders() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestErrorCodeFor(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want ErrorCode
	}{
		{
			name: "a plain error is an upstream failure",
			err:  errors.New("dial tcp: connection refused"),
			want: ErrorCodeUpstreamError,
		},
		{
			name: "a coded error keeps its code",
			err:  NewCodedError(ErrorCodeUnsupportedEncoding, errors.New("zstd")),
			want: ErrorCodeUnsupportedEncoding,
		},
		{
			name: "a code survives being wrapped",
			err: fmt.Errorf("executing request: %w",
				NewCodedError(ErrorCodeUnsupportedEncoding, errors.New("zstd"))),
			want: ErrorCodeUnsupportedEncoding,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if diff := cmp.Diff(tt.want, ErrorCodeFor(tt.err)); diff != "" {
				t.Errorf("ErrorCodeFor() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestCodedError_UnwrapsToItsCause(t *testing.T) {
	cause := errors.New("zstd cannot be redacted")
	wrapped := NewCodedError(ErrorCodeUnsupportedEncoding, cause)

	if !errors.Is(wrapped, cause) {
		t.Error("a coded error should unwrap to its cause")
	}
	if diff := cmp.Diff(cause.Error(), wrapped.Error()); diff != "" {
		t.Errorf("message mismatch (-want +got):\n%s", diff)
	}
}
