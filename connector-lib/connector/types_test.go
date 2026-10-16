package connector

import (
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
