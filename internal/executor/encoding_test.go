package executor

import (
	"bytes"
	"compress/gzip"
	"errors"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestClassifyContentCoding(t *testing.T) {
	tests := []struct {
		name   string
		values []string
		want   contentCoding
	}{
		{"absent header is identity", nil, codingIdentity},
		{"empty value is identity", []string{""}, codingIdentity},
		{"explicit identity", []string{"identity"}, codingIdentity},
		{"gzip", []string{"gzip"}, codingGzip},
		{"case and padding normalized", []string{"  GZip "}, codingGzip},
		{"deflate is named but not decodable", []string{"deflate"}, codingDeflate},
		{"zstd is named but not decodable", []string{"zstd"}, codingZstd},
		{"brotli is named but not decodable", []string{"br"}, codingBr},
		{"unknown coding collapses to other", []string{"exi"}, codingOther},
		{"stacked in one line is other", []string{"gzip, br"}, codingOther},
		{"stacked across lines is other", []string{"gzip", "br"}, codingOther},
		{"trailing comma is a single token", []string{"gzip,"}, codingGzip},
		{"identity plus gzip is still stacked", []string{"identity, gzip"}, codingOther},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if diff := cmp.Diff(tt.want, classifyContentCoding(tt.values)); diff != "" {
				t.Errorf("coding mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestContentCoding_CanDecode(t *testing.T) {
	decodable := []contentCoding{codingIdentity, codingGzip}
	for _, coding := range decodable {
		if !coding.canDecode() {
			t.Errorf("%q should be decodable", coding)
		}
	}

	for _, coding := range []contentCoding{codingDeflate, codingZstd, codingBr, codingOther} {
		if coding.canDecode() {
			t.Errorf("%q should not be decodable", coding)
		}
	}
}

func TestReadLimited(t *testing.T) {
	t.Run("body at the limit is accepted", func(t *testing.T) {
		got, err := readLimited(strings.NewReader("abcde"), 5)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if diff := cmp.Diff("abcde", string(got)); diff != "" {
			t.Errorf("body mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("body past the limit is refused", func(t *testing.T) {
		_, err := readLimited(strings.NewReader("abcdef"), 5)
		if !errors.Is(err, errBodyTooLarge) {
			t.Fatalf("want errBodyTooLarge, got %v", err)
		}
	})

	t.Run("non-positive limit means unlimited", func(t *testing.T) {
		got, err := readLimited(strings.NewReader("abcdef"), 0)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if diff := cmp.Diff("abcdef", string(got)); diff != "" {
			t.Errorf("body mismatch (-want +got):\n%s", diff)
		}
	})
}

func TestGzipRoundTrip(t *testing.T) {
	want := []byte("the quick brown fox jumps over the lazy dog")

	encoded, err := encodeGzip(want)
	if err != nil {
		t.Fatalf("encodeGzip() error: %v", err)
	}

	got, err := decodeGzip(encoded, 0)
	if err != nil {
		t.Fatalf("decodeGzip() error: %v", err)
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("round trip mismatch (-want +got):\n%s", diff)
	}
}

func TestDecodeGzip_Failures(t *testing.T) {
	t.Run("not a gzip stream", func(t *testing.T) {
		if _, err := decodeGzip([]byte("plain text"), 0); err == nil {
			t.Fatal("expected an error for a non-gzip body")
		}
	})

	t.Run("truncated stream", func(t *testing.T) {
		full, err := encodeGzip(bytes.Repeat([]byte("payload"), 100))
		if err != nil {
			t.Fatalf("encodeGzip() error: %v", err)
		}
		if _, err = decodeGzip(full[:len(full)/2], 0); err == nil {
			t.Fatal("expected an error for a truncated stream")
		}
	})

	t.Run("expansion past the limit", func(t *testing.T) {
		var buf bytes.Buffer
		writer := gzip.NewWriter(&buf)
		if _, err := writer.Write(bytes.Repeat([]byte("a"), 1<<20)); err != nil {
			t.Fatalf("write: %v", err)
		}
		if err := writer.Close(); err != nil {
			t.Fatalf("close: %v", err)
		}

		_, err := decodeGzip(buf.Bytes(), 1024)
		if !errors.Is(err, errBodyTooLarge) {
			t.Fatalf("want errBodyTooLarge, got %v", err)
		}
	})
}
