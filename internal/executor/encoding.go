package executor

import (
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"strings"
)

// contentCoding is a response's Content-Encoding reduced to the set the
// connector reports and acts on.
type contentCoding string

const (
	codingIdentity contentCoding = "identity"
	codingGzip     contentCoding = "gzip"
	codingDeflate  contentCoding = "deflate"
	codingZstd     contentCoding = "zstd"
	codingBr       contentCoding = "br"
	// codingOther covers every coding the connector does not name, including a
	// stacked value. It exists so a strange upstream cannot expand the
	// cardinality of the encoding metric one series at a time.
	codingOther contentCoding = "other"
)

// namedCodings are the codings worth their own metric series. Anything absent
// reports as codingOther.
var namedCodings = map[string]contentCoding{
	string(codingIdentity): codingIdentity,
	string(codingGzip):     codingGzip,
	string(codingDeflate):  codingDeflate,
	string(codingZstd):     codingZstd,
	string(codingBr):       codingBr,
}

// errBodyTooLarge marks a body that ran past a configured ceiling. The read
// stops there, so an oversized body is never held in full.
var errBodyTooLarge = errors.New("body exceeds configured size limit")

// classifyContentCoding reduces the Content-Encoding header lines of a response
// to a single coding. An absent header is codingIdentity.
//
// A stacked value classifies as codingOther even when every layer is
// individually supported: peeling one is not the same as peeling several, and
// the connector refuses what it cannot scan rather than guessing at the order.
func classifyContentCoding(values []string) contentCoding {
	var tokens []string
	for _, value := range values {
		for _, token := range strings.Split(value, ",") {
			if trimmed := strings.TrimSpace(token); trimmed != "" {
				tokens = append(tokens, strings.ToLower(trimmed))
			}
		}
	}

	switch len(tokens) {
	case 0:
		return codingIdentity
	case 1:
		if coding, ok := namedCodings[tokens[0]]; ok {
			return coding
		}
		return codingOther
	default:
		return codingOther
	}
}

// canDecode reports whether the connector can reach the plaintext under this
// coding, and therefore whether it can honor a redaction rule on the body.
func (c contentCoding) canDecode() bool {
	return c == codingIdentity || c == codingGzip
}

// readLimited reads r to EOF, failing with errBodyTooLarge past limit. A
// non-positive limit means unlimited, matching the request-body convention.
func readLimited(r io.Reader, limit int64) ([]byte, error) {
	if limit <= 0 {
		return io.ReadAll(r)
	}
	// Reading one byte past the limit is what separates a body sitting exactly
	// at the ceiling from one the reader silently truncated there.
	body, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, errBodyTooLarge
	}
	return body, nil
}

// decodeGzip inflates src, refusing a stream that expands past limit. A
// truncated or corrupt stream fails here rather than reaching the redactor as a
// partial body that patterns could straddle.
func decodeGzip(src []byte, limit int64) ([]byte, error) {
	reader, err := gzip.NewReader(bytes.NewReader(src))
	if err != nil {
		return nil, fmt.Errorf("open gzip stream: %w", err)
	}
	// Any stream error surfaces from the read below, so Close has nothing left to
	// report.
	defer func() { _ = reader.Close() }()

	// Reading to EOF is also what verifies the stream's CRC and length trailer.
	body, err := readLimited(reader, limit)
	if err != nil {
		return nil, fmt.Errorf("read gzip stream: %w", err)
	}
	return body, nil
}

// encodeGzip deflates src so a redacted body leaves under the coding the caller
// negotiated.
func encodeGzip(src []byte) ([]byte, error) {
	var buf bytes.Buffer
	writer := gzip.NewWriter(&buf)
	if _, err := writer.Write(src); err != nil {
		return nil, fmt.Errorf("write gzip stream: %w", err)
	}
	// Close flushes the final block and writes the trailer; skipping it yields a
	// stream no reader accepts.
	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("close gzip stream: %w", err)
	}
	return buf.Bytes(), nil
}
