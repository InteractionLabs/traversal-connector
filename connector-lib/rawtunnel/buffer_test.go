package rawtunnel

import (
	"bytes"
	"math/rand/v2"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestRecvBufferMatchesReference(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2)) //nolint:gosec // a reproducible sequence, not a secret.
	var b recvBuffer
	var want bytes.Buffer
	var next byte
	for range 20000 {
		if rng.IntN(2) == 0 && b.size < Window {
			chunk := make([]byte, 1+rng.IntN(min(MaxDataBytes, Window-b.size)))
			for i := range chunk {
				chunk[i] = next
				next++
			}
			b.write(chunk)
			want.Write(chunk)
		} else if b.size > 0 {
			got := b.peek()
			n := 1 + rng.IntN(len(got))
			if !bytes.Equal(got[:n], want.Next(n)) {
				t.Fatal("buffer returned bytes out of order")
			}
			b.consume(n)
		}
		if b.size != want.Len() {
			t.Fatalf("size = %d, want %d", b.size, want.Len())
		}
		// Any window's worth of bytes fits in one block more than it needs.
		if len(b.blocks) > Window/MaxDataBytes+1 {
			t.Fatalf("%d blocks hold %d bytes", len(b.blocks), b.size)
		}
	}
	if b.size == 0 && b.peek() != nil {
		t.Fatal("empty buffer returned bytes")
	}
}

func TestTinyFramesCostNoMoreThanFullOnes(t *testing.T) {
	var b recvBuffer
	for range Window {
		b.write([]byte{'x'})
	}
	if len(b.blocks) != Window/MaxDataBytes {
		t.Fatalf("%d single-byte writes used %d blocks", Window, len(b.blocks))
	}
}

func TestTruncateDetail(t *testing.T) {
	for _, in := range []string{
		"short",
		strings.Repeat("é", 200),
		strings.Repeat("a", 255) + "é",
		"bad \xff utf8",
	} {
		got := truncateDetail(in)
		if len(got) > maxDetailBytes || !utf8.ValidString(got) {
			t.Errorf("truncateDetail(%q) = %q", in, got)
		}
		if utf8.ValidString(in) && len(in) <= maxDetailBytes && got != in {
			t.Errorf("truncateDetail changed %q", in)
		}
	}
}
