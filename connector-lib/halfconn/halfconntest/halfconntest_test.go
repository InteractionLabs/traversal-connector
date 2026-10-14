package halfconntest_test

import (
	"io"
	"testing"
	"time"

	"github.com/InteractionLabs/traversal-connector/connector-lib/halfconn"
	"github.com/InteractionLabs/traversal-connector/connector-lib/halfconn/halfconntest"
)

// TestTCPPair: the two ends are connected to each other, and a half-close on
// one is a clean end on the other while the other way stays open.
func TestTCPPair(t *testing.T) {
	var a, b halfconn.Conn
	a, b = halfconntest.TCPPair(t)
	deadline := time.Now().Add(5 * time.Second)
	_, _ = a.SetDeadline(deadline), b.SetDeadline(deadline)
	_, _ = a.Write([]byte("ping"))
	_ = a.CloseWrite()
	if got, err := io.ReadAll(b); err != nil || string(got) != "ping" {
		t.Fatalf("b read %q, %v", got, err)
	}
	_, _ = b.Write([]byte("pong"))
	_ = b.Close()
	if got, err := io.ReadAll(a); err != nil || string(got) != "pong" {
		t.Fatalf("a read %q, %v", got, err)
	}
}
