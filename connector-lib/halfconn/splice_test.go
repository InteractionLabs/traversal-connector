package halfconn_test

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/InteractionLabs/traversal-connector/connector-lib/halfconn"
	"github.com/InteractionLabs/traversal-connector/connector-lib/halfconn/halfconntest"
)

// splice runs Splice between a caller and a destination, returning their
// far ends and its result.
func splice(
	t *testing.T,
	l halfconn.Limits,
) (caller, dest *net.TCPConn, done <-chan halfconn.Outcome) {
	caller, callerNear := halfconntest.TCPPair(t)
	destNear, dest := halfconntest.TCPPair(t)
	ch := make(chan halfconn.Outcome, 1)
	go func() {
		_, _, o := halfconn.Splice(halfconn.ConnEnd(callerNear), halfconn.ConnEnd(destNear), l)
		ch <- o
	}()
	return caller, dest, ch
}

func TestSplice(t *testing.T) {
	t.Run("ends map to ends", func(t *testing.T) {
		caller, dest, done := splice(t, halfconn.Limits{})
		_, _ = caller.Write([]byte("ping"))
		_ = caller.CloseWrite()
		if b, _ := io.ReadAll(dest); string(b) != "ping" {
			t.Fatalf("dest read %q", b)
		}
		_, _ = dest.Write([]byte("pong"))
		_ = dest.CloseWrite()
		if b, err := io.ReadAll(caller); string(b) != "pong" || err != nil {
			t.Fatalf("caller read %q %v", b, err)
		}
		if o := <-done; o != halfconn.Completed {
			t.Fatal(o)
		}
	})
	t.Run("a reset is a reset", func(t *testing.T) {
		caller, dest, done := splice(t, halfconn.Limits{})
		_ = dest.SetLinger(0)
		_ = dest.Close()
		if _, err := io.ReadAll(caller); err == nil {
			t.Fatal("caller saw a clean end")
		}
		if o := <-done; o != halfconn.DestAborted {
			t.Fatal(o)
		}
	})
	t.Run("idle limit", func(t *testing.T) {
		caller, _, done := splice(t, halfconn.Limits{Idle: time.Millisecond})
		if _, err := io.ReadAll(caller); err == nil {
			t.Fatal("caller saw a clean end")
		}
		if o := <-done; o != halfconn.Limit {
			t.Fatal(o)
		}
	})
}
