package rawpipe_test

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/InteractionLabs/traversal-connector/connector-lib/rawpipe"
)

// pair is two ends of a loopback TCP connection.
func pair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	a, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	b, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	return a.(*net.TCPConn), b.(*net.TCPConn) //nolint:forcetypeassert // tcp
}

// splice runs Splice between a caller and a destination, returning their
// far ends and its result.
func splice(
	t *testing.T,
	l rawpipe.Limits,
) (caller, dest *net.TCPConn, done <-chan rawpipe.Outcome) {
	caller, callerNear := pair(t)
	destNear, dest := pair(t)
	ch := make(chan rawpipe.Outcome, 1)
	go func() {
		_, _, o := rawpipe.Splice(rawpipe.Conn(callerNear), rawpipe.Conn(destNear), l)
		ch <- o
	}()
	return caller, dest, ch
}

func TestSplice(t *testing.T) {
	t.Run("ends map to ends", func(t *testing.T) {
		caller, dest, done := splice(t, rawpipe.Limits{})
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
		if o := <-done; o != rawpipe.Completed {
			t.Fatal(o)
		}
	})
	t.Run("a reset is a reset", func(t *testing.T) {
		caller, dest, done := splice(t, rawpipe.Limits{})
		_ = dest.SetLinger(0)
		_ = dest.Close()
		if _, err := io.ReadAll(caller); err == nil {
			t.Fatal("caller saw a clean end")
		}
		if o := <-done; o != rawpipe.DestAborted {
			t.Fatal(o)
		}
	})
	t.Run("idle limit", func(t *testing.T) {
		caller, _, done := splice(t, rawpipe.Limits{Idle: time.Millisecond})
		if _, err := io.ReadAll(caller); err == nil {
			t.Fatal("caller saw a clean end")
		}
		if o := <-done; o != rawpipe.Limit {
			t.Fatal(o)
		}
	})
}
