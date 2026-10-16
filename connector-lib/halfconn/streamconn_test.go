package halfconn_test

import (
	"errors"
	"io"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/InteractionLabs/traversal-connector/connector-lib/halfconn"
	"github.com/InteractionLabs/traversal-connector/connector-lib/halfconn/halfconntest"
)

// TestStreamConn: a read deadline unblocks a pending read and can be reset, as
// net/http's HTTP/1 server needs before a hijack; closing the conn ends the
// stream cleanly and, once the peer ends too, both copies stop.
func TestStreamConn(t *testing.T) {
	near, peer := halfconntest.TCPPair(t)
	c := halfconn.NewStreamConn(halfconn.ConnEnd(near))
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
	if _, err := c.Read(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("read past the deadline: %v", err)
	}
	_ = c.SetReadDeadline(time.Time{})
	_, _ = peer.Write([]byte("x"))
	if n, err := c.Read(make([]byte, 1)); n != 1 || err != nil {
		t.Fatalf("read after the deadline was reset: %d %v", n, err)
	}
	_, _ = c.Write([]byte("bye"))
	_ = c.Close()
	if b, err := io.ReadAll(peer); string(b) != "bye" || err != nil {
		t.Fatalf("peer read %q %v, want a clean end", b, err)
	}
	_ = peer.CloseWrite()
	if in, out := within(t, c.Wait); in != 1 || out != 3 {
		t.Fatalf("Wait = %d in, %d out; want 1, 3", in, out)
	}
}

// TestStreamConnEnds: the peer's clean end is the conn's io.EOF; its reset is
// a failure on the conn's reads and writes, and ends both copies.
func TestStreamConnEnds(t *testing.T) {
	t.Run("a clean end is EOF", func(t *testing.T) {
		near, peer := halfconntest.TCPPair(t)
		c := halfconn.NewStreamConn(halfconn.ConnEnd(near))
		_, _ = peer.Write([]byte("hi"))
		_ = peer.CloseWrite()
		if b, err := io.ReadAll(c); string(b) != "hi" || err != nil {
			t.Fatalf("read %q %v, want a clean end", b, err)
		}
		_ = c.Close()
		within(t, c.Wait)
	})
	t.Run("a reset is a failure", func(t *testing.T) {
		near, peer := halfconntest.TCPPair(t)
		c := halfconn.NewStreamConn(halfconn.ConnEnd(near))
		_, _ = peer.Write([]byte("hi"))
		if _, err := io.ReadFull(c, make([]byte, 2)); err != nil {
			t.Fatal(err)
		}
		_ = peer.SetLinger(0)
		_ = peer.Close()
		if _, err := io.ReadAll(c); err == nil {
			t.Fatal("read saw a clean end")
		}
		if _, err := c.Write([]byte("x")); err == nil {
			t.Fatal("write after the reset succeeded")
		}
		within(t, c.Wait)
	})
}

// TestStreamConnWriteFailure: a write to e that fails aborts e and fails the
// conn with e's error wrapped, rather than ending e cleanly and leaving the
// conn's next write with no reader. e is a fake: TCP fails reads and writes
// together on a reset, so it cannot fail only the write.
func TestStreamConnWriteFailure(t *testing.T) {
	e := newWriteFailingEnd()
	c := halfconn.NewStreamConn(e)
	_, _ = c.Write([]byte("x")) // the copy toward e takes it, and fails
	if _, err := within(t, func() (int, error) { return c.Write([]byte("y")) }); err == nil {
		t.Fatal("write after the failure succeeded")
	}
	// e's error, wrapped: an HTTP/2 conn over c would take net/http's own
	// StreamError for a reset of one of its streams and read on.
	_, err := c.Read(make([]byte, 1))
	if !errors.Is(err, errWrite) || err == errWrite { //nolint:errorlint // identity is the point
		t.Fatalf("read after the failure: %v, want errWrite wrapped", err)
	}
	within(t, c.Wait)
	if e.closedWrite {
		t.Fatal("e was ended cleanly")
	}
}

// within runs f, failing the test if it takes over a second.
func within[A, B any](t *testing.T, f func() (A, B)) (A, B) {
	t.Helper()
	type result struct {
		a A
		b B
	}
	done := make(chan result, 1)
	go func() { a, b := f(); done <- result{a, b} }()
	select {
	case r := <-done:
		return r.a, r.b
	case <-time.After(time.Second):
		t.Fatal("blocked")
	}
	var a A
	var b B
	return a, b
}

// writeFailingEnd is an End whose writes fail and whose reads block until
// Abort.
type writeFailingEnd struct {
	abortOnce   sync.Once
	aborted     chan struct{}
	closedWrite bool
}

func newWriteFailingEnd() *writeFailingEnd {
	return &writeFailingEnd{aborted: make(chan struct{})}
}

var errWrite = errors.New("write failed")

func (e *writeFailingEnd) Read([]byte) (int, error) {
	<-e.aborted
	return 0, errors.New("aborted")
}

func (e *writeFailingEnd) Write([]byte) (int, error) { return 0, errWrite }

func (e *writeFailingEnd) CloseWrite() error { e.closedWrite = true; return nil }

func (e *writeFailingEnd) Abort() { e.abortOnce.Do(func() { close(e.aborted) }) }
