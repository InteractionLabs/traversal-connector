package halfconn

import (
	"errors"
	"io"
	"net"
	"sync"
)

// StreamConn is a pipe End as a net.Conn, so crypto/tls and net/http can run
// over a pipe stream. A net.Pipe sits between them because net/http's HTTP/1
// server resets a read deadline to abort a background read before a hijack,
// and an HTTP/2 stream's read deadline ends its body for good.
//
// Closing the conn ends e cleanly (CloseWrite). e's clean end ends the conn:
// its reads return io.EOF and, as a net.Pipe cannot half-close, its writes
// fail. A failure reading or writing e aborts e and fails the conn's reads
// and writes with that error, so neither side mistakes it for an end.
type StreamConn struct {
	net.Conn
	closeOnce sync.Once
	closed    chan struct{}
	failOnce  sync.Once
	failed    chan struct{} // closed once err is set
	err       error
	copies    sync.WaitGroup
	in, out   int64
}

// NewStreamConn starts copying between e and the returned conn.
func NewStreamConn(e End) *StreamConn {
	near, far := net.Pipe()
	c := &StreamConn{Conn: near, closed: make(chan struct{}), failed: make(chan struct{})}
	fail := func(err error) {
		c.failOnce.Do(func() {
			c.err = err
			close(c.failed)
			e.Abort()
			_ = far.Close()
		})
	}
	c.copies.Go(func() {
		var rerr error
		// A write error is the conn closed: what e sends after is dropped.
		c.in, rerr, _ = pump(far, e)
		if rerr != nil && !errors.Is(rerr, io.EOF) {
			fail(rerr)
		}
		_ = far.Close()
	})
	c.copies.Go(func() {
		var werr error
		// far's read ends when the conn is closed, or far is: by e's end or
		// a failure.
		c.out, _, werr = pump(e, far)
		switch {
		case werr != nil:
			fail(werr)
		case c.failure() == nil:
			if err := e.CloseWrite(); err != nil {
				fail(err)
			}
		}
	})
	return c
}

// pump copies src to dst until either fails: rerr is src's error (io.EOF at
// a clean end), werr dst's. n is the bytes written.
func pump(dst io.Writer, src io.Reader) (n int64, rerr, werr error) {
	buf := make([]byte, copyBuffer)
	for {
		r, err := src.Read(buf)
		if r > 0 {
			w, werr := dst.Write(buf[:r])
			n += int64(w)
			if werr != nil {
				return n, nil, werr
			}
		}
		if err != nil {
			return n, err, nil
		}
	}
}

// Read is the conn's Read, but once e has failed it returns that failure,
// not io.EOF.
func (c *StreamConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	return n, c.orFailure(err)
}

// Write is the conn's Write, but once e has failed it returns that failure.
func (c *StreamConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	return n, c.orFailure(err)
}

// orFailure replaces err with e's failure, if there is one: a failure closes
// far, which the conn alone reports as io.EOF or io.ErrClosedPipe.
func (c *StreamConn) orFailure(err error) error {
	if err != nil {
		if f := c.failure(); f != nil {
			return f
		}
	}
	return err
}

func (c *StreamConn) failure() error {
	select {
	case <-c.failed:
		return c.err
	default:
		return nil
	}
}

// Close closes the conn; Closed then reports it.
func (c *StreamConn) Close() error {
	err := c.Conn.Close()
	c.closeOnce.Do(func() { close(c.closed) })
	return err
}

// Closed is closed once Close has run.
func (c *StreamConn) Closed() <-chan struct{} { return c.closed }

// Wait returns once both copies with e have stopped, with the bytes read
// from e and written to it. After Close, the copy toward e ends e
// (CloseWrite) once it has written what the conn sent; the copy from e stops
// at e's end: at once on a ServerStream, whose CloseWrite ends its reads,
// otherwise when e's peer ends or e is released. A failure stops both, as
// Abort unblocks e. A peer that stops reading holds the copy toward e until
// it reads or resets; bounding that is the pipe's idle limit (Splice's
// Limits) or the HTTP server's timeouts, not StreamConn's.
func (c *StreamConn) Wait() (in, out int64) {
	c.copies.Wait()
	return c.in, c.out
}
