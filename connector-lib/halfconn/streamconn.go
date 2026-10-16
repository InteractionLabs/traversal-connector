package halfconn

import (
	"io"
	"net"
	"sync"
)

// StreamConn is a pipe End as a net.Conn, so crypto/tls and net/http can run
// over a pipe stream. A net.Pipe sits between them because net/http's HTTP/1
// server resets a read deadline to abort a background read before a hijack,
// and an HTTP/2 stream's read deadline ends its body for good.
//
// Closing the conn ends e cleanly (CloseWrite); e's end ends the conn.
type StreamConn struct {
	net.Conn
	closeOnce sync.Once
	closed    chan struct{}
	copies    sync.WaitGroup
	in, out   int64
}

// NewStreamConn starts copying between e and the returned conn.
func NewStreamConn(e End) *StreamConn {
	near, far := net.Pipe()
	c := &StreamConn{Conn: near, closed: make(chan struct{})}
	c.copies.Go(func() {
		c.in, _ = io.Copy(far, e)
		_ = far.Close()
	})
	c.copies.Go(func() {
		c.out, _ = io.Copy(e, far)
		_ = e.CloseWrite()
	})
	return c
}

// Close closes the conn; Closed then reports it.
func (c *StreamConn) Close() error {
	err := c.Conn.Close()
	c.closeOnce.Do(func() { close(c.closed) })
	return err
}

// Closed is closed once Close has run.
func (c *StreamConn) Closed() <-chan struct{} { return c.closed }

// Wait returns once both copies with e have stopped, by e's peer ending,
// CloseWrite on a ServerStream, or Abort, with the bytes read from e and
// written to it.
func (c *StreamConn) Wait() (in, out int64) {
	c.copies.Wait()
	return c.in, c.out
}
