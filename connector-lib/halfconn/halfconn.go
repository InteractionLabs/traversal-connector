// Package halfconn is connections that can half-close, and the copy that
// joins two of them. The connector, the edge controller, the Integration
// Proxy and the egress proxy all carry byte streams whose ends must stay
// distinct: a peer that is done sending (CloseWrite, a FIN) is not a peer
// that failed (a reset).
//
// net.Conn alone cannot say that: its only end is Close, which ends both
// directions, so a copy that sees EOF one way would cut off the other. Conn
// adds CloseWrite, which *net.TCPConn and *tls.Conn have.
//
// A wrapper that buffers a conn's first bytes must also implement WriteTo:
// io.Copy prefers the source's WriteTo, and an embedded *net.TCPConn's would
// splice from the socket and skip what the buffer holds. Buffered does, and
// is the one such wrapper.
package halfconn

import (
	"bufio"
	"errors"
	"io"
	"net"
	"net/http"
)

// Conn is a connection that can half-close, such as *net.TCPConn.
type Conn interface {
	net.Conn
	CloseWrite() error
}

// Buffered is c read through r, a bufio.Reader over c that may already hold
// bytes c's peer sent: what followed a CONNECT request a server hijacked, or
// a CONNECT answer a client read. Reads drain r before c; CloseWrite and
// every other method are c's.
//
// With nothing buffered it returns c itself, which keeps io.Copy's
// zero-copy paths (*net.TCPConn's ReadFrom and WriteTo).
func Buffered(c Conn, r *bufio.Reader) Conn {
	if r == nil || r.Buffered() == 0 {
		return c
	}
	return &buffered{Conn: c, r: r}
}

type buffered struct {
	Conn
	r *bufio.Reader
}

func (b *buffered) Read(p []byte) (int, error) { return b.r.Read(p) }

// WriteTo lets io.Copy drain the buffer and then use c's own WriteTo, such
// as *net.TCPConn's splice, rather than copy through Read.
func (b *buffered) WriteTo(w io.Writer) (int64, error) { return b.r.WriteTo(w) }

// SetLinger reaches c's, so ConnEnd's Abort still resets a TCP connection.
func (b *buffered) SetLinger(sec int) error {
	if l, ok := b.Conn.(interface{ SetLinger(int) error }); ok {
		return l.SetLinger(sec)
	}
	return errors.ErrUnsupported
}

// Hijack takes over the HTTP/1 connection under w, for a CONNECT the handler
// answers itself (it writes the 200). Bytes the client sent after its
// request, such as a TLS ClientHello in the same packet, stay readable. A
// connection that cannot half-close is closed and refused: a pipe end must.
func Hijack(w http.ResponseWriter) (Conn, error) {
	c, rw, err := http.NewResponseController(w).Hijack()
	if err != nil {
		return nil, err
	}
	hc, ok := c.(Conn)
	if !ok {
		_ = c.Close()
		return nil, errors.New("halfconn: hijacked connection cannot half-close")
	}
	return Buffered(hc, rw.Reader), nil
}
