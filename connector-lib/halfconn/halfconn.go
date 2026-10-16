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
// splice from the socket and skip what the buffer holds. Prefixed does, and
// is the one such wrapper; Buffered is built on it.
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

// Prefixed is c with r's bytes read first: bytes already taken from c's
// peer, such as a sniffed TLS ClientHello. Reads drain r, then c; WriteTo
// does the same, so io.Copy still reaches c's own WriteTo (*net.TCPConn's
// splice) once r is drained. CloseWrite and every other method are c's.
func Prefixed(c Conn, r io.Reader) Conn {
	return &prefixed{Conn: c, r: io.MultiReader(r, c)}
}

type prefixed struct {
	Conn
	r io.Reader
}

func (p *prefixed) Read(b []byte) (int, error) { return p.r.Read(b) }

// WriteTo lets io.Copy drain the prefix and then use c's own WriteTo rather
// than copy through Read.
func (p *prefixed) WriteTo(w io.Writer) (int64, error) { return io.Copy(w, p.r) }

// SetLinger reaches c's, so ConnEnd's Abort still resets a TCP connection.
func (p *prefixed) SetLinger(sec int) error {
	if l, ok := p.Conn.(interface{ SetLinger(int) error }); ok {
		return l.SetLinger(sec)
	}
	return errors.ErrUnsupported
}

// Buffered is c read through r, a bufio.Reader over c that may already hold
// bytes c's peer sent: what followed a CONNECT request a server hijacked, or
// a CONNECT answer a client read. It is Prefixed with what r holds.
//
// With nothing buffered it returns c itself, which keeps io.Copy's
// zero-copy paths (*net.TCPConn's ReadFrom and WriteTo).
func Buffered(c Conn, r *bufio.Reader) Conn {
	if r == nil || r.Buffered() == 0 {
		return c
	}
	// Reading no more than r holds never makes r read c.
	return Prefixed(c, io.LimitReader(r, int64(r.Buffered())))
}

// hijack takes over the HTTP/1 connection under w. Bytes the client sent
// after its request, such as a TLS ClientHello in the same packet, stay
// readable. A connection that cannot half-close is closed and refused: a pipe
// end must.
func hijack(w http.ResponseWriter) (Conn, error) {
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

// Established takes over the HTTP/1 connection under w and accepts the
// CONNECT on it: it writes the 200, after which the connection is the tunnel.
// Bytes the client sent after its request stay readable. On error the
// connection is closed.
func Established(w http.ResponseWriter) (Conn, error) {
	c, err := hijack(w)
	if err != nil {
		return nil, err
	}
	if _, err := io.WriteString(c, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		_ = c.Close()
		return nil, err
	}
	return c, nil
}
