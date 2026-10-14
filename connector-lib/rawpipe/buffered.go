package rawpipe

import (
	"bufio"
	"errors"
	"io"
	"net/http"
)

// Buffered is c read through r, a bufio.Reader over c that may already hold
// bytes c's peer sent: what followed a CONNECT request a server hijacked, or
// a CONNECT answer a client read. Reads drain r before c; CloseWrite and
// every other method are c's.
//
// With nothing buffered it returns c itself, which keeps io.Copy's
// zero-copy paths (*net.TCPConn's ReadFrom and WriteTo).
func Buffered(c HalfCloser, r *bufio.Reader) HalfCloser {
	if r == nil || r.Buffered() == 0 {
		return c
	}
	return &buffered{HalfCloser: c, r: r}
}

type buffered struct {
	HalfCloser
	r *bufio.Reader
}

func (b *buffered) Read(p []byte) (int, error) { return b.r.Read(p) }

// WriteTo lets io.Copy drain the buffer and then use c's own WriteTo, such
// as *net.TCPConn's splice, rather than copy through Read.
func (b *buffered) WriteTo(w io.Writer) (int64, error) { return b.r.WriteTo(w) }

// SetLinger reaches c's, so Conn's Abort still resets a TCP connection.
func (b *buffered) SetLinger(sec int) error {
	if l, ok := b.HalfCloser.(interface{ SetLinger(int) error }); ok {
		return l.SetLinger(sec)
	}
	return errors.ErrUnsupported
}

// Hijack takes over the HTTP/1 connection under w, for a CONNECT the handler
// answers itself (it writes the 200). Bytes the client sent after its
// request, such as a TLS ClientHello in the same packet, stay readable. A
// connection that cannot half-close is closed and refused: a pipe end must.
func Hijack(w http.ResponseWriter) (HalfCloser, error) {
	c, rw, err := http.NewResponseController(w).Hijack()
	if err != nil {
		return nil, err
	}
	hc, ok := c.(HalfCloser)
	if !ok {
		_ = c.Close()
		return nil, errors.New("rawpipe: hijacked connection cannot half-close")
	}
	return Buffered(hc, rw.Reader), nil
}
