// The HTTP/2 CONNECT streams a tunnel carries pipes on, as halfconn.End
// values for halfconn.Splice. Go's HTTP/2 server ends a stream only when its
// handler returns, hence ServerStream's Finish.

package rawpipe

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync/atomic"
	"time"
)

// past is a deadline that unblocks a read or write at once.
var past = time.Unix(1, 0)

// ServerStream is an HTTP/2 server CONNECT stream as a halfconn.End. The stock
// server ends a stream only when its handler returns, so CloseWrite stops
// reading the peer and the stream ends with the handler: bytes the peer sends
// after it are dropped. The handler must call Finish once Splice returns.
type ServerStream struct {
	r       *http.Request
	w       http.ResponseWriter
	rc      *http.ResponseController
	ended   atomic.Bool
	aborted atomic.Bool
}

// Accept answers a CONNECT with 200 and any headers already set on w.
func Accept(w http.ResponseWriter, r *http.Request) (*ServerStream, error) {
	s := &ServerStream{r: r, w: w, rc: http.NewResponseController(w)}
	w.WriteHeader(http.StatusOK)
	if err := s.rc.EnableFullDuplex(); err != nil {
		return nil, err
	}
	return s, s.rc.Flush()
}

func (s *ServerStream) Read(p []byte) (int, error) {
	if s.ended.Load() {
		return 0, io.EOF
	}
	n, err := s.r.Body.Read(p)
	if err != nil && s.ended.Load() && !s.aborted.Load() {
		err = io.EOF
	}
	return n, err
}

func (s *ServerStream) Write(p []byte) (int, error) {
	n, err := s.w.Write(p)
	if err == nil {
		err = s.rc.Flush()
	}
	return n, err
}

// CloseWrite stops reading the peer; the stream ends when the handler
// returns.
func (s *ServerStream) CloseWrite() error {
	s.ended.Store(true)
	_ = s.rc.SetReadDeadline(past)
	return nil
}

// Abort marks the stream to be reset when Finish runs.
func (s *ServerStream) Abort() {
	s.aborted.Store(true)
	_ = s.rc.SetReadDeadline(past)
	_ = s.rc.SetWriteDeadline(past)
}

// Finish resets the stream if it was aborted. It must run on the handler's
// goroutine.
func (s *ServerStream) Finish() {
	if s.aborted.Load() {
		panic(http.ErrAbortHandler)
	}
}

// ClientStream is an HTTP/2 client CONNECT stream as a halfconn.End.
type ClientStream struct {
	body   *io.PipeWriter
	resp   *http.Response
	cancel context.CancelFunc
}

var errAborted = errors.New("rawpipe: pipe aborted")

// Refusal is a CONNECT answered with a status other than 200.
type Refusal struct {
	Status int
	Reason Reason
}

func (r *Refusal) Error() string { return fmt.Sprintf("refused: %d %s", r.Status, r.Reason) }

// IsNoTunnel reports whether r is an edge controller replica's answer that it
// holds no tunnel for the connector: 503 with no reason, which a caller
// answers by trying another replica.
func IsNoTunnel(r *Refusal) bool {
	return r != nil && r.Reason == "" && r.Status == http.StatusServiceUnavailable
}

// Connect sends CONNECT authority through rt to addr. The open is bounded by
// timeout; the stream it returns lives until Close or Abort. Any answer but
// 200 is a *Refusal.
func Connect(ctx context.Context, rt http.RoundTripper, addr, authority string, h http.Header,
	timeout time.Duration,
) (*ClientStream, error) {
	ctx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	timer := time.AfterFunc(timeout, cancel)
	pr, pw := io.Pipe()
	req := (&http.Request{
		Method: http.MethodConnect, URL: &url.URL{Scheme: "http", Host: addr},
		Host: authority, Header: h, Body: pr,
	}).WithContext(ctx)
	resp, err := rt.RoundTrip(req)
	if !timer.Stop() && err == nil {
		_ = resp.Body.Close()
		err = context.DeadlineExceeded
	}
	switch {
	case err != nil:
	case resp.StatusCode != http.StatusOK:
		_ = resp.Body.Close()
		// An unknown reason from the peer becomes Other, keeping label sets
		// and switches closed; none at all is IsNoTunnel's answer.
		reason := Reason(resp.Header.Get(HeaderReason))
		if reason != "" {
			reason = reason.Label()
		}
		err = &Refusal{resp.StatusCode, reason}
	default:
		return &ClientStream{body: pw, resp: resp, cancel: cancel}, nil
	}
	_ = pw.Close()
	cancel()
	return nil, err
}

func (c *ClientStream) Read(p []byte) (int, error)  { return c.resp.Body.Read(p) }
func (c *ClientStream) Write(p []byte) (int, error) { return c.body.Write(p) }
func (c *ClientStream) CloseWrite() error           { return c.body.Close() }

// Abort resets the stream.
func (c *ClientStream) Abort() {
	_ = c.body.CloseWithError(errAborted)
	c.Close()
}

// Close releases the stream once the pipe is over.
func (c *ClientStream) Close() {
	_ = c.resp.Body.Close()
	c.cancel()
}
