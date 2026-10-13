package rawpipe

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"
)

// End is one side of a pipe. Its Read returns io.EOF at a clean end.
type End interface {
	io.Reader
	io.Writer
	// CloseWrite ends the bytes toward this end cleanly.
	CloseWrite() error
	// Abort resets this end, so it sees a failure rather than an end, and
	// unblocks any Read or Write on it.
	Abort()
}

// Outcome is how a pipe ended.
type Outcome string

// Outcomes.
const (
	Completed     Outcome = "completed"
	Limit         Outcome = "limit"
	CallerAborted Outcome = "caller_aborted"
	DestAborted   Outcome = "destination_aborted"
)

// Limits end a pipe that is Lifetime old or has moved no bytes for Idle.
// Zero is no limit.
type Limits struct{ Lifetime, Idle time.Duration }

// Splice copies both ways until both directions end. A clean end on one side
// is a clean end on the other; the first failure, or a limit, aborts both
// ends, so neither mistakes it for an end. sent is caller to dest.
func Splice(caller, dest End, l Limits) (sent, received int64, outcome Outcome) {
	var once sync.Once
	outcome = Completed
	fail := func(o Outcome) {
		once.Do(func() { outcome = o; caller.Abort(); dest.Abort() })
	}
	var touched atomic.Int64
	touched.Store(time.Now().UnixNano())
	stop := watch(&touched, l, func() { fail(Limit) })
	up := make(chan int64, 1)
	go func() { up <- copyEnd(dest, caller, &touched, fail, CallerAborted, DestAborted) }()
	received = copyEnd(caller, dest, &touched, fail, DestAborted, CallerAborted)
	sent = <-up
	stop() // every fail has run: outcome is settled
	return sent, received, outcome
}

const copyBuffer = 64 << 10

func copyEnd(
	dst, src End,
	touched *atomic.Int64,
	fail func(Outcome),
	srcFailed, dstFailed Outcome,
) int64 {
	buf := make([]byte, copyBuffer)
	var n int64
	for {
		r, err := src.Read(buf)
		if r > 0 {
			touched.Store(time.Now().UnixNano())
			if _, werr := dst.Write(buf[:r]); werr != nil {
				fail(dstFailed)
				return n
			}
			n += int64(r)
		}
		switch {
		case errors.Is(err, io.EOF):
			if dst.CloseWrite() != nil {
				fail(dstFailed)
			}
			return n
		case err != nil:
			fail(srcFailed)
			return n
		}
	}
}

// watch runs end once a limit is reached. stop waits for it to exit.
func watch(touched *atomic.Int64, l Limits, end func()) (stop func()) {
	if l.Lifetime <= 0 && l.Idle <= 0 {
		return func() {}
	}
	done, exited := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(exited)
		start := time.Now()
		tick := time.NewTicker(time.Second)
		defer tick.Stop()
		for {
			select {
			case <-done:
				return
			case now := <-tick.C:
				if l.Lifetime > 0 && now.Sub(start) > l.Lifetime ||
					l.Idle > 0 && now.Sub(time.Unix(0, touched.Load())) > l.Idle {
					end()
					return
				}
			}
		}
	}()
	return func() { close(done); <-exited }
}

// HalfCloser is a connection that can half-close, such as *net.TCPConn.
type HalfCloser interface {
	net.Conn
	CloseWrite() error
}

// Conn is a connection as a pipe End. Abort resets it.
func Conn(c HalfCloser) End { return connEnd{c} }

type connEnd struct{ HalfCloser }

func (c connEnd) Abort() {
	if tcp, ok := c.HalfCloser.(interface{ SetLinger(int) error }); ok {
		_ = tcp.SetLinger(0)
	}
	_ = c.Close()
}

// past is a deadline that unblocks a read or write at once.
var past = time.Unix(1, 0)

// ServerStream is an HTTP/2 server CONNECT stream as a pipe End. The stock
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

// ClientStream is an HTTP/2 client CONNECT stream as a pipe End.
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
		// An unknown reason from the peer becomes "other", keeping label sets
		// and switches closed.
		reason := Reason(resp.Header.Get(HeaderReason))
		if reason != "" && !reason.Known() {
			reason = "other"
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
