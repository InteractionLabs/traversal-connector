package pipes

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/net/http2"
)

// Receive windows and frame size. The stream window bounds what one stalled
// pipe holds here; the connection window is far larger than any number of
// stalled pipes can fill, so a destination that stops reading never stalls
// the pipes beside it. Large frames carry each pipe's bytes in fewer frames.
const (
	streamWindow = 2 << 20
	connWindow   = 1 << 30
	maxReadFrame = 256 << 10
)

var (
	// errStreamReset is a stream's cause once the caller reset it.
	errStreamReset = errors.New("pipes: stream reset")
	// errConnClosed is a stream's cause once its connection was lost.
	errConnClosed = errors.New("pipes: connection closed")
	// errLocalReset is the cause of a stream this side ended.
	errLocalReset = errors.New("pipes: stream ended here")
)

// h2server serves pipes with the stock golang.org/x/net/http2 server, one
// handler per CONNECT stream. It counts running handlers, so a drain can
// wait for them; streams keep arriving during a drain, so the count cannot
// be a WaitGroup, whose Add may not race Wait.
type h2server struct {
	handle     func(*h2stream)
	maxStreams int
	h2         http2.Server

	mu     sync.Mutex
	active int
	idle   chan struct{} // closed when active falls to zero
}

// newH2Server serves pipes with handle, at most maxStreams at once per
// connection (clamped to [1, 2^20]).
func newH2Server(handle func(*h2stream), maxStreams int) *h2server {
	streams := uint32(min(max(maxStreams, 1), 1<<20))
	return &h2server{
		handle:     handle,
		maxStreams: maxStreams,
		h2: http2.Server{
			MaxConcurrentStreams:         streams,
			MaxUploadBufferPerStream:     streamWindow,
			MaxUploadBufferPerConnection: connWindow,
			MaxReadFrameSize:             maxReadFrame,
		},
	}
}

func (s *h2server) started() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active == 0 {
		s.idle = make(chan struct{})
	}
	s.active++
}

func (s *h2server) done() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.active--
	if s.active == 0 {
		close(s.idle)
	}
}

// wait blocks until no handler is running or ctx is done.
func (s *h2server) wait(ctx context.Context) error {
	s.mu.Lock()
	if s.active == 0 {
		s.mu.Unlock()
		return nil
	}
	idle := s.idle
	s.mu.Unlock()
	select {
	case <-idle:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Accept backoff after a transient failure, as net/http's server does.
const (
	minAcceptBackoff = 5 * time.Millisecond
	maxAcceptBackoff = time.Second
)

// serve accepts connections until ctx is done, then returns nil. A transient
// Accept failure, such as running out of file descriptors, is retried with
// backoff; any other ends serve with the error, for the caller to treat as
// fatal.
func (s *h2server) serve(ctx context.Context, ln net.Listener) error {
	stop := context.AfterFunc(ctx, func() { _ = ln.Close() })
	defer stop()
	backoff := time.Duration(0)
	for {
		nc, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if !transientAcceptError(err) {
				return err
			}
			backoff = min(max(2*backoff, minAcceptBackoff), maxAcceptBackoff)
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return nil
			}
			continue
		}
		backoff = 0
		go s.serveConn(nc)
	}
}

// serveConn serves pipes on one connection until it closes.
func (s *h2server) serveConn(nc net.Conn) { s.serveConnNotify(nc, nil) }

// DrainMethod is the request a draining tunnel gateway sends on a tunnel:
// the connector dials a replacement at once, and keeps serving pipes on this
// tunnel until the gateway closes it.
const DrainMethod = "TRAVERSAL-DRAIN"

// serveConnNotify is serveConn, calling drained once if the peer sends a
// DrainMethod request.
func (s *h2server) serveConnNotify(nc net.Conn, drained func()) {
	var drainOnce sync.Once
	defer func() { _ = nc.Close() }()
	// gone is closed once the connection is: a stream whose body read fails
	// after it was lost the tunnel, not reset by the caller.
	gone := make(chan struct{})
	var once sync.Once
	closed := func() { once.Do(func() { close(gone) }) }
	conn := &watchedConn{Conn: nc, closed: closed}
	s.h2.ServeConn(conn, &http2.ServeConnOpts{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == DrainMethod {
				if drained != nil {
					drainOnce.Do(drained)
				}
				w.WriteHeader(http.StatusOK)
				return
			}
			st := newH2Stream(w, r, gone)
			s.started()
			defer s.done()
			s.handle(st)
			st.finish()
		}),
	})
	closed()
}

// watchedConn reports when a read or write on the connection first fails,
// which is when the server learns the connection is gone.
type watchedConn struct {
	net.Conn
	closed func()
}

func (c *watchedConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if err != nil {
		c.closed()
	}
	return n, err
}

func (c *watchedConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if err != nil {
		c.closed()
	}
	return n, err
}

// h2stream is one CONNECT: Read returns the caller's bytes, Write sends
// bytes back.
//
// The stock server ends a stream only when its handler returns: returning
// sends END_STREAM and, if the caller's half is still open, RST_STREAM
// (NO_ERROR) with it (RFC 9113 §8.1). So CloseWrite here stops reading the
// caller and the stream ends when the pipe does. Bytes the caller sends
// after the destination's FIN are dropped: the one TCP behavior a pipe
// doesn't carry (raw-pipes-e2e's known_limit:send_after_destination_closes).
type h2stream struct {
	w         http.ResponseWriter
	r         *http.Request
	rc        *http.ResponseController
	method    string
	authority string
	header    map[string]string
	// ctx is cancelled once the stream is reset or its connection is lost,
	// with errStreamReset or errConnClosed as the cause, or errLocalReset
	// once this side ended it.
	ctx    context.Context
	cancel context.CancelCauseFunc
	gone   <-chan struct{}

	ended   atomic.Bool // CloseWrite: the destination finished
	aborted atomic.Bool
}

func newH2Stream(w http.ResponseWriter, r *http.Request, gone <-chan struct{}) *h2stream {
	ctx, cancel := context.WithCancelCause(context.Background())
	st := &h2stream{
		w: w, r: r, rc: http.NewResponseController(w),
		method: r.Method, authority: r.Host, header: map[string]string{},
		ctx: ctx, cancel: cancel, gone: gone,
	}
	for k, vs := range r.Header {
		if len(vs) > 0 {
			st.header[http.CanonicalHeaderKey(k)] = vs[0]
		}
	}
	// The request context ends when the caller resets the stream or the
	// connection is lost: tell them apart.
	stop := context.AfterFunc(r.Context(), func() { cancel(st.lostCause()) })
	go func() { <-ctx.Done(); stop() }()
	return st
}

// lostCause is why the stream ended from the caller's side.
func (st *h2stream) lostCause() error {
	select {
	case <-st.gone:
		return errConnClosed
	case <-time.After(10 * time.Millisecond):
		// A connection failure reaches every stream at once; a reset
		// reaches only this one.
	}
	select {
	case <-st.gone:
		return errConnClosed
	default:
		return errStreamReset
	}
}

// headerValue returns the request header name (in any case).
func (st *h2stream) headerValue(name string) string {
	return st.header[http.CanonicalHeaderKey(name)]
}

// respond sends the response headers, ending this direction if end is set.
func (st *h2stream) respond(status string, header map[string]string, end bool) error {
	code, err := strconv.Atoi(status)
	if err != nil {
		return err
	}
	if st.ctx.Err() != nil {
		return context.Cause(st.ctx)
	}
	for k, v := range header {
		st.w.Header().Set(k, v)
	}
	st.w.WriteHeader(code)
	if end {
		st.ended.Store(true)
		return nil
	}
	if err := st.rc.EnableFullDuplex(); err != nil {
		return err
	}
	if err := st.rc.Flush(); err != nil {
		return st.sendErr()
	}
	return nil
}

// sendErr is why a write failed: the stream reset or its connection lost.
func (st *h2stream) sendErr() error {
	if err := context.Cause(st.ctx); err != nil && !errors.Is(err, errLocalReset) {
		return err
	}
	select {
	case <-st.gone:
		return errConnClosed
	default:
		return errStreamReset
	}
}

// Read returns the caller's bytes, io.EOF after its END_STREAM (or once the
// destination finished), errStreamReset after a reset, or errConnClosed once
// the connection is lost.
func (st *h2stream) Read(p []byte) (int, error) {
	if st.ended.Load() {
		return 0, io.EOF
	}
	n, err := st.r.Body.Read(p)
	switch {
	case err == nil, errors.Is(err, io.EOF):
		return n, err
	case st.ended.Load():
		return n, io.EOF
	case st.aborted.Load():
		return n, errStreamReset
	default:
		select {
		case <-st.gone:
			return n, errConnClosed
		default:
			return n, errStreamReset
		}
	}
}

// Write sends p as DATA, within flow control.
func (st *h2stream) Write(p []byte) (int, error) {
	n, err := st.w.Write(p)
	if err == nil {
		err = st.rc.Flush()
	}
	if err != nil {
		return n, st.sendErr()
	}
	return n, nil
}

// CloseWrite ends this direction: the destination finished. The stream ends
// with END_STREAM once the pipe is done; a Read blocked on the caller
// returns io.EOF now.
func (st *h2stream) CloseWrite() error {
	st.ended.Store(true)
	_ = st.rc.SetReadDeadline(time.Unix(1, 0))
	return nil
}

// Abort resets the stream: the destination failed, so the caller must not
// see a clean end. The stock server resets a stream when its handler panics
// with http.ErrAbortHandler, on the handler goroutine: finish does.
func (st *h2stream) Abort() {
	if !st.aborted.CompareAndSwap(false, true) {
		return
	}
	st.cancel(errLocalReset)
	_ = st.rc.SetReadDeadline(time.Unix(1, 0))
	_ = st.rc.SetWriteDeadline(time.Unix(1, 0))
}

// finish runs on the handler goroutine when the pipe is done: returning
// ends the stream (END_STREAM), and an aborted pipe panics so the server
// resets it instead.
func (st *h2stream) finish() {
	defer st.cancel(errLocalReset)
	if st.aborted.Load() {
		panic(http.ErrAbortHandler)
	}
}

// transientAcceptError reports whether Accept may succeed if retried: the
// process or system is out of descriptors or buffers, or one connection was
// aborted before it was accepted.
func transientAcceptError(err error) bool {
	for _, errno := range []syscall.Errno{
		syscall.EMFILE, syscall.ENFILE, syscall.ENOBUFS, syscall.ENOMEM,
		syscall.ECONNABORTED, syscall.ECONNRESET, syscall.EINTR, syscall.EAGAIN,
	} {
		if errors.Is(err, errno) {
			return true
		}
	}
	return false
}
