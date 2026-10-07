package pipes

import (
	"bytes"
	"context"
	"errors"
	"io"
	"math"
	"net"
	"sync"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// A minimal HTTP/2 server for CONNECT streams.
//
// net/http's server sends RST_STREAM(NO_ERROR) when a handler returns before
// the request body ends (RFC 9113 §8.1 allows it). Envoy turns that reset into
// an abort of the downstream stream and drops response bytes still queued
// behind flow control, so a destination that writes and closes while the
// caller is still open loses its tail. A server where "handler returned" means
// "stream done" also cannot keep one direction open after the other ends,
// which TCP can. So the pipe server frames HTTP/2 itself: each direction ends
// with its own END_STREAM, and RST_STREAM is sent only to abort.
//
// Only the connector's own Envoy reaches this server, over loopback. It still
// enforces its receive windows and stream limit, so a misbehaving peer costs
// bounded memory.

// Receive windows. The stream window bounds what one stalled pipe holds here;
// Envoy is on loopback, so it is small and still carries a pipe at full speed.
// The connection window is far larger than any number of stalled pipes can
// fill, so a destination that stops reading never stalls the pipes beside it.
const (
	streamWindow = 256 << 10
	connWindow   = 1 << 30
	defaultWin   = 65535
	maxFrameSize = 16 << 10
	maxHeaders   = 64 << 10
)

var (
	errStreamReset = errors.New("pipes: stream reset")
	errConnClosed  = errors.New("pipes: connection closed")
	// errLocalReset is the cause of a stream this side ended: an abort, or
	// a handler that returned.
	errLocalReset = errors.New("pipes: stream ended here")
)

// h2server accepts HTTP/2 cleartext connections and runs handle for every
// stream. It counts running handlers, so a drain can wait for them; streams
// keep arriving during a drain, so the count cannot be a WaitGroup, whose Add
// may not race Wait.
type h2server struct {
	handle     func(*h2stream)
	maxStreams int

	mu     sync.Mutex
	active int
	idle   chan struct{} // closed when active falls to zero
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

func (s *h2server) serve(ctx context.Context, ln net.Listener) error {
	stop := context.AfterFunc(ctx, func() { _ = ln.Close() })
	defer stop()
	for {
		nc, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go s.serveConn(nc)
	}
}

type h2conn struct {
	nc  net.Conn
	fr  *http2.Framer
	wmu sync.Mutex // serializes frame writes and the HPACK encoder
	enc *hpack.Encoder
	buf bytes.Buffer

	mu            sync.Mutex
	cond          *sync.Cond
	sendWin       int64 // connection send window
	recvUsed      int64 // bytes received and not yet credited back
	connPending   int64 // bytes consumed by handlers, not yet credited back
	peerStreamWin int64 // peer's SETTINGS_INITIAL_WINDOW_SIZE
	maxFrame      int
	streams       map[uint32]*h2stream
	lastStream    uint32
	err           error // set once the connection is gone
}

// h2stream is one CONNECT. Read returns the caller's bytes; Write sends bytes
// back.
type h2stream struct {
	c         *h2conn
	id        uint32
	method    string
	authority string
	header    map[string]string
	// ctx is cancelled once the stream is reset or its connection is lost,
	// with errStreamReset (the peer reset it), errConnClosed, or
	// errLocalReset as the cause. It lets a handler stop work no one will
	// read, even while it is not reading the stream.
	ctx    context.Context
	cancel context.CancelCauseFunc

	// Guarded by c.mu.
	sendWin  int64
	pending  int64 // bytes the handler consumed, not yet credited back
	in       bytes.Buffer
	inErr    error // io.EOF after END_STREAM; errStreamReset after RST_STREAM
	reset    bool  // RST_STREAM sent or received: no more frames
	localEnd bool  // END_STREAM sent
}

func newStream(c *h2conn, id uint32) *h2stream {
	ctx, cancel := context.WithCancelCause(context.Background())
	return &h2stream{c: c, id: id, sendWin: c.peerStreamWin, ctx: ctx, cancel: cancel}
}

func (s *h2server) serveConn(nc net.Conn) {
	defer func() { _ = nc.Close() }()
	preface := make([]byte, len(http2.ClientPreface))
	if _, err := io.ReadFull(nc, preface); err != nil ||
		string(preface) != http2.ClientPreface {
		return
	}
	c := &h2conn{
		nc:            nc,
		fr:            http2.NewFramer(nc, nc),
		sendWin:       defaultWin,
		peerStreamWin: defaultWin,
		maxFrame:      maxFrameSize,
		streams:       map[uint32]*h2stream{},
	}
	c.cond = sync.NewCond(&c.mu)
	c.enc = hpack.NewEncoder(&c.buf)
	c.fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	c.fr.MaxHeaderListSize = maxHeaders
	settings := []http2.Setting{{ID: http2.SettingInitialWindowSize, Val: streamWindow}}
	if s.maxStreams > 0 {
		settings = append(settings, http2.Setting{
			ID:  http2.SettingMaxConcurrentStreams,
			Val: windowIncrement(int64(s.maxStreams)),
		})
	}
	_ = c.write(func() error {
		if err := c.fr.WriteSettings(settings...); err != nil {
			return err
		}
		return c.fr.WriteWindowUpdate(0, connWindow-defaultWin)
	})
	err := c.readLoop(s)
	if errors.Is(err, errProtocol) {
		_ = c.write(func() error {
			return c.fr.WriteGoAway(c.lastStream, http2.ErrCodeProtocol, nil)
		})
	}
	c.mu.Lock()
	c.err = errConnClosed
	for _, st := range c.streams {
		if st.inErr == nil {
			st.inErr = errConnClosed
		}
		st.reset = true
		st.cancel(errConnClosed)
	}
	c.cond.Broadcast()
	c.mu.Unlock()
}

var errProtocol = errors.New("pipes: peer violated HTTP/2")

// write runs fn with the write lock. A failed write ends the connection;
// errStreamReset or errConnClosed from fn means only that the stream can no
// longer send.
//
// Lock order: wmu, then mu. A stream's state is re-checked under both locks
// right before its frame is written, so no frame follows the stream's
// RST_STREAM or its END_STREAM.
func (c *h2conn) write(fn func() error) error {
	c.wmu.Lock()
	err := fn()
	c.wmu.Unlock()
	if err != nil && !errors.Is(err, errStreamReset) && !errors.Is(err, errConnClosed) {
		_ = c.nc.Close()
	}
	return err
}

// sendErr reports why st may no longer send frames, or nil if it may: the
// connection is gone (errConnClosed) or the stream ended (errStreamReset).
// c.mu must be held.
func (st *h2stream) sendErr() error {
	switch {
	case st.c.err != nil:
		return errConnClosed
	case st.reset || st.localEnd:
		return errStreamReset
	}
	return nil
}

func (c *h2conn) readLoop(s *h2server) error {
	for {
		f, err := c.fr.ReadFrame()
		if err != nil {
			var se http2.StreamError
			if errors.As(err, &se) {
				c.resetStream(se.StreamID, se.Code)
				continue
			}
			var ce http2.ConnectionError
			if errors.As(err, &ce) {
				return errProtocol
			}
			return err
		}
		switch f := f.(type) {
		case *http2.MetaHeadersFrame:
			c.onHeaders(s, f)
		case *http2.DataFrame:
			if err := c.onData(f); err != nil {
				return err
			}
		case *http2.WindowUpdateFrame:
			if err := c.onWindowUpdate(f); err != nil {
				return err
			}
		case *http2.SettingsFrame:
			if f.IsAck() {
				continue
			}
			if err := c.onSettings(f); err != nil {
				return err
			}
			if err := c.write(c.fr.WriteSettingsAck); err != nil {
				return err
			}
		case *http2.PingFrame:
			if !f.IsAck() {
				data := f.Data
				if err := c.write(func() error { return c.fr.WritePing(true, data) }); err != nil {
					return err
				}
			}
		case *http2.RSTStreamFrame:
			c.mu.Lock()
			dropped := 0
			if st := c.streams[f.StreamID]; st != nil {
				dropped = st.dropBuffered()
				st.inErr, st.reset = errStreamReset, true
				st.cancel(errStreamReset)
				c.cond.Broadcast()
			}
			c.mu.Unlock()
			if err := c.credit(dropped); err != nil {
				return err
			}
		}
	}
}

func (c *h2conn) onSettings(f *http2.SettingsFrame) error {
	return f.ForeachSetting(func(set http2.Setting) error {
		if err := set.Valid(); err != nil {
			return errProtocol
		}
		c.mu.Lock()
		defer c.mu.Unlock()
		switch set.ID {
		case http2.SettingInitialWindowSize:
			delta := int64(set.Val) - c.peerStreamWin
			c.peerStreamWin = int64(set.Val)
			for _, st := range c.streams {
				st.sendWin += delta
				if st.sendWin > math.MaxInt32 {
					return errProtocol
				}
			}
			c.cond.Broadcast()
		case http2.SettingMaxFrameSize:
			c.maxFrame = int(set.Val)
		}
		return nil
	})
}

func (c *h2conn) onWindowUpdate(f *http2.WindowUpdateFrame) error {
	c.mu.Lock()
	overflow := false
	if f.StreamID == 0 {
		c.sendWin += int64(f.Increment)
		if c.sendWin > math.MaxInt32 {
			c.mu.Unlock()
			return errProtocol
		}
	} else if st := c.streams[f.StreamID]; st != nil {
		st.sendWin += int64(f.Increment)
		overflow = st.sendWin > math.MaxInt32
	}
	c.cond.Broadcast()
	c.mu.Unlock()
	if overflow {
		// A stream error (RFC 9113 §6.9.1): reset the stream on the wire,
		// or the peer's side of it hangs.
		c.resetStream(f.StreamID, http2.ErrCodeFlowControl)
	}
	return nil
}

func (c *h2conn) onHeaders(s *h2server, f *http2.MetaHeadersFrame) {
	c.mu.Lock()
	if st := c.streams[f.StreamID]; st != nil {
		// Trailers: only END_STREAM matters.
		if f.StreamEnded() && st.inErr == nil {
			st.inErr = io.EOF
			c.cond.Broadcast()
		}
		c.mu.Unlock()
		return
	}
	if f.StreamID <= c.lastStream {
		// A closed stream's late HEADERS, or a reused ID: never a new pipe.
		c.mu.Unlock()
		c.resetStream(f.StreamID, http2.ErrCodeStreamClosed)
		return
	}
	c.lastStream = f.StreamID
	if s.maxStreams > 0 && len(c.streams) >= s.maxStreams {
		c.mu.Unlock()
		c.resetStream(f.StreamID, http2.ErrCodeRefusedStream)
		return
	}
	st := newStream(c, f.StreamID)
	st.method = f.PseudoValue("method")
	st.authority = f.PseudoValue("authority")
	st.header = map[string]string{}
	for _, hf := range f.RegularFields() {
		st.header[hf.Name] = hf.Value
	}
	if f.StreamEnded() {
		st.inErr = io.EOF
	}
	c.streams[f.StreamID] = st
	c.mu.Unlock()
	s.started()
	go func() {
		defer s.done()
		defer st.finish()
		s.handle(st)
	}()
}

// onData buffers a stream's bytes. A peer that sends past either receive
// window is broken, and the connection ends rather than buffering without
// bound.
func (c *h2conn) onData(f *http2.DataFrame) error {
	data := f.Data()
	credit := f.Length - windowIncrement(int64(len(data))) // padding is consumed at once
	c.mu.Lock()
	c.recvUsed += int64(f.Length)
	if c.recvUsed > connWindow {
		c.mu.Unlock()
		return errProtocol
	}
	st := c.streams[f.StreamID]
	switch {
	case st == nil || st.inErr != nil:
		credit = f.Length // nobody will read it
	case int64(st.in.Len())+st.pending+int64(f.Length) > streamWindow:
		c.mu.Unlock()
		c.resetStream(f.StreamID, http2.ErrCodeFlowControl)
		c.mu.Lock()
		credit = f.Length
	default:
		st.in.Write(data)
		// Padding counts against the stream window too; credit it with
		// the stream's consumed bytes.
		st.pending += int64(credit)
		if f.StreamEnded() {
			st.inErr = io.EOF
		}
		c.cond.Broadcast()
	}
	c.recvUsed -= int64(credit)
	c.mu.Unlock()
	if credit > 0 {
		return c.write(func() error { return c.fr.WriteWindowUpdate(0, credit) })
	}
	return nil
}

func (c *h2conn) resetStream(id uint32, code http2.ErrCode) {
	c.mu.Lock()
	dropped := 0
	if st := c.streams[id]; st != nil {
		dropped = st.dropBuffered()
		st.inErr, st.reset = errStreamReset, true
		st.cancel(errStreamReset)
		c.cond.Broadcast()
	}
	c.mu.Unlock()
	_ = c.write(func() error { return c.fr.WriteRSTStream(id, code) })
	_ = c.credit(dropped)
}

// dropBuffered discards bytes nobody will read and returns how many, for
// the caller to credit back to the connection window. c.mu must be held.
func (st *h2stream) dropBuffered() int {
	n := st.in.Len()
	st.in.Reset()
	st.c.recvUsed -= int64(n)
	return n
}

// credit returns n received bytes to the peer's connection window.
func (c *h2conn) credit(n int) error {
	if n == 0 {
		return nil
	}
	return c.write(func() error { return c.fr.WriteWindowUpdate(0, windowIncrement(int64(n))) })
}

// windowIncrement converts a byte count to a WINDOW_UPDATE increment. Counts
// here are bounded by the receive windows, far below the HTTP/2 maximum.
func windowIncrement(n int64) uint32 {
	if n <= 0 {
		return 0
	}
	if n > math.MaxInt32 {
		return math.MaxInt32
	}
	return uint32(n)
}

// Read returns the caller's bytes, io.EOF after its END_STREAM, or
// errStreamReset after an abort. Consumed bytes are credited back, so a
// destination that stops reading stops the caller. Credit is batched: a
// WINDOW_UPDATE goes out once a quarter of a window has been consumed, not
// for every read, which would cost two frames per read.
func (st *h2stream) Read(p []byte) (int, error) {
	c := st.c
	c.mu.Lock()
	for st.in.Len() == 0 && st.inErr == nil {
		c.cond.Wait()
	}
	if st.in.Len() == 0 {
		err := st.inErr
		c.mu.Unlock()
		return 0, err
	}
	n, _ := st.in.Read(p)
	var streamCredit, connCredit int64
	if st.inErr == nil {
		st.pending += int64(n)
		if st.pending >= streamWindow/creditFraction {
			streamCredit, st.pending = st.pending, 0
		}
	}
	c.connPending += int64(n)
	if c.connPending >= connWindow/creditFraction {
		connCredit, c.connPending = c.connPending, 0
		c.recvUsed -= connCredit
	}
	c.mu.Unlock()
	if streamCredit > 0 || connCredit > 0 {
		_ = c.write(func() error {
			if streamCredit > 0 {
				if err := c.fr.WriteWindowUpdate(st.id, windowIncrement(streamCredit)); err != nil {
					return err
				}
			}
			if connCredit > 0 {
				return c.fr.WriteWindowUpdate(0, windowIncrement(connCredit))
			}
			return nil
		})
	}
	return n, nil
}

// creditFraction is how much of a window is consumed before it is credited
// back: a quarter.
const creditFraction = 4

// Write sends p as DATA within both send windows. It fails with
// errConnClosed once the connection is gone, and errStreamReset once only
// the stream is.
func (st *h2stream) Write(p []byte) (int, error) {
	c := st.c
	written := 0
	for len(p) > 0 {
		c.mu.Lock()
		for (st.sendWin <= 0 || c.sendWin <= 0) && !st.reset && c.err == nil {
			c.cond.Wait()
		}
		if err := st.sendErr(); err != nil {
			c.mu.Unlock()
			return written, err
		}
		n := int(min(int64(len(p)), int64(c.maxFrame), st.sendWin, c.sendWin))
		st.sendWin -= int64(n)
		c.sendWin -= int64(n)
		c.mu.Unlock()
		chunk := p[:n]
		if err := c.write(func() error {
			c.mu.Lock()
			err := st.sendErr()
			c.mu.Unlock()
			if err != nil {
				return err
			}
			return c.fr.WriteData(st.id, false, chunk)
		}); err != nil {
			// The chunk never went out, so the peer will never credit it:
			// return the reservation, or the connection loses it for good.
			c.mu.Lock()
			st.sendWin += int64(n)
			c.sendWin += int64(n)
			c.cond.Broadcast()
			c.mu.Unlock()
			if !errors.Is(err, errStreamReset) {
				err = errConnClosed // a failed frame write ends the connection
			}
			return written, err
		}
		p, written = p[n:], written+n
	}
	return written, nil
}

// respond sends the response headers, ending this direction if end is set.
func (st *h2stream) respond(status string, header map[string]string, end bool) error {
	c := st.c
	return c.write(func() error {
		c.mu.Lock()
		if st.reset || c.err != nil {
			c.mu.Unlock()
			return errStreamReset
		}
		st.localEnd = end
		c.mu.Unlock()
		c.buf.Reset()
		_ = c.enc.WriteField(hpack.HeaderField{Name: ":status", Value: status})
		for k, v := range header {
			_ = c.enc.WriteField(hpack.HeaderField{Name: k, Value: v})
		}
		return c.fr.WriteHeaders(http2.HeadersFrameParam{
			StreamID:      st.id,
			BlockFragment: c.buf.Bytes(),
			EndHeaders:    true,
			EndStream:     end,
		})
	})
}

// CloseWrite ends this direction with END_STREAM: the destination finished.
func (st *h2stream) CloseWrite() error {
	c := st.c
	err := c.write(func() error {
		c.mu.Lock()
		if st.reset || st.localEnd || c.err != nil {
			c.mu.Unlock()
			return nil
		}
		st.localEnd = true
		c.mu.Unlock()
		return c.fr.WriteData(st.id, true, nil)
	})
	if errors.Is(err, errStreamReset) {
		return nil
	}
	return err
}

// Abort resets the stream: the destination failed, so the caller must not see
// a clean end.
func (st *h2stream) Abort() {
	c := st.c
	_ = c.write(func() error {
		c.mu.Lock()
		if st.reset || c.err != nil {
			c.mu.Unlock()
			return nil
		}
		st.reset = true
		if st.inErr == nil {
			st.inErr = errStreamReset
		}
		st.cancel(errLocalReset)
		c.cond.Broadcast()
		c.mu.Unlock()
		return c.fr.WriteRSTStream(st.id, http2.ErrCodeInternal)
	})
}

// finish forgets the stream once its handler is done and returns the window
// held by bytes nobody will read. A handler that ended its direction is done,
// even if the caller is still sending: resetting here is what truncates
// responses behind Envoy, so the caller's late bytes are dropped and credited
// instead. Only a handler that never ended its direction resets the stream.
func (st *h2stream) finish() {
	c := st.c
	c.mu.Lock()
	left := st.dropBuffered()
	// Credit what this stream consumed but never credited, so a connection
	// with few, short pipes does not hold the peer's window down.
	left += int(c.connPending)
	c.recvUsed -= c.connPending
	c.connPending = 0
	unfinished := !st.reset && !st.localEnd
	// Nothing may follow on this stream once it is forgotten: a late Abort
	// (a lifetime timer) or Write sends no frame.
	st.reset = true
	st.cancel(errLocalReset)
	delete(c.streams, st.id)
	c.mu.Unlock()
	if unfinished {
		_ = c.write(func() error { return c.fr.WriteRSTStream(st.id, http2.ErrCodeCancel) })
	}
	_ = c.credit(left)
}
