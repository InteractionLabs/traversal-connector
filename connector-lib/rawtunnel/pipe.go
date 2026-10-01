package rawtunnel

import (
	"context"
	"errors"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"buf.build/go/protovalidate"
	pb "github.com/InteractionLabs/traversal-connector/connector-lib/gen/connector/v1"
	"google.golang.org/protobuf/proto"
)

const (
	maxDetailBytes = 256
	// closeWriteGrace is how long a close record may wait for the peer to
	// read. Past that, the stream window is full and only a reset gets through.
	closeWriteGrace = 50 * time.Millisecond
)

// Local is one end of a pipe. The Mux reads and writes it from its own
// goroutines and closes it when the pipe ends. Close must unblock Read and Write.
type Local interface {
	io.Reader
	io.Writer
	// CloseWrite ends the Local's outbound direction, like a TCP FIN.
	CloseWrite() error
	Close() error
}

// Result describes how a pipe ended.
type Result struct {
	// Reason is unset for a pipe that never opened.
	Reason pb.RawCloseReason
	// BytesSent counts bytes read from the Local and sent to the peer.
	BytesSent int64
	// BytesReceived counts bytes received from the peer and written to the Local.
	BytesReceived int64
}

// OpenError is a refusal returned by WaitOpened.
type OpenError struct {
	Reason pb.RawOpenFailureReason
	Detail string
}

func (e *OpenError) Error() string {
	if e.Detail == "" {
		return "rawtunnel: open refused: " + e.Reason.String()
	}
	return "rawtunnel: open refused: " + e.Reason.String() + ": " + e.Detail
}

// ClosedError is how a pipe ended before it opened, or when WaitOpened is
// called after a reset that carried no open error.
type ClosedError struct {
	Reason pb.RawCloseReason
}

func (e *ClosedError) Error() string {
	return "rawtunnel: pipe closed: " + e.Reason.String()
}

// Pipe is one byte flow inside a tunnel.
type Pipe struct {
	m       *Mux
	id      uint64
	open    *pb.RawOpen
	ctx     context.Context
	cancel  context.CancelFunc
	done    chan struct{}
	opened  chan struct{}
	decided chan struct{}

	reqMu     sync.Mutex
	reqR      *io.PipeReader
	reqW      *io.PipeWriter
	reqCancel context.CancelFunc
	resp      *http.Response

	mu        sync.Mutex
	local     Local
	resolved  bool
	finished  bool
	wasOpened bool
	readHalf  bool
	writeHalf bool
	refusal   *pb.RawOpenError
	openErr   *pb.RawOpenError
	result    Result

	openOnce    sync.Once
	decidedOnce sync.Once
	releaseOnce sync.Once

	sent atomic.Int64
	recv atomic.Int64
	last atomic.Int64
	idle *time.Timer
	life *time.Timer
}

// ID is the controller-assigned pipe id.
func (p *Pipe) ID() uint64 { return p.id }

// Context is cancelled when the pipe ends. Accept may use it to abandon a dial.
func (p *Pipe) Context() context.Context { return p.ctx }

// Done is closed when the pipe has finished.
func (p *Pipe) Done() <-chan struct{} { return p.done }

// Result reports how the pipe ended. It is meaningful after Done is closed.
func (p *Pipe) Result() Result {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.result.BytesSent = p.sent.Load()
	p.result.BytesReceived = p.recv.Load()
	return p.result
}

// WaitOpened blocks until the connector accepts the pipe or the open fails.
func (p *Pipe) WaitOpened(ctx context.Context) error {
	if p.opened == nil {
		return errors.New("rawtunnel: only controller pipes wait to open")
	}
	select {
	case <-p.opened:
	case <-ctx.Done():
		return ctx.Err()
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	switch {
	case p.wasOpened:
		return nil
	case p.openErr != nil:
		return &OpenError{Reason: p.openErr.GetReason(), Detail: p.openErr.GetDetail()}
	default:
		return &ClosedError{Reason: p.result.Reason}
	}
}

// Start connects the pipe to local and begins moving bytes. Start takes
// ownership of local and closes it even when it returns an error.
func (p *Pipe) Start(local Local) error {
	p.mu.Lock()
	switch {
	case p.finished:
		p.mu.Unlock()
		_ = local.Close()
		return ErrPipeClosed
	case p.resolved:
		p.mu.Unlock()
		_ = local.Close()
		return errors.New("rawtunnel: pipe already started or refused")
	case p.m.cfg.Role == RoleController && !p.wasOpened:
		p.mu.Unlock()
		_ = local.Close()
		return errors.New("rawtunnel: pipe has not opened")
	}
	p.resolved = true
	p.local = local
	resp := p.resp
	p.mu.Unlock()
	p.armTimers()
	if p.m.cfg.Role == RoleConnector {
		p.signalDecided()
		return nil
	}
	go func() {
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			p.copyToPeer()
		}()
		go func() {
			defer wg.Done()
			p.copyFromPeer(resp)
		}()
		wg.Wait()
		p.finish(pb.RawCloseReason_RAW_CLOSE_REASON_COMPLETED, "")
	}()
	return nil
}

// Refuse declines a connector pipe instead of starting it.
func (p *Pipe) Refuse(reason pb.RawOpenFailureReason, detail string) error {
	if p.m.cfg.Role != RoleConnector {
		return errors.New("rawtunnel: only the connector refuses pipes")
	}
	msg := &pb.RawOpenError{
		PipeId: p.id, Reason: reason, Detail: truncateDetail(detail),
	}
	if protovalidate.Validate(msg) != nil {
		return errors.New("rawtunnel: invalid refusal")
	}
	p.mu.Lock()
	if p.resolved || p.finished {
		p.mu.Unlock()
		return errors.New("rawtunnel: pipe already started or refused")
	}
	p.resolved = true
	p.refusal = msg
	p.mu.Unlock()
	p.signalDecided()
	p.finish(pb.RawCloseReason_RAW_CLOSE_REASON_UNSPECIFIED, "")
	return nil
}

// Reset aborts the pipe in both directions.
func (p *Pipe) Reset(reason pb.RawCloseReason) {
	if reason == pb.RawCloseReason_RAW_CLOSE_REASON_UNSPECIFIED {
		reason = pb.RawCloseReason_RAW_CLOSE_REASON_PROTOCOL_ERROR
	}
	p.finish(reason, "sent")
}

func (p *Pipe) roundTrip() {
	defer p.signalOpened()
	encoded, err := encodeOpen(p.open)
	if err != nil {
		p.finish(pb.RawCloseReason_RAW_CLOSE_REASON_PROTOCOL_ERROR, "sent")
		return
	}
	// The request outlives the pipe context so a normal close can still write
	// its record. reqCancel aborts it only when that write cannot finish.
	reqCtx, reqCancel := context.WithCancel(p.m.ctx)
	p.reqCancel = reqCancel
	req, err := http.NewRequestWithContext(
		reqCtx, http.MethodPost, "http://tunnel"+pipePath, p.reqR,
	)
	if err != nil {
		p.finish(pb.RawCloseReason_RAW_CLOSE_REASON_PROTOCOL_ERROR, "sent")
		return
	}
	req.ContentLength = -1
	req.Header.Set(headerOpen, encoded)
	resp, err := p.m.cc.RoundTrip(req)
	if err != nil {
		p.finish(pb.RawCloseReason_RAW_CLOSE_REASON_TUNNEL_LOST, "received")
		return
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, helloLimit))
		_ = resp.Body.Close()
		var oe pb.RawOpenError
		if proto.Unmarshal(body, &oe) == nil && protovalidate.Validate(&oe) == nil {
			p.mu.Lock()
			if !p.finished {
				p.openErr = &oe
			}
			p.mu.Unlock()
		}
		p.finish(pb.RawCloseReason_RAW_CLOSE_REASON_UNSPECIFIED, "")
		return
	}
	p.mu.Lock()
	finished := p.finished
	if !finished {
		p.wasOpened = true
		p.resp = resp
	}
	p.mu.Unlock()
	if finished {
		_ = resp.Body.Close()
	}
}

func (p *Pipe) copyToPeer() {
	buf := make([]byte, maxRecord)
	for {
		n, err := p.local.Read(buf)
		if n > 0 {
			p.reqMu.Lock()
			w := p.reqW
			p.reqMu.Unlock()
			var werr error
			if w != nil {
				_, werr = (recordWriter{w: w}).Write(buf[:n])
			}
			if werr != nil {
				if p.m.conn.Lost() {
					p.finish(pb.RawCloseReason_RAW_CLOSE_REASON_TUNNEL_LOST, "received")
					return
				}
				p.finish(pb.RawCloseReason_RAW_CLOSE_REASON_CANCELLED, "sent")
				return
			}
			p.addSent(int64(n))
		}
		if err == nil {
			continue
		}
		if errors.Is(err, io.EOF) {
			p.reqMu.Lock()
			w := p.reqW
			p.reqMu.Unlock()
			if w != nil {
				_ = (recordWriter{w: w}).CloseWrite()
			}
			p.noteWriteHalf()
			return
		}
		p.finish(pb.RawCloseReason_RAW_CLOSE_REASON_CANCELLED, "sent")
		return
	}
}

func (p *Pipe) copyFromPeer(resp *http.Response) {
	if resp == nil {
		p.finish(pb.RawCloseReason_RAW_CLOSE_REASON_TUNNEL_LOST, "received")
		return
	}
	p.readPeer(resp.Body, p.local)
}

// readPeer copies records from r onto local until that direction ends.
// A close record is a reset this side received. A failed write to local is a
// reset this side sends.
func (p *Pipe) readPeer(r io.Reader, local Local) {
	rr := &recordReader{r: r}
	buf := make([]byte, maxRecord)
	for {
		n, err := rr.Read(buf)
		if n > 0 {
			if _, werr := local.Write(buf[:n]); werr != nil {
				p.finish(pb.RawCloseReason_RAW_CLOSE_REASON_UPSTREAM_ERROR, "sent")
				return
			}
			p.addRecv(int64(n))
		}
		if err == nil {
			continue
		}
		var closed *closeError
		switch {
		case errors.As(err, &closed):
			// finish closes local after the reason is stored, so the other
			// direction cannot record a different reason first.
			p.finish(closed.reason, "received")
			return
		case errors.Is(err, errHalfClose):
			_ = local.CloseWrite()
			rr.half = false
			p.noteReadHalf()
			continue
		case errors.Is(err, io.EOF), errors.Is(err, io.ErrClosedPipe):
			_ = local.CloseWrite()
			return
		case errors.Is(err, errRecordTooLarge):
			p.finish(pb.RawCloseReason_RAW_CLOSE_REASON_PROTOCOL_ERROR, "received")
			return
		default:
			// The record source is the tunnel, not the destination.
			p.finish(pb.RawCloseReason_RAW_CLOSE_REASON_TUNNEL_LOST, "received")
			return
		}
	}
}

func (p *Pipe) relay(
	ctx context.Context, local Local, body io.Reader, w io.Writer, flushFn func(),
) {
	// A reset arrives on the request context. The copy can be blocked inside
	// local, so it will not observe the reset on its next read. Closing local
	// is what unblocks it.
	gone := make(chan struct{})
	defer close(gone)
	go func() {
		select {
		case <-ctx.Done():
			reason := pb.RawCloseReason_RAW_CLOSE_REASON_CANCELLED
			if p.m.conn.Lost() {
				reason = pb.RawCloseReason_RAW_CLOSE_REASON_TUNNEL_LOST
			}
			p.finish(reason, "received")
		case <-gone:
		}
	}()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		p.readPeer(body, local)
	}()
	go func() {
		defer wg.Done()
		rw := recordWriter{w: w, flush: flushFn}
		n, err := io.Copy(rw, local)
		p.addSent(int64(n))
		if err == nil {
			_ = rw.CloseWrite()
			p.noteWriteHalf()
			return
		}
		reason := p.Result().Reason
		if reason == pb.RawCloseReason_RAW_CLOSE_REASON_UNSPECIFIED {
			if p.m.conn.Lost() {
				p.finish(pb.RawCloseReason_RAW_CLOSE_REASON_TUNNEL_LOST, "received")
				return
			}
			reason = pb.RawCloseReason_RAW_CLOSE_REASON_UPSTREAM_ERROR
		}
		_ = rw.frameClose(reason)
		p.finish(reason, "sent")
	}()
	wg.Wait()
	p.finish(pb.RawCloseReason_RAW_CLOSE_REASON_COMPLETED, "")
}

func (p *Pipe) noteReadHalf() {
	p.mu.Lock()
	p.readHalf = true
	both := p.writeHalf
	p.mu.Unlock()
	if both {
		p.finish(pb.RawCloseReason_RAW_CLOSE_REASON_COMPLETED, "")
	}
}

func (p *Pipe) noteWriteHalf() {
	p.mu.Lock()
	p.writeHalf = true
	both := p.readHalf
	p.mu.Unlock()
	if both {
		p.finish(pb.RawCloseReason_RAW_CLOSE_REASON_COMPLETED, "")
	}
}

func (p *Pipe) finish(reason pb.RawCloseReason, origin string) {
	p.mu.Lock()
	if p.finished {
		p.mu.Unlock()
		return
	}
	p.finished = true
	if p.result.Reason == pb.RawCloseReason_RAW_CLOSE_REASON_UNSPECIFIED &&
		reason != pb.RawCloseReason_RAW_CLOSE_REASON_UNSPECIFIED {
		p.result.Reason = reason
	}
	local := p.local
	report := origin != "" && p.result.Reason != pb.RawCloseReason_RAW_CLOSE_REASON_COMPLETED
	reported := p.result.Reason
	p.mu.Unlock()

	if p.idle != nil {
		p.idle.Stop()
	}
	if p.life != nil {
		p.life.Stop()
	}
	// Connector dials are bound to the pipe context. The controller's HTTP/2
	// request is not: cancelling it resets the stream and can drop a close
	// record that is still buffered.
	if p.m.cfg.Role == RoleConnector {
		p.cancel()
	}
	// The data stream's window may already be full, so the close record below
	// cannot pass. The control stream is a different window.
	if origin == "sent" {
		p.m.notifyPeer(p.id, reported)
	}
	if local != nil {
		_ = local.Close()
	}
	p.reqMu.Lock()
	reqW := p.reqW
	p.reqW = nil
	p.reqMu.Unlock()
	if reqW != nil {
		p.writeClose(reqW, reported)
	}
	p.signalDecided()
	p.signalOpened()
	p.releaseOnce.Do(func() { p.m.release(p) })
	if report && p.m.cfg.OnReset != nil {
		phase := "opening"
		if p.wasOpened || local != nil {
			phase = "open"
		}
		p.m.cfg.OnReset(origin, phase, reported)
	}
	close(p.done)
}

func (p *Pipe) writeClose(reqW *io.PipeWriter, reason pb.RawCloseReason) {
	go func() {
		if reason != pb.RawCloseReason_RAW_CLOSE_REASON_UNSPECIFIED &&
			reason != pb.RawCloseReason_RAW_CLOSE_REASON_COMPLETED {
			_ = (recordWriter{w: reqW}).frameClose(reason)
		}
		_ = reqW.Close()
	}()
	if reason == pb.RawCloseReason_RAW_CLOSE_REASON_UNSPECIFIED ||
		reason == pb.RawCloseReason_RAW_CLOSE_REASON_COMPLETED {
		return
	}
	// A full stream window accepts the record into the pipe and then waits
	// forever to send it. Reset is not flow-controlled. Closing the body
	// unblocks the writer that is holding the pipe.
	time.AfterFunc(closeWriteGrace, func() {
		if p.reqR != nil {
			_ = p.reqR.Close()
		}
		if p.reqCancel != nil {
			p.reqCancel()
		}
	})
}

func (p *Pipe) signalOpened() {
	if p.opened == nil {
		return
	}
	p.openOnce.Do(func() { close(p.opened) })
}

func (p *Pipe) signalDecided() {
	if p.decided == nil {
		return
	}
	p.decidedOnce.Do(func() { close(p.decided) })
}

func (p *Pipe) armTimers() {
	p.last.Store(time.Now().UnixNano())
	p.idle = time.AfterFunc(p.m.cfg.IdleTimeout, p.onIdle)
	p.life = time.AfterFunc(p.m.cfg.MaxLifetime, func() {
		p.finish(pb.RawCloseReason_RAW_CLOSE_REASON_MAX_LIFETIME, "sent")
	})
}

func (p *Pipe) onIdle() {
	idle := time.Duration(time.Now().UnixNano() - p.last.Load())
	if idle < p.m.cfg.IdleTimeout {
		p.idle.Reset(p.m.cfg.IdleTimeout - idle)
		return
	}
	p.finish(pb.RawCloseReason_RAW_CLOSE_REASON_IDLE_TIMEOUT, "sent")
}

func (p *Pipe) addSent(n int64) {
	if n <= 0 {
		return
	}
	p.sent.Add(n)
	p.last.Store(time.Now().UnixNano())
}

func (p *Pipe) addRecv(n int64) {
	if n <= 0 {
		return
	}
	p.recv.Add(n)
	p.last.Store(time.Now().UnixNano())
}

func truncateDetail(detail string) string {
	if len(detail) <= maxDetailBytes {
		return detail
	}
	cut := maxDetailBytes
	for cut > 0 && !utf8.RuneStart(detail[cut]) {
		cut--
	}
	return detail[:cut]
}
