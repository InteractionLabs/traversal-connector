// Package rawtunnel runs the pipe protocol carried by ConnectorService.RawTunnel.
//
// Both ends of a raw tunnel run a Mux over the same bidirectional stream: the
// controller in RoleController and the connector in RoleConnector. The Mux
// multiplexes many pipes, each an opaque byte stream between a Local on each
// side, and owns everything after the hello exchange: pipe lifecycle,
// credit-based flow control, frame scheduling, drain, and keepalive replies.
//
// Flow control bounds memory per pipe. A Mux reads from a Local only when the
// peer has granted send credit, never more than MaxDataBytes at a time, and
// holds at most Window received bytes per pipe that its Local has not yet
// accepted. Control frames are sent before data frames, and data frames from
// different pipes are sent round-robin, so one stalled pipe cannot delay
// another pipe or the tunnel's control traffic.
//
// A stalled pipe stops only its own sends. A slow destination fills the
// connection window the same way a frozen peer does, and a bulk transfer is
// allowed to pause, so a blocked write does not end the tunnel. The Mux sends
// its own pings so an idle tunnel still produces traffic. A ping that goes
// unanswered does not end it: the acknowledgement is written by the same send
// loop a slow pipe can block. A peer that has stopped running is detected by
// the HTTP/2 connection. ConfigureHTTP2 sets those timeouts. When they close
// the connection, Send and Receive return and the tunnel ends.
package rawtunnel

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
	"unicode/utf8"

	"buf.build/go/protovalidate"

	pb "github.com/InteractionLabs/traversal-connector/connector-lib/gen/connector/v1"
)

const (
	// ProtocolVersion is the raw tunnel protocol version this package speaks.
	ProtocolVersion = 1
	// MaxDataBytes is the largest payload of one data frame.
	MaxDataBytes = 32 << 10
	// Window is the send credit each direction of a pipe starts with, and the
	// most it can ever hold.
	Window = 256 << 10
	// DefaultIdleTimeout ends a pipe on which no bytes moved in either
	// direction for this long.
	DefaultIdleTimeout = 15 * time.Minute
	// DefaultMaxLifetime ends a pipe this long after it opened.
	DefaultMaxLifetime = 4 * time.Hour
	// DefaultPingInterval is how often a tunnel pings its peer.
	DefaultPingInterval = 30 * time.Second
	// DefaultPingTimeout is how long Ping waits for an acknowledgement. A miss
	// does not end the tunnel: the peer may be unable to write it while a slow
	// pipe blocks its send loop.
	DefaultPingTimeout = 10 * time.Second
	// DefaultWriteByteTimeout is how long an HTTP/2 connection write may make
	// no progress before the connection is closed. Flow control does not start
	// this clock: a slow destination does not look like a dead connection.
	DefaultWriteByteTimeout = 30 * time.Second
)

// grantThreshold is how many consumed bytes a pipe accumulates before it
// returns them to the peer as credit. Returning credit in half-window steps
// keeps window updates rare without letting a sender run dry.
const grantThreshold = Window / 2

var (
	// ErrClosed reports that the tunnel has ended.
	ErrClosed = errors.New("rawtunnel: tunnel closed")
	// ErrDraining reports that the tunnel accepts no new pipes.
	ErrDraining = errors.New("rawtunnel: tunnel draining")
	// ErrCapacity reports that the tunnel already carries its maximum number
	// of pipes.
	ErrCapacity = errors.New("rawtunnel: tunnel at pipe capacity")
	// ErrPipeClosed reports that a pipe ended before it could be started.
	ErrPipeClosed = errors.New("rawtunnel: pipe closed")
)

// ProtocolError reports a peer frame that violates the tunnel protocol. It
// ends the tunnel.
type ProtocolError struct {
	msg string
}

func (e *ProtocolError) Error() string {
	return "rawtunnel: protocol error: " + e.msg
}

func protocolErrorf(format string, args ...any) *ProtocolError {
	return &ProtocolError{msg: fmt.Sprintf(format, args...)}
}

// Role selects which side of the protocol a Mux implements.
type Role int

const (
	// RoleController opens pipes.
	RoleController Role = iota + 1
	// RoleConnector accepts pipes and connects them to destinations.
	RoleConnector
)

// Stream is the tunnel's bidirectional frame stream. Connect's client and
// server bidirectional streams both implement it. Send must not retain the
// frame after it returns.
type Stream interface {
	Send(*pb.RawTunnelFrame) error
	Receive() (*pb.RawTunnelFrame, error)
}

// Config configures a Mux.
type Config struct {
	Role Role
	// MaxPipes is the most pipes the tunnel carries at once. A controller must
	// not exceed the connector's advertised RawConnectorHello.max_pipes.
	MaxPipes int
	// IdleTimeout defaults to DefaultIdleTimeout.
	IdleTimeout time.Duration
	// MaxLifetime defaults to DefaultMaxLifetime.
	MaxLifetime time.Duration
	// PingInterval is how often the tunnel pings its peer. Zero uses
	// DefaultPingInterval.
	PingInterval time.Duration
	// PingTimeout is how long Ping waits for an acknowledgement. A miss does not
	// end the tunnel. Zero uses DefaultPingTimeout.
	PingTimeout time.Duration
	// Accept is required for RoleConnector and invalid for RoleController. The
	// Mux calls it on a new goroutine for every admitted open, and it must
	// eventually call exactly one of Pipe.Start or Pipe.Refuse. The pipe's
	// Context is cancelled if the pipe ends first, so Accept can abandon a dial.
	Accept func(p *Pipe, open *pb.RawOpen)
	// Abort releases a Send or Receive blocked on the stream. The Mux calls it
	// once, when the tunnel ends, and Run does not return until Abort has
	// returned. It must not block and must not use the Mux.
	//
	// For a Connect server, set the handler response's read and write deadlines
	// to the past. For a Connect client, cancel the call context. Call
	// ConfigureHTTP2 on that client and server as well: a stream write deadline
	// cannot unblock a connection write that has stopped making progress,
	// because the reset it queues is stuck behind that write.
	Abort func()
}

// Mux runs one raw tunnel. Create it with New, then call Run.
type Mux struct {
	cfg                                        Config
	stream                                     Stream
	kick                                       chan struct{}
	done                                       chan struct{}
	sendStopped, recvStopped, keepaliveStopped chan struct{}
	abortStopped                               chan struct{}
	abortOnce                                  sync.Once
	pingMu                                     sync.Mutex

	mu      sync.Mutex
	running bool
	err     error // why the tunnel ended; nil while it runs
	closing bool

	pipes map[uint64]*Pipe
	// lastID is the controller's last allocated pipe ID, or the connector's
	// last accepted one. IDs at or below it that are absent from pipes are
	// retired, and frames for them are ignored.
	lastID uint64
	// slots counts pipes against MaxPipes until both sides have released them.
	slots int

	control []*Pipe // pipes with pending control frames, each at most once
	ready   []*Pipe // pipes with a data chunk waiting to be sent

	localDrain, peerDrain bool
	drainReason           pb.RawDrainReason
	drainPending          bool
	draining, drained     chan struct{}
	// pendingOpens counts queued, unsent opens. A controller's drain waits for
	// them, so the connector never sees an open after the drain.
	pendingOpens int

	pingSeq, pingNonce uint64
	pingPending        bool
	pingWaiter         chan struct{}
	pingAckPending     bool
	pingAckNonce       uint64
}

// New validates cfg and returns a Mux for stream. The caller performs the hello
// exchange on stream before calling Run.
func New(cfg Config, stream Stream) (*Mux, error) {
	switch {
	case cfg.Role != RoleController && cfg.Role != RoleConnector:
		return nil, errors.New("rawtunnel: invalid role")
	case cfg.MaxPipes <= 0:
		return nil, errors.New("rawtunnel: MaxPipes must be positive")
	case cfg.Role == RoleConnector && cfg.Accept == nil:
		return nil, errors.New("rawtunnel: RoleConnector requires Accept")
	case cfg.Role == RoleController && cfg.Accept != nil:
		return nil, errors.New("rawtunnel: RoleController does not accept pipes")
	case cfg.IdleTimeout < 0 || cfg.MaxLifetime < 0 || cfg.PingInterval < 0 || cfg.PingTimeout < 0:
		return nil, errors.New("rawtunnel: timeouts must not be negative")
	case cfg.Abort == nil:
		return nil, errors.New("rawtunnel: Abort is required")
	}
	if cfg.IdleTimeout == 0 {
		cfg.IdleTimeout = DefaultIdleTimeout
	}
	if cfg.MaxLifetime == 0 {
		cfg.MaxLifetime = DefaultMaxLifetime
	}
	if cfg.PingInterval == 0 {
		cfg.PingInterval = DefaultPingInterval
	}
	if cfg.PingTimeout == 0 {
		cfg.PingTimeout = DefaultPingTimeout
	}
	return &Mux{
		cfg:              cfg,
		stream:           stream,
		kick:             make(chan struct{}, 1),
		done:             make(chan struct{}),
		sendStopped:      make(chan struct{}),
		recvStopped:      make(chan struct{}),
		keepaliveStopped: make(chan struct{}),
		abortStopped:     make(chan struct{}),
		pipes:            make(map[uint64]*Pipe),
		draining:         make(chan struct{}),
		drained:          make(chan struct{}),
	}, nil
}

// Run sends and receives frames until the tunnel ends, ends every pipe, and
// returns why: ErrClosed after Close, ctx's error when ctx is done, a
// *ProtocolError when the peer broke the protocol, or the stream's error.
//
// When the tunnel ends, Run calls Abort and does not return until Abort, Send,
// and Receive have all finished. The stream is unused when Run returns, so a
// server handler can return immediately.
func (m *Mux) Run(ctx context.Context) error {
	m.mu.Lock()
	if m.running {
		m.mu.Unlock()
		return errors.New("rawtunnel: Run called twice")
	}
	m.running = true
	m.mu.Unlock()

	stop := context.AfterFunc(ctx, func() { m.end(ctx.Err()) })
	defer stop()
	go m.receiveLoop()
	go m.sendLoop()
	go m.keepalive(ctx)
	<-m.done
	<-m.sendStopped
	<-m.recvStopped
	<-m.keepaliveStopped
	// Abort runs on whichever goroutine ended the tunnel, which may not be
	// this one. Wait for it before returning: the handler must not return,
	// and net/http must not tear the response down, while Abort still uses it.
	<-m.abortStopped
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.err
}

func (m *Mux) sendLoop() {
	defer close(m.sendStopped)
	for {
		m.mu.Lock()
		f, sent := m.nextFrameLocked()
		var closeSend func() error
		ended := false
		if f == nil && m.err == nil && m.closing && len(m.control) == 0 &&
			(m.cfg.Role == RoleController || m.slots == 0) {
			// Half-close a client stream so the peer reads the close frames
			// before the RPC ends. Ending here aborts the call, and the peer
			// can record tunnel_lost instead of the typed reason.
			if closer, ok := m.stream.(interface{ CloseRequest() error }); ok {
				closeSend = closer.CloseRequest
			} else {
				ended = m.endLocked(ErrClosed)
			}
		}
		if m.err != nil {
			m.mu.Unlock()
			if ended {
				m.releaseStream()
			}
			return
		}
		m.mu.Unlock()
		if closeSend != nil {
			if err := closeSend(); err != nil {
				m.end(fmt.Errorf("rawtunnel: close send: %w", err))
			}
			return
		}
		if f == nil {
			<-m.kick
			continue
		}
		if err := m.stream.Send(f); err != nil {
			m.end(fmt.Errorf("rawtunnel: send: %w", err))
			return
		}
		if sent == nil {
			continue
		}
		m.mu.Lock()
		if m.err != nil {
			m.mu.Unlock()
			return
		}
		sent()
		m.mu.Unlock()
	}
}

// keepalive sends pings so an idle tunnel still produces traffic. An
// acknowledgement that never arrives is retried on the next interval. It is
// not a failure: the peer writes it on the same send loop a slow pipe can
// block, and a stopped process is detected by HTTP/2.
func (m *Mux) keepalive(ctx context.Context) {
	defer close(m.keepaliveStopped)
	ticker := time.NewTicker(m.cfg.PingInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-m.done:
			return
		case <-ticker.C:
		}
		pctx, cancel := context.WithTimeout(ctx, m.cfg.PingTimeout)
		_ = m.Ping(pctx)
		cancel()
	}
}

// Close ends every pipe with reason and sends the resulting resets and
// closes. A client stream then half-closes so the peer can read those frames
// before the RPC ends. A stream that cannot half-close ends locally. If the
// peer stops reading, Run stays blocked until its context is cancelled.
func (m *Mux) Close(reason pb.RawCloseReason) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closing || m.err != nil {
		return
	}
	m.closing = true
	for _, p := range m.pipes {
		p.finishLocked(closeReasonOrProtocolError(reason), true)
	}
	m.wakeLocked()
}

// Done is closed when the tunnel has ended.
func (m *Mux) Done() <-chan struct{} {
	return m.done
}

// Open starts opening a pipe to the capability's destination. It is valid only
// for RoleController. Wait for the connector's answer with Pipe.WaitOpened.
func (m *Mux) Open(
	capability, host string,
	port uint32,
	mode pb.RawPipeMode,
) (*Pipe, error) {
	if m.cfg.Role != RoleController {
		return nil, errors.New("rawtunnel: only the controller opens pipes")
	}
	open := &pb.RawOpen{PipeId: 1, Capability: capability, Host: host, Port: port, Mode: mode}
	// Protobuf refuses to marshal invalid UTF-8, which would fail the tunnel's
	// Send and every other pipe with it.
	if err := protovalidate.Validate(open); err != nil ||
		!utf8.ValidString(capability) || !utf8.ValidString(host) {
		return nil, errors.New("rawtunnel: invalid open request")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	switch {
	case m.err != nil || m.closing:
		return nil, ErrClosed
	case m.localDrain || m.peerDrain:
		return nil, ErrDraining
	case m.slots >= m.cfg.MaxPipes:
		return nil, ErrCapacity
	}
	m.lastID++
	p := m.newPipeLocked(m.lastID)
	open.PipeId = p.id
	p.open = open
	p.resolved = true
	p.opened = make(chan struct{})
	m.pendingOpens++
	m.queueLocked(p, sendOpen)
	return p, nil
}

// Drain stops new pipes on the tunnel and tells the peer. Existing pipes run
// until they end. Drain is idempotent.
func (m *Mux) Drain(reason pb.RawDrainReason) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.localDrain || m.err != nil {
		return
	}
	m.localDrain = true
	m.drainReason = reason
	m.drainPending = true
	m.startDrainLocked()
	m.wakeLocked()
}

// Draining is closed once either side has drained the tunnel.
func (m *Mux) Draining() <-chan struct{} {
	return m.draining
}

// Drained is closed once the tunnel is draining and its last pipe is released.
func (m *Mux) Drained() <-chan struct{} {
	return m.drained
}

// Ping sends a keepalive and waits for the peer's acknowledgement. Concurrent
// calls are serialized.
func (m *Mux) Ping(ctx context.Context) error {
	m.pingMu.Lock()
	defer m.pingMu.Unlock()

	m.mu.Lock()
	if m.err != nil {
		m.mu.Unlock()
		return ErrClosed
	}
	m.pingSeq++
	m.pingNonce = m.pingSeq
	m.pingPending = true
	acked := make(chan struct{})
	m.pingWaiter = acked
	m.wakeLocked()
	m.mu.Unlock()

	select {
	case <-acked:
		return nil
	case <-m.done:
		return ErrClosed
	case <-ctx.Done():
		m.mu.Lock()
		m.pingWaiter = nil
		m.mu.Unlock()
		return ctx.Err()
	}
}

func (m *Mux) receiveLoop() {
	defer close(m.recvStopped)
	for {
		f, err := m.stream.Receive()
		if err != nil {
			m.end(fmt.Errorf("rawtunnel: receive: %w", err))
			return
		}
		m.mu.Lock()
		if m.err != nil {
			m.mu.Unlock()
			return
		}
		err = m.handleLocked(f)
		ended := err != nil && m.endLocked(err)
		m.mu.Unlock()
		if ended {
			m.releaseStream()
		}
	}
}

func (m *Mux) end(err error) {
	m.mu.Lock()
	ended := m.endLocked(err)
	m.mu.Unlock()
	if ended {
		m.releaseStream()
	}
}

// endLocked records err and tears the tunnel down. It reports whether this
// call was the one that ended it, in which case the caller must release the
// stream after unlocking.
func (m *Mux) endLocked(err error) bool {
	if m.err != nil {
		return false
	}
	m.err = err
	m.teardownLocked()
	m.wakeLocked()
	return true
}

// releaseStream unblocks Send and Receive. It runs outside the mux lock, since
// Abort may end the call context and re-enter the mux.
func (m *Mux) releaseStream() {
	m.abortOnce.Do(func() {
		m.cfg.Abort()
		close(m.abortStopped)
	})
}

// teardownLocked ends every remaining pipe once the tunnel has ended. Nothing
// more reaches the peer, so every pipe is released as soon as it finishes.
func (m *Mux) teardownLocked() {
	reason := pb.RawCloseReason_RAW_CLOSE_REASON_TUNNEL_LOST
	var perr *ProtocolError
	if errors.As(m.err, &perr) {
		reason = pb.RawCloseReason_RAW_CLOSE_REASON_PROTOCOL_ERROR
	}
	m.control, m.ready = nil, nil
	m.drainPending, m.pingPending, m.pingAckPending = false, false, false
	for _, p := range m.pipes {
		// A controller pipe may already have ended locally and be waiting for
		// the connector's close. The tunnel is gone, so that wait must end and
		// the slot must be released. remoteReleased is set before finish so a
		// pipe that ends in this loop does not wait either.
		if p.state != pipeEnded {
			p.remoteReleased = true
			p.finishLocked(reason, false)
		} else {
			p.remoteReleased = true
		}
		m.maybeFinishLocked(p)
		if p.finished {
			m.releaseLocked(p)
		}
	}
	close(m.done)
}

func (m *Mux) wakeLocked() {
	select {
	case m.kick <- struct{}{}:
	default:
	}
}

func (m *Mux) startDrainLocked() {
	select {
	case <-m.draining:
	default:
		close(m.draining)
	}
	m.checkDrainedLocked()
}

func (m *Mux) checkDrainedLocked() {
	if !m.localDrain && !m.peerDrain || m.slots > 0 {
		return
	}
	select {
	case <-m.drained:
	default:
		close(m.drained)
	}
}

func (m *Mux) releaseLocked(p *Pipe) {
	if p.released {
		return
	}
	p.released = true
	delete(m.pipes, p.id)
	m.slots--
	m.checkDrainedLocked()
}

// queueLocked marks control frames pending for p and schedules it.
func (m *Mux) queueLocked(p *Pipe, frames pending) {
	if m.err != nil {
		return
	}
	p.pending |= frames
	if !p.queued {
		p.queued = true
		m.control = append(m.control, p)
	}
	m.wakeLocked()
}

// nextFrameLocked picks the next frame to send: tunnel control first, then pipe
// control in arrival order, then one data chunk per ready pipe in turn. sent,
// when not nil, runs under the lock after the frame was sent.
func (m *Mux) nextFrameLocked() (f *pb.RawTunnelFrame, sent func()) {
	if m.err != nil {
		return nil, nil
	}
	if f := m.tunnelControlLocked(); f != nil {
		return f, nil
	}
	for len(m.control) > 0 {
		p := m.control[0]
		m.control = m.control[1:]
		p.queued = false
		if f := p.nextControlLocked(); f != nil {
			if p.pending != 0 {
				p.queued = true
				m.control = append(m.control, p)
			}
			return f, nil
		}
	}
	for len(m.ready) > 0 {
		p := m.ready[0]
		m.ready = m.ready[1:]
		if p.chunk == nil {
			continue
		}
		// Counted now, not after Send, so Result is final once the pipe is
		// done even if it ends while this chunk is being sent.
		p.result.BytesSent += int64(len(p.chunk))
		p.lastActivity = time.Now()
		f := &pb.RawTunnelFrame{Frame: &pb.RawTunnelFrame_Data{
			Data: &pb.RawData{PipeId: p.id, Payload: p.chunk},
		}}
		return f, p.chunkSentLocked
	}
	return nil, nil
}

func (m *Mux) tunnelControlLocked() *pb.RawTunnelFrame {
	switch {
	case m.pingAckPending:
		m.pingAckPending = false
		return &pb.RawTunnelFrame{Frame: &pb.RawTunnelFrame_Ping{
			Ping: &pb.RawPing{Nonce: m.pingAckNonce, Ack: true},
		}}
	case m.pingPending:
		m.pingPending = false
		return &pb.RawTunnelFrame{Frame: &pb.RawTunnelFrame_Ping{
			Ping: &pb.RawPing{Nonce: m.pingNonce},
		}}
	case m.drainPending && m.pendingOpens == 0:
		m.drainPending = false
		return &pb.RawTunnelFrame{Frame: &pb.RawTunnelFrame_Drain{
			Drain: &pb.RawDrain{Reason: m.drainReason},
		}}
	}
	return nil
}

// handleLocked applies one received frame. A returned error ends the tunnel;
// pipe-level violations reset only the offending pipe.
func (m *Mux) handleLocked(f *pb.RawTunnelFrame) error {
	controller := m.cfg.Role == RoleController
	switch fr := f.GetFrame().(type) {
	case *pb.RawTunnelFrame_Data:
		return m.withPipeLocked(fr.Data.GetPipeId(), func(p *Pipe) {
			p.receiveDataLocked(fr.Data.GetPayload())
		})
	case *pb.RawTunnelFrame_WindowUpdate:
		return m.withPipeLocked(fr.WindowUpdate.GetPipeId(), func(p *Pipe) {
			p.receiveCreditLocked(fr.WindowUpdate.GetCreditBytes())
		})
	case *pb.RawTunnelFrame_HalfClose:
		return m.withPipeLocked(fr.HalfClose.GetPipeId(), (*Pipe).receiveHalfCloseLocked)
	case *pb.RawTunnelFrame_PipeReset:
		return m.withPipeLocked(fr.PipeReset.GetPipeId(), func(p *Pipe) {
			p.finishLocked(closeReasonOrProtocolError(fr.PipeReset.GetReason()), false)
		})
	case *pb.RawTunnelFrame_Open:
		if controller {
			return protocolErrorf("controller received open")
		}
		return m.acceptLocked(fr.Open)
	case *pb.RawTunnelFrame_Opened:
		if !controller {
			return protocolErrorf("connector received opened")
		}
		return m.withPipeLocked(fr.Opened.GetPipeId(), (*Pipe).receiveOpenedLocked)
	case *pb.RawTunnelFrame_OpenError:
		if !controller {
			return protocolErrorf("connector received open_error")
		}
		return m.withPipeLocked(fr.OpenError.GetPipeId(), func(p *Pipe) {
			p.receiveOpenErrorLocked(fr.OpenError)
		})
	case *pb.RawTunnelFrame_Close:
		if !controller {
			return protocolErrorf("connector received close")
		}
		return m.withPipeLocked(fr.Close.GetPipeId(), func(p *Pipe) {
			p.receiveCloseLocked(fr.Close)
		})
	case *pb.RawTunnelFrame_Drain:
		if err := protovalidate.Validate(fr.Drain); err != nil {
			return protocolErrorf("malformed drain")
		}
		if !m.peerDrain {
			m.peerDrain = true
			m.startDrainLocked()
		}
		return nil
	case *pb.RawTunnelFrame_Ping:
		if fr.Ping.GetAck() {
			if m.pingWaiter != nil && fr.Ping.GetNonce() == m.pingNonce {
				close(m.pingWaiter)
				m.pingWaiter = nil
			}
			return nil
		}
		m.pingAckPending = true
		m.pingAckNonce = fr.Ping.GetNonce()
		m.wakeLocked()
		return nil
	case *pb.RawTunnelFrame_ConnectorHello, *pb.RawTunnelFrame_ControllerHello:
		return protocolErrorf("hello after the tunnel started")
	default:
		return protocolErrorf("empty or unknown frame")
	}
}

// withPipeLocked runs fn on the live pipe id names. Frames for retired pipes are
// ignored, since they can legitimately cross a reset or close in flight. A frame
// for a pipe that was never opened ends the tunnel.
func (m *Mux) withPipeLocked(id uint64, fn func(*Pipe)) error {
	if id == 0 {
		return protocolErrorf("frame without a pipe id")
	}
	if id > m.lastID {
		return protocolErrorf("frame for unopened pipe %d", id)
	}
	if p := m.pipes[id]; p != nil {
		// The connector has not been told about a pipe whose open is still
		// queued, so a frame for it cannot be a late one from a retired pipe.
		if p.pending&sendOpen != 0 {
			return protocolErrorf("frame for pipe %d before its open was sent", id)
		}
		fn(p)
	}
	return nil
}

// acceptLocked admits an open on the connector, or refuses it without calling
// Accept when the tunnel cannot take it.
func (m *Mux) acceptLocked(open *pb.RawOpen) error {
	id := open.GetPipeId()
	if id == 0 {
		return protocolErrorf("open without a pipe id")
	}
	if id <= m.lastID {
		return protocolErrorf("open reused pipe id %d", id)
	}
	// A controller releases a slot only after it receives the connector's
	// close or open_error, so its count of open pipes never falls below the
	// connector's. An open past MaxPipes means the peer ignored the limit.
	if m.slots >= m.cfg.MaxPipes {
		return protocolErrorf("open exceeds %d pipes", m.cfg.MaxPipes)
	}
	m.lastID = id
	p := m.newPipeLocked(id)
	p.open = open

	var refuse pb.RawOpenFailureReason
	var detail string
	switch {
	case protovalidate.Validate(open) != nil:
		refuse, detail = pb.RawOpenFailureReason_RAW_OPEN_FAILURE_REASON_PROTOCOL_ERROR,
			"malformed open"
	case m.localDrain || m.closing:
		refuse, detail = pb.RawOpenFailureReason_RAW_OPEN_FAILURE_REASON_CONNECTOR_DRAINING,
			"tunnel draining"
	case m.peerDrain:
		refuse, detail = pb.RawOpenFailureReason_RAW_OPEN_FAILURE_REASON_PROTOCOL_ERROR,
			"open after controller drain"
	}
	if refuse != 0 {
		p.refuseLocked(refuse, detail)
		return nil
	}
	go m.cfg.Accept(p, open)
	return nil
}

func closeReasonOrProtocolError(r pb.RawCloseReason) pb.RawCloseReason {
	if _, ok := pb.RawCloseReason_name[int32(r)]; !ok ||
		r == pb.RawCloseReason_RAW_CLOSE_REASON_UNSPECIFIED {
		return pb.RawCloseReason_RAW_CLOSE_REASON_PROTOCOL_ERROR
	}
	return r
}
