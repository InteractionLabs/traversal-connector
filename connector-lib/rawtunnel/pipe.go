package rawtunnel

import (
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	pb "github.com/InteractionLabs/traversal-connector/connector-lib/gen/connector/v1"
)

// maxDetailBytes bounds RawOpenError.detail, which the contract limits to 256
// characters.
const maxDetailBytes = 256

// Local is one end of a pipe: the destination socket on the connector, or the
// caller's stream on the controller. The Mux reads and writes it from its own
// goroutines and closes it exactly once when the pipe ends. Close must unblock
// pending Read and Write calls.
type Local interface {
	io.Reader
	io.Writer
	// CloseWrite ends the Local's outbound direction after the peer
	// half-closed the pipe, like a TCP FIN.
	CloseWrite() error
	Close() error
}

// Result describes how a pipe ended.
type Result struct {
	// Reason is unset for a pipe that never opened.
	Reason pb.RawCloseReason
	// BytesSent counts bytes read from the Local and sent to the peer.
	BytesSent int64
	// BytesReceived counts bytes received from the peer and written to the
	// Local.
	BytesReceived int64
}

// OpenError reports that the connector refused an open.
type OpenError struct {
	Reason pb.RawOpenFailureReason
	Detail string
}

func (e *OpenError) Error() string {
	return "rawtunnel: open refused: " + e.Reason.String()
}

// ClosedError reports that a pipe ended before it opened.
type ClosedError struct {
	Reason pb.RawCloseReason
}

func (e *ClosedError) Error() string {
	return "rawtunnel: pipe closed before opening: " + e.Reason.String()
}

type pipeState int

const (
	pipeOpening pipeState = iota
	pipeOpen
	pipeEnded
)

// pending is a set of control frames waiting to be sent for one pipe. At most
// one of each is ever pending, which bounds the control queue by the number
// of pipes. Frames are sent in bit order, which is always their protocol order.
type pending uint8

const (
	sendOpen pending = 1 << iota
	sendOpened
	sendOpenError
	sendWindow
	sendHalfClose
	sendReset
	sendClose
)

// Pipe is one byte stream on a tunnel.
type Pipe struct {
	m      *Mux
	id     uint64
	open   *pb.RawOpen
	ctx    context.Context
	cancel context.CancelFunc
	done   chan struct{}
	// opened is closed when a controller pipe opens or ends; nil on the
	// connector.
	opened chan struct{}

	// Everything below is guarded by m.mu.
	cond      sync.Cond
	state     pipeState
	resolved  bool // Start or Refuse was called, or no call is needed
	started   bool
	local     Local
	workers   int
	localShut bool // the Local, if any, is closed
	finished  bool
	released  bool

	pending        pending
	queued         bool
	resetReason    pb.RawCloseReason
	refusal        *pb.RawOpenError // connector: refusal to send
	openErr        *pb.RawOpenError // controller: refusal received
	wasOpened      bool
	remoteReleased bool // controller: the connector sent close or open_error

	sendCredit     int // bytes this side may still send
	recvCredit     int // bytes the peer may still send
	unacked        int // consumed bytes not yet returned as credit
	recv           recvBuffer
	chunk          []byte // read from the Local, waiting to be sent
	sentHalfClose  bool
	peerHalfClosed bool
	downDone       bool // the Local's outbound direction is closed

	result       Result
	lastActivity time.Time
	idleTimer    *time.Timer
	lifeTimer    *time.Timer
}

func (m *Mux) newPipeLocked(id uint64) *Pipe {
	ctx, cancel := context.WithCancel(context.Background())
	p := &Pipe{
		m:          m,
		id:         id,
		ctx:        ctx,
		cancel:     cancel,
		done:       make(chan struct{}),
		sendCredit: Window,
		recvCredit: Window,
	}
	p.cond.L = &m.mu
	m.pipes[id] = p
	m.slots++
	return p
}

// ID returns the pipe's tunnel-unique ID.
func (p *Pipe) ID() uint64 {
	return p.id
}

// Context is cancelled when the pipe ends.
func (p *Pipe) Context() context.Context {
	return p.ctx
}

// Done is closed when the pipe has ended and its Local is closed.
func (p *Pipe) Done() <-chan struct{} {
	return p.done
}

// Result reports how the pipe ended. It is final once Done is closed.
func (p *Pipe) Result() Result {
	p.m.mu.Lock()
	defer p.m.mu.Unlock()
	return p.result
}

// WaitOpened waits for the connector to answer a controller pipe's open. It
// returns nil once the pipe opened, an *OpenError if the connector refused it,
// a *ClosedError if it ended first, or ctx's error. On ctx's error the pipe is
// still opening; Reset it to give up.
func (p *Pipe) WaitOpened(ctx context.Context) error {
	if p.opened == nil {
		return errors.New("rawtunnel: only controller pipes wait to open")
	}
	select {
	case <-p.opened:
	case <-ctx.Done():
		return ctx.Err()
	}
	p.m.mu.Lock()
	defer p.m.mu.Unlock()
	switch {
	case p.wasOpened:
		return nil
	case p.openErr != nil:
		return &OpenError{Reason: p.openErr.GetReason(), Detail: p.openErr.GetDetail()}
	default:
		return &ClosedError{Reason: p.result.Reason}
	}
}

// Start connects the pipe to local and begins moving bytes. On the connector it
// also tells the controller the pipe opened; on the controller it is valid
// only after WaitOpened returned nil. Start takes ownership of local and
// closes it even when it returns an error.
func (p *Pipe) Start(local Local) error {
	m := p.m
	m.mu.Lock()
	var err error
	switch {
	case p.started || m.cfg.Role == RoleConnector && p.resolved:
		err = errors.New("rawtunnel: pipe already started or refused")
	case p.state == pipeEnded:
		// Resolving an ended connector pipe lets it finish and be released.
		p.started, p.resolved = true, true
		m.maybeFinishLocked(p)
		err = ErrPipeClosed
	case m.cfg.Role == RoleController && !p.wasOpened:
		err = errors.New("rawtunnel: pipe has not opened")
	}
	if err != nil {
		m.mu.Unlock()
		_ = local.Close()
		return err
	}
	p.started, p.resolved = true, true
	p.local = local
	if m.cfg.Role == RoleConnector {
		p.state = pipeOpen
		m.queueLocked(p, sendOpened)
		p.armTimersLocked()
	}
	p.workers = 2
	m.mu.Unlock()
	go p.sendLoop()
	go p.receiveLoop()
	return nil
}

// Refuse declines a connector pipe instead of starting it. The controller
// receives reason and detail; detail must be a fixed, payload-free string.
func (p *Pipe) Refuse(reason pb.RawOpenFailureReason, detail string) error {
	m := p.m
	if m.cfg.Role != RoleConnector {
		return errors.New("rawtunnel: only the connector refuses pipes")
	}
	if _, ok := pb.RawOpenFailureReason_name[int32(reason)]; !ok ||
		reason == pb.RawOpenFailureReason_RAW_OPEN_FAILURE_REASON_UNSPECIFIED {
		return errors.New("rawtunnel: invalid refusal reason")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if p.resolved {
		return errors.New("rawtunnel: pipe already started or refused")
	}
	p.resolved = true
	if p.state != pipeEnded {
		p.refuseLocked(reason, detail)
	}
	m.maybeFinishLocked(p)
	return nil
}

// Reset aborts the pipe in both directions and tells the peer why.
func (p *Pipe) Reset(reason pb.RawCloseReason) {
	p.m.mu.Lock()
	defer p.m.mu.Unlock()
	p.finishLocked(closeReasonOrProtocolError(reason), true)
}

func (p *Pipe) refuseLocked(reason pb.RawOpenFailureReason, detail string) {
	p.resolved = true
	p.refusal = &pb.RawOpenError{
		PipeId: p.id,
		Reason: reason,
		Detail: truncateDetail(detail),
	}
	p.finishLocked(pb.RawCloseReason_RAW_CLOSE_REASON_UNSPECIFIED, false)
}

// finishLocked ends the pipe once, for reason. notifyPeer sends a reset to the peer, unless
// the peer can no longer be reached or never learned of the pipe.
func (p *Pipe) finishLocked(reason pb.RawCloseReason, notifyPeer bool) {
	if p.state == pipeEnded {
		return
	}
	m := p.m
	p.state = pipeEnded
	p.result.Reason = reason
	p.cancel()
	if p.idleTimer != nil {
		p.idleTimer.Stop()
		p.lifeTimer.Stop()
	}
	p.recv = recvBuffer{}
	p.chunk = nil
	p.pending &^= sendWindow | sendHalfClose
	if p.pending&sendOpen != 0 {
		// The connector never saw the open, so there is nothing to reset and
		// nothing it will release.
		p.pending &^= sendOpen
		m.pendingOpens--
		m.wakeLocked()
		p.remoteReleased = true
		notifyPeer = false
	}
	if notifyPeer && m.err == nil {
		p.resetReason = reason
		m.queueLocked(p, sendReset)
	}
	if p.opened != nil && !p.wasOpened {
		close(p.opened)
	}
	p.cond.Broadcast()
	go p.shutLocal()
}

// shutLocal closes the Local, if Start attached one, so blocked reads and
// writes return, then lets the pipe finish.
func (p *Pipe) shutLocal() {
	m := p.m
	m.mu.Lock()
	local := p.local
	m.mu.Unlock()
	if local != nil {
		_ = local.Close()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	p.localShut = true
	m.maybeFinishLocked(p)
}

// maybeFinishLocked completes an ended pipe once nothing local still uses it:
// it has been started or refused, both copy loops have exited, and the Local
// is closed. The connector then tells the controller it released the pipe.
func (m *Mux) maybeFinishLocked(p *Pipe) {
	if p.finished || p.state != pipeEnded || p.workers > 0 || !p.resolved || !p.localShut {
		return
	}
	p.finished = true
	close(p.done)
	switch {
	case m.err != nil:
		m.releaseLocked(p)
	case m.cfg.Role == RoleController:
		p.releaseIfRemoteDoneLocked()
	case p.refusal != nil:
		m.queueLocked(p, sendOpenError)
	default:
		m.queueLocked(p, sendClose)
	}
}

// releaseIfRemoteDoneLocked frees a controller pipe's slot once it finished
// here and the connector reported releasing it, in either order.
func (p *Pipe) releaseIfRemoteDoneLocked() {
	if p.finished && p.remoteReleased {
		p.m.releaseLocked(p)
	}
}

// nextControlLocked builds p's next pending control frame, or returns nil if
// none is left.
func (p *Pipe) nextControlLocked() *pb.RawTunnelFrame {
	m := p.m
	for p.pending != 0 {
		bit := p.pending & -p.pending
		p.pending &^= bit
		switch bit {
		case sendOpen:
			m.pendingOpens--
			return &pb.RawTunnelFrame{Frame: &pb.RawTunnelFrame_Open{Open: p.open}}
		case sendOpened:
			return &pb.RawTunnelFrame{Frame: &pb.RawTunnelFrame_Opened{
				Opened: &pb.RawOpened{PipeId: p.id},
			}}
		case sendOpenError:
			m.releaseLocked(p)
			return &pb.RawTunnelFrame{Frame: &pb.RawTunnelFrame_OpenError{OpenError: p.refusal}}
		case sendWindow:
			credit := p.unacked
			if credit == 0 {
				continue
			}
			p.unacked = 0
			p.recvCredit += credit
			return &pb.RawTunnelFrame{Frame: &pb.RawTunnelFrame_WindowUpdate{
				WindowUpdate: &pb.RawWindowUpdate{
					PipeId:      p.id,
					CreditBytes: uint32(credit), //nolint:gosec // credit never exceeds Window.
				},
			}}
		case sendHalfClose:
			// Recorded before the frame is sent: once it is, the peer may
			// finish the pipe and report it before Send even returns.
			p.sentHalfClose = true
			p.checkCompleteLocked()
			return &pb.RawTunnelFrame{Frame: &pb.RawTunnelFrame_HalfClose{
				HalfClose: &pb.RawHalfClose{PipeId: p.id},
			}}
		case sendReset:
			return &pb.RawTunnelFrame{Frame: &pb.RawTunnelFrame_PipeReset{
				PipeReset: &pb.RawReset{PipeId: p.id, Reason: p.resetReason},
			}}
		case sendClose:
			m.releaseLocked(p)
			return &pb.RawTunnelFrame{Frame: &pb.RawTunnelFrame_Close{
				Close: &pb.RawClose{PipeId: p.id, Reason: p.result.Reason},
			}}
		}
	}
	return nil
}

// chunkSentLocked releases the send loop's buffer once Send no longer uses it.
func (p *Pipe) chunkSentLocked() {
	p.chunk = nil
	p.cond.Broadcast()
}

// checkCompleteLocked ends the pipe normally once both directions are closed.
func (p *Pipe) checkCompleteLocked() {
	if p.sentHalfClose && p.downDone {
		p.finishLocked(pb.RawCloseReason_RAW_CLOSE_REASON_COMPLETED, false)
	}
}

func (p *Pipe) protocolErrorLocked() {
	p.finishLocked(pb.RawCloseReason_RAW_CLOSE_REASON_PROTOCOL_ERROR, true)
}

func (p *Pipe) localFailedLocked() {
	reason := pb.RawCloseReason_RAW_CLOSE_REASON_CANCELLED
	if p.m.cfg.Role == RoleConnector {
		reason = pb.RawCloseReason_RAW_CLOSE_REASON_UPSTREAM_ERROR
	}
	p.finishLocked(reason, true)
}

func (p *Pipe) receiveDataLocked(payload []byte) {
	switch {
	case p.state == pipeEnded:
	case p.state == pipeOpening, p.peerHalfClosed,
		len(payload) == 0, len(payload) > MaxDataBytes, len(payload) > p.recvCredit:
		p.protocolErrorLocked()
	default:
		p.recvCredit -= len(payload)
		p.recv.write(payload)
		p.lastActivity = time.Now()
		p.cond.Broadcast()
	}
}

func (p *Pipe) receiveCreditLocked(credit uint32) {
	switch {
	case p.state == pipeEnded:
	case p.state == pipeOpening, credit == 0, int64(p.sendCredit)+int64(credit) > Window:
		p.protocolErrorLocked()
	default:
		p.sendCredit += int(credit)
		p.cond.Broadcast()
	}
}

func (p *Pipe) receiveHalfCloseLocked() {
	switch {
	case p.state == pipeEnded:
	case p.state == pipeOpening, p.peerHalfClosed:
		p.protocolErrorLocked()
	default:
		p.peerHalfClosed = true
		p.cond.Broadcast()
	}
}

func (p *Pipe) receiveOpenedLocked() {
	switch p.state {
	case pipeEnded:
	case pipeOpen:
		p.protocolErrorLocked()
	case pipeOpening:
		p.state = pipeOpen
		p.wasOpened = true
		p.armTimersLocked()
		close(p.opened)
	}
}

func (p *Pipe) receiveOpenErrorLocked(e *pb.RawOpenError) {
	p.remoteReleased = true
	switch p.state {
	case pipeEnded:
	case pipeOpening:
		p.openErr = e
		p.finishLocked(pb.RawCloseReason_RAW_CLOSE_REASON_UNSPECIFIED, false)
	case pipeOpen:
		p.finishLocked(pb.RawCloseReason_RAW_CLOSE_REASON_PROTOCOL_ERROR, false)
	}
	p.releaseIfRemoteDoneLocked()
}

// receiveCloseLocked records that the connector released the pipe. A close is
// valid once the pipe ended here, or once both sides half-closed, when the
// connector may finish before this side drains the last bytes to its Local.
func (p *Pipe) receiveCloseLocked() {
	p.remoteReleased = true
	if p.state != pipeEnded && (!p.peerHalfClosed || !p.sentHalfClose) {
		p.finishLocked(pb.RawCloseReason_RAW_CLOSE_REASON_PROTOCOL_ERROR, false)
	}
	p.releaseIfRemoteDoneLocked()
}

func (p *Pipe) armTimersLocked() {
	m := p.m
	p.lastActivity = time.Now()
	p.lifeTimer = time.AfterFunc(m.cfg.MaxLifetime, func() {
		m.mu.Lock()
		defer m.mu.Unlock()
		p.finishLocked(pb.RawCloseReason_RAW_CLOSE_REASON_MAX_LIFETIME, true)
	})
	p.idleTimer = time.AfterFunc(m.cfg.IdleTimeout, p.checkIdle)
}

func (p *Pipe) checkIdle() {
	m := p.m
	m.mu.Lock()
	defer m.mu.Unlock()
	if p.state == pipeEnded {
		return
	}
	if idle := time.Since(p.lastActivity); idle < m.cfg.IdleTimeout {
		p.idleTimer.Reset(m.cfg.IdleTimeout - idle)
		return
	}
	p.finishLocked(pb.RawCloseReason_RAW_CLOSE_REASON_IDLE_TIMEOUT, true)
}

// sendLoop copies the Local's bytes to the peer. It reads only as much as the
// peer's credit allows and reuses one chunk buffer, waiting until each chunk
// is sent before reading the next.
func (p *Pipe) sendLoop() {
	m := p.m
	buf := make([]byte, MaxDataBytes)
	defer p.workerDone()
	for {
		m.mu.Lock()
		for p.sendCredit == 0 && p.state != pipeEnded {
			p.cond.Wait()
		}
		if p.state == pipeEnded {
			m.mu.Unlock()
			return
		}
		n := min(MaxDataBytes, p.sendCredit)
		m.mu.Unlock()

		k, err := p.local.Read(buf[:n])

		m.mu.Lock()
		if p.state == pipeEnded {
			m.mu.Unlock()
			return
		}
		if k > 0 {
			p.sendCredit -= k
			p.chunk = buf[:k]
			m.ready = append(m.ready, p)
			m.wakeLocked()
			for p.chunk != nil && p.state != pipeEnded {
				p.cond.Wait()
			}
			if p.state == pipeEnded {
				m.mu.Unlock()
				return
			}
		}
		switch {
		case errors.Is(err, io.EOF):
			m.queueLocked(p, sendHalfClose)
			m.mu.Unlock()
			return
		case err != nil:
			p.localFailedLocked()
			m.mu.Unlock()
			return
		}
		m.mu.Unlock()
	}
}

// receiveLoop copies the peer's bytes to the Local, returning credit as they
// are consumed, and closes the Local's outbound direction after the peer
// half-closes.
func (p *Pipe) receiveLoop() {
	m := p.m
	defer p.workerDone()
	for {
		m.mu.Lock()
		for p.recv.size == 0 && !p.peerHalfClosed && p.state != pipeEnded {
			p.cond.Wait()
		}
		if p.state == pipeEnded {
			m.mu.Unlock()
			return
		}
		if p.recv.size == 0 {
			m.mu.Unlock()
			err := p.local.CloseWrite()
			m.mu.Lock()
			if err != nil {
				p.localFailedLocked()
			} else if p.state != pipeEnded {
				p.downDone = true
				p.checkCompleteLocked()
			}
			m.mu.Unlock()
			return
		}
		chunk := p.recv.peek()
		m.mu.Unlock()

		_, err := p.local.Write(chunk)

		m.mu.Lock()
		if p.state == pipeEnded {
			m.mu.Unlock()
			return
		}
		if err != nil {
			p.localFailedLocked()
			m.mu.Unlock()
			return
		}
		p.recv.consume(len(chunk))
		p.result.BytesReceived += int64(len(chunk))
		p.lastActivity = time.Now()
		p.unacked += len(chunk)
		if p.unacked >= grantThreshold && !p.peerHalfClosed {
			m.queueLocked(p, sendWindow)
		}
		m.mu.Unlock()
	}
}

func (p *Pipe) workerDone() {
	m := p.m
	m.mu.Lock()
	defer m.mu.Unlock()
	p.workers--
	m.maybeFinishLocked(p)
}

// truncateDetail makes detail safe to send: protobuf rejects invalid UTF-8,
// which would fail the whole tunnel's Send, and the contract caps its length.
func truncateDetail(detail string) string {
	detail = strings.ToValidUTF8(detail, "")
	if len(detail) <= maxDetailBytes {
		return detail
	}
	i := maxDetailBytes
	for !utf8.RuneStart(detail[i]) {
		i--
	}
	return detail[:i]
}
