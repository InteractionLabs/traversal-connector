package rawtunnel

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net/http"
	"sync"
	"time"

	"buf.build/go/protovalidate"
	pb "github.com/InteractionLabs/traversal-connector/connector-lib/gen/connector/v1"
	"golang.org/x/net/http2"
	"google.golang.org/protobuf/proto"
)

const (
	helloPath    = "/raw/v1/hello"
	controlPath  = "/raw/v1/control"
	drainPath    = "/raw/v1/drain"
	pipePath     = "/raw/v1/pipes"
	headerOpen   = "Raw-Open"
	headerDrain  = "Raw-Drain"
	trailerClose = "Raw-Close-Reason"
	helloLimit   = 8192
	// Control records share one stream, separate from any pipe's window.
	// A pipe reset has to be readable while that pipe's stream window is full.
	controlDrain = byte(1)
	controlReset = byte(2)
)

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
	// ErrIncompatibleHello reports a hello the peer cannot accept.
	ErrIncompatibleHello = errors.New("rawtunnel: incompatible hello")
)

// Role selects which side of the tunnel a Mux implements.
type Role int

const (
	// RoleController is the inner HTTP/2 client. It opens pipes.
	RoleController Role = iota + 1
	// RoleConnector is the inner HTTP/2 server. It accepts pipes.
	RoleConnector
)

// Config configures a Mux.
type Config struct {
	Role Role
	// MaxPipes is the most pipes this side will carry. The controller lowers
	// it to the connector's advertised maximum after hello.
	MaxPipes int
	// IdleTimeout defaults to DefaultIdleTimeout. It starts when a pipe opens.
	IdleTimeout time.Duration
	// MaxLifetime defaults to DefaultMaxLifetime. It starts when a pipe opens.
	MaxLifetime time.Duration
	// PingInterval is how often an idle inner session sends an HTTP/2 ping.
	// Zero uses DefaultPingInterval.
	PingInterval time.Duration
	// PingTimeout is how long a ping may go unanswered. Zero uses
	// DefaultPingTimeout.
	PingTimeout time.Duration
	// Hello is the connector's hello. Required for RoleConnector.
	Hello *pb.RawConnectorHello
	// TunnelID is the controller-assigned tunnel id. Required for RoleController.
	TunnelID string
	// OnEstablished runs on the controller after hello, before pipes are opened.
	// A non-nil error ends the tunnel.
	OnEstablished func(*pb.RawConnectorHello) error
	// Accept is required for RoleConnector. The Mux calls it on a new goroutine
	// and it must call exactly one of Pipe.Start or Pipe.Refuse.
	Accept func(*Pipe, *pb.RawOpen)
	// Abort unblocks the outer gRPC stream. The Mux calls it when the tunnel
	// ends and when the inner session closes the byte pipe, so a stuck read
	// cannot outlive the peer. It may run more than once. It must not block
	// and must not use the Mux or the connection.
	Abort func()
	// OnReset is called when this side resets a pipe or the tunnel drops it.
	// origin is "sent" or "received". It must not block or use the Mux.
	OnReset func(origin, phase string, reason pb.RawCloseReason)
	// OnControlDrop is called when a connector control record other than
	// drain is discarded because the send buffer is full. It must not block
	// or use the Mux. Drain has its own slot and is not counted here.
	OnControlDrop func()
	// StreamWindow is this side's per-pipe HTTP/2 receive window. Zero uses
	// the package default. The connection window is this value times MaxPipes.
	StreamWindow int
	// OuterWindow is this side's outer gRPC receive window. Zero uses the
	// package default. ApplyOuterWindow is what sets it on the gRPC connection.
	OuterWindow int
}

// Mux is one raw tunnel: an HTTP/2 session carried on the outer gRPC stream.
type Mux struct {
	cfg    Config
	stream Stream
	conn   *ChunkConn

	ctx    context.Context
	cancel context.CancelFunc

	established chan struct{}
	done        chan struct{}
	draining    chan struct{}
	drained     chan struct{}

	once         sync.Once
	establishOne sync.Once
	drainingOne  sync.Once
	drainedOne   sync.Once

	cc *http2.ClientConn
	tr *http.Transport

	drainOut chan []byte

	controlOut chan []byte
	controlMu  sync.Mutex
	controlW   *io.PipeWriter

	mu         sync.Mutex
	err        error
	peer       *pb.RawConnectorHello
	tunnelID   string
	pipes      map[uint64]*Pipe
	seen       map[uint64]struct{}
	lastID     uint64
	slots      int
	localDrain bool
	peerDrain  bool
	// drainPosted is closed after the controller's drain request finishes.
	// Close waits for it before ending the control stream, or the connector
	// sees the tunnel drop and backs off instead of rotating.
	drainPosted chan struct{}

	handlerMu      sync.Mutex
	handlerN       int
	handlersClosed bool
	handlersIdle   chan struct{}
	handlersOnce   sync.Once
}

// New validates cfg and returns a Mux for stream. Hello is exchanged inside Run.
func New(cfg Config, stream Stream) (*Mux, error) {
	switch {
	case cfg.Role != RoleController && cfg.Role != RoleConnector:
		return nil, errors.New("rawtunnel: invalid role")
	case cfg.MaxPipes <= 0:
		return nil, errors.New("rawtunnel: MaxPipes must be positive")
	case cfg.Role == RoleConnector && cfg.Accept == nil:
		return nil, errors.New("rawtunnel: RoleConnector requires Accept")
	case cfg.Role == RoleConnector && cfg.Hello == nil:
		return nil, errors.New("rawtunnel: RoleConnector requires Hello")
	case cfg.Role == RoleController && cfg.Accept != nil:
		return nil, errors.New("rawtunnel: RoleController does not accept pipes")
	case cfg.Role == RoleController && cfg.TunnelID == "":
		return nil, errors.New("rawtunnel: RoleController requires TunnelID")
	case cfg.IdleTimeout < 0 || cfg.MaxLifetime < 0 || cfg.PingInterval < 0 || cfg.PingTimeout < 0:
		return nil, errors.New("rawtunnel: timeouts must not be negative")
	case cfg.Abort == nil:
		return nil, errors.New("rawtunnel: Abort is required")
	}
	if cfg.Role == RoleConnector {
		if err := protovalidate.Validate(cfg.Hello); err != nil {
			return nil, errors.New("rawtunnel: invalid hello")
		}
	}
	if cfg.Role == RoleController {
		hello := &pb.RawControllerHello{
			ProtocolVersion: ProtocolVersion,
			TunnelId:        cfg.TunnelID,
		}
		if err := protovalidate.Validate(hello); err != nil {
			return nil, errors.New("rawtunnel: invalid tunnel id")
		}
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
	ctx, cancel := context.WithCancel(context.Background())
	conn := NewChunkConn(stream)
	m := &Mux{
		cfg:          cfg,
		stream:       stream,
		conn:         conn,
		ctx:          ctx,
		cancel:       cancel,
		established:  make(chan struct{}),
		done:         make(chan struct{}),
		draining:     make(chan struct{}),
		drained:      make(chan struct{}),
		controlOut:   make(chan []byte, cfg.MaxPipes+8),
		drainOut:     make(chan []byte, 1),
		pipes:        make(map[uint64]*Pipe),
		seen:         make(map[uint64]struct{}),
		handlersIdle: make(chan struct{}),
		tunnelID:     cfg.TunnelID,
	}
	// Closing the byte pipe has to cancel the gRPC read. ServeConn does not
	// return, and Abort never runs, while Receive is still blocked.
	conn.interrupt = m.unblock
	return m, nil
}

// unblock cancels the outer read when the inner session gives up on the byte
// pipe. The controller skips it until hello has finished: Abort before then
// replaces the hello status with a reset.
func (m *Mux) unblock() {
	if m.cfg.Abort == nil {
		return
	}
	if m.cfg.Role == RoleController && !m.establishedClosed() {
		return
	}
	m.cfg.Abort()
}

// Run exchanges hello and carries pipes until the tunnel ends.
func (m *Mux) Run(ctx context.Context) error {
	runCtx, cancel := context.WithCancel(ctx)
	m.mu.Lock()
	prev := m.cancel
	m.ctx = runCtx
	m.cancel = cancel
	m.mu.Unlock()
	if prev != nil {
		prev()
	}
	go func() {
		select {
		case <-runCtx.Done():
			m.shutdown(runCtx.Err())
		case <-m.done:
		}
	}()
	var err error
	if m.cfg.Role == RoleConnector {
		err = m.serve()
	} else {
		err = m.dial(runCtx)
	}
	if err == nil {
		err = ErrClosed
	}
	m.shutdown(err)
	return m.Err()
}

// Established is closed after hello, once pipes may open.
func (m *Mux) Established() <-chan struct{} { return m.established }

// Done is closed when the tunnel has ended.
func (m *Mux) Done() <-chan struct{} { return m.done }

// Draining is closed once either side has drained the tunnel.
func (m *Mux) Draining() <-chan struct{} { return m.draining }

// Drained is closed once the tunnel is draining and its last pipe has ended.
func (m *Mux) Drained() <-chan struct{} { return m.drained }

// Err reports why the tunnel ended. It is nil while Run is in progress.
func (m *Mux) Err() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.err
}

// TunnelID is the controller-assigned id, empty until hello on the connector.
func (m *Mux) TunnelID() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.tunnelID
}

// PeerHello is the connector hello observed by the controller.
func (m *Mux) PeerHello() *pb.RawConnectorHello {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.peer
}

// Close ends the tunnel and every pipe still open.
func (m *Mux) Close(reason pb.RawCloseReason) {
	if reason == pb.RawCloseReason_RAW_CLOSE_REASON_UNSPECIFIED {
		reason = pb.RawCloseReason_RAW_CLOSE_REASON_TUNNEL_LOST
	}
	for _, p := range m.snapshot() {
		p.finish(reason, "sent")
	}
	// Handlers write the close record and return only after the peer has a
	// chance to read it. A second Close can run after the pipe has left the
	// map, so the wait is on the handler, not on map membership.
	m.waitHandlers()
	// The drain request is not on the control stream. Ending that stream first
	// drops the tunnel before the connector has observed the drain.
	m.waitDrainPosted()
	m.closeControl()
	if m.cfg.Role == RoleController {
		timer := time.NewTimer(2 * time.Second)
		defer timer.Stop()
		select {
		case <-m.done:
			return
		case <-timer.C:
		}
	}
	m.shutdown(ErrClosed)
}

// Drain stops new pipes. Pipes already open continue until they finish.
func (m *Mux) Drain(reason pb.RawDrainReason) {
	if reason == pb.RawDrainReason_RAW_DRAIN_REASON_UNSPECIFIED {
		reason = pb.RawDrainReason_RAW_DRAIN_REASON_ROTATION
	}
	msg := &pb.RawDrain{Reason: reason}
	body, err := encodeDrain(msg)
	if err != nil {
		return
	}
	m.mu.Lock()
	if m.localDrain || m.err != nil {
		m.mu.Unlock()
		return
	}
	m.localDrain = true
	var posted chan struct{}
	if m.cfg.Role == RoleController {
		posted = make(chan struct{})
		m.drainPosted = posted
	}
	m.signalDraining()
	m.checkDrainedLocked()
	m.mu.Unlock()
	// Pipe data can fill the connection window. A drain carried as a DATA
	// frame then waits behind it. HEADERS are not flow-controlled, so the
	// controller sends the drain as a header on its own request.
	if posted != nil {
		go func() {
			defer close(posted)
			m.postDrain(body)
		}()
		return
	}
	// The connector cannot open its own request. Drain uses a reserved slot
	// so a buffer full of resets cannot drop the shutdown signal.
	m.sendDrain(body)
}

// waitDrainPosted lets the controller's drain request finish before Close
// ends the control stream. A full connection window does not block it: the
// request is headers only. A peer that never answers does not pin Close.
func (m *Mux) waitDrainPosted() {
	m.mu.Lock()
	posted := m.drainPosted
	m.mu.Unlock()
	if posted == nil {
		return
	}
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	select {
	case <-posted:
	case <-timer.C:
	case <-m.done:
	}
}

// Open asks the connector to open one pipe. It is valid only for RoleController.
func (m *Mux) Open(capability, host string, port uint32, mode pb.RawPipeMode) (*Pipe, error) {
	if m.cfg.Role != RoleController {
		return nil, errors.New("rawtunnel: only the controller opens pipes")
	}
	open := &pb.RawOpen{
		PipeId: 1, Capability: capability, Host: host, Port: port, Mode: mode,
	}
	if protovalidate.Validate(open) != nil {
		return nil, errors.New("rawtunnel: invalid open request")
	}
	select {
	case <-m.established:
	case <-m.done:
		return nil, ErrClosed
	}
	m.mu.Lock()
	switch {
	case m.err != nil:
		m.mu.Unlock()
		return nil, ErrClosed
	case m.localDrain || m.peerDrain:
		m.mu.Unlock()
		return nil, ErrDraining
	case m.slots >= m.cfg.MaxPipes:
		m.mu.Unlock()
		return nil, ErrCapacity
	}
	m.lastID++
	open.PipeId = m.lastID
	p := m.newPipeLocked(open)
	m.mu.Unlock()
	pr, pw := io.Pipe()
	p.reqR = pr
	p.reqW = pw
	go p.roundTrip()
	return p, nil
}

func (m *Mux) newPipeLocked(open *pb.RawOpen) *Pipe {
	ctx, cancel := context.WithCancel(m.ctx)
	p := &Pipe{
		m:      m,
		id:     open.GetPipeId(),
		open:   open,
		ctx:    ctx,
		cancel: cancel,
		done:   make(chan struct{}),
	}
	if m.cfg.Role == RoleController {
		p.opened = make(chan struct{})
	} else {
		p.decided = make(chan struct{})
	}
	m.pipes[p.id] = p
	m.slots++
	return p
}

func (m *Mux) snapshot() []*Pipe {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*Pipe, 0, len(m.pipes))
	for _, p := range m.pipes {
		out = append(out, p)
	}
	return out
}

func (m *Mux) release(p *Pipe) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.pipes[p.id]; !ok {
		return
	}
	delete(m.pipes, p.id)
	if m.slots > 0 {
		m.slots--
	}
	m.checkDrainedLocked()
}

func (m *Mux) signalEstablished() {
	m.establishOne.Do(func() { close(m.established) })
}

func (m *Mux) signalDraining() {
	m.drainingOne.Do(func() { close(m.draining) })
}

func (m *Mux) checkDrainedLocked() {
	if (m.localDrain || m.peerDrain) && len(m.pipes) == 0 {
		m.drainedOne.Do(func() { close(m.drained) })
	}
}

func (m *Mux) markPeerDrain() {
	m.mu.Lock()
	m.peerDrain = true
	m.signalDraining()
	m.checkDrainedLocked()
	m.mu.Unlock()
}

func (m *Mux) establishedClosed() bool {
	select {
	case <-m.established:
		return true
	default:
		return false
	}
}

func (m *Mux) shutdown(err error) {
	m.once.Do(func() {
		m.mu.Lock()
		if m.err == nil {
			if err == nil {
				err = ErrClosed
			}
			m.err = err
		}
		m.mu.Unlock()
		for _, p := range m.snapshot() {
			p.finish(pb.RawCloseReason_RAW_CLOSE_REASON_TUNNEL_LOST, "received")
		}
		if m.cancel != nil {
			m.cancel()
		}
		// The controller skips Abort when hello never finished: Run is about
		// to return that error as the RPC status, and aborting first turns
		// the status into a reset. The connector always aborts, because it is
		// the gRPC client and this is what unblocks its own read.
		if m.cfg.Abort != nil && (m.cfg.Role == RoleConnector || m.establishedClosed()) {
			m.cfg.Abort()
		}
		// A controller that has not finished hello reports the failure as the
		// RPC status. Closing the stream here would replace that status with
		// a reset. Context cancellation still has to close it, or the read
		// that Run is waiting on never returns.
		keepStatus := m.cfg.Role == RoleController && !m.establishedClosed() &&
			!errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded)
		if !keepStatus {
			if m.cc != nil {
				_ = m.cc.Close()
			}
			_ = m.conn.Close()
		}
		close(m.done)
	})
}

func (m *Mux) serve() error {
	// ConnectionWindow caps at MaxInt32, so the conversion cannot overflow.
	streamWindow := streamWindow(m.cfg.StreamWindow)
	uploadWindow := int32(connectionWindow(m.cfg.MaxPipes, streamWindow)) //nolint:gosec // G115
	srv := &http2.Server{
		// Pipes, the control stream, and one drain request. The drain must still
		// open after every pipe slot is taken.
		// MaxPipes is validated to a small limit, so the cap fits in uint32.
		MaxConcurrentStreams:         uint32(m.cfg.MaxPipes + 3), //nolint:gosec // G115
		MaxUploadBufferPerStream:     int32(streamWindow),        //nolint:gosec // G115
		MaxUploadBufferPerConnection: uploadWindow,
		MaxReadFrameSize:             maxChunk,
		IdleTimeout:                  0,
		ReadIdleTimeout:              m.cfg.PingInterval,
		PingTimeout:                  m.cfg.PingTimeout,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+helloPath, m.handleHello)
	mux.HandleFunc("POST "+controlPath, m.handleControl)
	mux.HandleFunc("POST "+drainPath, m.handleDrain)
	mux.HandleFunc("POST "+pipePath, m.handlePipe)
	srv.ServeConn(m.conn, &http2.ServeConnOpts{Handler: mux, Context: m.ctx})
	if err := m.ctx.Err(); err != nil {
		return err
	}
	return ErrClosed
}

func (m *Mux) handleHello(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, helloLimit))
	if err != nil {
		http.Error(w, "bad hello", http.StatusBadRequest)
		return
	}
	var hello pb.RawControllerHello
	if proto.Unmarshal(body, &hello) != nil || protovalidate.Validate(&hello) != nil ||
		hello.GetProtocolVersion() != ProtocolVersion {
		http.Error(w, "bad hello", http.StatusBadRequest)
		m.shutdown(ErrIncompatibleHello)
		return
	}
	m.mu.Lock()
	m.tunnelID = hello.GetTunnelId()
	m.mu.Unlock()
	out, err := proto.Marshal(m.cfg.Hello)
	if err != nil {
		http.Error(w, "bad hello", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(out)
}

func (m *Mux) handleControl(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	flush(w)
	m.signalEstablished()
	bodyDone := make(chan struct{})
	go func() {
		m.readControl(r.Body)
		close(bodyDone)
	}()
	writer := recordWriter{w: w, flush: func() { flush(w) }}
	for {
		msg, ok := m.nextControl(bodyDone, r.Context().Done())
		if !ok {
			return
		}
		if err := writer.frame(msg); err != nil {
			return
		}
	}
}

// nextControl prefers a queued drain over ordinary control records. Drain is
// how shutdown reaches the controller, so it must not wait behind a full
// buffer of resets.
func (m *Mux) nextControl(bodyDone, reqDone <-chan struct{}) ([]byte, bool) {
	select {
	case msg := <-m.drainOut:
		return msg, true
	default:
	}
	select {
	case msg := <-m.drainOut:
		return msg, true
	case msg := <-m.controlOut:
		return msg, true
	case <-bodyDone:
		return nil, false
	case <-reqDone:
		return nil, false
	case <-m.done:
		return nil, false
	}
}

func (m *Mux) handlePipe(w http.ResponseWriter, r *http.Request) {
	open, err := decodeOpen(r.Header.Get(headerOpen))
	if err != nil {
		writeOpenError(w, &pb.RawOpenError{
			PipeId: 1,
			Reason: pb.RawOpenFailureReason_RAW_OPEN_FAILURE_REASON_PROTOCOL_ERROR,
			Detail: "malformed open",
		})
		return
	}
	if !m.trackHandler() {
		writeOpenError(w, &pb.RawOpenError{
			PipeId: open.GetPipeId(),
			Reason: pb.RawOpenFailureReason_RAW_OPEN_FAILURE_REASON_CONNECTOR_DRAINING,
			Detail: "tunnel closing",
		})
		return
	}
	defer m.untrackHandler()
	p, admitErr := m.admit(open)
	if admitErr != nil {
		writeOpenError(w, admitErr)
		return
	}
	go m.cfg.Accept(p, open)
	select {
	case <-p.decided:
	case <-r.Context().Done():
		p.finish(pb.RawCloseReason_RAW_CLOSE_REASON_CANCELLED, "received")
		return
	}
	p.mu.Lock()
	local := p.local
	refusal := p.refusal
	p.mu.Unlock()
	if local == nil {
		if refusal != nil {
			writeOpenError(w, refusal)
			return
		}
		// Reset, tunnel loss, or shutdown can finish the pipe while Accept is
		// still dialing. Returning without a status makes net/http answer 200,
		// which the controller treats as an open.
		panic(http.ErrAbortHandler)
	}
	w.Header().Set("Trailer", trailerClose)
	w.WriteHeader(http.StatusOK)
	flush(w)
	p.relay(r.Context(), local, r.Body, w, func() { flush(w) })
	w.Header().Set(trailerClose, closeReasonToken(p.Result().Reason))
}

func (m *Mux) admit(open *pb.RawOpen) (*Pipe, *pb.RawOpenError) {
	fail := func(reason pb.RawOpenFailureReason, detail string) (*Pipe, *pb.RawOpenError) {
		return nil, &pb.RawOpenError{PipeId: open.GetPipeId(), Reason: reason, Detail: detail}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	switch {
	case m.err != nil:
		return fail(pb.RawOpenFailureReason_RAW_OPEN_FAILURE_REASON_PROTOCOL_ERROR, "tunnel closed")
	case m.localDrain || m.peerDrain:
		return fail(
			pb.RawOpenFailureReason_RAW_OPEN_FAILURE_REASON_CONNECTOR_DRAINING,
			"tunnel draining",
		)
	case m.slots >= m.cfg.MaxPipes:
		return fail(
			pb.RawOpenFailureReason_RAW_OPEN_FAILURE_REASON_CAPACITY,
			"tunnel at pipe capacity",
		)
	case open.GetPipeId() == 0:
		return fail(
			pb.RawOpenFailureReason_RAW_OPEN_FAILURE_REASON_PROTOCOL_ERROR,
			"pipe id is not increasing",
		)
	}
	// Opens arrive on concurrent HTTP/2 streams, so admission order is not
	// allocation order. Uniqueness is what keeps a pipe id from being reused.
	if _, ok := m.seen[open.GetPipeId()]; ok {
		return fail(
			pb.RawOpenFailureReason_RAW_OPEN_FAILURE_REASON_PROTOCOL_ERROR,
			"pipe id is not increasing",
		)
	}
	m.seen[open.GetPipeId()] = struct{}{}
	if open.GetPipeId() > m.lastID {
		m.lastID = open.GetPipeId()
	}
	return m.newPipeLocked(open), nil
}

func (m *Mux) dial(ctx context.Context) error {
	tr := &http.Transport{DisableCompression: true}
	h2, err := http2.ConfigureTransports(tr)
	if err != nil {
		return err
	}
	h2.AllowHTTP = true
	streamWindow := streamWindow(m.cfg.StreamWindow)
	tr.HTTP2 = &http.HTTP2Config{
		MaxReceiveBufferPerStream:     streamWindow,
		MaxReceiveBufferPerConnection: connectionWindow(m.cfg.MaxPipes, streamWindow),
		MaxReadFrameSize:              maxChunk,
		SendPingTimeout:               m.cfg.PingInterval,
		PingTimeout:                   m.cfg.PingTimeout,
	}
	cc, err := h2.NewClientConn(m.conn)
	if err != nil {
		return err
	}
	m.tr = tr
	m.cc = cc
	if err := m.exchangeHello(ctx); err != nil {
		return err
	}
	if m.cfg.OnEstablished != nil {
		if err := m.cfg.OnEstablished(m.PeerHello()); err != nil {
			return err
		}
	}
	body, err := m.openControl(ctx)
	if err != nil {
		return err
	}
	m.signalEstablished()
	m.readControl(body)
	if err := ctx.Err(); err != nil {
		return err
	}
	return ErrClosed
}

func (m *Mux) exchangeHello(ctx context.Context) error {
	hello := &pb.RawControllerHello{
		ProtocolVersion: ProtocolVersion,
		TunnelId:        m.cfg.TunnelID,
	}
	b, err := proto.Marshal(hello)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(
		ctx, http.MethodPost, "http://tunnel"+helloPath, bytes.NewReader(b),
	)
	if err != nil {
		return err
	}
	resp, err := m.cc.RoundTrip(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ErrIncompatibleHello
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, helloLimit))
	if err != nil {
		return err
	}
	var peer pb.RawConnectorHello
	if proto.Unmarshal(body, &peer) != nil || protovalidate.Validate(&peer) != nil {
		return ErrIncompatibleHello
	}
	if !supportsVersion(peer.GetSupportedProtocolVersions()) {
		return ErrIncompatibleHello
	}
	m.mu.Lock()
	m.peer = &peer
	if advertised := int(peer.GetMaxPipes()); advertised > 0 && advertised < m.cfg.MaxPipes {
		m.cfg.MaxPipes = advertised
	}
	m.mu.Unlock()
	return nil
}

func supportsVersion(versions []uint32) bool {
	for _, v := range versions {
		if v == ProtocolVersion {
			return true
		}
	}
	return false
}

func (m *Mux) openControl(ctx context.Context) (io.ReadCloser, error) {
	pr, pw := io.Pipe()
	m.controlMu.Lock()
	m.controlW = pw
	m.controlMu.Unlock()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://tunnel"+controlPath, pr)
	if err != nil {
		return nil, err
	}
	req.ContentLength = -1
	resp, err := m.cc.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		return nil, ErrIncompatibleHello
	}
	return resp.Body, nil
}

func (m *Mux) sendControl(body []byte) {
	if m.cfg.Role == RoleController {
		m.writeControlBytes(body)
		return
	}
	// Close finishes every pipe on this goroutine. Blocking here while the
	// peer has stopped reading would keep the process from cancelling the TCP
	// connection. A full buffer drops the record; the pipe is already closed
	// locally, and the outer abort ends the session.
	select {
	case m.controlOut <- body:
	case <-m.done:
	default:
		if m.cfg.OnControlDrop != nil {
			m.cfg.OnControlDrop()
		}
	}
}

func (m *Mux) sendDrain(body []byte) {
	select {
	case m.drainOut <- body:
	case <-m.done:
	default:
		// A drain is already queued. The controller only needs one.
	}
}

func (m *Mux) writeControlBytes(body []byte) {
	m.controlMu.Lock()
	w := m.controlW
	m.controlMu.Unlock()
	if w == nil {
		return
	}
	// The HTTP/2 client reads this pipe only between flow-control waits. A
	// full connection window must not pin the caller, or Close never reaches
	// shutdown. Each record is one Write, so concurrent records stay intact.
	go func() {
		_ = (recordWriter{w: w}).frame(body)
	}()
}

func (m *Mux) postDrain(body []byte) {
	if m.cc == nil {
		return
	}
	req, err := http.NewRequestWithContext(
		m.ctx, http.MethodPost, "http://tunnel"+drainPath, nil,
	)
	if err != nil {
		return
	}
	req.Header.Set(headerDrain, base64.StdEncoding.EncodeToString(body))
	resp, err := m.cc.RoundTrip(req)
	if err != nil {
		return
	}
	_ = resp.Body.Close()
}

func (m *Mux) handleDrain(w http.ResponseWriter, r *http.Request) {
	raw, err := base64.StdEncoding.DecodeString(r.Header.Get(headerDrain))
	if err != nil || len(raw) == 0 || len(raw) > helloLimit || !m.applyControl(raw) {
		http.Error(w, "bad drain", http.StatusBadRequest)
		m.shutdown(ErrIncompatibleHello)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// notifyPeer tells the other side that this pipe ended. The data stream may
// be unable to carry that record once its window is full.
func (m *Mux) notifyPeer(id uint64, reason pb.RawCloseReason) {
	if reason == pb.RawCloseReason_RAW_CLOSE_REASON_UNSPECIFIED ||
		reason == pb.RawCloseReason_RAW_CLOSE_REASON_COMPLETED {
		return
	}
	m.sendControl(encodeReset(id, reason))
}

func (m *Mux) finishPipe(id uint64, reason pb.RawCloseReason) {
	m.mu.Lock()
	p := m.pipes[id]
	m.mu.Unlock()
	if p != nil {
		p.finish(reason, "received")
	}
}

func (m *Mux) closeControl() {
	m.controlMu.Lock()
	w := m.controlW
	m.controlW = nil
	m.controlMu.Unlock()
	if w != nil {
		_ = w.Close()
	}
}

func (m *Mux) readControl(r io.Reader) {
	for {
		b, err := readRecord(r)
		if err != nil {
			// A dropped tunnel tears a record in half. That is the session
			// ending, not a drain the peer refused to encode.
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) ||
				errors.Is(err, io.ErrUnexpectedEOF) {
				return
			}
			// A malformed record is a protocol failure. A reset or a transport
			// error is the session ending; calling it an incompatible hello makes
			// the connector treat a dropped tunnel as a bad peer.
			if errors.Is(err, errRecordTooLarge) {
				m.shutdown(ErrIncompatibleHello)
				return
			}
			m.shutdown(ErrClosed)
			return
		}
		if !m.applyControl(b) {
			m.shutdown(ErrIncompatibleHello)
			return
		}
	}
}

func encodeDrain(msg *pb.RawDrain) ([]byte, error) {
	raw, err := proto.Marshal(msg)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 1+len(raw))
	out[0] = controlDrain
	copy(out[1:], raw)
	return out, nil
}

func encodeReset(id uint64, reason pb.RawCloseReason) []byte {
	out := make([]byte, 13)
	out[0] = controlReset
	binary.BigEndian.PutUint64(out[1:9], id)
	reasonWire := uint32(reason) //nolint:gosec // G115: enum fits in uint32
	binary.BigEndian.PutUint32(out[9:13], reasonWire)
	return out
}

func (m *Mux) applyControl(body []byte) bool {
	if len(body) == 0 {
		return false
	}
	switch body[0] {
	case controlDrain:
		var drain pb.RawDrain
		if proto.Unmarshal(body[1:], &drain) != nil || protovalidate.Validate(&drain) != nil {
			return false
		}
		m.markPeerDrain()
		return true
	case controlReset:
		if len(body) != 13 {
			return false
		}
		id := binary.BigEndian.Uint64(body[1:9])
		//nolint:gosec // G115: wire reason is a small int32 enum
		reason := pb.RawCloseReason(binary.BigEndian.Uint32(body[9:13]))
		if reason == pb.RawCloseReason_RAW_CLOSE_REASON_UNSPECIFIED ||
			reason == pb.RawCloseReason_RAW_CLOSE_REASON_COMPLETED {
			return false
		}
		m.finishPipe(id, reason)
		return true
	default:
		return false
	}
}

func (m *Mux) trackHandler() bool {
	m.handlerMu.Lock()
	defer m.handlerMu.Unlock()
	if m.handlersClosed {
		return false
	}
	m.handlerN++
	return true
}

func (m *Mux) untrackHandler() {
	m.handlerMu.Lock()
	defer m.handlerMu.Unlock()
	m.handlerN--
	if m.handlersClosed && m.handlerN == 0 {
		m.handlersOnce.Do(func() { close(m.handlersIdle) })
	}
}

func (m *Mux) waitHandlers() {
	m.handlerMu.Lock()
	m.handlersClosed = true
	idle := m.handlerN == 0
	if idle {
		m.handlersOnce.Do(func() { close(m.handlersIdle) })
	}
	m.handlerMu.Unlock()
	if idle {
		return
	}
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	select {
	case <-m.handlersIdle:
	case <-timer.C:
	}
}

func decodeOpen(v string) (*pb.RawOpen, error) {
	b, err := base64.StdEncoding.DecodeString(v)
	if err != nil {
		return nil, err
	}
	var open pb.RawOpen
	if proto.Unmarshal(b, &open) != nil || protovalidate.Validate(&open) != nil {
		return nil, errors.New("rawtunnel: malformed open")
	}
	return &open, nil
}

func encodeOpen(open *pb.RawOpen) (string, error) {
	b, err := proto.Marshal(open)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

func writeOpenError(w http.ResponseWriter, e *pb.RawOpenError) {
	b, err := proto.Marshal(e)
	if err != nil {
		http.Error(w, "bad open", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusConflict)
	_, _ = w.Write(b) //nolint:gosec // G705: body is a marshaled protobuf, not HTML
}

func flush(w http.ResponseWriter) {
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
}

func closeReasonToken(reason pb.RawCloseReason) string {
	return reason.String()
}
