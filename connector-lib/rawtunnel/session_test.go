package rawtunnel

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"sync"
	"testing"
	"time"

	pb "github.com/InteractionLabs/traversal-connector/connector-lib/gen/connector/v1"
)

func TestSessionIdentityAndOuterWindow(t *testing.T) {
	ctrl := startSession(t, TunnelWindow, func(p *Pipe, _ *pb.RawOpen) {
		if err := p.Start(newEcho()); err != nil {
			t.Errorf("start: %v", err)
		}
	})
	if ctrl.TunnelID() != "550e8400-e29b-41d4-a716-446655440000" {
		t.Fatalf("tunnel id %q", ctrl.TunnelID())
	}
	select {
	case <-ctrl.Done():
		t.Fatal("session ended before close")
	case <-ctrl.Drained():
		t.Fatal("session drained before close")
	default:
	}
	pipe := openPipe(t, ctrl, "id.test", newScript([]byte("x")))
	if pipe.ID() == 0 {
		t.Fatal("pipe id is zero")
	}
	var cfg http.HTTP2Config
	ApplyOuterWindows(&cfg)
	if cfg.MaxReceiveBufferPerStream != TunnelWindow ||
		cfg.MaxReceiveBufferPerConnection != TunnelWindow {
		t.Fatalf("windows %d %d", cfg.MaxReceiveBufferPerStream, cfg.MaxReceiveBufferPerConnection)
	}
	if got, want := ConnectionWindow(100), 100*StreamWindow; got != want {
		t.Fatalf("connection window %d, want %d", got, want)
	}
	if got := ConnectionWindow(math.MaxInt32); got != math.MaxInt32 {
		t.Fatalf("connection window overflowed: %d", got)
	}
	var custom http.HTTP2Config
	ApplyOuterWindow(&custom, 2<<20)
	if custom.MaxReceiveBufferPerStream != 2<<20 ||
		custom.MaxReceiveBufferPerConnection != 2<<20 {
		t.Fatalf("custom windows %d %d", custom.MaxReceiveBufferPerStream, custom.MaxReceiveBufferPerConnection)
	}
	if got := connectionWindow(4, 64<<10); got != 4*(64<<10) {
		t.Fatalf("narrow connection window %d", got)
	}
	var http2cfg http.HTTP2Config
	ConfigureHTTP2(&http2cfg)
	if http2cfg.SendPingTimeout != DefaultPingInterval ||
		http2cfg.PingTimeout != DefaultPingTimeout ||
		http2cfg.WriteByteTimeout != DefaultWriteByteTimeout {
		t.Fatal("http2 timeouts were not set")
	}
}

type memChunks struct {
	msgs []*pb.RawTunnelChunk
}

func (m *memChunks) Send(c *pb.RawTunnelChunk) error {
	b := append([]byte(nil), c.GetData()...)
	m.msgs = append(m.msgs, &pb.RawTunnelChunk{Data: b})
	return nil
}

func (m *memChunks) Receive() (*pb.RawTunnelChunk, error) {
	if len(m.msgs) == 0 {
		return nil, io.EOF
	}
	c := m.msgs[0]
	m.msgs = m.msgs[1:]
	return c, nil
}

func TestFromChunksCopiesOneMessage(t *testing.T) {
	src := FromChunks(&memChunks{})
	if err := src.Send([]byte{1, 2, 3}); err != nil {
		t.Fatal(err)
	}
	got, err := src.Receive()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte{1, 2, 3}) {
		t.Fatalf("chunk %v", got)
	}
}

func TestSessionEcho(t *testing.T) {
	payload := bytes.Repeat([]byte("echo-bytes."), 40<<10)
	ctrl := startSession(t, TunnelWindow, func(p *Pipe, _ *pb.RawOpen) {
		if err := p.Start(newEcho()); err != nil {
			t.Errorf("start: %v", err)
		}
	})

	local := newScript(payload)
	pipe := openPipe(t, ctrl, "example.com", local)
	waitDone(t, pipe)
	if got := pipe.Result().Reason; got != pb.RawCloseReason_RAW_CLOSE_REASON_COMPLETED {
		t.Fatalf("reason %s", got)
	}
	if !bytes.Equal(local.got(), payload) {
		t.Fatalf("echo = %d bytes, want %d", len(local.got()), len(payload))
	}
}

func TestTwoPipesEcho(t *testing.T) {
	ctrl := startSession(t, TunnelWindow, func(p *Pipe, _ *pb.RawOpen) {
		if err := p.Start(newEcho()); err != nil {
			t.Errorf("start: %v", err)
		}
	})
	payload := bytes.Repeat([]byte("both"), 32<<10)
	a := newScript(payload)
	b := newScript(payload)
	pa := openPipe(t, ctrl, "a.test", a)
	pbPipe := openPipe(t, ctrl, "b.test", b)
	waitDone(t, pa)
	waitDone(t, pbPipe)
	if !bytes.Equal(a.got(), payload) || !bytes.Equal(b.got(), payload) {
		t.Fatal("concurrent echoes diverged")
	}
}

func TestSessionStallDoesNotBlockOtherPipes(t *testing.T) {
	for _, stream := range []int{0, 64 << 10} {
		t.Run(fmt.Sprintf("stream=%d", streamWindow(stream)), func(t *testing.T) {
			testSessionStallDoesNotBlockOtherPipes(t, stream)
		})
	}
}

func testSessionStallDoesNotBlockOtherPipes(t *testing.T, stream int) {
	t.Helper()
	perPipe := streamWindow(stream)
	ctrl := startSessionWindow(t, TunnelWindow, stream, func(p *Pipe, open *pb.RawOpen) {
		local := Local(newEcho())
		if open.GetHost() == "stall.test" {
			local = newHold()
		}
		if err := p.Start(local); err != nil {
			t.Errorf("start: %v", err)
		}
	})

	// Larger than one stream window, smaller than the connection window, so a
	// pipe nobody reads cannot stop the session's other pipes.
	stall := openPipe(
		t,
		ctrl,
		"stall.test",
		newScript(bytes.Repeat([]byte{7}, perPipe+64<<10)),
	)
	select {
	case <-stall.Done():
		t.Fatal("unread pipe ended on its own")
	case <-time.After(50 * time.Millisecond):
	}
	payload := bytes.Repeat([]byte("other"), 8<<10)
	local := newScript(payload)
	echo, err := ctrl.Open("token", "other.test", 443, pb.RawPipeMode_RAW_PIPE_MODE_PASSTHROUGH)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := echo.WaitOpened(ctx); err != nil {
		t.Fatalf("sibling open: %v (stall sent %d)", err, stall.Result().BytesSent)
	}
	if err := echo.Start(local); err != nil {
		t.Fatal(err)
	}
	waitDone(t, echo)
	if !bytes.Equal(local.got(), payload) {
		t.Fatalf("sibling echo = %d bytes, want %d", len(local.got()), len(payload))
	}
	select {
	case <-stall.Done():
		t.Fatal("sibling completion ended the stalled pipe")
	default:
	}
}

func TestResetUnblocksAStalledPeer(t *testing.T) {
	seen := make(chan *Pipe, 1)
	ctrl := startSession(t, TunnelWindow, func(p *Pipe, _ *pb.RawOpen) {
		seen <- p
		if err := p.Start(newHold()); err != nil {
			t.Errorf("start: %v", err)
		}
	})
	stall := openPipe(
		t,
		ctrl,
		"stall.test",
		newScript(bytes.Repeat([]byte{7}, StreamWindow+64<<10)),
	)
	select {
	case <-stall.Done():
		t.Fatal("unread pipe ended on its own")
	case <-time.After(50 * time.Millisecond):
	}
	peer := <-seen
	stall.Reset(pb.RawCloseReason_RAW_CLOSE_REASON_CANCELLED)
	select {
	case <-peer.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("reset did not end the stalled peer")
	}
	if got := peer.Result().Reason; got != pb.RawCloseReason_RAW_CLOSE_REASON_CANCELLED {
		t.Fatalf("peer reason %s", got)
	}
}

func TestResetReachesThePeer(t *testing.T) {
	seen := make(chan *Pipe, 1)
	ctrl := startSession(t, TunnelWindow, func(p *Pipe, _ *pb.RawOpen) {
		if err := p.Start(newEcho()); err != nil {
			t.Errorf("start: %v", err)
		}
		seen <- p
	})

	local := newScript([]byte("ping"))
	pipe := openPipe(t, ctrl, "reset.test", local)
	var peer *Pipe
	select {
	case peer = <-seen:
	case <-time.After(2 * time.Second):
		t.Fatal("connector did not accept")
	}
	pipe.Reset(pb.RawCloseReason_RAW_CLOSE_REASON_CANCELLED)
	waitDone(t, peer)
	if got := peer.Result().Reason; got != pb.RawCloseReason_RAW_CLOSE_REASON_CANCELLED {
		t.Fatalf("peer reason %s", got)
	}
}

func TestRefusalIsAnOpenError(t *testing.T) {
	ctrl := startSession(t, TunnelWindow, func(p *Pipe, _ *pb.RawOpen) {
		if err := p.Refuse(
			pb.RawOpenFailureReason_RAW_OPEN_FAILURE_REASON_DIAL_FAILED, "no route",
		); err != nil {
			t.Errorf("refuse: %v", err)
		}
	})

	pipe, err := ctrl.Open("token", "refuse.test", 443, pb.RawPipeMode_RAW_PIPE_MODE_PASSTHROUGH)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err = pipe.WaitOpened(ctx)
	openErr, ok := err.(*OpenError)
	if !ok || openErr.Reason != pb.RawOpenFailureReason_RAW_OPEN_FAILURE_REASON_DIAL_FAILED {
		t.Fatalf("WaitOpened() = %v", err)
	}
}

func TestTunnelWindowBoundsQueuedBytes(t *testing.T) {
	for _, tc := range []struct {
		name   string
		outer  int
		stream int
		n      int
		size   int
	}{
		{name: "production", outer: TunnelWindow, stream: 0, n: 8, size: 512 << 10},
		{name: "outer smaller than inner", outer: 64 << 10, stream: 0, n: 4, size: 1 << 20},
		{name: "narrow stream", outer: TunnelWindow, stream: 64 << 10, n: 4, size: 128 << 10},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var maxQueued func() int
			ctrl, _, stop := startSessionObserved(t, tc.outer, tc.stream, func(p *Pipe, _ *pb.RawOpen) {
				if err := p.Start(newEcho()); err != nil {
					t.Errorf("start: %v", err)
				}
			}, &maxQueued)
			defer stop()
			payload := bytes.Repeat([]byte{0xab}, tc.size)
			var pipes []*Pipe
			for i := 0; i < tc.n; i++ {
				pipes = append(pipes, openPipe(t, ctrl, "bulk.test", newScript(payload)))
			}
			for _, p := range pipes {
				waitDone(t, p)
				if p.Result().Reason != pb.RawCloseReason_RAW_CLOSE_REASON_COMPLETED {
					t.Fatalf("reason %s", p.Result().Reason)
				}
			}
			if held := ctrl.conn.MaxHeld(); held > maxChunk {
				t.Fatalf("adapter held %d bytes, want at most one chunk", held)
			}
			if got := maxQueued(); got > tc.outer {
				t.Fatalf("queued %d bytes, outer window %d", got, tc.outer)
			}
		})
	}
}

func TestDrainCrossesAFullConnectionWindow(t *testing.T) {
	// startSessionObserved admits 32 pipes. Eight full stream windows are
	// 2 MiB, past the 1 MiB outer window, so this fails if the inner
	// connection window is still the outer window.
	const pipes = 8
	ctrl, conn, stop := startSessionObserved(t, TunnelWindow, 0, func(p *Pipe, _ *pb.RawOpen) {
		if err := p.Start(newHold()); err != nil {
			t.Errorf("start: %v", err)
		}
	}, nil)
	defer stop()
	payload := bytes.Repeat([]byte{7}, StreamWindow)
	var opened []*Pipe
	for range pipes {
		opened = append(opened, openPipe(t, ctrl, "stall.test", newScript(payload)))
	}
	want := int64(pipes)*int64(StreamWindow) - int64(pipes)*int64(maxRecord)
	deadline := time.Now().Add(5 * time.Second)
	var sent int64
	for time.Now().Before(deadline) {
		sent = 0
		for _, p := range opened {
			sent += p.Result().BytesSent
		}
		if sent >= want {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if sent < want {
		t.Fatalf("pipes stalled below the connection window, sent %d want %d", sent, want)
	}
	ctrl.Drain(pb.RawDrainReason_RAW_DRAIN_REASON_ROTATION)
	select {
	case <-conn.Draining():
	case <-time.After(2 * time.Second):
		t.Fatal("drain did not reach the connector")
	}
}

func TestCloseReturnsWhileTheWindowIsFull(t *testing.T) {
	ctrl, _, stop := startSessionObserved(t, TunnelWindow, 0, func(p *Pipe, _ *pb.RawOpen) {
		if err := p.Start(newHold()); err != nil {
			t.Errorf("start: %v", err)
		}
	}, nil)
	defer stop()
	const pipes = 32 // startSessionObserved admits 32
	payload := bytes.Repeat([]byte{7}, StreamWindow)
	var opened []*Pipe
	for range pipes {
		opened = append(opened, openPipe(t, ctrl, "stall.test", newScript(payload)))
	}
	want := int64(ConnectionWindow(pipes)) - int64(pipes)*int64(maxRecord)
	deadline := time.Now().Add(5 * time.Second)
	var sent int64
	for time.Now().Before(deadline) {
		sent = 0
		for _, p := range opened {
			sent += p.Result().BytesSent
		}
		if sent >= want {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if sent < want {
		t.Fatalf("connection window did not fill, sent %d want %d", sent, want)
	}
	done := make(chan struct{})
	go func() {
		ctrl.Close(pb.RawCloseReason_RAW_CLOSE_REASON_CONNECTOR_TERMINATING)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Close blocked while the connection window was full")
	}
}

func TestResetDuringAcceptIsNotAnOpen(t *testing.T) {
	started := make(chan struct{})
	ctrl := startSession(t, TunnelWindow, func(p *Pipe, _ *pb.RawOpen) {
		close(started)
		<-p.Context().Done()
	})
	pipe, err := ctrl.Open("token", "dial.test", 443, pb.RawPipeMode_RAW_PIPE_MODE_PASSTHROUGH)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("connector did not accept")
	}
	pipe.Reset(pb.RawCloseReason_RAW_CLOSE_REASON_CANCELLED)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err = pipe.WaitOpened(ctx)
	if err == nil {
		t.Fatal("reset during dial was reported as an open")
	}
	if got := pipe.Result().Reason; got != pb.RawCloseReason_RAW_CLOSE_REASON_CANCELLED {
		t.Fatalf("reason %s", got)
	}
}

func TestConcurrentFramesStayIntact(t *testing.T) {
	pr, pw := io.Pipe()
	payload := bytes.Repeat([]byte{0x11}, 100)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		w := recordWriter{w: pw}
		for range 50 {
			if err := w.frame(payload); err != nil {
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		w := recordWriter{w: pw}
		for range 50 {
			if err := w.frameClose(pb.RawCloseReason_RAW_CLOSE_REASON_CANCELLED); err != nil {
				return
			}
		}
	}()
	go func() {
		wg.Wait()
		_ = pw.Close()
	}()
	frames := 0
	for {
		got, err := readFrame(pr)
		if err == io.EOF {
			break
		}
		var closed *closeError
		if errors.As(err, &closed) {
			if closed.reason != pb.RawCloseReason_RAW_CLOSE_REASON_CANCELLED {
				t.Fatalf("close reason %s", closed.reason)
			}
			frames++
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, payload) {
			t.Fatalf("torn frame len %d", len(got))
		}
		frames++
	}
	if frames != 100 {
		t.Fatalf("frames = %d, want 100", frames)
	}
}

func openPipe(t *testing.T, ctrl *Mux, host string, local Local) *Pipe {
	t.Helper()
	pipe, err := ctrl.Open("token", host, 443, pb.RawPipeMode_RAW_PIPE_MODE_PASSTHROUGH)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := pipe.WaitOpened(ctx); err != nil {
		t.Fatal(err)
	}
	if err := pipe.Start(local); err != nil {
		t.Fatal(err)
	}
	return pipe
}

func waitDone(t *testing.T, p *Pipe) {
	t.Helper()
	select {
	case <-p.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("pipe did not finish")
	}
}

func startSession(t *testing.T, outer int, accept func(*Pipe, *pb.RawOpen)) *Mux {
	t.Helper()
	return startSessionWindow(t, outer, 0, accept)
}

func startSessionWindow(
	t *testing.T, outer, stream int, accept func(*Pipe, *pb.RawOpen),
) *Mux {
	t.Helper()
	ctrl, _, stop := startSessionObserved(t, outer, stream, accept, nil)
	t.Cleanup(stop)
	return ctrl
}

func startSessionObserved(
	t *testing.T, outer, stream int, accept func(*Pipe, *pb.RawOpen), queued *func() int,
) (*Mux, *Mux, func()) {
	t.Helper()
	left, right, maxQueued := newWindowPair(outer)
	if queued != nil {
		*queued = maxQueued
	}
	ctx, cancel := context.WithCancel(context.Background())
	hello := &pb.RawConnectorHello{
		SupportedProtocolVersions: []uint32{ProtocolVersion},
		Hostname:                  "edge-1",
		MaxPipes:                  32,
		SupportedModes:            []pb.RawPipeMode{pb.RawPipeMode_RAW_PIPE_MODE_PASSTHROUGH},
	}
	ctrl, err := New(Config{
		Role:         RoleController,
		TunnelID:     "550e8400-e29b-41d4-a716-446655440000",
		MaxPipes:     32,
		StreamWindow: stream,
		IdleTimeout:  time.Hour,
		MaxLifetime:  time.Hour,
		PingInterval: time.Hour,
		PingTimeout:  time.Hour,
		Abort:        cancel,
	}, left)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := New(Config{
		Role:         RoleConnector,
		MaxPipes:     32,
		StreamWindow: stream,
		IdleTimeout:  time.Hour,
		MaxLifetime:  time.Hour,
		PingInterval: time.Hour,
		PingTimeout:  time.Hour,
		Hello:        hello,
		Abort:        func() {},
		Accept:       accept,
	}, right)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = ctrl.Run(ctx) }()
	go func() { _ = conn.Run(ctx) }()
	select {
	case <-ctrl.Established():
	case <-time.After(2 * time.Second):
		t.Fatal("tunnel did not establish")
	}
	stop := func() {
		ctrl.Close(pb.RawCloseReason_RAW_CLOSE_REASON_CONNECTOR_TERMINATING)
		conn.Close(pb.RawCloseReason_RAW_CLOSE_REASON_CONNECTOR_TERMINATING)
		cancel()
	}
	return ctrl, conn, stop
}

type scriptLocal struct {
	mu     sync.Mutex
	unread []byte
	wrote  bytes.Buffer
	closed bool
}

func newScript(payload []byte) *scriptLocal {
	return &scriptLocal{unread: append([]byte(nil), payload...)}
}

func (s *scriptLocal) Read(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return 0, io.ErrClosedPipe
	}
	if len(s.unread) == 0 {
		return 0, io.EOF
	}
	n := copy(p, s.unread)
	s.unread = s.unread[n:]
	return n, nil
}

func (s *scriptLocal) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return 0, io.ErrClosedPipe
	}
	return s.wrote.Write(p)
}

func (s *scriptLocal) CloseWrite() error { return nil }
func (s *scriptLocal) Close() error {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	return nil
}

func (s *scriptLocal) got() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte(nil), s.wrote.Bytes()...)
}

type echoLocal struct {
	pr *io.PipeReader
	pw *io.PipeWriter
}

func newEcho() *echoLocal {
	pr, pw := io.Pipe()
	return &echoLocal{pr: pr, pw: pw}
}

func (e *echoLocal) Read(p []byte) (int, error)  { return e.pr.Read(p) }
func (e *echoLocal) Write(p []byte) (int, error) { return e.pw.Write(p) }
func (e *echoLocal) CloseWrite() error           { return e.pw.Close() }
func (e *echoLocal) Close() error {
	_ = e.pr.Close()
	return e.pw.Close()
}

type holdLocal struct {
	once sync.Once
	done chan struct{}
}

func newHold() *holdLocal { return &holdLocal{done: make(chan struct{})} }

func (h *holdLocal) Read(p []byte) (int, error) {
	<-h.done
	return 0, io.EOF
}

func (h *holdLocal) Write(p []byte) (int, error) {
	<-h.done
	return 0, io.ErrClosedPipe
}

func (h *holdLocal) CloseWrite() error { return nil }
func (h *holdLocal) Close() error {
	h.once.Do(func() { close(h.done) })
	return nil
}

// windowDir is one direction of the outer stream. Send blocks once `window`
// bytes are sitting unread, which is the outer gRPC receive window.
type windowDir struct {
	mu        sync.Mutex
	cond      *sync.Cond
	window    int
	maxWindow int
	queued    int
	maxQueued int
	buf       [][]byte
	closed    bool
}

func newWindowDir(window int) *windowDir {
	d := &windowDir{window: window, maxWindow: window}
	d.cond = sync.NewCond(&d.mu)
	return d
}

func (d *windowDir) send(p []byte) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	for d.window < len(p) && !d.closed {
		d.cond.Wait()
	}
	if d.closed {
		return io.ErrClosedPipe
	}
	b := append([]byte(nil), p...)
	d.window -= len(b)
	d.queued += len(b)
	if d.queued > d.maxQueued {
		d.maxQueued = d.queued
	}
	d.buf = append(d.buf, b)
	d.cond.Broadcast()
	return nil
}

func (d *windowDir) recv() ([]byte, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for len(d.buf) == 0 && !d.closed {
		d.cond.Wait()
	}
	if len(d.buf) == 0 {
		return nil, io.EOF
	}
	b := d.buf[0]
	d.buf = d.buf[1:]
	d.queued -= len(b)
	d.window += len(b)
	if d.window > d.maxWindow {
		d.window = d.maxWindow
	}
	d.cond.Broadcast()
	return b, nil
}

func (d *windowDir) close() {
	d.mu.Lock()
	d.closed = true
	d.cond.Broadcast()
	d.mu.Unlock()
}

type windowStream struct {
	out *windowDir
	in  *windowDir
}

func (s windowStream) Send(p []byte) error      { return s.out.send(p) }
func (s windowStream) Receive() ([]byte, error) { return s.in.recv() }
func (s windowStream) Close() error {
	s.out.close()
	s.in.close()
	return nil
}

func TestDrainIsQueuedWhenControlRecordsAreDropped(t *testing.T) {
	_, cancel := context.WithCancel(context.Background())
	defer cancel()
	drops := 0
	_, right, _ := newWindowPair(TunnelWindow)
	mux, err := New(Config{
		Role:     RoleConnector,
		MaxPipes: 1,
		Hello: &pb.RawConnectorHello{
			SupportedProtocolVersions: []uint32{ProtocolVersion},
			Hostname:                  "edge-1",
			MaxPipes:                  1,
			SupportedModes:            []pb.RawPipeMode{pb.RawPipeMode_RAW_PIPE_MODE_PASSTHROUGH},
		},
		Abort: cancel,
		Accept: func(*Pipe, *pb.RawOpen) {
		},
		OnControlDrop: func() { drops++ },
	}, right)
	if err != nil {
		t.Fatal(err)
	}
	defer mux.Close(pb.RawCloseReason_RAW_CLOSE_REASON_TUNNEL_LOST)
	capacity := cap(mux.controlOut)
	for range capacity {
		mux.sendControl([]byte{1})
	}
	if drops != 0 {
		t.Fatalf("drops = %d before the buffer was full", drops)
	}
	mux.sendControl([]byte{1})
	if drops != 1 {
		t.Fatalf("drops = %d, want 1", drops)
	}
	mux.Drain(pb.RawDrainReason_RAW_DRAIN_REASON_SHUTDOWN)
	select {
	case <-mux.drainOut:
	default:
		t.Fatal("drain was dropped with the control buffer full")
	}
}

func newWindowPair(window int) (left, right Stream, maxQueued func() int) {
	a := newWindowDir(window)
	b := newWindowDir(window)
	left = windowStream{out: a, in: b}
	right = windowStream{out: b, in: a}
	maxQueued = func() int {
		a.mu.Lock()
		b.mu.Lock()
		defer a.mu.Unlock()
		defer b.mu.Unlock()
		if a.maxQueued > b.maxQueued {
			return a.maxQueued
		}
		return b.maxQueued
	}
	return left, right, maxQueued
}
