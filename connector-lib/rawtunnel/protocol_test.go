package rawtunnel

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	pb "github.com/InteractionLabs/traversal-connector/connector-lib/gen/connector/v1"
)

const (
	protocolError = pb.RawCloseReason_RAW_CLOSE_REASON_PROTOCOL_ERROR
	cancelled     = pb.RawCloseReason_RAW_CLOSE_REASON_CANCELLED
)

// peer drives one Mux frame by frame, playing the other side of the tunnel.
type peer struct {
	t      *testing.T
	m      *Mux
	s      *chanStream
	runErr <-chan error
}

func newPeer(t *testing.T, cfg Config, buffer int) *peer {
	t.Helper()
	ours, theirs := streamPair(buffer)
	cfg.Abort = theirs.abort
	m, err := New(cfg, theirs)
	if err != nil {
		t.Fatal(err)
	}
	return &peer{t: t, m: m, s: ours, runErr: runMux(t, m, theirs)}
}

// connectorPeer runs a connector Mux whose Accept starts local.
func connectorPeer(t *testing.T, maxPipes int, newLocal func() Local) *peer {
	t.Helper()
	return newPeer(t, Config{
		Role:     RoleConnector,
		MaxPipes: maxPipes,
		Accept:   func(p *Pipe, _ *pb.RawOpen) { _ = p.Start(newLocal()) },
	}, 0)
}

func controllerPeer(t *testing.T) *peer {
	t.Helper()
	return newPeer(t, Config{Role: RoleController, MaxPipes: 4}, 0)
}

func (p *peer) send(frames ...*pb.RawTunnelFrame) {
	p.t.Helper()
	for _, f := range frames {
		if err := p.s.Send(f); err != nil {
			p.t.Fatalf("send %v: %v", f, err)
		}
	}
}

func (p *peer) next() *pb.RawTunnelFrame {
	p.t.Helper()
	type result struct {
		f   *pb.RawTunnelFrame
		err error
	}
	got := make(chan result, 1)
	go func() {
		f, err := p.s.Receive()
		got <- result{f, err}
	}()
	select {
	case r := <-got:
		if r.err != nil {
			p.t.Fatalf("receive: %v", r.err)
		}
		return r.f
	case <-time.After(waitTimeout):
		p.t.Fatal("no frame from mux")
		return nil
	}
}

// expect asserts the mux's next frames, in order.
func (p *peer) expect(want ...*pb.RawTunnelFrame) {
	p.t.Helper()
	for _, w := range want {
		if got := p.next(); !proto.Equal(got, w) {
			p.t.Fatalf("got frame %v, want %v", got, w)
		}
	}
}

// expectAlive asserts that the mux sent nothing else and still answers pings.
func (p *peer) expectAlive() {
	p.t.Helper()
	p.send(ping(99, false))
	p.expect(ping(99, true))
}

func (p *peer) expectFatal() {
	p.t.Helper()
	select {
	case err := <-p.runErr:
		var perr *ProtocolError
		if !errors.As(err, &perr) {
			p.t.Fatalf("Run = %v, want a protocol error", err)
		}
	case <-time.After(waitTimeout):
		p.t.Fatal("mux kept running after a fatal frame")
	}
}

func frame(f any) *pb.RawTunnelFrame {
	switch f := f.(type) {
	case *pb.RawOpen:
		return &pb.RawTunnelFrame{Frame: &pb.RawTunnelFrame_Open{Open: f}}
	case *pb.RawOpened:
		return &pb.RawTunnelFrame{Frame: &pb.RawTunnelFrame_Opened{Opened: f}}
	case *pb.RawOpenError:
		return &pb.RawTunnelFrame{Frame: &pb.RawTunnelFrame_OpenError{OpenError: f}}
	case *pb.RawData:
		return &pb.RawTunnelFrame{Frame: &pb.RawTunnelFrame_Data{Data: f}}
	case *pb.RawWindowUpdate:
		return &pb.RawTunnelFrame{Frame: &pb.RawTunnelFrame_WindowUpdate{WindowUpdate: f}}
	case *pb.RawHalfClose:
		return &pb.RawTunnelFrame{Frame: &pb.RawTunnelFrame_HalfClose{HalfClose: f}}
	case *pb.RawReset:
		return &pb.RawTunnelFrame{Frame: &pb.RawTunnelFrame_PipeReset{PipeReset: f}}
	case *pb.RawClose:
		return &pb.RawTunnelFrame{Frame: &pb.RawTunnelFrame_Close{Close: f}}
	case *pb.RawDrain:
		return &pb.RawTunnelFrame{Frame: &pb.RawTunnelFrame_Drain{Drain: f}}
	case *pb.RawPing:
		return &pb.RawTunnelFrame{Frame: &pb.RawTunnelFrame_Ping{Ping: f}}
	case *pb.RawConnectorHello:
		return &pb.RawTunnelFrame{Frame: &pb.RawTunnelFrame_ConnectorHello{ConnectorHello: f}}
	case *pb.RawControllerHello:
		return &pb.RawTunnelFrame{Frame: &pb.RawTunnelFrame_ControllerHello{ControllerHello: f}}
	}
	panic("unknown frame type")
}

func open(id uint64) *pb.RawTunnelFrame {
	return frame(&pb.RawOpen{
		PipeId: id, Capability: testCapability, Host: "db.internal", Port: 5432, Mode: passthrough,
	})
}

func opened(id uint64) *pb.RawTunnelFrame { return frame(&pb.RawOpened{PipeId: id}) }

func data(id uint64, n int) *pb.RawTunnelFrame {
	return frame(&pb.RawData{PipeId: id, Payload: bytes.Repeat([]byte{'x'}, n)})
}

func window(id uint64, credit uint32) *pb.RawTunnelFrame {
	return frame(&pb.RawWindowUpdate{PipeId: id, CreditBytes: credit})
}

func halfClose(id uint64) *pb.RawTunnelFrame { return frame(&pb.RawHalfClose{PipeId: id}) }

func reset(id uint64, r pb.RawCloseReason) *pb.RawTunnelFrame {
	return frame(&pb.RawReset{PipeId: id, Reason: r})
}

func closeFrame(id uint64, r pb.RawCloseReason) *pb.RawTunnelFrame {
	return frame(&pb.RawClose{PipeId: id, Reason: r})
}

func openError(id uint64, r pb.RawOpenFailureReason, detail string) *pb.RawTunnelFrame {
	return frame(&pb.RawOpenError{PipeId: id, Reason: r, Detail: detail})
}

func ping(nonce uint64, ack bool) *pb.RawTunnelFrame {
	return frame(&pb.RawPing{Nonce: nonce, Ack: ack})
}

func drain(r pb.RawDrainReason) *pb.RawTunnelFrame { return frame(&pb.RawDrain{Reason: r}) }

func fill(n int) []*pb.RawTunnelFrame {
	var frames []*pb.RawTunnelFrame
	for ; n > 0; n -= MaxDataBytes {
		frames = append(frames, data(1, min(n, MaxDataBytes)))
	}
	return frames
}

func TestConnectorResetsPipeOnViolation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		frames []*pb.RawTunnelFrame
	}{
		{"data beyond credit", append(fill(Window), data(1, 1))},
		{"empty data", []*pb.RawTunnelFrame{data(1, 0)}},
		{"oversized data", []*pb.RawTunnelFrame{data(1, MaxDataBytes+1)}},
		{"data after half-close", []*pb.RawTunnelFrame{halfClose(1), data(1, 1)}},
		{"duplicate half-close", []*pb.RawTunnelFrame{halfClose(1), halfClose(1)}},
		{"credit beyond window", []*pb.RawTunnelFrame{window(1, 1)}},
		{"zero credit", []*pb.RawTunnelFrame{window(1, 0)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := connectorPeer(t, 4, blockingLocal)
			p.send(open(1))
			p.expect(opened(1))
			p.send(tc.frames...)
			p.expect(reset(1, protocolError), closeFrame(1, protocolError))
			p.expectAlive()
		})
	}
}

func TestConnectorAcceptsFullWindow(t *testing.T) {
	p := connectorPeer(t, 4, blockingLocal)
	p.send(open(1))
	p.expect(opened(1))
	p.send(fill(Window)...)
	p.expectAlive()
}

func TestConnectorResetsOpeningPipeOnViolation(t *testing.T) {
	resolved := make(chan error, 1)
	p := newPeer(t, Config{Role: RoleConnector, MaxPipes: 4, Accept: func(p *Pipe, _ *pb.RawOpen) {
		<-p.Context().Done()
		resolved <- p.Refuse(pb.RawOpenFailureReason_RAW_OPEN_FAILURE_REASON_DIAL_FAILED, "")
	}}, 0)
	p.send(open(1), data(1, 1))
	p.expect(reset(1, protocolError), closeFrame(1, protocolError))
	if err := <-resolved; err != nil {
		t.Fatal(err)
	}
}

func TestConnectorClosesPipeResetWhileOpening(t *testing.T) {
	p := newPeer(t, Config{Role: RoleConnector, MaxPipes: 4, Accept: func(p *Pipe, _ *pb.RawOpen) {
		<-p.Context().Done()
		_ = p.Start(newSilentLocal())
	}}, 0)
	p.send(open(1), reset(1, cancelled))
	p.expect(closeFrame(1, cancelled))
	p.expectAlive()
}

func TestConnectorRefusesWithoutAccept(t *testing.T) {
	malformed := open(1)
	malformed.GetOpen().Port = 0

	t.Run("malformed open", func(t *testing.T) {
		p := newPeer(t, Config{Role: RoleConnector, MaxPipes: 4, Accept: func(*Pipe, *pb.RawOpen) {
			t.Error("Accept called for a malformed open")
		}}, 0)
		p.send(malformed)
		p.expect(openError(1, pb.RawOpenFailureReason_RAW_OPEN_FAILURE_REASON_PROTOCOL_ERROR,
			"malformed open"))
	})
	t.Run("connector draining", func(t *testing.T) {
		p := connectorPeer(t, 4, quietLocal)
		p.m.Drain(pb.RawDrainReason_RAW_DRAIN_REASON_SHUTDOWN)
		p.expect(drain(pb.RawDrainReason_RAW_DRAIN_REASON_SHUTDOWN))
		p.send(open(1))
		p.expect(openError(1,
			pb.RawOpenFailureReason_RAW_OPEN_FAILURE_REASON_CONNECTOR_DRAINING, "tunnel draining"))
		waitClosed(t, p.m.Drained(), "drained")
	})
	t.Run("controller drained", func(t *testing.T) {
		p := connectorPeer(t, 4, quietLocal)
		p.send(drain(pb.RawDrainReason_RAW_DRAIN_REASON_ROTATION), open(1))
		p.expect(openError(1, pb.RawOpenFailureReason_RAW_OPEN_FAILURE_REASON_PROTOCOL_ERROR,
			"open after controller drain"))
	})
}

func TestConnectorIgnoresFramesForRetiredPipes(t *testing.T) {
	p := connectorPeer(t, 4, quietLocal)
	p.send(open(1))
	p.expect(opened(1))
	p.send(reset(1, cancelled))
	p.expect(closeFrame(1, cancelled))
	p.send(data(1, 1), window(1, 1), halfClose(1), reset(1, cancelled))
	p.expectAlive()
}

func TestConnectorEndsTunnelOnFatalFrame(t *testing.T) {
	for _, tc := range []struct {
		name   string
		frames []*pb.RawTunnelFrame
	}{
		{"empty frame", []*pb.RawTunnelFrame{{}}},
		{"hello", []*pb.RawTunnelFrame{frame(&pb.RawControllerHello{})}},
		{"connector hello", []*pb.RawTunnelFrame{frame(&pb.RawConnectorHello{})}},
		{"opened", []*pb.RawTunnelFrame{open(1), opened(1)}},
		{"open_error", []*pb.RawTunnelFrame{open(1), openError(1,
			pb.RawOpenFailureReason_RAW_OPEN_FAILURE_REASON_CAPACITY, "")}},
		{"close", []*pb.RawTunnelFrame{open(1), closeFrame(1, cancelled)}},
		{"data for unopened pipe", []*pb.RawTunnelFrame{data(5, 1)}},
		{"pipe id zero", []*pb.RawTunnelFrame{open(1), data(0, 1)}},
		{"open id zero", []*pb.RawTunnelFrame{open(0)}},
		{"duplicate open", []*pb.RawTunnelFrame{open(1), open(1)}},
		{"decreasing open", []*pb.RawTunnelFrame{open(2), open(1)}},
		{"open beyond max pipes", []*pb.RawTunnelFrame{open(1), open(2), open(3)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var mu sync.Mutex
			var pipes []*Pipe
			p := newPeer(t, Config{Role: RoleConnector, MaxPipes: 2,
				Accept: func(p *Pipe, _ *pb.RawOpen) {
					mu.Lock()
					pipes = append(pipes, p)
					mu.Unlock()
					_ = p.Start(newSilentLocal())
				}}, 64)
			p.send(tc.frames...)
			p.expectFatal()
			eventually(t, "every pipe to be released", func() bool { return slots(p.m) == 0 })
			mu.Lock()
			defer mu.Unlock()
			for _, pipe := range pipes {
				if r := waitDone(t, pipe); r.Reason != protocolError {
					t.Fatalf("pipe ended with %v", r.Reason)
				}
			}
		})
	}
}

// openOnController opens pipe 1 on a controller mux and answers it.
func openOnController(t *testing.T, p *peer) *Pipe {
	t.Helper()
	pipe, err := p.m.Open(testCapability, "db.internal", 5432, passthrough)
	if err != nil {
		t.Fatal(err)
	}
	p.expect(open(1))
	return pipe
}

func TestControllerOpenLifecycle(t *testing.T) {
	p := controllerPeer(t)
	pipe := openOnController(t, p)
	p.send(opened(1))
	if err := pipe.WaitOpened(testContext(t)); err != nil {
		t.Fatal(err)
	}
	if err := pipe.Start(eofLocal()); err != nil {
		t.Fatal(err)
	}
	p.expect(halfClose(1))
	p.send(halfClose(1), closeFrame(1, pb.RawCloseReason_RAW_CLOSE_REASON_COMPLETED))
	wantReason(t, waitDone(t, pipe), pb.RawCloseReason_RAW_CLOSE_REASON_COMPLETED)
	eventually(t, "release", func() bool { return slots(p.m) == 0 })
}

func TestControllerHandlesViolations(t *testing.T) {
	t.Run("data before opened", func(t *testing.T) {
		p := controllerPeer(t)
		pipe := openOnController(t, p)
		p.send(data(1, 1))
		p.expect(reset(1, protocolError))
		var closed *ClosedError
		if err := pipe.WaitOpened(testContext(t)); !errors.As(err, &closed) ||
			closed.Reason != protocolError {
			t.Fatalf("WaitOpened = %v", err)
		}
		if slots(p.m) != 1 {
			t.Fatal("slot released before the connector's close")
		}
		p.send(closeFrame(1, protocolError))
		eventually(t, "release", func() bool { return slots(p.m) == 0 })
	})
	t.Run("duplicate opened", func(t *testing.T) {
		p := controllerPeer(t)
		openOnController(t, p)
		p.send(opened(1), opened(1))
		p.expect(reset(1, protocolError))
	})
	t.Run("open_error after opened", func(t *testing.T) {
		p := controllerPeer(t)
		pipe := openOnController(t, p)
		p.send(opened(1), openError(1,
			pb.RawOpenFailureReason_RAW_OPEN_FAILURE_REASON_DIAL_FAILED, ""))
		p.expectAlive()
		_ = pipe.Start(newSilentLocal())
		wantReason(t, waitDone(t, pipe), protocolError)
		eventually(t, "release", func() bool { return slots(p.m) == 0 })
	})
	t.Run("close before half-close", func(t *testing.T) {
		p := controllerPeer(t)
		pipe := openOnController(t, p)
		p.send(opened(1))
		if err := pipe.WaitOpened(testContext(t)); err != nil {
			t.Fatal(err)
		}
		if err := pipe.Start(newSilentLocal()); err != nil {
			t.Fatal(err)
		}
		p.send(closeFrame(1, pb.RawCloseReason_RAW_CLOSE_REASON_COMPLETED))
		wantReason(t, waitDone(t, pipe), protocolError)
		p.expectAlive()
		eventually(t, "release", func() bool { return slots(p.m) == 0 })
	})
	t.Run("reset while opening", func(t *testing.T) {
		p := controllerPeer(t)
		pipe := openOnController(t, p)
		p.send(reset(1, pb.RawCloseReason_RAW_CLOSE_REASON_CONNECTOR_TERMINATING))
		var closed *ClosedError
		if err := pipe.WaitOpened(testContext(t)); !errors.As(err, &closed) ||
			closed.Reason != pb.RawCloseReason_RAW_CLOSE_REASON_CONNECTOR_TERMINATING {
			t.Fatalf("WaitOpened = %v", err)
		}
		p.send(closeFrame(1, pb.RawCloseReason_RAW_CLOSE_REASON_CONNECTOR_TERMINATING))
		eventually(t, "release", func() bool { return slots(p.m) == 0 })
	})
	for _, tc := range []struct {
		name   string
		frames []*pb.RawTunnelFrame
	}{
		{"open", []*pb.RawTunnelFrame{open(1)}},
		{"frame for unopened pipe", []*pb.RawTunnelFrame{opened(1)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := controllerPeer(t)
			p.send(tc.frames...)
			p.expectFatal()
		})
	}
}

// A pipe reset before its open was sent never reaches the connector.
func TestControllerResetBeforeOpenIsSent(t *testing.T) {
	p := controllerPeer(t)
	// Park the writer in Send so the open stays queued.
	p.send(ping(1, false))
	eventually(t, "the writer to take the ack", func() bool {
		p.m.mu.Lock()
		defer p.m.mu.Unlock()
		return !p.m.pingAckPending
	})
	pipe, err := p.m.Open(testCapability, "db.internal", 5432, passthrough)
	if err != nil {
		t.Fatal(err)
	}
	pipe.Reset(cancelled)
	p.expect(ping(1, true))
	p.expectAlive()
	wantReason(t, waitDone(t, pipe), cancelled)
	eventually(t, "release", func() bool { return slots(p.m) == 0 })
}

func TestControlFramesOvertakeData(t *testing.T) {
	var pipes []*Pipe
	accepted := make(chan struct{}, 3)
	p := newPeer(
		t,
		Config{Role: RoleConnector, MaxPipes: 4, Accept: func(pipe *Pipe, _ *pb.RawOpen) {
			pipes = append(pipes, pipe)
			_ = pipe.Start(newMemLocal(true))
			accepted <- struct{}{}
		}},
		0,
	)
	for id := uint64(1); id <= 3; id++ {
		p.send(open(id))
		<-accepted
	}
	for openedPipes := 0; openedPipes < 3; {
		if p.next().GetOpened() != nil {
			openedPipes++
		}
	}

	// With every pipe saturated, data is sent round-robin.
	seen := map[uint64]int{}
	for range 9 {
		time.Sleep(time.Millisecond)
		f := p.next()
		if f.GetData() == nil {
			t.Fatalf("got %v, want data", f)
		}
		seen[f.GetData().GetPipeId()]++
	}
	for id := uint64(1); id <= 3; id++ {
		if seen[id] < 2 {
			t.Fatalf("pipe %d sent %d of 9 chunks: %v", id, seen[id], seen)
		}
	}

	p.m.Drain(pb.RawDrainReason_RAW_DRAIN_REASON_SHUTDOWN)
	pipes[1].Reset(cancelled)
	dataFrames := 0
	for sawDrain, sawReset := false, false; !sawDrain || !sawReset; {
		f := p.next()
		switch {
		case f.GetData() != nil:
			dataFrames++
		case f.GetDrain() != nil:
			sawDrain = true
		case f.GetPipeReset() != nil:
			sawReset = true
		}
	}
	// Only the chunk already being sent may precede the control frames.
	if dataFrames > 1 {
		t.Fatalf("%d data frames were sent ahead of queued control frames", dataFrames)
	}
}

func TestRetiredFramesCannotLeakAcrossPipes(t *testing.T) {
	p := connectorPeer(t, 4, blockingLocal)
	p.send(open(1))
	p.expect(opened(1))
	p.send(reset(1, cancelled))
	p.expect(closeFrame(1, cancelled))
	p.send(open(2))
	p.expect(opened(2))
	// Credit for the retired pipe must not raise pipe 2's window.
	p.send(window(1, Window))
	p.send(window(2, 1))
	p.expect(reset(2, protocolError), closeFrame(2, protocolError))
}

func TestPingAckOnlyMatchesOutstandingNonce(t *testing.T) {
	p := controllerPeer(t)
	errs := make(chan error, 1)
	go func() { errs <- p.m.Ping(testContext(t)) }()
	f := p.next()
	if f.GetPing() == nil || f.GetPing().GetAck() {
		t.Fatalf("got %v, want ping", f)
	}
	p.send(ping(f.GetPing().GetNonce()+1, true))
	select {
	case err := <-errs:
		t.Fatalf("Ping returned %v on a mismatched ack", err)
	case <-time.After(20 * time.Millisecond):
	}
	p.send(ping(f.GetPing().GetNonce(), true))
	if err := <-errs; err != nil {
		t.Fatal(err)
	}
}

func TestPingAfterCancelledPing(t *testing.T) {
	p := controllerPeer(t)
	ctx, cancel := context.WithCancel(testContext(t))
	errs := make(chan error, 1)
	go func() { errs <- p.m.Ping(ctx) }()
	first := p.next().GetPing().GetNonce()
	cancel()
	if err := <-errs; !errors.Is(err, context.Canceled) {
		t.Fatalf("Ping = %v, want context.Canceled", err)
	}
	p.send(ping(first, true))

	go func() { errs <- p.m.Ping(testContext(t)) }()
	second := p.next().GetPing().GetNonce()
	if second == first {
		t.Fatal("nonce reused")
	}
	p.send(ping(second, true))
	if err := <-errs; err != nil {
		t.Fatal(err)
	}
	p.expectAlive()
}

// blockedMux runs a connector mux whose peer never reads, after opening one
// pipe that streams data, so the mux's writer ends up blocked in Send.
func blockedMux(t *testing.T) (m *Mux, peer, stream *chanStream, pipe *Pipe,
	cancel context.CancelFunc, runErr <-chan error) {
	t.Helper()
	ours, theirs := streamPair(0)
	pipes := make(chan *Pipe, 1)
	m, err := New(Config{
		Role: RoleConnector, MaxPipes: 4, Abort: theirs.abort,
		Accept: func(p *Pipe, _ *pb.RawOpen) {
			_ = p.Start(newMemLocal(true))
			pipes <- p
		},
	}, theirs)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	errs := make(chan error, 1)
	go func() { errs <- m.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		ours.close()
	})
	if err := ours.Send(open(1)); err != nil {
		t.Fatal(err)
	}
	if f, err := ours.Receive(); err != nil || f.GetOpened() == nil {
		t.Fatalf("got %v, %v, want opened", f, err)
	}
	pipe = <-pipes
	// Bytes are counted when the writer takes a chunk, so it is now in Send.
	eventually(t, "the writer to block", func() bool { return pipe.Result().BytesSent > 0 })
	return m, ours, theirs, pipe, cancel, errs
}

func TestTunnelEndsWhileSendIsBlocked(t *testing.T) {
	waitRun := func(t *testing.T, runErr <-chan error, stream *chanStream) error {
		t.Helper()
		select {
		case err := <-runErr:
			// Run waits for Send to return, so a handler can return after it.
			if stream.sending.Load() != 0 {
				t.Fatal("Run returned while Send was in progress")
			}
			return err
		case <-time.After(waitTimeout):
			t.Fatal("Run did not return while Send was blocked")
			return nil
		}
	}
	t.Run("protocol error", func(t *testing.T) {
		_, peer, stream, pipe, _, runErr := blockedMux(t)
		if err := peer.Send(&pb.RawTunnelFrame{}); err != nil {
			t.Fatal(err)
		}
		var perr *ProtocolError
		if err := waitRun(t, runErr, stream); !errors.As(err, &perr) {
			t.Fatalf("Run = %v, want a protocol error", err)
		}
		wantReason(t, waitDone(t, pipe), protocolError)
	})
	t.Run("context cancelled", func(t *testing.T) {
		_, _, stream, pipe, cancel, runErr := blockedMux(t)
		cancel()
		if err := waitRun(t, runErr, stream); !errors.Is(err, context.Canceled) {
			t.Fatalf("Run = %v, want context.Canceled", err)
		}
		wantReason(t, waitDone(t, pipe), pb.RawCloseReason_RAW_CLOSE_REASON_TUNNEL_LOST)
	})
	t.Run("close", func(t *testing.T) {
		m, _, stream, pipe, cancel, runErr := blockedMux(t)
		m.Close(pb.RawCloseReason_RAW_CLOSE_REASON_CONNECTOR_TERMINATING)
		wantReason(t, waitDone(t, pipe), pb.RawCloseReason_RAW_CLOSE_REASON_CONNECTOR_TERMINATING)
		// The flush cannot finish while the peer is not reading; ctx bounds it.
		select {
		case err := <-runErr:
			t.Fatalf("Run = %v before the close was flushed", err)
		case <-time.After(20 * time.Millisecond):
		}
		cancel()
		if err := waitRun(t, runErr, stream); !errors.Is(err, context.Canceled) {
			t.Fatalf("Run = %v, want context.Canceled", err)
		}
	})
}

// A controller's drain must not overtake an open queued before it: the
// connector treats an open after the drain as a protocol error.
func TestControllerDrainFollowsQueuedOpen(t *testing.T) {
	p := controllerPeer(t)
	p.send(ping(1, false))
	eventually(t, "the writer to take the ack", func() bool {
		p.m.mu.Lock()
		defer p.m.mu.Unlock()
		return !p.m.pingAckPending
	})
	if _, err := p.m.Open(testCapability, "db.internal", 5432, passthrough); err != nil {
		t.Fatal(err)
	}
	p.m.Drain(pb.RawDrainReason_RAW_DRAIN_REASON_ROTATION)
	p.expect(ping(1, true), open(1), drain(pb.RawDrainReason_RAW_DRAIN_REASON_ROTATION))
}

func TestControllerDrainAfterUnsentOpenIsReset(t *testing.T) {
	p := controllerPeer(t)
	p.send(ping(1, false))
	eventually(t, "the writer to take the ack", func() bool {
		p.m.mu.Lock()
		defer p.m.mu.Unlock()
		return !p.m.pingAckPending
	})
	pipe, err := p.m.Open(testCapability, "db.internal", 5432, passthrough)
	if err != nil {
		t.Fatal(err)
	}
	p.m.Drain(pb.RawDrainReason_RAW_DRAIN_REASON_ROTATION)
	pipe.Reset(cancelled)
	p.expect(ping(1, true), drain(pb.RawDrainReason_RAW_DRAIN_REASON_ROTATION))
	waitClosed(t, p.m.Drained(), "drained")
	p.expectAlive()
}

// A frame for a pipe whose open is still queued cannot be a late frame for a
// retired pipe: the peer has never heard of it.
func TestControllerRejectsFramesBeforeOpenIsSent(t *testing.T) {
	p := controllerPeer(t)
	p.send(ping(1, false))
	eventually(t, "the writer to take the ack", func() bool {
		p.m.mu.Lock()
		defer p.m.mu.Unlock()
		return !p.m.pingAckPending
	})
	pipe, err := p.m.Open(testCapability, "db.internal", 5432, passthrough)
	if err != nil {
		t.Fatal(err)
	}
	p.send(opened(1))
	p.expectFatal()
	var closed *ClosedError
	if err := pipe.WaitOpened(testContext(t)); !errors.As(err, &closed) ||
		closed.Reason != protocolError {
		t.Fatalf("WaitOpened = %v", err)
	}
}

// lastChunkLocal returns its only bytes together with io.EOF.
type lastChunkLocal struct {
	*silentLocal
	done bool
}

func (l *lastChunkLocal) Read(b []byte) (int, error) {
	if l.done {
		return 0, io.EOF
	}
	l.done = true
	return copy(b, "hello"), io.EOF
}

func TestConnectorSendsFinalBytesBeforeHalfClose(t *testing.T) {
	pipes := make(chan *Pipe, 1)
	p := newPeer(
		t,
		Config{Role: RoleConnector, MaxPipes: 4, Accept: func(pipe *Pipe, _ *pb.RawOpen) {
			_ = pipe.Start(&lastChunkLocal{silentLocal: newSilentLocal()})
			pipes <- pipe
		}},
		0,
	)
	p.send(open(1))
	p.expect(opened(1), frame(&pb.RawData{PipeId: 1, Payload: []byte("hello")}), halfClose(1))
	p.send(halfClose(1))
	p.expect(closeFrame(1, pb.RawCloseReason_RAW_CLOSE_REASON_COMPLETED))
	r := waitDone(t, <-pipes)
	if r.BytesSent != 5 || r.BytesReceived != 0 {
		t.Fatalf("result = %+v", r)
	}
}

func TestResultIsFinalOnceDone(t *testing.T) {
	pipes := make(chan *Pipe, 1)
	p := newPeer(
		t,
		Config{Role: RoleConnector, MaxPipes: 4, Accept: func(pipe *Pipe, _ *pb.RawOpen) {
			_ = pipe.Start(newMemLocal(true))
			pipes <- pipe
		}},
		0,
	)
	p.send(open(1))
	p.expect(opened(1))
	pipe := <-pipes
	sent := 0
	for range 3 {
		sent += len(p.next().GetData().GetPayload())
	}
	p.send(reset(1, cancelled))
	for {
		f := p.next()
		if f.GetClose() != nil {
			break
		}
		sent += len(f.GetData().GetPayload())
	}
	r := waitDone(t, pipe)
	p.expectAlive()
	if r != pipe.Result() || r.BytesSent != int64(sent) {
		t.Fatalf("result %+v changed to %+v after Done; peer received %d bytes",
			r, pipe.Result(), sent)
	}
}

func TestControllerClose(t *testing.T) {
	for _, tc := range []struct {
		name       string
		reason     pb.RawCloseReason
		wantReason pb.RawCloseReason
	}{
		{"valid reason", pb.RawCloseReason_RAW_CLOSE_REASON_CONTROLLER_TERMINATING,
			pb.RawCloseReason_RAW_CLOSE_REASON_CONTROLLER_TERMINATING},
		{"unspecified reason", pb.RawCloseReason_RAW_CLOSE_REASON_UNSPECIFIED, protocolError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := controllerPeer(t)
			pipe := openOnController(t, p)
			p.send(opened(1))
			if err := pipe.WaitOpened(testContext(t)); err != nil {
				t.Fatal(err)
			}
			if err := pipe.Start(newSilentLocal()); err != nil {
				t.Fatal(err)
			}
			p.m.Close(tc.reason)
			p.expect(reset(1, tc.wantReason))
			if err := <-p.runErr; !errors.Is(err, ErrClosed) {
				t.Fatalf("Run = %v, want ErrClosed", err)
			}
			wantReason(t, waitDone(t, pipe), tc.wantReason)
		})
	}
}

func TestTunnelLossWhileAcceptIsPending(t *testing.T) {
	pipes := make(chan *Pipe, 1)
	started := make(chan error, 1)
	p := newPeer(
		t,
		Config{Role: RoleConnector, MaxPipes: 4, Accept: func(pipe *Pipe, _ *pb.RawOpen) {
			pipes <- pipe
			<-pipe.Context().Done()
			started <- pipe.Start(newSilentLocal())
		}},
		0,
	)
	p.send(open(1))
	pipe := <-pipes
	p.s.close()
	if err := <-started; !errors.Is(err, ErrPipeClosed) {
		t.Fatalf("Start = %v, want ErrPipeClosed", err)
	}
	wantReason(t, waitDone(t, pipe), pb.RawCloseReason_RAW_CLOSE_REASON_TUNNEL_LOST)
	eventually(t, "release", func() bool { return slots(p.m) == 0 })
}

func TestStartAndRefuseResolveOnce(t *testing.T) {
	t.Run("connector", func(t *testing.T) {
		errs := make(chan error, 2)
		p := newPeer(
			t,
			Config{Role: RoleConnector, MaxPipes: 4, Accept: func(pipe *Pipe, _ *pb.RawOpen) {
				_ = pipe.Start(newSilentLocal())
				errs <- pipe.Start(newSilentLocal())
				errs <- pipe.Refuse(pb.RawOpenFailureReason_RAW_OPEN_FAILURE_REASON_DIAL_FAILED, "")
			}},
			0,
		)
		p.send(open(1))
		p.expect(opened(1))
		for range 2 {
			if err := <-errs; err == nil {
				t.Fatal("second resolution succeeded")
			}
		}
		p.expectAlive()
	})
	t.Run("controller start before opened", func(t *testing.T) {
		p := controllerPeer(t)
		pipe := openOnController(t, p)
		early := newSilentLocal()
		if err := pipe.Start(early); err == nil {
			t.Fatal("Start succeeded before the pipe opened")
		}
		early.waitClosed(t)
		if err := pipe.Refuse(pb.RawOpenFailureReason_RAW_OPEN_FAILURE_REASON_DIAL_FAILED,
			""); err == nil {
			t.Fatal("controller refused a pipe")
		}
		p.send(opened(1))
		if err := pipe.WaitOpened(testContext(t)); err != nil {
			t.Fatal(err)
		}
		if err := pipe.Start(eofLocal()); err != nil {
			t.Fatalf("Start after opened = %v", err)
		}
		p.expect(halfClose(1))
		if err := pipe.Start(newSilentLocal()); err == nil {
			t.Fatal("second Start succeeded")
		}
	})
}

func TestControllerResetsPipeOnCreditViolation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		frames []*pb.RawTunnelFrame
	}{
		{"data beyond credit", append(fill(Window), data(1, 1))},
		{"credit beyond window", []*pb.RawTunnelFrame{window(1, 1)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := controllerPeer(t)
			pipe := openOnController(t, p)
			p.send(opened(1))
			if err := pipe.WaitOpened(testContext(t)); err != nil {
				t.Fatal(err)
			}
			if err := pipe.Start(blockingLocal()); err != nil {
				t.Fatal(err)
			}
			p.send(tc.frames...)
			p.expect(reset(1, protocolError))
			wantReason(t, waitDone(t, pipe), protocolError)
		})
	}
}

type eofReader struct{ *memLocal }

func (eofReader) Read([]byte) (int, error) { return 0, io.EOF }

func eofLocal() Local { return eofReader{newMemLocal(true)} }
