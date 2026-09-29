package rawtunnel

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"math/rand/v2"
	"net"
	"sync"
	"testing"
	"time"

	pb "github.com/InteractionLabs/traversal-connector/connector-lib/gen/connector/v1"
)

var (
	callerSeed   = [32]byte{1}
	upstreamSeed = [32]byte{2}
)

func stream(seed [32]byte, size int64) io.Reader {
	return io.LimitReader(rand.NewChaCha8(seed), size)
}

func streamHash(seed [32]byte, size int64) [32]byte {
	h := sha256.New()
	_, _ = io.Copy(h, stream(seed, size))
	return [32]byte(h.Sum(nil))
}

// hashServer streams size bytes to each client while hashing everything the
// client sends, then appends that hash once the client half-closes.
func hashServer(size int64) func(*net.TCPConn) {
	return func(c *net.TCPConn) {
		sum := make(chan []byte, 1)
		go func() {
			h := sha256.New()
			_, _ = io.Copy(h, c)
			sum <- h.Sum(nil)
		}()
		if _, err := io.Copy(c, stream(upstreamSeed, size)); err != nil {
			return
		}
		_, _ = c.Write(<-sum)
		_ = c.CloseWrite()
	}
}

// transfer sends size bytes each way through a new pipe and verifies both
// directions byte for byte.
func transfer(t *testing.T, ctrl *Mux, addr string, size int64) *Pipe {
	t.Helper()
	p, caller := openPipe(t, ctrl, addr)
	writeErr := make(chan error, 1)
	go func() {
		_, err := io.Copy(caller, stream(callerSeed, size))
		if err == nil {
			err = caller.CloseWrite()
		}
		writeErr <- err
	}()
	h := sha256.New()
	if _, err := io.CopyN(h, caller, size); err != nil {
		t.Errorf("reading upstream stream: %v", err)
		return p
	}
	upstreamSum, err := io.ReadAll(caller)
	if err != nil {
		t.Errorf("reading upstream hash: %v", err)
		return p
	}
	if err := <-writeErr; err != nil {
		t.Errorf("writing caller stream: %v", err)
	}
	if got, want := [32]byte(h.Sum(nil)), streamHash(upstreamSeed, size); got != want {
		t.Errorf("upstream-to-caller bytes corrupted")
	}
	if want := streamHash(callerSeed, size); !bytes.Equal(upstreamSum, want[:]) {
		t.Errorf("caller-to-upstream bytes corrupted")
	}
	return p
}

func TestBidirectionalTransferIntegrity(t *testing.T) {
	const size = 32 << 20
	tun := startTunnel(t, Config{}, Config{})
	addr := serve(t, hashServer(size))

	p := transfer(t, tun.ctrl, addr, size)
	got := waitDone(t, p)
	wantReason(t, got, pb.RawCloseReason_RAW_CLOSE_REASON_COMPLETED)
	if got.BytesSent != size || got.BytesReceived != size+sha256.Size {
		t.Fatalf("result = %+v, want %d bytes sent and %d received", got, size, size+sha256.Size)
	}
	eventually(t, "both sides to release the pipe", func() bool {
		return slots(tun.ctrl) == 0 && slots(tun.conn) == 0
	})
}

func TestConcurrentPipesStayIndependent(t *testing.T) {
	const pipes, size = 12, 2 << 20
	tun := startTunnel(t, Config{MaxPipes: pipes}, Config{})
	addr := serve(t, hashServer(size))

	var wg sync.WaitGroup
	for range pipes {
		wg.Go(func() {
			p := transfer(t, tun.ctrl, addr, size)
			wantReason(t, waitDone(t, p), pb.RawCloseReason_RAW_CLOSE_REASON_COMPLETED)
		})
	}
	wg.Wait()
	eventually(t, "every pipe to be released", func() bool {
		return slots(tun.ctrl) == 0 && slots(tun.conn) == 0
	})
}

func TestCallerHalfCloseLeavesUpstreamDirectionOpen(t *testing.T) {
	tun := startTunnel(t, Config{}, Config{})
	addr := serve(t, func(c *net.TCPConn) {
		got, _ := io.ReadAll(c)
		_, _ = c.Write(append([]byte("after eof: "), got...))
		_ = c.CloseWrite()
	})

	p, caller := openPipe(t, tun.ctrl, addr)
	_, _ = caller.Write([]byte("request"))
	_ = caller.CloseWrite()
	reply, err := io.ReadAll(caller)
	if err != nil || string(reply) != "after eof: request" {
		t.Fatalf("reply = %q, %v", reply, err)
	}
	wantReason(t, waitDone(t, p), pb.RawCloseReason_RAW_CLOSE_REASON_COMPLETED)
}

func TestUpstreamHalfCloseLeavesCallerDirectionOpen(t *testing.T) {
	tun := startTunnel(t, Config{}, Config{})
	late := make(chan []byte, 1)
	addr := serve(t, func(c *net.TCPConn) {
		_, _ = c.Write([]byte("banner"))
		_ = c.CloseWrite()
		got, _ := io.ReadAll(c)
		late <- got
	})

	p, caller := openPipe(t, tun.ctrl, addr)
	banner, err := io.ReadAll(caller)
	if err != nil || string(banner) != "banner" {
		t.Fatalf("banner = %q, %v", banner, err)
	}
	_, _ = caller.Write([]byte("sent after upstream eof"))
	_ = caller.CloseWrite()
	if got := <-late; string(got) != "sent after upstream eof" {
		t.Fatalf("upstream received %q", got)
	}
	wantReason(t, waitDone(t, p), pb.RawCloseReason_RAW_CLOSE_REASON_COMPLETED)
}

func TestStalledPipeDoesNotBlockOthers(t *testing.T) {
	tun := startTunnel(t, Config{}, Config{})
	flood := serve(t, func(c *net.TCPConn) {
		_, _ = io.Copy(c, rand.NewChaCha8(upstreamSeed))
	})
	echoAddr := serve(t, echo)

	// Nobody reads the stalled pipe, so its window and socket buffers fill.
	stalled, _ := openPipe(t, tun.ctrl, flood)
	time.Sleep(100 * time.Millisecond)

	const size = 4 << 20
	p, caller := openPipe(t, tun.ctrl, echoAddr)
	go func() {
		_, _ = io.Copy(caller, stream(callerSeed, size))
		_ = caller.CloseWrite()
	}()
	h := sha256.New()
	if n, err := io.Copy(h, caller); err != nil || n != size {
		t.Fatalf("echoed %d bytes, %v", n, err)
	}
	if [32]byte(h.Sum(nil)) != streamHash(callerSeed, size) {
		t.Fatal("echo corrupted")
	}
	wantReason(t, waitDone(t, p), pb.RawCloseReason_RAW_CLOSE_REASON_COMPLETED)

	stalled.Reset(pb.RawCloseReason_RAW_CLOSE_REASON_CANCELLED)
	wantReason(t, waitDone(t, stalled), pb.RawCloseReason_RAW_CLOSE_REASON_CANCELLED)
}

// A receiver that never consumes must stop the sender from reading its Local
// once one window is outstanding, and hold no more than one window itself.
func TestSenderReadsNoMoreThanPeerCredit(t *testing.T) {
	for _, tc := range []struct {
		name         string
		sourceIsConn bool
	}{
		{name: "connector to controller", sourceIsConn: true},
		{name: "controller to connector"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			connLocal := newMemLocal(false)
			ctrlLocal := newMemLocal(false)
			source := ctrlLocal
			if tc.sourceIsConn {
				source = connLocal
			}
			var connPipe *Pipe
			accepted := make(chan struct{})
			tun := startTunnel(t, Config{}, Config{Accept: func(p *Pipe, _ *pb.RawOpen) {
				connPipe = p
				close(accepted)
				_ = p.Start(connLocal)
			}})
			p := openOnly(t, tun.ctrl, "127.0.0.1:1")
			if err := p.WaitOpened(testContext(t)); err != nil {
				t.Fatal(err)
			}
			<-accepted
			if err := p.Start(ctrlLocal); err != nil {
				t.Fatal(err)
			}
			sinkPipe, sinkMux := p, tun.ctrl
			if !tc.sourceIsConn {
				sinkPipe, sinkMux = connPipe, tun.conn
			}

			eventually(t, "the sender to exhaust its credit", func() bool {
				return source.bytesRead() == Window
			})
			time.Sleep(50 * time.Millisecond)
			if got := source.bytesRead(); got != Window {
				t.Fatalf("sender read %d bytes, want exactly %d", got, Window)
			}
			sinkMux.mu.Lock()
			buffered, blocks := sinkPipe.recv.size, len(sinkPipe.recv.blocks)
			sinkMux.mu.Unlock()
			if buffered != Window || blocks > Window/MaxDataBytes {
				t.Fatalf("receiver buffered %d bytes in %d blocks", buffered, blocks)
			}
			p.Reset(pb.RawCloseReason_RAW_CLOSE_REASON_CANCELLED)
			connLocal.waitClosed(t)
			ctrlLocal.waitClosed(t)
		})
	}
}

func TestControllerResetClosesUpstream(t *testing.T) {
	tun := startTunnel(t, Config{}, Config{})
	upstreamEOF := make(chan struct{})
	addr := serve(t, func(c *net.TCPConn) {
		_, _ = io.Copy(io.Discard, c)
		close(upstreamEOF)
	})

	p, caller := openPipe(t, tun.ctrl, addr)
	p.Reset(pb.RawCloseReason_RAW_CLOSE_REASON_CANCELLED)
	waitClosed(t, upstreamEOF, "upstream close")
	wantReason(t, waitDone(t, p), pb.RawCloseReason_RAW_CLOSE_REASON_CANCELLED)
	if _, err := io.ReadAll(caller); err != nil {
		t.Fatalf("caller read after reset: %v", err)
	}
	eventually(t, "the connector's close", func() bool {
		return slots(tun.ctrl) == 0 && slots(tun.conn) == 0
	})
}

func TestUpstreamFailureResetsCaller(t *testing.T) {
	tun := startTunnel(t, Config{}, Config{})
	addr := serve(t, func(c *net.TCPConn) {
		_ = c.SetLinger(0)
		_, _ = c.Read(make([]byte, 1))
	})

	p, caller := openPipe(t, tun.ctrl, addr)
	_, _ = caller.Write([]byte("x"))
	wantReason(t, waitDone(t, p), pb.RawCloseReason_RAW_CLOSE_REASON_UPSTREAM_ERROR)
}

func TestCallerFailureResetsUpstream(t *testing.T) {
	var connPipe *Pipe
	started := make(chan struct{})
	tun := startTunnel(t, Config{}, Config{Accept: func(p *Pipe, open *pb.RawOpen) {
		connPipe = p
		dialAccept(p, open)
		close(started)
	}})
	addr := serve(t, func(c *net.TCPConn) { _, _ = io.Copy(io.Discard, c) })

	p, caller := openPipe(t, tun.ctrl, addr)
	<-started
	_ = caller.SetLinger(0)
	_ = caller.Close()
	wantReason(t, waitDone(t, p), pb.RawCloseReason_RAW_CLOSE_REASON_CANCELLED)
	wantReason(t, waitDone(t, connPipe), pb.RawCloseReason_RAW_CLOSE_REASON_CANCELLED)
}

func TestResetWhileOpeningCancelsDial(t *testing.T) {
	startErr := make(chan error, 1)
	tun := startTunnel(t, Config{}, Config{Accept: func(p *Pipe, _ *pb.RawOpen) {
		<-p.Context().Done()
		startErr <- p.Start(newMemLocal(true))
	}})

	p := openOnly(t, tun.ctrl, "127.0.0.1:1")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := p.WaitOpened(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("WaitOpened = %v, want deadline", err)
	}
	p.Reset(pb.RawCloseReason_RAW_CLOSE_REASON_CANCELLED)
	var closed *ClosedError
	if err := p.WaitOpened(testContext(t)); !errors.As(err, &closed) ||
		closed.Reason != pb.RawCloseReason_RAW_CLOSE_REASON_CANCELLED {
		t.Fatalf("WaitOpened after reset = %v", err)
	}
	if err := <-startErr; !errors.Is(err, ErrPipeClosed) {
		t.Fatalf("Start after reset = %v", err)
	}
	eventually(t, "the connector's close", func() bool {
		return slots(tun.ctrl) == 0 && slots(tun.conn) == 0
	})
}

func TestRefusalReachesController(t *testing.T) {
	tun := startTunnel(t, Config{}, Config{Accept: func(p *Pipe, _ *pb.RawOpen) {
		_ = p.Refuse(pb.RawOpenFailureReason_RAW_OPEN_FAILURE_REASON_FORBIDDEN_ADDRESS,
			"loopback")
	}})

	p := openOnly(t, tun.ctrl, "127.0.0.1:1")
	var refused *OpenError
	if err := p.WaitOpened(testContext(t)); !errors.As(err, &refused) ||
		refused.Reason != pb.RawOpenFailureReason_RAW_OPEN_FAILURE_REASON_FORBIDDEN_ADDRESS ||
		refused.Detail != "loopback" {
		t.Fatalf("WaitOpened = %v", err)
	}
	if err := p.Start(newMemLocal(true)); err == nil {
		t.Fatal("Start succeeded on a refused pipe")
	}
	eventually(t, "the refusal to release both sides", func() bool {
		return slots(tun.ctrl) == 0 && slots(tun.conn) == 0
	})
}

func TestIdleTimeout(t *testing.T) {
	tun := startTunnel(t, Config{}, Config{IdleTimeout: 150 * time.Millisecond})
	addr := serve(t, echo)

	p, caller := openPipe(t, tun.ctrl, addr)
	buf := make([]byte, 1)
	for range 8 {
		time.Sleep(50 * time.Millisecond)
		if _, err := caller.Write(buf); err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadFull(caller, buf); err != nil {
			t.Fatalf("pipe idled out while active: %v", err)
		}
	}
	wantReason(t, waitDone(t, p), pb.RawCloseReason_RAW_CLOSE_REASON_IDLE_TIMEOUT)
}

func TestMaxLifetime(t *testing.T) {
	tun := startTunnel(t, Config{MaxLifetime: 100 * time.Millisecond}, Config{})
	addr := serve(t, echo)

	p, _ := openPipe(t, tun.ctrl, addr)
	wantReason(t, waitDone(t, p), pb.RawCloseReason_RAW_CLOSE_REASON_MAX_LIFETIME)
	eventually(t, "the connector's close", func() bool { return slots(tun.ctrl) == 0 })
}

func TestTunnelLossEndsEveryPipe(t *testing.T) {
	block := make(chan struct{})
	defer close(block)
	tun := startTunnel(t, Config{}, Config{Accept: func(p *Pipe, open *pb.RawOpen) {
		if open.GetPort() == 1 {
			<-block
			_ = p.Refuse(pb.RawOpenFailureReason_RAW_OPEN_FAILURE_REASON_DIAL_FAILED, "")
			return
		}
		dialAccept(p, open)
	}})
	addr := serve(t, echo)

	first, caller := openPipe(t, tun.ctrl, addr)
	second, _ := openPipe(t, tun.ctrl, addr)
	opening := openOnly(t, tun.ctrl, "127.0.0.1:1")
	tun.stream.close()

	for _, p := range []*Pipe{first, second} {
		wantReason(t, waitDone(t, p), pb.RawCloseReason_RAW_CLOSE_REASON_TUNNEL_LOST)
	}
	var closed *ClosedError
	if err := opening.WaitOpened(testContext(t)); !errors.As(err, &closed) ||
		closed.Reason != pb.RawCloseReason_RAW_CLOSE_REASON_TUNNEL_LOST {
		t.Fatalf("opening pipe: %v", err)
	}
	if _, err := io.ReadAll(caller); err != nil {
		t.Fatalf("caller read after tunnel loss: %v", err)
	}
	if err := <-tun.ctrlErr; err == nil || errors.Is(err, ErrClosed) {
		t.Fatalf("Run = %v, want a stream error", err)
	}
	if _, err := tun.ctrl.Open(testCapability, "h", 1, passthrough); !errors.Is(err, ErrClosed) {
		t.Fatalf("Open after loss = %v", err)
	}
	if err := tun.ctrl.Ping(testContext(t)); !errors.Is(err, ErrClosed) {
		t.Fatalf("Ping after loss = %v", err)
	}
	if slots(tun.ctrl) != 0 {
		t.Fatal("pipes still hold slots after tunnel loss")
	}
}

func TestCloseTerminatesPipesAndFlushesCloses(t *testing.T) {
	tun := startTunnel(t, Config{}, Config{})
	addr := serve(t, echo)

	first, _ := openPipe(t, tun.ctrl, addr)
	second, _ := openPipe(t, tun.ctrl, addr)
	tun.conn.Close(pb.RawCloseReason_RAW_CLOSE_REASON_CONNECTOR_TERMINATING)

	if err := <-tun.connErr; !errors.Is(err, ErrClosed) {
		t.Fatalf("connector Run = %v, want ErrClosed", err)
	}
	for _, p := range []*Pipe{first, second} {
		wantReason(t, waitDone(t, p),
			pb.RawCloseReason_RAW_CLOSE_REASON_CONNECTOR_TERMINATING)
	}
}

func TestDrainStopsNewPipesOnly(t *testing.T) {
	tun := startTunnel(t, Config{}, Config{})
	addr := serve(t, echo)

	p, caller := openPipe(t, tun.ctrl, addr)
	tun.ctrl.Drain(pb.RawDrainReason_RAW_DRAIN_REASON_ROTATION)
	waitClosed(t, tun.ctrl.Draining(), "controller draining")
	waitClosed(t, tun.conn.Draining(), "connector draining")
	if _, err := tun.ctrl.Open(testCapability, "h", 1, passthrough); !errors.Is(err, ErrDraining) {
		t.Fatalf("Open while draining = %v", err)
	}
	select {
	case <-tun.ctrl.Drained():
		t.Fatal("drained with a pipe still open")
	default:
	}

	_, _ = caller.Write([]byte("still flowing"))
	_ = caller.CloseWrite()
	if got, err := io.ReadAll(caller); err != nil || string(got) != "still flowing" {
		t.Fatalf("echo while draining = %q, %v", got, err)
	}
	wantReason(t, waitDone(t, p), pb.RawCloseReason_RAW_CLOSE_REASON_COMPLETED)
	waitClosed(t, tun.ctrl.Drained(), "controller drained")
	waitClosed(t, tun.conn.Drained(), "connector drained")
}

func TestConnectorDrainStopsControllerOpens(t *testing.T) {
	tun := startTunnel(t, Config{}, Config{})
	tun.conn.Drain(pb.RawDrainReason_RAW_DRAIN_REASON_SHUTDOWN)
	waitClosed(t, tun.ctrl.Drained(), "controller drained")
	if _, err := tun.ctrl.Open(testCapability, "h", 1, passthrough); !errors.Is(err, ErrDraining) {
		t.Fatalf("Open after connector drain = %v", err)
	}
}

func TestPingBothWays(t *testing.T) {
	tun := startTunnel(t, Config{}, Config{})
	for _, m := range []*Mux{tun.ctrl, tun.conn, tun.ctrl} {
		if err := m.Ping(testContext(t)); err != nil {
			t.Fatal(err)
		}
	}
}

func TestCapacityIsReleasedByClose(t *testing.T) {
	tun := startTunnel(t, Config{MaxPipes: 2}, Config{})
	addr := serve(t, func(c *net.TCPConn) { _, _ = io.Copy(io.Discard, c) })

	first, _ := openPipe(t, tun.ctrl, addr)
	openPipe(t, tun.ctrl, addr)
	if _, err := tun.ctrl.Open(testCapability, "h", 1, passthrough); !errors.Is(err, ErrCapacity) {
		t.Fatalf("Open over capacity = %v", err)
	}
	first.Reset(pb.RawCloseReason_RAW_CLOSE_REASON_CANCELLED)
	eventually(t, "the slot to free", func() bool { return slots(tun.ctrl) == 1 })
	openPipe(t, tun.ctrl, addr)
}

func TestNewRejectsInvalidConfig(t *testing.T) {
	accept := func(*Pipe, *pb.RawOpen) {}
	abort := func() {}
	for _, cfg := range []Config{
		{MaxPipes: 1},
		{Role: RoleController},
		{Role: RoleConnector, MaxPipes: 1},
		{Role: RoleController, MaxPipes: 1, Accept: accept},
		{Role: RoleController, MaxPipes: 1, IdleTimeout: -1},
		{Role: RoleController, MaxPipes: 1, Abort: abort, PingInterval: -1},
		{Role: RoleController, MaxPipes: 1, Abort: abort, PingTimeout: -1},
		{Role: RoleController, MaxPipes: 1},
	} {
		if _, err := New(cfg, nil); err == nil {
			t.Errorf("New(%+v) succeeded", cfg)
		}
	}
}

func TestOpenRejectsInvalidRequests(t *testing.T) {
	tun := startTunnel(t, Config{}, Config{})
	for _, tc := range []struct {
		capability, host string
		port             uint32
	}{
		{capability: "", host: "h", port: 1},
		{capability: "c", host: "", port: 1},
		{capability: "c", host: "h", port: 0},
		{capability: "c", host: "h\xff", port: 1},
	} {
		if _, err := tun.ctrl.Open(tc.capability, tc.host, tc.port, passthrough); err == nil {
			t.Errorf("Open(%+v) succeeded", tc)
		}
	}
	if _, err := tun.conn.Open(testCapability, "h", 1, passthrough); err == nil {
		t.Error("connector Open succeeded")
	}
}
