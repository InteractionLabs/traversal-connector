package rawtunnel

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	pb "github.com/InteractionLabs/traversal-connector/connector-lib/gen/connector/v1"
)

const (
	testCapability = "test-capability"
	waitTimeout    = 10 * time.Second
	passthrough    = pb.RawPipeMode_RAW_PIPE_MODE_PASSTHROUGH
)

// TestMain fails the run if goroutines running this package's code outlive
// the tests, since every pipe and tunnel must stop its goroutines when it ends.
func TestMain(m *testing.M) {
	code := m.Run()
	deadline := time.Now().Add(waitTimeout)
	for code == 0 {
		leaked := leakedGoroutines()
		if len(leaked) == 0 {
			break
		}
		if time.Now().After(deadline) {
			fmt.Fprintf(os.Stderr, "leaked goroutines:\n\n%s\n", strings.Join(leaked, "\n\n"))
			code = 1
		}
		time.Sleep(10 * time.Millisecond)
	}
	os.Exit(code)
}

func leakedGoroutines() []string {
	buf := make([]byte, 1<<20)
	stacks := strings.Split(string(buf[:runtime.Stack(buf, true)]), "\n\n")
	var leaked []string
	for _, s := range stacks {
		if strings.Contains(s, "/connector-lib/rawtunnel.") &&
			!strings.Contains(s, "rawtunnel.TestMain") {
			leaked = append(leaked, s)
		}
	}
	return leaked
}

// chanStream is one end of an in-memory frame stream. Sent frames are cloned so
// the receiver never aliases the sender's buffers, as on a real transport.
type chanStream struct {
	in        <-chan *pb.RawTunnelFrame
	out       chan<- *pb.RawTunnelFrame
	closed    chan struct{}
	once      *sync.Once
	aborted   chan struct{}
	abortOnce sync.Once
	sending   atomic.Int32
}

// streamPair returns connected stream ends. buffer frames can be in flight in
// each direction before Send blocks.
func streamPair(buffer int) (*chanStream, *chanStream) {
	ab := make(chan *pb.RawTunnelFrame, buffer)
	ba := make(chan *pb.RawTunnelFrame, buffer)
	closed := make(chan struct{})
	once := new(sync.Once)
	return &chanStream{in: ba, out: ab, closed: closed, once: once, aborted: make(chan struct{})},
		&chanStream{in: ab, out: ba, closed: closed, once: once, aborted: make(chan struct{})}
}

func (s *chanStream) Send(f *pb.RawTunnelFrame) error {
	s.sending.Add(1)
	defer s.sending.Add(-1)
	clone := proto.Clone(f).(*pb.RawTunnelFrame)
	select {
	case <-s.closed:
		return io.ErrClosedPipe
	case <-s.aborted:
		return io.ErrClosedPipe
	default:
	}
	select {
	case s.out <- clone:
		return nil
	case <-s.closed:
		return io.ErrClosedPipe
	case <-s.aborted:
		return io.ErrClosedPipe
	}
}

// Receive delivers every frame sent before the stream closed, like a real
// stream, and only then reports EOF.
func (s *chanStream) Receive() (*pb.RawTunnelFrame, error) {
	select {
	case f := <-s.in:
		return f, nil
	case <-s.aborted:
		return nil, io.ErrClosedPipe
	case <-s.closed:
		select {
		case f := <-s.in:
			return f, nil
		default:
			return nil, io.EOF
		}
	}
}

func (s *chanStream) close() {
	s.once.Do(func() { close(s.closed) })
}

// abort fails this end's Send and Receive without closing the peer's end.
func (s *chanStream) abort() {
	s.abortOnce.Do(func() { close(s.aborted) })
}

// runMux runs m until the test ends and reports Run's result on the returned
// channel.
func runMux(t *testing.T, m *Mux, s *chanStream) <-chan error {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		err := m.Run(ctx)
		s.close()
		result <- err
	}()
	t.Cleanup(func() {
		cancel()
		s.close()
		select {
		case <-m.Done():
		case <-time.After(waitTimeout):
			t.Error("mux did not stop")
		}
	})
	return result
}

type tunnel struct {
	ctrl, conn       *Mux
	ctrlErr, connErr <-chan error
	stream           *chanStream
}

// startTunnel runs a controller and a connector Mux against each other.
// Unset MaxPipes and Accept default to 16 and dialAccept.
func startTunnel(t *testing.T, ctrlCfg, connCfg Config) *tunnel {
	t.Helper()
	ctrlCfg.Role, connCfg.Role = RoleController, RoleConnector
	if ctrlCfg.MaxPipes == 0 {
		ctrlCfg.MaxPipes = 16
	}
	if connCfg.MaxPipes == 0 {
		connCfg.MaxPipes = ctrlCfg.MaxPipes
	}
	if connCfg.Accept == nil {
		connCfg.Accept = dialAccept
	}
	a, b := streamPair(8)
	ctrlCfg.Abort, connCfg.Abort = a.abort, b.abort
	ctrl, err := New(ctrlCfg, a)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := New(connCfg, b)
	if err != nil {
		t.Fatal(err)
	}
	return &tunnel{
		ctrl:    ctrl,
		conn:    conn,
		ctrlErr: runMux(t, ctrl, a),
		connErr: runMux(t, conn, b),
		stream:  a,
	}
}

// dialAccept connects every pipe to the TCP address it names.
func dialAccept(p *Pipe, open *pb.RawOpen) {
	var d net.Dialer
	addr := net.JoinHostPort(open.GetHost(), strconv.FormatUint(uint64(open.GetPort()), 10))
	c, err := d.DialContext(p.Context(), "tcp", addr)
	if err != nil {
		_ = p.Refuse(pb.RawOpenFailureReason_RAW_OPEN_FAILURE_REASON_DIAL_FAILED, "dial failed")
		return
	}
	_ = p.Start(c.(*net.TCPConn))
}

// openPipe opens a pipe to addr and returns it with the caller's end of a TCP
// connection attached as the controller's Local.
func openPipe(t *testing.T, ctrl *Mux, addr string) (*Pipe, *net.TCPConn) {
	t.Helper()
	p := openOnly(t, ctrl, addr)
	if err := p.WaitOpened(testContext(t)); err != nil {
		t.Fatalf("WaitOpened: %v", err)
	}
	caller, local := tcpPair(t)
	if err := p.Start(local); err != nil {
		t.Fatalf("Start: %v", err)
	}
	return p, caller
}

func openOnly(t *testing.T, ctrl *Mux, addr string) *Pipe {
	t.Helper()
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		t.Fatal(err)
	}
	p, err := ctrl.Open(testCapability, host, uint32(port), passthrough)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return p
}

// tcpPair returns both ends of a loopback TCP connection.
func tcpPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, _ := ln.Accept()
		accepted <- c
	}()
	dialed, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	server := <-accepted
	if server == nil {
		t.Fatal("accept failed")
	}
	t.Cleanup(func() {
		_ = dialed.Close()
		_ = server.Close()
	})
	return dialed.(*net.TCPConn), server.(*net.TCPConn)
}

// serve runs handle for every connection to a new loopback listener.
func serve(t *testing.T, handle func(*net.TCPConn)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	t.Cleanup(func() {
		_ = ln.Close()
		wg.Wait()
	})
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer c.Close()
				handle(c.(*net.TCPConn))
			}()
		}
	}()
	return ln.Addr().String()
}

func echo(c *net.TCPConn) {
	_, _ = io.Copy(c, c)
	_ = c.CloseWrite()
}

func testContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), waitTimeout)
	t.Cleanup(cancel)
	return ctx
}

func waitDone(t *testing.T, p *Pipe) Result {
	t.Helper()
	select {
	case <-p.Done():
		return p.Result()
	case <-time.After(waitTimeout):
		t.Fatalf("pipe %d did not finish", p.ID())
		return Result{}
	}
}

func waitClosed(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(waitTimeout):
		t.Fatalf("%s did not happen", what)
	}
}

// eventually polls cond until it holds.
func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(waitTimeout)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

func slots(m *Mux) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.slots
}

func wantReason(t *testing.T, got Result, want pb.RawCloseReason) {
	t.Helper()
	if got.Reason != want {
		t.Fatalf("close reason = %v, want %v", got.Reason, want)
	}
}

// memLocal is an in-memory Local. Read returns fill forever; Write blocks
// until Close unless acceptWrites is set.
type memLocal struct {
	acceptWrites bool

	mu      sync.Mutex
	read    int
	written int
	closed  chan struct{}
	once    sync.Once
}

func newMemLocal(acceptWrites bool) *memLocal {
	return &memLocal{acceptWrites: acceptWrites, closed: make(chan struct{})}
}

func (l *memLocal) Read(p []byte) (int, error) {
	select {
	case <-l.closed:
		return 0, net.ErrClosed
	default:
	}
	for i := range p {
		p[i] = byte(i)
	}
	l.mu.Lock()
	l.read += len(p)
	l.mu.Unlock()
	return len(p), nil
}

func (l *memLocal) Write(p []byte) (int, error) {
	if !l.acceptWrites {
		<-l.closed
		return 0, net.ErrClosed
	}
	l.mu.Lock()
	l.written += len(p)
	l.mu.Unlock()
	return len(p), nil
}

func (l *memLocal) CloseWrite() error { return nil }

func (l *memLocal) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *memLocal) bytesRead() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.read
}

// silentLocal never produces bytes until closed.
type silentLocal struct {
	memLocal
}

// newSilentLocal returns a silentLocal that accepts every write.
func newSilentLocal() *silentLocal {
	return &silentLocal{memLocal{acceptWrites: true, closed: make(chan struct{})}}
}

// blockingLocal neither produces nor consumes bytes, so the peer never gets
// credit back.
func blockingLocal() Local {
	return &silentLocal{memLocal{closed: make(chan struct{})}}
}

func quietLocal() Local {
	return newSilentLocal()
}

func (l *silentLocal) Read([]byte) (int, error) {
	<-l.closed
	return 0, net.ErrClosed
}

func (l *memLocal) waitClosed(t *testing.T) {
	t.Helper()
	waitClosed(t, l.closed, "local close")
}
