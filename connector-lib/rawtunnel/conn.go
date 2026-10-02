package rawtunnel

import (
	"io"
	"net"
	"sync"
	"time"

	pb "github.com/InteractionLabs/traversal-connector/connector-lib/gen/connector/v1"
)

// Stream is one direction of the outer gRPC tunnel. Send and Receive may be
// called concurrently. Send must not retain p after it returns. Receive
// returns one message; the outer flow-control window is returned when
// Receive returns, which is why the adapter calls it only for the chunk the
// inner session is reading now.
type Stream interface {
	Send(p []byte) error
	Receive() ([]byte, error)
}

// ChunkConn is the byte pipe between the outer gRPC stream and the inner
// HTTP/2 session.
//
// Read calls Receive only after the previous message has been copied to the
// caller, so the adapter holds at most one chunk. It does not prefetch: doing
// so would return outer-window credit early and keep the bytes here. Write
// calls Send before it returns and does not queue. A queue would put the next
// window update behind a data write that is waiting on the outer window.
// Read and Write take no shared lock across those calls.
type ChunkConn struct {
	stream Stream

	rmu        sync.Mutex
	wmu        sync.Mutex
	writes     sync.WaitGroup
	closeOnce  sync.Once
	closedDone chan struct{}
	buf        []byte
	off        int
	maxHeld    int
	closed     bool
	lost       bool
	// readErr is the first Receive failure that Close did not cause, such as
	// a TLS or dial error on the outer stream.
	readErr error
	// interrupt unblocks a Receive that Close cannot cancel itself. The gRPC
	// stream behind FromChunks is not an io.Closer.
	interrupt func()
}

// NewChunkConn adapts stream to a net.Conn. Deadlines are ignored: a blocked
// Send is outer-window backpressure, and the outer connection's write timeout
// is what detects a stuck TCP write.
func NewChunkConn(stream Stream) *ChunkConn {
	return &ChunkConn{stream: stream, closedDone: make(chan struct{})}
}

// MaxHeld is the most bytes Read had buffered at once.
func (c *ChunkConn) MaxHeld() int {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	return c.maxHeld
}

func (c *ChunkConn) Read(p []byte) (int, error) {
	c.rmu.Lock()
	if c.off >= len(c.buf) {
		if c.closed {
			c.rmu.Unlock()
			return 0, io.EOF
		}
		// Drop the lock across Receive so Close can mark the conn closed and
		// a peer abort can unblock this read.
		c.rmu.Unlock()
		b, err := c.stream.Receive()
		c.rmu.Lock()
		if err != nil {
			c.lost = true
			if !c.closed && c.readErr == nil {
				c.readErr = err
			}
		}
		if c.closed {
			c.rmu.Unlock()
			if err != nil {
				return 0, err
			}
			return 0, io.EOF
		}
		if err != nil {
			c.rmu.Unlock()
			return 0, err
		}
		c.buf = b
		c.off = 0
		if len(b) > c.maxHeld {
			c.maxHeld = len(b)
		}
	}
	n := copy(p, c.buf[c.off:])
	c.off += n
	c.rmu.Unlock()
	return n, nil
}

func (c *ChunkConn) Write(p []byte) (int, error) {
	c.wmu.Lock()
	if c.closed {
		c.wmu.Unlock()
		return 0, io.ErrClosedPipe
	}
	// Count the send before dropping the lock so Close can wait for it. The
	// wait keeps a reset from using the gRPC response after its handler has
	// returned.
	c.writes.Add(1)
	c.wmu.Unlock()
	defer c.writes.Done()

	sent := 0
	for len(p) > 0 {
		n := min(len(p), maxChunk)
		if err := c.stream.Send(p[:n]); err != nil {
			return sent, err
		}
		sent += n
		p = p[n:]
	}
	return sent, nil
}

func (c *ChunkConn) Close() error {
	// The HTTP/2 stack closes the conn from its own goroutine as well as from
	// the handler. Every caller waits until the in-flight writes finish, so
	// the handler cannot return while one of them is still using the response.
	c.closeOnce.Do(func() {
		c.wmu.Lock()
		c.rmu.Lock()
		c.closed = true
		c.lost = true
		c.rmu.Unlock()
		c.wmu.Unlock()
		if c.interrupt != nil {
			c.interrupt()
		}
		c.writes.Wait()
		if closer, ok := c.stream.(io.Closer); ok {
			_ = closer.Close()
		}
		close(c.closedDone)
	})
	<-c.closedDone
	return nil
}

// Err is the first outer-stream read failure that Close did not cause.
func (c *ChunkConn) Err() error {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	return c.readErr
}

// Lost reports that a read failed or Close has started. Callers use it to
// tell a dropped tunnel from a reset of one pipe.
func (c *ChunkConn) Lost() bool {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	return c.lost
}

func (c *ChunkConn) LocalAddr() net.Addr         { return stubAddr{} }
func (c *ChunkConn) RemoteAddr() net.Addr        { return stubAddr{} }
func (c *ChunkConn) SetDeadline(time.Time) error { return nil }
func (c *ChunkConn) SetReadDeadline(time.Time) error {
	return nil
}
func (c *ChunkConn) SetWriteDeadline(time.Time) error { return nil }

type stubAddr struct{}

func (stubAddr) Network() string { return "tunnel" }
func (stubAddr) String() string  { return "tunnel" }

// ChunkStream is the gRPC stream that carries one raw tunnel. Connect's client
// and server bidirectional streams both implement it.
type ChunkStream interface {
	Send(*pb.RawTunnelChunk) error
	Receive() (*pb.RawTunnelChunk, error)
}

// FromChunks adapts the gRPC stream to the byte pipe the inner HTTP/2 session
// reads and writes. Send copies p; the caller may reuse it.
func FromChunks(s ChunkStream) Stream { return chunkSource{s: s} }

type chunkSource struct{ s ChunkStream }

func (c chunkSource) Send(p []byte) (err error) {
	// The inner HTTP/2 client writes on the gRPC handler's stream. A reset can
	// still be flushing when that handler returns, and net/http panics if the
	// response is used afterward. The tunnel is already over by then.
	defer func() {
		if recover() != nil {
			err = io.ErrClosedPipe
		}
	}()
	if len(p) == 0 || len(p) > maxChunk {
		return io.ErrShortBuffer
	}
	b := make([]byte, len(p))
	copy(b, p)
	return c.s.Send(&pb.RawTunnelChunk{Data: b})
}

func (c chunkSource) Receive() ([]byte, error) {
	msg, err := c.s.Receive()
	if err != nil {
		return nil, err
	}
	if len(msg.GetData()) == 0 || len(msg.GetData()) > maxChunk {
		return nil, io.ErrUnexpectedEOF
	}
	return msg.GetData(), nil
}
