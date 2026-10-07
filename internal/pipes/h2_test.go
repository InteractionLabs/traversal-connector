package pipes

import (
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

// newTestConn is an h2conn over one end of an in-memory pipe, with the
// stream id open on it. Frames it writes can be read from the returned peer.
func newTestConn(t *testing.T, id uint32) (*h2conn, *h2stream, net.Conn) {
	t.Helper()
	server, peer := net.Pipe()
	t.Cleanup(func() { _ = server.Close(); _ = peer.Close() })
	c := &h2conn{
		nc:            server,
		fr:            http2.NewFramer(server, server),
		sendWin:       defaultWin,
		peerStreamWin: defaultWin,
		maxFrame:      maxFrameSize,
		streams:       map[uint32]*h2stream{},
	}
	c.cond = sync.NewCond(&c.mu)
	st := &h2stream{c: c, id: id, sendWin: c.peerStreamWin}
	c.streams[id] = st
	return c, st, peer
}

// A stream reset while Write waits for the write lock must give back the
// connection send window it reserved: Envoy credits only bytes it received,
// so a reservation never returned is lost for the connection's life.
func TestWriteReturnsConnWindowOnReset(t *testing.T) {
	c, st, _ := newTestConn(t, 1)
	before := c.sendWin

	c.wmu.Lock() // hold the write lock so Write blocks after reserving
	done := make(chan error, 1)
	go func() {
		_, err := st.Write(make([]byte, 1024))
		done <- err
	}()
	deadline := time.Now().Add(5 * time.Second)
	for {
		c.mu.Lock()
		reserved := c.sendWin < before
		c.mu.Unlock()
		if reserved {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("Write never reserved the send window")
		}
		time.Sleep(time.Millisecond)
	}
	c.mu.Lock()
	st.reset = true // RST_STREAM arrived meanwhile
	c.mu.Unlock()
	c.wmu.Unlock()

	if err := <-done; !errors.Is(err, errStreamReset) {
		t.Fatalf("Write returned %v, want errStreamReset", err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.sendWin != before {
		t.Fatalf("connection send window %d after the reset, want %d", c.sendWin, before)
	}
}
