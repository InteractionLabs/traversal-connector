package pipes

import (
	"bytes"
	"errors"
	"io"
	"math"
	"net"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
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
	st := newStream(c, id)
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

// A WINDOW_UPDATE that overflows a stream's send window is a stream error:
// the stream must be reset on the wire, or Envoy's side of it hangs.
func TestStreamWindowOverflowSendsReset(t *testing.T) {
	server, client := net.Pipe()
	t.Cleanup(func() { _ = server.Close(); _ = client.Close() })
	handled := make(chan struct{})
	s := &h2server{handle: func(st *h2stream) {
		_ = st.respond("200", nil, false)
		close(handled)
		_, _ = io.Copy(io.Discard, st)
	}}
	go s.serveConn(server)

	fr := http2.NewFramer(client, client)
	fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	frames := make(chan http2.Frame, 16)
	go func() {
		defer close(frames)
		for {
			f, err := fr.ReadFrame()
			if err != nil {
				return
			}
			frames <- f
		}
	}()
	var hb bytes.Buffer
	enc := hpack.NewEncoder(&hb)
	_ = enc.WriteField(hpack.HeaderField{Name: ":method", Value: "CONNECT"})
	_ = enc.WriteField(hpack.HeaderField{Name: ":authority", Value: "db.internal:5432"})
	if _, err := client.Write([]byte(http2.ClientPreface)); err != nil {
		t.Fatal(err)
	}
	if err := fr.WriteSettings(); err != nil {
		t.Fatal(err)
	}
	if err := fr.WriteHeaders(http2.HeadersFrameParam{
		StreamID: 1, BlockFragment: hb.Bytes(), EndHeaders: true,
	}); err != nil {
		t.Fatal(err)
	}
	<-handled
	if err := fr.WriteWindowUpdate(1, math.MaxInt32); err != nil {
		t.Fatal(err)
	}
	timeout := time.After(5 * time.Second)
	for {
		select {
		case f, ok := <-frames:
			if !ok {
				t.Fatal("connection closed without resetting the stream")
			}
			if rst, ok := f.(*http2.RSTStreamFrame); ok {
				if rst.StreamID != 1 || rst.ErrCode != http2.ErrCodeFlowControl {
					t.Fatalf("got RST_STREAM(%d, %v), want (1, FLOW_CONTROL_ERROR)",
						rst.StreamID, rst.ErrCode)
				}
				return
			}
		case <-timeout:
			t.Fatal("no RST_STREAM after the stream's send window overflowed")
		}
	}
}
