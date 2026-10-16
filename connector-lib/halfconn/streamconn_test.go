package halfconn_test

import (
	"errors"
	"io"
	"os"
	"testing"
	"time"

	"github.com/InteractionLabs/traversal-connector/connector-lib/halfconn"
	"github.com/InteractionLabs/traversal-connector/connector-lib/halfconn/halfconntest"
)

// TestStreamConn: a read deadline unblocks a pending read and can be reset, as
// net/http's HTTP/1 server needs before a hijack; closing the conn ends the
// stream cleanly and, once the peer ends too, both copies stop.
func TestStreamConn(t *testing.T) {
	near, peer := halfconntest.TCPPair(t)
	c := halfconn.NewStreamConn(halfconn.ConnEnd(near))
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
	if _, err := c.Read(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("read past the deadline: %v", err)
	}
	_ = c.SetReadDeadline(time.Time{})
	_, _ = peer.Write([]byte("x"))
	if n, err := c.Read(make([]byte, 1)); n != 1 || err != nil {
		t.Fatalf("read after the deadline was reset: %d %v", n, err)
	}
	_, _ = c.Write([]byte("bye"))
	_ = c.Close()
	if b, err := io.ReadAll(peer); string(b) != "bye" || err != nil {
		t.Fatalf("peer read %q %v, want a clean end", b, err)
	}
	_ = peer.CloseWrite()
	if in, out := c.Wait(); in != 1 || out != 3 {
		t.Fatalf("Wait = %d in, %d out; want 1, 3", in, out)
	}
}
