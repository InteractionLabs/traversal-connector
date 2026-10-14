package halfconn_test

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/InteractionLabs/traversal-connector/connector-lib/halfconn"
	"github.com/InteractionLabs/traversal-connector/connector-lib/halfconn/halfconntest"
)

// plainWriter is an io.Writer that is not an io.ReaderFrom, so io.Copy uses
// the source's WriteTo.
type plainWriter []byte

func (w *plainWriter) Write(b []byte) (int, error) { *w = append(*w, b...); return len(b), nil }

// reads reads a conn to its end through Read, and through io.Copy (WriteTo).
var reads = map[string]func(io.Reader) ([]byte, error){
	"Read": io.ReadAll,
	"WriteTo": func(r io.Reader) ([]byte, error) {
		var w plainWriter
		_, err := io.Copy(&w, r)
		return w, err
	},
}

// TestPrefixed: the prefix comes first, then the conn, through Read and
// WriteTo alike; CloseWrite still half-closes and Abort still resets.
func TestPrefixed(t *testing.T) {
	for name, read := range reads {
		t.Run(name, func(t *testing.T) {
			far, near := halfconntest.TCPPair(t)
			c := halfconn.Prefixed(near, strings.NewReader("hello"))
			_, _ = far.Write([]byte(" world"))
			_ = far.CloseWrite()
			if b, err := read(c); err != nil || string(b) != "hello world" {
				t.Fatalf("read %q, %v", b, err)
			}
			if err := c.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			if b, err := io.ReadAll(far); err != nil || len(b) != 0 {
				t.Fatalf("far end after CloseWrite: %q, %v", b, err)
			}
		})
	}
	t.Run("Abort", func(t *testing.T) {
		far, near := halfconntest.TCPPair(t)
		halfconn.ConnEnd(halfconn.Prefixed(near, strings.NewReader("x"))).Abort()
		_ = far.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := io.ReadAll(far); err == nil {
			t.Fatal("peer saw a clean end, not a reset")
		}
	})
}

// TestBuffered: bytes already in the reader come first, through Read and
// through io.Copy (WriteTo) alike, and CloseWrite still half-closes.
func TestBuffered(t *testing.T) {
	for name, read := range reads {
		t.Run(name, func(t *testing.T) {
			far, near := halfconntest.TCPPair(t)
			_, _ = far.Write([]byte("hello"))
			br := bufio.NewReader(near)
			if _, err := br.Peek(5); err != nil {
				t.Fatal(err)
			}
			c := halfconn.Buffered(near, br)
			if c == halfconn.Conn(near) {
				t.Fatal("Buffered dropped the buffered bytes")
			}
			_, _ = far.Write([]byte(" world"))
			_ = far.CloseWrite()
			if b, err := read(c); err != nil || string(b) != "hello world" {
				t.Fatalf("read %q, %v", b, err)
			}
			if err := c.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			if b, err := io.ReadAll(far); err != nil || len(b) != 0 {
				t.Fatalf("far end after CloseWrite: %q, %v", b, err)
			}
		})
	}
	t.Run("nothing buffered", func(t *testing.T) {
		_, near := halfconntest.TCPPair(t)
		if c := halfconn.Buffered(near, bufio.NewReader(near)); c != halfconn.Conn(near) {
			t.Fatalf("Buffered wrapped an empty reader: %T", c)
		}
	})
}

// TestEstablished: a CONNECT handler that accepts gets the client the exact
// 200 line, then reads what the client sent straight after its request, in
// the same write, and can half-close.
func TestEstablished(t *testing.T) {
	got := make(chan string, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		c, err := halfconn.Established(w)
		if err != nil {
			got <- err.Error()
			return
		}
		defer c.Close()
		var b plainWriter
		_, _ = io.Copy(&b, c) // until the client half-closes
		got <- string(b)
		_, _ = io.WriteString(c, "tunnel")
		_ = c.CloseWrite()
	}))
	defer srv.Close()
	c, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	tcp := c.(*net.TCPConn) //nolint:forcetypeassert // tcp
	_, _ = io.WriteString(
		tcp,
		"CONNECT db.internal:5432 HTTP/1.1\r\nHost: db.internal:5432\r\n\r\n"+
			"pipelined",
	)
	_ = tcp.CloseWrite()
	_ = tcp.SetDeadline(time.Now().Add(5 * time.Second))
	if b := <-got; b != "pipelined" {
		t.Fatalf("handler read %q, want the pipelined bytes", b)
	}
	const want = "HTTP/1.1 200 Connection Established\r\n\r\ntunnel"
	if b, err := io.ReadAll(tcp); err != nil || string(b) != want {
		t.Fatalf("client read %q, %v; want %q", b, err, want)
	}
}

// TestBufferedAbort: halfconn.ConnEnd's Abort still resets a buffered TCP
// connection, so the peer sees a failure rather than an end.
func TestBufferedAbort(t *testing.T) {
	far, near := halfconntest.TCPPair(t)
	_, _ = far.Write([]byte("x"))
	br := bufio.NewReader(near)
	if _, err := br.Peek(1); err != nil {
		t.Fatal(err)
	}
	halfconn.ConnEnd(halfconn.Buffered(near, br)).Abort()
	_ = far.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadAll(far); err == nil {
		t.Fatal("peer saw a clean end, not a reset")
	}
}
