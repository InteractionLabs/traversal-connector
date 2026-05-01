package telemetry

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// fakeConnectProxy answers a single HTTP CONNECT request with 200 OK,
// then proxies bytes between the client and an in-memory upstream.
// Returns the proxy listener and a channel yielding the upstream-side
// conn once a CONNECT has been served.
func fakeConnectProxy(t *testing.T) (net.Listener, <-chan net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	upstreamCh := make(chan net.Conn, 1)
	go func() {
		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			return
		}
		br := bufio.NewReader(conn)
		req, readErr := http.ReadRequest(br)
		if readErr != nil {
			_ = conn.Close()
			return
		}
		if req.Method != http.MethodConnect {
			_, _ = conn.Write([]byte("HTTP/1.1 405 Method Not Allowed\r\n\r\n"))
			_ = conn.Close()
			return
		}
		if _, writeErr := conn.Write(
			[]byte("HTTP/1.1 200 OK\r\n\r\n"),
		); writeErr != nil {
			_ = conn.Close()
			return
		}
		// Hand the tunneled conn back to the test as the "upstream" side.
		upstreamCh <- conn
	}()
	return ln, upstreamCh
}

func TestHTTPConnectDialer_Success(t *testing.T) {
	ln, upstreamCh := fakeConnectProxy(t)
	defer ln.Close()

	proxyURL, err := url.Parse("http://" + ln.Addr().String())
	if err != nil {
		t.Fatalf("parse proxy URL: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	dialer := httpConnectDialer(proxyURL)
	clientConn, err := dialer(ctx, "example.com:443")
	if err != nil {
		t.Fatalf("dialer error: %v", err)
	}
	defer clientConn.Close()

	// Verify the tunnel is end-to-end: write on the client, read on the
	// upstream side of the proxy.
	upstream := <-upstreamCh
	defer upstream.Close()

	want := "ping"
	if _, err = clientConn.Write([]byte(want)); err != nil {
		t.Fatalf("client write: %v", err)
	}
	buf := make([]byte, len(want))
	if err = upstream.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	if _, err = io.ReadFull(upstream, buf); err != nil {
		t.Fatalf("upstream read: %v", err)
	}
	if string(buf) != want {
		t.Errorf("tunnel mismatch: got %q want %q", buf, want)
	}
}

func TestHTTPConnectDialer_ProxyRejects(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			return
		}
		_, _ = conn.Write([]byte("HTTP/1.1 403 Forbidden\r\n\r\n"))
		_ = conn.Close()
	}()

	proxyURL, _ := url.Parse("http://" + ln.Addr().String())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if _, err := httpConnectDialer(proxyURL)(ctx, "example.com:443"); err == nil {
		t.Fatal("expected error on proxy rejection, got nil")
	} else if !strings.Contains(err.Error(), "403") {
		t.Errorf("expected 403 in error, got: %v", err)
	}
}

func TestProxyHostPort(t *testing.T) {
	tests := []struct {
		raw  string
		want string
	}{
		{"http://proxy.example.com:3128", "proxy.example.com:3128"},
		{"http://proxy.example.com", "proxy.example.com:80"},
	}
	for _, tt := range tests {
		u, err := url.Parse(tt.raw)
		if err != nil {
			t.Fatalf("parse %q: %v", tt.raw, err)
		}
		if got := proxyHostPort(u); got != tt.want {
			t.Errorf("proxyHostPort(%q) = %q, want %q", tt.raw, got, tt.want)
		}
	}
}
