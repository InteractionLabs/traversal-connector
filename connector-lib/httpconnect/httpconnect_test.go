// Dial closes a refusal's body itself.
//
//nolint:bodyclose // see above
package httpconnect

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"
)

// proxy accepts one connection, reads its CONNECT request, sends it on the
// returned channel, and lets serve answer on the raw connection.
func proxy(
	t *testing.T,
	serve func(c net.Conn, req *http.Request),
) (*url.URL, <-chan *http.Request) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	got := make(chan *http.Request, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		req, err := http.ReadRequest(bufio.NewReader(c))
		if err != nil {
			return
		}
		got <- req
		serve(c, req)
	}()
	return &url.URL{Scheme: "http", Host: ln.Addr().String()}, got
}

func dial(t *testing.T, p *url.URL, h http.Header) (net.Conn, *http.Response, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return Dial(ctx, p, "db.internal:5432", h)
}

// TestTrailingBytes: bytes the proxy sends with its 200 are the tunnel's
// first bytes, through Read and through io.Copy alike.
func TestTrailingBytes(t *testing.T) {
	for name, read := range map[string]func(io.Reader) ([]byte, error){
		"Read": io.ReadAll,
		"WriteTo": func(c io.Reader) ([]byte, error) {
			var b writer
			_, err := io.Copy(&b, c)
			return b, err
		},
	} {
		t.Run(name, func(t *testing.T) {
			p, got := proxy(t, func(c net.Conn, _ *http.Request) {
				_, _ = io.WriteString(c, "HTTP/1.1 200 Connection Established\r\n\r\nhello")
			})
			conn, resp, err := dial(t, p, http.Header{"X-Integration": {"acme"}})
			if err != nil || resp != nil {
				t.Fatalf("Dial: %v, response %v", err, resp)
			}
			defer conn.Close()
			req := <-got
			if req.Method != http.MethodConnect || req.Host != "db.internal:5432" ||
				req.RequestURI != "db.internal:5432" || req.Header.Get("X-Integration") != "acme" {
				t.Fatalf("proxy got %s %s Host %s, header %v",
					req.Method, req.RequestURI, req.Host, req.Header)
			}
			if b, err := read(conn); err != nil || string(b) != "hello" {
				t.Fatalf("read %q, %v through the tunnel", b, err)
			}
		})
	}
}

// writer is an io.Writer that is not an io.ReaderFrom, so io.Copy uses the
// source's WriteTo.
type writer []byte

func (w *writer) Write(b []byte) (int, error) { *w = append(*w, b...); return len(b), nil }

// TestRefusal: a non-200 answer comes back with its status and headers, and
// RefusalReason reads the reason SetRefusal wrote in them.
func TestRefusal(t *testing.T) {
	p, _ := proxy(t, func(c net.Conn, _ *http.Request) {
		resp := &http.Response{StatusCode: http.StatusForbidden, ProtoMajor: 1, ProtoMinor: 1,
			Header: http.Header{}}
		SetRefusal(resp.Header, "forbidden_address")
		_ = resp.Write(c)
	})
	conn, resp, err := dial(t, p, nil)
	if err == nil || conn != nil {
		t.Fatalf("Dial: %v, conn %v; want a refusal", err, conn)
	}
	if resp == nil || resp.StatusCode != http.StatusForbidden ||
		resp.Header.Get("Proxy-Status") != "traversal-integration-proxy; error=forbidden_address" {
		t.Fatalf("response %+v", resp)
	}
	if r := RefusalReason(resp); r != "forbidden_address" {
		t.Fatalf("RefusalReason = %q", r)
	}
}

// TestRefusalReason: the error parameter alone, without later parameters,
// and nothing without one.
func TestRefusalReason(t *testing.T) {
	for status, want := range map[string]string{
		"traversal-integration-proxy; error=dns_failed": "dns_failed",
		"egress; error=dial_failed; details=\"x\"":      "dial_failed",
		"traversal-integration-proxy":                   "",
		"":                                              "",
	} {
		resp := &http.Response{Header: http.Header{"Proxy-Status": {status}}}
		if got := RefusalReason(resp); got != want {
			t.Errorf("RefusalReason(%q) = %q, want %q", status, got, want)
		}
	}
	if got := RefusalReason(nil); got != "" {
		t.Errorf("RefusalReason(nil) = %q", got)
	}
}

// TestUserInfo: the proxy URL's user info is sent as Proxy-Authorization,
// over any the caller's header carries.
func TestUserInfo(t *testing.T) {
	p, got := proxy(t, func(c net.Conn, _ *http.Request) {
		_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\n\r\n")
	})
	p.User = url.UserPassword("u", "p")
	conn, _, err := dial(t, p, http.Header{"Proxy-Authorization": {"Basic stale"}})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if a := (<-got).Header.Values("Proxy-Authorization"); len(a) != 1 || a[0] != "Basic dTpw" {
		t.Fatalf("Proxy-Authorization %q, want Basic dTpw", a)
	}
}

// TestCancel: cancelling the context unblocks a proxy that never answers.
func TestCancel(t *testing.T) {
	hold := make(chan struct{})
	defer close(hold)
	p, got := proxy(t, func(net.Conn, *http.Request) { <-hold })
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, _, err := Dial(ctx, p, "db.internal:5432", nil)
		done <- err
	}()
	<-got
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Dial: %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Dial did not return after cancel")
	}
}

// TestScheme: only an http:// proxy is dialed.
func TestScheme(t *testing.T) {
	for _, s := range []string{"https", "socks5", ""} {
		if conn, resp, err := dial(t, &url.URL{Scheme: s, Host: "127.0.0.1:1"}, nil); err == nil ||
			conn != nil || resp != nil {
			t.Errorf("scheme %q: %v %v %v, want an error", s, conn, resp, err)
		}
	}
}

// TestCloseWrite: the tunnel half-closes, so the far end reads EOF and can
// still answer.
func TestCloseWrite(t *testing.T) {
	p, _ := proxy(t, func(c net.Conn, _ *http.Request) {
		_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\n\r\n")
		b, _ := io.ReadAll(c) // until the client's CloseWrite
		_, _ = c.Write(b)
	})
	conn, _, err := dial(t, p, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	hc, ok := conn.(interface{ CloseWrite() error })
	if !ok {
		t.Fatalf("%T cannot half-close", conn)
	}
	_, _ = io.WriteString(conn, "ping")
	if err := hc.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if b, err := io.ReadAll(conn); err != nil || string(b) != "ping" {
		t.Fatalf("read %q, %v after CloseWrite", b, err)
	}
}

func TestProxyAddr(t *testing.T) {
	for raw, want := range map[string]string{
		"http://proxy.example.com:3128": "proxy.example.com:3128",
		"http://proxy.example.com":      "proxy.example.com:80",
	} {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		if got := ProxyAddr(u); got != want {
			t.Errorf("ProxyAddr(%q) = %q, want %q", raw, got, want)
		}
	}
}
