package dialpolicy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

type connectRequest struct {
	method, target, host, auth string
}

// connectProxy is a forward proxy that tunnels CONNECT requests to the real
// address its targets map gives for the requested authority.
type connectProxy struct {
	targets map[string]string
	// response is the CONNECT response head, "HTTP/1.1 200 ...\r\n\r\n" if
	// unset; early is written right after it.
	response string
	early    string

	mu       sync.Mutex
	status   int // answers every CONNECT with this status when set
	requests []connectRequest
}

func (h *connectProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	h.requests = append(h.requests, connectRequest{
		r.Method, r.RequestURI, r.Host, r.Header.Get("Proxy-Authorization"),
	})
	status := h.status
	h.mu.Unlock()
	target, ok := h.targets[r.Host]
	switch {
	case r.Method != http.MethodConnect:
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	case status != 0:
		w.WriteHeader(status)
		return
	case !ok:
		w.WriteHeader(http.StatusBadGateway)
		return
	}
	up, err := net.Dial("tcp", target)
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		return
	}
	defer up.Close()
	client, rw, err := w.(http.Hijacker).Hijack()
	if err != nil {
		return
	}
	defer client.Close()
	response := h.response
	if response == "" {
		response = "HTTP/1.1 200 Connection established\r\n\r\n"
	}
	_, _ = io.WriteString(client, response+h.early)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = io.Copy(up, rw)
		_ = up.(*net.TCPConn).CloseWrite()
	}()
	_, _ = io.Copy(client, up)
	_ = client.(interface{ CloseWrite() error }).CloseWrite()
	<-done
}

func (h *connectProxy) got() []connectRequest {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]connectRequest(nil), h.requests...)
}

func proxyAt(t *testing.T, raw string) func(string, uint16) (*url.URL, error) {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return func(string, uint16) (*url.URL, error) { return u, nil }
}

func newProxiedPolicy(t *testing.T, cfg Config) *Policy {
	t.Helper()
	cfg.LookupNetIP = (&fakeNet{t: t}).lookup
	p, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestDialThroughProxy(t *testing.T) {
	echo := echoServer(t)
	h := &connectProxy{targets: map[string]string{
		"db.internal.:5432": echo, "192.0.2.10:5432": echo, "[2001:db8::1]:5432": echo,
	}}
	proxy := httptest.NewServer(h)
	t.Cleanup(proxy.Close)
	proxyURL := strings.Replace(proxy.URL, "http://", "http://user:s3cret@", 1)
	lookups := &fakeNet{t: t}

	for _, tc := range []struct {
		name, host, authority string
		delegated             bool
	}{
		{"hostname", "db.internal", "db.internal.:5432", true},
		{"ipv4 literal", "192.0.2.10", "192.0.2.10:5432", false},
		{"ipv6 literal", "2001:db8::1", "[2001:db8::1]:5432", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := New(Config{
				Proxy:                     proxyAt(t, proxyURL),
				AllowDelegatedProxyChecks: tc.delegated,
				LookupNetIP:               lookups.lookup,
			})
			if err != nil {
				t.Fatal(err)
			}
			before := len(h.got())
			c, route, err := p.Dial(context.Background(), tc.host, 5432)
			if err != nil {
				t.Fatal(err)
			}
			if route.Addr.IsValid() || route.Proxy == nil || route.Proxy.User != nil ||
				route.Proxy.Host != strings.TrimPrefix(proxy.URL, "http://") {
				t.Fatalf("route = %+v", route)
			}
			roundTrip(t, c, "through the proxy")
			reqs := h.got()[before:]
			want := connectRequest{http.MethodConnect, tc.authority, tc.authority,
				"Basic dXNlcjpzM2NyZXQ="}
			if len(reqs) != 1 || reqs[0] != want {
				t.Fatalf("proxy saw %+v, want %+v", reqs, want)
			}
		})
	}
	if n, _ := lookups.counts(); n != 0 {
		t.Fatalf("resolved %d names locally for proxied dials", n)
	}
}

func TestDialThroughHTTPSProxy(t *testing.T) {
	echo := echoServer(t)
	proxy := httptest.NewTLSServer(&connectProxy{
		targets: map[string]string{"db.internal.:5432": echo},
		early:   "early:",
	})
	t.Cleanup(proxy.Close)
	roots := x509.NewCertPool()
	roots.AddCert(proxy.Certificate())
	p := newProxiedPolicy(t, Config{
		Proxy:                     proxyAt(t, proxy.URL),
		ProxyTLS:                  &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
		AllowDelegatedProxyChecks: true,
	})
	c, _, err := p.Dial(context.Background(), "db.internal", 5432)
	if err != nil {
		t.Fatal(err)
	}
	roundTrip(t, &prefixCheck{Conn: c, t: t, prefix: "early:"}, "over tls")
}

// Every 2xx response form leaves the tunnel's first bytes for the caller.
func TestProxyResponseForms(t *testing.T) {
	echo := echoServer(t)
	for _, response := range []string{
		"HTTP/1.0 200 Connection established\r\n\r\n",
		"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n",
		"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
		"HTTP/1.1 204 No Content\r\n\r\n",
		"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\n",
		"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
		"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 Connection established\r\n\r\n",
	} {
		t.Run(strings.SplitN(response, "\r\n", 2)[0], func(t *testing.T) {
			proxy := httptest.NewServer(&connectProxy{
				targets:  map[string]string{"db.internal.:5432": echo},
				response: response,
				early:    "early:",
			})
			t.Cleanup(proxy.Close)
			p := newProxiedPolicy(t, Config{
				Proxy:                     proxyAt(t, proxy.URL),
				AllowDelegatedProxyChecks: true,
			})
			c, _, err := p.Dial(context.Background(), "db.internal", 5432)
			if err != nil {
				t.Fatal(err)
			}
			roundTrip(t, &prefixCheck{Conn: c, t: t, prefix: "early:"}, "hello")
		})
	}
}

// prefixCheck strips and checks bytes the proxy sent right after its response.
type prefixCheck struct {
	Conn
	t      *testing.T
	prefix string
	seen   bool
}

func (c *prefixCheck) Read(b []byte) (int, error) {
	if !c.seen {
		c.seen = true
		got := make([]byte, len(c.prefix))
		if _, err := io.ReadFull(c.Conn, got); err != nil || string(got) != c.prefix {
			c.t.Errorf("first bytes = %q, %v; want %q", got, err, c.prefix)
		}
	}
	return c.Conn.Read(b)
}

func TestProxyRefusals(t *testing.T) {
	h := &connectProxy{}
	proxy := httptest.NewServer(h)
	t.Cleanup(proxy.Close)
	withCreds := strings.Replace(proxy.URL, "http://", "http://user:s3cret@", 1)

	for _, tc := range []struct {
		name      string
		host      string
		proxy     func(string, uint16) (*url.URL, error)
		delegated bool
		status    int
		code      Code
		reachesIt bool
	}{
		{"hostname without delegation", "db.internal", proxyAt(t, withCreds), false, 0,
			CodeProxyChecksDelegated, false},
		{"forbidden literal", "169.254.169.254", proxyAt(t, withCreds), true, 0,
			CodeForbiddenAddress, false},
		{"metadata name", "metadata.goog", proxyAt(t, withCreds), true, 0,
			CodeForbiddenAddress, false},
		{"proxy auth required", "db.internal", proxyAt(t, withCreds), true,
			http.StatusProxyAuthRequired, CodeDialFailed, true},
		{"proxy forbids", "db.internal", proxyAt(t, withCreds), true, http.StatusForbidden,
			CodeDialFailed, true},
		{"unsupported scheme", "db.internal", proxyAt(t, "socks5://user:s3cret@127.0.0.1:1"),
			true, 0, CodeDialFailed, false},
		{"proxy selection error", "db.internal", func(string, uint16) (*url.URL, error) {
			return nil, errors.New(`invalid proxy "http://user:s3cret@bad host"`)
		}, true, 0, CodeDialFailed, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h.mu.Lock()
			h.status = tc.status
			h.mu.Unlock()
			before := len(h.got())
			p := newProxiedPolicy(
				t,
				Config{Proxy: tc.proxy, AllowDelegatedProxyChecks: tc.delegated},
			)
			_, _, err := p.Dial(context.Background(), tc.host, 5432)
			wantCode(t, err, tc.code)
			if strings.Contains(err.Error(), "s3cret") {
				t.Fatalf("error leaks proxy credentials: %v", err)
			}
			if reached := len(h.got()) > before; reached != tc.reachesIt {
				t.Fatalf("proxy reached = %v, want %v", reached, tc.reachesIt)
			}
		})
	}
}

func TestProxyHandshakeHonorsContext(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var silent []net.Conn
	t.Cleanup(func() {
		_ = ln.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, c := range silent {
			_ = c.Close()
		}
	})
	go func() {
		// Accept and never answer.
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			silent = append(silent, c)
			mu.Unlock()
		}
	}()
	p := newProxiedPolicy(t, Config{
		Proxy:                     proxyAt(t, "http://"+ln.Addr().String()),
		AllowDelegatedProxyChecks: true,
	})
	for _, tc := range []struct {
		name string
		ctx  func() (context.Context, context.CancelFunc)
		want error
	}{
		{"deadline", func() (context.Context, context.CancelFunc) {
			return context.WithTimeout(context.Background(), 50*time.Millisecond)
		}, context.DeadlineExceeded},
		{"cancel", func() (context.Context, context.CancelFunc) {
			ctx, cancel := context.WithCancel(context.Background())
			time.AfterFunc(50*time.Millisecond, cancel)
			return ctx, cancel
		}, context.Canceled},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := tc.ctx()
			defer cancel()
			start := time.Now()
			_, _, err := p.Dial(ctx, "db.internal", 5432)
			wantCode(t, err, CodeDialFailed)
			if !errors.Is(err, tc.want) || time.Since(start) > 5*time.Second {
				t.Fatalf("Dial = %v after %v, want %v promptly", err, time.Since(start), tc.want)
			}
		})
	}
}

// TestNilProxyIgnoresEnvironment checks that a nil Config.Proxy dials
// directly even when HTTPS_PROXY is set: the connector's proxy variables are
// for its own traffic, and raw pipes go through a forward proxy only when the
// caller opts in.
func TestNilProxyIgnoresEnvironment(t *testing.T) {
	echo := echoServer(t)
	h := &connectProxy{targets: map[string]string{"db.internal.:5432": echo}}
	proxy := httptest.NewServer(h)
	t.Cleanup(proxy.Close)
	for _, name := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy",
		"NO_PROXY", "no_proxy"} {
		t.Setenv(name, "")
	}
	t.Setenv("HTTPS_PROXY", proxy.URL)
	t.Setenv("HTTP_PROXY", proxy.URL)

	f := &fakeNet{t: t,
		addrs:  map[string][]string{"db.internal": {"192.0.2.10"}},
		listen: map[string]string{"192.0.2.10:5432": echo},
	}
	p, err := New(Config{AllowDelegatedProxyChecks: true, LookupNetIP: f.lookup})
	if err != nil {
		t.Fatal(err)
	}
	p.dial = f.dial
	c, route, err := p.Dial(context.Background(), "db.internal", 5432)
	if err != nil {
		t.Fatal(err)
	}
	if route.Proxy != nil || route.Addr.String() != "192.0.2.10:5432" {
		t.Fatalf("route = %+v, want a direct dial despite HTTPS_PROXY", route)
	}
	roundTrip(t, c, "direct")
	if got := h.got(); len(got) != 0 {
		t.Fatalf("proxy saw %d CONNECTs, want none", len(got))
	}
}
