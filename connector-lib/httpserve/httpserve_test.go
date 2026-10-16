package httpserve_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"testing"
	"time"

	"github.com/InteractionLabs/traversal-connector/connector-lib/halfconn/halfconntest"
	"github.com/InteractionLabs/traversal-connector/connector-lib/httpserve"
	"github.com/InteractionLabs/traversal-connector/connector-lib/rawpipe/rawpipetest"
)

// TestServeConn: a *tls.Conn is served in the protocol its ALPN chose, and
// ServeConn returns once the client closes the connection.
func TestServeConn(t *testing.T) {
	ca := rawpipetest.NewCA(t)
	cert := ca.Server(t, "example.internal")
	for alpn, want := range map[string]string{"h2": "HTTP/2.0", "http/1.1": "HTTP/1.1"} {
		t.Run(alpn, func(t *testing.T) {
			a, b := halfconntest.TCPPair(t)
			protocols := new(http.Protocols)
			protocols.SetHTTP1(true)
			protocols.SetHTTP2(true)
			srv := &http.Server{
				Protocols:         protocols,
				ReadHeaderTimeout: 5 * time.Second,
				Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					_, _ = io.WriteString(w, r.Proto) //nolint:gosec // test echo
				}),
			}
			served := make(chan error, 1)
			go func() {
				served <- httpserve.ServeConn(srv, tls.Server(a, &tls.Config{
					Certificates: []tls.Certificate{cert},
					MinVersion:   tls.VersionTLS13,
					NextProtos:   []string{"h2", "http/1.1"},
				}))
			}()
			client := &tls.Config{RootCAs: ca.Pool(), ServerName: "example.internal",
				MinVersion: tls.VersionTLS13, NextProtos: []string{alpn}}
			clientProtocols := new(http.Protocols)
			clientProtocols.SetHTTP1(alpn == "http/1.1")
			clientProtocols.SetHTTP2(alpn == "h2")
			tr := &http.Transport{Protocols: clientProtocols, TLSClientConfig: client,
				DialTLSContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					tc := tls.Client(b, client)
					return tc, tc.HandshakeContext(ctx)
				}}
			resp, err := (&http.Client{Transport: tr}).Get("https://example.internal/")
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if string(body) != want {
				t.Fatalf("served %q, want %q", body, want)
			}
			tr.CloseIdleConnections()
			select {
			case err := <-served:
				if err != nil {
					t.Fatalf("ServeConn: %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("ServeConn did not return once the connection closed")
			}
		})
	}
}

// TestServeConnWaitsForHijacker: a handler that hijacks the connection (an
// upgrade) keeps it after net/http lets go of it, so ServeConn returns only
// once that handler has.
func TestServeConnWaitsForHijacker(t *testing.T) {
	a, b := halfconntest.TCPPair(t)
	release, done := make(chan struct{}), make(chan struct{})
	srv := &http.Server{ReadHeaderTimeout: 5 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			c, _, err := http.NewResponseController(w).Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			<-release
			_ = c.Close()
			close(done)
		})}
	served := make(chan error, 1)
	go func() { served <- httpserve.ServeConn(srv, a) }()
	_, _ = io.WriteString(b, "GET / HTTP/1.1\r\nHost: x\r\n\r\n")
	select {
	case <-served:
		t.Fatal("ServeConn returned while the hijacking handler still ran")
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	if err := <-served; err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	default:
		t.Fatal("ServeConn returned before the handler did")
	}
}

// TestReverseProxyFlushes: each write upstream reaches the client before the
// response ends, even with a Content-Length, which net/http's own streaming
// detection does not flush for.
func TestReverseProxyFlushes(t *testing.T) {
	release := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "1024")
		_, _ = io.WriteString(w, "first\n")
		w.(http.Flusher).Flush()
		<-release
	}))
	defer upstream.Close()
	defer close(release)
	target, _ := url.Parse(upstream.URL)
	proxy := httptest.NewServer(httpserve.ReverseProxy(
		func(pr *httputil.ProxyRequest) { pr.SetURL(target) },
		http.DefaultTransport,
		func(w http.ResponseWriter, _ *http.Request, err error) { t.Error(err) },
	))
	defer proxy.Close()
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, proxy.URL, http.NoBody)
	resp, err := http.DefaultClient.Do(req) //nolint:bodyclose // closed by the defer below
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	line := make(chan string, 1)
	go func() {
		l, _ := bufio.NewReader(resp.Body).ReadString('\n')
		line <- l
	}()
	select {
	case l := <-line:
		if l != "first\n" {
			t.Fatalf("read %q", l)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the first write did not arrive before the response ended")
	}
}
