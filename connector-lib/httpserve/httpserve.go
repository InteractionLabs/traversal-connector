// Package httpserve is the net/http plumbing the connector and the
// Integration Proxy share for HTTP they terminate on a connection they
// already hold: a tunnel, a pipe's TLS, or a caller's CONNECT.
package httpserve

import (
	"cmp"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"sync"
)

// ServeConn serves c, and only c, with srv: net/http serves only connections
// a Listener accepts, and these are dialed or hijacked. It returns once c is
// closed or hijacked and srv's handlers have returned, so a handler that
// hijacked c (an upgrade) is done with it. c is served as it is, so a
// *tls.Conn's ALPN picks h2 or http/1.1; hide its TLS (struct{ net.Conn }{c})
// to serve it as plaintext. ServeConn sets srv.ConnState and wraps
// srv.Handler.
func ServeConn(srv *http.Server, c net.Conn) error {
	l := &oneConn{conn: c, done: make(chan struct{})}
	srv.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateClosed || state == http.StateHijacked {
			l.end()
		}
	}
	var handlers sync.WaitGroup
	h := cmp.Or[http.Handler](srv.Handler, http.DefaultServeMux)
	srv.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlers.Add(1)
		defer handlers.Done()
		h.ServeHTTP(w, r)
	})
	err := srv.Serve(l)
	handlers.Wait()
	if errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

// oneConn is a Listener that accepts conn once, then blocks until end.
type oneConn struct {
	conn     net.Conn
	accepted bool // only Serve's goroutine calls Accept
	done     chan struct{}
	once     sync.Once
}

func (l *oneConn) Accept() (net.Conn, error) {
	if !l.accepted {
		l.accepted = true
		return l.conn, nil
	}
	<-l.done
	return nil, net.ErrClosed
}

func (l *oneConn) end()           { l.once.Do(func() { close(l.done) }) }
func (l *oneConn) Close() error   { l.end(); return nil }
func (l *oneConn) Addr() net.Addr { return l.conn.LocalAddr() }

// ReverseProxy forwards with rewrite through rt, answering failures with
// onError. It flushes every write (FlushInterval -1), since server streams,
// SSE and gRPC must not wait on a buffer, and logs net/http's own errors to
// slog at warn rather than to the standard logger.
func ReverseProxy(
	rewrite func(*httputil.ProxyRequest),
	rt http.RoundTripper,
	onError func(http.ResponseWriter, *http.Request, error),
) *httputil.ReverseProxy {
	return &httputil.ReverseProxy{
		Rewrite:       rewrite,
		Transport:     rt,
		FlushInterval: -1,
		ErrorHandler:  onError,
		ErrorLog:      slog.NewLogLogger(slog.Default().Handler(), slog.LevelWarn),
	}
}
