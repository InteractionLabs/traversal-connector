// Package pipeserver is the connector's pipe side. It holds tunnels to
// Traversal's edge controller (tunnels.go) and serves each pipe the edge
// controller opens on them: verify the capability, then speak TLS with the
// Integration Proxy and forward the HTTP inside it to the capability's
// destination.
package pipeserver

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/InteractionLabs/traversal-connector/connector-lib/capability"
	"github.com/InteractionLabs/traversal-connector/connector-lib/drain"
	"github.com/InteractionLabs/traversal-connector/connector-lib/halfconn"
	"github.com/InteractionLabs/traversal-connector/connector-lib/httpserve"
	"github.com/InteractionLabs/traversal-connector/connector-lib/rawpipe"
	"github.com/InteractionLabs/traversal-connector/internal/upstream"
)

const (
	// streamWindow carries one pipe at full speed at WAN latency and bounds
	// what a pipe whose destination stops reading can hold.
	streamWindow = 512 << 10
	// pingAfter and pingTimeout find a tunnel whose far end is gone without
	// a FIN (a lost controller node behind a gateway that keeps the socket):
	// the connector then redials instead of holding a tunnel to nowhere.
	pingAfter   = 45 * time.Second
	pingTimeout = 15 * time.Second
	// prefaceTimeout bounds the wait for the edge controller's HTTP/2 preface
	// on a new tunnel; net/http clears the deadline once HTTP/2 starts.
	prefaceTimeout = 15 * time.Second
	// handshakeTimeout bounds a pipe's TLS handshake, which holds a pipe slot.
	handshakeTimeout = 10 * time.Second
)

// h2 is the tunnel's HTTP/2 configuration. Its stream limit is the
// connector's pipe limit per tunnel, so a pipe over it is refused as capacity
// rather than queued into open_timeout.
func (s *Server) h2() *http.HTTP2Config {
	tunnels := max(1, s.Tunnels)
	perTunnel := max(1, (s.MaxPipes+tunnels-1)/tunnels)
	return &http.HTTP2Config{
		// Headroom for drain requests and refusals.
		MaxConcurrentStreams:          min(perTunnel+16, 1<<20),
		MaxReceiveBufferPerStream:     streamWindow,
		MaxReceiveBufferPerConnection: min(perTunnel*streamWindow, 1<<30),
		MaxReadFrameSize:              256 << 10,
		SendPingTimeout:               pingAfter,
		PingTimeout:                   pingTimeout,
	}
}

// Inner bounds the HTTP/2 inside one pipe. It nests in the tunnel stream's
// flow control (streamWindow), so a window past that only buffers more.
type Inner struct {
	MaxStreams                     int
	StreamWindow, ConnectionWindow int
	// IdleTimeout closes a pipe that has carried no request for that long.
	IdleTimeout time.Duration
}

// Server serves pipes on tunnels.
type Server struct {
	ConnectorID string
	Verifier    *capability.Verifier
	// Certificate is the tunnel certificate; each pipe's TLS presents it.
	Certificate tls.Certificate
	Upstream    *upstream.Client
	// Ready answers requests to rawpipe.ProbeAuthority.
	Ready http.Handler
	// MaxPipes caps the pipes open at once; zero is no cap.
	MaxPipes int
	Inner    Inner
	// Tunnels is how many tunnels share MaxPipes; 0 means 1.
	Tunnels     int
	MaxLifetime time.Duration
	metrics     *metrics

	pipes drain.Tracker
}

// ServeConn serves pipes on one tunnel until it closes. drained runs once if
// the edge controller asks for a replacement tunnel. The tunnel is HTTP/2
// with prior knowledge inside TLS whose ALPN is rawpipe.ALPN, not h2; net/http
// would serve a *tls.Conn by its ALPN, so it gets nc without its TLS state.
func (s *Server) ServeConn(nc net.Conn, drained func()) {
	var once sync.Once
	protocols := new(http.Protocols)
	protocols.SetUnencryptedHTTP2(true)
	_ = httpserve.ServeConn(&http.Server{
		Protocols:         protocols,
		HTTP2:             s.h2(),
		ReadHeaderTimeout: prefaceTimeout,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == rawpipe.DrainMethod {
				once.Do(drained)
				return
			}
			s.serve(w, r)
		}),
	}, struct{ net.Conn }{nc})
}

// Drain refuses new pipes with connector_draining and waits, until ctx is
// done, for open ones to finish. It is not a GOAWAY (http.Server.Shutdown):
// tunnels stay up so a pipe already on its way gets a connector_draining
// refusal, a reason, rather than a reset.
func (s *Server) Drain(ctx context.Context) {
	s.pipes.Drain()
	if err := s.pipes.Wait(ctx); err != nil {
		slog.Warn("drain timed out; ending open pipes", "error", err)
	}
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	log := slog.With("target", r.Host)
	target, err := s.open(r)
	if err != nil {
		reason := rawpipe.ReasonOf(err, rawpipe.ProtocolError)
		s.metrics.opened(reason)
		log.Info("pipe refused", "reason", reason, "error", err)
		rawpipe.Refuse(w, reason, string(reason))
		return
	}
	defer s.pipes.Done()
	stream, err := rawpipe.Accept(w, r)
	if err != nil {
		return
	}
	s.metrics.opened("")
	s.metrics.pipes.Add(context.Background(), 1)
	start := time.Now()
	conn := halfconn.NewStreamConn(stream)
	proto, outcome := s.intercept(r.Context(), conn, target)
	_ = conn.Close()
	sent, received := conn.Wait()
	s.metrics.pipes.Add(context.Background(), -1)
	s.metrics.ended(sent, received, outcome)
	log.Info("pipe", "protocol", proto, "outcome", outcome, "bytes_sent", sent,
		"bytes_received", received, "duration_ms", time.Since(start).Milliseconds())
	stream.Finish()
}

// open checks and admits the pipe, and returns its destination.
func (s *Server) open(r *http.Request) (*url.URL, error) {
	host, port, ok := capability.SplitAuthority(r.Host)
	switch {
	case s.pipes.Draining():
		return nil, rawpipe.Errorf(rawpipe.Draining, "draining")
	case r.Method != http.MethodConnect || !ok:
		return nil, rawpipe.Errorf(rawpipe.ProtocolError,
			"expected CONNECT to a canonical host:port")
	}
	claims, err := s.Verifier.Verify(r.Header.Get(rawpipe.HeaderCapability), s.ConnectorID,
		host, port)
	if err != nil {
		return nil, err
	}
	slog.Info("pipe authorized", "jti", claims.JTI, "organization_id", claims.OrganizationID,
		"integration_id", claims.IntegrationID, "consumer_id", claims.ConsumerID,
		"session_id", claims.SessionID, "target", r.Host)
	authority := net.JoinHostPort(host, strconv.Itoa(int(port)))
	if host == rawpipe.ProbeHost && authority != rawpipe.ProbeAuthority {
		// Never dialed: a customer resolver might answer for the name.
		return nil, rawpipe.Errorf(rawpipe.WrongDestination, "probes are on port 443")
	}
	if !s.pipes.Add(s.MaxPipes) {
		return nil, rawpipe.Errorf(rawpipe.Capacity, "pipe cap reached")
	}
	return &url.URL{Host: authority}, nil
}

// intercept runs the pipe's TLS and serves the protocol it negotiated until
// the Integration Proxy closes it, it idles out, or it reaches MaxLifetime.
func (s *Server) intercept(ctx context.Context, conn *halfconn.StreamConn, target *url.URL,
) (string, halfconn.Outcome) {
	if s.MaxLifetime > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, s.MaxLifetime)
		defer cancel()
	}
	tc := tls.Server(conn, rawpipe.PipeServerTLS(s.Certificate))
	hctx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	err := tc.HandshakeContext(hctx)
	cancel()
	if err != nil {
		slog.Info("pipe TLS failed", "error", err)
		return "", halfconn.CallerAborted
	}
	// The server does not end its connection when its context does.
	defer context.AfterFunc(ctx, func() { _ = tc.Close() })()
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	protocols.SetHTTP2(true)
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			s.request(w, r, target)
		}),
		Protocols: protocols,
		HTTP2: &http.HTTP2Config{
			MaxConcurrentStreams:          min(s.Inner.MaxStreams, 1<<20),
			MaxReceiveBufferPerStream:     min(s.Inner.StreamWindow, 1<<30),
			MaxReceiveBufferPerConnection: min(s.Inner.ConnectionWindow, 1<<30),
		},
		ReadHeaderTimeout: handshakeTimeout,
		IdleTimeout:       s.Inner.IdleTimeout,
		BaseContext:       func(net.Listener) context.Context { return ctx },
	}
	// net/http serves HTTP/2 or HTTP/1.1 by the ALPN the handshake chose.
	_ = srv.Serve(&oneConn{conn: tc, done: conn.Closed()})
	proto := tc.ConnectionState().NegotiatedProtocol
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return proto, halfconn.Limit
	}
	return proto, halfconn.Completed
}

// request forwards one request from inside a pipe. Its authority, the port
// defaulting from its scheme, must be the pipe's: the capability is for that
// host:port only.
func (s *Server) request(w http.ResponseWriter, r *http.Request, pipe *url.URL) {
	if r.Method == http.MethodConnect {
		upstream.Refuse(w, rawpipe.ProtocolError, "CONNECT is not carried inside a pipe")
		return
	}
	scheme, authority, err := requestTarget(r)
	if err != nil {
		upstream.Refuse(w, rawpipe.ProtocolError, err.Error())
		return
	}
	r.Header.Del(rawpipe.HeaderUpstreamScheme)
	if authority != pipe.Host {
		upstream.Refuse(
			w,
			rawpipe.WrongDestination,
			"the request is not for this pipe's destination",
		)
		return
	}
	if pipe.Host == rawpipe.ProbeAuthority {
		if r.URL.Path != rawpipe.ProbePath || r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		s.Ready.ServeHTTP(w, r)
		return
	}
	s.Upstream.Forward(w, r, &url.URL{Scheme: scheme, Host: pipe.Host})
}

// requestTarget is r's scheme and canonical host:port.
func requestTarget(r *http.Request) (scheme, authority string, err error) {
	scheme, err = requestScheme(r)
	if err != nil {
		return "", "", err
	}
	host, port, err := net.SplitHostPort(r.Host)
	if err != nil {
		host, port = strings.Trim(r.Host, "[]"), "443"
		if scheme == "http" {
			port = "80"
		}
	}
	if c, ok := capability.Canonical(host); ok {
		host = c
	}
	return scheme, net.JoinHostPort(host, port), nil
}

// requestScheme is the destination's scheme for r. On HTTP/2 it is
// rawpipe.HeaderUpstreamScheme, https when absent: net/http does not show a
// handler :scheme, and r.TLS is the pipe's own TLS, not the destination's.
// On HTTP/1.1 it is the absolute-form target's; origin form names no scheme,
// so it is refused rather than guessed.
func requestScheme(r *http.Request) (string, error) {
	if r.ProtoMajor == 2 {
		switch v := r.Header.Get(rawpipe.HeaderUpstreamScheme); v {
		case "":
			return "https", nil
		case "http", "https":
			return v, nil
		}
		return "", errors.New(rawpipe.HeaderUpstreamScheme + " is http or https")
	}
	if r.URL.Scheme == "http" || r.URL.Scheme == "https" {
		return r.URL.Scheme, nil
	}
	return "", errors.New(
		"HTTP/1.1 requests in a pipe are in absolute form (GET https://host/path)")
}

// oneConn is a Listener that accepts conn once, then blocks until done, so
// http.Server serves exactly the pipe's connection.
type oneConn struct {
	conn net.Conn
	done <-chan struct{}
	once sync.Once
}

func (l *oneConn) Accept() (net.Conn, error) {
	var c net.Conn
	l.once.Do(func() { c = l.conn })
	if c != nil {
		return c, nil
	}
	<-l.done
	return nil, net.ErrClosed
}

func (l *oneConn) Close() error   { return nil }
func (l *oneConn) Addr() net.Addr { return l.conn.LocalAddr() }
