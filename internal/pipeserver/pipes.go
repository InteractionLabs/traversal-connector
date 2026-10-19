// Package pipeserver is the connector's raw pipe side. It holds tunnels to
// Traversal's edge controller (tunnels.go) and serves each pipe the edge
// controller opens on them: verify the capability, dial the destination,
// copy bytes.
package pipeserver

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/InteractionLabs/traversal-connector/connector-lib/capability"
	"github.com/InteractionLabs/traversal-connector/connector-lib/drain"
	"github.com/InteractionLabs/traversal-connector/connector-lib/halfconn"
	"github.com/InteractionLabs/traversal-connector/connector-lib/httpserve"
	"github.com/InteractionLabs/traversal-connector/connector-lib/rawpipe"
)

// destinationDialTimeout bounds a pipe's dial to its destination.
const destinationDialTimeout = 10 * time.Second

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

// Server serves pipes on tunnels.
type Server struct {
	ConnectorID string
	Verifier    *capability.Verifier
	Policy      interface {
		Dial(ctx context.Context, host string, port uint16) (halfconn.Conn, string, error)
	}
	// MaxPipes caps the pipes open at once; zero is no cap.
	MaxPipes int
	// RequiresInspection reports hosts redaction rules cover; a raw pipe to
	// one is refused (inspection_required). Nil covers none.
	RequiresInspection func(host string) bool
	// RefuseTCP refuses every raw TCP pipe (raw_tcp_refused) while tunnels
	// stay up: the customer's switch for a connector that must only carry
	// redacted HTTP.
	RefuseTCP bool
	// Tunnels is how many tunnels share MaxPipes; 0 means 1.
	Tunnels int
	// MaxLifetime and IdleTimeout, if set, abort a pipe that is that old or
	// has moved no bytes for that long.
	MaxLifetime, IdleTimeout time.Duration
	metrics                  *metrics

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
	conn, upstream, err := s.open(r)
	if err != nil {
		reason := rawpipe.ReasonOf(err, rawpipe.DialFailed)
		s.metrics.opened(reason)
		log.Info("pipe refused", "reason", reason, "error", err)
		rawpipe.Refuse(w, reason, string(reason))
		return
	}
	defer s.pipes.Done()
	start := time.Now()
	stream, err := rawpipe.Accept(w, r)
	if err != nil {
		_ = conn.Close()
		s.metrics.acceptFailed()
		return
	}
	s.metrics.opened("")
	s.metrics.pipes.Add(context.Background(), 1)
	sent, received, outcome := halfconn.Splice(stream, halfconn.ConnEnd(conn),
		halfconn.Limits{Lifetime: s.MaxLifetime, Idle: s.IdleTimeout})
	_ = conn.Close()
	s.metrics.pipes.Add(context.Background(), -1)
	s.metrics.ended(sent, received, outcome)
	log.Info("pipe", "upstream", upstream, "outcome", outcome, "bytes_sent", sent,
		"bytes_received", received, "duration_ms", time.Since(start).Milliseconds())
	stream.Finish()
}

// open checks and admits the pipe and dials its destination.
func (s *Server) open(r *http.Request) (halfconn.Conn, string, error) {
	host, port, ok := capability.SplitAuthority(r.Host)
	switch {
	case s.pipes.Draining():
		return nil, "", rawpipe.Errorf(rawpipe.Draining, "draining")
	case r.Method != http.MethodConnect || !ok:
		return nil, "", rawpipe.Errorf(rawpipe.ProtocolError,
			"expected CONNECT to a canonical host:port")
	case s.RefuseTCP:
		return nil, "", rawpipe.Errorf(rawpipe.TCPRefused,
			"raw TCP pipes are off on this connector")
	}
	claims, err := s.Verifier.Verify(r.Header.Get(rawpipe.HeaderCapability), s.ConnectorID,
		host, port)
	if err != nil {
		return nil, "", err
	}
	slog.Info("pipe authorized", "jti", claims.JTI, "organization_id", claims.OrganizationID,
		"integration_id", claims.IntegrationID, "consumer_id", claims.ConsumerID,
		"session_id", claims.SessionID, "target", r.Host)
	if !s.pipes.Add(s.MaxPipes) {
		return nil, "", rawpipe.Errorf(rawpipe.Capacity, "pipe cap reached")
	}
	if s.RequiresInspection != nil && s.RequiresInspection(host) {
		s.pipes.Done()
		return nil, "", rawpipe.Errorf(rawpipe.InspectionRequired, "redaction rules cover the host")
	}
	ctx, cancel := context.WithTimeout(r.Context(), destinationDialTimeout)
	defer cancel()
	conn, upstream, err := s.Policy.Dial(ctx, host, port)
	if err != nil {
		s.pipes.Done()
	}
	return conn, upstream, err
}
