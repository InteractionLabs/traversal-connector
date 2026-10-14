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

	"golang.org/x/net/http2"

	"github.com/InteractionLabs/traversal-connector/connector-lib/capability"
	"github.com/InteractionLabs/traversal-connector/connector-lib/drain"
	"github.com/InteractionLabs/traversal-connector/connector-lib/halfconn"
	"github.com/InteractionLabs/traversal-connector/connector-lib/rawpipe"
)

const dialTimeout = 10 * time.Second

const (
	// streamWindow carries one pipe at full speed at WAN latency and bounds
	// what a pipe whose destination stops reading can hold.
	streamWindow = 512 << 10
	// pingAfter and pingTimeout find a tunnel whose far end is gone without
	// a FIN (a lost controller node behind a gateway that keeps the socket):
	// the connector then redials instead of holding a tunnel to nowhere.
	pingAfter   = 45 * time.Second
	pingTimeout = 15 * time.Second
)

// h2 is the tunnel's HTTP/2 server. Its stream limit is the connector's pipe
// limit per tunnel, so a pipe over it is refused as capacity rather than
// queued into open_timeout.
func (s *Server) h2(tunnels int) *http2.Server {
	perTunnel := max(1, (s.MaxPipes+int64(tunnels)-1)/int64(tunnels))
	return &http2.Server{
		// Headroom for drain requests and refusals.
		MaxConcurrentStreams:         clamp32[uint32](perTunnel+16, 1<<20),
		MaxUploadBufferPerStream:     streamWindow,
		MaxUploadBufferPerConnection: clamp32[int32](perTunnel*streamWindow, 1<<30),
		MaxReadFrameSize:             256 << 10,
		ReadIdleTimeout:              pingAfter,
		PingTimeout:                  pingTimeout,
	}
}

// clamp32 is n capped at limit, converted to a 32-bit type limit fits.
func clamp32[T int32 | uint32](n, limit int64) T {
	return T(min(max(n, 0), limit)) //nolint:gosec // limit fits T at every call
}

// Server serves pipes on tunnels.
type Server struct {
	ConnectorID string
	Verifier    *capability.Verifier
	Policy      interface {
		Dial(ctx context.Context, host string, port uint16) (halfconn.Conn, string, error)
	}
	// MaxPipes caps the pipes open at once; zero is no cap.
	MaxPipes int64
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
// the edge controller asks for a replacement tunnel. It is x/net/http2's
// ServeConn because net/http serves only connections a Listener accepts, and
// the connector dials its tunnels.
func (s *Server) ServeConn(nc net.Conn, drained func()) {
	var once sync.Once
	s.h2(max(1, s.Tunnels)).ServeConn(nc, &http2.ServeConnOpts{Handler: http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if r.Method == rawpipe.DrainMethod {
				once.Do(drained)
				return
			}
			s.serve(w, r)
		})})
}

// Drain refuses new pipes with connector_draining and waits, until ctx is
// done, for open ones to finish. It is not a GOAWAY (http.Server.Shutdown):
// tunnels stay up so a pipe already on its way gets a connector_draining
// refusal, a reason, rather than a reset.
func (s *Server) Drain(ctx context.Context) {
	s.pipes.Drain()
	if err := s.pipes.Wait(ctx); err != nil {
		slog.Warn("drain timed out; ending open pipes", "err", err)
	}
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	log := slog.With("authority", r.Host)
	conn, upstream, err := s.open(r)
	if err != nil {
		reason := rawpipe.ReasonOf(err, rawpipe.DialFailed)
		s.metrics.opened(reason)
		log.Info("pipe refused", "reason", reason, "err", err)
		w.Header().Set(rawpipe.HeaderReason, string(reason))
		w.WriteHeader(reason.Status())
		return
	}
	defer s.closed()
	start := time.Now()
	stream, err := rawpipe.Accept(w, r)
	if err != nil {
		_ = conn.Close()
		return
	}
	s.metrics.opened("")
	s.metrics.pipe(1)
	sent, received, outcome := halfconn.Splice(stream, halfconn.ConnEnd(conn),
		halfconn.Limits{Lifetime: s.MaxLifetime, Idle: s.IdleTimeout})
	_ = conn.Close()
	s.metrics.pipe(-1)
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
		return nil, "", rawpipe.Errorf(
			rawpipe.ProtocolError,
			"expected CONNECT to a canonical host:port",
		)
	case s.RefuseTCP:
		return nil, "", rawpipe.Errorf(
			rawpipe.TCPRefused,
			"raw TCP pipes are off on this connector",
		)
	}
	claims, err := s.Verifier.Verify(
		r.Header.Get(rawpipe.HeaderCapability),
		s.ConnectorID,
		host,
		port,
	)
	if err != nil {
		return nil, "", err
	}
	slog.Info("pipe authorized", "jti", claims.JTI, "organization_id", claims.OrganizationID,
		"integration_id", claims.IntegrationID, "consumer_id", claims.ConsumerID,
		"session_id", claims.SessionID, "authority", r.Host)
	if !s.pipes.Add(int(s.MaxPipes)) {
		return nil, "", rawpipe.Errorf(rawpipe.Capacity, "pipe cap reached")
	}
	if s.RequiresInspection != nil && s.RequiresInspection(host) {
		s.closed()
		return nil, "", rawpipe.Errorf(rawpipe.InspectionRequired, "redaction rules cover the host")
	}
	ctx, cancel := context.WithTimeout(r.Context(), dialTimeout)
	defer cancel()
	conn, upstream, err := s.Policy.Dial(ctx, host, port)
	if err != nil {
		s.closed()
	}
	return conn, upstream, err
}

func (s *Server) closed() { s.pipes.Done() }
