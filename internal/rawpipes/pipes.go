// Package rawpipes is the connector's raw pipe side. It holds tunnels to
// Traversal's tunnel gateway (tunnels.go) and serves each pipe the gateway
// opens on them: verify the capability, dial the destination, copy bytes.
package rawpipes

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/http2"

	"github.com/InteractionLabs/traversal-connector/connector-lib/capability"
	"github.com/InteractionLabs/traversal-connector/connector-lib/rawpipe"
)

const dialTimeout = 10 * time.Second

// h2 has windows big enough that one pipe is not flow-control bound.
var h2 = &http2.Server{
	MaxUploadBufferPerStream:     2 << 20,
	MaxUploadBufferPerConnection: 1 << 30,
	MaxReadFrameSize:             256 << 10,
}

// Server serves pipes on tunnels.
type Server struct {
	ConnectorID string
	Verifier    *capability.Verifier
	Policy      interface {
		Dial(ctx context.Context, host string, port uint16) (rawpipe.HalfCloser, string, error)
	}
	MaxPipes int64
	// MaxLifetime and IdleTimeout, if set, abort a pipe that is that old or
	// has moved no bytes for that long.
	MaxLifetime, IdleTimeout time.Duration

	inFlight atomic.Int64
	draining atomic.Bool
	pipes    sync.WaitGroup
}

// ServeConn serves pipes on one tunnel until it closes. drained runs once if
// the gateway asks for a replacement tunnel.
func (s *Server) ServeConn(nc net.Conn, drained func()) {
	var once sync.Once
	h2.ServeConn(nc, &http2.ServeConnOpts{Handler: http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if r.Method == rawpipe.DrainMethod {
				once.Do(drained)
				return
			}
			s.serve(w, r)
		})})
}

// Drain refuses new pipes with connector_draining and waits, until ctx is
// done, for open ones to finish.
func (s *Server) Drain(ctx context.Context) {
	s.draining.Store(true)
	done := make(chan struct{})
	go func() { s.pipes.Wait(); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
		slog.Warn("drain timed out; ending open pipes", "open", s.inFlight.Load())
	}
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	log := slog.With("authority", r.Host)
	conn, upstream, err := s.open(r)
	if err != nil {
		reason := rawpipe.ReasonOf(err, rawpipe.DialFailed)
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
	sent, received, outcome := rawpipe.Splice(stream, rawpipe.Conn(conn),
		rawpipe.Limits{Lifetime: s.MaxLifetime, Idle: s.IdleTimeout})
	_ = conn.Close()
	log.Info("pipe", "upstream", upstream, "outcome", outcome, "bytes_sent", sent,
		"bytes_received", received, "duration_ms", time.Since(start).Milliseconds())
	stream.Finish()
}

// open checks and admits the pipe and dials its destination.
func (s *Server) open(r *http.Request) (rawpipe.HalfCloser, string, error) {
	host, port, ok := capability.SplitAuthority(r.Host)
	switch {
	case s.draining.Load():
		return nil, "", rawpipe.Errorf(rawpipe.Draining, "draining")
	case r.Method != http.MethodConnect || !ok:
		return nil, "", rawpipe.Errorf(
			rawpipe.ProtocolError,
			"expected CONNECT to a canonical host:port",
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
	if s.inFlight.Add(1) > s.MaxPipes {
		s.inFlight.Add(-1)
		return nil, "", rawpipe.Errorf(rawpipe.Capacity, "pipe cap reached")
	}
	s.pipes.Add(1)
	ctx, cancel := context.WithTimeout(r.Context(), dialTimeout)
	defer cancel()
	conn, upstream, err := s.Policy.Dial(ctx, host, port)
	if err != nil {
		s.closed()
	}
	return conn, upstream, err
}

func (s *Server) closed() { s.inFlight.Add(-1); s.pipes.Done() }
