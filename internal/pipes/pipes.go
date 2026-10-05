// Package pipes is connector-core's pipe server: the Go half of the
// connector's Envoy reverse tunnels.
//
// The connector's Envoy owns the transport (reverse tunnels to Traversal,
// mutual TLS, multiplexing, flow control) and forwards each pipe here
// unchanged, as an HTTP/2 CONNECT over loopback. This package decides: it
// verifies the capability (open limit included), admits the pipe under the
// pipe cap, applies the dial policy to resolved addresses, dials, and copies
// bytes so that every close and abort reaches the other side as what it was.
package pipes

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/InteractionLabs/traversal-connector/connector-lib/capability"
	"github.com/InteractionLabs/traversal-connector/connector-lib/dialpolicy"
	pb "github.com/InteractionLabs/traversal-connector/connector-lib/gen/connector/v1"
)

// Header names on the CONNECT stream between Traversal and the connector.
const (
	// HeaderCapability carries the signed capability authorizing the pipe.
	HeaderCapability = "x-capability"
	// HeaderReason names why an open was refused: a RawOpenFailureReason,
	// lower-cased without its prefix, such as "inspection_required".
	HeaderReason = "x-traversal-reason"
	// HeaderDetail is a fixed, payload-free explanation of a refusal.
	HeaderDetail = "x-traversal-detail"
)

// dialTimeout bounds resolving and connecting to a destination. It is well
// above the Integration Proxy's open timeout, which decides first.
const dialTimeout = 10 * time.Second

// copyBuffer is the size of each read from the destination.
const copyBuffer = 32 << 10

// Config configures a Server.
type Config struct {
	// ConnectorID is this connector's ID. Capabilities must name it.
	ConnectorID string
	// Verifier checks capabilities. It counts opens per capability.
	Verifier *capability.Verifier
	// Policy resolves and dials destinations, refusing forbidden ones.
	Policy *dialpolicy.Policy
	// MaxPipes is the most pipes open at once. Opens beyond it are refused
	// with CAPACITY.
	MaxPipes int64
	// MaxLifetime, if set, ends a pipe that has been open this long. The
	// pipe is aborted, never closed cleanly, so the caller knows to reconnect.
	MaxLifetime time.Duration
}

// Server serves pipes. Create one with New.
type Server struct {
	cfg      Config
	h2       *h2server
	draining atomic.Bool
	open     atomic.Int64
}

// New returns a Server for cfg.
func New(cfg Config) (*Server, error) {
	switch {
	case cfg.ConnectorID == "":
		return nil, errors.New("pipes: connector ID is required")
	case cfg.Verifier == nil || cfg.Policy == nil:
		return nil, errors.New("pipes: a verifier and a dial policy are required")
	case cfg.MaxPipes <= 0:
		return nil, errors.New("pipes: the pipe cap must be positive")
	}
	s := &Server{cfg: cfg}
	// Streams beyond the cap are refused by admission with a typed reason;
	// the HTTP/2 limit only bounds what a broken peer can start at once.
	s.h2 = &h2server{handle: s.serve, maxStreams: int(min(2*cfg.MaxPipes, 1<<20))}
	return s, nil
}

// Serve accepts connections from the connector's Envoy on ln until ctx is
// done. Pipes already open keep running after Serve returns; see Wait.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	return s.h2.serve(ctx, ln)
}

// Drain refuses every later open with CONNECTOR_DRAINING. Open pipes continue.
func (s *Server) Drain() { s.draining.Store(true) }

// Open is the number of pipes open now.
func (s *Server) Open() int64 { return s.open.Load() }

// Wait blocks until every stream handler has returned or ctx is done.
func (s *Server) Wait(ctx context.Context) error {
	done := make(chan struct{})
	go func() { s.h2.wg.Wait(); close(done) }()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// ReasonName is how a refusal reason appears on the wire and in logs: the
// enum name, lower-cased, without its prefix.
func ReasonName(r pb.RawOpenFailureReason) string {
	return strings.ToLower(strings.TrimPrefix(r.String(), "RAW_OPEN_FAILURE_REASON_"))
}

// refuse answers a CONNECT that will not become a pipe.
func refuse(st *h2stream, reason pb.RawOpenFailureReason, detail string) {
	_ = st.respond(strconv.Itoa(statusFor(reason)), map[string]string{
		HeaderReason: ReasonName(reason),
		HeaderDetail: detail,
	}, true)
}

// statusFor is the HTTP status that accompanies a refusal reason.
func statusFor(reason pb.RawOpenFailureReason) int {
	switch reason {
	case pb.RawOpenFailureReason_RAW_OPEN_FAILURE_REASON_INVALID_CAPABILITY,
		pb.RawOpenFailureReason_RAW_OPEN_FAILURE_REASON_UNKNOWN_KEY,
		pb.RawOpenFailureReason_RAW_OPEN_FAILURE_REASON_CAPABILITY_EXPIRED,
		pb.RawOpenFailureReason_RAW_OPEN_FAILURE_REASON_WRONG_AUDIENCE:
		return 401
	case pb.RawOpenFailureReason_RAW_OPEN_FAILURE_REASON_DNS_FAILED,
		pb.RawOpenFailureReason_RAW_OPEN_FAILURE_REASON_DIAL_FAILED:
		return 502
	case pb.RawOpenFailureReason_RAW_OPEN_FAILURE_REASON_CAPACITY,
		pb.RawOpenFailureReason_RAW_OPEN_FAILURE_REASON_CONNECTOR_DRAINING:
		return 503
	case pb.RawOpenFailureReason_RAW_OPEN_FAILURE_REASON_PROTOCOL_ERROR:
		return 400
	default:
		return 403
	}
}

func (s *Server) serve(st *h2stream) {
	start := time.Now()
	log := slog.With("connector_id", s.cfg.ConnectorID, "authority", st.authority)
	refused := func(reason pb.RawOpenFailureReason, detail string) {
		log.Info("pipe refused", "reason", ReasonName(reason), "detail", detail)
		refuse(st, reason, detail)
	}
	if s.draining.Load() {
		refused(pb.RawOpenFailureReason_RAW_OPEN_FAILURE_REASON_CONNECTOR_DRAINING, "draining")
		return
	}
	if st.method != "CONNECT" {
		refused(pb.RawOpenFailureReason_RAW_OPEN_FAILURE_REASON_PROTOCOL_ERROR, "expected CONNECT")
		return
	}
	host, port, ok := splitAuthority(st.authority)
	if !ok {
		refused(pb.RawOpenFailureReason_RAW_OPEN_FAILURE_REASON_PROTOCOL_ERROR,
			"authority must be canonical host:port")
		return
	}
	verified, err := s.cfg.Verifier.Verify(st.header[HeaderCapability], capability.Expected{
		ConnectorID: s.cfg.ConnectorID,
		Host:        host,
		Port:        port,
		Mode:        pb.RawPipeMode_RAW_PIPE_MODE_PASSTHROUGH,
	})
	if err != nil {
		reason, detail := pb.RawOpenFailureReason_RAW_OPEN_FAILURE_REASON_INVALID_CAPABILITY, "invalid"
		var ce *capability.Error
		if errors.As(err, &ce) {
			reason, detail = ce.OpenFailureReason(), string(ce.Code)
		}
		refused(reason, detail)
		return
	}
	// Admission after verification: a refused capability never takes a slot.
	if s.open.Add(1) > s.cfg.MaxPipes {
		s.open.Add(-1)
		refused(pb.RawOpenFailureReason_RAW_OPEN_FAILURE_REASON_CAPACITY, "pipe cap reached")
		return
	}
	defer s.open.Add(-1)
	claims := verified.Claims
	log = log.With("jti", claims.JTI, "session_id", claims.SessionID,
		"organization_id", claims.OrganizationID, "integration_id", claims.IntegrationID)

	dialCtx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	dst, route, err := s.cfg.Policy.Dial(dialCtx, host, port)
	cancel()
	if err != nil {
		reason, detail := pb.RawOpenFailureReason_RAW_OPEN_FAILURE_REASON_DIAL_FAILED, "dial_failed"
		var refusal *dialpolicy.Refusal
		if errors.As(err, &refusal) {
			reason, detail = refusal.OpenFailureReason(), string(refusal.Code)
		}
		log.Info("pipe refused", "reason", ReasonName(reason), "detail", detail)
		refuse(st, reason, detail)
		return
	}
	defer func() { _ = dst.Close() }()
	if err := st.respond("200", nil, false); err != nil {
		abort(dst)
		return
	}
	if s.cfg.MaxLifetime > 0 {
		timer := time.AfterFunc(s.cfg.MaxLifetime, func() { st.Abort(); abort(dst) })
		defer timer.Stop()
	}
	result := splice(st, dst)
	if s.cfg.MaxLifetime > 0 && time.Since(start) >= s.cfg.MaxLifetime {
		result.outcome = outcomeMaxLifetime
	}
	log.Info("pipe",
		"upstream", route.Addr.String(),
		"outcome", result.outcome,
		"bytes_sent", result.sent,
		"bytes_received", result.received,
		"duration_ms", time.Since(start).Milliseconds())
}

// Pipe outcomes, as audited.
const (
	outcomeCompleted         = "completed"
	outcomeCallerAborted     = "caller_aborted"
	outcomeUpstreamAborted   = "upstream_aborted"
	outcomeMaxLifetime       = "max_lifetime"
	outcomeTunnelUnavailable = "tunnel_lost"
)

type spliceResult struct {
	outcome        string
	sent, received int64
}

// splice copies bytes both ways until both directions end. END_STREAM from
// the caller half-closes the destination and the destination's FIN becomes
// END_STREAM; a reset on either side aborts the other, so neither mistakes a
// failure for an end. Like TCP, the caller may keep sending after the
// destination's FIN.
func splice(st *h2stream, dst dialpolicy.Conn) spliceResult {
	var callerAborted atomic.Bool
	callerDone := make(chan int64, 1)
	go func() {
		n, err := io.Copy(dst, st)
		if err == nil {
			_ = dst.CloseWrite()
		} else {
			callerAborted.Store(true)
			abort(dst)
		}
		callerDone <- n
	}()

	result := spliceResult{outcome: outcomeCompleted}
	buf := make([]byte, copyBuffer)
	for {
		n, err := dst.Read(buf)
		if n > 0 {
			if _, werr := st.Write(buf[:n]); werr != nil {
				result.outcome = outcomeCallerAborted
				if errors.Is(werr, errConnClosed) {
					result.outcome = outcomeTunnelUnavailable
				}
				abort(dst)
				break
			}
			result.received += int64(n)
		}
		if errors.Is(err, io.EOF) {
			_ = st.CloseWrite()
			break
		}
		if err != nil {
			result.outcome = outcomeUpstreamAborted
			if callerAborted.Load() {
				result.outcome = outcomeCallerAborted
			}
			st.Abort()
			abort(dst)
			break
		}
	}
	result.sent = <-callerDone
	if callerAborted.Load() && result.outcome == outcomeCompleted {
		result.outcome = outcomeCallerAborted
	}
	return result
}

// splitAuthority parses a canonical host:port. The port must be canonical
// too, so the audited authority is the one dialed.
func splitAuthority(authority string) (string, uint16, bool) {
	host, portText, err := net.SplitHostPort(authority)
	if err != nil {
		return "", 0, false
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 || strconv.FormatUint(port, 10) != portText {
		return "", 0, false
	}
	return host, uint16(port), true
}

// abort closes conn with a TCP reset rather than a FIN, so the far end sees
// the pipe failed instead of finished.
func abort(conn net.Conn) {
	if tcp, ok := conn.(interface{ SetLinger(sec int) error }); ok {
		_ = tcp.SetLinger(0)
	}
	_ = conn.Close()
}
