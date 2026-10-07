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
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/otel/metric"

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
	// IdleTimeout, if set, ends a pipe that has moved no bytes in either
	// direction for this long, aborted like MaxLifetime.
	IdleTimeout time.Duration
	// TrustedKeyIDs are the kids Verifier trusts. They are logged and counted
	// at startup, so a key rollout can be confirmed before the signer uses it.
	TrustedKeyIDs []string
	// MeterProvider records the server's metrics. Nil means the global one.
	MeterProvider metric.MeterProvider
}

// Server serves pipes. Create one with New.
type Server struct {
	cfg      Config
	h2       *h2server
	metrics  *pipeMetrics
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
	m, err := newPipeMetrics(cfg.MeterProvider)
	if err != nil {
		return nil, fmt.Errorf("pipes: metrics: %w", err)
	}
	m.keysLoaded(len(cfg.TrustedKeyIDs))
	slog.Info("trusting capability keys", "key_ids", cfg.TrustedKeyIDs)
	s := &Server{cfg: cfg, metrics: m}
	// Streams beyond the cap are refused by admission with a typed reason;
	// the HTTP/2 limit only bounds what a broken peer can start at once.
	s.h2 = &h2server{handle: s.serve, maxStreams: int(min(2*cfg.MaxPipes, 1<<20))}
	return s, nil
}

// Serve accepts connections from the connector's Envoy on ln until ctx is
// done, then returns nil. It retries transient Accept failures; any other
// error means the server cannot accept pipes again. Pipes already open keep
// running after Serve returns; see Wait.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	return s.h2.serve(ctx, ln)
}

// Drain refuses every later open with CONNECTOR_DRAINING. Open pipes continue.
func (s *Server) Drain() {
	if s.draining.CompareAndSwap(false, true) {
		s.metrics.drained()
	}
}

// Open is the number of pipes open now.
func (s *Server) Open() int64 { return s.open.Load() }

// Wait blocks until every stream handler has returned or ctx is done.
func (s *Server) Wait(ctx context.Context) error {
	return s.h2.wait(ctx)
}

// ReasonName is how a refusal reason appears on the wire and in logs: the
// enum name, lower-cased, without its prefix.
func ReasonName(r pb.RawOpenFailureReason) string {
	return lowerName(r.String(), "RAW_OPEN_FAILURE_REASON_")
}

func lowerName(enum, prefix string) string {
	return strings.ToLower(strings.TrimPrefix(enum, prefix))
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
		s.metrics.refused(reason)
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
		code := capability.CodeMalformed
		var ce *capability.Error
		if errors.As(err, &ce) {
			reason, detail, code = ce.OpenFailureReason(), string(ce.Code), ce.Code
		}
		s.metrics.rejected(code)
		refused(reason, detail)
		return
	}
	s.metrics.verified()
	claims := verified.Claims
	// Who asked, on every line from here: refusals included.
	log = log.With("jti", claims.JTI, "session_id", claims.SessionID,
		"organization_id", claims.OrganizationID, "integration_id", claims.IntegrationID,
		"consumer_id", claims.ConsumerID, "traffic_class", claims.TrafficClass)
	// Admission after verification: a refused capability never takes a slot.
	if s.open.Add(1) > s.cfg.MaxPipes {
		s.open.Add(-1)
		refused(pb.RawOpenFailureReason_RAW_OPEN_FAILURE_REASON_CAPACITY, "pipe cap reached")
		return
	}
	defer s.open.Add(-1)

	// Tied to the stream: a caller that gives up stops the dial.
	dialCtx, cancel := context.WithTimeout(st.ctx, dialTimeout)
	dst, route, err := s.cfg.Policy.Dial(dialCtx, host, port)
	cancel()
	if err != nil {
		reason, detail := pb.RawOpenFailureReason_RAW_OPEN_FAILURE_REASON_DIAL_FAILED, "dial_failed"
		var refusal *dialpolicy.Refusal
		if errors.As(err, &refusal) {
			reason, detail = refusal.OpenFailureReason(), string(refusal.Code)
		}
		refused(reason, detail)
		return
	}
	defer func() { _ = dst.Close() }()
	// A reset or a lost tunnel ends the destination too, even while nothing
	// reads the stream: after the caller's END_STREAM, or while a write to
	// the destination is blocked.
	stopAbort := context.AfterFunc(st.ctx, func() { abort(dst) })
	defer stopAbort()
	if err := st.respond("200", nil, false); err != nil {
		abort(dst)
		// The destination was dialed, so the pipe is audited, though it
		// never opened.
		log.Info("pipe",
			"upstream", upstreamName(route),
			"outcome", string(outcomeOf(st, outcomeCallerAborted)),
			"bytes_sent", 0,
			"bytes_received", 0,
			"duration_ms", time.Since(start).Milliseconds())
		return
	}
	s.metrics.opened()
	limits := startLimits(s.cfg.MaxLifetime, s.cfg.IdleTimeout, func() { st.Abort(); abort(dst) })
	result := splice(st, dst, limits.touch)
	limits.stop()
	if reached := limits.reached(); reached != "" {
		result.outcome = reached
	}
	s.metrics.closed(result, time.Since(start))
	log.Info("pipe",
		"upstream", upstreamName(route),
		"outcome", string(result.outcome),
		"bytes_sent", result.sent,
		"bytes_received", result.received,
		"duration_ms", time.Since(start).Milliseconds())
}

// upstreamName is the audited destination a route reached.
func upstreamName(route dialpolicy.Route) string {
	if route.Proxy != nil {
		return "proxy " + route.Proxy.Host
	}
	return route.Addr.String()
}

// outcome is how a pipe ended, as audited.
type outcome string

// Pipe outcomes.
const (
	outcomeCompleted         outcome = "completed"
	outcomeCallerAborted     outcome = "caller_aborted"
	outcomeUpstreamAborted   outcome = "upstream_aborted"
	outcomeMaxLifetime       outcome = "max_lifetime"
	outcomeIdleTimeout       outcome = "idle_timeout"
	outcomeTunnelUnavailable outcome = "tunnel_lost"
)

type spliceResult struct {
	outcome        outcome
	sent, received int64
}

// callerReader remembers whether reading the caller failed, so a copy error
// can be told apart from a failed write to the destination. It reports every
// byte read to touch.
type callerReader struct {
	st     *h2stream
	touch  func()
	failed bool
}

func (r *callerReader) Read(p []byte) (int, error) {
	n, err := r.st.Read(p)
	if n > 0 {
		r.touch()
	}
	if err != nil && !errors.Is(err, io.EOF) {
		r.failed = true
	}
	return n, err
}

// splice copies bytes both ways until both directions end. END_STREAM from
// the caller half-closes the destination and the destination's FIN becomes
// END_STREAM; a reset on either side aborts the other, so neither mistakes a
// failure for an end. Like TCP, the caller may keep sending after the
// destination's FIN. touch is called whenever bytes move either way.
func splice(st *h2stream, dst dialpolicy.Conn, touch func()) spliceResult {
	var callerAborted, upstreamFailed atomic.Bool
	callerDone := make(chan int64, 1)
	go func() {
		src := &callerReader{st: st, touch: touch}
		n, err := io.Copy(dst, src)
		switch {
		case err == nil:
			_ = dst.CloseWrite()
		case src.failed:
			callerAborted.Store(true)
			abort(dst)
		default:
			// The destination failed while the caller was still sending,
			// perhaps after its own FIN: the caller must hear it as a reset,
			// not keep writing into a pipe that has nowhere to go.
			upstreamFailed.Store(true)
			st.Abort()
			abort(dst)
		}
		callerDone <- n
	}()

	result := spliceResult{outcome: outcomeCompleted}
	buf := make([]byte, copyBuffer)
	for {
		n, err := dst.Read(buf)
		if n > 0 {
			touch()
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
	switch {
	case result.outcome != outcomeCompleted:
	case upstreamFailed.Load():
		result.outcome = outcomeUpstreamAborted
	case callerAborted.Load():
		result.outcome = outcomeCallerAborted
	}
	if result.outcome != outcomeCompleted {
		// A peer reset or lost tunnel aborts the destination from outside
		// the copies, which then see only the destination failing.
		result.outcome = outcomeOf(st, result.outcome)
	}
	return result
}

// outcomeOf is the outcome for a stream ended from Envoy's side, the caller
// resetting it or the tunnel being lost, or otherwise fallback.
func outcomeOf(st *h2stream, fallback outcome) outcome {
	switch cause := context.Cause(st.ctx); {
	case errors.Is(cause, errStreamReset):
		return outcomeCallerAborted
	case errors.Is(cause, errConnClosed):
		return outcomeTunnelUnavailable
	default:
		return fallback
	}
}

// limits ends a pipe at its lifetime cap or after it has idled too long,
// whichever comes first. Either one aborts the pipe through end.
type limits struct {
	start   time.Time
	idle    time.Duration
	end     func()
	last    atomic.Int64 // when bytes last moved, as time since start
	hit     atomic.Pointer[outcome]
	stopped atomic.Bool
	timers  []*time.Timer
}

// startLimits starts the timers for the limits that are set. A zero
// lifetime or idle timeout means that limit does not apply.
func startLimits(lifetime, idle time.Duration, end func()) *limits {
	l := &limits{start: time.Now(), idle: idle, end: end}
	if lifetime > 0 {
		l.timers = append(l.timers, time.AfterFunc(lifetime, func() {
			l.expire(outcomeMaxLifetime)
		}))
	}
	if idle > 0 {
		// Armed only once assigned, so the callback always sees timer.
		var timer *time.Timer
		timer = time.AfterFunc(math.MaxInt64, func() {
			quiet := time.Since(l.start) - time.Duration(l.last.Load())
			if quiet < l.idle {
				if !l.stopped.Load() {
					timer.Reset(l.idle - quiet)
				}
				return
			}
			l.expire(outcomeIdleTimeout)
		})
		timer.Reset(idle)
		l.timers = append(l.timers, timer)
	}
	return l
}

// touch records that bytes moved.
func (l *limits) touch() { l.last.Store(int64(time.Since(l.start))) }

func (l *limits) expire(o outcome) {
	if !l.stopped.Load() && l.hit.CompareAndSwap(nil, &o) {
		l.end()
	}
}

// stop ends the timers once the pipe has ended.
func (l *limits) stop() {
	l.stopped.Store(true)
	for _, t := range l.timers {
		t.Stop()
	}
}

// reached is the limit that ended the pipe, or "" if none did.
func (l *limits) reached() outcome {
	if o := l.hit.Load(); o != nil {
		return *o
	}
	return ""
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
