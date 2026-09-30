package rawclient

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/InteractionLabs/traversal-connector/connector-lib/capability"
	"github.com/InteractionLabs/traversal-connector/connector-lib/dialpolicy"
	pb "github.com/InteractionLabs/traversal-connector/connector-lib/gen/connector/v1"
	"github.com/InteractionLabs/traversal-connector/connector-lib/rawtunnel"
	"github.com/InteractionLabs/traversal-connector/internal/config"
	"github.com/InteractionLabs/traversal-connector/internal/redact"
)

func newOpener(
	cfg *config.Config,
	redactor *redact.Redactor,
	policy *dialpolicy.Policy,
	metrics *rawMetrics,
	logger *slog.Logger,
	host string,
	shuttingDown func() bool,
) (*opener, error) {
	verifier, err := newVerifier(cfg, metrics)
	if err != nil {
		return nil, err
	}
	if policy == nil {
		policy, err = newPolicy(cfg, redactor)
		if err != nil {
			return nil, err
		}
	}
	return &opener{
		cfg:          cfg,
		host:         host,
		verifier:     verifier,
		policy:       policy,
		pipes:        &pipeSlots{max: cfg.RawTunnel.MaxPipesPerPod},
		metrics:      metrics,
		log:          logger,
		shuttingDown: shuttingDown,
	}, nil
}

func newVerifier(cfg *config.Config, metrics *rawMetrics) (*capability.Verifier, error) {
	raw := cfg.RawTunnel
	keys := map[string]*ecdsa.PublicKey{}
	current, err := loadKey(metrics, keySlotCurrent, raw.CurrentPublicKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("RAW_TUNNEL_CURRENT_PUBLIC_KEY: %w", err)
	}
	keys[raw.CurrentKeyID] = current
	if raw.NextKeyID != "" {
		next, err := loadKey(metrics, keySlotNext, raw.NextPublicKeyPEM)
		if err != nil {
			return nil, fmt.Errorf("RAW_TUNNEL_NEXT_PUBLIC_KEY: %w", err)
		}
		keys[raw.NextKeyID] = next
	}
	return capability.NewVerifier(capability.VerifierConfig{
		Keys:               keys,
		Issuer:             raw.Issuer,
		AllowedSubjects:    raw.AllowedSubjects,
		AllowUnknownClaims: true,
	})
}

func loadKey(metrics *rawMetrics, slot keySlot, pemText string) (*ecdsa.PublicKey, error) {
	key, err := capability.ParsePublicKeyPEM([]byte(pemText))
	metrics.keyLoad(slot, err == nil)
	return key, err
}

func newPolicy(cfg *config.Config, redactor *redact.Redactor) (*dialpolicy.Policy, error) {
	prefixes := make([]netip.Prefix, 0, len(cfg.RawTunnel.ForbiddenCIDRs))
	for _, cidr := range cfg.RawTunnel.ForbiddenCIDRs {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			return nil, fmt.Errorf("RAW_TUNNEL_FORBIDDEN_CIDRS %q: %w", cidr, err)
		}
		prefixes = append(prefixes, prefix)
	}
	return dialpolicy.New(dialpolicy.Config{
		Forbidden: prefixes,
		RequiresInspection: func(host string, _ uint16) bool {
			if redactor == nil {
				return false
			}
			if redactor.HasRulesForHost(host) {
				return true
			}
			// A host-scoped rule does not match an IP literal, so the pipe
			// would skip inspection. Refuse the address instead.
			if _, err := netip.ParseAddr(host); err == nil && redactor.HasHostScopedRule() {
				return true
			}
			return false
		},
		AllowDelegatedProxyChecks: cfg.RawTunnel.AllowDelegatedProxyChecks,
	})
}

// pipeSlots is the per-pod pipe limit. Pipes on draining tunnels count, so a
// rotation cannot grow memory without bound while old pipes finish.
type pipeSlots struct {
	mu  sync.Mutex
	n   int
	max int
}

func (s *pipeSlots) tryAcquire() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.n >= s.max {
		return false
	}
	s.n++
	return true
}

func (s *pipeSlots) release() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.n > 0 {
		s.n--
	}
}

type opener struct {
	cfg          *config.Config
	host         string
	verifier     *capability.Verifier
	policy       *dialpolicy.Policy
	pipes        *pipeSlots
	metrics      *rawMetrics
	log          *slog.Logger
	shuttingDown func() bool

	// live is every Accept still running and every pipe not yet audited.
	// stop refuses new ones so Shutdown can wait without losing a close record.
	mu   sync.Mutex
	live sync.WaitGroup
	stop bool
}

func (o *opener) accept(tunnelID string, p *rawtunnel.Pipe, open *pb.RawOpen) {
	if !o.enter() {
		o.refuse(tunnelID, open, p, nil,
			pb.RawOpenFailureReason_RAW_OPEN_FAILURE_REASON_CONNECTOR_DRAINING,
			"connector draining")
		return
	}
	defer o.leave()
	if o.shuttingDown() {
		o.refuse(tunnelID, open, p, nil,
			pb.RawOpenFailureReason_RAW_OPEN_FAILURE_REASON_CONNECTOR_DRAINING,
			"connector draining")
		return
	}
	// A TCP port does not fit this frame. Refuse before Verify so a malformed
	// open cannot consume a jti.
	port, ok := tcpPort(open)
	if !ok {
		o.refuse(tunnelID, open, p, nil,
			pb.RawOpenFailureReason_RAW_OPEN_FAILURE_REASON_PROTOCOL_ERROR,
			"port is invalid")
		return
	}
	// Reserve pod capacity before Verify so repeated capacity refusals cannot
	// exhaust a valid capability's per-jti open budget.
	if !o.pipes.tryAcquire() {
		o.refuse(tunnelID, open, p, nil,
			pb.RawOpenFailureReason_RAW_OPEN_FAILURE_REASON_CAPACITY,
			"connector pipe capacity reached")
		return
	}
	verified, err := o.verifier.Verify(open.GetCapability(), capability.Expected{
		ConnectorID: o.cfg.ConnectorID,
		Host:        open.GetHost(),
		Port:        port,
		Mode:        open.GetMode(),
	})
	if err != nil {
		o.pipes.release()
		o.logDial(err)
		var capErr *capability.Error
		if errors.As(err, &capErr) {
			o.metrics.rejected(capErr.Code)
		}
		o.refuse(tunnelID, open, p, nil, openFailure(err), failureDetail(err))
		return
	}
	o.metrics.skew(verified.ClockSkew)
	// OpenTimeout bounds dial and forward-proxy handshake before OPENED.
	// Maximum pipe lifetime (MaxLifetime) begins at OPENED / Start, not OPEN.
	dialCtx, cancel := context.WithTimeout(p.Context(), o.cfg.RawTunnel.OpenTimeout)
	defer cancel()
	conn, _, err := o.policy.Dial(
		dialCtx, verified.Claims.Host, verified.Claims.Port,
	)
	if err != nil {
		o.pipes.release()
		// Reset, tunnel loss, and shutdown cancel the pipe while dial is in
		// flight. The pipe already has a terminal reason. Recording a dial
		// refusal would blame the destination for a peer that went away.
		// Open timeout cancels only dialCtx, so a live pipe still records it.
		if p.Context().Err() != nil && !errors.Is(err, context.DeadlineExceeded) {
			return
		}
		o.logDial(err)
		o.refuse(tunnelID, open, p, &verified.Claims, dialFailure(err), dialDetail(err))
		return
	}
	counted := &countingConn{Conn: conn, onHalf: o.metrics.halfClose}
	if err := p.Start(counted); err != nil {
		o.pipes.release()
		o.closed(tunnelID, p, verified.Claims, time.Now())
		return
	}
	o.metrics.admitted()
	o.metrics.addPipe(1)
	opened := time.Now()
	claims := verified.Claims
	// Counted before Accept returns, while this call still holds live, so
	// Shutdown's Wait cannot miss the close record.
	o.track(func() {
		<-p.Done()
		o.pipes.release()
		o.metrics.addPipe(-1)
		o.closed(tunnelID, p, claims, opened)
	})
}

func (o *opener) enter() bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.stop {
		return false
	}
	o.live.Add(1)
	return true
}

func (o *opener) leave() { o.live.Done() }

func (o *opener) track(fn func()) {
	o.live.Add(1)
	go func() {
		defer o.live.Done()
		fn()
	}()
}

func (o *opener) closed(
	tunnelID string, p *rawtunnel.Pipe, claims capability.Claims, opened time.Time,
) {
	result := p.Result()
	o.metrics.closed(
		result.Reason, result.BytesSent, result.BytesReceived, time.Since(opened),
	)
	pipeAudit{
		ConnectorID:  o.cfg.ConnectorID,
		TunnelID:     tunnelID,
		PipeID:       p.ID(),
		Organization: claims.OrganizationID,
		Integration:  claims.IntegrationID,
		JTI:          claims.JTI,
		SessionID:    claims.SessionID,
		ConsumerID:   claims.ConsumerID,
		TrafficClass: claims.TrafficClass,
		Host:         claims.Host,
		Port:         uint32(claims.Port),
		Hostname:     o.host,
		Opened:       opened,
		Closed:       time.Now(),
		BytesSent:    result.BytesSent,
		BytesRecv:    result.BytesReceived,
		Outcome:      "closed",
		Reason:       result.Reason.String(),
	}.log(o.log)
}

func (o *opener) refuse(
	tunnelID string, open *pb.RawOpen, p *rawtunnel.Pipe, claims *capability.Claims,
	reason pb.RawOpenFailureReason, detail string,
) {
	_ = p.Refuse(reason, detail)
	o.metrics.refused(reason)
	now := time.Now()
	record := pipeAudit{
		ConnectorID: o.cfg.ConnectorID,
		TunnelID:    tunnelID,
		PipeID:      p.ID(),
		Host:        open.GetHost(),
		Port:        open.GetPort(),
		Hostname:    o.host,
		Opened:      now,
		Closed:      now,
		Outcome:     "refused",
		Reason:      reason.String(),
	}
	// The token is untrusted until Verify succeeds, so a refusal before that
	// records only the frame. After that, the audit uses the canonical claims.
	if claims != nil {
		record.Organization = claims.OrganizationID
		record.Integration = claims.IntegrationID
		record.JTI = claims.JTI
		record.SessionID = claims.SessionID
		record.ConsumerID = claims.ConsumerID
		record.TrafficClass = claims.TrafficClass
		record.Host = claims.Host
		record.Port = uint32(claims.Port)
	}
	record.log(o.log)
}

func tcpPort(open *pb.RawOpen) (uint16, bool) {
	port := open.GetPort()
	if port == 0 || port > 65535 {
		return 0, false
	}
	return uint16(port), true //nolint:gosec // G115: port is at most 65535
}

func openFailure(err error) pb.RawOpenFailureReason {
	var capErr *capability.Error
	if errors.As(err, &capErr) {
		return capErr.OpenFailureReason()
	}
	var refusal *dialpolicy.Refusal
	if errors.As(err, &refusal) {
		return refusal.OpenFailureReason()
	}
	return pb.RawOpenFailureReason_RAW_OPEN_FAILURE_REASON_DIAL_FAILED
}

func dialFailure(err error) pb.RawOpenFailureReason {
	if errors.Is(err, context.DeadlineExceeded) {
		return pb.RawOpenFailureReason_RAW_OPEN_FAILURE_REASON_OPEN_TIMEOUT
	}
	return openFailure(err)
}

func failureDetail(err error) string {
	var capErr *capability.Error
	if errors.As(err, &capErr) {
		return capErr.Error()
	}
	var refusal *dialpolicy.Refusal
	if errors.As(err, &refusal) {
		return refusalDetail(refusal)
	}
	return "dial failed"
}

// refusalDetail is the fixed explanation on the wire. The wrapped error can
// name a resolved address, a DNS server, or a proxy response, and that stays
// in the local log.
func refusalDetail(r *dialpolicy.Refusal) string {
	switch r.Code {
	case dialpolicy.CodeResolveFailed:
		return "name did not resolve"
	case dialpolicy.CodeForbiddenAddress, dialpolicy.CodeProxyChecksDelegated:
		return "address forbidden by policy"
	case dialpolicy.CodeInspectionRequired:
		return "destination requires inspection"
	case dialpolicy.CodeInvalidDestination:
		return "destination is invalid"
	default:
		return "dial failed"
	}
}

func (o *opener) logDial(err error) {
	var refusal *dialpolicy.Refusal
	if errors.As(err, &refusal) {
		o.log.Warn("raw dial refused", "code", string(refusal.Code), "err", refusal.Unwrap())
		return
	}
}

func dialDetail(err error) string {
	if errors.Is(err, context.DeadlineExceeded) {
		return "open timed out"
	}
	return failureDetail(err)
}

// countingConn reports a directional half-close without closing the other
// direction. The destination conn already implements CloseWrite.
type countingConn struct {
	dialpolicy.Conn
	onHalf func()
	once   sync.Once
	read   sync.Once
}

func (c *countingConn) Read(buf []byte) (int, error) {
	n, err := c.Conn.Read(buf)
	if errors.Is(err, io.EOF) {
		c.read.Do(c.onHalf)
	}
	return n, err
}

func (c *countingConn) CloseWrite() error {
	c.once.Do(c.onHalf)
	return c.Conn.CloseWrite()
}
