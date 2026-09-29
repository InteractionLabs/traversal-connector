package rawclient

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
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
	verifier, err := newVerifier(cfg)
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

func newVerifier(cfg *config.Config) (*capability.Verifier, error) {
	keys := map[string]*ecdsa.PublicKey{}
	current, err := parsePublicKey(cfg.RawTunnel.CurrentPublicKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("RAW_TUNNEL_CURRENT_PUBLIC_KEY: %w", err)
	}
	keys[cfg.RawTunnel.CurrentKeyID] = current
	if cfg.RawTunnel.NextKeyID != "" {
		next, err := parsePublicKey(cfg.RawTunnel.NextPublicKeyPEM)
		if err != nil {
			return nil, fmt.Errorf("RAW_TUNNEL_NEXT_PUBLIC_KEY: %w", err)
		}
		keys[cfg.RawTunnel.NextKeyID] = next
	}
	return capability.NewVerifier(capability.VerifierConfig{
		Keys:            keys,
		Issuer:          cfg.RawTunnel.Issuer,
		AllowedSubjects: cfg.RawTunnel.AllowedSubjects,
	})
}

func parsePublicKey(pemText string) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemText))
	if block == nil {
		return nil, errors.New("public key is not PEM")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(*ecdsa.PublicKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, errors.New("public key is not P-256")
	}
	return key, nil
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
			return redactor != nil && redactor.HasRulesForHost(host)
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
		o.refuse(tunnelID, open, p,
			pb.RawOpenFailureReason_RAW_OPEN_FAILURE_REASON_CONNECTOR_DRAINING,
			"connector draining")
		return
	}
	defer o.leave()
	if o.shuttingDown() {
		o.refuse(tunnelID, open, p,
			pb.RawOpenFailureReason_RAW_OPEN_FAILURE_REASON_CONNECTOR_DRAINING,
			"connector draining")
		return
	}
	verified, err := o.verifier.Verify(open.GetCapability(), capability.Expected{
		ConnectorID: o.cfg.ConnectorID,
		Host:        open.GetHost(),
		Port:        portOf(open),
		Mode:        open.GetMode(),
	})
	if err != nil {
		o.refuse(tunnelID, open, p, openFailure(err), failureDetail(err))
		return
	}
	o.metrics.skew(verified.ClockSkew)
	// Count the pipe, including ones still running on a draining tunnel,
	// before dialing so a full pod never opens another socket.
	if !o.pipes.tryAcquire() {
		o.refuse(tunnelID, open, p,
			pb.RawOpenFailureReason_RAW_OPEN_FAILURE_REASON_CAPACITY,
			"connector pipe capacity reached")
		return
	}
	conn, _, err := o.policy.Dial(
		p.Context(), verified.Claims.Host, verified.Claims.Port,
	)
	if err != nil {
		o.pipes.release()
		o.refuse(tunnelID, open, p, openFailure(err), failureDetail(err))
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
		Reason:       closeReasonName(result.Reason),
	}.log(o.log)
}

func (o *opener) refuse(
	tunnelID string, open *pb.RawOpen, p *rawtunnel.Pipe,
	reason pb.RawOpenFailureReason, detail string,
) {
	_ = p.Refuse(reason, detail)
	o.metrics.refused(reason)
	now := time.Now()
	pipeAudit{
		ConnectorID: o.cfg.ConnectorID,
		TunnelID:    tunnelID,
		PipeID:      p.ID(),
		Host:        open.GetHost(),
		Port:        open.GetPort(),
		Hostname:    o.host,
		Opened:      now,
		Closed:      now,
		Outcome:     "refused",
		Reason:      openReasonName(reason),
	}.log(o.log)
}

func portOf(open *pb.RawOpen) uint16 {
	port := open.GetPort()
	if port > 65535 {
		return 0
	}
	return uint16(port) //nolint:gosec // G115: port is at most 65535
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

func failureDetail(err error) string {
	var capErr *capability.Error
	if errors.As(err, &capErr) {
		return capErr.Error()
	}
	var refusal *dialpolicy.Refusal
	if errors.As(err, &refusal) {
		return refusal.Error()
	}
	return "dial failed"
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
