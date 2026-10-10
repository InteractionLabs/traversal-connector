package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/InteractionLabs/traversal-connector/connector-lib/capability"
	"github.com/InteractionLabs/traversal-connector/connector-lib/dialpolicy"
	pb "github.com/InteractionLabs/traversal-connector/connector-lib/gen/connector/v1"
	"github.com/InteractionLabs/traversal-connector/internal/config"
	"github.com/InteractionLabs/traversal-connector/internal/pipes"
	"github.com/InteractionLabs/traversal-connector/internal/redact"
	"github.com/InteractionLabs/traversal-connector/internal/router"
	"github.com/InteractionLabs/traversal-connector/internal/tunnels"
)

const (
	// capabilitySubject is the only caller allowed to open pipes: the
	// Integration Proxy mints every capability.
	capabilitySubject = "integration-proxy"
	// pipeDrainGrace is how long a stopping connector lets open pipes finish.
	// It stays under the pod's termination grace period (30 s by default).
	pipeDrainGrace = 20 * time.Second
	// drainSettle is how long pipes already launched toward a draining
	// connector may still arrive after its tunnels get GOAWAY.
	drainSettle = 2 * time.Second
)

// systemRoots are where container images keep their CA bundle. Tunnel
// gateways use publicly trusted certificates unless TLS_CA_BASE64 adds a
// private root.
var systemRoots = []string{
	"/etc/ssl/certs/ca-certificates.crt",
	"/etc/pki/tls/certs/ca-bundle.crt",
	"/etc/ssl/cert.pem",
}

// rawPipes is the connector's raw pipe side: connector-core's pipe server and
// the tunnels it serves pipes on.
type rawPipes struct {
	server  *pipes.Server
	tunnels *tunnels.Manager
	// stopTransport closes the tunnels, after the drain.
	stopTransport context.CancelFunc
	tunnelsDone   chan struct{}
	drainOnce     sync.Once
}

// startRawPipes starts serving pipes and holding tunnels. It returns nil
// when raw pipes cannot run on this connector, after saying why in the log
// and through report, for metadata responses: raw pipes never stop the
// legacy transport, so no raw pipe failure reaches main.
func startRawPipes(
	ctx context.Context,
	cfg *config.Config,
	report statusReporter,
	redactor *redact.Redactor,
) *rawPipes {
	tunnelCfg, err := tunnelConfig(cfg)
	if err != nil {
		slog.WarnContext(ctx, "raw pipes are enabled but this connector cannot hold tunnels; "+
			"serving the legacy transport only", "reason", err.Error())
		reportUnavailable(report, err)
		return nil
	}
	raw, err := setUpRawPipes(ctx, cfg, tunnelCfg, redactor)
	if err != nil {
		// Configuration the operator must fix, not a network that blocks
		// tunnels: an error, though the legacy transport carries on.
		slog.ErrorContext(ctx, "raw pipes are enabled but failed to start; "+
			"serving the legacy transport only", "err", err)
		reportUnavailable(report, err)
		return nil
	}
	report(raw.status)
	return raw
}

// setUpRawPipes builds the pipe server and tunnels and starts them.
func setUpRawPipes(
	ctx context.Context,
	cfg *config.Config,
	tunnelCfg tunnels.Config,
	redactor *redact.Redactor,
) (*rawPipes, error) {
	server, err := newPipeServer(cfg, redactor)
	if err != nil {
		return nil, fmt.Errorf("pipe server: %w", err)
	}
	tunnelCfg.Server = server
	manager, err := tunnels.New(tunnelCfg)
	if err != nil {
		return nil, err
	}
	raw := runRawPipes(ctx, server, manager)
	slog.InfoContext(ctx, "raw pipes enabled",
		"max_pipes", cfg.RawPipes.MaxPipes,
		"tunnels", cfg.RawPipes.TunnelCount,
		"issuer", cfg.RawPipes.CapabilityIssuer,
		"max_lifetime", cfg.RawPipes.MaxLifetime,
		"idle_timeout", cfg.RawPipes.IdleTimeout)
	return raw, nil
}

// runRawPipes holds the tunnels, serving pipes on each, until drained.
func runRawPipes(ctx context.Context, server *pipes.Server, manager *tunnels.Manager) *rawPipes {
	// The tunnels outlive ctx: pipes already on their way still arrive while
	// the connector drains, and are refused with CONNECTOR_DRAINING.
	transport, stopTransport := context.WithCancel(context.WithoutCancel(ctx))
	r := &rawPipes{
		server:        server,
		tunnels:       manager,
		stopTransport: stopTransport,
		tunnelsDone:   make(chan struct{}),
	}
	go func() {
		defer close(r.tunnelsDone)
		if err := manager.Run(transport); err != nil {
			slog.Error("tunnels stopped", "err", err)
		}
	}()
	return r
}

// statusReporter publishes what metadata responses say about raw pipes:
// client.ConnectionManager.SetRawPipesStatus.
type statusReporter func(func() *pb.RawPipesStatus)

// reportUnavailable reports raw pipes as enabled but not running, and why.
func reportUnavailable(report statusReporter, err error) {
	unavailable := &pb.RawPipesStatus{Enabled: true, Detail: err.Error()}
	report(func() *pb.RawPipesStatus { return unavailable })
}

// status is what metadata responses report about raw pipes.
func (r *rawPipes) status() *pb.RawPipesStatus {
	up, detail := r.tunnels.TunnelsUp(context.Background())
	return &pb.RawPipesStatus{Enabled: true, TunnelsUp: up, Detail: detail}
}

// readiness is the raw pipe side's readiness gate.
func (r *rawPipes) readiness() router.ReadinessGate {
	return r.tunnels.Status
}

// drain stops this connector taking pipes without cutting the ones it
// carries: stop redialing tunnels, a short settle for pipes already on their
// way, then refusals with CONNECTOR_DRAINING, which send Traversal to another
// connector replica, while open pipes finish; then the tunnels close. It
// runs once; later calls wait for the first to finish.
func (r *rawPipes) drain() { r.drainOnce.Do(r.drainNow) }

func (r *rawPipes) drainNow() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	if err := r.tunnels.Drain(ctx); err != nil {
		slog.Warn("could not drain the tunnels", "err", err)
	}
	cancel()
	time.Sleep(drainSettle)
	r.server.Drain()
	wait, cancelWait := context.WithTimeout(context.Background(), pipeDrainGrace)
	defer cancelWait()
	if err := r.server.Wait(wait); err != nil {
		slog.Warn("drain grace over; ending open pipes", "open", r.server.Open())
	}
	r.stopTransport()
	<-r.tunnelsDone
}

func newPipeServer(cfg *config.Config, redactor *redact.Redactor) (*pipes.Server, error) {
	verifier, err := capability.NewVerifier(capability.VerifierConfig{
		Issuer:          cfg.RawPipes.CapabilityIssuer,
		Keys:            cfg.RawPipes.CapabilityKeys,
		AllowedSubjects: []string{capabilitySubject},
		// A capability claim added later must not force a customer upgrade.
		AllowUnknownClaims: true,
	})
	if err != nil {
		return nil, err
	}
	policyCfg := dialpolicy.Config{
		RequiresInspection: func(host string, _ uint16) bool {
			return redactor.RequiresInspection(host)
		},
	}
	// Raw pipes dial directly unless TRAVERSAL_RAW_PIPES_EGRESS_PROXY names a
	// proxy. Hostnames through it are refused as delegated unless the
	// operator accepts the proxy's own destination policy.
	if proxy := cfg.RawPipes.EgressProxy; proxy != nil {
		policyCfg.Proxy = func(string, uint16) (*url.URL, error) { return proxy, nil }
		policyCfg.AllowDelegatedProxyChecks = cfg.RawPipes.EgressProxyResolves
	}
	policy, err := dialpolicy.New(policyCfg)
	if err != nil {
		return nil, err
	}
	return pipes.New(pipes.Config{
		ConnectorID: cfg.ConnectorID,
		Verifier:    verifier,
		Policy:      policy,
		MaxPipes:    cfg.RawPipes.MaxPipes,
		MaxLifetime: cfg.RawPipes.MaxLifetime,
		IdleTimeout: cfg.RawPipes.IdleTimeout,
		// Sorted, so the startup log reads the same on every pod.
		TrustedKeyIDs: slices.Sorted(maps.Keys(cfg.RawPipes.CapabilityKeys)),
	})
}

// tunnelConfig derives the tunnel settings, or says why this connector
// cannot hold tunnels.
func tunnelConfig(cfg *config.Config) (tunnels.Config, error) {
	if cfg.EgressProxyURL != nil {
		// Tunnels through a customer's forward proxy are not supported yet.
		return tunnels.Config{}, errors.New("EGRESS_PROXY_URL is set")
	}
	controller, err := url.Parse(cfg.TraversalControllerURL)
	if err != nil || controller.Scheme != "https" || cfg.TLSCert == nil || cfg.TLSKey == nil {
		return tunnels.Config{}, errors.New(
			"tunnels need an https:// controller URL and a client certificate")
	}
	identity, err := tunnels.IdentityFromCertificate([]byte(*cfg.TLSCert), cfg.ConnectorID)
	if err != nil {
		return tunnels.Config{}, err
	}
	roots, err := tunnelRoots(cfg.TLSCA)
	if err != nil {
		return tunnels.Config{}, err
	}
	return tunnels.Config{
		Identity: identity,
		Tunnels:  cfg.RawPipes.TunnelCount,
		// The tunnel gateway answers on the controller's host: Traversal's
		// edge router sends tunnels to it by ALPN.
		Endpoint:  strings.ToLower(controller.Hostname()),
		ConnectTo: cfg.RawPipes.TunnelsConnectTo,
		CertPEM:   []byte(*cfg.TLSCert),
		KeyPEM:    []byte(*cfg.TLSKey),
		CAPEM:     roots,
	}, nil
}

// tunnelRoots is the system CA bundle plus any private root from
// TLS_CA_BASE64, the same trust the legacy transport uses.
func tunnelRoots(extra *string) ([]byte, error) {
	var roots []byte
	for _, path := range systemRoots {
		if data, err := os.ReadFile(path); err == nil { //nolint:gosec // fixed system paths
			roots = append(roots, data...)
			break
		}
	}
	if extra != nil {
		roots = append(append(roots, '\n'), *extra...)
	}
	if len(roots) == 0 {
		return nil, errors.New(
			"no CA roots: the image has no system bundle and TLS_CA_BASE64 is unset",
		)
	}
	return roots, nil
}
