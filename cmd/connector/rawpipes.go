package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/InteractionLabs/traversal-connector/connector-lib/capability"
	"github.com/InteractionLabs/traversal-connector/connector-lib/dialpolicy"
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
// endpoints use publicly trusted certificates unless TLS_CA_BASE64 adds a
// private root.
var systemRoots = []string{
	"/etc/ssl/certs/ca-certificates.crt",
	"/etc/pki/tls/certs/ca-bundle.crt",
	"/etc/ssl/cert.pem",
}

// rawPipes is the connector's raw pipe side: connector-core's pipe server and
// the Envoy tunnels that carry pipes to it.
type rawPipes struct {
	server  *pipes.Server
	tunnels *tunnels.Manager
	// stopTransport ends Envoy and the pipe listener, after the drain.
	stopTransport context.CancelFunc
	envoyDone     chan struct{}
	// failed is set when the pipe server stopped for good, and raw pipes
	// with it.
	failed    atomic.Bool
	drainOnce sync.Once
}

// startRawPipes starts serving pipes and holding tunnels. It returns nil
// when raw pipes cannot run on this connector, after saying why: raw pipes
// never stop the legacy transport, so no raw pipe failure reaches main.
func startRawPipes(
	ctx context.Context,
	cfg *config.Config,
	redactor *redact.Redactor,
) *rawPipes {
	tunnelCfg, err := tunnelConfig(cfg)
	if err != nil {
		slog.WarnContext(ctx, "raw pipes are enabled but this connector cannot hold tunnels; "+
			"serving the legacy transport only", "reason", err.Error())
		return nil
	}
	raw, err := setUpRawPipes(ctx, cfg, tunnelCfg, redactor)
	if err != nil {
		// Configuration the operator must fix, not a network that blocks
		// tunnels: an error, though the legacy transport carries on.
		slog.ErrorContext(ctx, "raw pipes are enabled but failed to start; "+
			"serving the legacy transport only", "err", err)
		return nil
	}
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
	manager, err := tunnels.New(tunnelCfg)
	if err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", cfg.RawPipes.Listen)
	if err != nil {
		return nil, fmt.Errorf("listen for pipes: %w", err)
	}
	raw := runRawPipes(ctx, server, manager, ln)
	if tunnelCfg.InnerTLS == tunnels.InnerTLSDisabled {
		slog.WarnContext(ctx, "tunnel inner TLS is disabled: pipes cross the internet in "+
			"cleartext once each tunnel is up; set TRAVERSAL_TUNNEL_INNER_TLS=required "+
			"as soon as Traversal's tunnel endpoint supports it")
	}
	slog.InfoContext(ctx, "raw pipes enabled",
		"max_pipes", cfg.RawPipes.MaxPipes,
		"tunnels", cfg.RawPipes.TunnelCount,
		"tunnel_inner_tls", tunnelCfg.InnerTLS.String(),
		"issuer", cfg.RawPipes.CapabilityIssuer,
		"max_lifetime", cfg.RawPipes.MaxLifetime,
		"idle_timeout", cfg.RawPipes.IdleTimeout)
	return raw, nil
}

// runRawPipes serves pipes on ln and runs Envoy's tunnels until drained.
func runRawPipes(
	ctx context.Context,
	server *pipes.Server,
	manager *tunnels.Manager,
	ln net.Listener,
) *rawPipes {
	// The transport outlives ctx: pipes the tunnels already carry still arrive
	// while Envoy drains, and are refused with CONNECTOR_DRAINING.
	transport, stopTransport := context.WithCancel(context.WithoutCancel(ctx))
	r := &rawPipes{
		server:        server,
		tunnels:       manager,
		stopTransport: stopTransport,
		envoyDone:     make(chan struct{}),
	}
	go r.serve(transport, ln)
	go func() {
		defer close(r.envoyDone)
		if err := manager.Run(transport); err != nil {
			slog.Error("tunnels stopped", "err", err)
		}
	}()
	return r
}

// serve runs the pipe server. If it stops for good (an Accept error it
// cannot retry), raw pipes stop with it and the legacy transport carries on:
// the drain sends GOAWAY on every tunnel and then stops Envoy, so the tunnel
// endpoint routes pipes to other connector replicas instead of answering
// them with connection refused from this one. Exiting would restart the pod
// and cut the legacy transport too, which raw pipes never do.
func (r *rawPipes) serve(ctx context.Context, ln net.Listener) {
	err := r.server.Serve(ctx, ln)
	if err == nil {
		return
	}
	slog.Error("pipe server stopped; stopping raw pipes and "+
		"serving the legacy transport only", "err", err)
	_ = ln.Close()
	r.failed.Store(true)
	r.drain()
}

// readiness is the raw pipe side's readiness gate. Once raw pipes have
// failed it no longer gates: the connector serves the legacy transport only.
func (r *rawPipes) readiness() router.ReadinessGate {
	return func(ctx context.Context) (bool, string) {
		if r.failed.Load() {
			return true, "raw pipes stopped after the pipe server failed; " +
				"serving the legacy transport only"
		}
		return r.tunnels.Status(ctx)
	}
}

// drain stops this connector taking pipes without cutting the ones it
// carries: GOAWAY on every tunnel so Traversal sends new pipes to another
// connector replica, a short settle for pipes already on their way, then
// refusals with CONNECTOR_DRAINING while open pipes finish, then Envoy
// stops. It runs once; later calls wait for the first to finish.
func (r *rawPipes) drain() { r.drainOnce.Do(r.drainNow) }

func (r *rawPipes) drainNow() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	if err := r.tunnels.Drain(ctx); err != nil {
		slog.Warn("could not drain Envoy's tunnels", "err", err)
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
	<-r.envoyDone
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
	// proxy. Hostnames through it are still refused as delegated.
	if proxy := cfg.RawPipes.EgressProxy; proxy != nil {
		policyCfg.Proxy = func(string, uint16) (*url.URL, error) { return proxy, nil }
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
		Identity:    identity,
		Dir:         cfg.RawPipes.RunDir,
		EnvoyPath:   cfg.RawPipes.EnvoyPath,
		CoreAddress: cfg.RawPipes.Listen,
		MaxPipes:    cfg.RawPipes.MaxPipes,
		Tunnels:     cfg.RawPipes.TunnelCount,
		// The tunnel endpoint answers on the controller's host: Traversal's
		// front door routes tunnels to it by ALPN.
		Endpoint:         strings.ToLower(controller.Hostname()),
		ConnectTo:        cfg.RawPipes.TunnelsConnectTo,
		StreamWindow:     cfg.RawPipes.TunnelStreamWindow,
		ConnectionWindow: cfg.RawPipes.TunnelConnectionWindow,
		CertPEM:          []byte(*cfg.TLSCert),
		KeyPEM:           []byte(*cfg.TLSKey),
		CAPEM:            roots,
		InnerTLS:         cfg.RawPipes.TunnelInnerTLS,
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
