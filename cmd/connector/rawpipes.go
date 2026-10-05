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
	"time"

	"github.com/InteractionLabs/traversal-connector/connector-lib/capability"
	"github.com/InteractionLabs/traversal-connector/connector-lib/dialpolicy"
	"github.com/InteractionLabs/traversal-connector/internal/client"
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
}

// startRawPipes starts serving pipes and holding tunnels. It returns nil,
// nil when this connector cannot hold tunnels yet, after saying why: raw
// pipes never stop the legacy transport from starting.
func startRawPipes(
	ctx context.Context,
	cfg *config.Config,
	redactor *redact.Redactor,
) (*rawPipes, error) {
	tunnelCfg, err := tunnelConfig(cfg)
	if err != nil {
		slog.WarnContext(ctx, "raw pipes are enabled but this connector cannot hold tunnels; "+
			"serving the legacy transport only", "reason", err.Error())
		return nil, nil
	}
	server, err := newPipeServer(cfg, redactor)
	if err != nil {
		return nil, err
	}
	manager, err := tunnels.New(tunnelCfg)
	if err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", cfg.RawPipes.Listen)
	if err != nil {
		return nil, fmt.Errorf("listen for pipes: %w", err)
	}
	// The transport outlives ctx: pipes the tunnels already carry still arrive
	// while Envoy drains, and are refused with CONNECTOR_DRAINING.
	transport, stopTransport := context.WithCancel(context.WithoutCancel(ctx))
	go func() {
		if err := server.Serve(transport, ln); err != nil {
			// The pipe server cannot recover, and a pod that stays healthy
			// without it answers every pipe with connection refused until
			// someone restarts it. Exit, so the pod restarts instead.
			slog.Error("pipe server stopped; exiting", "err", err)
			os.Exit(1)
		}
	}()
	envoyDone := make(chan struct{})
	go func() {
		defer close(envoyDone)
		if err := manager.Run(transport); err != nil {
			slog.Error("tunnels stopped", "err", err)
		}
	}()
	slog.InfoContext(ctx, "raw pipes enabled",
		"max_pipes", cfg.RawPipes.MaxPipes,
		"tunnels_per_replica", cfg.RawPipes.TunnelsPerReplica,
		"issuer", cfg.RawPipes.CapabilityIssuer,
		"max_lifetime", cfg.RawPipes.MaxLifetime,
		"idle_timeout", cfg.RawPipes.IdleTimeout)
	return &rawPipes{
		server:        server,
		tunnels:       manager,
		stopTransport: stopTransport,
		envoyDone:     envoyDone,
	}, nil
}

// readiness is the raw pipe side's readiness gate.
func (r *rawPipes) readiness() router.ReadinessGate {
	return r.tunnels.Status
}

// drain stops this connector taking pipes without cutting the ones it
// carries: GOAWAY on every tunnel so Traversal sends new pipes to another
// connector replica, a short settle for pipes already on their way, then
// refusals with CONNECTOR_DRAINING while open pipes finish.
func (r *rawPipes) drain() {
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
	discoveryClient, err := client.NewConfigHTTPClient(cfg)
	if err != nil {
		return tunnels.Config{}, err
	}
	return tunnels.Config{
		Identity:    identity,
		Dir:         cfg.RawPipes.RunDir,
		EnvoyPath:   cfg.RawPipes.EnvoyPath,
		CoreAddress: cfg.RawPipes.Listen,
		PerReplica:  cfg.RawPipes.TunnelsPerReplica,
		DiscoveryURL: (&url.URL{
			Scheme: controller.Scheme,
			Host:   controller.Host,
			Path:   "/v1/tunnels/" + cfg.ConnectorID,
		}).String(),
		DiscoveryClient:   discoveryClient,
		DiscoveryInterval: cfg.RawPipes.TunnelDiscoveryInterval,
		ConnectTo:         cfg.RawPipes.TunnelsConnectTo,
		CertPEM:           []byte(*cfg.TLSCert),
		KeyPEM:            []byte(*cfg.TLSKey),
		CAPEM:             roots,
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
		return nil, errors.New("no CA roots: the image has no system bundle and TLS_CA_BASE64 is unset")
	}
	return roots, nil
}
