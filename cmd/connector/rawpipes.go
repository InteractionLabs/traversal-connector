package main

import (
	"context"
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
	"github.com/InteractionLabs/traversal-connector/internal/config"
	"github.com/InteractionLabs/traversal-connector/internal/pipes"
	"github.com/InteractionLabs/traversal-connector/internal/redact"
)

const (
	// capabilitySubject is the only caller allowed to open pipes: the
	// Integration Proxy mints every capability.
	capabilitySubject = "integration-proxy"
	// pipeDrainGrace is how long a stopping connector lets open pipes finish.
	// It stays under the pod's termination grace period (30 s by default).
	pipeDrainGrace = 25 * time.Second
)

// startRawPipes serves pipes on cfg.Listen until ctx is done. The returned
// function drains: it refuses new pipes and waits up to pipeDrainGrace for
// open ones to finish.
func startRawPipes(
	ctx context.Context,
	cfg config.RawPipes,
	connectorID string,
	redactor *redact.Redactor,
) (*pipes.Server, func(), error) {
	verifier, err := capability.NewVerifier(capability.VerifierConfig{
		Issuer:          cfg.CapabilityIssuer,
		Keys:            cfg.CapabilityKeys,
		AllowedSubjects: []string{capabilitySubject},
		// A capability claim added later must not force a customer upgrade.
		AllowUnknownClaims: true,
	})
	if err != nil {
		return nil, nil, err
	}
	policyCfg := dialpolicy.Config{
		RequiresInspection: func(host string, _ uint16) bool {
			return redactor.RequiresInspection(host)
		},
	}
	// Raw pipes dial directly unless TRAVERSAL_RAW_PIPES_EGRESS_PROXY names a
	// proxy. Hostnames through it are still refused as delegated.
	if proxy := cfg.EgressProxy; proxy != nil {
		policyCfg.Proxy = func(string, uint16) (*url.URL, error) { return proxy, nil }
	}
	policy, err := dialpolicy.New(policyCfg)
	if err != nil {
		return nil, nil, err
	}
	server, err := pipes.New(pipes.Config{
		ConnectorID: connectorID,
		Verifier:    verifier,
		Policy:      policy,
		MaxPipes:    cfg.MaxPipes,
		MaxLifetime: cfg.MaxLifetime,
		IdleTimeout: cfg.IdleTimeout,
		// Sorted, so the startup log reads the same on every pod.
		TrustedKeyIDs: slices.Sorted(maps.Keys(cfg.CapabilityKeys)),
	})
	if err != nil {
		return nil, nil, err
	}
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return nil, nil, fmt.Errorf("listen for pipes: %w", err)
	}
	// The listener outlives ctx: pipes the tunnels already carry still arrive
	// while Envoy drains, and are refused with CONNECTOR_DRAINING.
	serveCtx, stopServing := context.WithCancel(context.WithoutCancel(ctx))
	go func() {
		if err := server.Serve(serveCtx, ln); err != nil {
			// The pipe server cannot recover, and a pod that stays healthy
			// without it answers every pipe with connection refused until
			// someone restarts it. Exit, so the pod restarts instead.
			slog.Error("pipe server stopped; exiting", "err", err)
			os.Exit(1)
		}
	}()
	slog.InfoContext(ctx, "raw pipes enabled",
		"listen", cfg.Listen, "max_pipes", cfg.MaxPipes, "issuer", cfg.CapabilityIssuer,
		"max_lifetime", cfg.MaxLifetime, "idle_timeout", cfg.IdleTimeout)
	drain := func() {
		server.Drain()
		waitCtx, cancel := context.WithTimeout(context.Background(), pipeDrainGrace)
		defer cancel()
		if err := server.Wait(waitCtx); err != nil {
			slog.Warn("drain grace over; ending open pipes", "open", server.Open())
		}
		stopServing()
	}
	return server, drain, nil
}
