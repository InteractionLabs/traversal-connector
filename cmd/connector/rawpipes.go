package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
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
	policy, err := dialpolicy.New(dialpolicy.Config{
		RequiresInspection: func(host string, _ uint16) bool {
			return redactor.RequiresInspection(host)
		},
	})
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
			slog.Error("pipe server stopped", "err", err)
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
