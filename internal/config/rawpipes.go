package config

import (
	"crypto/ecdsa"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/InteractionLabs/traversal-connector/connector-lib/capability"
	"github.com/InteractionLabs/traversal-connector/internal/env"
	"github.com/InteractionLabs/traversal-connector/internal/tunnels"
)

const (
	defaultRawPipesMax = 200
	// maxRawPipesMax keeps every pipe able to stall without stalling the
	// rest: connector-core's 1 GiB connection window holds 4,096 stalled
	// 256 KiB streams.
	maxRawPipesMax     = 4096
	defaultTunnelCount = 2
	// Pipe limits (TRAVERSAL_RAW_PIPES_MAX_LIFETIME, TRAVERSAL_RAW_PIPES_IDLE_TIMEOUT).
	// They match the Traversal side's, so neither side ends a pipe the other
	// would still keep.
	defaultRawPipesMaxLifetime = 4 * time.Hour
	defaultRawPipesIdleTimeout = 15 * time.Minute
	// rawPipesListen is where connector-core accepts pipes from the
	// connector's own Envoy. Loopback only: nothing outside the pod reaches
	// it, and the dial policy refuses loopback, so no pipe reaches it either.
	rawPipesListen = "127.0.0.1:9100"
	// keyIDHeader names a public key's kid inside its PEM block.
	keyIDHeader = "Key-ID"
)

// RawPipes configures raw pipes: opaque byte streams Traversal opens through
// the connector to one exact destination, each authorized by a capability.
type RawPipes struct {
	// Enabled is set by TRAVERSAL_RAW_PIPES=enabled. Disabled by default;
	// TRAVERSAL_RAW_PIPES=disabled is the customer's opt-out once it is on.
	Enabled bool
	// Listen is the loopback address connector-core serves pipes on.
	Listen string
	// MaxPipes is the most pipes open at once (TRAVERSAL_RAW_PIPES_MAX).
	MaxPipes int64
	// MaxLifetime, if positive, aborts a pipe open this long
	// (TRAVERSAL_RAW_PIPES_MAX_LIFETIME, default 4h). Zero means no cap.
	MaxLifetime time.Duration
	// IdleTimeout, if positive, aborts a pipe that has moved no bytes either
	// way for this long (TRAVERSAL_RAW_PIPES_IDLE_TIMEOUT, default 15m). Zero
	// means no cap.
	IdleTimeout time.Duration
	// CapabilityIssuer is the iss claim capabilities must carry
	// (TRAVERSAL_CAPABILITY_ISSUER).
	CapabilityIssuer string
	// CapabilityKeys are the trusted capability verification keys by kid.
	// They are provided at deploy time with the connector's credentials, never
	// over the tunnel: TRAVERSAL_CAPABILITY_KEYS (raw or base64-encoded PEM)
	// or TRAVERSAL_CAPABILITY_KEYS_FILE. Each PUBLIC KEY block names its kid
	// in a Key-ID header.
	CapabilityKeys map[string]*ecdsa.PublicKey
	// EgressProxy, if set, is the http:// or https:// forward proxy raw pipes
	// reach their destinations through (TRAVERSAL_RAW_PIPES_EGRESS_PROXY).
	// Nil, the default, dials every destination directly. HTTPS_PROXY and
	// EGRESS_PROXY_URL never apply: they route the connector's own traffic.
	EgressProxy *url.URL
	// EnvoyPath is the Envoy binary the connector supervises
	// (TRAVERSAL_ENVOY_PATH).
	EnvoyPath string
	// RunDir holds Envoy's generated configuration and a copy of the
	// connector's credentials (TRAVERSAL_RUN_DIR). It must be private and
	// writable.
	RunDir string
	// TunnelCount is W, the tunnels this connector holds to Traversal's tunnel
	// endpoint, one per Envoy worker (TRAVERSAL_TUNNEL_COUNT; the older
	// TRAVERSAL_TUNNELS_PER_REPLICA is still read when it is unset).
	TunnelCount int
	// TunnelsConnectTo, if set, replaces the address the tunnels dial, the
	// controller's host on port 443, with host:port, for PrivateLink or a
	// fixed endpoint (TRAVERSAL_TUNNELS_CONNECT_TO). SNI and certificate
	// checks still use the controller's host.
	TunnelsConnectTo string
	// TunnelStreamWindow and TunnelConnectionWindow are the tunnels' HTTP/2
	// receive windows in bytes (TRAVERSAL_TUNNEL_STREAM_WINDOW,
	// TRAVERSAL_TUNNEL_CONNECTION_WINDOW). Zero uses the defaults.
	TunnelStreamWindow, TunnelConnectionWindow int
	// TunnelInnerTLS is whether each tunnel's data leg runs its own TLS
	// (TRAVERSAL_TUNNEL_INNER_TLS: required, the default, or disabled).
	TunnelInnerTLS tunnels.InnerTLS
}

func loadRawPipes() (RawPipes, error) {
	switch mode := env.GetEnvString("TRAVERSAL_RAW_PIPES", "disabled"); mode {
	case "disabled":
		return RawPipes{}, nil
	case "enabled":
	default:
		return RawPipes{}, fmt.Errorf(
			"TRAVERSAL_RAW_PIPES must be enabled or disabled, got %q", mode)
	}
	cfg := RawPipes{
		Enabled:   true,
		Listen:    rawPipesListen,
		EnvoyPath: env.GetEnvString("TRAVERSAL_ENVOY_PATH", "envoy"),
		RunDir: env.GetEnvString("TRAVERSAL_RUN_DIR",
			filepath.Join(os.TempDir(), "traversal-tunnels")),
		TunnelsConnectTo: env.GetEnvString("TRAVERSAL_TUNNELS_CONNECT_TO", ""),
	}
	var err error
	// A value that does not parse fails startup: a silent default would
	// change pipe or tunnel limits without anyone noticing.
	if cfg.TunnelCount, err = loadTunnelCount(); err != nil {
		return RawPipes{}, err
	}
	if cfg.TunnelStreamWindow, err = env.ParseEnvInt(
		"TRAVERSAL_TUNNEL_STREAM_WINDOW", 0); err != nil {
		return RawPipes{}, err
	}
	if cfg.TunnelConnectionWindow, err = env.ParseEnvInt(
		"TRAVERSAL_TUNNEL_CONNECTION_WINDOW", 0); err != nil {
		return RawPipes{}, err
	}
	if cfg.TunnelInnerTLS, err = tunnels.ParseInnerTLS(
		env.GetEnvString("TRAVERSAL_TUNNEL_INNER_TLS", tunnels.InnerTLSRequired.String()),
	); err != nil {
		return RawPipes{}, fmt.Errorf("TRAVERSAL_TUNNEL_INNER_TLS %w", err)
	}
	if cfg.TunnelCount < 1 || cfg.TunnelCount > tunnels.MaxTunnels {
		return RawPipes{}, fmt.Errorf(
			"TRAVERSAL_TUNNEL_COUNT must be between 1 and %d", tunnels.MaxTunnels)
	}
	if cfg.TunnelsConnectTo != "" {
		if err := validateConnectTo("TRAVERSAL_TUNNELS_CONNECT_TO", cfg.TunnelsConnectTo); err != nil {
			return RawPipes{}, err
		}
	}
	if cfg.MaxPipes, err = env.ParseEnvInt64(
		"TRAVERSAL_RAW_PIPES_MAX", defaultRawPipesMax); err != nil {
		return RawPipes{}, err
	}
	if cfg.MaxLifetime, err = env.ParseEnvDuration(
		"TRAVERSAL_RAW_PIPES_MAX_LIFETIME", defaultRawPipesMaxLifetime); err != nil {
		return RawPipes{}, err
	}
	if cfg.IdleTimeout, err = env.ParseEnvDuration(
		"TRAVERSAL_RAW_PIPES_IDLE_TIMEOUT", defaultRawPipesIdleTimeout); err != nil {
		return RawPipes{}, err
	}
	if cfg.MaxPipes <= 0 || cfg.MaxPipes > maxRawPipesMax {
		return RawPipes{}, fmt.Errorf(
			"TRAVERSAL_RAW_PIPES_MAX must be between 1 and %d",
			maxRawPipesMax,
		)
	}
	if cfg.MaxLifetime < 0 || cfg.IdleTimeout < 0 {
		return RawPipes{}, errors.New("TRAVERSAL_RAW_PIPES_MAX_LIFETIME and " +
			"TRAVERSAL_RAW_PIPES_IDLE_TIMEOUT must not be negative")
	}
	issuer := env.GetEnvOptionalString("TRAVERSAL_CAPABILITY_ISSUER")
	if issuer == nil {
		return RawPipes{}, errors.New(
			"TRAVERSAL_CAPABILITY_ISSUER is required when TRAVERSAL_RAW_PIPES=enabled")
	}
	cfg.CapabilityIssuer = *issuer
	keys, err := loadCapabilityKeys()
	if err != nil {
		return RawPipes{}, err
	}
	cfg.CapabilityKeys = keys
	if cfg.EgressProxy, err = parseEgressProxy(
		env.GetEnvString("TRAVERSAL_RAW_PIPES_EGRESS_PROXY", "")); err != nil {
		return RawPipes{}, err
	}
	return cfg, nil
}

// parseEgressProxy parses TRAVERSAL_RAW_PIPES_EGRESS_PROXY. Empty means no
// proxy. Errors never quote the value, which can carry proxy credentials.
func parseEgressProxy(raw string) (*url.URL, error) {
	if raw == "" {
		return nil, nil
	}
	invalid := errors.New("TRAVERSAL_RAW_PIPES_EGRESS_PROXY must be an http:// or " +
		"https:// URL with a host, an optional port, and no path or query")
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" ||
		(u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" ||
		u.Opaque != "" {
		return nil, invalid
	}
	if port := u.Port(); port != "" {
		if n, err := strconv.Atoi(port); err != nil || n < 1 || n > maxTCPPort {
			return nil, invalid
		}
	}
	return u, nil
}

// loadTunnelCount reads TRAVERSAL_TUNNEL_COUNT, falling back to the older
// TRAVERSAL_TUNNELS_PER_REPLICA when it is unset.
func loadTunnelCount() (int, error) {
	perReplica, err := env.ParseEnvInt("TRAVERSAL_TUNNELS_PER_REPLICA", defaultTunnelCount)
	if err != nil {
		return 0, err
	}
	return env.ParseEnvInt("TRAVERSAL_TUNNEL_COUNT", perReplica)
}

func loadCapabilityKeys() (map[string]*ecdsa.PublicKey, error) {
	inline := env.GetEnvOptionalString("TRAVERSAL_CAPABILITY_KEYS")
	path := env.GetEnvOptionalString("TRAVERSAL_CAPABILITY_KEYS_FILE")
	var bundle string
	switch {
	case inline != nil && path != nil:
		return nil, errors.New("TRAVERSAL_CAPABILITY_KEYS and " +
			"TRAVERSAL_CAPABILITY_KEYS_FILE are mutually exclusive: set only one")
	case inline != nil:
		bundle = *decodeCertificate(inline)
	case path != nil:
		contents, err := os.ReadFile(*path)
		if err != nil {
			return nil, fmt.Errorf("read TRAVERSAL_CAPABILITY_KEYS_FILE: %w", err)
		}
		bundle = string(contents)
	default:
		return nil, errors.New("TRAVERSAL_CAPABILITY_KEYS or TRAVERSAL_CAPABILITY_KEYS_FILE " +
			"is required when TRAVERSAL_RAW_PIPES=enabled")
	}
	return ParseCapabilityKeys([]byte(bundle))
}

// ParseCapabilityKeys reads a PEM bundle of P-256 PUBLIC KEY blocks, each
// naming its kid in a Key-ID header:
//
//	-----BEGIN PUBLIC KEY-----
//	Key-ID: prod-2026-10
//
//	MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...
//	-----END PUBLIC KEY-----
func ParseCapabilityKeys(bundle []byte) (map[string]*ecdsa.PublicKey, error) {
	keys := map[string]*ecdsa.PublicKey{}
	rest := bundle
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "PUBLIC KEY" {
			return nil, fmt.Errorf("capability keys: unexpected PEM block %q", block.Type)
		}
		kid := strings.TrimSpace(block.Headers[keyIDHeader])
		if kid == "" {
			return nil, errors.New("capability keys: every key needs a Key-ID header")
		}
		if _, dup := keys[kid]; dup {
			return nil, fmt.Errorf("capability keys: duplicate Key-ID %q", kid)
		}
		key, err := capability.ParsePublicKeyPEM(
			pem.EncodeToMemory(&pem.Block{Type: block.Type, Bytes: block.Bytes}))
		if err != nil {
			return nil, fmt.Errorf("capability keys: %s: %w", kid, err)
		}
		keys[kid] = key
	}
	if strings.TrimSpace(string(rest)) != "" {
		return nil, errors.New("capability keys: trailing data after the last PEM block")
	}
	if len(keys) == 0 {
		return nil, errors.New("capability keys: no keys found")
	}
	return keys, nil
}
