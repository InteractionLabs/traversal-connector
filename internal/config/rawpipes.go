package config

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"os"
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
	// keyIDHeader names a public key's kid inside its PEM block.
	keyIDHeader = "Key-ID"
)

// RawPipes configures raw pipes: opaque byte streams Traversal opens through
// the connector to one exact destination, each authorized by a capability.
type RawPipes struct {
	// Enabled is set by TRAVERSAL_RAW_PIPES=enabled. Disabled by default;
	// TRAVERSAL_RAW_PIPES=disabled is the customer's opt-out once it is on.
	Enabled bool
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
	// CapabilityRoots are the trusted capability root certificates
	// (TRAVERSAL_CAPABILITY_ROOTS, raw or base64-encoded PEM, or
	// TRAVERSAL_CAPABILITY_ROOTS_FILE). A capability whose x5c certificate
	// chains to one, and names this connector's controller host, is trusted
	// without its environment's key being configured. Either these or
	// CapabilityKeys are required; both may be set while moving to roots.
	CapabilityRoots []*x509.Certificate
	// EgressProxy, if set, is the http:// or https:// forward proxy raw pipes
	// reach their destinations through (TRAVERSAL_RAW_PIPES_EGRESS_PROXY).
	// Nil, the default, dials every destination directly. HTTPS_PROXY and
	// EGRESS_PROXY_URL never apply: they route the connector's own traffic.
	EgressProxy *url.URL
	// EgressProxyResolves lets raw pipes send hostnames to EgressProxy
	// (TRAVERSAL_RAW_PIPES_EGRESS_PROXY_RESOLVES=true). Which addresses a
	// hostname reaches is then the proxy's policy, not the connector's, so it
	// is off by default and only IP literals go through the proxy. Set it
	// only where the proxy refuses loopback, link-local and metadata
	// addresses itself.
	EgressProxyResolves bool
	// TunnelCount is W, the tunnels this connector holds to Traversal's tunnel
	// gateway (TRAVERSAL_TUNNEL_COUNT; the older TRAVERSAL_TUNNELS_PER_REPLICA
	// is still read when it is unset).
	TunnelCount int
	// TunnelsConnectTo, if set, replaces the address the tunnels dial, the
	// controller's host on port 443, with host:port, for PrivateLink or a
	// fixed endpoint (TRAVERSAL_TUNNELS_CONNECT_TO). SNI and certificate
	// checks still use the controller's host.
	TunnelsConnectTo string
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
		Enabled:          true,
		TunnelsConnectTo: env.GetEnvString("TRAVERSAL_TUNNELS_CONNECT_TO", ""),
	}
	var err error
	// A value that does not parse fails startup: a silent default would
	// change pipe or tunnel limits without anyone noticing.
	if cfg.TunnelCount, err = loadTunnelCount(); err != nil {
		return RawPipes{}, err
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
	if cfg.CapabilityRoots, err = loadCapabilityRoots(); err != nil {
		return RawPipes{}, err
	}
	keys, err := loadCapabilityKeys(cfg.CapabilityRoots != nil)
	if err != nil {
		return RawPipes{}, err
	}
	cfg.CapabilityKeys = keys
	issuer := env.GetEnvOptionalString("TRAVERSAL_CAPABILITY_ISSUER")
	switch {
	case issuer != nil:
		cfg.CapabilityIssuer = *issuer
	case keys != nil:
		// Pinned keys carry no issuer of their own; roots certify theirs.
		return RawPipes{}, errors.New("TRAVERSAL_CAPABILITY_ISSUER is required with " +
			"TRAVERSAL_CAPABILITY_KEYS or TRAVERSAL_CAPABILITY_KEYS_FILE")
	default:
	}
	if cfg.EgressProxy, err = parseEgressProxy(
		env.GetEnvString("TRAVERSAL_RAW_PIPES_EGRESS_PROXY", "")); err != nil {
		return RawPipes{}, err
	}
	if cfg.EgressProxyResolves, err = parseEnvBool(
		"TRAVERSAL_RAW_PIPES_EGRESS_PROXY_RESOLVES"); err != nil {
		return RawPipes{}, err
	}
	if cfg.EgressProxyResolves && cfg.EgressProxy == nil {
		return RawPipes{}, errors.New("TRAVERSAL_RAW_PIPES_EGRESS_PROXY_RESOLVES needs " +
			"TRAVERSAL_RAW_PIPES_EGRESS_PROXY")
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

// parseEnvBool reads a true/false setting, false when unset. Anything else
// is an error naming key, not a silent default.
func parseEnvBool(key string) (bool, error) {
	switch v := os.Getenv(key); v {
	case "", "false":
		return false, nil
	case "true":
		return true, nil
	default:
		return false, fmt.Errorf("%s must be true or false, got %q", key, v)
	}
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

// loadCapabilityKeys reads the pinned capability keys. They are optional
// when roots are configured.
func loadCapabilityKeys(haveRoots bool) (map[string]*ecdsa.PublicKey, error) {
	bundle, ok, err := loadPEMSetting("TRAVERSAL_CAPABILITY_KEYS")
	switch {
	case err != nil:
		return nil, err
	case !ok && haveRoots:
		return nil, nil
	case !ok:
		return nil, errors.New("TRAVERSAL_CAPABILITY_ROOTS or TRAVERSAL_CAPABILITY_KEYS " +
			"(or their _FILE forms) is required when TRAVERSAL_RAW_PIPES=enabled")
	}
	return ParseCapabilityKeys(bundle)
}

// loadCapabilityRoots reads the trusted capability roots, or nil if none are
// configured.
func loadCapabilityRoots() ([]*x509.Certificate, error) {
	bundle, ok, err := loadPEMSetting("TRAVERSAL_CAPABILITY_ROOTS")
	if err != nil || !ok {
		return nil, err
	}
	roots, err := capability.ParseRootsPEM(bundle)
	if err != nil {
		return nil, fmt.Errorf("TRAVERSAL_CAPABILITY_ROOTS: %w", err)
	}
	return roots, nil
}

// loadPEMSetting reads a PEM bundle from name (raw or base64-encoded) or from
// the file name_FILE names. ok is false when neither is set.
func loadPEMSetting(name string) ([]byte, bool, error) {
	inline := env.GetEnvOptionalString(name)
	path := env.GetEnvOptionalString(name + "_FILE")
	switch {
	case inline != nil && path != nil:
		return nil, false, fmt.Errorf("%s and %s_FILE are mutually exclusive: set only one",
			name, name)
	case inline != nil:
		return []byte(*decodeCertificate(inline)), true, nil
	case path != nil:
		contents, err := os.ReadFile(*path)
		if err != nil {
			return nil, false, fmt.Errorf("read %s_FILE: %w", name, err)
		}
		return contents, true, nil
	default:
		return nil, false, nil
	}
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
