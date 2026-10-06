package config

import (
	"crypto/ecdsa"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/InteractionLabs/traversal-connector/connector-lib/capability"
	"github.com/InteractionLabs/traversal-connector/internal/env"
)

const (
	defaultRawPipesMax = 200
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
		Enabled:  true,
		Listen:   rawPipesListen,
		MaxPipes: env.GetEnvInt64("TRAVERSAL_RAW_PIPES_MAX", defaultRawPipesMax),
		MaxLifetime: env.GetEnvDuration(
			"TRAVERSAL_RAW_PIPES_MAX_LIFETIME", defaultRawPipesMaxLifetime),
		IdleTimeout: env.GetEnvDuration(
			"TRAVERSAL_RAW_PIPES_IDLE_TIMEOUT", defaultRawPipesIdleTimeout),
	}
	if cfg.MaxPipes <= 0 {
		return RawPipes{}, errors.New("TRAVERSAL_RAW_PIPES_MAX must be positive")
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
	return cfg, nil
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
