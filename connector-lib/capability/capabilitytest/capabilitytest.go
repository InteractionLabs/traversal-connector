// Package capabilitytest makes capability keys and claims for tests.
package capabilitytest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/InteractionLabs/traversal-connector/connector-lib/capability"
)

// Key derives a P-256 key from seed, so tests need no key material. Its keys
// are guessable, so it refuses to run outside a test binary.
func Key(seed string) *ecdsa.PrivateKey {
	if !testing.Testing() {
		panic("capabilitytest: deterministic keys outside a test")
	}
	scalar := sha256.Sum256([]byte(seed))
	key, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), scalar[:])
	if err != nil {
		panic(err)
	}
	return key
}

// Claims returns valid claims from issuer for connector to host:port.
func Claims(issuer, connector, host string, port uint16) capability.Claims {
	now := time.Now()
	return capability.Claims{
		Issuer: issuer, Audience: capability.Audience, Subject: "integration-proxy",
		OrganizationID: "org", IntegrationID: "integration", ConnectorID: connector,
		ConsumerID: "consumer", SessionID: "session", Host: host, Port: port,
		JTI: now.Format(
			time.RFC3339Nano,
		), IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Minute).Unix(),
	}
}
