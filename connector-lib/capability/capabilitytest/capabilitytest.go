// Package capabilitytest makes capability keys and claims for tests.
package capabilitytest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"time"

	"github.com/InteractionLabs/traversal-connector/connector-lib/capability"
)

// Key derives a P-256 key from seed, so tests need no key material.
func Key(seed string) *ecdsa.PrivateKey {
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
