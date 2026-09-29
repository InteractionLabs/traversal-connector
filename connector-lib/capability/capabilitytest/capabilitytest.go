// Package capabilitytest signs connector capabilities for tests. Production
// capabilities are signed by the capability signer service with a KMS key;
// nothing outside tests may use this package.
package capabilitytest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"

	"github.com/InteractionLabs/traversal-connector/connector-lib/capability"
)

// Key derives a P-256 signing key from seed: the private scalar is
// SHA-256(seed). Deriving keys keeps private key material out of the
// repository while letting other languages reproduce the test vectors.
func Key(seed string) *ecdsa.PrivateKey {
	scalar := sha256.Sum256([]byte(seed))
	key, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), scalar[:])
	if err != nil {
		panic("capabilitytest: seed does not yield a P-256 scalar; choose another")
	}
	return key
}

// Sign returns claims as a capability signed by key under kid.
func Sign(key *ecdsa.PrivateKey, kid string, claims capability.Claims) (string, error) {
	header, err := json.Marshal(capability.Header{
		Algorithm: capability.Algorithm,
		KeyID:     kid,
		Type:      capability.TokenType,
	})
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	return SignRaw(key, header, payload)
}

// SignRaw signs arbitrary header and payload JSON, for testing how validators
// treat tokens a correct signer would never produce.
func SignRaw(key *ecdsa.PrivateKey, header, payload []byte) (string, error) {
	signingInput := encode(header) + "." + encode(payload)
	digest := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		return "", err
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return signingInput + "." + encode(sig), nil
}

func encode(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}
