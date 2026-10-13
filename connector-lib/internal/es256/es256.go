// Package es256 signs and verifies JWS compact serializations with ES256
// (RFC 7518 section 3.4): SHA-256 over the signing input, signed with a
// P-256 key, the signature r and s as 32 big-endian bytes each.
package es256

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"math/big"
)

// Sign returns input, the JWS signing input (header "." payload), followed by
// "." and key's signature over it.
func Sign(key *ecdsa.PrivateKey, input string) (string, error) {
	digest := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		return "", err
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return input + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// Verify reports whether sig, a JWS signature segment, is key's signature
// over input.
func Verify(key *ecdsa.PublicKey, input, sig string) bool {
	raw, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil || len(raw) != 64 {
		return false
	}
	digest := sha256.Sum256([]byte(input))
	return ecdsa.Verify(key, digest[:],
		new(big.Int).SetBytes(raw[:32]), new(big.Int).SetBytes(raw[32:]))
}
