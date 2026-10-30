package jws

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/asn1"
	"errors"
	"io"
	"math/big"
	"testing"
)

type testClaims struct {
	Sub string `json:"sub"`
	N   int64  `json:"n"`
}

// opaqueSigner is a crypto.Signer that, like a key management service,
// exposes only its public key and returns ASN.1 signatures.
type opaqueSigner struct{ key *ecdsa.PrivateKey }

func (s opaqueSigner) Public() crypto.PublicKey { return &s.key.PublicKey }

func (s opaqueSigner) Sign(r io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return s.key.Sign(r, digest, opts)
}

func mustKey(t *testing.T, curve elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestSignWithVerifies(t *testing.T) {
	key := mustKey(t, elliptic.P256())
	want := testClaims{Sub: "s", N: 7}
	for name, signer := range map[string]crypto.Signer{
		"private key":   key,
		"opaque signer": opaqueSigner{key},
	} {
		t.Run(name, func(t *testing.T) {
			token, err := SignWith(signer, Header{Typ: "example+jwt", Kid: "k1"}, want)
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := Parse(token, 1024, "example+jwt", false)
			if err != nil {
				t.Fatal(err)
			}
			var got testClaims
			if err := parsed.Verify(&key.PublicKey, &got, RefuseUnknown); err != nil {
				t.Fatal(err)
			}
			if got != want {
				t.Fatalf("claims = %+v, want %+v", got, want)
			}
		})
	}
}

func TestSignWithRefusesOtherKeys(t *testing.T) {
	for name, signer := range map[string]crypto.Signer{
		"P-384": mustKey(t, elliptic.P384()),
		"P-224": mustKey(t, elliptic.P224()),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := SignWith(signer, Header{Typ: "example+jwt"}, testClaims{}); !errors.Is(err, ErrSigner) {
				t.Fatalf("err = %v, want ErrSigner", err)
			}
		})
	}
	if _, err := Sign(nil, Header{Typ: "example+jwt"}, testClaims{}); !errors.Is(err, ErrSigner) {
		t.Fatalf("nil key: err = %v, want ErrSigner", err)
	}
}

func der(t *testing.T, r, s *big.Int) []byte {
	t.Helper()
	b, err := asn1.Marshal(struct{ R, S *big.Int }{r, s})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestRawSignaturePadsShortScalars(t *testing.T) {
	sig, err := rawSignature(der(t, big.NewInt(1), big.NewInt(2)))
	if err != nil {
		t.Fatal(err)
	}
	want := make([]byte, 64)
	want[31], want[63] = 1, 2
	if !bytes.Equal(sig, want) {
		t.Fatalf("sig = %x, want %x", sig, want)
	}
}

func TestRawSignatureRefusesMalformed(t *testing.T) {
	n := elliptic.P256().Params().N
	good := der(t, big.NewInt(1), big.NewInt(2))
	for name, in := range map[string][]byte{
		"not DER":       []byte("junk"),
		"trailing data": append(append([]byte{}, good...), 0),
		"zero r":        der(t, big.NewInt(0), big.NewInt(2)),
		"negative s":    der(t, big.NewInt(1), big.NewInt(-2)),
		"r = order":     der(t, n, big.NewInt(2)),
		"s above order": der(t, big.NewInt(1), new(big.Int).Add(n, big.NewInt(1))),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := rawSignature(in); err == nil {
				t.Fatal("accepted a malformed signature")
			}
		})
	}
}
