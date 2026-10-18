// Package capabilitytest makes capability keys, claims and certificates for
// tests.
package capabilitytest

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"maps"
	"math/big"
	"net/url"
	"slices"
	"strings"
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
		Issuer: issuer, Audience: capability.Audience, Subject: capability.SubjectIntegrationProxy,
		OrganizationID: "org", IntegrationID: "integration", ConnectorID: connector,
		ConsumerID: "consumer", SessionID: "session", Host: host, Port: port,
		JTI: now.Format(time.RFC3339Nano), IssuedAt: now.Unix(),
		ExpiresAt: now.Add(time.Minute).Unix(),
	}
}

// Root is a capability root CA for tests.
type Root struct {
	Certificate *x509.Certificate
	DER         []byte
	key         *ecdsa.PrivateKey
}

// NewRoot returns a self-signed capability root, valid from notBefore to
// notAfter.
func NewRoot(key *ecdsa.PrivateKey, notBefore, notAfter time.Time) (*Root, error) {
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Traversal capability root (test)"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &Root{Certificate: cert, DER: der, key: key}, nil
}

// EnvironmentCert describes an environment certificate. Zero ExtKeyUsage
// means code signing, as Traversal issues; zero KeyUsage means
// digitalSignature.
type EnvironmentCert struct {
	Key         *ecdsa.PublicKey
	Issuer      string // the issuer URI SAN, not the iss claim; empty for none
	Hosts       []string
	NotBefore   time.Time
	NotAfter    time.Time
	KeyUsage    x509.KeyUsage
	ExtKeyUsage []x509.ExtKeyUsage
	IsCA        bool
}

// Issue signs spec with the root and returns the certificate's DER.
func (r *Root) Issue(spec EnvironmentCert) ([]byte, error) {
	usage, ext := spec.KeyUsage, spec.ExtKeyUsage
	if usage == 0 {
		usage = x509.KeyUsageDigitalSignature
	}
	if ext == nil {
		ext = []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "capability signer (test)"},
		NotBefore:             spec.NotBefore,
		NotAfter:              spec.NotAfter,
		KeyUsage:              usage,
		ExtKeyUsage:           ext,
		DNSNames:              spec.Hosts,
		BasicConstraintsValid: true,
		IsCA:                  spec.IsCA,
	}
	if spec.IsCA {
		tmpl.KeyUsage |= x509.KeyUsageCertSign
	}
	if spec.Issuer != "" {
		u, err := url.Parse(spec.Issuer)
		if err != nil {
			return nil, err
		}
		tmpl.URIs = []*url.URL{u}
	}
	return x509.CreateCertificate(rand.Reader, tmpl, r.Certificate, spec.Key, r.key)
}

// KeysPEM is keys as the bundle capability.ParseKeys reads: one PUBLIC KEY
// block per kid, in kid order.
func KeysPEM(keys map[string]*ecdsa.PublicKey) []byte {
	var b bytes.Buffer
	for _, kid := range slices.Sorted(maps.Keys(keys)) {
		der, err := x509.MarshalPKIXPublicKey(keys[kid])
		if err != nil {
			panic(err)
		}
		_ = pem.Encode(&b, &pem.Block{
			Type: "PUBLIC KEY", Headers: map[string]string{"Key-ID": kid}, Bytes: der,
		})
	}
	return b.Bytes()
}

// RootsPEM is roots as the bundle capability.ParseRootsPEM reads, in order.
func RootsPEM(roots ...*Root) []byte {
	var b bytes.Buffer
	for _, r := range roots {
		_ = pem.Encode(&b, &pem.Block{Type: "CERTIFICATE", Bytes: r.DER})
	}
	return b.Bytes()
}

// ValidRoot is a root for Key(seed), valid from an hour ago for a day.
func ValidRoot(tb testing.TB, seed string) *Root {
	tb.Helper()
	now := time.Now()
	root, err := NewRoot(Key(seed), now.Add(-time.Hour), now.Add(24*time.Hour))
	if err != nil {
		tb.Fatal(err)
	}
	return root
}

// Chained is c signed by key under kid, chained to an environment
// certificate from root for key. The certificate names host and the issuer
// URI SAN of c's environment, and is valid for the hour around now.
func Chained(
	tb testing.TB, root *Root, key *ecdsa.PrivateKey, kid, host string, c capability.Claims,
) string {
	tb.Helper()
	now := time.Now()
	der, err := root.Issue(EnvironmentCert{
		Key:    &key.PublicKey,
		Issuer: capability.IssuerURIPrefix + strings.TrimPrefix(c.Issuer, capability.IssuerPrefix),
		Hosts:  []string{host}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
	})
	if err != nil {
		tb.Fatal(err)
	}
	token, err := capability.SignChained(key, kid, [][]byte{der}, c)
	if err != nil {
		tb.Fatal(err)
	}
	return token
}
