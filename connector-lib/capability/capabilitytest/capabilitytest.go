// Package capabilitytest signs connector capabilities for tests. Production
// capabilities are issued by the Integration Proxy behind a CapabilityIssuer;
// extraction to a key-isolated signer remains optional. Nothing outside tests
// may use this package.
package capabilitytest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/url"
	"time"

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

// SignChained returns claims as a capability signed by key, carrying x5c (DER
// certificates, leaf first) in its header.
func SignChained(
	key *ecdsa.PrivateKey, kid string, x5c [][]byte, claims capability.Claims,
) (string, error) {
	chain := make([]string, len(x5c))
	for i, der := range x5c {
		chain[i] = base64.StdEncoding.EncodeToString(der)
	}
	header, err := json.Marshal(capability.Header{
		Algorithm: capability.Algorithm,
		KeyID:     kid,
		Type:      capability.TokenType,
		X5C:       chain,
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

// Root is a capability root CA for tests.
type Root struct {
	Certificate *x509.Certificate
	DER         []byte
	key         *ecdsa.PrivateKey
}

// NewRoot returns a self-signed capability root valid from notBefore to
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

// EnvironmentCert describes an environment certificate. The zero
// ExtKeyUsage means code signing, as Traversal issues.
type EnvironmentCert struct {
	Key         *ecdsa.PublicKey
	Issuer      string // the issuer URI SAN; empty for none
	Hosts       []string
	NotBefore   time.Time
	NotAfter    time.Time
	ExtKeyUsage []x509.ExtKeyUsage
	IsCA        bool
}

// Issue signs spec with the root and returns the certificate's DER.
func (r *Root) Issue(spec EnvironmentCert) ([]byte, error) {
	usage := spec.ExtKeyUsage
	if usage == nil {
		usage = []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "capability signer (test)"},
		NotBefore:             spec.NotBefore,
		NotAfter:              spec.NotAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           usage,
		DNSNames:              spec.Hosts,
		BasicConstraintsValid: true,
		IsCA:                  spec.IsCA,
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
