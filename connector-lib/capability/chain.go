package capability

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"
)

// Chained capabilities.
//
// A connector pins Traversal's capability roots, not each environment's
// signing key. A root certifies each environment's key in an environment
// certificate, and the Integration Proxy sends that certificate in every
// capability's x5c header (RFC 7515 section 4.1.6: standard base64 DER, leaf
// first). A verifier then trusts a new environment, or a rotated environment
// key, without a connector upgrade.
//
// An environment certificate:
//   - is a leaf (not a CA) that chains to a pinned root, with the CodeSigning
//     extended key usage and the digitalSignature key usage;
//   - certifies a P-256 key;
//   - names exactly one URI SAN, spiffe://traversal.com/capability-issuer/<env>,
//     and the capabilities it signs carry the issuer traversal-raw-tunnel/<env>;
//   - names, as a DNS SAN, the controller host the verifying connector dials.
//     That host is what binds a capability to this connector's environment;
//   - is within its validity.
//
// The chain is verified offline against the pinned roots: no network
// lookups, no revocation. Environment certificates are short-lived.

// IssuerURIPrefix prefixes an environment certificate's issuer URI SAN.
const IssuerURIPrefix = "spiffe://traversal.com/capability-issuer/"

const (
	// maxChainCerts bounds x5c: the environment certificate and, should a
	// root ever delegate through one, an intermediate.
	maxChainCerts = 2
	// maxChainBytes bounds x5c's total DER. A P-256 environment certificate
	// is about 600 bytes; the bound leaves room for an intermediate and keeps
	// a chained token, with its claims, under maxTokenLen.
	maxChainBytes = 1536
	// maxEnvironmentLen bounds <env> in an issuer URI SAN.
	maxEnvironmentLen = 32
)

// Code names a refusal more precisely than its rawpipe.Reason. Match it with
// errors.Is; the wire reason stays rawpipe.InvalidCapability.
type Code string

func (c Code) Error() string { return "capability: " + string(c) }

// CodeUntrustedChain is an x5c certificate the verifier does not trust: it
// does not chain to a pinned root, is not a P-256 code-signing leaf within
// its validity, or does not name this connector's controller host and one
// capability issuer.
const CodeUntrustedChain Code = "untrusted_chain"

func untrusted(msg string) error { return fmt.Errorf("%w: %w", CodeUntrustedChain, reject(msg)) }

// chains checks x5c chains against pinned roots for one controller host.
type chains struct {
	roots *x509.CertPool
	host  string
}

func newChains(roots []*x509.Certificate, host string) (*chains, error) {
	if _, err := netip.ParseAddr(host); err == nil || !IsCanonical(host) {
		return nil, errors.New("capability: roots need a canonical controller host name")
	}
	pool := x509.NewCertPool()
	for _, root := range roots {
		if root == nil || !root.IsCA {
			return nil, errors.New("capability: every root must be a CA certificate")
		}
		pool.AddCert(root)
	}
	return &chains{roots: pool, host: host}, nil
}

// parseChain decodes x5c within its bounds, leaf first.
func parseChain(x5c []string) ([]*x509.Certificate, error) {
	if len(x5c) == 0 || len(x5c) > maxChainCerts {
		return nil, reject("x5c must hold one or two certificates")
	}
	certs := make([]*x509.Certificate, 0, len(x5c))
	total := 0
	for _, encoded := range x5c {
		der, err := base64.StdEncoding.Strict().DecodeString(encoded)
		if total += len(der); err != nil || total > maxChainBytes {
			return nil, reject("x5c is not base64 DER within its size limit")
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, reject("x5c holds an invalid certificate")
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

// verify checks a parsed chain at now and returns the environment's signing
// key and the issuer its capabilities must carry.
func (c *chains) verify(
	certs []*x509.Certificate,
	now time.Time,
) (*ecdsa.PublicKey, string, error) {
	leaf := certs[0]
	intermediates := x509.NewCertPool()
	for _, cert := range certs[1:] {
		intermediates.AddCert(cert)
	}
	// Verify checks signatures, every certificate's validity at now, CA
	// constraints, path length and the extended key usage.
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         c.roots,
		Intermediates: intermediates,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}); err != nil {
		return nil, "", untrusted("x5c does not chain to a trusted root")
	}
	if leaf.IsCA || leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return nil, "", untrusted("x5c leaf is not a signing certificate")
	}
	// VerifyHostname matches DNS SANs only, never the common name.
	if leaf.VerifyHostname(c.host) != nil || len(leaf.IPAddresses) != 0 {
		return nil, "", untrusted("x5c certificate is for another controller host")
	}
	key, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, "", untrusted("x5c certificate does not certify a P-256 key")
	}
	if len(leaf.URIs) != 1 {
		return nil, "", untrusted("x5c certificate must name exactly one issuer")
	}
	env, ok := strings.CutPrefix(leaf.URIs[0].String(), IssuerURIPrefix)
	if !ok || !validEnvironment(env) {
		return nil, "", untrusted("x5c certificate names no capability issuer")
	}
	return key, IssuerPrefix + env, nil
}

// validEnvironment accepts lower-case environment names: letters, digits and
// hyphens, not starting with a hyphen.
func validEnvironment(env string) bool {
	if env == "" || len(env) > maxEnvironmentLen || env[0] == '-' {
		return false
	}
	return strings.Trim(env, "abcdefghijklmnopqrstuvwxyz0123456789-") == ""
}

// ParseRootsPEM parses PEM CERTIFICATE blocks into capability roots. Anything
// else in data is refused, so a misplaced key or truncated block is not
// silently dropped.
func ParseRootsPEM(data []byte) ([]*x509.Certificate, error) {
	var roots []*x509.Certificate
	for rest := data; ; {
		var block *pem.Block
		if block, rest = pem.Decode(rest); block == nil {
			if strings.TrimSpace(string(rest)) != "" {
				return nil, errors.New("capability: roots: data outside PEM blocks")
			}
			break
		}
		if block.Type != "CERTIFICATE" {
			return nil, errors.New("capability: roots: expected CERTIFICATE blocks")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !cert.IsCA {
			return nil, errors.New("capability: roots: each must be a CA certificate")
		}
		roots = append(roots, cert)
	}
	if len(roots) == 0 {
		return nil, errors.New("capability: roots: no certificates")
	}
	return roots, nil
}
