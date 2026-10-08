package capability

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"net/url"
	"strings"
	"time"
)

// Chained capabilities.
//
// A connector pins Traversal's capability roots, not each environment's
// signing key. Each environment's key is certified by a root in an
// environment certificate, and the Integration Proxy sends that certificate
// in every capability's x5c header. A verifier then trusts a new environment,
// or a rotated environment key, without a connector upgrade.
//
// An environment certificate:
//   - is a leaf (not a CA) signed by a root, with the CodeSigning extended
//     key usage and the digitalSignature key usage;
//   - certifies a P-256 key;
//   - names the environment's issuer as a URI SAN,
//     spiffe://traversal.com/capability-issuer/<env>, the issuer claim its
//     capabilities carry being traversal-raw-tunnel/<env>;
//   - names the environment's controller host as a DNS SAN, which must be
//     the host the verifying connector dials. That host is what binds a
//     capability to this connector's environment.
//
// The chain is verified offline against the pinned roots: no network
// lookups, no revocation checks. Environment certificates are short-lived
// and renewed by Traversal, and disabling an environment's KMS key stops it
// signing at once.

const (
	// IssuerURIPrefix prefixes an environment certificate's issuer URI SAN.
	IssuerURIPrefix = "spiffe://traversal.com/capability-issuer/"
	// IssuerPrefix prefixes the iss claim of every capability.
	IssuerPrefix = "traversal-raw-tunnel/"
	// maxChainCertificates bounds x5c: the environment certificate and, if a
	// root ever delegates through one, an intermediate.
	maxChainCertificates = 2
)

// chainVerifier checks x5c chains against pinned roots.
type chainVerifier struct {
	roots *x509.CertPool
	host  string
}

func newChainVerifier(roots []*x509.Certificate, host string) (*chainVerifier, error) {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if host == "" {
		return nil, errors.New("capability: a controller host is required with roots")
	}
	if canonical, err := CanonicalHost(host); err != nil || canonical != host {
		return nil, errors.New("capability: controller host is not a canonical host name")
	}
	pool := x509.NewCertPool()
	for _, root := range roots {
		if root == nil || !root.IsCA {
			return nil, errors.New("capability: every root must be a CA certificate")
		}
		pool.AddCert(root)
	}
	return &chainVerifier{roots: pool, host: host}, nil
}

// verify checks an x5c chain at now and returns the environment's signing
// key and the issuer its capabilities must name.
func (c *chainVerifier) verify(x5c []string, now time.Time) (*ecdsa.PublicKey, string, error) {
	if len(x5c) == 0 || len(x5c) > maxChainCertificates {
		return nil, "", fail(CodeMalformed, "x5c must hold one or two certificates")
	}
	certs := make([]*x509.Certificate, 0, len(x5c))
	for _, encoded := range x5c {
		// RFC 7515 x5c entries are standard (not URL-safe) base64, padded.
		der, err := base64.StdEncoding.Strict().DecodeString(encoded)
		if err != nil {
			return nil, "", fail(CodeMalformed, "x5c: invalid base64")
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, "", fail(CodeMalformed, "x5c: invalid certificate")
		}
		certs = append(certs, cert)
	}
	leaf := certs[0]
	intermediates := x509.NewCertPool()
	for _, cert := range certs[1:] {
		intermediates.AddCert(cert)
	}
	// Verify checks the signatures, every certificate's validity at now, CA
	// constraints, path length, and the extended key usage.
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         c.roots,
		Intermediates: intermediates,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}); err != nil {
		return nil, "", fail(CodeUntrustedChain, "x5c does not chain to a trusted root")
	}
	if leaf.IsCA || leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return nil, "", fail(CodeUntrustedChain, "x5c leaf is not a signing certificate")
	}
	// VerifyHostname matches DNS SANs only, never the common name.
	if err := leaf.VerifyHostname(c.host); err != nil || len(leaf.IPAddresses) != 0 {
		return nil, "", fail(CodeUntrustedChain,
			"x5c certificate is for another controller host")
	}
	key, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, "", fail(CodeUntrustedChain, "x5c certificate does not certify a P-256 key")
	}
	issuer, err := certifiedIssuer(leaf.URIs)
	if err != nil {
		return nil, "", fail(CodeUntrustedChain, err.Error())
	}
	return key, issuer, nil
}

// certifiedIssuer is the iss claim an environment certificate's single
// issuer URI SAN certifies.
func certifiedIssuer(uris []*url.URL) (string, error) {
	if len(uris) != 1 {
		return "", errors.New("x5c certificate must name exactly one issuer")
	}
	env, ok := strings.CutPrefix(uris[0].String(), IssuerURIPrefix)
	if !ok || !validEnvironment(env) {
		return "", errors.New("x5c certificate names no capability issuer")
	}
	return IssuerPrefix + env, nil
}

// validEnvironment accepts lowercase environment names: letters, digits and
// hyphens, starting with a letter or digit, at most 32 characters.
func validEnvironment(env string) bool {
	if env == "" || len(env) > 32 || env[0] == '-' {
		return false
	}
	for _, r := range env {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
			return false
		}
	}
	return true
}

// ParseRootsPEM parses PEM CERTIFICATE blocks into capability roots. It
// rejects anything else in the input, so a misplaced key or truncated block
// is not silently dropped.
func ParseRootsPEM(data []byte) ([]*x509.Certificate, error) {
	var roots []*x509.Certificate
	rest := data
	for {
		block, next := pem.Decode(rest)
		if block == nil {
			if strings.TrimSpace(string(next)) != "" {
				return nil, errors.New("capability: roots: unexpected data outside PEM blocks")
			}
			break
		}
		if block.Type != "CERTIFICATE" {
			return nil, errors.New("capability: roots: expected CERTIFICATE blocks")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, errors.New("capability: roots: invalid certificate")
		}
		if !cert.IsCA {
			return nil, errors.New("capability: roots: a root is not a CA certificate")
		}
		roots = append(roots, cert)
		rest = next
	}
	if len(roots) == 0 {
		return nil, errors.New("capability: roots: no certificates")
	}
	return roots, nil
}
