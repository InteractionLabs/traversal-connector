// Inside a pipe the Integration Proxy and the connector speak TLS, so the edge
// controller and edge gateway carry only ciphertext. The connector serves it
// with its tunnel certificate; inside it, it is an HTTP/2 or HTTP/1.1 forward
// proxy to the capability's destination.

package rawpipe

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
)

// Protocols inside a pipe's TLS, the connector preferring h2.
const (
	ALPNH2    = "h2"
	ALPNHTTP1 = "http/1.1"
)

// A request inside a pipe names its destination's scheme, which decides TLS
// toward the server: on h2, :scheme; on HTTP/1.1, an absolute-form target
// (GET https://host/path HTTP/1.1). Its authority, the port defaulting from
// the scheme, must be the capability's host:port. A request the connector
// refuses or cannot complete is answered with its Reason's Status and
// HeaderReason.

// The connector answers requests to ProbeAuthority itself and never dials it:
// GET https://traversal-connector.internal/readyz, on a pipe whose capability
// is for ProbeAuthority, is its readiness. The name is not an address, so it
// is no exception to the dial policy.
const (
	ProbeHost      = "traversal-connector.internal"
	ProbeAuthority = ProbeHost + ":443"
	ProbePath      = "/readyz"
)

// PipeServerTLS is the connector's side of a pipe's TLS. It asks for no client
// certificate: the capability authorizes the caller.
func PipeServerTLS(cert tls.Certificate) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{ALPNH2, ALPNHTTP1},
	}
}

// PipeClientTLS is the Integration Proxy's side of a pipe's TLS to
// connectorID of org. The connector's certificate must chain to tenantCAs and
// name a tenant SPIFFE ID of org that CheckIdentity accepts for connectorID.
//
// The certificate is the connector's client certificate, so its extended key
// usage is client authentication only; that is accepted on purpose. There is
// no pinning: the same certificate authenticated the tunnel at the edge
// gateway.
func PipeClientTLS(tenantCAs *x509.CertPool, org, connectorID string) *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{ALPNH2, ALPNHTTP1},
		// A connector certificate names a SPIFFE ID, not a host, so
		// VerifyConnection checks the chain and identity in place of the
		// host name check.
		InsecureSkipVerify: true, //nolint:gosec // VerifyConnection verifies
		VerifyConnection: func(cs tls.ConnectionState) error {
			return verifyConnector(cs.PeerCertificates, tenantCAs, org, connectorID)
		},
	}
}

func verifyConnector(chain []*x509.Certificate, roots *x509.CertPool, org, connectorID string,
) error {
	if len(chain) == 0 {
		return errors.New("rawpipe: the connector sent no certificate")
	}
	intermediates := x509.NewCertPool()
	for _, c := range chain[1:] {
		intermediates.AddCert(c)
	}
	leaf := chain[0]
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots: roots, Intermediates: intermediates,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return fmt.Errorf("rawpipe: the connector certificate: %w", err)
	}
	if len(leaf.URIs) != 1 {
		return errors.New("rawpipe: the connector certificate needs exactly one URI SAN")
	}
	san := leaf.URIs[0].String()
	if certOrg, _, ok := TenantID(san); !ok || certOrg != org {
		return fmt.Errorf("rawpipe: %q is not a SPIFFE ID of org %s", san, org)
	}
	return CheckIdentity(san, connectorID)
}
