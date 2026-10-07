package tunnels

import (
	"crypto/x509"
	"errors"
	"fmt"
	"slices"
)

// InnerTLS is whether the tunnels' data leg runs its own TLS.
//
// Envoy's reverse tunnels authenticate with mutual TLS when the connector
// dials, but once a tunnel registers, Envoy (v1.39.2) duplicates the raw
// socket on both sides and quietly drops the dial's TLS session. From then on
// the tunnel carries pipes over whatever transport the connector's rc://
// listener and the tunnel endpoint's cluster configure, which without inner
// TLS is cleartext HTTP/2 across the internet. Inner TLS is a second
// handshake on that socket, owned by the listener, with the roles reversed:
// the connector is the TLS server and requires the tunnel endpoint's client
// certificate.
type InnerTLS int

const (
	// InnerTLSRequired runs TLS 1.3 on every tunnel's data leg. The zero
	// value, so a Config that does not say is secure.
	InnerTLSRequired InnerTLS = iota
	// InnerTLSDisabled leaves the data leg cleartext, for tunnel endpoints
	// that do not speak inner TLS yet.
	InnerTLSDisabled
)

// ParseInnerTLS reads the TRAVERSAL_TUNNEL_INNER_TLS spelling of a mode.
func ParseInnerTLS(s string) (InnerTLS, error) {
	switch s {
	case "required":
		return InnerTLSRequired, nil
	case "disabled":
		return InnerTLSDisabled, nil
	}
	return 0, fmt.Errorf("must be required or disabled, got %q", s)
}

func (m InnerTLS) String() string {
	if m == InnerTLSDisabled {
		return "disabled"
	}
	return "required"
}

// ErrCertificateNotForServers means the connector certificate's extended key
// usage forbids serving TLS, which inner TLS needs.
var ErrCertificateNotForServers = errors.New(
	"the connector certificate's extended key usage lacks serverAuth, which " +
		"tunnel inner TLS needs: the connector is the TLS server on each tunnel's " +
		"data leg. Reissue the certificate with serverAuth (as well as clientAuth), " +
		"or set TRAVERSAL_TUNNEL_INNER_TLS=disabled until it is")

// checkServesTLS checks the connector certificate may serve TLS: its
// extended key usage is absent, any, or includes serverAuth. A TLS client
// may refuse a server certificate restricted to other uses, so this says so
// at startup rather than as failed handshakes.
func checkServesTLS(certPEM []byte) error {
	cert, err := parseLeaf(certPEM)
	if err != nil {
		return err
	}
	if len(cert.ExtKeyUsage) == 0 && len(cert.UnknownExtKeyUsage) == 0 {
		return nil
	}
	if slices.Contains(cert.ExtKeyUsage, x509.ExtKeyUsageServerAuth) ||
		slices.Contains(cert.ExtKeyUsage, x509.ExtKeyUsageAny) {
		return nil
	}
	return ErrCertificateNotForServers
}
