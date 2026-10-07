package tunnels

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"regexp"
)

// Identity is who this connector is to a Traversal tunnel endpoint. The
// endpoint binds a tunnel to the connector ID and tenant in the client
// certificate's SPIFFE URI SAN, so a connector can only ever register as
// itself.
type Identity struct {
	ConnectorID string
	TenantID    string
}

// ErrNoConnectorIdentity means the certificate names a tenant but no
// connector. Tunnels need connector-scoped certificates; a tenant-only
// certificate keeps the connector on the legacy transport.
var ErrNoConnectorIdentity = errors.New(
	"the client certificate has no connector-scoped SPIFFE ID; " +
		"raw pipes need spiffe://traversal.com/tenant/<tenant>/<name>/connector/<connector>")

const uuidPattern = `[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`

// connectorSAN matches a connector-scoped SPIFFE ID. The tunnel endpoint
// extracts both IDs with the same pattern.
var connectorSAN = regexp.MustCompile(
	`^spiffe://traversal\.com/tenant/(` + uuidPattern + `)/[^/]+/connector/(` + uuidPattern + `)$`)

// IdentityFromCertificate reads the connector identity from a PEM client
// certificate and checks it names connectorID, the ID the connector already
// presents to the legacy controller.
func IdentityFromCertificate(certPEM []byte, connectorID string) (Identity, error) {
	cert, err := parseLeaf(certPEM)
	if err != nil {
		return Identity{}, err
	}
	// The tunnel endpoint reads the first URI SAN. With more than one, a
	// certificate accepted here could be refused there, so require exactly
	// one: both sides then read the same SAN.
	switch len(cert.URIs) {
	case 0:
		return Identity{}, ErrNoConnectorIdentity
	case 1:
	default:
		return Identity{}, fmt.Errorf(
			"the client certificate has %d URI SANs; raw pipes need exactly one, "+
				"its connector-scoped SPIFFE ID", len(cert.URIs))
	}
	m := connectorSAN.FindStringSubmatch(cert.URIs[0].String())
	if m == nil {
		return Identity{}, ErrNoConnectorIdentity
	}
	if m[2] != connectorID {
		return Identity{}, fmt.Errorf(
			"the client certificate is for connector %s, but TRAVERSAL_CONNECTOR_ID is %s",
			m[2], connectorID)
	}
	return Identity{ConnectorID: m[2], TenantID: m[1]}, nil
}

// parseLeaf parses the first certificate of a PEM chain: the connector's
// own.
func parseLeaf(certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("client certificate is not PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse client certificate: %w", err)
	}
	return cert, nil
}
