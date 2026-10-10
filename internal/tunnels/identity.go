package tunnels

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"regexp"
)

// Identity is who this connector is to a Traversal tunnel endpoint: the
// tenant (org) from the client certificate's SPIFFE URI SAN, and the
// connector ID it claims within that org.
//
// The tunnel endpoint binds a tunnel to the certificate's org, so a
// connector can never register under another org. Production certificates
// are org-scoped, shared by every connector of the org, so the endpoint
// cannot tell those connectors apart: any holder of an org's certificate
// can claim any connector ID within that org. That is a known limit until
// per-connector handshake tokens bind the connector ID too.
type Identity struct {
	ConnectorID string
	TenantID    string
}

// ErrNoTenantIdentity means the certificate has no Traversal tenant SPIFFE
// ID, so the connector keeps to the legacy transport.
var ErrNoTenantIdentity = errors.New(
	"the client certificate has no Traversal tenant SPIFFE ID; raw pipes need " +
		"spiffe://traversal.com/tenant/<org>/<name>, optionally ending /connector/<connector>")

const uuidPattern = `[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`

// canonicalUUID is a lower-case canonical UUID: the form the tunnel
// endpoint routes connector IDs by.
var canonicalUUID = regexp.MustCompile(`^` + uuidPattern + `$`)

// tenantSAN matches a Traversal tenant SPIFFE ID: org-scoped
// (.../tenant/<org>/<name>) or workload-scoped (.../<name>/<kind>/<id>),
// the shapes Traversal's gateways accept.
var tenantSAN = regexp.MustCompile(
	`^spiffe://traversal\.com/tenant/(` + uuidPattern + `)/[^/]+` +
		`(?:/(connector|processor)/(` + uuidPattern + `))?$`)

// IdentityFromCertificate reads the connector identity from a PEM client
// certificate. connectorID is TRAVERSAL_CONNECTOR_ID, the ID the connector
// already presents to the legacy controller; it must be a lower-case
// canonical UUID.
//
// The tenant always comes from the certificate. An org-scoped certificate
// names no connector, so the connector ID is connectorID, trusted within
// the org (see Identity). A connector-scoped certificate must name
// connectorID. Processor certificates are refused.
func IdentityFromCertificate(certPEM []byte, connectorID string) (Identity, error) {
	if !canonicalUUID.MatchString(connectorID) {
		return Identity{}, fmt.Errorf(
			"TRAVERSAL_CONNECTOR_ID %q is not a lower-case canonical UUID; raw pipes need one",
			connectorID)
	}
	cert, err := parseLeaf(certPEM)
	if err != nil {
		return Identity{}, err
	}
	// The tunnel endpoint reads the first URI SAN. With more than one, a
	// certificate accepted here could be refused there, so require exactly
	// one: both sides then read the same SAN.
	switch len(cert.URIs) {
	case 0:
		return Identity{}, ErrNoTenantIdentity
	case 1:
	default:
		return Identity{}, fmt.Errorf(
			"the client certificate has %d URI SANs; raw pipes need exactly one, "+
				"its Traversal tenant SPIFFE ID", len(cert.URIs))
	}
	m := tenantSAN.FindStringSubmatch(cert.URIs[0].String())
	switch {
	case m == nil:
		return Identity{}, ErrNoTenantIdentity
	case m[2] == "processor":
		return Identity{}, errors.New(
			"the client certificate is a processor's; raw pipes need an org- or connector-scoped one",
		)
	case m[2] == "connector" && m[3] != connectorID:
		return Identity{}, fmt.Errorf(
			"the client certificate is for connector %s, but TRAVERSAL_CONNECTOR_ID is %s",
			m[3], connectorID)
	}
	return Identity{ConnectorID: connectorID, TenantID: m[1]}, nil
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
