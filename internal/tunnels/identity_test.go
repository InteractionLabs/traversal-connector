package tunnels

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/url"
	"strings"
	"testing"
	"time"
)

const (
	testConnector = "11111111-2222-4333-8444-555555555555"
	testTenant    = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
)

func certWithURIs(t *testing.T, uris ...string) []byte {
	t.Helper()
	return certWith(t, nil, uris...)
}

// certWith is a self-signed certificate with the given extended key usage
// and URI SANs.
func certWith(t *testing.T, eku []x509.ExtKeyUsage, uris ...string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "connector"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtKeyUsage:  eku,
	}
	for _, u := range uris {
		parsed, err := url.Parse(u)
		if err != nil {
			t.Fatal(err)
		}
		tmpl.URIs = append(tmpl.URIs, parsed)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keys[string(certPEM)] = key
	return certPEM
}

// keys are the private keys of the certificates certWith made.
var keys = map[string]*ecdsa.PrivateKey{}

// testKeyPEM is cert's private key, PEM, or a fresh key for nil.
func testKeyPEM(t *testing.T, cert []byte) []byte {
	t.Helper()
	key := keys[string(cert)]
	if key == nil {
		var err error
		if key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
			t.Fatal(err)
		}
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

const (
	orgSAN       = "spiffe://traversal.com/tenant/" + testTenant + "/acme"
	connectorSAN = orgSAN + "/connector/" + testConnector
)

func TestIdentityFromCertificate(t *testing.T) {
	want := Identity{ConnectorID: testConnector, TenantID: testTenant}
	for name, san := range map[string]string{"org-scoped": orgSAN, "connector-scoped": connectorSAN} {
		t.Run(name, func(t *testing.T) {
			id, err := IdentityFromCertificate(certWithURIs(t, san), testConnector)
			if err != nil || id != want {
				t.Fatalf("got %+v, %v; want %+v", id, err, want)
			}
		})
	}
	// Another connector of the same org shares the org-scoped certificate:
	// the known within-org limit.
	sibling := "99999999-2222-4333-8444-555555555555"
	id, err := IdentityFromCertificate(certWithURIs(t, orgSAN), sibling)
	if err != nil || id != (Identity{ConnectorID: sibling, TenantID: testTenant}) {
		t.Fatalf("sibling connector: %+v, %v", id, err)
	}
}

func TestIdentityRefusesCertificatesThatCannotHoldTunnels(t *testing.T) {
	for name, san := range map[string]string{
		"another connector":   orgSAN + "/connector/99999999-2222-4333-8444-555555555555",
		"processor":           orgSAN + "/processor/" + testConnector,
		"non-Traversal":       "spiffe://example.com/tenant/" + testTenant + "/acme",
		"not SPIFFE":          "https://traversal.com/tenant/" + testTenant + "/acme",
		"no org name":         "spiffe://traversal.com/tenant/" + testTenant,
		"malformed org UUID":  "spiffe://traversal.com/tenant/not-a-uuid/acme",
		"upper-case org UUID": "spiffe://traversal.com/tenant/" + strings.ToUpper(testTenant) + "/acme",
		"unknown workload":    orgSAN + "/agent/" + testConnector,
		"malformed connector": orgSAN + "/connector/not-a-uuid",
	} {
		t.Run(name, func(t *testing.T) {
			if id, err := IdentityFromCertificate(certWithURIs(t, san), testConnector); err == nil {
				t.Fatalf("accepted %s as %+v", san, id)
			}
		})
	}
	if _, err := IdentityFromCertificate([]byte("not pem"), testConnector); err == nil {
		t.Fatal("accepted garbage")
	}
}

// The tunnel gateway routes by the connector ID as a lower-case canonical UUID, so
// any other form is refused before the certificate is read.
func TestIdentityRequiresACanonicalConnectorID(t *testing.T) {
	for _, id := range []string{
		"", "connector-1", strings.ToUpper(testTenant),
		"{" + testConnector + "}", strings.ReplaceAll(testConnector, "-", ""),
	} {
		t.Run(id, func(t *testing.T) {
			for _, san := range []string{orgSAN, orgSAN + "/connector/" + id} {
				if got, err := IdentityFromCertificate(certWithURIs(t, san), id); err == nil {
					t.Fatalf("accepted connector ID %q with %s as %+v", id, san, got)
				}
			}
		})
	}
}

// The tunnel gateway reads the certificate's one URI SAN. A certificate
// with more than one could pass here and be refused there, so it is refused
// here, whichever order the SANs are in.
func TestIdentityRequiresExactlyOneURISAN(t *testing.T) {
	other := "spiffe://example.com/workload"
	for name, uris := range map[string][]string{
		"scoped first":      {connectorSAN, other},
		"scoped second":     {other, connectorSAN},
		"scoped twice":      {connectorSAN, connectorSAN},
		"org and connector": {orgSAN, connectorSAN},
		"two orgs":          {orgSAN, "spiffe://traversal.com/tenant/" + testConnector + "/other"},
	} {
		t.Run(name, func(t *testing.T) {
			if id, err := IdentityFromCertificate(certWithURIs(t, uris...), testConnector); err == nil {
				t.Fatalf("accepted %d URI SANs as %+v", len(uris), id)
			}
		})
	}
	if _, err := IdentityFromCertificate(certWithURIs(t), testConnector); !errors.Is(
		err, ErrNoTenantIdentity) {
		t.Fatalf("no URI SAN: %v", err)
	}
}

// New refuses settings that can't hold tunnels, before any dial.
func TestNewRejectsBadTunnelSettings(t *testing.T) {
	cert := certWith(t, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, orgSAN)
	id, err := IdentityFromCertificate(cert, testConnector)
	if err != nil {
		t.Fatal(err)
	}
	key := testKeyPEM(t, cert)
	base := func() Config {
		return Config{Identity: id, Endpoint: "edge.traversal.test", Tunnels: 2,
			CertPEM: cert, KeyPEM: key, CAPEM: cert, Server: nopServer{}}
	}
	if _, err := New(base()); err != nil {
		t.Fatalf("base config refused: %v", err)
	}
	for name, mutate := range map[string]func(*Config){
		"no identity":    func(c *Config) { c.Identity = Identity{} },
		"no endpoint":    func(c *Config) { c.Endpoint = "" },
		"no server":      func(c *Config) { c.Server = nil },
		"zero tunnels":   func(c *Config) { c.Tunnels = 0 },
		"too many":       func(c *Config) { c.Tunnels = MaxTunnels + 1 },
		"no roots":       func(c *Config) { c.CAPEM = nil },
		"bad connect-to": func(c *Config) { c.ConnectTo = "no-port" },
		"key mismatch":   func(c *Config) { c.KeyPEM = testKeyPEM(t, nil) },
	} {
		t.Run(name, func(t *testing.T) {
			c := base()
			mutate(&c)
			if _, err := New(c); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

type nopServer struct{}

func (nopServer) ServeConn(net.Conn, func()) {}
