// Package rawpipetest makes tenant CAs and the certificates they issue, for
// tests of a pipe's TLS.
package rawpipetest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"net/url"
	"testing"
	"time"
)

// CA is a certificate authority, such as a tenant CA.
type CA struct {
	Cert *x509.Certificate
	Key  *ecdsa.PrivateKey
}

// NewCA is a CA valid for an hour either side of now.
func NewCA(tb testing.TB) *CA {
	tb.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: serial(), IsCA: true, BasicConstraintsValid: true,
		KeyUsage:  x509.KeyUsageCertSign,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		tb.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return &CA{Cert: cert, Key: key}
}

// Pool trusts ca alone.
func (ca *CA) Pool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(ca.Cert)
	return p
}

// Connector is a connector certificate for spiffeID, valid until notAfter,
// as a tenant CA issues it: client authentication only.
func (ca *CA) Connector(tb testing.TB, spiffeID string, notAfter time.Time) tls.Certificate {
	tb.Helper()
	uri, err := url.Parse(spiffeID)
	if err != nil {
		tb.Fatal(err)
	}
	return ca.issue(tb, &x509.Certificate{URIs: []*url.URL{uri}, NotAfter: notAfter,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
}

// Server is a server certificate for host, valid for an hour.
func (ca *CA) Server(tb testing.TB, host string) tls.Certificate {
	tb.Helper()
	return ca.issue(tb, &x509.Certificate{
		DNSNames:    []string{host},
		NotAfter:    time.Now().Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
}

func (ca *CA) issue(tb testing.TB, tmpl *x509.Certificate) tls.Certificate {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl.SerialNumber = serial()
	tmpl.NotBefore = time.Now().Add(-2 * time.Hour)
	tmpl.KeyUsage = x509.KeyUsageDigitalSignature
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, &key.PublicKey, ca.Key)
	if err != nil {
		tb.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

func serial() *big.Int {
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	return n
}
