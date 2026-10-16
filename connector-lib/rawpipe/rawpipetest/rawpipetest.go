// Package rawpipetest makes tenant CAs and the certificates they issue, and
// a connector's pipe side, for tests of a pipe's peers.
package rawpipetest

import (
	"cmp"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/InteractionLabs/traversal-connector/connector-lib/capability"
	"github.com/InteractionLabs/traversal-connector/connector-lib/halfconn"
	"github.com/InteractionLabs/traversal-connector/connector-lib/httpserve"
	"github.com/InteractionLabs/traversal-connector/connector-lib/rawpipe"
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

// PipeServer is a connector's pipe side, for tests of its peer. It verifies
// a CONNECT's capability with v for the connector cert names (its
// connector-scoped SPIFFE ID), accepts it, serves PipeServerTLS with cert,
// then serves h inside, h2 or http/1.1 by ALPN. A request reaches h with
// r.URL.Scheme its destination's: on h2, rawpipe.HeaderUpstreamScheme (https
// when absent); on HTTP/1.1, the absolute-form target's.
func PipeServer(tb testing.TB, v *capability.Verifier, cert tls.Certificate, h http.Handler,
) http.HandlerFunc {
	tb.Helper()
	var connectorID string
	if cert.Leaf != nil && len(cert.Leaf.URIs) == 1 {
		_, connectorID, _ = rawpipe.TenantID(cert.Leaf.URIs[0].String())
	}
	if connectorID == "" {
		tb.Fatal("rawpipetest: PipeServer needs a connector-scoped certificate")
	}
	scheme := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor == 2 {
			r.URL.Scheme = cmp.Or(r.Header.Get(rawpipe.HeaderUpstreamScheme), "https")
		}
		h.ServeHTTP(w, r)
	})
	return func(w http.ResponseWriter, r *http.Request) {
		host, port, ok := capability.SplitAuthority(r.Host)
		if r.Method != http.MethodConnect || !ok {
			rawpipe.Refuse(w, rawpipe.ProtocolError, "expected CONNECT to a canonical host:port")
			return
		}
		_, err := v.Verify(r.Header.Get(rawpipe.HeaderCapability), connectorID, host, port)
		if err != nil {
			rawpipe.Refuse(w, rawpipe.ReasonOf(err, rawpipe.InvalidCapability), err.Error())
			return
		}
		stream, err := rawpipe.Accept(w, r)
		if err != nil {
			return
		}
		conn := halfconn.NewStreamConn(stream)
		tc := tls.Server(conn, rawpipe.PipeServerTLS(cert))
		if tc.HandshakeContext(r.Context()) == nil {
			_ = httpserve.ServeConn(&http.Server{
				Handler:           scheme,
				ReadHeaderTimeout: 10 * time.Second,
				BaseContext:       func(net.Listener) context.Context { return r.Context() },
			}, tc)
		}
		_ = conn.Close()
		conn.Wait() // the stream's CloseWrite must run before the handler returns
		stream.Finish()
	}
}
