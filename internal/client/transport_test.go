package client

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/InteractionLabs/traversal-connector/internal/config"
)

func ptrTo[T any](v T) *T { return &v }

// generateTestKeyPair returns a freshly-generated self-signed cert and key
// as PEM strings. Used by tests that exercise the TLS transport path, since
// tls.X509KeyPair validates that the cert and key actually pair up.
func generateTestKeyPair(t *testing.T) (certPEM, keyPEM string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(
		rand.Reader, template, template, &priv.PublicKey, priv,
	)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	certPEM = string(pem.EncodeToMemory(
		&pem.Block{Type: "CERTIFICATE", Bytes: der},
	))
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM = string(pem.EncodeToMemory(
		&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER},
	))
	return certPEM, keyPEM
}

func TestNewTransport_NoProxy(t *testing.T) {
	cfg := &config.Config{
		TraversalControllerURL: "http://localhost:9080",
	}

	transport, err := newTransport(cfg)
	if err != nil {
		t.Fatalf("newTransport() error: %v", err)
	}

	assertH2C(t, transport)
}

func TestNewTransport_WithTLSCertsAndProxy(t *testing.T) {
	certPEM, keyPEM := generateTestKeyPair(t)

	cfg := &config.Config{
		TraversalControllerURL: "https://controller.example.com:9080",
		EgressProxyURL:         ptrTo("http://proxy.example.com:3128"),
		TLSCert:                &certPEM,
		TLSKey:                 &keyPEM,
	}

	transport, err := newTransport(cfg)
	if err != nil {
		t.Fatalf("newTransport() error: %v", err)
	}

	httpTransport, ok := transport.(*http.Transport)
	if !ok {
		t.Fatalf("expected *http.Transport when TLS certs provided, got %T", transport)
	}

	if httpTransport.TLSClientConfig == nil {
		t.Fatal("expected TLSClientConfig to be set")
	}

	if len(httpTransport.TLSClientConfig.Certificates) != 1 {
		t.Errorf(
			"expected exactly 1 client certificate, got %d",
			len(httpTransport.TLSClientConfig.Certificates),
		)
	}

	// Verify the proxy function is set.
	proxyReq, _ := http.NewRequestWithContext(
		context.Background(),
		"GET",
		"https://controller.example.com",
		nil,
	)
	egressProxyURL, err := httpTransport.Proxy(proxyReq)
	if err != nil {
		t.Fatalf("proxy function returned error: %v", err)
	}
	if egressProxyURL == nil {
		t.Fatal("expected proxy URL to be set")
	}
	if diff := cmp.Diff("proxy.example.com:3128", egressProxyURL.Host); diff != "" {
		t.Errorf("proxy host mismatch (-want +got):\n%s", diff)
	}
}

func TestNewTransport_TLSOverridePinsLogicalServerName(t *testing.T) {
	certPEM, keyPEM := generateTestKeyPair(t)
	cfg := &config.Config{
		TraversalControllerURL:       "https://logical-controller.example:9080/base",
		TraversalControllerConnectTo: "127.0.0.1:9443",
		TLSCert:                      &certPEM,
		TLSKey:                       &keyPEM,
	}

	transport, err := newTransport(cfg)
	if err != nil {
		t.Fatalf("newTransport() error: %v", err)
	}
	httpTransport := transport.(*http.Transport)
	if got := httpTransport.TLSClientConfig.ServerName; got != "logical-controller.example" {
		t.Fatalf("TLS ServerName = %q", got)
	}
	if httpTransport.DialContext == nil {
		t.Fatal("DialContext is nil with override")
	}
	if httpTransport.Proxy != nil {
		t.Fatal("Proxy is set with fixed direct routing")
	}
}

func TestNewTransport_HTTPSWithoutCertsReturnsError(t *testing.T) {
	// In production this configuration is rejected by config.Load; if Load
	// is bypassed, newTransport surfaces the error rather than silently
	// falling back to a misleading transport.
	cfg := &config.Config{
		TraversalControllerURL: "https://controller.example.com:9080",
	}

	if _, err := newTransport(cfg); err == nil {
		t.Fatal("newTransport() returned nil error for https without certs")
	}
}

func TestNewTransport_InvalidProxyURL(t *testing.T) {
	cfg := &config.Config{
		TraversalControllerURL: "http://localhost:9080",
		EgressProxyURL:         ptrTo("://bad-url"),
	}

	transport, err := newTransport(cfg)
	if err != nil {
		t.Fatalf("newTransport() error: %v", err)
	}

	// http URL → h2c regardless of proxy validity.
	assertH2C(t, transport)
}

// assertH2C checks transport speaks only HTTP/2 cleartext, the http:// controller
// transport.
func assertH2C(t *testing.T, transport http.RoundTripper) {
	t.Helper()
	tr, ok := transport.(*http.Transport)
	if !ok {
		t.Fatalf("expected *http.Transport, got %T", transport)
	}
	if p := tr.Protocols; p == nil || !p.UnencryptedHTTP2() || p.HTTP1() || p.HTTP2() {
		t.Errorf("protocols %v, want only unencrypted HTTP/2", p)
	}
}
