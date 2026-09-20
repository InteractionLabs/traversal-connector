package executor

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"testing"
	"time"

	"github.com/InteractionLabs/traversal-connector/internal/config"
	"github.com/InteractionLabs/traversal-connector/internal/redact"
)

func TestNewExecutorUsesDefaultSystemRootsWithoutCustomCA(t *testing.T) {
	originalSystemCertPool := systemCertPool
	systemCertPool = func() (*x509.CertPool, error) {
		t.Fatal("systemCertPool must not be called without a custom upstream CA")
		return nil, nil
	}
	t.Cleanup(func() { systemCertPool = originalSystemCertPool })

	exec, err := NewExecutor(&config.Config{}, redact.NewRedactor())
	if err != nil {
		t.Fatalf("NewExecutor() failed: %v", err)
	}

	if roots := executorRootCAs(t, exec); roots != nil {
		t.Error("expected nil RootCAs so TLS uses the default system trust store")
	}
}

func TestNewExecutorExtendsSystemRootsWithCustomCA(t *testing.T) {
	systemRoot, _ := newTestRootCA(t, "fake system root", 1)
	customRoot, customPEM := newTestRootCA(t, "custom root", 2)
	systemRoots := x509.NewCertPool()
	systemRoots.AddCert(systemRoot)

	originalSystemCertPool := systemCertPool
	systemCertPool = func() (*x509.CertPool, error) { return systemRoots, nil }
	t.Cleanup(func() { systemCertPool = originalSystemCertPool })

	customCA := string(customPEM)
	exec, err := NewExecutor(
		&config.Config{UpstreamTLSCA: &customCA},
		redact.NewRedactor(),
	)
	if err != nil {
		t.Fatalf("NewExecutor() failed: %v", err)
	}

	roots := executorRootCAs(t, exec)
	assertCertificateTrusted(t, systemRoot, roots)
	assertCertificateTrusted(t, customRoot, roots)
}

func TestNewExecutorRejectsInvalidCustomCA(t *testing.T) {
	originalSystemCertPool := systemCertPool
	systemCertPool = func() (*x509.CertPool, error) { return x509.NewCertPool(), nil }
	t.Cleanup(func() { systemCertPool = originalSystemCertPool })

	invalidCA := "not a PEM certificate"
	_, err := NewExecutor(
		&config.Config{UpstreamTLSCA: &invalidCA},
		redact.NewRedactor(),
	)
	if err == nil || err.Error() != "failed to parse upstream CA certificate" {
		t.Fatalf("expected invalid custom CA error, got %v", err)
	}
}

func TestNewExecutorReturnsSystemCertPoolError(t *testing.T) {
	wantErr := errors.New("system trust store unavailable")
	originalSystemCertPool := systemCertPool
	systemCertPool = func() (*x509.CertPool, error) { return nil, wantErr }
	t.Cleanup(func() { systemCertPool = originalSystemCertPool })

	_, customPEM := newTestRootCA(t, "custom root", 3)
	customCA := string(customPEM)
	_, err := NewExecutor(
		&config.Config{UpstreamTLSCA: &customCA},
		redact.NewRedactor(),
	)
	if !errors.Is(err, wantErr) {
		t.Fatalf("expected system certificate pool error, got %v", err)
	}
	if got, want := err.Error(), "failed to load system certificate pool for upstream TLS: system trust store unavailable"; got != want {
		t.Fatalf("error mismatch: got %q, want %q", got, want)
	}
}

func executorRootCAs(t *testing.T, exec *Executor) *x509.CertPool {
	t.Helper()
	transport, ok := exec.client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("executor transport has type %T, want *http.Transport", exec.client.Transport)
	}
	return transport.TLSClientConfig.RootCAs
}

func newTestRootCA(t *testing.T, commonName string, serial int64) (*x509.Certificate, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate test CA key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Unix(0, 0),
		NotAfter:              time.Unix(1<<31, 0),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create test CA: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse test CA: %v", err)
	}
	return cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func assertCertificateTrusted(t *testing.T, cert *x509.Certificate, roots *x509.CertPool) {
	t.Helper()
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		t.Errorf("expected %q to be trusted: %v", cert.Subject.CommonName, err)
	}
}
