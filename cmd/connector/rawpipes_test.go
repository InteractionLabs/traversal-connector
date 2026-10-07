package main

import (
	"context"
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
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/InteractionLabs/traversal-connector/internal/config"
	"github.com/InteractionLabs/traversal-connector/internal/redact"
	"github.com/InteractionLabs/traversal-connector/internal/tunnels"
)

const (
	testConnector = "11111111-2222-4333-8444-555555555555"
	testTenant    = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
)

// rawPipesConfig is a config that can hold tunnels, with a capability key.
func rawPipesConfig(t *testing.T) *config.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	san, _ := url.Parse(
		"spiffe://traversal.com/tenant/" + testTenant + "/acme/connector/" + testConnector)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "connector"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		URIs:         []*url.URL{san},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	cert := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	return &config.Config{
		TraversalControllerURL: "https://edge.traversal.com",
		ConnectorID:            testConnector,
		TLSCert:                &cert,
		TLSKey:                 &keyPEM,
		TLSCA:                  &cert,
		RawPipes: config.RawPipes{
			Enabled:          true,
			Listen:           "127.0.0.1:0",
			MaxPipes:         10,
			CapabilityIssuer: "traversal-raw-tunnel/test",
			CapabilityKeys:   map[string]*ecdsa.PublicKey{"test": &key.PublicKey},
			EnvoyPath:        "envoy",
			RunDir:           t.TempDir(),
			TunnelCount:      1,
		},
	}
}

// A raw pipe setup failure disables raw pipes only: startRawPipes reports
// no raw pipe side, and main carries on with the legacy transport.
func TestRawPipeSetupFailureLeavesLegacyRunning(t *testing.T) {
	for name, mutate := range map[string]func(t *testing.T, cfg *config.Config){
		"pipe server": func(_ *testing.T, cfg *config.Config) {
			cfg.RawPipes.CapabilityKeys = nil // the verifier needs a key
		},
		"tunnels": func(_ *testing.T, cfg *config.Config) {
			cfg.RawPipes.TunnelStreamWindow = 1 // below the 64 KiB minimum
		},
		"listener": func(t *testing.T, cfg *config.Config) {
			taken, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = taken.Close() })
			cfg.RawPipes.Listen = taken.Addr().String()
		},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := rawPipesConfig(t)
			// Otherwise the test passes for the wrong reason: a connector
			// that cannot hold tunnels never reaches the step under test.
			if _, err := tunnelConfig(cfg); err != nil {
				t.Fatalf("the base config cannot hold tunnels: %v", err)
			}
			mutate(t, cfg)
			if raw := startRawPipes(context.Background(), cfg, redact.NewRedactor()); raw != nil {
				t.Fatal("raw pipes started from a config that cannot run them")
			}
		})
	}
}

// brokenListener fails every Accept with an error the pipe server cannot
// retry, and records that it was closed.
type brokenListener struct {
	net.Listener
	closed atomic.Bool
}

var errListenerBroken = errors.New("listener broken")

func (*brokenListener) Accept() (net.Conn, error) { return nil, errListenerBroken }

func (l *brokenListener) Close() error {
	l.closed.Store(true)
	return nil
}

// A pipe server that stops for good stops raw pipes only: the tunnels are
// drained and Envoy stopped, so the tunnel endpoint routes pipes elsewhere,
// and readiness falls back to the legacy transport. The process does not
// exit: if it did, the test binary would die rather than pass.
func TestFatalAcceptErrorStopsRawPipesOnly(t *testing.T) {
	cfg := rawPipesConfig(t)
	// Never start a real Envoy, even if one is installed.
	cfg.RawPipes.EnvoyPath = filepath.Join(t.TempDir(), "no-envoy")
	tunnelCfg, err := tunnelConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	server, err := newPipeServer(cfg, redact.NewRedactor())
	if err != nil {
		t.Fatal(err)
	}
	manager, err := tunnels.New(tunnelCfg)
	if err != nil {
		t.Fatal(err)
	}
	ln := &brokenListener{}
	raw := runRawPipes(context.Background(), server, manager, ln)

	select {
	case <-raw.envoyDone:
	case <-time.After(pipeDrainGrace):
		t.Fatal("Envoy's tunnels kept running after the pipe server failed")
	}
	if !ln.closed.Load() {
		t.Fatal("the pipe listener was left open")
	}
	if ready, reason := manager.Status(context.Background()); ready || reason != "draining" {
		t.Fatalf("tunnels not drained: ready %v, %q", ready, reason)
	}
	if ready, reason := raw.readiness()(context.Background()); !ready {
		t.Fatalf("raw pipes failing held the connector unready: %q", reason)
	}
	raw.drain() // shutdown after a failure returns, without draining twice
}
