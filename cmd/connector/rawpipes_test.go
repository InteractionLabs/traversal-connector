package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"log/slog"
	"math/big"
	"net"
	"net/url"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	pb "github.com/InteractionLabs/traversal-connector/connector-lib/gen/connector/v1"
	"github.com/InteractionLabs/traversal-connector/internal/config"
	"github.com/InteractionLabs/traversal-connector/internal/redact"
	"github.com/InteractionLabs/traversal-connector/internal/tunnels"
)

const (
	testConnector = "11111111-2222-4333-8444-555555555555"
	testTenant    = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
)

// connectorCertificate is a self-signed org-scoped connector certificate,
// the shape production issues, and its key, PEM, with the given extended
// key usage.
func connectorCertificate(t *testing.T, eku []x509.ExtKeyUsage) (cert, key string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	san, _ := url.Parse("spiffe://traversal.com/tenant/" + testTenant + "/acme")
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "connector"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		URIs:         []*url.URL{san},
		ExtKeyUsage:  eku,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
}

// rawPipesConfig is a config that can hold tunnels, with a capability key.
func rawPipesConfig(t *testing.T) *config.Config {
	t.Helper()
	capabilityKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert, key := connectorCertificate(t,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth})
	return &config.Config{
		TraversalControllerURL: "https://edge.traversal.com",
		ConnectorID:            testConnector,
		TLSCert:                &cert,
		TLSKey:                 &key,
		TLSCA:                  &cert,
		RawPipes: config.RawPipes{
			Enabled:          true,
			Listen:           "127.0.0.1:0",
			MaxPipes:         10,
			CapabilityIssuer: "traversal-raw-tunnel/test",
			CapabilityKeys:   map[string]*ecdsa.PublicKey{"test": &capabilityKey.PublicKey},
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
		"clientAuth-only certificate with inner TLS": func(t *testing.T, cfg *config.Config) {
			cert, key := connectorCertificate(t, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
			cfg.TLSCert, cfg.TLSKey = &cert, &key
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
			var reported recordedStatus
			if raw := startRawPipes(
				context.Background(), cfg, reported.report, redact.NewRedactor(),
			); raw != nil {
				t.Fatal("raw pipes started from a config that cannot run them")
			}
			if st := reported.get(t); !st.GetEnabled() || st.GetTunnelsUp() ||
				st.GetDetail() == "" {
				t.Fatalf("metadata would report %v, want enabled, down, and why", st)
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
	tunnelCfg.AdminPort = unusedPort(t) // the drain must not reach a real Envoy
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
	if st := raw.status(); st.GetTunnelsUp() || st.GetDetail() != "the pipe server stopped" {
		t.Fatalf("metadata would report %v after the pipe server failed", st)
	}
	raw.drain() // shutdown after a failure returns, without draining twice
}

// With inner TLS disabled, startup warns that the data leg is cleartext.
func TestInnerTLSDisabledWarnsAtStartup(t *testing.T) {
	var logs bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	cfg := rawPipesConfig(t)
	cfg.RawPipes.EnvoyPath = filepath.Join(t.TempDir(), "no-envoy")
	cfg.RawPipes.TunnelInnerTLS = tunnels.InnerTLSDisabled
	var reported recordedStatus
	raw := startRawPipes(context.Background(), cfg, reported.report, redact.NewRedactor())
	if raw == nil {
		t.Fatalf("raw pipes did not start: %s", logs.String())
	}
	// Stop without draining: a drain would POST to Envoy's admin port,
	// and a developer's own Envoy may be listening there.
	t.Cleanup(func() { raw.stopTransport(); <-raw.envoyDone })
	if !strings.Contains(logs.String(), "level=WARN") ||
		!strings.Contains(logs.String(), "tunnel inner TLS is disabled") ||
		!strings.Contains(logs.String(), "cleartext") {
		t.Fatalf("no cleartext warning in:\n%s", logs.String())
	}
}

// unusedPort is a loopback port nothing listens on.
func unusedPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port
}

// recordedStatus records the raw pipe status startRawPipes reports.
type recordedStatus struct {
	f func() *pb.RawPipesStatus
}

func (r *recordedStatus) report(f func() *pb.RawPipesStatus) { r.f = f }

func (r *recordedStatus) get(t *testing.T) *pb.RawPipesStatus {
	t.Helper()
	if r.f == nil {
		t.Fatal("no raw pipe status was reported")
	}
	return r.f()
}
