package pipeserver

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/InteractionLabs/traversal-connector/connector-lib/capability"
	"github.com/InteractionLabs/traversal-connector/connector-lib/capability/capabilitytest"
	"github.com/InteractionLabs/traversal-connector/connector-lib/rawpipe"
	"github.com/InteractionLabs/traversal-connector/internal/config"
)

const org = "0b6e5a3c-1d2f-4a5b-8c7d-9e0f1a2b3c4d"

// connectorConfig is a connector config whose client certificate names
// spiffeID.
func connectorConfig(t *testing.T, spiffeID string) *config.Config {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	uri, _ := url.Parse(spiffeID)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), URIs: []*url.URL{uri},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	cert := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	return &config.Config{
		ConnectorID:            connector,
		TraversalControllerURL: "https://edge.example.com",
		TLSCert:                &cert,
		TLSKey:                 &keyPEM,
	}
}

func keysPEM(t *testing.T) string {
	t.Helper()
	der, _ := x509.MarshalPKIXPublicKey(&capabilitytest.Key("config").PublicKey)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY",
		Headers: map[string]string{"Key-ID": "k1"}, Bytes: der}))
}

func TestNew(t *testing.T) {
	orgScoped := "spiffe://traversal.com/tenant/" + org + "/acme"
	for _, c := range []struct {
		name, spiffeID string
		env            map[string]string
		mutate         func(*config.Config)
		wantErr        string // empty: valid
	}{
		{name: "defaults", spiffeID: orgScoped},
		{name: "connector-scoped certificate", spiffeID: orgScoped + "/connector/" + connector},
		{name: "every setting", spiffeID: orgScoped, env: map[string]string{
			"TRAVERSAL_RAW_PIPES_MAX": "10", "TRAVERSAL_TUNNEL_COUNT": "4",
			"TRAVERSAL_RAW_PIPES_MAX_LIFETIME": "1h", "TRAVERSAL_RAW_PIPES_IDLE_TIMEOUT": "0s",
			"TRAVERSAL_TUNNELS_CONNECT_TO":     "10.0.0.1:443",
			"TRAVERSAL_RAW_PIPES_EGRESS_PROXY": "http://proxy:3128", "TRAVERSAL_RAW_PIPES_EGRESS_PROXY_RESOLVES": "true",
			"TRAVERSAL_RAW_PIPES_FORBIDDEN_CIDRS": "10.9.0.0/16, fd00:1::/32",
		}},
		{name: "base64 keys", spiffeID: orgScoped, env: map[string]string{"TRAVERSAL_CAPABILITY_KEYS": "b64"}},
		{name: "no keys or roots", spiffeID: orgScoped, env: map[string]string{"TRAVERSAL_CAPABILITY_KEYS": ""},
			wantErr: "TRAVERSAL_CAPABILITY_KEYS or TRAVERSAL_CAPABILITY_ROOTS is required"},
		{name: "keys without issuer", spiffeID: orgScoped, env: map[string]string{"TRAVERSAL_CAPABILITY_ISSUER": ""},
			wantErr: "TRAVERSAL_CAPABILITY_ISSUER is required"},
		{name: "roots alone", spiffeID: orgScoped, env: map[string]string{"TRAVERSAL_CAPABILITY_KEYS": "",
			"TRAVERSAL_CAPABILITY_ISSUER": "", "TRAVERSAL_CAPABILITY_ROOTS": "roots"}},
		{name: "base64 roots", spiffeID: orgScoped, env: map[string]string{"TRAVERSAL_CAPABILITY_KEYS": "",
			"TRAVERSAL_CAPABILITY_ROOTS": "b64 roots"}},
		{name: "roots beside keys", spiffeID: orgScoped, env: map[string]string{"TRAVERSAL_CAPABILITY_ROOTS": "roots"}},
		{name: "roots that are not certificates", spiffeID: orgScoped,
			env: map[string]string{"TRAVERSAL_CAPABILITY_ROOTS": "b64"}, wantErr: "TRAVERSAL_CAPABILITY_ROOTS: "},
		{name: "roots with an IP controller", spiffeID: orgScoped,
			env:     map[string]string{"TRAVERSAL_CAPABILITY_ROOTS": "roots"},
			mutate:  func(c *config.Config) { c.TraversalControllerURL = "https://10.0.0.1" },
			wantErr: "canonical controller host name"},
		{name: "bad count", spiffeID: orgScoped, env: map[string]string{"TRAVERSAL_TUNNEL_COUNT": "9"},
			wantErr: "TRAVERSAL_TUNNEL_COUNT must be 1 to 8"},
		{name: "bad duration", spiffeID: orgScoped, env: map[string]string{"TRAVERSAL_RAW_PIPES_IDLE_TIMEOUT": "soon"},
			wantErr: "TRAVERSAL_RAW_PIPES_IDLE_TIMEOUT"},
		{name: "bad bool", spiffeID: orgScoped, env: map[string]string{"TRAVERSAL_RAW_PIPES_EGRESS_PROXY_RESOLVES": "yes"},
			wantErr: "must be true or false"},
		{name: "bad forbidden CIDR", spiffeID: orgScoped,
			env:     map[string]string{"TRAVERSAL_RAW_PIPES_FORBIDDEN_CIDRS": "10.9.0.0/16,10.9.0.1"},
			wantErr: `TRAVERSAL_RAW_PIPES_FORBIDDEN_CIDRS: "10.9.0.1" is not a CIDR`},
		{name: "empty forbidden CIDR", spiffeID: orgScoped,
			env:     map[string]string{"TRAVERSAL_RAW_PIPES_FORBIDDEN_CIDRS": "10.9.0.0/16,"},
			wantErr: "TRAVERSAL_RAW_PIPES_FORBIDDEN_CIDRS"},
		{name: "https egress proxy", spiffeID: orgScoped, env: map[string]string{"TRAVERSAL_RAW_PIPES_EGRESS_PROXY": "https://p:3128"},
			wantErr: "must be an http:// URL"},
		{name: "another connector's certificate", spiffeID: orgScoped + "/connector/" + strings.Replace(connector, "6", "7", 1),
			wantErr: "is for connector"},
		{name: "not a tenant certificate", spiffeID: "spiffe://traversal.com/processor/x",
			wantErr: "no Traversal tenant SPIFFE ID"},
		{name: "upper-case connector ID", spiffeID: orgScoped,
			mutate: func(c *config.Config) { c.ConnectorID = strings.ToUpper(c.ConnectorID) }, wantErr: "lower-case UUID"},
		{name: "http controller", spiffeID: orgScoped,
			mutate: func(c *config.Config) { c.TraversalControllerURL = "http://edge" }, wantErr: "https://"},
		{name: "refuse TCP", spiffeID: orgScoped, env: map[string]string{"TRAVERSAL_RAW_PIPES_REFUSE_TCP": "true"}},
		{name: "bad connect-to", spiffeID: orgScoped, env: map[string]string{"TRAVERSAL_TUNNELS_CONNECT_TO": "10.0.0.1"},
			wantErr: "invalid TRAVERSAL_TUNNELS_CONNECT_TO: expected host:port"},
		{name: "connect-to port not a number", spiffeID: orgScoped,
			env:     map[string]string{"TRAVERSAL_TUNNELS_CONNECT_TO": "10.0.0.1:https"},
			wantErr: "invalid TRAVERSAL_TUNNELS_CONNECT_TO: port must be a number"},
		{name: "legacy egress proxy", spiffeID: orgScoped,
			mutate: func(c *config.Config) { p := "http://p"; c.EgressProxyURL = &p }, wantErr: "EGRESS_PROXY_URL"},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv("TRAVERSAL_CAPABILITY_ISSUER", "traversal-raw-tunnel/test")
			t.Setenv("TRAVERSAL_CAPABILITY_KEYS", keysPEM(t))
			for k, v := range c.env {
				switch v {
				case "b64":
					v = base64Of(keysPEM(t))
				case "roots":
					v = rootPEM(testRoot(t))
				case "b64 roots":
					v = base64Of(rootPEM(testRoot(t)))
				}
				t.Setenv(k, v)
			}
			cfg := connectorConfig(t, c.spiffeID)
			if c.mutate != nil {
				c.mutate(cfg)
			}
			tunnels, err := New(cfg, nil)
			switch {
			case c.wantErr == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case c.wantErr != "" && (err == nil || !strings.Contains(err.Error(), c.wantErr)):
				t.Fatalf("error %v, want one containing %q", err, c.wantErr)
			case c.wantErr == "" && c.name == "every setting" &&
				(tunnels.Count != 4 || tunnels.Addr != "10.0.0.1:443" || tunnels.Server.MaxPipes != 10 ||
					tunnels.Server.IdleTimeout != 0 || tunnels.Server.MaxLifetime != time.Hour):
				t.Fatalf("settings not applied: %+v %+v", tunnels, tunnels.Server)
			case c.name == "every setting" && forbidden(tunnels, "10.9.1.1") != rawpipe.ForbiddenAddress:
				t.Fatal("TRAVERSAL_RAW_PIPES_FORBIDDEN_CIDRS not applied")
			case c.name == "refuse TCP" && !tunnels.Server.RefuseTCP:
				t.Fatal("RefuseTCP not applied")
			case c.wantErr == "" && c.name == "defaults" &&
				(tunnels.Count != 2 || tunnels.Addr != "edge.example.com:443" || tunnels.Server.MaxPipes != 200 ||
					!slices.Equal(tunnels.Kids, []string{"k1"}) || len(tunnels.Roots) != 0):
				t.Fatalf("defaults: %+v", tunnels)
			}
		})
	}
}

// TestTunnelTLS: tunnels speak TLS 1.3 with the tunnel ALPN to the
// controller host, and trust the controller CA the legacy tunnels trust.
func TestTunnelTLS(t *testing.T) {
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	defer srv.Close()
	ca := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE",
		Bytes: srv.Certificate().Raw}))
	cfg := connectorConfig(t, "spiffe://traversal.com/tenant/"+org+"/acme")
	cfg.TLSCA = &ca
	t.Setenv("TRAVERSAL_CAPABILITY_ISSUER", "traversal-raw-tunnel/test")
	t.Setenv("TRAVERSAL_CAPABILITY_KEYS", keysPEM(t))
	tunnels, err := New(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := tunnels.TLS
	if c.MinVersion != tls.VersionTLS13 || c.ServerName != "edge.example.com" ||
		!slices.Equal(c.NextProtos, []string{rawpipe.ALPN}) || len(c.Certificates) != 1 {
		t.Fatalf("tunnel TLS: %+v", c)
	}
	if _, err := srv.Certificate().Verify(x509.VerifyOptions{Roots: c.RootCAs}); err != nil {
		t.Errorf("TLS_CA_BASE64 is not trusted: %v", err)
	}
}

// forbidden is the reason tunnels' dial policy refuses host, or "" if it
// allows it. Policies refuse before dialing, so nothing is dialed.
func forbidden(tunnels *Tunnels, host string) rawpipe.Reason {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // an allowed host fails to dial at once
	conn, _, err := tunnels.Server.Policy.Dial(ctx, host, 443)
	if conn != nil {
		_ = conn.Close()
	}
	if r := rawpipe.ReasonOf(err, ""); r == rawpipe.ForbiddenAddress {
		return r
	}
	return ""
}

var (
	rootKey = capabilitytest.Key("config root")
	envKey  = capabilitytest.Key("config environment")
)

func testRoot(t *testing.T) *capabilitytest.Root {
	t.Helper()
	now := time.Now()
	root, err := capabilitytest.NewRoot(rootKey, now.Add(-time.Hour), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func rootPEM(root *capabilitytest.Root) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.DER}))
}

// TestRootsVerifyForTheControllerHost: with TRAVERSAL_CAPABILITY_ROOTS alone,
// the connector trusts a capability whose environment certificate names the
// host of TRAVERSAL_CONTROLLER_URL, and no other host.
func TestRootsVerifyForTheControllerHost(t *testing.T) {
	t.Setenv("TRAVERSAL_CAPABILITY_ISSUER", "")
	t.Setenv("TRAVERSAL_CAPABILITY_KEYS", "")
	root := testRoot(t)
	t.Setenv("TRAVERSAL_CAPABILITY_ROOTS", rootPEM(root))
	tunnels, err := New(connectorConfig(t, "spiffe://traversal.com/tenant/"+org+"/acme"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(tunnels.Roots, []string{rawpipe.RootFingerprint(root.DER)}) ||
		len(tunnels.Kids) != 0 {
		t.Fatalf("reported trust: roots %v kids %v", tunnels.Roots, tunnels.Kids)
	}
	for host, want := range map[string]bool{"edge.example.com": true, "edge.other.com": false} {
		cert, err := root.Issue(capabilitytest.EnvironmentCert{
			Key: &envKey.PublicKey, Issuer: capability.IssuerURIPrefix + "test",
			Hosts: []string{host}, NotBefore: time.Now().Add(-time.Minute),
			NotAfter: time.Now().Add(time.Hour),
		})
		if err != nil {
			t.Fatal(err)
		}
		claims := capabilitytest.Claims(capability.IssuerPrefix+"test", connector,
			"db.internal", 5432)
		token, err := capability.SignChained(envKey, "env", [][]byte{cert}, claims)
		if err != nil {
			t.Fatal(err)
		}
		_, err = tunnels.Server.Verifier.Verify(token, connector, "db.internal", 5432)
		if (err == nil) != want {
			t.Errorf("certificate for %s: %v, want accepted %v", host, err, want)
		}
	}
}

func base64Of(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

// TestNewVerifierBundleErrors: a bad bundle's error starts with the setting
// it came from, so an operator knows which to fix.
func TestNewVerifierBundleErrors(t *testing.T) {
	for setting, want := range map[string]string{
		"TRAVERSAL_CAPABILITY_KEYS":  "TRAVERSAL_CAPABILITY_KEYS: capability: no keys",
		"TRAVERSAL_CAPABILITY_ROOTS": "TRAVERSAL_CAPABILITY_ROOTS: capability: roots: ",
	} {
		t.Run(setting, func(t *testing.T) {
			t.Setenv("TRAVERSAL_CAPABILITY_ISSUER", "traversal-raw-tunnel/test")
			t.Setenv("TRAVERSAL_CAPABILITY_KEYS", keysPEM(t))
			t.Setenv("TRAVERSAL_CAPABILITY_ROOTS", rootPEM(testRoot(t)))
			t.Setenv(setting, base64Of("junk"))
			_, _, err := newVerifier("https://edge.example.com")
			if err == nil || !strings.HasPrefix(err.Error(), want) {
				t.Fatalf("error %v, want one starting %q", err, want)
			}
		})
	}
}
