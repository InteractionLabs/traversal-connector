package rawpipes

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/InteractionLabs/traversal-connector/connector-lib/capability/capabilitytest"
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
		}},
		{name: "base64 keys", spiffeID: orgScoped, env: map[string]string{"TRAVERSAL_CAPABILITY_KEYS": "b64"}},
		{name: "no keys", spiffeID: orgScoped, env: map[string]string{"TRAVERSAL_CAPABILITY_KEYS": ""},
			wantErr: "TRAVERSAL_CAPABILITY_KEYS"},
		{name: "bad count", spiffeID: orgScoped, env: map[string]string{"TRAVERSAL_TUNNEL_COUNT": "9"},
			wantErr: "TRAVERSAL_TUNNEL_COUNT must be 1 to 8"},
		{name: "bad duration", spiffeID: orgScoped, env: map[string]string{"TRAVERSAL_RAW_PIPES_IDLE_TIMEOUT": "soon"},
			wantErr: "TRAVERSAL_RAW_PIPES_IDLE_TIMEOUT"},
		{name: "bad bool", spiffeID: orgScoped, env: map[string]string{"TRAVERSAL_RAW_PIPES_EGRESS_PROXY_RESOLVES": "yes"},
			wantErr: "must be true or false"},
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
		{name: "legacy egress proxy", spiffeID: orgScoped,
			mutate: func(c *config.Config) { p := "http://p"; c.EgressProxyURL = &p }, wantErr: "EGRESS_PROXY_URL"},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv("TRAVERSAL_CAPABILITY_ISSUER", "traversal-raw-tunnel/test")
			t.Setenv("TRAVERSAL_CAPABILITY_KEYS", keysPEM(t))
			for k, v := range c.env {
				if v == "b64" {
					v = base64Of(keysPEM(t))
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
			case c.wantErr == "" && c.name == "defaults" &&
				(tunnels.Count != 2 || tunnels.Addr != "edge.example.com:443" || tunnels.Server.MaxPipes != 200):
				t.Fatalf("defaults: %+v", tunnels)
			}
		})
	}
}

func base64Of(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
