package pipeserver

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/InteractionLabs/traversal-connector/connector-lib/capability"
	"github.com/InteractionLabs/traversal-connector/connector-lib/capability/capabilitytest"
	"github.com/InteractionLabs/traversal-connector/connector-lib/env"
	"github.com/InteractionLabs/traversal-connector/connector-lib/rawpipe"
	"github.com/InteractionLabs/traversal-connector/internal/config"
	"github.com/InteractionLabs/traversal-connector/internal/redact"
)

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

// keysPEM pins capabilitytest.Key("config") as k1.
var keysPEM = string(capabilitytest.KeysPEM(map[string]*ecdsa.PublicKey{
	"k1": &capabilitytest.Key("config").PublicKey,
}))

func TestNew(t *testing.T) {
	orgScoped := "spiffe://traversal.com/tenant/" + org + "/acme"
	for _, c := range []struct {
		name, spiffeID string
		env            map[string]string
		mutate         func(*config.Config)
		wantErr        string // empty: valid
		// check, if set, says what is wrong with a valid result, or "".
		check func(*Tunnels) string
	}{
		{name: "defaults", spiffeID: orgScoped, check: func(tunnels *Tunnels) string {
			if tunnels.Count != 2 || tunnels.Addr != "edge.example.com:443" ||
				tunnels.Server.MaxPipes != 200 || !slices.Equal(tunnels.Kids, []string{"k1"}) ||
				len(tunnels.Roots) != 0 {
				return "defaults not applied"
			}
			return ""
		}},
		{name: "connector-scoped certificate", spiffeID: orgScoped + "/connector/" + connector},
		{name: "every setting", spiffeID: orgScoped, env: map[string]string{
			"TRAVERSAL_PIPES_MAX": "10", "TRAVERSAL_TUNNELS_COUNT": "4",
			"TRAVERSAL_PIPES_MAX_LIFETIME": "1h", "TRAVERSAL_PIPES_IDLE_TIMEOUT": "0s",
			"TRAVERSAL_TUNNELS_CONNECT_TO": "10.0.0.1:443",
			"TRAVERSAL_PIPES_EGRESS_PROXY": "http://proxy:3128", "TRAVERSAL_PIPES_EGRESS_PROXY_RESOLVES": "true",
			"TRAVERSAL_PIPES_FORBIDDEN_CIDRS": "10.9.0.0/16, fd00:1::/32",
			"TRAVERSAL_PIPES_MAX_STREAMS":     "50", "TRAVERSAL_PIPES_STREAM_WINDOW_KB": "64",
		}, check: func(tunnels *Tunnels) string {
			s := tunnels.Server
			switch {
			case tunnels.Count != 4 || tunnels.Addr != "10.0.0.1:443" || s.MaxPipes != 10 ||
				s.PipeLimits.IdleTimeout != 0 || s.MaxLifetime != time.Hour ||
				s.PipeLimits.MaxStreams != 50 || s.PipeLimits.StreamWindow != 64<<10:
				return "settings not applied"
			case forbidden(t, "10.9.1.1") != rawpipe.ForbiddenAddress:
				return "TRAVERSAL_PIPES_FORBIDDEN_CIDRS not applied"
			}
			return ""
		}},
		{name: "base64 keys", spiffeID: orgScoped, env: map[string]string{"TRAVERSAL_CAPABILITY_KEYS": "b64"}},
		{name: "no keys or roots", spiffeID: orgScoped, env: map[string]string{"TRAVERSAL_CAPABILITY_KEYS": ""},
			wantErr: "TRAVERSAL_CAPABILITY_KEYS or TRAVERSAL_CAPABILITY_ROOTS: one is required"},
		{name: "keys without issuer", spiffeID: orgScoped, env: map[string]string{"TRAVERSAL_CAPABILITY_ISSUER": ""},
			wantErr: "TRAVERSAL_CAPABILITY_ISSUER: required"},
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
		{name: "bad forbidden CIDR", spiffeID: orgScoped,
			env:     map[string]string{"TRAVERSAL_PIPES_FORBIDDEN_CIDRS": "10.9.0.0/16,10.9.0.1"},
			wantErr: `TRAVERSAL_PIPES_FORBIDDEN_CIDRS: "10.9.0.1" is not a CIDR`},
		{name: "https egress proxy", spiffeID: orgScoped, env: map[string]string{"TRAVERSAL_PIPES_EGRESS_PROXY": "https://p:3128"},
			wantErr: "TRAVERSAL_PIPES_EGRESS_PROXY: must be an http:// URL"},
		{name: "another connector's certificate", spiffeID: orgScoped + "/connector/" + strings.Replace(connector, "6", "7", 1),
			wantErr: "is for connector"},
		{name: "not a tenant certificate", spiffeID: "spiffe://traversal.com/processor/x",
			wantErr: "is not a tenant SPIFFE ID"},
		{name: "upper-case connector ID", spiffeID: orgScoped,
			mutate: func(c *config.Config) { c.ConnectorID = strings.ToUpper(c.ConnectorID) }, wantErr: "lower-case UUID"},
		{name: "http controller", spiffeID: orgScoped,
			mutate: func(c *config.Config) { c.TraversalControllerURL = "http://edge" }, wantErr: "https://"},
		{name: "bad connect-to", spiffeID: orgScoped, env: map[string]string{"TRAVERSAL_TUNNELS_CONNECT_TO": "10.0.0.1"},
			wantErr: "invalid TRAVERSAL_TUNNELS_CONNECT_TO: expected host:port"},
		{name: "legacy egress proxy", spiffeID: orgScoped,
			mutate: func(c *config.Config) { p := "http://p"; c.EgressProxyURL = &p }, wantErr: "EGRESS_PROXY_URL: "},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv("TRAVERSAL_CAPABILITY_ISSUER", "traversal-raw-tunnel/test")
			t.Setenv("TRAVERSAL_CAPABILITY_KEYS", keysPEM)
			for k, v := range c.env {
				switch v {
				case "b64":
					v = base64Of(keysPEM)
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
			tunnels, err := New(cfg, redact.NewRedactor(), http.NotFoundHandler())
			switch {
			case c.wantErr == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case c.wantErr != "" && (err == nil || !strings.Contains(err.Error(), c.wantErr)):
				t.Fatalf("error %v, want one containing %q", err, c.wantErr)
			case c.check != nil:
				if why := c.check(tunnels); why != "" {
					t.Fatal(why)
				}
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
	t.Setenv("TRAVERSAL_CAPABILITY_KEYS", keysPEM)
	tunnels, err := New(cfg, redact.NewRedactor(), http.NotFoundHandler())
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
// forbidden is whether the dial policy built from the environment refuses
// host.
func forbidden(t *testing.T, host string) rawpipe.Reason {
	dial, err := newPolicy(&env.Reader{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // an allowed host fails to dial at once
	conn, _, err := dial(ctx, host, 443)
	if conn != nil {
		_ = conn.Close()
	}
	if r := rawpipe.ReasonOf(err, ""); r == rawpipe.ForbiddenAddress {
		return r
	}
	return ""
}

var envKey = capabilitytest.Key("config environment")

func testRoot(t *testing.T) *capabilitytest.Root {
	t.Helper()
	return capabilitytest.ValidRoot(t, "config root")
}

func rootPEM(root *capabilitytest.Root) string { return string(capabilitytest.RootsPEM(root)) }

// TestRootsVerifyForTheControllerHost: with TRAVERSAL_CAPABILITY_ROOTS alone,
// the connector trusts a capability whose environment certificate names the
// host of TRAVERSAL_CONTROLLER_URL, and no other host.
func TestRootsVerifyForTheControllerHost(t *testing.T) {
	t.Setenv("TRAVERSAL_CAPABILITY_ISSUER", "")
	t.Setenv("TRAVERSAL_CAPABILITY_KEYS", "")
	root := testRoot(t)
	t.Setenv("TRAVERSAL_CAPABILITY_ROOTS", rootPEM(root))
	tunnels, err := New(connectorConfig(t, "spiffe://traversal.com/tenant/"+org+"/acme"),
		redact.NewRedactor(), http.NotFoundHandler())
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(tunnels.Roots, []string{rawpipe.RootFingerprint(root.DER)}) ||
		len(tunnels.Kids) != 0 {
		t.Fatalf("reported trust: roots %v kids %v", tunnels.Roots, tunnels.Kids)
	}
	for host, want := range map[string]bool{"edge.example.com": true, "edge.other.com": false} {
		claims := capabilitytest.Claims(capability.IssuerPrefix+"test", connector,
			"db.internal", 5432)
		token := capabilitytest.Chained(t, root, envKey, "env", host, claims)
		_, err = tunnels.Server.Verifier.Verify(token, connector, "db.internal", 5432)
		if (err == nil) != want {
			t.Errorf("certificate for %s: %v, want accepted %v", host, err, want)
		}
	}
}

func base64Of(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

// TestEgressProxyFromEnvironment: with TRAVERSAL_PIPES_EGRESS_PROXY unset,
// HTTPS_PROXY is the egress proxy, resolving hostnames as in #67, and NO_PROXY
// hosts are dialed direct, both through the dial policy; the setting, when set,
// wins.
func TestEgressProxyFromEnvironment(t *testing.T) {
	const dest = "192.0.2.10" // TEST-NET-1: allowed, and never answers
	for _, c := range []struct {
		name string
		env  map[string]string // "{proxy}" is the recording proxy's URL
		host string
		via  string // "proxy", "direct" or "forbidden"
	}{
		{name: "HTTPS_PROXY when the setting is unset", host: dest, via: "proxy",
			env: map[string]string{"HTTPS_PROXY": "{proxy}"}},
		{name: "HTTP_PROXY without HTTPS_PROXY", host: dest, via: "proxy",
			env: map[string]string{"HTTP_PROXY": "{proxy}"}},
		{name: "hostname through HTTPS_PROXY goes unresolved", host: "db.internal", via: "proxy",
			env: map[string]string{"HTTPS_PROXY": "{proxy}"}},
		{name: "NO_PROXY host dialed direct", host: dest, via: "direct",
			env: map[string]string{"HTTPS_PROXY": "{proxy}", "NO_PROXY": "192.0.2.0/24"}},
		{name: "setting wins over HTTPS_PROXY and NO_PROXY", host: dest, via: "proxy",
			env: map[string]string{"TRAVERSAL_PIPES_EGRESS_PROXY": "{proxy}",
				"HTTPS_PROXY": "http://unused.invalid:3128", "NO_PROXY": dest}},
		{name: "forbidden address through HTTPS_PROXY", host: "169.254.169.254", via: "forbidden",
			env: map[string]string{"HTTPS_PROXY": "{proxy}"}},
		{name: "forbidden address in NO_PROXY", host: "169.254.169.254", via: "forbidden",
			env: map[string]string{"HTTPS_PROXY": "{proxy}", "NO_PROXY": "169.254.0.0/16"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			proxyURL, connects := recordingProxy(t)
			for _, k := range []string{"TRAVERSAL_PIPES_EGRESS_PROXY",
				"TRAVERSAL_PIPES_EGRESS_PROXY_RESOLVES", "HTTPS_PROXY",
				"https_proxy", "HTTP_PROXY", "http_proxy", "NO_PROXY", "no_proxy"} {
				t.Setenv(k, strings.ReplaceAll(c.env[k], "{proxy}", proxyURL))
			}
			dial, err := newPolicy(&env.Reader{})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
			defer cancel()
			conn, _, err := dial(ctx, c.host, 443)
			if conn != nil {
				_ = conn.Close()
			}
			var got string
			switch reason := rawpipe.ReasonOf(err, ""); {
			case reason == rawpipe.ForbiddenAddress:
				got = "forbidden"
			case err == nil && slices.Equal(connects(), []string{c.host + ":443"}):
				got = "proxy"
			case reason == rawpipe.DialFailed && len(connects()) == 0:
				got = "direct"
			default:
				t.Fatalf("dial: %v, proxy saw %v", err, connects())
			}
			if got != c.via || c.via == "forbidden" && len(connects()) != 0 {
				t.Fatalf("went %s, want %s (proxy saw %v)", got, c.via, connects())
			}
		})
	}
}

// recordingProxy is an http:// proxy URL that accepts every CONNECT, and the
// authorities it has been asked for.
func recordingProxy(t *testing.T) (string, func() []string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	var mu sync.Mutex
	var seen []string
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			if req, err := http.ReadRequest(bufio.NewReader(c)); err == nil &&
				req.Method == http.MethodConnect {
				mu.Lock()
				seen = append(seen, req.Host)
				mu.Unlock()
				_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\n\r\n")
			}
			_ = c.Close()
		}
	}()
	return "http://" + ln.Addr().String(), func() []string {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(seen)
	}
}
