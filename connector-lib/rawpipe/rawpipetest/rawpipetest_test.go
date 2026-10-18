package rawpipetest_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/InteractionLabs/traversal-connector/connector-lib/capability"
	"github.com/InteractionLabs/traversal-connector/connector-lib/capability/capabilitytest"
	"github.com/InteractionLabs/traversal-connector/connector-lib/halfconn"
	"github.com/InteractionLabs/traversal-connector/connector-lib/rawpipe"
	"github.com/InteractionLabs/traversal-connector/connector-lib/rawpipe/rawpipetest"
)

const (
	org       = "0b6e5a3c-1d2f-4a5b-8c7d-9e0f1a2b3c4d"
	connector = "6f1c0a52-8d3e-4b7a-9c21-5e4f3a2b1d00"
	issuer    = "traversal-raw-tunnel/test"
)

// TestPipeServer: a pipe whose capability verifies is served inside the
// proxy's pipe TLS, h2 with the scheme from rawpipe.HeaderUpstreamScheme or
// HTTP/1.1 with the absolute-form target's; a bad capability is refused with
// its reason before any TLS.
func TestPipeServer(t *testing.T) {
	key := capabilitytest.Key("rawpipetest")
	v, err := capability.NewVerifier(capability.VerifierConfig{Issuer: issuer,
		Subject: capability.SubjectIntegrationProxy,
		Keys:    map[string]*ecdsa.PublicKey{"k": &key.PublicKey}})
	if err != nil {
		t.Fatal(err)
	}
	ca := rawpipetest.NewCA(t)
	cert := ca.Connector(t, "spiffe://traversal.com/tenant/"+org+"/acme/connector/"+connector,
		time.Now().Add(time.Hour))
	srv := httptest.NewUnstartedServer(rawpipetest.PipeServer(t, v, cert,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			echo := r.Proto + " " + r.URL.Scheme + " " + r.Host
			_, _ = io.WriteString(w, echo) //nolint:gosec // test echo
		})))
	srv.EnableHTTP2 = true
	srv.Config.Protocols = new(http.Protocols)
	srv.Config.Protocols.SetUnencryptedHTTP2(true)
	srv.Start()
	t.Cleanup(srv.Close)
	tunnel := &http.Transport{Protocols: srv.Config.Protocols}
	t.Cleanup(tunnel.CloseIdleConnections)

	open := func(token string, alpn string) (net.Conn, error) {
		stream, err := rawpipe.Connect(t.Context(), tunnel, srv.Listener.Addr().String(),
			"api.internal:443", http.Header{rawpipe.HeaderCapability: {token}}, 5*time.Second)
		if err != nil {
			return nil, err
		}
		cfg := rawpipe.PipeClientTLS(ca.Pool(), org, connector)
		cfg.NextProtos = []string{alpn}
		tc := tls.Client(halfconn.NewStreamConn(stream), cfg)
		t.Cleanup(func() { _ = tc.Close() })
		return tc, tc.HandshakeContext(t.Context())
	}
	token, err := capability.Sign(key, "k",
		capabilitytest.Claims(issuer, connector, "api.internal", 443))
	if err != nil {
		t.Fatal(err)
	}
	get := func(alpn string, req *http.Request) string {
		t.Helper()
		protocols := new(http.Protocols)
		protocols.SetHTTP1(alpn == rawpipe.ALPNHTTP1)
		protocols.SetHTTP2(alpn == rawpipe.ALPNH2)
		tr := &http.Transport{Protocols: protocols,
			DialTLSContext: func(context.Context, string, string) (net.Conn, error) {
				return open(token, alpn)
			}}
		if alpn == rawpipe.ALPNHTTP1 {
			tr.Proxy = http.ProxyURL(&url.URL{Scheme: "https", Host: "pipe:443"})
		}
		t.Cleanup(tr.CloseIdleConnections)
		resp, err := tr.RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return string(b)
	}

	h2, _ := http.NewRequest(http.MethodGet, "https://api.internal/", http.NoBody)
	h2.Header.Set(rawpipe.HeaderUpstreamScheme, "http")
	if got := get(rawpipe.ALPNH2, h2); got != "HTTP/2.0 http api.internal" {
		t.Errorf("h2: %q", got)
	}
	http1, _ := http.NewRequest(http.MethodGet, "http://api.internal/", http.NoBody)
	if got := get(rawpipe.ALPNHTTP1, http1); got != "HTTP/1.1 http api.internal" {
		t.Errorf("HTTP/1.1: %q", got)
	}
	_, err = open("bogus", rawpipe.ALPNH2)
	if r, ok := errors.AsType[*rawpipe.Refusal](err); !ok || r.Reason != rawpipe.InvalidCapability {
		t.Errorf("bad capability: %v", err)
	}
}
