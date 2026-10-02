package client

import (
	"crypto/tls"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/InteractionLabs/traversal-connector/internal/config"
)

func TestConfigHTTPClientMTLSAndRouting(t *testing.T) {
	cert, key := generateTestKeyPair(t)
	for _, mode := range []string{"direct", "proxy", "connect-to"} {
		t.Run(mode, func(t *testing.T) {
			var sawClient, sawProxy atomic.Bool
			server := httptest.NewUnstartedServer(
				http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					sawClient.Store(len(r.TLS.PeerCertificates) == 1)
					if r.URL.Path != "/v1/config/connector-1" {
						t.Errorf("unexpected path %s", r.URL.Path)
					}
					if mode == "connect-to" && r.Host != "127.0.0.1:1" {
						t.Errorf("connect-to changed logical authority: %s", r.Host)
					}
					_, _ = w.Write([]byte("config"))
				}),
			)
			server.TLS = &tls.Config{
				ClientAuth: tls.RequireAnyClientCert,
				MinVersion: tls.VersionTLS12,
			}
			server.EnableHTTP2 = true
			server.StartTLS()
			defer server.Close()
			ca := string(
				pem.EncodeToMemory(
					&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw},
				),
			)
			cfg := &config.Config{
				TraversalControllerURL: server.URL,
				TLSCert:                &cert,
				TLSKey:                 &key,
				TLSCA:                  &ca,
			}
			if mode == "connect-to" {
				cfg.TraversalControllerURL = "https://127.0.0.1:1"
				cfg.TraversalControllerConnectTo = server.Listener.Addr().String()
			}
			if mode == "proxy" {
				proxy := httptest.NewServer(
					http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						if r.Method != http.MethodConnect {
							http.Error(w, "CONNECT required", http.StatusMethodNotAllowed)
							return
						}
						sawProxy.Store(true)
						upstream, err := net.Dial("tcp", server.Listener.Addr().String())
						if err != nil {
							t.Error(err)
							return
						}
						defer upstream.Close()
						conn, _, err := w.(http.Hijacker).Hijack()
						if err != nil {
							t.Error(err)
							return
						}
						defer conn.Close()
						_, _ = conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
						go func() {
							defer upstream.Close()
							_, _ = io.Copy(upstream, conn)
						}()
						_, _ = io.Copy(conn, upstream)
					}),
				)
				defer proxy.Close()
				cfg.EgressProxyURL = &proxy.URL
			}
			client, err := NewConfigHTTPClient(cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer client.CloseIdleConnections()
			resp, err := client.Get(cfg.TraversalControllerURL + "/v1/config/connector-1")
			if err != nil {
				t.Fatal(err)
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode != 200 || !sawClient.Load() ||
				(mode == "proxy" && !sawProxy.Load()) {
				t.Fatal("config fetch did not use the expected mTLS/proxy transport")
			}
			if client.Timeout <= 0 {
				t.Fatal("config client has no timeout")
			}
			if err = client.CheckRedirect(nil, nil); err != http.ErrUseLastResponse {
				t.Fatal("config redirects are not blocked")
			}
		})
	}
}
