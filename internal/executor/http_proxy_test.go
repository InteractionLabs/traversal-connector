package executor

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	pb "github.com/InteractionLabs/traversal-connector/connector-lib/gen/connector/v1"
)

// Upstream hosts use the reserved .invalid TLD: loopback targets always bypass
// the proxy, and a real hostname would make the NO_PROXY case depend on DNS.
const proxiedUpstreamURL = "http://upstream.internal.invalid/api"

func newForwardProxy(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.String() != proxiedUpstreamURL {
			t.Errorf("proxy got request-URI %q, want %q", r.URL.String(), proxiedUpstreamURL)
		}
		w.WriteHeader(http.StatusTeapot)
	}))
	t.Cleanup(proxy.Close)
	return proxy, &hits
}

func TestExecute_RoutesThroughProxyFromEnvironment(t *testing.T) {
	proxy, hits := newForwardProxy(t)
	t.Setenv("HTTP_PROXY", proxy.URL)
	t.Setenv("NO_PROXY", "")

	exec := newTestExecutor(t, 2*time.Second, 32)
	resp, err := exec.Execute(context.Background(), &pb.HttpRequest{
		Method: "GET",
		Url:    proxiedUpstreamURL,
	})
	if err != nil {
		t.Fatalf("Execute() error: %v", err)
	}
	if resp.GetHttpStatus() != http.StatusTeapot {
		t.Errorf("status = %d, want %d", resp.GetHttpStatus(), http.StatusTeapot)
	}
	if hits.Load() != 1 {
		t.Errorf("proxy hits = %d, want 1", hits.Load())
	}
}

func TestExecute_NoProxyBypassesProxy(t *testing.T) {
	proxy, hits := newForwardProxy(t)
	t.Setenv("HTTP_PROXY", proxy.URL)
	t.Setenv("NO_PROXY", ".internal.invalid")

	exec := newTestExecutor(t, 2*time.Second, 32)
	// The direct dial fails to resolve .invalid, which proves the proxy was skipped.
	if _, err := exec.Execute(context.Background(), &pb.HttpRequest{
		Method: "GET",
		Url:    proxiedUpstreamURL,
	}); err == nil {
		t.Fatal("expected direct dial to fail, got nil error")
	}
	if hits.Load() != 0 {
		t.Errorf("proxy hits = %d, want 0", hits.Load())
	}
}
