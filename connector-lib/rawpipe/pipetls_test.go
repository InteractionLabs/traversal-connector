package rawpipe_test

import (
	"crypto/tls"
	"strings"
	"testing"
	"time"

	"github.com/InteractionLabs/traversal-connector/connector-lib/halfconn/halfconntest"
	"github.com/InteractionLabs/traversal-connector/connector-lib/rawpipe"
	"github.com/InteractionLabs/traversal-connector/connector-lib/rawpipe/rawpipetest"
)

// TestPipeTLS: the proxy accepts the connector only with a certificate from
// the tenant CA, unexpired, naming this pipe's org and connector, and they
// agree on h2.
func TestPipeTLS(t *testing.T) {
	const org, conn = "0b6e5a3c-1d2f-4a5b-8c7d-9e0f1a2b3c4d", "6f1c0a52-8d3e-4b7a-9c21-5e4f3a2b1d00"
	otherOrg := strings.Replace(org, "0b", "1b", 1)
	otherConn := strings.Replace(conn, "6f", "7f", 1)
	tenant, stranger := rawpipetest.NewCA(t), rawpipetest.NewCA(t)
	orgScoped := "spiffe://traversal.com/tenant/" + org + "/acme"
	later := time.Now().Add(time.Hour)
	for _, c := range []struct {
		name string
		cert tls.Certificate
		ok   bool
	}{
		{"org-scoped", tenant.Connector(t, orgScoped, later), true},
		{"connector-scoped", tenant.Connector(t, orgScoped+"/connector/"+conn, later), true},
		{"another CA", stranger.Connector(t, orgScoped, later), false},
		{"another org", tenant.Connector(t, "spiffe://traversal.com/tenant/"+otherOrg+"/acme", later), false},
		{"another connector", tenant.Connector(t, orgScoped+"/connector/"+otherConn, later), false},
	} {
		t.Run(c.name, func(t *testing.T) {
			a, b := halfconntest.TCPPair(t)
			server := tls.Server(a, rawpipe.PipeServerTLS(c.cert))
			go func() { _ = server.Handshake() }()
			client := tls.Client(b, rawpipe.PipeClientTLS(tenant.Pool(), org, conn))
			err := client.Handshake()
			if (err == nil) != c.ok {
				t.Fatalf("handshake: %v, want ok=%v", err, c.ok)
			}
			if c.ok && client.ConnectionState().NegotiatedProtocol != rawpipe.ALPNH2 {
				t.Fatalf("ALPN %q", client.ConnectionState().NegotiatedProtocol)
			}
		})
	}
}
