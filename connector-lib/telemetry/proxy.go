package telemetry

import (
	"context"
	"fmt"
	"net"
	"net/url"

	"github.com/InteractionLabs/traversal-connector/connector-lib/httpconnect"
)

// httpConnectDialer returns a context dialer that opens a TCP connection
// to addr through an HTTP CONNECT forward proxy (the connector's
// configured EGRESS_PROXY_URL). It is meant to be plugged into
// grpc.WithContextDialer so OTLP gRPC exporters can traverse a corporate
// egress proxy. The returned net.Conn is plain TCP — the caller (gRPC)
// layers TLS on top via WithTLSCredentials.
func httpConnectDialer(
	egressProxyURL *url.URL,
) func(context.Context, string) (net.Conn, error) {
	return func(ctx context.Context, addr string) (net.Conn, error) {
		conn, _, err := httpconnect.Dial( //nolint:bodyclose // Dial closes it
			ctx, egressProxyURL, addr, nil)
		if err != nil {
			return nil, fmt.Errorf("otlp proxy CONNECT %s via %s: %w",
				addr, httpconnect.ProxyAddr(egressProxyURL), err)
		}
		return conn, nil
	}
}
