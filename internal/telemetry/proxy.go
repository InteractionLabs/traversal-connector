package telemetry

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
)

// httpConnectDialer returns a context dialer that opens a TCP connection
// to addr through an HTTP CONNECT forward proxy. It is meant to be plugged
// into grpc.WithContextDialer so OTLP gRPC exporters can traverse a
// corporate egress proxy. The returned net.Conn is plain TCP — the caller
// (gRPC) layers TLS on top via WithTLSCredentials.
func httpConnectDialer(
	proxyURL *url.URL,
) func(context.Context, string) (net.Conn, error) {
	return func(ctx context.Context, addr string) (net.Conn, error) {
		proxyAddr := proxyHostPort(proxyURL)
		conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", proxyAddr)
		if err != nil {
			return nil, fmt.Errorf(
				"otlp proxy dial %s: %w", proxyAddr, err,
			)
		}

		req := &http.Request{
			Method: http.MethodConnect,
			URL:    &url.URL{Opaque: addr},
			Host:   addr,
			Header: make(http.Header),
		}
		if writeErr := req.Write(conn); writeErr != nil {
			_ = conn.Close()
			return nil, fmt.Errorf(
				"otlp proxy write CONNECT: %w", writeErr,
			)
		}

		br := bufio.NewReader(conn)
		resp, respErr := http.ReadResponse(br, req)
		if respErr != nil {
			_ = conn.Close()
			return nil, fmt.Errorf(
				"otlp proxy read CONNECT response: %w", respErr,
			)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			_ = conn.Close()
			return nil, fmt.Errorf(
				"otlp proxy CONNECT %s rejected: %s",
				addr, resp.Status,
			)
		}

		// Hand the connection back. If the bufio.Reader buffered any
		// bytes past the CONNECT response, wrap the conn so the
		// subsequent TLS handshake reads them first.
		if br.Buffered() > 0 {
			return &bufferedConn{r: br, Conn: conn}, nil
		}
		return conn, nil
	}
}

// proxyHostPort returns host:port for the proxy URL, defaulting to port 80.
func proxyHostPort(u *url.URL) string {
	if u.Port() != "" {
		return u.Host
	}
	return net.JoinHostPort(u.Hostname(), "80")
}

// bufferedConn fronts reads with a bufio.Reader so any bytes the reader
// pulled past the CONNECT response are not lost on the next Read.
type bufferedConn struct {
	r *bufio.Reader
	net.Conn
}

func (bc *bufferedConn) Read(p []byte) (int, error) {
	return bc.r.Read(p)
}
