package dialpolicy

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"
)

// dialProxy opens a tunnel to authority through an http:// or https://
// forward proxy with HTTP CONNECT, authenticating with the URL's user info.
// The proxy's own address is not checked: the operator configured it, and it
// may well be a loopback sidecar.
func (p *Policy) dialProxy(ctx context.Context, proxy *url.URL, authority string) (Conn, error) {
	var defaultPort string
	switch proxy.Scheme {
	case "http":
		defaultPort = "80"
	case "https":
		defaultPort = "443"
	default:
		return nil, errors.New("forward proxy scheme must be http or https")
	}
	port := proxy.Port()
	if port == "" {
		port = defaultPort
	}
	conn, err := p.dialConn(ctx, net.JoinHostPort(proxy.Hostname(), port))
	if err != nil {
		return nil, fmt.Errorf("connect to forward proxy: %w", err)
	}
	tunnel, err := p.connect(ctx, conn, proxy, authority)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return tunnel, nil
}

func (p *Policy) connect(ctx context.Context, conn Conn, proxy *url.URL,
	authority string) (Conn, error) {
	// ctx interrupts the handshake by expiring the connection's deadline.
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Unix(1, 0)) })
	tunnel, err := p.handshake(ctx, conn, proxy, authority)
	if !stop() {
		return nil, fmt.Errorf("forward proxy handshake: %w", ctx.Err())
	}
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	return tunnel, nil
}

func (p *Policy) handshake(ctx context.Context, conn Conn, proxy *url.URL,
	authority string) (Conn, error) {
	if proxy.Scheme == "https" {
		cfg := &tls.Config{MinVersion: tls.VersionTLS12}
		if p.proxyTLS != nil {
			cfg = p.proxyTLS.Clone()
		}
		if cfg.ServerName == "" {
			cfg.ServerName = proxy.Hostname()
		}
		// CONNECT is HTTP/1.1. A caller config that asks for h2 would make the
		// proxy speak a protocol this handshake cannot.
		cfg.NextProtos = nil
		tlsConn := tls.Client(conn, cfg)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			return nil, fmt.Errorf("forward proxy TLS: %w", err)
		}
		conn = tlsConn
	}
	req := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Opaque: authority},
		Host:   authority,
		Header: make(http.Header),
	}
	if user := proxy.User; user != nil {
		password, _ := user.Password()
		credentials := base64.StdEncoding.EncodeToString([]byte(user.Username() + ":" + password))
		req.Header.Set("Proxy-Authorization", "Basic "+credentials)
	}
	if err := req.Write(conn); err != nil {
		return nil, fmt.Errorf("send CONNECT: %w", err)
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		return nil, fmt.Errorf("read CONNECT response: %w", err)
	}
	if resp.StatusCode/100 != 2 {
		// Only a refusal has a body. A 2xx must not be read as one: RFC 9110
		// says a client ignores Content-Length and Transfer-Encoding on a
		// successful CONNECT, and those bytes are the tunnel.
		_ = resp.Body.Close()
		return nil, fmt.Errorf("forward proxy refused CONNECT: %d", resp.StatusCode)
	}
	if br.Buffered() > 0 {
		return &bufferedConn{Conn: conn, r: br}, nil
	}
	return conn, nil
}

// bufferedConn returns bytes the proxy sent right after its CONNECT response
// before reading the connection again.
type bufferedConn struct {
	Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(b []byte) (int, error) {
	return c.r.Read(b)
}
