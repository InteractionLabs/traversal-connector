package dialpolicy

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"
)

// DialConnect opens a TCP tunnel to authority (host:port) through proxy, a
// plain-TCP forward proxy, with HTTP CONNECT, authenticating with proxy's
// user info. ctx bounds the dial and the CONNECT exchange, not the tunnel.
//
// It is hand-written because the standard library has no raw CONNECT client:
// http.Transport sends CONNECT only for its own requests, and x/net/proxy
// speaks only SOCKS5.
func DialConnect(ctx context.Context, proxy *url.URL, authority string) (*Tunnel, error) {
	c, err := (&net.Dialer{KeepAlive: 30 * time.Second}).DialContext(ctx, "tcp", ProxyAddr(proxy))
	if err != nil {
		return nil, err
	}
	conn := c.(*net.TCPConn) //nolint:errcheck,forcetypeassert // tcp dials return *net.TCPConn
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Unix(1, 0)) })
	defer stop()
	req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n", authority, authority)
	if u := proxy.User; u != nil {
		pw, _ := u.Password()
		req += "Proxy-Authorization: Basic " +
			base64.StdEncoding.EncodeToString([]byte(u.Username()+":"+pw)) + "\r\n"
	}
	br := bufio.NewReader(conn)
	if _, err = fmt.Fprint(conn, req+"\r\n"); err == nil {
		var resp *http.Response
		if resp, err = http.ReadResponse(br, &http.Request{Method: http.MethodConnect}); err == nil {
			// A 200's body is the tunnel itself, so it is never read or closed.
			if resp.StatusCode != http.StatusOK {
				_ = resp.Body.Close()
				err = fmt.Errorf("forward proxy refused CONNECT: %s", resp.Status)
			}
		}
	}
	if err != nil || !stop() {
		_ = conn.Close()
		return nil, errors.Join(err, ctx.Err())
	}
	// Bytes the proxy sent after its answer belong to the tunnel.
	return &Tunnel{TCPConn: conn, r: br}, conn.SetDeadline(time.Time{})
}

// ProxyAddr is proxy's host:port, port 80 if the URL names none.
func ProxyAddr(proxy *url.URL) string {
	if proxy.Port() != "" {
		return proxy.Host
	}
	return net.JoinHostPort(proxy.Hostname(), "80")
}

// Tunnel is a TCP connection through a CONNECT proxy. Its Read first returns
// any bytes the proxy sent after its answer.
type Tunnel struct {
	*net.TCPConn
	r *bufio.Reader
}

func (t *Tunnel) Read(b []byte) (int, error) { return t.r.Read(b) }
