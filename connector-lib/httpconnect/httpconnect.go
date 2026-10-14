// Package httpconnect opens a TCP tunnel through an HTTP forward proxy with
// CONNECT.
//
// It is hand-written because the standard library has no raw CONNECT client:
// http.Transport sends CONNECT only for its own requests, and x/net/proxy
// speaks only SOCKS5.
package httpconnect

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/InteractionLabs/traversal-connector/connector-lib/halfconn"
)

// Dial connects to proxy (an http:// URL; user info becomes
// Proxy-Authorization, replacing any in header), sends CONNECT authority
// (host:port) with header, and returns the tunnel on 200. ctx bounds the dial
// and the CONNECT exchange, not the tunnel.
//
// On any other status it returns the proxy's response (body closed, headers
// intact) and a non-nil error, so callers can read the refusal. On every
// other failure the response is nil.
//
// The tunnel is TCP and can half-close.
func Dial(
	ctx context.Context,
	proxy *url.URL,
	authority string,
	header http.Header,
) (halfconn.Conn, *http.Response, error) {
	if proxy.Scheme != "http" {
		return nil, nil, fmt.Errorf("forward proxy %s must be http://", proxy.Redacted())
	}
	c, err := (&net.Dialer{KeepAlive: 30 * time.Second}).DialContext(ctx, "tcp", ProxyAddr(proxy))
	if err != nil {
		return nil, nil, err
	}
	conn := c.(*net.TCPConn) //nolint:errcheck,forcetypeassert // tcp dials return *net.TCPConn
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Unix(1, 0)) })
	defer stop()
	header = header.Clone()
	if header == nil {
		header = http.Header{}
	}
	if u := proxy.User; u != nil {
		pw, _ := u.Password()
		header.Set("Proxy-Authorization",
			"Basic "+base64.StdEncoding.EncodeToString([]byte(u.Username()+":"+pw)))
	}
	// Request.Write is how http.Transport sends its own CONNECT; it also keeps
	// a header value from breaking the request line.
	req := &http.Request{Method: http.MethodConnect, URL: &url.URL{Opaque: authority},
		Host: authority, Header: header}
	br := bufio.NewReader(conn)
	var resp *http.Response
	if err = req.Write(conn); err == nil {
		if resp, err = http.ReadResponse(br, req); err == nil && resp.StatusCode != http.StatusOK {
			_ = resp.Body.Close()
			err = fmt.Errorf("forward proxy refused CONNECT: %s", resp.Status)
		}
	}
	// A 200's body is the tunnel itself, so it is never read or closed.
	if err != nil || !stop() {
		_ = conn.Close()
		if resp != nil && resp.StatusCode == http.StatusOK {
			resp = nil
		}
		return nil, resp, errors.Join(err, ctx.Err())
	}
	// Bytes the proxy sent after its answer belong to the tunnel.
	return halfconn.Buffered(conn, br), nil, conn.SetDeadline(time.Time{})
}

// ProxyAddr is proxy's host:port, port 80 if the URL names none.
func ProxyAddr(proxy *url.URL) string {
	if proxy.Port() != "" {
		return proxy.Host
	}
	return net.JoinHostPort(proxy.Hostname(), "80")
}

// A refused CONNECT says why in Proxy-Status (RFC 9209), as the Integration
// Proxy sends it:
//
//	Proxy-Status: traversal-integration-proxy; error=<reason>
const (
	headerProxyStatus = "Proxy-Status"
	proxyStatusName   = "traversal-integration-proxy"
	errorParam        = "error="
)

// SetRefusal sets h's Proxy-Status to say a CONNECT was refused for reason.
func SetRefusal(h http.Header, reason string) {
	h.Set(headerProxyStatus, proxyStatusName+"; "+errorParam+reason)
}

// RefusalReason is the error parameter of resp's Proxy-Status, as
// SetRefusal writes it (any later parameter dropped), or empty if resp is
// nil or names none.
func RefusalReason(resp *http.Response) string {
	if resp == nil {
		return ""
	}
	_, reason, _ := strings.Cut(resp.Header.Get(headerProxyStatus), errorParam)
	reason, _, _ = strings.Cut(reason, ";")
	return reason
}
