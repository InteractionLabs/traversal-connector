// Package dialpolicy dials a raw pipe's destination, refusing addresses a
// pipe must never reach: loopback, link-local, cloud metadata, and the
// connector's own addresses. Private ranges are allowed; reaching them is
// what raw pipes are for.
//
// A direct dial resolves the name once, refuses the pipe if any answer is
// forbidden, and races the checked addresses. A proxied dial sends CONNECT to
// the customer's forward proxy, which resolves the name itself: hostnames
// then go through only if the operator delegates that check to the proxy.
package dialpolicy

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/InteractionLabs/traversal-connector/connector-lib/capability"
	"github.com/InteractionLabs/traversal-connector/connector-lib/rawpipe"
)

var forbiddenPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"), // link-local and most metadata services
	netip.MustParsePrefix("224.0.0.0/3"),    // multicast and reserved
	netip.MustParsePrefix("100.100.100.200/32"),
	netip.MustParsePrefix("168.63.129.16/32"),
	netip.MustParsePrefix("::/96"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("ff00::/8"),
	netip.MustParsePrefix("fd00:ec2::/32"),
	netip.MustParsePrefix("fd20:ce::254/128"),
}

// embedded maps IPv6 prefixes that carry an IPv4 address to where it sits,
// so the policy checks the IPv4 address too.
var embedded = []struct {
	prefix netip.Prefix
	ipv4   func(b [16]byte) [4]byte
}{
	// NAT64 (RFC 6052): /96 keeps it in the last 32 bits; /48 puts it in bits
	// 48-63 and 72-87, around the reserved u octet (bits 64-71).
	{netip.MustParsePrefix("64:ff9b::/96"), func(b [16]byte) [4]byte { return [4]byte(b[12:]) }},
	{netip.MustParsePrefix("64:ff9b:1::/48"),
		func(b [16]byte) [4]byte { return [4]byte{b[6], b[7], b[9], b[10]} }},
	// 6to4 (RFC 3056): bits 16-47.
	{netip.MustParsePrefix("2002::/16"), func(b [16]byte) [4]byte { return [4]byte(b[2:6]) }},
	// Teredo (RFC 4380): the client address, inverted, in the last 32 bits.
	{netip.MustParsePrefix("2001::/32"), func(b [16]byte) [4]byte {
		return [4]byte{^b[12], ^b[13], ^b[14], ^b[15]}
	}},
}

// Config configures a Policy.
type Config struct {
	// Proxy, if set, is the forward proxy every pipe dials through.
	Proxy *url.URL
	// ProxyResolves sends hostnames to Proxy, delegating their address checks
	// to it. Off, only IP literals go through the proxy.
	ProxyResolves bool
	// Resolver resolves hostnames; nil uses net.DefaultResolver.
	Resolver interface {
		LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
	}
}

// Policy dials raw pipe destinations. It is safe for concurrent use.
type Policy struct {
	cfg  Config
	deny []netip.Prefix
}

func refuse(reason rawpipe.Reason, err error) error { return rawpipe.Errorf(reason, "%v", err) }

// New returns a Policy. It snapshots the host's own addresses.
func New(cfg Config) (*Policy, error) {
	if cfg.Resolver == nil {
		cfg.Resolver = net.DefaultResolver
	}
	deny := append([]netip.Prefix(nil), forbiddenPrefixes...)
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok {
			if addr, ok := netip.AddrFromSlice(n.IP); ok {
				deny = append(deny, netip.PrefixFrom(addr.Unmap(), addr.Unmap().BitLen()))
			}
		}
	}
	return &Policy{cfg: cfg, deny: deny}, nil
}

// Dial connects to a canonical host:port. Every error is a *rawpipe.Error. It
// returns the address dialed, or the proxy, for the audit log.
func (p *Policy) Dial(
	ctx context.Context,
	host string,
	port uint16,
) (rawpipe.HalfCloser, string, error) {
	literal, err := netip.ParseAddr(host)
	isLiteral := err == nil
	if isLiteral && p.forbidden(literal) || forbiddenName(host) {
		return nil, "", rawpipe.Errorf(rawpipe.ForbiddenAddress, "forbidden destination")
	}
	if p.cfg.Proxy != nil {
		if !isLiteral && !p.cfg.ProxyResolves {
			return nil, "", rawpipe.Errorf(rawpipe.ForbiddenAddress,
				"hostnames through the proxy are not allowed")
		}
		// No trailing dot: customer proxy ACLs match the name as written.
		conn, err := p.dialProxy(ctx, net.JoinHostPort(host, fmt.Sprint(port)))
		if err != nil {
			return nil, "", refuse(rawpipe.DialFailed, err)
		}
		return conn, "proxy " + p.cfg.Proxy.Host, nil
	}
	addrs := []netip.Addr{literal}
	if !isLiteral {
		if addrs, err = p.cfg.Resolver.LookupNetIP(ctx, "ip", capability.Absolute(host)); err != nil ||
			len(addrs) == 0 {
			return nil, "", refuse(rawpipe.DNSFailed, fmt.Errorf("resolve %s: %w", host, err))
		}
		if len(addrs) > 8 {
			addrs = addrs[:8]
		}
	}
	for _, a := range addrs {
		if p.forbidden(a) {
			return nil, "", rawpipe.Errorf(
				rawpipe.ForbiddenAddress,
				"resolves to a forbidden address",
			)
		}
	}
	conn, err := race(ctx, addrs, port)
	if err != nil {
		return nil, "", refuse(rawpipe.DialFailed, err)
	}
	return conn, conn.RemoteAddr().String(), nil
}

func (p *Policy) forbidden(a netip.Addr) bool {
	a = a.Unmap().WithZone("")
	check := []netip.Addr{a}
	for _, e := range embedded {
		if e.prefix.Contains(a) {
			check = append(check, netip.AddrFrom4(e.ipv4(a.As16())))
		}
	}
	for _, c := range check {
		for _, d := range p.deny {
			if d.Contains(c) {
				return true
			}
		}
	}
	return false
}

func forbiddenName(host string) bool {
	switch host {
	case "localhost", "metadata.google.internal", "metadata.goog", "instance-data.ec2.internal":
		return true
	}
	return strings.HasSuffix(host, ".localhost")
}

// race dials every address at once and keeps the first to connect, so one
// that never answers cannot hide one that would.
func race(ctx context.Context, addrs []netip.Addr, port uint16) (*net.TCPConn, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	type result struct {
		conn *net.TCPConn
		err  error
	}
	results := make(chan result, len(addrs))
	for _, a := range addrs {
		go func() {
			c, err := (&net.Dialer{KeepAlive: 30 * time.Second}).DialContext(ctx, "tcp",
				netip.AddrPortFrom(a.Unmap(), port).String())
			tc, _ := c.(*net.TCPConn)
			results <- result{tc, err}
		}()
	}
	var winner *net.TCPConn
	var errs []error
	for range addrs {
		r := <-results
		switch {
		case r.err != nil:
			errs = append(errs, r.err)
		case winner == nil:
			winner = r.conn
			cancel()
		default:
			_ = r.conn.Close()
		}
	}
	if winner == nil {
		return nil, errors.Join(errs...)
	}
	return winner, nil
}

// dialProxy opens a tunnel to authority through the forward proxy with
// HTTP CONNECT, authenticating with the URL's user info.
func (p *Policy) dialProxy(ctx context.Context, authority string) (rawpipe.HalfCloser, error) {
	proxy := p.cfg.Proxy
	if proxy.Scheme != "http" {
		return nil, errors.New("the forward proxy must be http://")
	}
	addr := proxy.Host
	if proxy.Port() == "" {
		addr = net.JoinHostPort(proxy.Hostname(), "80")
	}
	c, err := (&net.Dialer{KeepAlive: 30 * time.Second}).DialContext(ctx, "tcp", addr)
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
				err = fmt.Errorf("forward proxy refused CONNECT: %d", resp.StatusCode)
			}
		}
	}
	if err != nil || !stop() {
		_ = conn.Close()
		return nil, errors.Join(err, ctx.Err())
	}
	// Bytes the proxy sent after its answer belong to the tunnel.
	return &proxied{TCPConn: conn, r: br}, conn.SetDeadline(time.Time{})
}

type proxied struct {
	*net.TCPConn
	r *bufio.Reader
}

func (c *proxied) Read(b []byte) (int, error) { return c.r.Read(b) }
