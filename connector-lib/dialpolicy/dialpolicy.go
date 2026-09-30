// Package dialpolicy connects the connector to a raw pipe's destination and
// refuses destinations a pipe must never reach.
//
// A direct dial resolves the host once, as an absolute name so a search list
// cannot rewrite it, refuses the pipe if any returned address is forbidden,
// and dials the checked addresses at once. One that never answers cannot use
// up the deadline and hide another. The authorized host is never replaced by
// the dialed address: callers keep it for audit, and a proxied dial sends the
// absolute name to the proxy.
//
// A proxied dial sends CONNECT host:port to the customer's forward proxy, which
// resolves the host and connects on its own. The connector then enforces only a
// floor: an IP-literal destination is checked like a direct one, and names that
// always reach the local host or cloud metadata are refused. Which addresses a
// hostname reaches through the proxy is delegated to the proxy's own policy, so
// proxied hostnames are refused unless Config.AllowDelegatedProxyChecks records
// that the operator accepted this.
package dialpolicy

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"time"

	"golang.org/x/net/http/httpproxy"

	"github.com/InteractionLabs/traversal-connector/connector-lib/capability"
	pb "github.com/InteractionLabs/traversal-connector/connector-lib/gen/connector/v1"
)

// KeepAlive is the TCP keepalive period of connections Dial makes.
const KeepAlive = 30 * time.Second

// maxDialTargets caps how many unique addresses one pipe may dial at once.
// LookupNetIP has no small result bound; without a cap, repeated RRs and
// IPv4-mapped duplicates could fan one admitted pipe into unbounded
// goroutines and sockets. Eight covers legitimate dual-stack and small
// multi-homed answers without letting DNS amplify a single admission.
const maxDialTargets = 8

// Code classifies a refused or failed dial.
type Code string

// Refusal codes.
const (
	CodeInvalidDestination Code = "invalid_destination"
	CodeInspectionRequired Code = "inspection_required"
	CodeForbiddenAddress   Code = "forbidden_address"
	// CodeProxyChecksDelegated refuses a proxied hostname, whose address only
	// the proxy sees, when delegating that check is not allowed.
	CodeProxyChecksDelegated Code = "proxy_checks_delegated"
	CodeResolveFailed        Code = "resolve_failed"
	CodeDialFailed           Code = "dial_failed"
)

// Refusal reports why Dial did not connect. It never contains proxy
// credentials.
type Refusal struct {
	Code Code
	err  error
}

func (r *Refusal) Error() string {
	if r.err == nil {
		return "dialpolicy: " + string(r.Code)
	}
	return fmt.Sprintf("dialpolicy: %s: %v", r.Code, r.err)
}

func (r *Refusal) Unwrap() error {
	return r.err
}

// OpenFailureReason maps the refusal to the reason sent in RawOpenError.
func (r *Refusal) OpenFailureReason() pb.RawOpenFailureReason {
	switch r.Code {
	case CodeInvalidDestination:
		return pb.RawOpenFailureReason_RAW_OPEN_FAILURE_REASON_PROTOCOL_ERROR
	case CodeInspectionRequired:
		return pb.RawOpenFailureReason_RAW_OPEN_FAILURE_REASON_INSPECTION_REQUIRED
	case CodeForbiddenAddress, CodeProxyChecksDelegated:
		return pb.RawOpenFailureReason_RAW_OPEN_FAILURE_REASON_FORBIDDEN_ADDRESS
	case CodeResolveFailed:
		return pb.RawOpenFailureReason_RAW_OPEN_FAILURE_REASON_DNS_FAILED
	default:
		return pb.RawOpenFailureReason_RAW_OPEN_FAILURE_REASON_DIAL_FAILED
	}
}

func refuse(code Code, err error) *Refusal {
	return &Refusal{Code: code, err: err}
}

// Config configures a Policy.
type Config struct {
	// Forbidden adds ranges a pipe must never reach, such as the cluster's pod
	// and service ranges, to the built-in list and the connector's own
	// addresses.
	Forbidden []netip.Prefix
	// RequiresInspection reports destinations whose traffic must pass
	// connector-side payload inspection, which a raw pipe cannot provide. Nil
	// means none do.
	RequiresInspection func(host string, port uint16) bool
	// Proxy returns the forward proxy for a destination, or nil to dial it
	// directly. Nil uses HTTPS_PROXY and NO_PROXY (or their lowercase forms),
	// because CONNECT is how a forward proxy carries TLS.
	Proxy func(host string, port uint16) (*url.URL, error)
	// AllowDelegatedProxyChecks permits proxied dials to hostnames. Set it
	// only where the customer's proxy refuses loopback, link-local, and
	// metadata addresses itself.
	AllowDelegatedProxyChecks bool
	// LookupNetIP resolves hostnames. Nil uses net.DefaultResolver.
	LookupNetIP func(ctx context.Context, network, host string) ([]netip.Addr, error)
	// DialContext connects to checked addresses and proxies. Nil uses a
	// net.Dialer with KeepAlive. Its connections must implement CloseWrite.
	DialContext func(ctx context.Context, network, address string) (net.Conn, error)
	// ProxyTLS configures TLS to https:// proxies. Nil uses the system roots.
	ProxyTLS *tls.Config
}

// Conn is a connection to a destination. CloseWrite half-closes it.
type Conn interface {
	net.Conn
	CloseWrite() error
}

// Route records how Dial reached a destination.
type Route struct {
	// Addr is the checked address a direct dial connected to. It is the zero
	// value for a proxied dial.
	Addr netip.AddrPort
	// Proxy is the forward proxy a proxied dial went through, without
	// credentials. It is nil for a direct dial.
	Proxy *url.URL
}

// Policy checks and dials raw pipe destinations. It is safe for concurrent
// use.
type Policy struct {
	deny           []netip.Prefix
	inspect        func(string, uint16) bool
	proxy          func(string, uint16) (*url.URL, error)
	allowDelegated bool
	lookup         func(context.Context, string, string) ([]netip.Addr, error)
	dial           func(context.Context, string, string) (net.Conn, error)
	proxyTLS       *tls.Config
}

// New returns a Policy for cfg. It snapshots the host's interface addresses
// and, when cfg.Proxy is nil, the proxy environment variables.
func New(cfg Config) (*Policy, error) {
	self, err := interfacePrefixes()
	if err != nil {
		return nil, fmt.Errorf("dialpolicy: list interface addresses: %w", err)
	}
	deny := append(append([]netip.Prefix{}, builtinForbidden...), self...)
	for _, prefix := range cfg.Forbidden {
		normalized, err := normalizePrefix(prefix)
		if err != nil {
			return nil, err
		}
		deny = append(deny, normalized)
	}
	p := &Policy{
		deny:           deny,
		inspect:        cfg.RequiresInspection,
		proxy:          cfg.Proxy,
		allowDelegated: cfg.AllowDelegatedProxyChecks,
		lookup:         cfg.LookupNetIP,
		dial:           cfg.DialContext,
		proxyTLS:       cfg.ProxyTLS,
	}
	if p.proxy == nil {
		p.proxy = environmentProxy()
	}
	if p.lookup == nil {
		p.lookup = net.DefaultResolver.LookupNetIP
	}
	if p.dial == nil {
		p.dial = (&net.Dialer{KeepAlive: KeepAlive}).DialContext
	}
	return p, nil
}

func environmentProxy() func(string, uint16) (*url.URL, error) {
	proxyFor := httpproxy.FromEnvironment().ProxyFunc()
	return func(host string, port uint16) (*url.URL, error) {
		return proxyFor(&url.URL{Scheme: "https", Host: capability.CanonicalAuthority(host, port)})
	}
}

// Dial connects to host:port, where host is canonical as
// capability.CanonicalHost returns it. Every error is a *Refusal. The host is
// checked before any lookup or connection, and every resolved address before
// any is dialed.
func (p *Policy) Dial(ctx context.Context, host string, port uint16) (Conn, Route, error) {
	if canonical, err := capability.CanonicalHost(host); err != nil || canonical != host ||
		port == 0 {
		return nil, Route{}, refuse(CodeInvalidDestination, errors.New("host is not canonical"))
	}
	if p.inspect != nil && p.inspect(host, port) {
		return nil, Route{}, refuse(CodeInspectionRequired, nil)
	}
	literal, err := netip.ParseAddr(host)
	isLiteral := err == nil
	if isLiteral && p.forbidden(literal) || forbiddenName(host) {
		return nil, Route{}, refuse(CodeForbiddenAddress, nil)
	}
	proxy, err := p.proxy(host, port)
	if err != nil {
		// The error can quote the proxy URL, credentials included.
		return nil, Route{}, refuse(CodeDialFailed, errors.New("invalid forward proxy"))
	}
	if proxy != nil {
		if !isLiteral && !p.allowDelegated {
			return nil, Route{}, refuse(CodeProxyChecksDelegated, nil)
		}
		// Absolute form, so the proxy's resolver cannot rewrite the name with a
		// search list. The capability still records the canonical host.
		conn, err := p.dialProxy(ctx, proxy,
			capability.CanonicalAuthority(capability.AbsoluteHost(host), port))
		if err != nil {
			return nil, Route{}, refuse(CodeDialFailed, err)
		}
		return conn, Route{Proxy: withoutCredentials(proxy)}, nil
	}

	addrs := []netip.Addr{literal}
	if !isLiteral {
		addrs, err = p.lookup(ctx, "ip", capability.AbsoluteHost(host))
		if err != nil {
			return nil, Route{}, refuse(CodeResolveFailed, err)
		}
		if len(addrs) == 0 {
			return nil, Route{}, refuse(CodeResolveFailed, errors.New("no addresses"))
		}
	}
	targets, err := dialTargets(addrs, port)
	if err != nil {
		return nil, Route{}, refuse(CodeResolveFailed, err)
	}
	for _, target := range targets {
		if p.forbidden(target.Addr()) {
			return nil, Route{}, refuse(CodeForbiddenAddress, nil)
		}
	}
	conn, addr, err := p.dialChecked(ctx, targets)
	if err != nil {
		return nil, Route{}, refuse(CodeDialFailed, err)
	}
	return conn, Route{Addr: addr}, nil
}

// dialTargets unmaps IPv4-mapped addresses, clears zones, and deduplicates
// before any dial. It refuses when the unique set exceeds maxDialTargets so
// one pipe cannot fan out unboundedly.
func dialTargets(addrs []netip.Addr, port uint16) ([]netip.AddrPort, error) {
	seen := make(map[netip.Addr]struct{}, len(addrs))
	targets := make([]netip.AddrPort, 0, len(addrs))
	for _, addr := range addrs {
		addr = addr.Unmap().WithZone("")
		if _, ok := seen[addr]; ok {
			continue
		}
		seen[addr] = struct{}{}
		targets = append(targets, netip.AddrPortFrom(addr, port))
	}
	if len(targets) > maxDialTargets {
		return nil, fmt.Errorf("resolved %d unique addresses; limit is %d",
			len(targets), maxDialTargets)
	}
	return targets, nil
}

// dialChecked dials every allowed address at once and returns the first
// connection. One address that never answers must not consume the whole
// deadline and hide an address that would have worked. targets must already
// be normalized by dialTargets, so len(targets) never exceeds maxDialTargets.
func (p *Policy) dialChecked(
	ctx context.Context, targets []netip.AddrPort,
) (Conn, netip.AddrPort, error) {
	if len(targets) == 0 {
		return nil, netip.AddrPort{}, errors.New("no addresses")
	}
	if len(targets) > maxDialTargets {
		return nil, netip.AddrPort{}, fmt.Errorf(
			"resolved %d unique addresses; limit is %d",
			len(targets), maxDialTargets)
	}
	if len(targets) == 1 {
		conn, err := p.dialConn(ctx, targets[0].String())
		if err != nil {
			return nil, netip.AddrPort{}, err
		}
		return conn, targets[0], nil
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	type dialResult struct {
		conn Conn
		addr netip.AddrPort
		err  error
	}
	results := make(chan dialResult, len(targets))
	for _, target := range targets {
		go func() {
			conn, err := p.dialConn(ctx, target.String())
			results <- dialResult{conn: conn, addr: target, err: err}
		}()
	}
	var (
		errs       []error
		winner     Conn
		winnerAddr netip.AddrPort
	)
	for range targets {
		result := <-results
		if result.err != nil {
			errs = append(errs, result.err)
			continue
		}
		if winner != nil {
			_ = result.conn.Close()
			continue
		}
		winner, winnerAddr = result.conn, result.addr
		cancel()
	}
	if winner == nil {
		return nil, netip.AddrPort{}, errors.Join(errs...)
	}
	return winner, winnerAddr, nil
}

func (p *Policy) dialConn(ctx context.Context, address string) (Conn, error) {
	raw, err := p.dial(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	conn, ok := raw.(Conn)
	if !ok {
		_ = raw.Close()
		return nil, errors.New("dialer returned a connection without CloseWrite")
	}
	return conn, nil
}

func withoutCredentials(u *url.URL) *url.URL {
	clean := *u
	clean.User = nil
	return &clean
}
