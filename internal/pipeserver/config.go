package pipeserver

import (
	"cmp"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/InteractionLabs/traversal-connector/connector-lib/capability"
	"github.com/InteractionLabs/traversal-connector/connector-lib/dialpolicy"
	"github.com/InteractionLabs/traversal-connector/connector-lib/halfconn"
	"github.com/InteractionLabs/traversal-connector/connector-lib/rawpipe"
	"github.com/InteractionLabs/traversal-connector/internal/config"
	"github.com/InteractionLabs/traversal-connector/internal/redact"
	"github.com/InteractionLabs/traversal-connector/internal/upstream"
	"golang.org/x/net/http/httpproxy"
)

// New builds the pipe side from the environment, or says why the connector
// cannot run it. Responses from hosts r's rules cover are redacted.
func New(cfg *config.Config, r *redact.Redactor) (*Tunnels, error) {
	e := envReader{}
	verifier, trust, err := newVerifier(cfg.TraversalControllerURL)
	if err != nil {
		return nil, err
	}
	dial, err := newPolicy(&e)
	if err != nil {
		return nil, err
	}
	up, err := upstream.New(cfg, r, dial)
	if err != nil {
		return nil, err
	}
	m, err := newMetrics()
	if err != nil {
		return nil, err
	}
	if err := observeTrust(trust); err != nil {
		return nil, err
	}
	server := &Server{
		metrics:     m,
		ConnectorID: cfg.ConnectorID,
		Verifier:    verifier,
		Upstream:    up,
		MaxPipes:    e.int("TRAVERSAL_PIPES_MAX", 200, 4096),
		MaxLifetime: e.duration("TRAVERSAL_PIPES_MAX_LIFETIME", 4*time.Hour),
		Inner: Inner{
			MaxStreams:       e.int("TRAVERSAL_PIPES_MAX_STREAMS", 100, 1000),
			StreamWindow:     e.int("TRAVERSAL_PIPES_STREAM_WINDOW_KB", 256, 16<<10) << 10,
			ConnectionWindow: e.int("TRAVERSAL_PIPES_CONNECTION_WINDOW_KB", 1<<10, 64<<10) << 10,
			IdleTimeout:      e.duration("TRAVERSAL_PIPES_IDLE_TIMEOUT", 15*time.Minute),
		},
	}
	t := &Tunnels{
		ConnectorID: cfg.ConnectorID,
		Count:       e.int("TRAVERSAL_TUNNELS_COUNT", 2, 8),
		Server:      server,
		Roots:       trust.Roots,
		Kids:        trust.Kids,
	}
	server.Tunnels = t.Count
	if t.TLS, t.Addr, err = tunnelTLS(cfg); err != nil {
		return nil, err
	}
	server.Certificate = t.TLS.Certificates[0]
	if connectTo := os.Getenv("TRAVERSAL_TUNNELS_CONNECT_TO"); connectTo != "" {
		if err := config.ValidateConnectTo("TRAVERSAL_TUNNELS_CONNECT_TO", connectTo); err != nil {
			return nil, err
		}
		t.Addr = connectTo
	}
	if cfg.EgressProxyURL != nil {
		return nil, errors.New("tunnels through EGRESS_PROXY_URL are not supported yet")
	}
	return t, errors.Join(e.errs...)
}

// newPolicy is how every request a pipe carries reaches its destination:
// through the dial policy, and the egress proxy unless NO_PROXY exempts the
// destination.
func newPolicy(e *envReader) (upstream.Dialer, error) {
	proxy, direct, err := egressProxy()
	if err != nil {
		return nil, err
	}
	forbidden, err := forbiddenCIDRs(os.Getenv("TRAVERSAL_PIPES_FORBIDDEN_CIDRS"))
	if err != nil {
		return nil, err
	}
	fromEnv := direct != nil // a proxy from HTTPS_PROXY or HTTP_PROXY, as in #67
	cfg := dialpolicy.Config{
		Proxy:          proxy,
		ProxyResolves:  e.bool("TRAVERSAL_PIPES_EGRESS_PROXY_RESOLVES", fromEnv),
		ExtraForbidden: forbidden,
	}
	proxied, err := dialpolicy.New(cfg)
	if err != nil {
		return nil, err
	}
	if direct == nil {
		return proxied.Dial, nil
	}
	cfg.Proxy = nil
	unproxied, err := dialpolicy.New(cfg)
	if err != nil {
		return nil, err
	}
	return func(ctx context.Context, host string, port uint16) (halfconn.Conn, string, error) {
		if direct(host, port) {
			return unproxied.Dial(ctx, host, port)
		}
		return proxied.Dial(ctx, host, port)
	}, nil
}

// egressProxy is the forward proxy destinations are reached through, if any,
// and, for one from HTTPS_PROXY or HTTP_PROXY, whether NO_PROXY sends a
// destination direct instead.
func egressProxy() (*url.URL, func(host string, port uint16) bool, error) {
	ambient := httpproxy.FromEnvironment()
	raw := cmp.Or(ambient.HTTPSProxy, ambient.HTTPProxy)
	if setting := os.Getenv("TRAVERSAL_PIPES_EGRESS_PROXY"); setting != "" {
		if raw != "" {
			slog.Info("HTTPS_PROXY, HTTP_PROXY and NO_PROXY are ignored for destinations: " +
				"TRAVERSAL_PIPES_EGRESS_PROXY is set")
		}
		proxy, err := parseProxy("TRAVERSAL_PIPES_EGRESS_PROXY", setting)
		return proxy, nil, err
	}
	if raw == "" {
		return nil, nil, nil
	}
	// Backwards compatibility with #67, which honoured HTTP(S)_PROXY and
	// NO_PROXY for destinations and sent hostnames to the proxy unresolved;
	// TRAVERSAL_PIPES_EGRESS_PROXY is the documented setting.
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw // as net/http reads a bare host:port
	}
	proxy, err := parseProxy("HTTPS_PROXY or HTTP_PROXY", raw)
	if err != nil {
		return nil, nil, err
	}
	match := (&httpproxy.Config{HTTPSProxy: raw, NoProxy: ambient.NoProxy}).ProxyFunc()
	return proxy, func(host string, port uint16) bool {
		dest := &url.URL{Scheme: "https", Host: net.JoinHostPort(host, strconv.Itoa(int(port)))}
		u, err := match(dest)
		return err == nil && u == nil
	}, nil
}

// parseProxy is the http:// proxy URL raw, from setting name.
func parseProxy(name, raw string) (*url.URL, error) {
	proxy, err := url.Parse(raw)
	if err != nil || proxy.Scheme != "http" || proxy.Host == "" {
		return nil, errors.New(name + " must be an http:// URL")
	}
	return proxy, nil
}

// bundleEnv is the setting each capability trust bundle comes from.
var bundleEnv = map[capability.Bundle]string{
	capability.BundleKeys:  "TRAVERSAL_CAPABILITY_KEYS",
	capability.BundleRoots: "TRAVERSAL_CAPABILITY_ROOTS",
}

// newVerifier trusts capabilities signed by a pinned key
// (TRAVERSAL_CAPABILITY_KEYS, with TRAVERSAL_CAPABILITY_ISSUER), or certified
// under a pinned root (TRAVERSAL_CAPABILITY_ROOTS) for the controller host
// the connector dials, or both while moving from keys to roots.
func newVerifier(controllerURL string) (*capability.Verifier, capability.Loaded, error) {
	issuer := os.Getenv("TRAVERSAL_CAPABILITY_ISSUER")
	keys, roots := os.Getenv("TRAVERSAL_CAPABILITY_KEYS"), os.Getenv("TRAVERSAL_CAPABILITY_ROOTS")
	var host string
	switch {
	case keys == "" && roots == "":
		return nil, capability.Loaded{}, errors.New(
			"TRAVERSAL_CAPABILITY_KEYS or TRAVERSAL_CAPABILITY_ROOTS is required")
	case keys != "" && issuer == "":
		return nil, capability.Loaded{}, errors.New(
			"TRAVERSAL_CAPABILITY_ISSUER is required with TRAVERSAL_CAPABILITY_KEYS")
	case roots != "":
		u, err := url.Parse(controllerURL)
		ok := false
		if err == nil {
			host, ok = capability.Canonical(u.Hostname())
		}
		if !ok {
			return nil, capability.Loaded{}, errors.New(
				"TRAVERSAL_CAPABILITY_ROOTS needs a controller URL with a host name")
		}
	}
	v, loaded, err := capability.ParseTrust(
		config.DecodePEM(keys), config.DecodePEM(roots), issuer, host)
	if te, ok := errors.AsType[*capability.TrustError](err); ok {
		return nil, capability.Loaded{}, fmt.Errorf("%s: %w", bundleEnv[te.Bundle], te.Err)
	}
	return v, loaded, err
}

// tunnelTLS is mutual TLS 1.3 to the controller host, with the connector's
// own certificate and the roots its legacy tunnels trust.
func tunnelTLS(cfg *config.Config) (*tls.Config, string, error) {
	u, err := url.Parse(cfg.TraversalControllerURL)
	if err != nil || u.Scheme != "https" || cfg.TLSCert == nil || cfg.TLSKey == nil {
		return nil, "", errors.New(
			"tunnels need an https:// controller URL and a client certificate")
	}
	tlsCfg, err := config.BuildClientTLSConfig(cfg)
	if err != nil {
		return nil, "", err
	}
	if err := checkIdentity(tlsCfg.Certificates[0].Leaf, cfg.ConnectorID); err != nil {
		return nil, "", err
	}
	tlsCfg.MinVersion = tls.VersionTLS13
	tlsCfg.ServerName = u.Hostname()
	tlsCfg.NextProtos = []string{rawpipe.ALPN}
	return tlsCfg, net.JoinHostPort(u.Hostname(), "443"), nil
}

// envReader reads settings, collecting an error for each one set but invalid
// rather than falling back to its default. internal/env falls back silently,
// so a typo would quietly run the default, and its bools take "1" and "T".
type envReader struct{ errs []error }

func (e *envReader) int(key string, def, maxVal int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 || n > maxVal {
		e.errs = append(e.errs, fmt.Errorf("%s must be 1 to %d, got %q", key, maxVal, v))
	}
	return n
}

func (e *envReader) duration(key string, def time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil || d < 0 {
		e.errs = append(e.errs, fmt.Errorf("%s must be a duration such as 15m, got %q", key, v))
	}
	return d
}

func (e *envReader) bool(key string, def bool) bool {
	switch v := os.Getenv(key); v {
	case "":
		return def
	case "false":
		return false
	case "true":
		return true
	default:
		e.errs = append(e.errs, fmt.Errorf("%s must be true or false, got %q", key, v))
		return def
	}
}

// forbiddenCIDRs parses TRAVERSAL_PIPES_FORBIDDEN_CIDRS, comma-separated
// CIDRs the connector refuses beside its built-in list.
func forbiddenCIDRs(v string) ([]netip.Prefix, error) {
	if v == "" {
		return nil, nil
	}
	var prefixes []netip.Prefix
	for cidr := range strings.SplitSeq(v, ",") {
		p, err := netip.ParsePrefix(strings.TrimSpace(cidr))
		if err != nil {
			return nil, fmt.Errorf("TRAVERSAL_PIPES_FORBIDDEN_CIDRS: %q is not a CIDR", cidr)
		}
		prefixes = append(prefixes, p)
	}
	return prefixes, nil
}

// checkIdentity refuses a certificate the edge controller would refuse, so
// such a connector keeps to the legacy transport and says why.
// It applies rawpipe.CheckIdentity, the edge controller's rule, naming the
// setting and certificate it read.
func checkIdentity(cert *x509.Certificate, connectorID string) error {
	if !rawpipe.IsConnectorID(connectorID) {
		return fmt.Errorf("TRAVERSAL_CONNECTOR_ID %q is not a lower-case UUID", connectorID)
	}
	if cert == nil || len(cert.URIs) != 1 {
		return errors.New("the client certificate needs exactly one Traversal tenant SPIFFE ID")
	}
	if err := rawpipe.CheckIdentity(cert.URIs[0].String(), connectorID); err != nil {
		return fmt.Errorf("the client certificate: %w", err)
	}
	return nil
}
