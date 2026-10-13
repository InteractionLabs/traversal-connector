package rawpipes

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/InteractionLabs/traversal-connector/connector-lib/capability"
	"github.com/InteractionLabs/traversal-connector/connector-lib/dialpolicy"
	"github.com/InteractionLabs/traversal-connector/connector-lib/rawpipe"
	"github.com/InteractionLabs/traversal-connector/internal/config"
)

// systemRoots is where container images keep their CA bundle.
var systemRoots = []string{"/etc/ssl/certs/ca-certificates.crt", "/etc/ssl/cert.pem"}

// New builds the raw pipe side from the environment, or says why the
// connector cannot run it. requiresInspection reports hosts redaction rules
// cover.
func New(cfg *config.Config, requiresInspection func(string) bool) (*Tunnels, error) {
	e := envReader{}
	verifier, trust, err := newVerifier(cfg.TraversalControllerURL)
	if err != nil {
		return nil, err
	}
	var proxy *url.URL
	if raw := os.Getenv("TRAVERSAL_RAW_PIPES_EGRESS_PROXY"); raw != "" {
		if proxy, err = url.Parse(raw); err != nil || proxy.Scheme != "http" || proxy.Host == "" {
			return nil, errors.New("TRAVERSAL_RAW_PIPES_EGRESS_PROXY must be an http:// URL")
		}
	}
	policy, err := dialpolicy.New(dialpolicy.Config{
		Proxy:         proxy,
		ProxyResolves: e.bool("TRAVERSAL_RAW_PIPES_EGRESS_PROXY_RESOLVES"),
	})
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
		metrics:            m,
		ConnectorID:        cfg.ConnectorID,
		Verifier:           verifier,
		Policy:             policy,
		MaxPipes:           int64(e.int("TRAVERSAL_RAW_PIPES_MAX", 200, 4096)),
		RequiresInspection: requiresInspection,
		RefuseTCP:          e.bool("TRAVERSAL_RAW_PIPES_REFUSE_TCP"),
		MaxLifetime:        e.duration("TRAVERSAL_RAW_PIPES_MAX_LIFETIME", 4*time.Hour),
		IdleTimeout:        e.duration("TRAVERSAL_RAW_PIPES_IDLE_TIMEOUT", 15*time.Minute),
	}
	t := &Tunnels{
		ConnectorID: cfg.ConnectorID,
		Count:       e.int("TRAVERSAL_TUNNEL_COUNT", 2, 8),
		Server:      server,
		Roots:       trust.roots,
		Kids:        trust.kids,
	}
	server.Tunnels = t.Count
	if t.TLS, t.Addr, err = tunnelTLS(cfg); err != nil {
		return nil, err
	}
	if connectTo := os.Getenv("TRAVERSAL_TUNNELS_CONNECT_TO"); connectTo != "" {
		if host, port, err := net.SplitHostPort(connectTo); err != nil || host == "" || port == "" {
			return nil, fmt.Errorf(
				"TRAVERSAL_TUNNELS_CONNECT_TO must be host:port, got %q",
				connectTo,
			)
		}
		t.Addr = connectTo
	}
	if cfg.EgressProxyURL != nil {
		return nil, errors.New("tunnels through EGRESS_PROXY_URL are not supported yet")
	}
	return t, errors.Join(e.errs...)
}

// trust is the capability trust a connector has loaded, as it reports it:
// each root's rawpipe.RootFingerprint, and the pinned keys' IDs, sorted.
type trust struct{ roots, kids []string }

// newVerifier trusts capabilities signed by a pinned key
// (TRAVERSAL_CAPABILITY_KEYS, with TRAVERSAL_CAPABILITY_ISSUER), or certified
// under a pinned root (TRAVERSAL_CAPABILITY_ROOTS) for the controller host
// the connector dials, or both while moving from keys to roots.
func newVerifier(controllerURL string) (*capability.Verifier, trust, error) {
	vc := capability.VerifierConfig{
		Issuer:  os.Getenv("TRAVERSAL_CAPABILITY_ISSUER"),
		Subject: "integration-proxy",
	}
	keys, roots := os.Getenv("TRAVERSAL_CAPABILITY_KEYS"), os.Getenv("TRAVERSAL_CAPABILITY_ROOTS")
	if keys == "" && roots == "" {
		return nil, trust{}, errors.New(
			"TRAVERSAL_CAPABILITY_KEYS or TRAVERSAL_CAPABILITY_ROOTS is required",
		)
	}
	var err error
	if keys != "" {
		if vc.Keys, err = capability.ParseKeys([]byte(decodePEM(keys))); err != nil {
			return nil, trust{}, fmt.Errorf("TRAVERSAL_CAPABILITY_KEYS: %w", err)
		}
		if vc.Issuer == "" {
			return nil, trust{}, errors.New(
				"TRAVERSAL_CAPABILITY_ISSUER is required with TRAVERSAL_CAPABILITY_KEYS",
			)
		}
	}
	if roots != "" {
		if vc.Roots, err = capability.ParseRootsPEM([]byte(decodePEM(roots))); err != nil {
			return nil, trust{}, fmt.Errorf("TRAVERSAL_CAPABILITY_ROOTS: %w", err)
		}
		u, err := url.Parse(controllerURL)
		host, ok := "", false
		if err == nil {
			host, ok = capability.Canonical(u.Hostname())
		}
		if !ok {
			return nil, trust{}, errors.New(
				"TRAVERSAL_CAPABILITY_ROOTS needs a controller URL with a host name",
			)
		}
		vc.ControllerHost = host
	}
	var t trust
	for _, root := range vc.Roots {
		t.roots = append(t.roots, rawpipe.RootFingerprint(root.Raw))
	}
	for kid := range vc.Keys {
		t.kids = append(t.kids, kid)
	}
	slices.Sort(t.kids)
	v, err := capability.NewVerifier(vc)
	return v, t, err
}

// tunnelTLS is mutual TLS 1.3 to the controller host, with the connector's
// own certificate and the roots its other connections trust.
func tunnelTLS(cfg *config.Config) (*tls.Config, string, error) {
	u, err := url.Parse(cfg.TraversalControllerURL)
	if err != nil || u.Scheme != "https" || cfg.TLSCert == nil || cfg.TLSKey == nil {
		return nil, "", errors.New(
			"tunnels need an https:// controller URL and a client certificate",
		)
	}
	cert, err := tls.X509KeyPair([]byte(*cfg.TLSCert), []byte(*cfg.TLSKey))
	if err != nil {
		return nil, "", err
	}
	if err := checkIdentity(cert.Leaf, cfg.ConnectorID); err != nil {
		return nil, "", err
	}
	roots := x509.NewCertPool()
	// SSL_CERT_FILE first: customers set it for TLS-intercepting proxies, as
	// for the connector's other connections.
	paths := systemRoots
	if f := os.Getenv("SSL_CERT_FILE"); f != "" {
		paths = append([]string{f}, paths...)
	}
	for _, path := range paths {
		if pem, err := os.ReadFile(path); err == nil { //nolint:gosec // fixed paths
			roots.AppendCertsFromPEM(pem)
		}
	}
	if cfg.TLSCA != nil {
		roots.AppendCertsFromPEM([]byte(*cfg.TLSCA))
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		ServerName:   u.Hostname(),
		Certificates: []tls.Certificate{cert},
		RootCAs:      roots,
		NextProtos:   []string{rawpipe.ALPN},
	}, net.JoinHostPort(u.Hostname(), "443"), nil
}

// envReader reads settings, collecting an error for each one set but invalid
// rather than falling back to its default.
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

func (e *envReader) bool(key string) bool {
	switch v := os.Getenv(key); v {
	case "", "false":
		return false
	case "true":
		return true
	default:
		e.errs = append(e.errs, fmt.Errorf("%s must be true or false, got %q", key, v))
		return false
	}
}

// decodePEM accepts PEM raw or base64-encoded, the install command's form.
func decodePEM(v string) string {
	if b, err := base64.StdEncoding.DecodeString(v); err == nil &&
		strings.HasPrefix(string(b), "-----") {
		return string(b)
	}
	return v
}

// checkIdentity refuses a certificate the edge controller would refuse, so
// such a connector keeps to the legacy transport and says why.
func checkIdentity(cert *x509.Certificate, connectorID string) error {
	if !rawpipe.IsConnectorID(connectorID) {
		return fmt.Errorf("TRAVERSAL_CONNECTOR_ID %q is not a lower-case UUID", connectorID)
	}
	if cert == nil || len(cert.URIs) != 1 {
		return errors.New("the client certificate needs exactly one Traversal tenant SPIFFE ID")
	}
	_, scoped, ok := rawpipe.TenantID(cert.URIs[0].String())
	switch {
	case !ok:
		return errors.New("the client certificate has no Traversal tenant SPIFFE ID")
	case scoped != "" && scoped != connectorID:
		return fmt.Errorf("the client certificate is for connector %s, not %s", scoped, connectorID)
	}
	return nil
}
