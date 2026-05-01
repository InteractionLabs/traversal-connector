package client

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/InteractionLabs/traversal-connector/internal/config"
)

const connectivityTestTimeout = 10 * time.Second

// TestConnectivity runs a suite of connectivity tests against the Traversal control plane
// controller and, when configured, the forward proxy. Every test logs
// its result extensively regardless of success or failure.
//
// The tests executed depend on the configuration:
//
// Always:
//   - Direct TLS dial (insecure — mirrors grpcurl -insecure)
//   - Direct TLS dial (secure  — full cert verification)
//
// When EgressProxyURL is set, three additional proxy-specific tests run first:
//  1. Proxy TCP reachability  — plain TCP dial to the proxy
//  2. Manual HTTP CONNECT + TLS — hand-rolled CONNECT tunnel, then TLS
//  3. Go http.Transport + Proxy — uses Go's built-in proxy support
//     (same mechanism the production gRPC transport uses)
//
// Only the insecure direct-TLS test is fatal (returns error). All other
// failures are logged as warnings so the service can still attempt to start.
func TestConnectivity(cfg *config.Config) error {
	addr, err := extractHostPort(cfg.TraversalControllerURL)
	if err != nil {
		return fmt.Errorf(
			"failed to parse controller URL: %w", err,
		)
	}

	// --- shared TLS material ---
	clientCerts, caPool, loadErr := loadTLSMaterial(cfg)
	if loadErr != nil {
		return loadErr
	}

	// --- proxy ---
	var egressProxyURL *url.URL
	if cfg.EgressProxyURL != nil {
		egressProxyURL, err = url.Parse(*cfg.EgressProxyURL)
		if err != nil {
			slog.Error(
				"connectivity test: invalid EGRESS_PROXY_URL, skipping proxy tests",
				"egress_proxy_url", *cfg.EgressProxyURL,
				"error", err,
			)
			egressProxyURL = nil
		}
	}

	// ---------------------------------------------------------------
	// Proxy-specific tests (only when EgressProxyURL is set)
	// ---------------------------------------------------------------
	if egressProxyURL != nil {
		testProxyTCPReachability(egressProxyURL)
		testManualCONNECT(
			addr, egressProxyURL, clientCerts, caPool,
		)
		testHTTPTransportViaProxy(
			cfg.TraversalControllerURL, addr, egressProxyURL,
			clientCerts, caPool,
		)
	}

	// ---------------------------------------------------------------
	// Test: Direct TLS — insecure (skip server verification)
	// ---------------------------------------------------------------
	slog.Info(
		"connectivity test [direct-insecure]: starting",
		"address", addr,
		"has_client_cert", len(clientCerts) > 0,
		"has_ca", caPool != nil,
	)

	//nolint:gosec // InsecureSkipVerify mirrors grpcurl -insecure.
	insecureTLS := &tls.Config{
		InsecureSkipVerify: true,
		Certificates:       clientCerts,
		RootCAs:            caPool,
		NextProtos:         []string{"h2"},
	}
	if dialErr := directTLSDial(
		addr, insecureTLS, "direct-insecure",
	); dialErr != nil {
		return fmt.Errorf(
			"insecure connectivity test failed: %w", dialErr,
		)
	}

	// ---------------------------------------------------------------
	// Test: Direct TLS — secure (full certificate verification)
	// ---------------------------------------------------------------
	slog.Info(
		"connectivity test [direct-secure]: starting",
		"address", addr,
		"has_client_cert", len(clientCerts) > 0,
		"has_ca", caPool != nil,
		"server_name", cfg.TLSServerName,
	)

	secureTLS := &tls.Config{
		Certificates: clientCerts,
		RootCAs:      caPool,
		ServerName:   cfg.TLSServerName,
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"h2"},
	}
	if dialErr := directTLSDial(
		addr, secureTLS, "direct-secure",
	); dialErr != nil {
		slog.Warn(
			"connectivity test [direct-secure]: FAILED",
			"address", addr,
			"error", dialErr,
		)
	}

	return nil
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

// loadTLSMaterial loads client certs and CA pool from config.
func loadTLSMaterial(
	cfg *config.Config,
) ([]tls.Certificate, *x509.CertPool, error) {
	var clientCerts []tls.Certificate
	if cfg.TLSCert != nil && cfg.TLSKey != nil {
		slog.Debug(
			"connectivity test: loading client certificate from PEM",
		)
		cert, err := tls.X509KeyPair(
			[]byte(*cfg.TLSCert), []byte(*cfg.TLSKey),
		)
		if err != nil {
			return nil, nil, fmt.Errorf(
				"failed to load client certificate: %w", err,
			)
		}
		slog.Info(
			"connectivity test: client certificate loaded",
			"subject", cert.Leaf,
		)
		clientCerts = []tls.Certificate{cert}
	} else {
		slog.Info(
			"connectivity test: no client certificate configured",
		)
	}

	var caPool *x509.CertPool
	if cfg.TLSCA != nil {
		caPool = x509.NewCertPool()
		if ok := caPool.AppendCertsFromPEM([]byte(*cfg.TLSCA)); !ok {
			slog.Warn(
				"connectivity test: failed to parse CA cert, " +
					"will use system roots",
			)
			caPool = nil
		} else {
			slog.Info("connectivity test: custom CA pool loaded")
		}
	} else {
		slog.Info(
			"connectivity test: no custom CA configured, " +
				"using system roots",
		)
	}

	return clientCerts, caPool, nil
}

// logTLSState logs everything interesting about a TLS connection.
func logTLSState(label, addr string, state tls.ConnectionState) {
	slog.Info(
		fmt.Sprintf("connectivity test [%s]: TLS state", label),
		"address", addr,
		"tls_version", tlsVersionName(state.Version),
		"cipher_suite", tls.CipherSuiteName(state.CipherSuite),
		"negotiated_protocol", state.NegotiatedProtocol,
		"server_name", state.ServerName,
		"handshake_complete", state.HandshakeComplete,
		"mutual_tls", len(state.PeerCertificates) > 0,
		"peer_certificates", len(state.PeerCertificates),
		"verified_chains", len(state.VerifiedChains),
	)
	for i, cert := range state.PeerCertificates {
		slog.Info(
			fmt.Sprintf(
				"connectivity test [%s]: peer cert #%d", label, i,
			),
			"subject", cert.Subject.String(),
			"issuer", cert.Issuer.String(),
			"serial", cert.SerialNumber.String(),
			"not_before", cert.NotBefore,
			"not_after", cert.NotAfter,
			"dns_names", cert.DNSNames,
			"ip_addresses", cert.IPAddresses,
			"is_ca", cert.IsCA,
		)
	}
}

// ---------------------------------------------------------------------------
// Test 1: Proxy TCP reachability
// ---------------------------------------------------------------------------

func testProxyTCPReachability(egressProxyURL *url.URL) {
	proxyAddr := proxyHostPort(egressProxyURL)
	slog.Info(
		"connectivity test [proxy-tcp]: dialing proxy",
		"proxy_address", proxyAddr,
	)

	ctx, cancel := context.WithTimeout(
		context.Background(), connectivityTestTimeout,
	)
	defer cancel()

	start := time.Now()
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", proxyAddr)
	elapsed := time.Since(start)

	if err != nil {
		slog.Warn(
			"connectivity test [proxy-tcp]: FAILED — cannot reach proxy",
			"proxy_address", proxyAddr,
			"latency", elapsed.String(),
			"error", err,
		)
		return
	}
	_ = conn.Close()

	slog.Info(
		"connectivity test [proxy-tcp]: OK — proxy is reachable",
		"proxy_address", proxyAddr,
		"latency", elapsed.String(),
	)
}

// ---------------------------------------------------------------------------
// Test 2: Manual HTTP CONNECT tunnel + TLS (insecure)
// ---------------------------------------------------------------------------

func testManualCONNECT(
	targetAddr string,
	egressProxyURL *url.URL,
	clientCerts []tls.Certificate,
	caPool *x509.CertPool,
) {
	label := "proxy-manual-connect"
	proxyAddr := proxyHostPort(egressProxyURL)
	slog.Info(
		fmt.Sprintf("connectivity test [%s]: starting", label),
		"proxy_address", proxyAddr,
		"target_address", targetAddr,
	)

	ctx, cancel := context.WithTimeout(
		context.Background(), connectivityTestTimeout,
	)
	defer cancel()

	start := time.Now()

	// Step 1 — TCP to proxy.
	slog.Debug(
		fmt.Sprintf(
			"connectivity test [%s]: TCP dialing proxy", label,
		),
		"proxy_address", proxyAddr,
	)
	rawConn, err := (&net.Dialer{}).DialContext(
		ctx, "tcp", proxyAddr,
	)
	if err != nil {
		slog.Warn(
			fmt.Sprintf(
				"connectivity test [%s]: FAILED — TCP to proxy",
				label,
			),
			"proxy_address", proxyAddr,
			"error", err,
		)
		return
	}

	// Step 2 — HTTP CONNECT request.
	slog.Debug(
		fmt.Sprintf(
			"connectivity test [%s]: sending CONNECT", label,
		),
		"target_address", targetAddr,
	)
	connectReq := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Opaque: targetAddr},
		Host:   targetAddr,
		Header: make(http.Header),
	}
	if writeErr := connectReq.Write(rawConn); writeErr != nil {
		_ = rawConn.Close()
		slog.Warn(
			fmt.Sprintf(
				"connectivity test [%s]: FAILED — write CONNECT",
				label,
			),
			"error", writeErr,
		)
		return
	}

	// Step 3 — read CONNECT response. Use a bufio.Reader, but wrap the
	// connection so reads after the HTTP response come from the buffer
	// (avoids losing bytes the reader may have read ahead of the response).
	br := bufio.NewReader(rawConn)
	resp, err := http.ReadResponse(br, connectReq)
	if err != nil {
		_ = rawConn.Close()
		slog.Warn(
			fmt.Sprintf(
				"connectivity test [%s]: "+
					"FAILED — read CONNECT response",
				label,
			),
			"error", err,
		)
		return
	}
	_ = resp.Body.Close()

	slog.Info(
		fmt.Sprintf(
			"connectivity test [%s]: CONNECT response received",
			label,
		),
		"status", resp.Status,
		"status_code", resp.StatusCode,
		"proto", resp.Proto,
		"content_length", resp.ContentLength,
	)
	for k, v := range resp.Header {
		slog.Debug(
			fmt.Sprintf(
				"connectivity test [%s]: CONNECT response header",
				label,
			),
			"key", k,
			"value", v,
		)
	}

	if resp.StatusCode != http.StatusOK {
		_ = rawConn.Close()
		slog.Warn(
			fmt.Sprintf(
				"connectivity test [%s]: FAILED — proxy rejected",
				label,
			),
			"status", resp.Status,
		)
		return
	}

	// Step 4 — TLS handshake over the tunneled connection.
	// Wrap with bufferedConn so any bytes already buffered by the
	// bufio.Reader are not lost during the TLS handshake.
	tunnelConn := newBufferedConn(br, rawConn)

	//nolint:gosec // InsecureSkipVerify intentional for diagnostics.
	tlsCfg := &tls.Config{
		InsecureSkipVerify: true,
		Certificates:       clientCerts,
		RootCAs:            caPool,
		NextProtos:         []string{"h2"},
	}

	slog.Debug(
		fmt.Sprintf(
			"connectivity test [%s]: starting TLS handshake",
			label,
		),
	)
	tlsConn := tls.Client(tunnelConn, tlsCfg)
	if hsErr := tlsConn.HandshakeContext(ctx); hsErr != nil {
		_ = rawConn.Close()
		slog.Warn(
			fmt.Sprintf(
				"connectivity test [%s]: "+
					"FAILED — TLS handshake over tunnel",
				label,
			),
			"target_address", targetAddr,
			"error", hsErr,
		)
		return
	}
	defer func() { _ = tlsConn.Close() }()

	elapsed := time.Since(start)
	slog.Info(
		fmt.Sprintf(
			"connectivity test [%s]: OK — tunnel + TLS succeeded",
			label,
		),
		"proxy_address", proxyAddr,
		"target_address", targetAddr,
		"latency", elapsed.String(),
	)
	logTLSState(label, targetAddr, tlsConn.ConnectionState())
}

// ---------------------------------------------------------------------------
// Test 3: Go http.Transport with Proxy (same as production gRPC transport)
// ---------------------------------------------------------------------------

func testHTTPTransportViaProxy(
	controllerUrl string,
	targetAddr string,
	egressProxyURL *url.URL,
	clientCerts []tls.Certificate,
	caPool *x509.CertPool,
) {
	label := "proxy-http-transport"
	slog.Info(
		fmt.Sprintf("connectivity test [%s]: starting", label),
		"traversal_controller_url", controllerUrl,
		"egress_proxy_url", egressProxyURL.String(),
		"target_address", targetAddr,
	)

	//nolint:gosec // InsecureSkipVerify intentional for diagnostics.
	transport := &http.Transport{
		ForceAttemptHTTP2: true,
		Proxy:             http.ProxyURL(egressProxyURL),
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			Certificates:       clientCerts,
			RootCAs:            caPool,
			NextProtos:         []string{"h2"},
		},
	}

	httpClient := &http.Client{
		Transport: transport,
		Timeout:   connectivityTestTimeout,
	}

	// Build a request to the controller's base URL. We expect some
	// kind of HTTP response (even a 404 or gRPC error) — any response
	// proves the proxy tunnel and TLS are working.
	reqURL := controllerUrl
	slog.Debug(
		fmt.Sprintf(
			"connectivity test [%s]: sending GET via http.Transport",
			label,
		),
		"url", reqURL,
		"proxy", egressProxyURL.String(),
	)

	start := time.Now()
	resp, err := httpClient.Get(reqURL) //nolint:noctx // one-shot diagnostic
	elapsed := time.Since(start)

	if err != nil {
		slog.Warn(
			fmt.Sprintf(
				"connectivity test [%s]: "+
					"FAILED — http.Transport request",
				label,
			),
			"url", reqURL,
			"proxy", egressProxyURL.String(),
			"latency", elapsed.String(),
			"error", err,
		)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	// Read a small amount of the body for diagnostics.
	const maxSnippetSize = 512
	bodySnippet := make([]byte, maxSnippetSize)
	n, _ := io.ReadFull(resp.Body, bodySnippet) //nolint:errcheck // best-effort diagnostic read

	slog.Info(
		fmt.Sprintf(
			"connectivity test [%s]: OK — got HTTP response",
			label,
		),
		"url", reqURL,
		"proxy", egressProxyURL.String(),
		"latency", elapsed.String(),
		"status", resp.Status,
		"status_code", resp.StatusCode,
		"proto", resp.Proto,
		"content_length", resp.ContentLength,
		"body_snippet", string(bodySnippet[:n]),
	)
	for k, v := range resp.Header {
		slog.Debug(
			fmt.Sprintf(
				"connectivity test [%s]: response header",
				label,
			),
			"key", k,
			"value", v,
		)
	}

	if resp.TLS != nil {
		logTLSState(label, targetAddr, *resp.TLS)
	} else {
		slog.Warn(
			fmt.Sprintf(
				"connectivity test [%s]: "+
					"response has no TLS state (non-TLS?)",
				label,
			),
		)
	}
}

// ---------------------------------------------------------------------------
// Test: Direct TLS dial (no proxy)
// ---------------------------------------------------------------------------

func directTLSDial(
	addr string,
	tlsConfig *tls.Config,
	label string,
) error {
	ctx, cancel := context.WithTimeout(
		context.Background(), connectivityTestTimeout,
	)
	defer cancel()

	start := time.Now()
	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: connectivityTestTimeout},
		Config:    tlsConfig,
	}

	slog.Debug(
		fmt.Sprintf(
			"connectivity test [%s]: dialing %s", label, addr,
		),
	)
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	elapsed := time.Since(start)

	if err != nil {
		slog.Warn(
			fmt.Sprintf(
				"connectivity test [%s]: FAILED", label,
			),
			"address", addr,
			"latency", elapsed.String(),
			"error", err,
		)
		return fmt.Errorf("TLS dial to %s failed: %w", addr, err)
	}
	defer func() { _ = conn.Close() }()

	//nolint:errcheck // tls.Dialer always returns *tls.Conn
	tlsConn := conn.(*tls.Conn)

	slog.Info(
		fmt.Sprintf(
			"connectivity test [%s]: OK — TLS handshake succeeded",
			label,
		),
		"address", addr,
		"latency", elapsed.String(),
	)
	logTLSState(label, addr, tlsConn.ConnectionState())

	return nil
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

// bufferedConn wraps a bufio.Reader (which may contain buffered bytes
// read ahead from the underlying connection during HTTP response parsing)
// together with the raw net.Conn. Reads come from the bufio.Reader first,
// writes and other net.Conn methods go to the raw connection.
//
// This avoids the classic CONNECT-proxy pitfall where bufio.Reader
// consumes bytes beyond the HTTP response boundary, causing the
// subsequent TLS handshake on the raw conn to fail.
type bufferedConn struct {
	r *bufio.Reader
	net.Conn
}

func newBufferedConn(r *bufio.Reader, c net.Conn) *bufferedConn {
	return &bufferedConn{r: r, Conn: c}
}

func (bc *bufferedConn) Read(p []byte) (int, error) {
	return bc.r.Read(p)
}

// proxyHostPort returns host:port for the proxy, defaulting to port 80.
func proxyHostPort(u *url.URL) string {
	if u.Port() != "" {
		return u.Host
	}
	return net.JoinHostPort(u.Hostname(), "80")
}

// extractHostPort parses a URL-style address and returns host:port
// suitable for net.Dial.
func extractHostPort(address string) (string, error) {
	u, err := url.Parse(address)
	if err != nil {
		return "", fmt.Errorf(
			"invalid URL %q: %w", address, err,
		)
	}

	host := u.Hostname()
	port := u.Port()

	if port == "" {
		switch u.Scheme {
		case "https":
			port = "443"
		case "http":
			port = "80"
		default:
			return "", fmt.Errorf(
				"no port in address and unknown scheme %q",
				u.Scheme,
			)
		}
	}

	return net.JoinHostPort(host, port), nil
}

// tlsVersionName returns a human-readable TLS version string.
func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("unknown (0x%04x)", v)
	}
}
