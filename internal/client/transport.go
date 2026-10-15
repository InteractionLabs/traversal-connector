package client

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/InteractionLabs/traversal-connector/internal/config"
)

const (
	// h2ReadIdleTimeout is how long an idle HTTP/2 connection waits before
	// sending a PING frame to check if the peer is still alive.
	h2ReadIdleTimeout = 30 * time.Second
	// h2PingTimeout is how long to wait for a PING response before closing
	// a connection that appears dead.
	h2PingTimeout = 10 * time.Second
)

// newTransport returns the HTTP transport for the controller connection.
// URL scheme decides TLS vs h2c. config.Load enforces certs-required for
// https://. An error here indicates the Config was not validated by Load.
func newTransport(cfg *config.Config) (http.RoundTripper, error) {
	controllerURL, err := url.Parse(cfg.TraversalControllerURL)
	if err != nil {
		return nil, fmt.Errorf(
			"invalid TRAVERSAL_CONTROLLER_URL %q: %w",
			cfg.TraversalControllerURL, err,
		)
	}

	if controllerURL.Scheme != "https" {
		slog.Info("transport selected",
			"scheme", controllerURL.Scheme, "mtls", false)
		if cfg.TLSCert != nil || cfg.TLSKey != nil {
			slog.Warn(
				"TLS client cert is configured but " +
					"TRAVERSAL_CONTROLLER_URL is not https://; " +
					"cert will be ignored",
			)
		}
		return newH2CTransport(cfg.TraversalControllerConnectTo), nil
	}

	slog.Info("transport selected",
		"scheme", "https", "mtls", true, "proxy", cfg.EgressProxyURL != nil)
	return newTLSTransport(cfg)
}

// newTLSTransport builds the TLS transport for an https:// controller URL.
// mTLS is required: TLSCert and TLSKey must be non-nil and parseable. Both
// are validated by config.Load; an error here indicates Load was bypassed.
func newTLSTransport(cfg *config.Config) (http.RoundTripper, error) {
	tlsConfig, err := config.BuildClientTLSConfig(cfg)
	if err != nil {
		return nil, err
	}
	if tlsConfig == nil {
		return nil, errors.New(
			"https:// URL requires TLS_CERT_BASE64 and TLS_KEY_BASE64",
		)
	}
	controllerURL, err := url.Parse(cfg.TraversalControllerURL)
	if err != nil || controllerURL.Hostname() == "" {
		return nil, errors.New("https:// controller URL requires a hostname")
	}
	// Pin verification to the logical URL. A routing override must never change
	// SNI or the certificate identity being verified.
	tlsConfig.ServerName = controllerURL.Hostname()
	var egressProxyURL *url.URL
	if cfg.EgressProxyURL != nil {
		var perr error
		egressProxyURL, perr = url.Parse(*cfg.EgressProxyURL)
		if perr != nil {
			slog.Error("invalid EGRESS_PROXY_URL, proceeding with direct TLS connection")
			egressProxyURL = nil
		} else {
			slog.Info("using forward proxy for controller connection",
				"proxy_host", egressProxyURL.Host)
		}
	}

	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
		HTTP2:           h2Config(),
	}
	transport.Protocols = new(http.Protocols)
	transport.Protocols.SetHTTP1(true)
	transport.Protocols.SetHTTP2(true)
	if cfg.TraversalControllerConnectTo != "" {
		transport.Proxy = nil
		transport.DialContext = fixedTargetDialer(cfg.TraversalControllerConnectTo)
	}
	if egressProxyURL != nil {
		transport.Proxy = http.ProxyURL(egressProxyURL)
	}

	return transport, nil
}

// h2Config is the controller connection's HTTP/2 keepalive: a PING after
// h2ReadIdleTimeout of silence, and the connection closed if it goes
// unanswered for h2PingTimeout.
func h2Config() *http.HTTP2Config {
	return &http.HTTP2Config{
		SendPingTimeout: h2ReadIdleTimeout,
		PingTimeout:     h2PingTimeout,
	}
}

// newH2CTransport creates an HTTP/2 cleartext transport for direct connections
// without a proxy. Used for local development.
func newH2CTransport(connectTo string) *http.Transport {
	transport := &http.Transport{HTTP2: h2Config(), Protocols: new(http.Protocols)}
	transport.Protocols.SetUnencryptedHTTP2(true)
	if connectTo != "" {
		transport.DialContext = fixedTargetDialer(connectTo)
	}
	return transport
}

func fixedTargetDialer(address string) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}
}
