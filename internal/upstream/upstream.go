// Package upstream is how the connector reaches destinations: each request a
// pipe carries is forwarded with the customer's trust settings, through the
// dial policy, and its response streamed back, or buffered and redacted when
// the customer's rules cover the host.
package upstream

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"

	"github.com/InteractionLabs/traversal-connector/connector-lib/connector"
	"github.com/InteractionLabs/traversal-connector/connector-lib/halfconn"
	"github.com/InteractionLabs/traversal-connector/connector-lib/httpserve"
	"github.com/InteractionLabs/traversal-connector/connector-lib/rawpipe"
	"github.com/InteractionLabs/traversal-connector/internal/config"
	"github.com/InteractionLabs/traversal-connector/internal/redact"
	"github.com/InteractionLabs/traversal-connector/internal/telemetry"
)

// InstrumentationName names the OTel tracer and meter.
const InstrumentationName = "traversal-connector/upstream"

const bytesPerMB = 1 << 20

// Dialer reaches a canonical host:port, as dialpolicy.Policy.Dial does.
type Dialer func(ctx context.Context, host string, port uint16) (halfconn.Conn, string, error)

// Client forwards requests to destinations.
type Client struct {
	// auto speaks HTTP/2 to a server that offers it over TLS, as gRPC needs,
	// and HTTP/1.1 otherwise. h2c is gRPC to an http:// server: with no ALPN
	// to offer h2 it must be assumed, and gRPC has no HTTP/1. http1 carries
	// upgrades, which Go's transport keeps on HTTP/1 only for WebSocket.
	auto, h2c, http1 *http.Transport
	redactor         *redact.Redactor
	// maxRequest bounds a request body as it streams (0: no limit). maxBody
	// and maxDecoded bound a buffered response on the wire and decoded, and
	// are always finite; bufferFor bounds how long it may take to end.
	maxRequest, maxBody, maxDecoded int64
	bufferFor                       time.Duration
	// redactions holds a slot for each covered response buffered at once,
	// across the connector: each may hold maxBody and maxDecoded in memory.
	redactions chan struct{}
	tracer     trace.Tracer
	metrics    *metrics
}

func New(cfg *config.Config, r *redact.Redactor, dial Dialer) (*Client, error) {
	tlsCfg, err := trust(cfg)
	if err != nil {
		return nil, err
	}
	m, err := newMetrics()
	if err != nil {
		return nil, err
	}
	timeout := cfg.RequestTimeout
	if timeout <= 0 {
		// A timeout of none would make every buffered response time out at once.
		timeout = config.DefaultRequestTimeout
	}
	var auto, h2c, http1 http.Protocols
	auto.SetHTTP1(true)
	auto.SetHTTP2(true)
	h2c.SetUnencryptedHTTP2(true)
	http1.SetHTTP1(true)
	return &Client{
		auto:       transport(tlsCfg, dial, auto, timeout),
		h2c:        transport(tlsCfg, dial, h2c, timeout),
		http1:      transport(tlsCfg, dial, http1, timeout),
		redactor:   r,
		maxRequest: cfg.MaxRequestBodySizeMB * bytesPerMB,
		maxBody:    finite(cfg.MaxResponseBodySizeMB, config.DefaultBodySizeMB),
		maxDecoded: finite(cfg.MaxDecodedResponseBodySizeMB, config.DefaultDecodedBodySizeMB),
		bufferFor:  timeout,
		redactions: make(chan struct{}, positive(cfg.MaxConcurrentRedactions,
			config.DefaultMaxConcurrentRedactions)),
		tracer:  otel.Tracer(InstrumentationName),
		metrics: m,
	}, nil
}

// finite is limitMB in bytes, or defaultMB's when limitMB is none (0 or
// less): a buffered response is held whole in memory, so its limit cannot be
// none.
func finite(limitMB, defaultMB int64) int64 {
	if limitMB > 0 {
		return limitMB * bytesPerMB
	}
	return defaultMB * bytesPerMB
}

// positive is n, or def when n is none (0 or less).
func positive(n, def int64) int64 {
	if n > 0 {
		return n
	}
	return def
}

// trust is the customer's: UPSTREAM_TLS_VERIFY, and UPSTREAM_TLS_CA_BASE64 or
// UPSTREAM_TLS_CA_FILE beside the system roots.
func trust(cfg *config.Config) (*tls.Config, error) {
	tlsCfg := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: !cfg.UpstreamTLSVerify, //nolint:gosec // opt-in
	}
	if cfg.UpstreamTLSCA != nil && *cfg.UpstreamTLSCA != "" {
		var err error
		if tlsCfg.RootCAs, err = config.SystemPoolWith(*cfg.UpstreamTLSCA, "upstream"); err != nil {
			return nil, err
		}
	}
	return tlsCfg, nil
}

// transport dials only through dial, which owns the egress proxy and the
// address checks, so it has no Proxy of its own: HTTP(S)_PROXY would skip
// the dial policy. A destination has timeout to answer with its headers; its
// body, unless buffered to redact, streams for as long as it runs.
func transport(
	tlsCfg *tls.Config, dial Dialer, protocols http.Protocols, timeout time.Duration,
) *http.Transport {
	return &http.Transport{
		Protocols:       &protocols,
		TLSClientConfig: tlsCfg.Clone(),
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			host, p, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			port, err := strconv.ParseUint(p, 10, 16)
			if err != nil {
				return nil, err
			}
			conn, _, err := dial(ctx, host, uint16(port))
			return conn, err
		},
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: timeout,
		MaxIdleConnsPerHost:   8,
		IdleConnTimeout:       90 * time.Second,
	}
}

// Forward sends r to target, its pipe's destination, and streams the answer
// to w. A request to a host the customer's rules cover whose response could
// not be redacted (gRPC, an upgrade) is refused before it is sent, so it has
// no effect upstream.
func (c *Client) Forward(w http.ResponseWriter, r *http.Request, target *url.URL) {
	host := target.Hostname()
	ctx, span := c.tracer.Start(r.Context(), telemetry.SpanUpstreamHTTP,
		trace.WithAttributes(attribute.String(connector.AttrTargetHost, target.Host),
			attribute.String(connector.AttrMethod, r.Method)))
	defer span.End()
	r = r.WithContext(ctx)
	if c.maxRequest > 0 && r.Body != nil {
		if r.ContentLength > c.maxRequest {
			http.Error(w, fmt.Sprintf("request body exceeds %d bytes", c.maxRequest),
				http.StatusRequestEntityTooLarge)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, c.maxRequest)
	}
	start := time.Now()
	covered := c.redactor.HasRulesForHost(host)
	if covered {
		if why := unredactableRequest(r); why != "" {
			c.fail(w, r, c.refuse(ctx, target.Host, refusalUnredactable, errors.New(why)))
			return
		}
	}
	t := c.auto
	switch {
	case r.Header.Get("Upgrade") != "":
		t = c.http1
	case target.Scheme == "http" && isGRPC(r.Header.Get(headerContentType)):
		t = c.h2c
	}
	rp := httpserve.ReverseProxy(
		func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme, pr.Out.URL.Host = target.Scheme, target.Host
			pr.Out.Host = pr.In.Host
		},
		t,
		func(w http.ResponseWriter, r *http.Request, err error) {
			if !errors.Is(err, errRefused) {
				c.metrics.requested(ctx, target.Host, connector.StatusError, start)
			}
			_ = telemetry.RecordError(span, err)
			c.fail(w, r, err)
		},
	)
	rp.ModifyResponse = func(resp *http.Response) error {
		c.metrics.requested(ctx, target.Host, connector.StatusSuccess, start)
		span.SetAttributes(attribute.Int(connector.AttrHTTPStatusCode, resp.StatusCode))
		return c.respond(ctx, resp, start, target.Host, host, covered)
	}
	rp.ServeHTTP(w, r)
}

// fail answers r with err's reason: a dial refusal's, redaction_unsupported,
// or upstream_failed for any other failure.
func (c *Client) fail(w http.ResponseWriter, r *http.Request, err error) {
	if r.Context().Err() != nil {
		return // the caller is gone
	}
	reason := rawpipe.ReasonOf(err, rawpipe.UpstreamFailed)
	safe := telemetry.SanitizeError(err)
	slog.InfoContext(r.Context(), "upstream request failed", "reason", reason, "error", safe)
	rawpipe.Refuse(w, reason, safe.Error())
}

var errRefused = errors.New("refused")

// refuse counts a response dropped because it could not be redacted, and is
// the error that answers it.
func (c *Client) refuse(ctx context.Context, target, label string, err error) error {
	return c.drop(ctx, target, label, rawpipe.RedactionUnsupported, err)
}

// drop counts a covered response dropped rather than forwarded unredacted,
// under label, and is the error that answers it with reason.
func (c *Client) drop(
	ctx context.Context, target, label string, reason rawpipe.Reason, err error,
) error {
	c.metrics.refusals.Add(ctx, 1, metric.WithAttributes(
		attribute.String(connector.AttrTargetHost, target),
		attribute.String(attrRefusalReason, label)))
	slog.WarnContext(ctx, "upstream response dropped rather than forwarded unredacted",
		"target_host", target, "reason", label, "error", telemetry.SanitizeError(err))
	return fmt.Errorf("%w: %w", errRefused, rawpipe.Errorf(reason, "%s", err.Error()))
}
