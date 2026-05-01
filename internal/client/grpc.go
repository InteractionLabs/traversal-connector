package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"net/http"
	"net/url"
	"time"

	"buf.build/go/protovalidate"
	"connectrpc.com/connect"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/net/http2"

	"github.com/InteractionLabs/traversal-connector/connector-lib/connector"
	pb "github.com/InteractionLabs/traversal-connector/connector-lib/gen/connector/v1"
	"github.com/InteractionLabs/traversal-connector/connector-lib/gen/connector/v1/connectorconnect"
	"github.com/InteractionLabs/traversal-connector/internal/config"
	"github.com/InteractionLabs/traversal-connector/internal/telemetry"
)

const (
	// h2ReadIdleTimeout is how long an idle HTTP/2 connection waits before
	// sending a PING frame to check if the peer is still alive.
	h2ReadIdleTimeout = 30 * time.Second
	// h2PingTimeout is how long to wait for a PING response before closing
	// a connection that appears dead.
	h2PingTimeout = 10 * time.Second
)

// NewClient creates a ConnectRPC client for the Traversal control plane.
// Transport selection is driven by the URL scheme of cfg.TraversalControllerURL:
// https:// uses standard TLS transport with mTLS (which config.Load enforces);
// http:// (only allowed for localhost-style hosts) uses h2c.
// Returns an error if the URL or TLS material is malformed; in practice this
// can't happen on a Config that came from config.Load, but the error is
// surfaced rather than silently swallowed for callers that bypass Load.
func NewClient(cfg *config.Config) (connectorconnect.ConnectorServiceClient, error) {
	transport, err := newTransport(cfg)
	if err != nil {
		return nil, err
	}
	httpClient := &http.Client{Transport: transport}
	return connectorconnect.NewConnectorServiceClient(
		httpClient,
		cfg.TraversalControllerURL,
		connect.WithGRPC(),
	), nil
}

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
		return newH2CTransport(), nil
	}

	slog.Info("transport selected",
		"scheme", "https", "mtls", true, "proxy", cfg.EgressProxyURL != nil)
	return newTLSTransport(cfg)
}

// newTLSTransport builds the TLS transport for an https:// controller URL.
// mTLS is required: TLSCert and TLSKey must be non-nil and parseable. Both
// are validated by config.Load; an error here indicates Load was bypassed.
func newTLSTransport(cfg *config.Config) (http.RoundTripper, error) {
	if cfg.TLSCert == nil || cfg.TLSKey == nil {
		return nil, errors.New(
			"https:// URL requires TLS_CERT_BASE64 and TLS_KEY_BASE64",
		)
	}
	cert, err := tls.X509KeyPair([]byte(*cfg.TLSCert), []byte(*cfg.TLSKey))
	if err != nil {
		return nil, fmt.Errorf(
			"failed to parse client TLS certificate: %w", err,
		)
	}

	tlsConfig := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		ServerName:   cfg.TLSServerName,
		Certificates: []tls.Certificate{cert},
	}

	if cfg.TLSCA != nil {
		caCertPool := x509.NewCertPool()
		if ok := caCertPool.AppendCertsFromPEM([]byte(*cfg.TLSCA)); ok {
			tlsConfig.RootCAs = caCertPool
			slog.Info("CA certificate loaded from PEM content")
		} else {
			slog.Error("failed to parse CA certificate, using system CA bundle")
		}
	}

	var egressProxyURL *url.URL
	if cfg.EgressProxyURL != nil {
		var perr error
		egressProxyURL, perr = url.Parse(*cfg.EgressProxyURL)
		if perr != nil {
			slog.Error("invalid EGRESS_PROXY_URL, proceeding with direct TLS connection",
				"egress_proxy_url", *cfg.EgressProxyURL, "error", perr)
			egressProxyURL = nil
		} else {
			slog.Info("using forward proxy for controller connection",
				"egress_proxy_url", *cfg.EgressProxyURL)
		}
	}

	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}
	if egressProxyURL != nil {
		transport.Proxy = http.ProxyURL(egressProxyURL)
	}

	h2Transport, h2Err := http2.ConfigureTransports(transport)
	if h2Err != nil {
		slog.Error("failed to configure HTTP/2 transport, keepalives disabled",
			"error", h2Err)
	} else {
		h2Transport.ReadIdleTimeout = h2ReadIdleTimeout
		h2Transport.PingTimeout = h2PingTimeout
	}

	return transport, nil
}

// newH2CTransport creates an HTTP/2 cleartext transport for direct connections
// without a proxy. Used for local development.
func newH2CTransport() *http2.Transport {
	return &http2.Transport{
		AllowHTTP:       true,
		ReadIdleTimeout: h2ReadIdleTimeout,
		PingTimeout:     h2PingTimeout,
		DialTLSContext: func(
			ctx context.Context,
			network, addr string,
			_ *tls.Config,
		) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		},
	}
}

// RunTunnel opens a bidirectional stream to the Traversal control plane and runs a
// receive loop that responds to each message type with a stub response.
// It blocks until the context is canceled or the stream encounters an error.
func (cm *ConnectionManager) RunTunnel(ctx context.Context) error {
	slog.InfoContext(ctx, "opening tunnel", "addr", cm.config.TraversalControllerURL)

	// Add debug logging for connection attempt
	slog.DebugContext(ctx, "creating tunnel stream", "addr", cm.config.TraversalControllerURL)
	stream := cm.client.Tunnel(ctx)

	// ConnectRPC bidi streams are lazy — the HTTP/2 connection is not established
	// until the first Send or Receive. Send an initial health check response to
	// force the connection and fail fast if the server is unreachable.
	slog.DebugContext(
		ctx,
		"attempting to establish tunnel connection",
		"addr",
		cm.config.TraversalControllerURL,
	)
	if err := stream.Send(&pb.ConnectorMessage{
		RequestId: uuid.New().String(),
		Message: &pb.ConnectorMessage_HealthCheckResponse{
			HealthCheckResponse: &pb.HealthCheckResponse{
				UnixMillis: time.Now().UnixMilli(),
				Status:     "healthy",
			},
		},
	}); err != nil {
		slog.ErrorContext(
			ctx,
			"tunnel connection failed",
			"addr",
			cm.config.TraversalControllerURL,
			"error",
			err,
		)
		return fmt.Errorf("failed to establish tunnel connection: %w", err)
	}
	slog.InfoContext(ctx, "tunnel stream established, starting receive loop")

	conn := &StreamConnection{
		ID:           uuid.New(),
		Stream:       stream,
		ConnectedAt:  time.Now(),
		LastActivity: time.Now(),
	}

	cm.mu.Lock()
	cm.connections = append(cm.connections, conn)
	cm.mu.Unlock()

	cm.metrics.streamsActive.Add(ctx, 1)

	defer func() {
		cm.mu.Lock()
		for i, c := range cm.connections {
			if c.ID == conn.ID {
				cm.connections = append(cm.connections[:i], cm.connections[i+1:]...)
				break
			}
		}
		cm.mu.Unlock()
		cm.metrics.streamsActive.Add(ctx, -1)
		slog.InfoContext(ctx, "tunnel connection closed", "tunnel_id", conn.ID)
	}()

	es := &connectStream{BidiStreamForClient: stream}

	// Use a response sender to allow multiple goroutines to send safely.
	// This is required for multiplexed tunnels where multiple HTTP request
	// goroutines send responses concurrently.
	ss := newResponseSender(es, cm.config.MaxConcurrentRequests*2, cm.metrics)
	go ss.run(ctx)
	defer ss.close()

	return cm.receiveLoop(ctx, es, ss, conn)
}

// receiveLoop reads messages from the Traversal control plane and dispatches responses.
// The receiver is used for reading; the sender (serialized) is used for writing.
// HTTP requests are handled concurrently with a semaphore limiting concurrency.
func (cm *ConnectionManager) receiveLoop(
	ctx context.Context,
	receiver *connectStream,
	sender streamSender,
	conn *StreamConnection,
) error {
	sem := make(chan struct{}, cm.config.MaxConcurrentRequests)

	for {
		msg, err := receiver.Receive()
		if err != nil {
			if errors.Is(err, context.Canceled) {
				slog.InfoContext(ctx, "context canceled, closing tunnel", "tunnel_id", conn.ID)
				return nil
			}
			if errors.Is(err, io.EOF) {
				if inFlight := len(sem); inFlight > 0 {
					return fmt.Errorf(
						"controller closed tunnel with %d requests in flight",
						inFlight,
					)
				}
				slog.InfoContext(
					ctx,
					"controller closed tunnel for reconnect",
					"tunnel_id",
					conn.ID,
				)
				return nil
			}
			return fmt.Errorf("receive error: %w", err)
		}

		conn.LastActivity = time.Now()
		slog.DebugContext(ctx, "received controller message",
			"tunnel_id", conn.ID,
			"request_id", msg.RequestId)

		// HTTP requests are handled concurrently; other message types are fast
		// and handled inline to avoid goroutine overhead.
		if _, ok := msg.Message.(*pb.ControllerMessage_HttpRequest); ok {
			sem <- struct{}{}
			cm.metrics.concurrentRequests.Add(ctx, 1)
			go func(m *pb.ControllerMessage) {
				defer func() {
					<-sem
					cm.metrics.concurrentRequests.Add(ctx, -1)
				}()
				if err := cm.handleMessage(ctx, sender, conn.ID, m); err != nil {
					slog.ErrorContext(ctx, "concurrent http request failed",
						"tunnel_id", conn.ID,
						"request_id", m.RequestId,
						"error", err)
				}
			}(msg)
			continue
		}

		if err := cm.handleMessage(ctx, sender, conn.ID, msg); err != nil {
			return fmt.Errorf("failed to handle message: %w", err)
		}
	}
}

// streamSender is the send-only stream interface used by handleMessage.
type streamSender interface {
	Send(*pb.ConnectorMessage) error
}

// handleMessage dispatches a controller message to the appropriate stub handler.
func (cm *ConnectionManager) handleMessage(
	ctx context.Context,
	stream streamSender,
	connID uuid.UUID,
	msg *pb.ControllerMessage,
) error {
	switch m := msg.Message.(type) {
	case *pb.ControllerMessage_HealthCheckRequest:
		slog.DebugContext(ctx, "received health check request",
			"request_id", msg.RequestId,
			"unix_millis", m.HealthCheckRequest.UnixMillis)

		return stream.Send(&pb.ConnectorMessage{
			RequestId: msg.RequestId,
			Message: &pb.ConnectorMessage_HealthCheckResponse{
				HealthCheckResponse: &pb.HealthCheckResponse{
					UnixMillis: time.Now().UnixMilli(),
					Status:     "healthy",
				},
			},
		})

	case *pb.ControllerMessage_HttpRequest:
		reqCtx, span := cm.tracer.Start(ctx, telemetry.SpanConnectorHandleHTTP,
			trace.WithAttributes(
				attribute.String(connector.AttrRequestID, msg.RequestId),
				attribute.String(connector.AttrMethod, m.HttpRequest.Method),
				attribute.String(telemetry.AttrURL, m.HttpRequest.Url),
			),
		)
		defer span.End()

		slog.DebugContext(reqCtx, "received http request",
			"request_id", msg.RequestId,
			"method", m.HttpRequest.Method,
			"url", m.HttpRequest.Url)

		if err := protovalidate.Validate(m.HttpRequest); err != nil {
			span.RecordError(err)
			slog.WarnContext(reqCtx, "received invalid http request",
				"request_id", msg.RequestId,
				"error", err)
			return stream.Send(&pb.ConnectorMessage{
				RequestId: msg.RequestId,
				Message: &pb.ConnectorMessage_ErrorResponse{
					ErrorResponse: &pb.ErrorResponse{
						Code:    string(connector.ErrorCodeUpstreamError),
						Message: fmt.Sprintf("invalid request: %s", err),
					},
				},
			})
		}

		httpResp, err := cm.executor.Execute(reqCtx, m.HttpRequest)
		if err != nil {
			span.RecordError(err)
			return stream.Send(&pb.ConnectorMessage{
				RequestId: msg.RequestId,
				Message: &pb.ConnectorMessage_ErrorResponse{
					ErrorResponse: &pb.ErrorResponse{
						Code:    string(connector.ErrorCodeUpstreamError),
						Message: err.Error(),
					},
				},
			})
		}

		return stream.Send(&pb.ConnectorMessage{
			RequestId: msg.RequestId,
			Message: &pb.ConnectorMessage_HttpResponse{
				HttpResponse: httpResp,
			},
		})

	case *pb.ControllerMessage_MetadataRequest:
		slog.DebugContext(ctx, "received metadata request", "request_id", msg.RequestId)
		return stream.Send(&pb.ConnectorMessage{
			RequestId: msg.RequestId,
			Message: &pb.ConnectorMessage_MetadataResponse{
				MetadataResponse: &pb.MetadataResponse{
					ConnectionUuid: connID.String(),
					Hostname:       cm.hostname,
					//nolint:gosec // bounded by min
					MaxConcurrentRequests: int32(
						min(cm.config.MaxConcurrentRequests, math.MaxInt32),
					),
				},
			},
		})

	case *pb.ControllerMessage_ConnectionRequest:
		slog.WarnContext(ctx, "received connection request (not implemented)",
			"request_id", msg.RequestId,
			"action", m.ConnectionRequest.Action)
		return stream.Send(&pb.ConnectorMessage{
			RequestId: msg.RequestId,
			Message: &pb.ConnectorMessage_ErrorResponse{
				ErrorResponse: &pb.ErrorResponse{
					Code:    string(connector.ErrorCodeUpstreamError),
					Message: "connection requests are not supported",
				},
			},
		})

	default:
		msgType := fmt.Sprintf("%T", msg.Message)
		slog.WarnContext(ctx, "received unknown message type",
			"request_id", msg.RequestId,
			"type", msgType)
		return stream.Send(&pb.ConnectorMessage{
			RequestId: msg.RequestId,
			Message: &pb.ConnectorMessage_ErrorResponse{
				ErrorResponse: &pb.ErrorResponse{
					Code:    string(connector.ErrorCodeUpstreamError),
					Message: fmt.Sprintf("unknown message type: %s", msgType),
				},
			},
		})
	}
}
