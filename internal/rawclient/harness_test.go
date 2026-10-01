package rawclient

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"golang.org/x/net/http2"
	"google.golang.org/protobuf/proto"

	"github.com/InteractionLabs/traversal-connector/connector-lib/capability/capabilitytest"
	pb "github.com/InteractionLabs/traversal-connector/connector-lib/gen/connector/v1"
	"github.com/InteractionLabs/traversal-connector/connector-lib/gen/connector/v1/connectorconnect"
	"github.com/InteractionLabs/traversal-connector/connector-lib/rawtunnel"
	"github.com/InteractionLabs/traversal-connector/internal/config"
)

const (
	testIssuer  = "traversal-raw-tunnel/test"
	testSubject = "signer"
	testKid     = "k1"
)

type respKey struct{}

func testKey() *ecdsa.PrivateKey {
	return capabilitytest.Key("raw-connector-test")
}

func publicPEM(key *ecdsa.PrivateKey) string {
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		panic(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func baseConfig(controllerURL string) *config.Config {
	return &config.Config{
		ConnectorID:            "connector-1",
		TraversalControllerURL: controllerURL,
		EnvName:                "test",
		MaxTunnelsAllowed:      1,
		MaxConcurrentRequests:  2,
		ReconnectInterval:      time.Hour,
		RequestTimeout:         time.Second,
		UpstreamTLSVerify:      true,
		MaxRequestBodySizeMB:   1,
		MaxResponseBodySizeMB:  1,
		RawTunnel: config.RawTunnelConfig{
			Enabled:             true,
			MaxTunnels:          1,
			MaxPipesPerTunnel:   100,
			MaxPipesPerPod:      200,
			IdleTimeout:         time.Hour,
			MaxLifetime:         time.Hour,
			PingInterval:        time.Hour,
			ShutdownGrace:       time.Second,
			Issuer:              testIssuer,
			AllowedSubjects:     []string{testSubject},
			CurrentKeyID:        testKid,
			CurrentPublicKeyPEM: publicPEM(testKey()),
		},
	}
}

type h2Server struct {
	url     string
	remotes chan string
	close   func()
}

func serveH2C(t *testing.T, h connectorconnect.ConnectorServiceHandler) *h2Server {
	t.Helper()
	path, handler := connectorconnect.NewConnectorServiceHandler(h)
	remotes := make(chan string, 16)
	mux := http.NewServeMux()
	mux.Handle(path, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case remotes <- r.RemoteAddr:
		default:
		}
		ctx := context.WithValue(r.Context(), respKey{}, w)
		handler.ServeHTTP(w, r.WithContext(ctx))
	}))
	var protocols http.Protocols
	protocols.SetUnencryptedHTTP2(true)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{
		Handler:           mux,
		Protocols:         &protocols,
		ReadHeaderTimeout: time.Second,
		// net/http arms ReadHeaderTimeout on the connection before h2c takes
		// over, and clears it only when ReadTimeout is set. Without that, every
		// tunnel dies one second after accept.
		ReadTimeout: time.Hour,
	}
	go func() { _ = srv.Serve(ln) }()
	return &h2Server{
		url:     "http://" + ln.Addr().String(),
		remotes: remotes,
		close:   func() { _ = srv.Close() },
	}
}

// muxCtrl is a controller that speaks the real mux after hello.
type muxCtrl struct {
	connectorconnect.UnimplementedConnectorServiceHandler
	ready chan *rawtunnel.Mux
}

func newMuxCtrl() *muxCtrl {
	return &muxCtrl{ready: make(chan *rawtunnel.Mux, 8)}
}

func (c *muxCtrl) RawTunnel(
	ctx context.Context,
	stream *connect.BidiStream[pb.RawTunnelChunk, pb.RawTunnelChunk],
) error {
	return runController(ctx, stream, c.ready, time.Hour)
}

func (c *muxCtrl) Tunnel(
	_ context.Context,
	stream *connect.BidiStream[pb.ConnectorMessage, pb.ControllerMessage],
) error {
	for {
		if _, err := stream.Receive(); err != nil {
			return nil
		}
	}
}

type badVersionCtrl struct {
	connectorconnect.UnimplementedConnectorServiceHandler
	calls chan struct{}
}

func (c *badVersionCtrl) RawTunnel(
	ctx context.Context,
	stream *connect.BidiStream[pb.RawTunnelChunk, pb.RawTunnelChunk],
) error {
	select {
	case c.calls <- struct{}{}:
	default:
	}
	return rejectHello(ctx, stream, 99)
}

func (c *badVersionCtrl) Tunnel(
	ctx context.Context,
	stream *connect.BidiStream[pb.ConnectorMessage, pb.ControllerMessage],
) error {
	for {
		if _, err := stream.Receive(); err != nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return nil
		default:
		}
	}
}

type pingCtrl struct {
	connectorconnect.UnimplementedConnectorServiceHandler
	tunnels atomic.Int32
}

func (c *pingCtrl) RawTunnel(
	ctx context.Context,
	stream *connect.BidiStream[pb.RawTunnelChunk, pb.RawTunnelChunk],
) error {
	c.tunnels.Add(1)
	return runController(ctx, stream, nil, 20*time.Millisecond)
}

func waitFor(t *testing.T, d time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("condition not met")
}

func (m *Manager) snapshot() (active, draining, sessions, connecting int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.active, m.draining, len(m.sessions), m.connecting
}

func discardLogs() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// runController is the HTTP/2 client on one raw tunnel. ready receives the
// mux after hello, which is when pipes may open. Nil ready skips that signal.
func runController(
	ctx context.Context,
	stream *connect.BidiStream[pb.RawTunnelChunk, pb.RawTunnelChunk],
	ready chan *rawtunnel.Mux,
	ping time.Duration,
) error {
	rc := http.NewResponseController(ctx.Value(respKey{}).(http.ResponseWriter))
	mux, err := rawtunnel.New(rawtunnel.Config{
		Role:         rawtunnel.RoleController,
		TunnelID:     uuid.NewString(),
		MaxPipes:     128,
		IdleTimeout:  time.Hour,
		MaxLifetime:  time.Hour,
		PingInterval: ping,
		PingTimeout:  time.Hour,
		Abort: func() {
			now := time.Now()
			_ = rc.SetReadDeadline(now)
			_ = rc.SetWriteDeadline(now)
		},
	}, rawtunnel.FromChunks(stream))
	if err != nil {
		return err
	}
	// Run returns only after in-flight writes on the gRPC response have finished.
	// Returning earlier races those writes with the handler ending.
	runDone := make(chan struct{})
	go func() {
		_ = mux.Run(ctx)
		close(runDone)
	}()
	select {
	case <-mux.Established():
		if ready != nil {
			select {
			case ready <- mux:
			case <-runDone:
			case <-ctx.Done():
			}
		}
	case <-runDone:
	case <-ctx.Done():
	}
	<-runDone
	return mux.Err()
}

func rejectHello(
	ctx context.Context,
	stream *connect.BidiStream[pb.RawTunnelChunk, pb.RawTunnelChunk],
	version uint32,
) error {
	conn := rawtunnel.NewChunkConn(rawtunnel.FromChunks(stream))
	tr := &http.Transport{DisableCompression: true}
	h2, err := http2.ConfigureTransports(tr)
	if err != nil {
		return err
	}
	h2.AllowHTTP = true
	tr.HTTP2 = &http.HTTP2Config{
		MaxReceiveBufferPerStream:     rawtunnel.StreamWindow,
		MaxReceiveBufferPerConnection: rawtunnel.TunnelWindow,
	}
	cc, err := h2.NewClientConn(conn)
	if err != nil {
		return err
	}
	defer func() {
		_ = cc.Close()
		_ = conn.Close()
	}()
	body, err := proto.Marshal(&pb.RawControllerHello{
		ProtocolVersion: version,
		TunnelId:        uuid.NewString(),
	})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(
		ctx, http.MethodPost, "http://tunnel/raw/v1/hello", bytes.NewReader(body),
	)
	if err != nil {
		return err
	}
	resp, err := cc.RoundTrip(req)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	return nil
}
