package rawclient

import (
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
	stream *connect.BidiStream[pb.RawTunnelFrame, pb.RawTunnelFrame],
) error {
	if _, err := stream.Receive(); err != nil {
		return err
	}
	if err := stream.Send(&pb.RawTunnelFrame{Frame: &pb.RawTunnelFrame_ControllerHello{
		ControllerHello: &pb.RawControllerHello{
			ProtocolVersion: rawtunnel.ProtocolVersion,
			TunnelId:        uuid.NewString(),
		},
	}}); err != nil {
		return err
	}
	rc := http.NewResponseController(ctx.Value(respKey{}).(http.ResponseWriter))
	mux, err := rawtunnel.New(rawtunnel.Config{
		Role:         rawtunnel.RoleController,
		MaxPipes:     128,
		IdleTimeout:  time.Hour,
		MaxLifetime:  time.Hour,
		PingInterval: time.Hour,
		Abort: func() {
			now := time.Now()
			_ = rc.SetReadDeadline(now)
			_ = rc.SetWriteDeadline(now)
		},
	}, stream)
	if err != nil {
		return err
	}
	c.ready <- mux
	return mux.Run(ctx)
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
	_ context.Context,
	stream *connect.BidiStream[pb.RawTunnelFrame, pb.RawTunnelFrame],
) error {
	_, _ = stream.Receive()
	_ = stream.Send(&pb.RawTunnelFrame{Frame: &pb.RawTunnelFrame_ControllerHello{
		ControllerHello: &pb.RawControllerHello{
			ProtocolVersion: 99,
			TunnelId:        uuid.NewString(),
		},
	}})
	select {
	case c.calls <- struct{}{}:
	default:
	}
	return nil
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
	pings   chan struct{}
	tunnels atomic.Int32
}

func (c *pingCtrl) RawTunnel(
	ctx context.Context,
	stream *connect.BidiStream[pb.RawTunnelFrame, pb.RawTunnelFrame],
) error {
	c.tunnels.Add(1)
	if _, err := stream.Receive(); err != nil {
		return err
	}
	if err := stream.Send(&pb.RawTunnelFrame{Frame: &pb.RawTunnelFrame_ControllerHello{
		ControllerHello: &pb.RawControllerHello{
			ProtocolVersion: rawtunnel.ProtocolVersion,
			TunnelId:        uuid.NewString(),
		},
	}}); err != nil {
		return err
	}
	got := 0
	for got < 2 {
		frame, err := stream.Receive()
		if err != nil {
			return err
		}
		ping := frame.GetPing()
		if ping == nil || ping.GetAck() {
			continue
		}
		got++
		select {
		case c.pings <- struct{}{}:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	<-ctx.Done()
	return nil
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

func (m *Manager) snapshot() (active, draining int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.active, m.draining
}

func discardLogs() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
