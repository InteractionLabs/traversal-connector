package rawtunnel

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"

	pb "github.com/InteractionLabs/traversal-connector/connector-lib/gen/connector/v1"
	"github.com/InteractionLabs/traversal-connector/connector-lib/gen/connector/v1/connectorconnect"
)

// stallConn stops reading when stalled, the way a peer that has stopped
// running stops reading, while the TCP connection stays open.
type stallConn struct {
	net.Conn
	stalled atomic.Bool
	release chan struct{}
}

func (c *stallConn) Read(p []byte) (int, error) {
	if c.stalled.Load() {
		<-c.release
		return 0, io.EOF
	}
	return c.Conn.Read(p)
}

type h2Controller struct {
	connectorconnect.UnimplementedConnectorServiceHandler
	got      chan *Mux
	finished chan error
}

func (h *h2Controller) RawTunnel(
	ctx context.Context, stream *connect.BidiStream[pb.RawTunnelFrame, pb.RawTunnelFrame],
) error {
	f, err := stream.Receive()
	if err != nil {
		return err
	}
	if f.GetConnectorHello() == nil {
		return errors.New("expected connector hello")
	}
	if err := stream.Send(&pb.RawTunnelFrame{Frame: &pb.RawTunnelFrame_ControllerHello{
		ControllerHello: &pb.RawControllerHello{ProtocolVersion: ProtocolVersion},
	}}); err != nil {
		return err
	}
	rc := http.NewResponseController(ctx.Value(responseKey{}).(http.ResponseWriter))
	m, err := New(Config{
		Role:     RoleController,
		MaxPipes: 4,
		// Application pings wait out a blocked write. The HTTP/2 connection
		// is what notices a peer that has stopped running.
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
	h.got <- m
	h.finished <- m.Run(ctx)
	return nil
}

type responseKey struct{}

// TestStalledPeerUnblocksTunnel is the production failure mode: the peer
// process stops reading and the TCP connection stays open. The mux must end
// the tunnel, and Run must return so the handler can return.
func TestStalledPeerUnblocksTunnel(t *testing.T) {
	release := make(chan struct{})
	var releaseOnce sync.Once
	unpause := func() { releaseOnce.Do(func() { close(release) }) }
	stall := &stallConn{release: release}
	h := &h2Controller{got: make(chan *Mux), finished: make(chan error, 1)}
	path, handler := connectorconnect.NewConnectorServiceHandler(h)
	mux := http.NewServeMux()
	mux.Handle(path, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), responseKey{}, w)
		handler.ServeHTTP(w, r.WithContext(ctx))
	}))
	var protocols http.Protocols
	protocols.SetUnencryptedHTTP2(true)
	protocols.SetHTTP1(true)
	var http2 http.HTTP2Config
	ConfigureHTTP2(&http2)
	http2.SendPingTimeout = 100 * time.Millisecond
	http2.PingTimeout = 100 * time.Millisecond
	http2.WriteByteTimeout = time.Second
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{
		Handler: mux, Protocols: &protocols, HTTP2: &http2, ReadHeaderTimeout: time.Second,
	}
	go func() { _ = srv.Serve(ln) }()
	var cancel context.CancelFunc
	t.Cleanup(func() {
		unpause()
		if cancel != nil {
			cancel()
		}
		_ = srv.Close()
	})

	var clientProtocols http.Protocols
	clientProtocols.SetUnencryptedHTTP2(true)
	var clientHTTP2 http.HTTP2Config
	ConfigureHTTP2(&clientHTTP2)
	clientHTTP2.WriteByteTimeout = time.Second
	// Smaller than the pipe window, so once the peer stops reading, a Send
	// blocks on HTTP/2 flow control while the mux still has pipe credit.
	clientHTTP2.MaxReceiveBufferPerConnection = 64 << 10
	clientHTTP2.MaxReceiveBufferPerStream = 64 << 10
	httpClient := &http.Client{Transport: &http.Transport{
		Protocols: &clientProtocols,
		HTTP2:     &clientHTTP2,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			var d net.Dialer
			c, err := d.DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			stall.Conn = c
			return stall, nil
		},
	}}
	rpc := connectorconnect.NewConnectorServiceClient(
		httpClient, "http://"+ln.Addr().String(), connect.WithGRPC(),
	)
	var ctx context.Context
	ctx, cancel = context.WithCancel(t.Context())
	defer cancel()
	openCtx, openCancel := context.WithTimeout(ctx, waitTimeout)
	defer openCancel()
	stream := rpc.RawTunnel(ctx)
	if err := stream.Send(&pb.RawTunnelFrame{Frame: &pb.RawTunnelFrame_ConnectorHello{
		ConnectorHello: &pb.RawConnectorHello{
			SupportedProtocolVersions: []uint32{ProtocolVersion},
			Hostname:                  "connector",
			MaxPipes:                  4,
		},
	}}); err != nil {
		t.Fatal(err)
	}
	hello, err := stream.Receive()
	if err != nil || hello.GetControllerHello().GetProtocolVersion() != ProtocolVersion {
		t.Fatalf("controller hello %v, %v", hello, err)
	}
	connector, err := New(Config{
		Role:         RoleConnector,
		MaxPipes:     4,
		PingInterval: time.Hour,
		Abort:        cancel,
		Accept: func(p *Pipe, _ *pb.RawOpen) {
			_ = p.Start(newMemLocal(true))
		},
	}, stream)
	if err != nil {
		t.Fatal(err)
	}
	connectorErr := make(chan error, 1)
	go func() { connectorErr <- connector.Run(ctx) }()

	ctrl := <-h.got
	pipe, err := ctrl.Open(testCapability, "db.internal", 5432, passthrough)
	if err != nil {
		t.Fatal(err)
	}
	if err := pipe.WaitOpened(openCtx); err != nil {
		t.Fatal(err)
	}
	if err := pipe.Start(newMemLocal(true)); err != nil {
		t.Fatal(err)
	}
	eventually(t, "data to be flowing", func() bool {
		return pipe.Result().BytesSent > 1<<20
	})
	stall.stalled.Store(true)
	stalledAt := time.Now()

	select {
	case err := <-h.finished:
		if err == nil {
			t.Fatal("Run returned nil")
		}
		if time.Since(stalledAt) > 2*time.Second {
			t.Fatalf("tunnel ended only after %v: %v", time.Since(stalledAt), err)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("tunnel stayed up after the peer stopped reading, sent %d",
			pipe.Result().BytesSent)
	}
	wantReason(t, waitDone(t, pipe), pb.RawCloseReason_RAW_CLOSE_REASON_TUNNEL_LOST)
	unpause()
	cancel()
	select {
	case <-connectorErr:
	case <-time.After(waitTimeout):
		t.Fatal("connector mux did not stop")
	}
}
