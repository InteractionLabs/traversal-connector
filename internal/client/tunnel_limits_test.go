package client

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/proto"

	pb "github.com/InteractionLabs/traversal-connector/connector-lib/gen/connector/v1"
	"github.com/InteractionLabs/traversal-connector/connector-lib/gen/connector/v1/connectorconnect"
	"github.com/InteractionLabs/traversal-connector/internal/config"
)

func TestTunnelMessageCeiling(t *testing.T) {
	tests := []struct {
		name       string
		bodySizeMB int64
		want       int
	}{
		{
			name:       "body limit plus the per-message allowance",
			bodySizeMB: 32,
			want:       32*bytesPerMB + tunnelMessageOverheadBytes,
		},
		{
			name:       "one MB limit",
			bodySizeMB: 1,
			want:       bytesPerMB + tunnelMessageOverheadBytes,
		},
		{
			// An unset body limit disables the body checks, so it disables the
			// transport ceiling too rather than inventing one.
			name:       "unset limit is unbounded",
			bodySizeMB: 0,
			want:       unlimitedMessageSize,
		},
		{
			name:       "negative limit is unbounded",
			bodySizeMB: -1,
			want:       unlimitedMessageSize,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if diff := cmp.Diff(tt.want, tunnelMessageCeiling(tt.bodySizeMB)); diff != "" {
				t.Errorf("tunnelMessageCeiling(%d) mismatch (-want +got):\n%s", tt.bodySizeMB, diff)
			}
		})
	}
}

// A configured limit large enough to overflow the multiplication must not wrap
// into a negative ceiling, because the transport reads that as no limit at all.
func TestTunnelMessageCeiling_OverflowingLimitStaysPositive(t *testing.T) {
	got := tunnelMessageCeiling(math.MaxInt64)

	if got <= 0 {
		t.Fatalf("tunnelMessageCeiling(MaxInt64) = %d, want a positive ceiling", got)
	}
	if got > math.MaxInt32 {
		t.Errorf("tunnelMessageCeiling(MaxInt64) = %d, want no more than MaxInt32", got)
	}
}

// Each direction carries a different body, so each ceiling reads a different
// limit: a message in carries a request body, a message out a response body.
func TestTunnelCeilings_ReadTheirOwnDirection(t *testing.T) {
	cfg := &config.Config{MaxRequestBodySizeMB: 4, MaxResponseBodySizeMB: 16}

	if diff := cmp.Diff(4*bytesPerMB+tunnelMessageOverheadBytes, tunnelReadMaxBytes(cfg)); diff != "" {
		t.Errorf("tunnelReadMaxBytes mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(16*bytesPerMB+tunnelMessageOverheadBytes, tunnelSendMaxBytes(cfg)); diff != "" {
		t.Errorf("tunnelSendMaxBytes mismatch (-want +got):\n%s", diff)
	}
}

// The value of the ceiling is that an oversized message never reaches memory, so
// this asserts the rejection came from the declared length in the envelope prefix
// and not from anything that had to read the payload first. The server declares a
// payload larger than the process could allocate and then sends a token handful of
// bytes: a client that waited for the payload could neither report the declared
// size nor finish this test.
func TestTunnelReceive_RejectsDeclaredSizeBeforeReadingPayload(t *testing.T) {
	const declaredSize = uint32(math.MaxUint32)
	const tokenPayload = 8

	var payloadBytesSent atomic.Int64
	server := rawTunnelServer(t, func(w http.ResponseWriter) {
		w.Header().Set("Content-Type", "application/grpc")
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()

		envelope := make([]byte, 5)
		binary.BigEndian.PutUint32(envelope[1:], declaredSize)
		_, _ = w.Write(envelope)
		n, _ := w.Write(make([]byte, tokenPayload))
		payloadBytesSent.Store(int64(n))
		w.(http.Flusher).Flush()
	})

	client := tunnelTestClient(t, server.URL, 1, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// The stream is lazy: the request is not made until something is sent on it.
	stream := client.Tunnel(ctx)
	if err := stream.Send(&pb.ConnectorMessage{RequestId: "probe"}); err != nil {
		t.Fatalf("Send() opening the stream returned error: %v", err)
	}

	_, err := stream.Receive()
	if err == nil {
		t.Fatal("Receive() accepted a message declaring a size above the ceiling")
	}
	if got := connect.CodeOf(err); got != connect.CodeResourceExhausted {
		t.Errorf("Receive() code = %v, want %v (error: %v)", got, connect.CodeResourceExhausted, err)
	}
	// The declared length is the only place this number exists on the wire.
	if want := strconv.FormatUint(uint64(declaredSize), 10); !strings.Contains(err.Error(), want) {
		t.Errorf("Receive() error %q does not report the declared size %s", err, want)
	}
	if got := payloadBytesSent.Load(); got != tokenPayload {
		t.Errorf("server sent %d payload bytes, want %d", got, tokenPayload)
	}
}

// A body at exactly the configured limit still has a URL and a header block
// wrapped around it, so the whole message is necessarily larger than the body
// limit. A ceiling set equal to that limit would reject it; the allowance is what
// keeps the largest legitimate message deliverable.
func TestTunnelReceive_AcceptsMaximumBodyWithURLAndHeaders(t *testing.T) {
	const bodySizeMB = 1
	bodyLimit := bodySizeMB * bytesPerMB

	pushed := &pb.ControllerMessage{
		RequestId: "max-size-request",
		Message: &pb.ControllerMessage_HttpRequest{
			HttpRequest: &pb.HttpRequest{
				Method:  http.MethodPost,
				Url:     "https://upstream.example.com/api?q=" + strings.Repeat("k", 4096),
				Headers: filler(64, 256),
				Body:    make([]byte, bodyLimit),
			},
		},
	}
	if got := proto.Size(pushed); got <= bodyLimit {
		t.Fatalf("message is %d bytes, not larger than the %d byte body limit: "+
			"the test no longer exercises the boundary", got, bodyLimit)
	}

	server := connectTunnelServer(t, &recordingTunnel{push: []*pb.ControllerMessage{pushed}})
	client := tunnelTestClient(t, server.URL, bodySizeMB, bodySizeMB)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	stream := client.Tunnel(ctx)
	if err := stream.Send(&pb.ConnectorMessage{RequestId: "probe"}); err != nil {
		t.Fatalf("Send() to open the stream returned error: %v", err)
	}

	got, err := stream.Receive()
	if err != nil {
		t.Fatalf("Receive() rejected a maximum-size message: %v", err)
	}
	if diff := cmp.Diff(bodyLimit, len(got.GetHttpRequest().GetBody())); diff != "" {
		t.Errorf("received body length mismatch (-want +got):\n%s", diff)
	}
}

func TestTunnelSend_RejectsOversizedMessage(t *testing.T) {
	const bodySizeMB = 1

	// A receiving handler holds the stream open, so a rejection here is the
	// transport refusing to write rather than a stream that went away.
	server := connectTunnelServer(t, &recordingTunnel{received: make(chan *pb.ConnectorMessage, 1)})
	client := tunnelTestClient(t, server.URL, bodySizeMB, bodySizeMB)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	stream := client.Tunnel(ctx)
	err := stream.Send(&pb.ConnectorMessage{
		RequestId: "oversized-response",
		Message: &pb.ConnectorMessage_HttpResponse{
			HttpResponse: &pb.HttpResponse{
				HttpStatus: http.StatusOK,
				Body:       make([]byte, tunnelSendMaxBytes(&config.Config{MaxResponseBodySizeMB: bodySizeMB})+1),
			},
		},
	})

	if err == nil {
		t.Fatal("Send() accepted a message above the outbound ceiling")
	}
	if got := connect.CodeOf(err); got != connect.CodeResourceExhausted {
		t.Errorf("Send() code = %v, want %v (error: %v)", got, connect.CodeResourceExhausted, err)
	}
}

// The outbound boundary mirrors the inbound one: a response body at the limit
// carries headers as well, and must still leave the connector.
func TestTunnelSend_AcceptsMaximumBodyWithHeaders(t *testing.T) {
	const bodySizeMB = 1
	bodyLimit := bodySizeMB * bytesPerMB

	msg := &pb.ConnectorMessage{
		RequestId: "max-size-response",
		Message: &pb.ConnectorMessage_HttpResponse{
			HttpResponse: &pb.HttpResponse{
				HttpStatus: http.StatusOK,
				Headers:    filler(64, 256),
				Body:       make([]byte, bodyLimit),
			},
		},
	}
	if got := proto.Size(msg); got <= bodyLimit {
		t.Fatalf("message is %d bytes, not larger than the %d byte body limit: "+
			"the test no longer exercises the boundary", got, bodyLimit)
	}

	handler := &recordingTunnel{received: make(chan *pb.ConnectorMessage, 1)}
	server := connectTunnelServer(t, handler)
	client := tunnelTestClient(t, server.URL, bodySizeMB, bodySizeMB)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	stream := client.Tunnel(ctx)
	if err := stream.Send(msg); err != nil {
		t.Fatalf("Send() rejected a maximum-size message: %v", err)
	}

	select {
	case got := <-handler.received:
		if diff := cmp.Diff(bodyLimit, len(got.GetHttpResponse().GetBody())); diff != "" {
			t.Errorf("delivered body length mismatch (-want +got):\n%s", diff)
		}
	case <-ctx.Done():
		t.Fatal("maximum-size message never reached the server")
	}
}

// filler returns count headers of roughly valueLen bytes each, standing in for
// the header block a real proxied exchange carries alongside its body.
func filler(count, valueLen int) []*pb.Header {
	headers := make([]*pb.Header, 0, count)
	for i := range count {
		headers = append(headers, &pb.Header{
			Key:   fmt.Sprintf("x-filler-%d", i),
			Value: strings.Repeat("v", valueLen),
		})
	}
	return headers
}

// recordingTunnel is a control-plane stand-in: it pushes a fixed set of messages
// to the connector, then records what the connector sends back.
type recordingTunnel struct {
	connectorconnect.UnimplementedConnectorServiceHandler
	push     []*pb.ControllerMessage
	received chan *pb.ConnectorMessage
}

func (h *recordingTunnel) Tunnel(
	_ context.Context,
	stream *connect.BidiStream[pb.ConnectorMessage, pb.ControllerMessage],
) error {
	for _, msg := range h.push {
		if err := stream.Send(msg); err != nil {
			return err
		}
	}
	// With nothing to record there is nothing to wait for, and ending the stream
	// keeps a client that rejects a pushed message from waiting on a peer that
	// will never speak again.
	if h.received == nil {
		return nil
	}
	for {
		msg, err := stream.Receive()
		if err != nil {
			return nil
		}
		if h.received != nil {
			select {
			case h.received <- msg:
			default:
			}
		}
	}
}

func tunnelTestClient(
	t *testing.T,
	controllerURL string,
	requestBodyMB, responseBodyMB int64,
) connectorconnect.ConnectorServiceClient {
	t.Helper()
	client, err := NewClient(&config.Config{
		TraversalControllerURL: controllerURL,
		ConnectorID:            "test-connector",
		MaxRequestBodySizeMB:   requestBodyMB,
		MaxResponseBodySizeMB:  responseBodyMB,
	})
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}
	return client
}

// connectTunnelServer serves the connector service over h2c, which is the
// transport NewClient selects for an http:// controller URL.
func connectTunnelServer(
	t *testing.T,
	svc connectorconnect.ConnectorServiceHandler,
) *httptest.Server {
	t.Helper()
	path, handler := connectorconnect.NewConnectorServiceHandler(svc)
	mux := http.NewServeMux()
	mux.Handle(path, handler)
	return startH2CServer(t, mux)
}

// rawTunnelServer serves handwritten gRPC frames so a test can put bytes on the
// wire that no conforming server would produce. The handler returns as soon as
// write does, ending the stream, so a client that keeps reading sees the end of
// the body instead of waiting on a payload that will never arrive.
func rawTunnelServer(t *testing.T, write func(w http.ResponseWriter)) *httptest.Server {
	t.Helper()
	return startH2CServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		discardEnvelope(r.Body)
		write(w)
	}))
}

// discardEnvelope reads one length-prefixed gRPC message off r and throws it
// away, so the client's send completes before the response ends the stream.
func discardEnvelope(r io.Reader) {
	prefix := make([]byte, 5)
	if _, err := io.ReadFull(r, prefix); err != nil {
		return
	}
	_, _ = io.CopyN(io.Discard, r, int64(binary.BigEndian.Uint32(prefix[1:])))
}

func startH2CServer(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()
	server := httptest.NewUnstartedServer(handler)
	// The connector dials cleartext HTTP/2 with prior knowledge, so the server has
	// to speak it without a TLS handshake to negotiate it.
	protocols := new(http.Protocols)
	protocols.SetUnencryptedHTTP2(true)
	server.Config.Protocols = protocols
	server.Start()
	t.Cleanup(server.Close)
	return server
}
