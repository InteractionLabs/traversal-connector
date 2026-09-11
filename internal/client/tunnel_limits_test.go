package client

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
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

// The allowance has to cover more than the header block, because a message carries
// a request id, a method and an unbounded URL alongside it.
func TestTunnelMessageOverhead_ExceedsTheHeaderBudget(t *testing.T) {
	if tunnelMessageOverheadBytes <= maxHeaderBlockBytes {
		t.Errorf("overhead allowance %d does not exceed the header budget %d",
			tunnelMessageOverheadBytes, maxHeaderBlockBytes)
	}
}

// A limit too large to express must not wrap into a negative ceiling, which the
// transport reads as no limit at all.
func TestTunnelMessageCeiling_InexpressibleLimitStaysPositive(t *testing.T) {
	if !exceedsExpressibleCeiling(math.MaxInt64) {
		t.Fatal("MaxInt64 MB is expected to exceed what a ceiling can express")
	}
	if got := tunnelMessageCeiling(math.MaxInt64); got != math.MaxInt {
		t.Errorf("tunnelMessageCeiling(MaxInt64) = %d, want MaxInt (%d)", got, math.MaxInt)
	}
	// Every limit an operator could plausibly set stays expressible, so the clamp
	// never silently narrows a real configuration.
	if exceedsExpressibleCeiling(64 * 1024) {
		t.Error("a 64 GB body limit should still be expressible as a ceiling")
	}
}

func TestTunnelReadMaxBytes_TracksRequestBodyLimit(t *testing.T) {
	cfg := &config.Config{
		MaxRequestBodySizeMB:         4,
		MaxResponseBodySizeMB:        16,
		MaxDecodedResponseBodySizeMB: 64,
	}

	want := 4*bytesPerMB + tunnelMessageOverheadBytes
	if diff := cmp.Diff(want, tunnelReadMaxBytes(cfg)); diff != "" {
		t.Errorf("tunnelReadMaxBytes mismatch (-want +got):\n%s", diff)
	}
}

// Outbound is not the mirror of inbound: a body can leave larger than it arrived,
// because redacting a compressed body means decoding it and re-encoding what the
// decoded limit allows.
func TestTunnelSendMaxBytes_TracksTheLargerResponseLimit(t *testing.T) {
	tests := []struct {
		name        string
		responseMB  int64
		decodedMB   int64
		wantBodyMB  int64
		wantUnbound bool
	}{
		{
			name:       "decoded limit exceeds the wire limit",
			responseMB: 32,
			decodedMB:  256,
			wantBodyMB: 256,
		},
		{
			name:       "wire limit exceeds the decoded limit",
			responseMB: 64,
			decodedMB:  16,
			wantBodyMB: 64,
		},
		{
			name:        "unset wire limit leaves what can leave unbounded",
			responseMB:  0,
			decodedMB:   256,
			wantUnbound: true,
		},
		{
			name:        "unset decoded limit leaves what can leave unbounded",
			responseMB:  32,
			decodedMB:   0,
			wantUnbound: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tunnelSendMaxBytes(&config.Config{
				MaxResponseBodySizeMB:        tt.responseMB,
				MaxDecodedResponseBodySizeMB: tt.decodedMB,
			})

			want := unlimitedMessageSize
			if !tt.wantUnbound {
				want = int(tt.wantBodyMB)*bytesPerMB + tunnelMessageOverheadBytes
			}
			if diff := cmp.Diff(want, got); diff != "" {
				t.Errorf("tunnelSendMaxBytes mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// The rejection has to come from the length the envelope declares, before the
// payload behind it is read. The server here declares a payload larger than the
// process could allocate and then sends almost none of it, so a client that waited
// for the payload could not finish at all. The assertion carrying that proof is the
// code: on this path resource-exhausted is reachable only from the prefix
// comparison, and a client that read first fails as a truncated message instead.
func TestTunnelReceive_RejectsDeclaredSizeBeforeReadingPayload(t *testing.T) {
	const declaredSize = uint32(math.MaxUint32)

	server := rawTunnelServer(t, func(w http.ResponseWriter) {
		writeGRPCHeader(w)
		writeEnvelopePrefix(w, declaredSize)
		_, _ = w.Write(make([]byte, 8))
		flush(w)
	})

	stream := openTunnel(t, server.URL, &config.Config{MaxRequestBodySizeMB: 1})

	_, err := stream.Receive()
	if err == nil {
		t.Fatal("Receive() accepted a message declaring a size above the ceiling")
	}
	if got := connect.CodeOf(err); got != connect.CodeResourceExhausted {
		t.Errorf("Receive() code = %v, want %v (error: %v)",
			got, connect.CodeResourceExhausted, err)
	}
	// Raised on this side, which is what keeps it from reading as the controller
	// reporting exhaustion of its own.
	if connect.IsWireError(err) {
		t.Error("Receive() error is reported as coming from the server, want locally raised")
	}
	if !isLocalMessageSizeError(err) {
		t.Error("isLocalMessageSizeError() = false for a ceiling refusal")
	}
}

// The controller reports its own exhaustion with the same code the ceiling uses, so
// that case must not be mistaken for a message this side refused. Keeping them apart
// is what stops a full controller and an oversized message from being diagnosed as
// each other.
func TestTunnelReceive_ServerExhaustionIsNotALocalSizeError(t *testing.T) {
	server := connectTunnelServer(t, &exhaustedTunnel{})
	stream := openTunnel(t, server.URL, &config.Config{MaxRequestBodySizeMB: 1})

	_, err := stream.Receive()
	if got := connect.CodeOf(err); got != connect.CodeResourceExhausted {
		t.Fatalf("Receive() code = %v, want %v (error: %v)",
			got, connect.CodeResourceExhausted, err)
	}
	if isLocalMessageSizeError(err) {
		t.Error("isLocalMessageSizeError() = true for exhaustion reported by the server")
	}
}

// The payload is fully delivered here, so the only thing keeping it out of memory
// is the transport discarding it as it arrives. Measuring what the client allocated
// while draining it is what separates discarding from buffering.
func TestTunnelReceive_DoesNotBufferRejectedPayload(t *testing.T) {
	// Large enough that holding the payload would be unmistakable next to draining
	// it. The guard below keeps it above the ceiling if the allowance ever changes.
	const payloadSize = 52 << 20

	cfg := &config.Config{MaxRequestBodySizeMB: 1}
	if ceiling := tunnelReadMaxBytes(cfg); payloadSize <= ceiling {
		t.Fatalf("payload of %d does not exceed the ceiling of %d", payloadSize, ceiling)
	}

	server := rawTunnelServer(t, func(w http.ResponseWriter) {
		writeGRPCHeader(w)
		writeEnvelopePrefix(w, payloadSize)
		// One reused buffer, so the payload the client drains is not also a
		// measurable allocation on the server's side of the same process.
		chunk := make([]byte, 64*1024)
		for sent := 0; sent < payloadSize; sent += len(chunk) {
			_, _ = w.Write(chunk)
		}
		flush(w)
	})

	stream := openTunnel(t, server.URL, cfg)

	var err error
	allocated := allocatedDuring(func() {
		_, err = stream.Receive()
	})

	if !isLocalMessageSizeError(err) {
		t.Fatalf("Receive() error = %v, want a ceiling refusal", err)
	}
	if raceEnabled {
		return
	}
	// Draining costs a few reused buffers, so this sits well above what that takes
	// and far below what holding the payload would.
	if allocated > payloadSize/8 {
		t.Errorf("Receive() allocated %d bytes draining a %d byte payload, want under %d",
			allocated, payloadSize, payloadSize/8)
	}
}

// A body at exactly the configured limit arrives wrapped in a URL and the largest
// header block the transport lets through, so the whole message runs well past the
// body limit. A ceiling set to that limit, or an allowance merely equal to the
// header budget, would reject it.
func TestTunnelReceive_AcceptsMaximumBodyWithMaximumHeaderBlock(t *testing.T) {
	const bodySizeMB = 1
	cfg := &config.Config{MaxRequestBodySizeMB: bodySizeMB}
	bodyLimit := bodySizeMB * bytesPerMB

	pushed := &pb.ControllerMessage{
		RequestId: "max-size-request",
		Message: &pb.ControllerMessage_HttpRequest{
			HttpRequest: &pb.HttpRequest{
				Method:  http.MethodPost,
				Url:     "https://upstream.example.com/api?q=" + strings.Repeat("k", 4096),
				Headers: headerBlock(maxHeaderBlockBytes),
				Body:    make([]byte, bodyLimit),
			},
		},
	}
	requireExceedsBodyLimit(t, proto.Size(pushed), bodyLimit)

	server := connectTunnelServer(t, &recordingTunnel{push: []*pb.ControllerMessage{pushed}})
	stream := openTunnel(t, server.URL, cfg)

	got, err := stream.Receive()
	if err != nil {
		t.Fatalf("Receive() rejected a maximum-size message: %v", err)
	}
	if diff := cmp.Diff(bodyLimit, len(got.GetHttpRequest().GetBody())); diff != "" {
		t.Errorf("received body length mismatch (-want +got):\n%s", diff)
	}
}

func TestTunnelSend_RejectsOversizedMessage(t *testing.T) {
	cfg := &config.Config{MaxResponseBodySizeMB: 1, MaxDecodedResponseBodySizeMB: 1}

	// A receiving handler holds the stream open, so a rejection here is the
	// transport refusing to write rather than a stream that went away.
	server := connectTunnelServer(t, &recordingTunnel{received: make(chan *pb.ConnectorMessage, 1)})
	stream := openTunnel(t, server.URL, cfg)

	err := stream.Send(&pb.ConnectorMessage{
		RequestId: "oversized-response",
		Message: &pb.ConnectorMessage_HttpResponse{
			HttpResponse: &pb.HttpResponse{
				HttpStatus: http.StatusOK,
				Body:       make([]byte, tunnelSendMaxBytes(cfg)+1),
			},
		},
	})

	if err == nil {
		t.Fatal("Send() accepted a message above the outbound ceiling")
	}
	if got := connect.CodeOf(err); got != connect.CodeResourceExhausted {
		t.Errorf("Send() code = %v, want %v (error: %v)",
			got, connect.CodeResourceExhausted, err)
	}
}

// The largest body that can leave is the decoded limit, not the wire limit: a
// compressed body is decoded to be scanned and re-encoded from that plaintext. With
// the header block on top, a ceiling derived from the wire limit would drop it.
func TestTunnelSend_AcceptsMaximumDecodedBodyWithMaximumHeaderBlock(t *testing.T) {
	// The gap between the two limits has to exceed the overhead allowance, or the
	// allowance alone would carry this message and the test would pass even with the
	// ceiling derived from the wrong limit.
	const decodedMB = 8
	cfg := &config.Config{MaxResponseBodySizeMB: 1, MaxDecodedResponseBodySizeMB: decodedMB}
	decodedLimit := decodedMB * bytesPerMB

	msg := &pb.ConnectorMessage{
		RequestId: "max-size-response",
		Message: &pb.ConnectorMessage_HttpResponse{
			HttpResponse: &pb.HttpResponse{
				HttpStatus: http.StatusOK,
				Headers:    headerBlock(maxHeaderBlockBytes),
				Body:       make([]byte, decodedLimit),
			},
		},
	}
	requireExceedsBodyLimit(t, proto.Size(msg), int(cfg.MaxResponseBodySizeMB)*bytesPerMB)

	handler := &recordingTunnel{received: make(chan *pb.ConnectorMessage, 4)}
	server := connectTunnelServer(t, handler)
	stream := openTunnel(t, server.URL, cfg)

	if err := stream.Send(msg); err != nil {
		t.Fatalf("Send() rejected a maximum-size message: %v", err)
	}

	got := awaitMessage(t, handler.received, msg.GetRequestId())
	if diff := cmp.Diff(decodedLimit, len(got.GetHttpResponse().GetBody())); diff != "" {
		t.Errorf("delivered body length mismatch (-want +got):\n%s", diff)
	}
}

// awaitMessage waits for the message with requestID, skipping the send that opened
// the stream.
func awaitMessage(
	t *testing.T,
	received <-chan *pb.ConnectorMessage,
	requestID string,
) *pb.ConnectorMessage {
	t.Helper()
	deadline := time.After(30 * time.Second)
	for {
		select {
		case msg := <-received:
			if msg.GetRequestId() == requestID {
				return msg
			}
		case <-deadline:
			t.Fatalf("message %q never reached the server", requestID)
		}
	}
}

func requireExceedsBodyLimit(t *testing.T, messageSize, bodyLimit int) {
	t.Helper()
	if messageSize <= bodyLimit {
		t.Fatalf("message is %d bytes, not larger than the %d byte body limit: "+
			"the test no longer exercises the boundary", messageSize, bodyLimit)
	}
}

func allocatedDuring(f func()) uint64 {
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	f()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

// headerBlock returns headers whose values total about totalBytes, standing in for
// the header block a real proxied exchange carries alongside its body.
func headerBlock(totalBytes int) []*pb.Header {
	const valueLen = 4096
	count := totalBytes / valueLen
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
		select {
		case h.received <- msg:
		default:
		}
	}
}

// exhaustedTunnel refuses the stream the way a controller with no capacity for
// another tunnel does.
type exhaustedTunnel struct {
	connectorconnect.UnimplementedConnectorServiceHandler
}

func (*exhaustedTunnel) Tunnel(
	_ context.Context,
	_ *connect.BidiStream[pb.ConnectorMessage, pb.ControllerMessage],
) error {
	return connect.NewError(connect.CodeResourceExhausted, errors.New("at capacity"))
}

// openTunnel builds a client from cfg and opens a tunnel to controllerURL. The
// stream is lazy, so it sends once to make the request before returning.
func openTunnel(
	t *testing.T,
	controllerURL string,
	cfg *config.Config,
) *connect.BidiStreamForClient[pb.ConnectorMessage, pb.ControllerMessage] {
	t.Helper()
	cfg.TraversalControllerURL = controllerURL
	cfg.ConnectorID = "test-connector"

	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)

	stream := client.Tunnel(ctx)
	if err := stream.Send(&pb.ConnectorMessage{RequestId: "probe"}); err != nil {
		t.Fatalf("Send() opening the stream returned error: %v", err)
	}
	return stream
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

func writeGRPCHeader(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/grpc")
	w.WriteHeader(http.StatusOK)
	flush(w)
}

// writeEnvelopePrefix writes the five-byte gRPC message prefix: a flags byte and
// the declared payload length.
func writeEnvelopePrefix(w http.ResponseWriter, payloadSize uint32) {
	prefix := make([]byte, 5)
	binary.BigEndian.PutUint32(prefix[1:], payloadSize)
	_, _ = w.Write(prefix)
}

func flush(w http.ResponseWriter) {
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}
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
