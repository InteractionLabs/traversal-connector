package connector_test

import (
	"bytes"
	"strings"
	"testing"

	"buf.build/go/protovalidate"
	"google.golang.org/protobuf/proto"

	pb "github.com/InteractionLabs/traversal-connector/connector-lib/gen/connector/v1"
	"github.com/InteractionLabs/traversal-connector/connector-lib/gen/connector/v1/connectorconnect"
	streampb "github.com/InteractionLabs/traversal-connector/connector-lib/gen/stream/v1"
	"github.com/InteractionLabs/traversal-connector/connector-lib/gen/stream/v1/streamconnect"
)

// gatewayConnectorPrefix is the PathPrefix the edge gateway's HTTPRoute matches to
// reach the controller's connector gRPC port
// (infrastructure: helm/multitenant-edge-controller values servicePathPrefix).
const gatewayConnectorPrefix = "/connector.v1.ConnectorService/"

const maxDataPayload = 32 << 10

func TestRawTunnelUsesExistingGatewayRoute(t *testing.T) {
	for _, procedure := range []string{
		connectorconnect.ConnectorServiceTunnelProcedure,
		connectorconnect.ConnectorServiceRawTunnelProcedure,
	} {
		if !strings.HasPrefix(procedure, gatewayConnectorPrefix) {
			t.Errorf(
				"%s is not under the gateway route prefix %s",
				procedure,
				gatewayConnectorPrefix,
			)
		}
	}
}

// TestOpenStreamProcedureIsNotUnderConnectorPrefix checks only the generated
// procedure name. It does not prove OpenStream is unreachable on a deployed
// gateway: that requires a rendered Gateway and Service test once controller
// ingress is wired.
func TestOpenStreamProcedureIsNotUnderConnectorPrefix(t *testing.T) {
	procedure := streamconnect.StreamServiceOpenStreamProcedure
	if strings.HasPrefix(procedure, gatewayConnectorPrefix) {
		t.Fatalf(
			"%s shares the connector service prefix %s; this only checks the generated name",
			procedure,
			gatewayConnectorPrefix,
		)
	}
}

func TestRawTunnelMessageValidation(t *testing.T) {
	capability := strings.Repeat("a", 32)
	tests := []struct {
		name    string
		msg     proto.Message
		wantErr bool
	}{
		{name: "empty chunk", msg: &pb.RawTunnelChunk{}, wantErr: true},
		{name: "chunk", msg: &pb.RawTunnelChunk{Data: []byte{1}}, wantErr: false},
		{name: "chunk over the frame size", msg: &pb.RawTunnelChunk{Data: bytes.Repeat([]byte{1}, 16385)}, wantErr: true},
		{name: "controller hello", msg: &pb.RawControllerHello{ProtocolVersion: 1, TunnelId: "550e8400-e29b-41d4-a716-446655440000"}, wantErr: false},
		{name: "controller hello version zero", msg: &pb.RawControllerHello{ProtocolVersion: 0, TunnelId: "550e8400-e29b-41d4-a716-446655440000"}, wantErr: true},
		{name: "connector hello", msg: &pb.RawConnectorHello{
			SupportedProtocolVersions: []uint32{1}, Hostname: "edge-1", MaxPipes: 100,
			SupportedModes: []pb.RawPipeMode{pb.RawPipeMode_RAW_PIPE_MODE_PASSTHROUGH},
		}, wantErr: false},
		{name: "connector hello empty modes", msg: &pb.RawConnectorHello{
			SupportedProtocolVersions: []uint32{1}, Hostname: "edge-1", MaxPipes: 100,
		}, wantErr: true},
		{name: "open", msg: &pb.RawOpen{
			PipeId: 1, Mode: pb.RawPipeMode_RAW_PIPE_MODE_PASSTHROUGH,
			Host: "10.0.0.1", Port: 443, Capability: capability,
		}, wantErr: false},
		{name: "open missing capability", msg: &pb.RawOpen{
			PipeId: 1, Mode: pb.RawPipeMode_RAW_PIPE_MODE_PASSTHROUGH, Host: "10.0.0.1", Port: 443,
		}, wantErr: true},
		{name: "open error", msg: &pb.RawOpenError{PipeId: 1, Reason: pb.RawOpenFailureReason_RAW_OPEN_FAILURE_REASON_DIAL_FAILED}, wantErr: false},
		{name: "open error unspecified", msg: &pb.RawOpenError{PipeId: 1}, wantErr: true},
		{name: "drain", msg: &pb.RawDrain{Reason: pb.RawDrainReason_RAW_DRAIN_REASON_ROTATION}, wantErr: false},
		{name: "drain unspecified", msg: &pb.RawDrain{}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := protovalidate.Validate(tt.msg)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestOpenStreamDataCap(t *testing.T) {
	for _, size := range []int{1, maxDataPayload} {
		if err := protovalidate.Validate(openStreamData(size)); err != nil {
			t.Errorf("payload of %d bytes rejected: %v", size, err)
		}
	}
	for _, size := range []int{0, maxDataPayload + 1} {
		if err := protovalidate.Validate(openStreamData(size)); err == nil {
			t.Errorf("payload of %d bytes accepted", size)
		}
	}
}

func TestOpenStreamRejectsRelayBeyondOneHop(t *testing.T) {
	req := &streampb.OpenStreamRequest{Message: &streampb.OpenStreamRequest_Open{
		Open: &streampb.Open{Capability: "header.claims.signature", HopCount: 2},
	}}
	if err := protovalidate.Validate(req); err == nil {
		t.Fatal("open with hop_count 2 accepted")
	}
}

func TestChunkRoundTrip(t *testing.T) {
	chunk := &pb.RawTunnelChunk{Data: bytes.Repeat([]byte{0xab}, 16384)}
	wire, err := proto.Marshal(chunk)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	var got pb.RawTunnelChunk
	if err := proto.Unmarshal(wire, &got); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if !bytes.Equal(got.GetData(), chunk.GetData()) {
		t.Fatal("chunk changed across a round trip")
	}
}

func TestOpenedRequiresIdentity(t *testing.T) {
	valid := &streampb.Opened{
		ConnectorId:   "connector-1",
		TunnelId:      "11111111-1111-4111-8111-111111111111",
		PipeId:        1,
		ControllerPod: "edge-controller-0",
	}
	if err := protovalidate.Validate(valid); err != nil {
		t.Fatalf("valid opened rejected: %v", err)
	}
	cases := []*streampb.Opened{
		{TunnelId: valid.GetTunnelId(), PipeId: 1, ControllerPod: valid.GetControllerPod()},
		{ConnectorId: valid.GetConnectorId(), PipeId: 1, ControllerPod: valid.GetControllerPod()},
		{ConnectorId: valid.GetConnectorId(), TunnelId: "not-a-uuid", PipeId: 1,
			ControllerPod: valid.GetControllerPod()},
		{ConnectorId: valid.GetConnectorId(), TunnelId: valid.GetTunnelId(),
			ControllerPod: valid.GetControllerPod()},
		{ConnectorId: valid.GetConnectorId(), TunnelId: valid.GetTunnelId(), PipeId: 1},
	}
	for _, opened := range cases {
		if err := protovalidate.Validate(opened); err == nil {
			t.Fatalf("opened accepted: %+v", opened)
		}
	}
}

func TestClosedAndOpenErrorRequireADefinedReason(t *testing.T) {
	for _, reason := range []pb.RawCloseReason{
		0, 99,
	} {
		closed := &streampb.Closed{Reason: reason}
		if err := protovalidate.Validate(closed); err == nil {
			t.Fatalf("closed accepted reason %d", reason)
		}
	}
	if err := protovalidate.Validate(&streampb.Closed{
		Reason: pb.RawCloseReason_RAW_CLOSE_REASON_COMPLETED,
	}); err != nil {
		t.Fatalf("completed close rejected: %v", err)
	}
	for _, reason := range []pb.RawOpenFailureReason{0, 99} {
		failure := &streampb.OpenStreamError{Reason: reason}
		if err := protovalidate.Validate(failure); err == nil {
			t.Fatalf("open error accepted reason %d", reason)
		}
	}
	if err := protovalidate.Validate(&streampb.OpenStreamError{
		Reason: pb.RawOpenFailureReason_RAW_OPEN_FAILURE_REASON_DIAL_FAILED,
	}); err != nil {
		t.Fatalf("dial failure rejected: %v", err)
	}
}

// TestRequestResetIsOnlyCancelled freezes the sender split on the shared Reset
// message. Protovalidate still accepts every defined nonzero reason, because
// a response may carry an infrastructure reason. Callers may send only
// CANCELLED. COMPLETED is a close, not a reset, and is absent from both sets.
func TestRequestResetIsOnlyCancelled(t *testing.T) {
	callerAllowed := map[pb.RawCloseReason]bool{
		pb.RawCloseReason_RAW_CLOSE_REASON_CANCELLED: true,
	}
	responseAllowed := []pb.RawCloseReason{
		pb.RawCloseReason_RAW_CLOSE_REASON_CANCELLED,
		pb.RawCloseReason_RAW_CLOSE_REASON_UPSTREAM_ERROR,
		pb.RawCloseReason_RAW_CLOSE_REASON_IDLE_TIMEOUT,
		pb.RawCloseReason_RAW_CLOSE_REASON_MAX_LIFETIME,
		pb.RawCloseReason_RAW_CLOSE_REASON_CONTROLLER_TERMINATING,
		pb.RawCloseReason_RAW_CLOSE_REASON_CONNECTOR_TERMINATING,
		pb.RawCloseReason_RAW_CLOSE_REASON_TUNNEL_LOST,
		pb.RawCloseReason_RAW_CLOSE_REASON_PROTOCOL_ERROR,
		pb.RawCloseReason_RAW_CLOSE_REASON_ROTATION_DEADLINE,
	}
	if len(callerAllowed) != 1 ||
		!callerAllowed[pb.RawCloseReason_RAW_CLOSE_REASON_CANCELLED] {
		t.Fatal("a caller reset may only be CANCELLED")
	}
	for _, reason := range responseAllowed {
		req := &streampb.OpenStreamRequest{
			Message: &streampb.OpenStreamRequest_StreamReset{
				StreamReset: &streampb.Reset{Reason: reason},
			},
		}
		if err := protovalidate.Validate(req); err != nil {
			t.Fatalf("shared Reset rejected %s: %v", reason, err)
		}
		if reason != pb.RawCloseReason_RAW_CLOSE_REASON_CANCELLED && callerAllowed[reason] {
			t.Fatalf("caller reset allows infrastructure reason %s", reason)
		}
	}
}

func openStreamData(size int) *streampb.OpenStreamRequest {
	return &streampb.OpenStreamRequest{Message: &streampb.OpenStreamRequest_Data{
		Data: &streampb.Data{Payload: bytes.Repeat([]byte{0xcd}, size)},
	}}
}
