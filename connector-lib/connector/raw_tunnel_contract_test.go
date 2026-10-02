package connector_test

import (
	"bytes"
	"strings"
	"testing"

	"buf.build/go/protovalidate"
	"google.golang.org/protobuf/proto"

	pb "github.com/InteractionLabs/traversal-connector/connector-lib/gen/connector/v1"
	"github.com/InteractionLabs/traversal-connector/connector-lib/gen/connector/v1/connectorconnect"
)

// gatewayConnectorPrefix is the PathPrefix the edge gateway's HTTPRoute matches to
// reach the controller's connector gRPC port
// (infrastructure: helm/multitenant-edge-controller values servicePathPrefix).
const gatewayConnectorPrefix = "/connector.v1.ConnectorService/"

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

func TestRawTunnelMessageValidation(t *testing.T) {
	capability := strings.Repeat("a", 32)
	tests := []struct {
		name    string
		msg     proto.Message
		wantErr bool
	}{
		{name: "empty chunk", msg: &pb.RawTunnelChunk{}, wantErr: true},
		{name: "chunk", msg: &pb.RawTunnelChunk{Data: []byte{1}}, wantErr: false},
		{
			name:    "chunk over the frame size",
			msg:     &pb.RawTunnelChunk{Data: bytes.Repeat([]byte{1}, 16385)},
			wantErr: true,
		},
		{
			name: "controller hello",
			msg: &pb.RawControllerHello{
				ProtocolVersion: 1,
				TunnelId:        "550e8400-e29b-41d4-a716-446655440000",
			},
			wantErr: false,
		},
		{
			name: "controller hello version zero",
			msg: &pb.RawControllerHello{
				ProtocolVersion: 0,
				TunnelId:        "550e8400-e29b-41d4-a716-446655440000",
			},
			wantErr: true,
		},
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
		{
			name: "open error",
			msg: &pb.RawOpenError{
				PipeId: 1,
				Reason: pb.RawOpenFailureReason_RAW_OPEN_FAILURE_REASON_DIAL_FAILED,
			},
			wantErr: false,
		},
		{name: "open error unspecified", msg: &pb.RawOpenError{PipeId: 1}, wantErr: true},
		{
			name:    "drain",
			msg:     &pb.RawDrain{Reason: pb.RawDrainReason_RAW_DRAIN_REASON_ROTATION},
			wantErr: false,
		},
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
