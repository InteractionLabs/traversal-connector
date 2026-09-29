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

func TestOpenStreamIsNotReachableThroughGatewayRoute(t *testing.T) {
	if strings.HasPrefix(streamconnect.StreamServiceOpenStreamProcedure, gatewayConnectorPrefix) {
		t.Fatalf(
			"%s must not match the external gateway route prefix %s",
			streamconnect.StreamServiceOpenStreamProcedure,
			gatewayConnectorPrefix,
		)
	}
}

func TestRawTunnelFrameValidation(t *testing.T) {
	validOpen := func() *pb.RawOpen {
		return &pb.RawOpen{
			PipeId:     1,
			Capability: "header.claims.signature",
			Host:       "db.internal.example",
			Port:       5432,
			Mode:       pb.RawPipeMode_RAW_PIPE_MODE_PASSTHROUGH,
		}
	}
	tests := []struct {
		name    string
		frame   *pb.RawTunnelFrame
		wantErr bool
	}{
		{
			name:    "unset frame",
			frame:   &pb.RawTunnelFrame{},
			wantErr: true,
		},
		{
			name:  "data at the payload cap",
			frame: dataFrame(1, maxDataPayload),
		},
		{
			name:    "data over the payload cap",
			frame:   dataFrame(1, maxDataPayload+1),
			wantErr: true,
		},
		{
			name:    "empty data",
			frame:   dataFrame(1, 0),
			wantErr: true,
		},
		{
			name:    "data without a pipe",
			frame:   dataFrame(0, 1),
			wantErr: true,
		},
		{
			name: "window update at the window size",
			frame: &pb.RawTunnelFrame{Frame: &pb.RawTunnelFrame_WindowUpdate{
				WindowUpdate: &pb.RawWindowUpdate{PipeId: 1, CreditBytes: 256 << 10},
			}},
		},
		{
			name: "window update over the window size",
			frame: &pb.RawTunnelFrame{Frame: &pb.RawTunnelFrame_WindowUpdate{
				WindowUpdate: &pb.RawWindowUpdate{PipeId: 1, CreditBytes: 256<<10 + 1},
			}},
			wantErr: true,
		},
		{
			name: "zero credit",
			frame: &pb.RawTunnelFrame{Frame: &pb.RawTunnelFrame_WindowUpdate{
				WindowUpdate: &pb.RawWindowUpdate{PipeId: 1},
			}},
			wantErr: true,
		},
		{
			name:  "valid open",
			frame: openFrame(validOpen()),
		},
		{
			name: "open with port zero",
			frame: openFrame(func() *pb.RawOpen {
				o := validOpen()
				o.Port = 0
				return o
			}()),
			wantErr: true,
		},
		{
			name: "open with port above 65535",
			frame: openFrame(func() *pb.RawOpen {
				o := validOpen()
				o.Port = 65536
				return o
			}()),
			wantErr: true,
		},
		{
			name: "open without a mode",
			frame: openFrame(func() *pb.RawOpen {
				o := validOpen()
				o.Mode = pb.RawPipeMode_RAW_PIPE_MODE_UNSPECIFIED
				return o
			}()),
			wantErr: true,
		},
		{
			name: "open with an oversized capability",
			frame: openFrame(func() *pb.RawOpen {
				o := validOpen()
				o.Capability = strings.Repeat("a", 4097)
				return o
			}()),
			wantErr: true,
		},
		{
			name: "reset without a reason",
			frame: &pb.RawTunnelFrame{Frame: &pb.RawTunnelFrame_PipeReset{
				PipeReset: &pb.RawReset{PipeId: 1},
			}},
			wantErr: true,
		},
		{
			name: "controller hello with a non-uuid tunnel id",
			frame: &pb.RawTunnelFrame{Frame: &pb.RawTunnelFrame_ControllerHello{
				ControllerHello: &pb.RawControllerHello{ProtocolVersion: 1, TunnelId: "tunnel-1"},
			}},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := protovalidate.Validate(tt.frame)
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

// A full data frame must fit comfortably in one gRPC message and survive a
// round trip byte-for-byte.
func TestDataFrameRoundTrip(t *testing.T) {
	frame := dataFrame(7, maxDataPayload)
	wire, err := proto.Marshal(frame)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	var got pb.RawTunnelFrame
	if err := proto.Unmarshal(wire, &got); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if got.GetData().GetPipeId() != 7 ||
		!bytes.Equal(got.GetData().GetPayload(), frame.GetData().GetPayload()) {
		t.Fatal("data frame changed across a round trip")
	}
}

func dataFrame(pipeID uint64, size int) *pb.RawTunnelFrame {
	return &pb.RawTunnelFrame{Frame: &pb.RawTunnelFrame_Data{
		Data: &pb.RawData{PipeId: pipeID, Payload: bytes.Repeat([]byte{0xab}, size)},
	}}
}

func openFrame(open *pb.RawOpen) *pb.RawTunnelFrame {
	return &pb.RawTunnelFrame{Frame: &pb.RawTunnelFrame_Open{Open: open}}
}

func openStreamData(size int) *streampb.OpenStreamRequest {
	return &streampb.OpenStreamRequest{Message: &streampb.OpenStreamRequest_Data{
		Data: &streampb.Data{Payload: bytes.Repeat([]byte{0xcd}, size)},
	}}
}
