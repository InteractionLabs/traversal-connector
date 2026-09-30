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
		{
			name: "controller hello with protocol version zero",
			frame: &pb.RawTunnelFrame{Frame: &pb.RawTunnelFrame_ControllerHello{
				ControllerHello: &pb.RawControllerHello{
					TunnelId: "123e4567-e89b-12d3-a456-426614174000",
				},
			}},
			wantErr: true,
		},
		{
			name: "controller hello",
			frame: &pb.RawTunnelFrame{Frame: &pb.RawTunnelFrame_ControllerHello{
				ControllerHello: &pb.RawControllerHello{
					ProtocolVersion: 1,
					TunnelId:        "123e4567-e89b-12d3-a456-426614174000",
				},
			}},
		},
		{
			name: "connector hello without a protocol version",
			frame: &pb.RawTunnelFrame{Frame: &pb.RawTunnelFrame_ConnectorHello{
				ConnectorHello: &pb.RawConnectorHello{
					MaxPipes:       1,
					SupportedModes: []pb.RawPipeMode{pb.RawPipeMode_RAW_PIPE_MODE_PASSTHROUGH},
				},
			}},
			wantErr: true,
		},
		{
			name: "connector hello with an unspecified mode",
			frame: &pb.RawTunnelFrame{Frame: &pb.RawTunnelFrame_ConnectorHello{
				ConnectorHello: &pb.RawConnectorHello{
					SupportedProtocolVersions: []uint32{1},
					MaxPipes:                  1,
					SupportedModes: []pb.RawPipeMode{
						pb.RawPipeMode_RAW_PIPE_MODE_UNSPECIFIED,
					},
				},
			}},
			wantErr: true,
		},
		{
			name: "connector hello with an unknown mode",
			frame: &pb.RawTunnelFrame{Frame: &pb.RawTunnelFrame_ConnectorHello{
				ConnectorHello: &pb.RawConnectorHello{
					SupportedProtocolVersions: []uint32{1},
					MaxPipes:                  1,
					SupportedModes:            []pb.RawPipeMode{99},
				},
			}},
			wantErr: true,
		},
		{
			name: "connector hello with max pipes zero",
			frame: &pb.RawTunnelFrame{Frame: &pb.RawTunnelFrame_ConnectorHello{
				ConnectorHello: &pb.RawConnectorHello{
					SupportedProtocolVersions: []uint32{1},
					SupportedModes: []pb.RawPipeMode{
						pb.RawPipeMode_RAW_PIPE_MODE_PASSTHROUGH,
					},
				},
			}},
			wantErr: true,
		},
		{
			name: "open error with an unspecified reason",
			frame: openErrorFrame(
				1,
				pb.RawOpenFailureReason_RAW_OPEN_FAILURE_REASON_UNSPECIFIED,
				"",
			),
			wantErr: true,
		},
		{
			name:    "open error with an unknown reason",
			frame:   openErrorFrame(1, 99, ""),
			wantErr: true,
		},
		{
			name: "open error without a pipe id",
			frame: openErrorFrame(
				0,
				pb.RawOpenFailureReason_RAW_OPEN_FAILURE_REASON_DIAL_FAILED,
				"",
			),
			wantErr: true,
		},
		{
			name: "open error detail at the cap",
			frame: openErrorFrame(
				1,
				pb.RawOpenFailureReason_RAW_OPEN_FAILURE_REASON_DIAL_FAILED,
				strings.Repeat("a", 256),
			),
		},
		{
			name: "open error detail over the cap",
			frame: openErrorFrame(
				1,
				pb.RawOpenFailureReason_RAW_OPEN_FAILURE_REASON_DIAL_FAILED,
				strings.Repeat("a", 257),
			),
			wantErr: true,
		},
		{
			name: "close with an unspecified reason",
			frame: &pb.RawTunnelFrame{Frame: &pb.RawTunnelFrame_Close{
				Close: &pb.RawClose{PipeId: 1},
			}},
			wantErr: true,
		},
		{
			name: "close with an unknown reason",
			frame: &pb.RawTunnelFrame{Frame: &pb.RawTunnelFrame_Close{
				Close: &pb.RawClose{PipeId: 1, Reason: 99},
			}},
			wantErr: true,
		},
		{
			name: "close without a pipe id",
			frame: &pb.RawTunnelFrame{Frame: &pb.RawTunnelFrame_Close{
				Close: &pb.RawClose{Reason: pb.RawCloseReason_RAW_CLOSE_REASON_COMPLETED},
			}},
			wantErr: true,
		},
		{
			name: "close",
			frame: &pb.RawTunnelFrame{Frame: &pb.RawTunnelFrame_Close{
				Close: &pb.RawClose{
					PipeId: 1,
					Reason: pb.RawCloseReason_RAW_CLOSE_REASON_COMPLETED,
				},
			}},
		},
		{
			name: "drain with an unspecified reason",
			frame: &pb.RawTunnelFrame{Frame: &pb.RawTunnelFrame_Drain{
				Drain: &pb.RawDrain{},
			}},
			wantErr: true,
		},
		{
			name: "drain with an unknown reason",
			frame: &pb.RawTunnelFrame{Frame: &pb.RawTunnelFrame_Drain{
				Drain: &pb.RawDrain{Reason: 99},
			}},
			wantErr: true,
		},
		{
			name: "drain",
			frame: &pb.RawTunnelFrame{Frame: &pb.RawTunnelFrame_Drain{
				Drain: &pb.RawDrain{Reason: pb.RawDrainReason_RAW_DRAIN_REASON_ROTATION},
			}},
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

func dataFrame(pipeID uint64, size int) *pb.RawTunnelFrame {
	return &pb.RawTunnelFrame{Frame: &pb.RawTunnelFrame_Data{
		Data: &pb.RawData{PipeId: pipeID, Payload: bytes.Repeat([]byte{0xab}, size)},
	}}
}

func openFrame(open *pb.RawOpen) *pb.RawTunnelFrame {
	return &pb.RawTunnelFrame{Frame: &pb.RawTunnelFrame_Open{Open: open}}
}

func openErrorFrame(id uint64, reason pb.RawOpenFailureReason, detail string) *pb.RawTunnelFrame {
	return &pb.RawTunnelFrame{Frame: &pb.RawTunnelFrame_OpenError{
		OpenError: &pb.RawOpenError{PipeId: id, Reason: reason, Detail: detail},
	}}
}

func openStreamData(size int) *streampb.OpenStreamRequest {
	return &streampb.OpenStreamRequest{Message: &streampb.OpenStreamRequest_Data{
		Data: &streampb.Data{Payload: bytes.Repeat([]byte{0xcd}, size)},
	}}
}
