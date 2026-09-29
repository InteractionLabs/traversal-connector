package rawclient

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/google/uuid"

	pb "github.com/InteractionLabs/traversal-connector/connector-lib/gen/connector/v1"
	"github.com/InteractionLabs/traversal-connector/connector-lib/rawtunnel"
	"github.com/InteractionLabs/traversal-connector/internal/config"
)

var errIncompatible = errors.New("controller raw protocol version is not supported")

// session is one raw tunnel. state moves active → draining → finished, and
// only the manager mutates it, under the manager lock.
type session struct {
	mux      *rawtunnel.Mux
	tunnelID string
	ctx      context.Context
	cleanup  func()
	state    sessionState
	// replace is set when the peer drains this tunnel and the process is not
	// shutting down, so the slot opens another tunnel without backing off.
	replace bool
}

type sessionState uint8

const (
	sessionActive sessionState = iota
	sessionDraining
	sessionFinished
)

type connectorHello struct {
	hostname string
	maxPipes uint32
	keyIDs   []string
}

func helloFrom(cfg *config.Config) connectorHello {
	host, err := os.Hostname()
	if err != nil || host == "" {
		host = "unknown"
	}
	if len(host) > 253 {
		host = host[:253]
	}
	var keys []string
	if id := cfg.RawTunnel.CurrentKeyID; id != "" {
		keys = append(keys, id)
	}
	if id := cfg.RawTunnel.NextKeyID; id != "" {
		keys = append(keys, id)
	}
	return connectorHello{
		hostname: host,
		// MaxPipesPerTunnel is validated to fit.
		maxPipes: uint32(cfg.RawTunnel.MaxPipesPerTunnel), //nolint:gosec // bounded by validate
		keyIDs:   keys,
	}
}

func exchangeHello(stream rawtunnel.Stream, hello connectorHello) (string, error) {
	err := stream.Send(&pb.RawTunnelFrame{Frame: &pb.RawTunnelFrame_ConnectorHello{
		ConnectorHello: &pb.RawConnectorHello{
			SupportedProtocolVersions: []uint32{rawtunnel.ProtocolVersion},
			Hostname:                  hello.hostname,
			MaxPipes:                  hello.maxPipes,
			TrustedKeyIds:             hello.keyIDs,
			SupportedModes: []pb.RawPipeMode{
				pb.RawPipeMode_RAW_PIPE_MODE_PASSTHROUGH,
			},
		},
	}})
	if err != nil {
		return "", fmt.Errorf("send raw hello: %w", err)
	}
	frame, err := stream.Receive()
	if err != nil {
		return "", fmt.Errorf("receive raw hello: %w", err)
	}
	got := frame.GetControllerHello()
	if got == nil {
		return "", errors.New("controller hello missing")
	}
	if got.GetProtocolVersion() != rawtunnel.ProtocolVersion {
		return "", errIncompatible
	}
	if _, err := uuid.Parse(got.GetTunnelId()); err != nil {
		return "", errors.New("controller tunnel id is not a uuid")
	}
	return got.GetTunnelId(), nil
}
