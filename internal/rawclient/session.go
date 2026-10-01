package rawclient

import (
	"context"
	"os"

	pb "github.com/InteractionLabs/traversal-connector/connector-lib/gen/connector/v1"
	"github.com/InteractionLabs/traversal-connector/connector-lib/rawtunnel"
	"github.com/InteractionLabs/traversal-connector/internal/config"
)

// session is one raw tunnel. state moves active → draining → finished, and
// only the manager mutates it, under the manager lock.
type session struct {
	mux     *rawtunnel.Mux
	ctx     context.Context
	cleanup func()
	runDone chan struct{}
	state   sessionState
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
	hostname             string
	maxPipes             uint32
	keyIDs               []string
	redactionBlocksPipes bool
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

func (h connectorHello) message() *pb.RawConnectorHello {
	return &pb.RawConnectorHello{
		SupportedProtocolVersions: []uint32{rawtunnel.ProtocolVersion},
		Hostname:                  h.hostname,
		MaxPipes:                  h.maxPipes,
		TrustedKeyIds:             h.keyIDs,
		RedactionBlocksPipes:      h.redactionBlocksPipes,
		SupportedModes: []pb.RawPipeMode{
			pb.RawPipeMode_RAW_PIPE_MODE_PASSTHROUGH,
		},
	}
}
