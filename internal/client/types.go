package client

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"

	pb "github.com/InteractionLabs/traversal-connector/connector-lib/gen/connector/v1"
	"github.com/InteractionLabs/traversal-connector/connector-lib/gen/connector/v1/connectorconnect"
	"github.com/InteractionLabs/traversal-connector/internal/config"
	"github.com/InteractionLabs/traversal-connector/internal/executor"
)

const (
	// InstrumentationName is the OTel tracer name for the traversal connector handler.
	InstrumentationName = "traversal-connector/handler"
)

// connectStream wraps a Connect BidiStream, satisfying the streamSender interface.
type connectStream struct {
	*connect.BidiStreamForClient[pb.ConnectorMessage, pb.ControllerMessage]
}

// StreamConnection represents a single active bidirectional gRPC tunnel
// between this traversal connector and the Traversal control plane.
type StreamConnection struct {
	// ID is the unique identifier for this tunnel connection.
	ID uuid.UUID
	// Stream is the underlying ConnectRPC bidirectional stream.
	Stream *connect.BidiStreamForClient[pb.ConnectorMessage, pb.ControllerMessage]
	// ConnectedAt is the timestamp when this tunnel was established.
	ConnectedAt time.Time
	// LastActivity is the timestamp of the last message sent or received on this tunnel.
	LastActivity time.Time
}

// ConnectionManager manages the lifecycle of gRPC tunnel connections
// to the Traversal control plane.
type ConnectionManager struct {
	mu          sync.RWMutex
	connections []*StreamConnection
	client      connectorconnect.ConnectorServiceClient
	config      *config.Config
	executor    *executor.Executor
	tracer      trace.Tracer
	metrics     *connectionMetrics
	hostname    string
	tunnelFunc  func(ctx context.Context) error

	backoffMu sync.Mutex
	backoff   time.Duration
}

// NewConnectionManager creates a new ConnectionManager with the given configuration.
func NewConnectionManager(cfg *config.Config) (*ConnectionManager, error) {
	metrics, err := initConnectionMetrics()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize connection metrics: %w", err)
	}

	exec, err := executor.NewExecutor(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize executor: %w", err)
	}

	hostname, err := os.Hostname()
	if err != nil {
		slog.Warn("failed to get hostname, using 'unknown'", "error", err)
		hostname = "unknown"
	}

	client, err := NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create connector RPC client: %w", err)
	}

	cm := &ConnectionManager{
		connections: make([]*StreamConnection, 0, cfg.MaxTunnelsAllowed),
		client:      client,
		config:      cfg,
		executor:    exec,
		tracer:      otel.Tracer(InstrumentationName),
		metrics:     metrics,
		hostname:    hostname,
	}
	cm.tunnelFunc = cm.RunTunnel
	return cm, nil
}
