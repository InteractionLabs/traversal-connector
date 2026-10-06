// Package tunnels runs the connector's Envoy reverse tunnels.
//
// The connector holds W tunnels to one Traversal tunnel endpoint: the
// controller's host on port 443, reached with the ALPN protocol
// x-traversal-tunnel, which Traversal's front door routes to its tunnel
// endpoints. Which endpoint replica a tunnel lands on is Traversal's concern;
// the connector needs no discovery, and its Envoy configuration is written
// once, at startup.
package tunnels

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/otel/metric"
)

// TunnelPort is the port the connector dials its tunnel endpoint on, unless
// ConnectTo replaces the address.
const TunnelPort = 443

// MaxTunnels bounds W.
const MaxTunnels = 8

// Config configures a Manager.
type Config struct {
	Identity Identity
	// Dir is a private, writable directory for Envoy's configuration and
	// the connector's credentials. It must not be shared.
	Dir string
	// EnvoyPath is the Envoy binary.
	EnvoyPath string
	// CoreAddress is connector-core's pipe listener, host:port.
	CoreAddress string
	// MaxPipes is connector-core's pipe cap. Envoy's limits toward core are
	// sized above it, so core, not Envoy, refuses the overflow, with a typed
	// CAPACITY.
	MaxPipes int64
	// Tunnels is W, how many tunnels to hold. Envoy runs one worker per
	// tunnel, each holding one, so pipes spread across W threads as well as W
	// TCP connections.
	Tunnels int
	// Endpoint is the tunnel endpoint's DNS name: the controller's host. It
	// is the SNI the connector sends and the name the endpoint's certificate
	// must carry.
	Endpoint string
	// ConnectTo, if set, replaces Endpoint:443 as the address the connector
	// dials (host:port). SNI and certificate checks still use Endpoint.
	ConnectTo string
	// CertPEM and KeyPEM are the connector's client credentials; CAPEM is
	// every root that may sign a tunnel endpoint's certificate.
	CertPEM, KeyPEM, CAPEM []byte
	// AdminPort is the Envoy admin port. Zero means AdminPort.
	AdminPort int
	// StreamWindow and ConnectionWindow are the tunnels' HTTP/2 receive
	// windows in bytes. Zero means DefaultStreamWindow and
	// DefaultConnectionWindow. Larger windows raise throughput to distant
	// tunnel endpoints and let a stalled pipe hold more memory.
	StreamWindow, ConnectionWindow int
	// ReadyGrace is how long readiness waits for a first tunnel. A connector
	// whose network never lets a tunnel up becomes ready after it, so raw
	// pipes cannot hold up the legacy transport. Zero means one minute.
	ReadyGrace time.Duration
	// MeterProvider records the tunnel metrics. Nil means the global one.
	MeterProvider metric.MeterProvider
}

// Manager runs the connector's Envoy and reports on its tunnels.
type Manager struct {
	cfg   Config
	envoy envoyConfig
	admin admin
	start time.Time

	everConnected atomic.Bool
	draining      atomic.Bool
}

// dnsName is a lower-case DNS name.
var dnsName = regexp.MustCompile(
	`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)

// New checks cfg and returns a Manager.
func New(cfg Config) (*Manager, error) {
	host, portText, err := net.SplitHostPort(cfg.CoreAddress)
	port, perr := strconv.Atoi(portText)
	switch {
	case err != nil || perr != nil:
		return nil, fmt.Errorf("tunnels: invalid core address %q", cfg.CoreAddress)
	case cfg.Identity.ConnectorID == "" || cfg.Identity.TenantID == "":
		return nil, errors.New("tunnels: a connector identity is required")
	case cfg.Dir == "" || cfg.EnvoyPath == "":
		return nil, errors.New("tunnels: dir and envoy path are required")
	case !dnsName.MatchString(cfg.Endpoint) || len(cfg.Endpoint) > 253:
		return nil, fmt.Errorf("tunnels: invalid endpoint name %q", cfg.Endpoint)
	case cfg.MaxPipes <= 0:
		return nil, errors.New("tunnels: the pipe cap must be positive")
	case cfg.Tunnels <= 0 || cfg.Tunnels > MaxTunnels:
		return nil, fmt.Errorf("tunnels: the tunnel count must be between 1 and %d", MaxTunnels)
	case len(cfg.CertPEM) == 0 || len(cfg.KeyPEM) == 0 || len(cfg.CAPEM) == 0:
		return nil, errors.New("tunnels: client credentials and roots are required")
	}
	dialHost, dialPort := cfg.Endpoint, TunnelPort
	if cfg.ConnectTo != "" {
		if dialHost, dialPort, err = splitAddress(cfg.ConnectTo); err != nil {
			return nil, fmt.Errorf("tunnels: connect-to: %w", err)
		}
	}
	if cfg.AdminPort == 0 {
		cfg.AdminPort = AdminPort
	}
	if cfg.StreamWindow == 0 {
		cfg.StreamWindow = DefaultStreamWindow
	}
	if cfg.ConnectionWindow == 0 {
		cfg.ConnectionWindow = DefaultConnectionWindow
	}
	if cfg.StreamWindow < 64<<10 || cfg.StreamWindow > cfg.ConnectionWindow ||
		cfg.ConnectionWindow > 1<<30 {
		return nil, errors.New(
			"tunnels: windows must satisfy 64 KiB <= stream <= connection <= 1 GiB",
		)
	}
	if cfg.ReadyGrace == 0 {
		cfg.ReadyGrace = time.Minute
	}
	m := &Manager{
		cfg: cfg,
		envoy: envoyConfig{
			identity:         cfg.Identity,
			dir:              cfg.Dir,
			coreHost:         host,
			corePort:         port,
			endpoint:         endpoint{sni: cfg.Endpoint, host: dialHost, port: dialPort},
			maxPipes:         cfg.MaxPipes,
			streamWindow:     cfg.StreamWindow,
			connectionWindow: cfg.ConnectionWindow,
		},
		admin: newAdmin(cfg.AdminPort),
		start: time.Now(),
	}
	if err := m.registerMetrics(cfg.MeterProvider); err != nil {
		return nil, fmt.Errorf("tunnels: metrics: %w", err)
	}
	return m, nil
}

// Run writes Envoy's configuration and supervises Envoy until ctx is done.
// Envoy stops when Run returns, ending every tunnel, so cancel ctx only after
// open pipes have drained.
func (m *Manager) Run(ctx context.Context) error {
	if err := os.MkdirAll(m.cfg.Dir, 0o700); err != nil {
		return err
	}
	for name, data := range map[string][]byte{
		certFile: m.cfg.CertPEM, keyFile: m.cfg.KeyPEM, caFile: m.cfg.CAPEM,
	} {
		if err := os.WriteFile(m.envoy.path(name), data, 0o600); err != nil {
			return err
		}
	}
	if err := m.envoy.writeBootstrap(); err != nil {
		return err
	}
	supervise(ctx, m.cfg.EnvoyPath, m.envoy.path(bootstrapFile), m.cfg.Tunnels, envoyOutput)
	return nil
}

// Status reports whether the connector should take pipes, and if not, why.
// A connector is ready when it holds a tunnel. Until a first tunnel has come
// up, it is also ready once ReadyGrace has passed, so a network that blocks
// tunnels never blocks the connector's legacy transport.
func (m *Manager) Status(ctx context.Context) (bool, string) {
	if m.draining.Load() {
		return false, "draining"
	}
	up, err := m.admin.tunnels(ctx)
	if err == nil && up > 0 {
		m.everConnected.Store(true)
		return true, ""
	}
	if !m.everConnected.Load() && time.Since(m.start) > m.cfg.ReadyGrace {
		return true, "no tunnel has connected; serving the legacy transport only"
	}
	if err != nil {
		return false, "envoy is not answering: " + err.Error()
	}
	return false, "no tunnel to " + m.cfg.Endpoint
}

// Drain sends GOAWAY on every tunnel, so tunnel endpoints stop sending this
// connector new pipes and use another connector replica's tunnels. Pipes
// already open continue.
func (m *Manager) Drain(ctx context.Context) error {
	m.draining.Store(true)
	return m.admin.drainListeners(ctx)
}

func splitAddress(address string) (string, int, error) {
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return "", 0, err
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port <= 0 || port > 65535 || host == "" {
		return "", 0, fmt.Errorf("invalid address %q", address)
	}
	return host, port, nil
}
