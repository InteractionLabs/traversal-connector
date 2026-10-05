// Package tunnels runs the connector's Envoy reverse tunnels.
//
// The connector dials out to every Traversal tunnel endpoint replica and
// holds W tunnels to each, so any replica can carry a pipe to this connector
// and nothing on Traversal's side has to look up which replica holds which
// tunnel. Which replicas exist comes from discovery, polled on the
// controller's origin; Envoy picks up changes from files without dropping
// tunnels that are already up.
package tunnels

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/http"
	"os"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

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
	// PerReplica is W, how many tunnels to hold to each replica. Envoy runs
	// one worker per tunnel, each holding one, so pipes spread across W
	// threads as well as W TCP connections.
	PerReplica int
	// DiscoveryURL is polled for the replica set.
	DiscoveryURL string
	// DiscoveryClient makes discovery requests. It carries the connector's
	// client certificate and egress settings.
	DiscoveryClient *http.Client
	// DiscoveryInterval is the mean time between discovery polls.
	DiscoveryInterval time.Duration
	// ConnectTo, if set, replaces discovery's entry point address
	// (host:port) for every replica: SNI and certificate checks still use
	// the replica's name.
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
}

// Manager runs the connector's Envoy and keeps its tunnels pointed at the
// current replica set.
type Manager struct {
	cfg   Config
	envoy envoyConfig
	admin admin
	start time.Time

	mu       sync.Mutex
	replicas []replica
	cell     string
	// staleClusters is set while the cluster file still names replicas the
	// listeners no longer use. They are pruned on the next poll, once Envoy
	// has had time to apply the listeners: Envoy's file watches for clusters
	// and listeners apply independently, so pruning in the same breath could
	// leave a listener naming a removed cluster.
	staleClusters bool

	everConnected atomic.Bool
	draining      atomic.Bool
}

// New checks cfg and returns a Manager.
func New(cfg Config) (*Manager, error) {
	host, portText, err := net.SplitHostPort(cfg.CoreAddress)
	port, perr := strconv.Atoi(portText)
	switch {
	case err != nil || perr != nil:
		return nil, fmt.Errorf("tunnels: invalid core address %q", cfg.CoreAddress)
	case cfg.Identity.ConnectorID == "" || cfg.Identity.TenantID == "":
		return nil, errors.New("tunnels: a connector identity is required")
	case cfg.Dir == "" || cfg.EnvoyPath == "" || cfg.DiscoveryURL == "" || cfg.DiscoveryClient == nil:
		return nil, errors.New("tunnels: dir, envoy path, and discovery are required")
	case cfg.MaxPipes <= 0:
		return nil, errors.New("tunnels: the pipe cap must be positive")
	case cfg.PerReplica <= 0 || cfg.PerReplica > 8:
		return nil, errors.New("tunnels: tunnels per replica must be between 1 and 8")
	case len(cfg.CertPEM) == 0 || len(cfg.KeyPEM) == 0 || len(cfg.CAPEM) == 0:
		return nil, errors.New("tunnels: client credentials and roots are required")
	}
	if cfg.ConnectTo != "" {
		if _, _, err := splitAddress(cfg.ConnectTo); err != nil {
			return nil, fmt.Errorf("tunnels: connect-to: %w", err)
		}
	}
	if cfg.DiscoveryInterval <= 0 {
		cfg.DiscoveryInterval = 15 * time.Second
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
	return &Manager{
		cfg: cfg,
		envoy: envoyConfig{
			identity:         cfg.Identity,
			dir:              cfg.Dir,
			coreHost:         host,
			corePort:         port,
			perWorker:        1,
			maxPipes:         cfg.MaxPipes,
			streamWindow:     cfg.StreamWindow,
			connectionWindow: cfg.ConnectionWindow,
		},
		admin: newAdmin(cfg.AdminPort),
		start: time.Now(),
	}, nil
}

// Run writes Envoy's configuration, supervises Envoy, and polls discovery
// until ctx is done. Envoy stops when Run returns, ending every tunnel, so
// cancel ctx only after open pipes have drained.
func (m *Manager) Run(ctx context.Context) error {
	if err := os.MkdirAll(m.cfg.Dir, 0o700); err != nil {
		return err
	}
	for name, data := range map[string][]byte{
		certFile: m.cfg.CertPEM, keyFile: m.cfg.KeyPEM, caFile: m.cfg.CAPEM,
	} {
		if err := writeFileAtomic(m.envoy.path(name), data, 0o600); err != nil {
			return err
		}
	}
	if err := m.envoy.writeBootstrap(); err != nil {
		return err
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		supervise(ctx, m.cfg.EnvoyPath, m.envoy.path(bootstrapFile), m.cfg.PerReplica, envoyOutput)
	}()
	m.discover(ctx)
	<-done
	return nil
}

// discover polls discovery until ctx is done. A failed poll keeps the last
// replica set: tunnels that are up stay up.
func (m *Manager) discover(ctx context.Context) {
	failing := false
	backoff := time.Second
	for {
		d, err := fetchDiscovery(ctx, m.cfg.DiscoveryClient, m.cfg.DiscoveryURL)
		wait := jitter(m.cfg.DiscoveryInterval)
		switch {
		case err != nil && ctx.Err() == nil:
			if !failing {
				slog.Warn("tunnel discovery failed; keeping the last replica set",
					"err", err)
			}
			failing = true
			if m.knownReplicas() == 0 {
				// Nothing to keep yet: retry sooner.
				wait, backoff = backoff, min(2*backoff, m.cfg.DiscoveryInterval)
			}
		case err == nil:
			if failing {
				slog.Info("tunnel discovery recovered")
			}
			failing, backoff = false, time.Second
			if applyErr := m.apply(d); applyErr != nil {
				slog.Error("could not apply the tunnel replica set", "err", applyErr)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		m.observe(ctx)
	}
}

// apply points Envoy at d's replicas. Clusters are written as the union of
// old and new first, then listeners; clusters no listener uses are pruned on
// a later poll. No listener ever names a cluster Envoy lacks.
func (m *Manager) apply(d Discovery) error {
	host, port, err := splitAddress(d.Address)
	if m.cfg.ConnectTo != "" {
		host, port, err = splitAddress(m.cfg.ConnectTo)
	}
	if err != nil {
		return err
	}
	next := make([]replica, 0, len(d.Replicas))
	for _, sni := range d.Replicas {
		next = append(next, replica{name: replicaName(sni), sni: sni, host: host, port: port})
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if slices.Equal(next, m.replicas) {
		if m.staleClusters {
			if err := m.envoy.writeClusters(next); err != nil {
				return err
			}
			m.staleClusters = false
		}
		return nil
	}
	union := slices.Clone(next)
	for _, r := range m.replicas {
		if !slices.ContainsFunc(next, func(n replica) bool { return n.name == r.name }) {
			union = append(union, r)
		}
	}
	if err := m.envoy.writeClusters(union); err != nil {
		return err
	}
	if err := m.envoy.writeListeners(next); err != nil {
		return err
	}
	m.staleClusters = len(union) > len(next)
	slog.Info("tunnel replica set changed",
		"cell", d.Cell, "replicas", len(next), "was", len(m.replicas))
	m.replicas, m.cell = next, d.Cell
	return nil
}

func (m *Manager) knownReplicas() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.replicas)
}

// observe records whether any tunnel has ever come up, for readiness.
func (m *Manager) observe(ctx context.Context) {
	if m.everConnected.Load() {
		return
	}
	counts, err := m.admin.tunnels(ctx)
	if err != nil {
		return
	}
	for _, n := range counts {
		if n > 0 {
			m.everConnected.Store(true)
			slog.Info("tunnels connected")
			return
		}
	}
}

// Status reports whether the connector should take pipes, and if not, why.
// A connector is ready when it holds a tunnel to every replica discovery
// named. Until a first tunnel has come up, it is also ready once ReadyGrace
// has passed, so a network that blocks tunnels never blocks the connector's
// legacy transport.
func (m *Manager) Status(ctx context.Context) (bool, string) {
	if m.draining.Load() {
		return false, "draining"
	}
	m.mu.Lock()
	want := make([]string, 0, len(m.replicas))
	for _, r := range m.replicas {
		want = append(want, r.name)
	}
	m.mu.Unlock()
	counts, err := m.admin.tunnels(ctx)
	if err == nil && len(want) > 0 {
		var missing []string
		for _, name := range want {
			if counts[name] == 0 {
				missing = append(missing, name)
			}
		}
		if len(missing) == 0 {
			m.everConnected.Store(true)
			return true, ""
		}
		if !m.everConnected.Load() && time.Since(m.start) > m.cfg.ReadyGrace {
			return true, "no tunnel has connected; serving the legacy transport only"
		}
		return false, fmt.Sprintf("no tunnel to %v", missing)
	}
	if !m.everConnected.Load() && time.Since(m.start) > m.cfg.ReadyGrace {
		return true, "no tunnel has connected; serving the legacy transport only"
	}
	if err != nil {
		return false, "envoy is not answering: " + err.Error()
	}
	return false, "waiting for tunnel discovery"
}

// Drain sends GOAWAY on every tunnel, so tunnel endpoints stop sending this
// connector new pipes and use another connector replica's tunnels. Pipes
// already open continue.
func (m *Manager) Drain(ctx context.Context) error {
	m.draining.Store(true)
	return m.admin.drainListeners(ctx)
}

func (c envoyConfig) writeClusters(replicas []replica) error {
	clusters := make([]any, 0, len(replicas))
	for _, r := range replicas {
		clusters = append(clusters, c.cluster(r))
	}
	return writeJSON(c.path(clustersFile), map[string]any{"resources": clusters})
}

func (c envoyConfig) writeListeners(replicas []replica) error {
	listeners := make([]any, 0, len(replicas))
	for _, r := range replicas {
		listeners = append(listeners, c.listener(r))
	}
	return writeJSON(c.path(listenersFile), map[string]any{"resources": listeners})
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

// jitter spreads polls ±20% around d, so a fleet does not poll in lockstep.
func jitter(d time.Duration) time.Duration {
	//nolint:gosec // Poll jitter is not used for secrets or authorization.
	return d*4/5 + time.Duration(rand.Int64N(int64(d)*2/5+1))
}
