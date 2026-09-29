package rawclient

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/InteractionLabs/traversal-connector/connector-lib/dialpolicy"
	pb "github.com/InteractionLabs/traversal-connector/connector-lib/gen/connector/v1"
	connectorconnect "github.com/InteractionLabs/traversal-connector/connector-lib/gen/connector/v1/connectorconnect"
	"github.com/InteractionLabs/traversal-connector/connector-lib/rawtunnel"
	"github.com/InteractionLabs/traversal-connector/internal/client"
	"github.com/InteractionLabs/traversal-connector/internal/config"
	"github.com/InteractionLabs/traversal-connector/internal/redact"
)

var errShutdown = errors.New("raw tunnels are shutting down")

// clientFactory opens one HTTP/2 client that shares no connection with any
// other client. Tests replace it; production uses client.NewIsolatedClient.
type clientFactory func() (connectorconnect.ConnectorServiceClient, func(), error)

// Manager owns the raw tunnels for one connector process. It does not touch
// the legacy tunnel manager: separate connections, a separate backoff, and a
// shutdown that can outlive the legacy slots.
type Manager struct {
	cfg     *config.Config
	enabled bool
	newRPC  clientFactory
	metrics *rawMetrics
	hello   connectorHello
	backoff backoff
	log     *slog.Logger

	mu           sync.Mutex
	sessions     []*session
	active       int
	draining     int
	shuttingDown bool
	cancel       context.CancelFunc

	started      chan struct{}
	wg           sync.WaitGroup
	shutdownOnce sync.Once
}

// New builds a manager. When raw tunnels are disabled it does not dial and
// does not change process exit timing.
func New(cfg *config.Config, redactor *redact.Redactor) (*Manager, error) {
	return newManager(cfg, redactor, func() (
		connectorconnect.ConnectorServiceClient, func(), error,
	) {
		return client.NewIsolatedClient(cfg)
	}, slog.Default(), nil)
}

func newManager(
	cfg *config.Config,
	redactor *redact.Redactor,
	factory clientFactory,
	logger *slog.Logger,
	policy *dialpolicy.Policy,
) (*Manager, error) {
	metrics, err := newRawMetrics()
	if err != nil {
		return nil, err
	}
	if logger == nil {
		logger = slog.Default()
	}
	m := &Manager{
		cfg:     cfg,
		enabled: cfg.RawTunnel.Enabled,
		newRPC:  factory,
		metrics: metrics,
		hello:   helloFrom(cfg),
		backoff: newBackoff(),
		log:     logger,
		started: make(chan struct{}),
	}
	// Pipe relay arrives with the opener. Until then an open is refused, so a
	// controller cannot hang waiting for Start, and this process never dials.
	_, _ = redactor, policy
	return m, nil
}

// Start launches the raw tunnels and returns once they are running, or
// immediately when the feature is disabled. Shutdown waits for Start.
func (m *Manager) Start() {
	go m.run()
	<-m.started
}

func (m *Manager) run() {
	ctx, cancel := context.WithCancel(context.Background())
	m.mu.Lock()
	m.cancel = cancel
	n := m.cfg.RawTunnel.MaxTunnels
	early := m.shuttingDown || !m.enabled
	if !early {
		m.wg.Add(n)
	}
	m.mu.Unlock()
	close(m.started)
	if early {
		return
	}
	for range n {
		go m.runSlot(ctx)
	}
}

func (m *Manager) runSlot(ctx context.Context) {
	defer m.wg.Done()
	// Each slot backs off on its own. A shared delay would let one raw tunnel's
	// failures stall the other, and neither delay is the legacy tunnel's.
	bo := newBackoff()
	bo.initial = m.backoff.initial
	bo.max = m.backoff.max
	for {
		if ctx.Err() != nil || m.isShutdown() {
			return
		}
		opened := time.Now()
		sess, err := m.openSession(ctx)
		if err != nil {
			if ctx.Err() != nil || m.isShutdown() || errors.Is(err, errShutdown) {
				return
			}
			m.metrics.reconnect()
			delay := bo.next()
			m.log.Warn("raw tunnel failed to open", "error", err, "delay", delay)
			if !sleep(ctx, delay) {
				return
			}
			continue
		}
		if !m.serve(ctx, sess, opened, &bo) {
			return
		}
	}
}

// serve runs one tunnel. It returns false when this slot goroutine should
// stop. A rotation starts a replacement slot and lets this one wait out the
// pipes already on the draining tunnel.
func (m *Manager) serve(
	ctx context.Context, sess *session, opened time.Time, bo *backoff,
) bool {
	next := make(chan struct{})
	runDone := make(chan struct{})
	go func() {
		_ = sess.mux.Run(sess.ctx)
		close(runDone)
	}()
	go m.watch(sess, next)
	select {
	case <-next:
		if !m.spawnSlot(ctx) {
			<-runDone
			m.finish(sess)
			return false
		}
		<-runDone
		m.finish(sess)
		return false
	case <-runDone:
		// Drain and tunnel-end can become ready together when the controller
		// closes an idle tunnel as soon as it drains. Observe the drain here
		// so that race still opens a replacement instead of backing off.
		select {
		case <-sess.mux.Draining():
			m.markDraining(sess)
		default:
		}
		replace := m.finish(sess)
		if ctx.Err() != nil || m.isShutdown() {
			return false
		}
		if replace {
			return true
		}
		if time.Since(opened) >= backoffResetAfter {
			bo.reset()
		}
		m.metrics.reconnect()
		return sleep(ctx, bo.next())
	}
}

// spawnSlot starts a replacement tunnel. The Add happens under the same lock
// Shutdown uses to stop new work, so Wait cannot miss the goroutine.
func (m *Manager) spawnSlot(ctx context.Context) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.shuttingDown {
		return false
	}
	m.wg.Add(1)
	go m.runSlot(ctx)
	return true
}

func (m *Manager) watch(sess *session, next chan struct{}) {
	select {
	case <-sess.mux.Draining():
		if m.markDraining(sess) {
			close(next)
		}
	case <-sess.mux.Done():
	}
}

func (m *Manager) openSession(ctx context.Context) (*session, error) {
	if m.isShutdown() {
		return nil, errShutdown
	}
	rpc, cleanup, err := m.newRPC()
	if err != nil {
		return nil, err
	}
	sessCtx, cancel := context.WithCancel(ctx)
	stream := rpc.RawTunnel(sessCtx)
	tunnelID, err := exchangeHello(stream, m.hello)
	if err != nil {
		cancel()
		closeClient(cleanup)
		return nil, err
	}
	mux, err := rawtunnel.New(rawtunnel.Config{
		Role:         rawtunnel.RoleConnector,
		MaxPipes:     m.cfg.RawTunnel.MaxPipesPerTunnel,
		IdleTimeout:  m.cfg.RawTunnel.IdleTimeout,
		MaxLifetime:  m.cfg.RawTunnel.MaxLifetime,
		PingInterval: m.cfg.RawTunnel.PingInterval,
		OnSendStall:  m.metrics.stall,
		Abort: func() {
			cancel()
			closeClient(cleanup)
		},
		Accept: func(p *rawtunnel.Pipe, _ *pb.RawOpen) {
			_ = p.Refuse(
				pb.RawOpenFailureReason_RAW_OPEN_FAILURE_REASON_CONNECTOR_DRAINING,
				"connector draining",
			)
		},
	}, stream)
	if err != nil {
		cancel()
		closeClient(cleanup)
		return nil, err
	}
	sess := &session{
		mux: mux, tunnelID: tunnelID, ctx: sessCtx, cleanup: cleanup,
	}
	m.mu.Lock()
	if m.shuttingDown {
		m.mu.Unlock()
		cancel()
		closeClient(cleanup)
		return nil, errShutdown
	}
	m.sessions = append(m.sessions, sess)
	m.active++
	m.mu.Unlock()
	m.metrics.addActive(1)
	m.log.Info("raw tunnel established", "tunnel_id", tunnelID)
	return sess, nil
}

func (m *Manager) markDraining(sess *session) bool {
	m.mu.Lock()
	if sess.state != sessionActive {
		m.mu.Unlock()
		return false
	}
	sess.state = sessionDraining
	sess.replace = !m.shuttingDown
	m.active--
	m.draining++
	replace := sess.replace
	m.mu.Unlock()
	m.metrics.addActive(-1)
	m.metrics.addDraining(1)
	reason := pb.RawDrainReason_RAW_DRAIN_REASON_ROTATION
	if !replace {
		reason = pb.RawDrainReason_RAW_DRAIN_REASON_SHUTDOWN
	}
	m.metrics.drain(reason)
	return replace
}

// finish drops the session from the live set. It returns whether the slot
// should open a replacement without backing off.
func (m *Manager) finish(sess *session) bool {
	m.mu.Lock()
	replace := sess.replace && !m.shuttingDown
	if sess.state == sessionFinished {
		m.mu.Unlock()
		return replace
	}
	switch sess.state {
	case sessionActive:
		m.active--
	case sessionDraining:
		m.draining--
	}
	wasDraining := sess.state == sessionDraining
	sess.state = sessionFinished
	m.removeLocked(sess)
	cleanup := sess.cleanup
	m.mu.Unlock()
	if wasDraining {
		m.metrics.addDraining(-1)
	} else {
		m.metrics.addActive(-1)
	}
	closeClient(cleanup)
	return replace
}

func closeClient(cleanup func()) {
	if cleanup != nil {
		cleanup()
	}
}

func (m *Manager) removeLocked(sess *session) {
	for i, cur := range m.sessions {
		if cur == sess {
			m.sessions[i] = m.sessions[len(m.sessions)-1]
			m.sessions = m.sessions[:len(m.sessions)-1]
			return
		}
	}
}

// Shutdown stops the raw tunnels. When they are disabled it returns
// immediately, so process exit timing is unchanged. It is safe to call more
// than once; the second call waits for the first.
func (m *Manager) Shutdown() {
	m.shutdownOnce.Do(m.shutdown)
}

func (m *Manager) shutdown() {
	<-m.started
	if !m.enabled {
		return
	}
	m.mu.Lock()
	m.shuttingDown = true
	cancel := m.cancel
	m.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	m.wg.Wait()
}

func (m *Manager) isShutdown() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.shuttingDown
}
