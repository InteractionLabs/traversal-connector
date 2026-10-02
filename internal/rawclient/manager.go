package rawclient

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/InteractionLabs/traversal-connector/connector-lib/dialpolicy"
	pb "github.com/InteractionLabs/traversal-connector/connector-lib/gen/connector/v1"
	connectorconnect "github.com/InteractionLabs/traversal-connector/connector-lib/gen/connector/v1/connectorconnect"
	"github.com/InteractionLabs/traversal-connector/connector-lib/rawtunnel"
	"github.com/InteractionLabs/traversal-connector/internal/client"
	"github.com/InteractionLabs/traversal-connector/internal/config"
	"github.com/InteractionLabs/traversal-connector/internal/redact"
)

var (
	errShutdown        = errors.New("raw tunnels are shutting down")
	errSessionCapacity = errors.New("raw tunnel session capacity reached")
)

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
	opener  *opener
	metrics *rawMetrics
	hello   connectorHello
	// redactor's rules can hot-reload, so each new tunnel's hello reads them.
	redactor    *redact.Redactor
	blocksPipes atomic.Bool
	// backoff is copied into each slot. Slots do not share its counter, so one
	// raw tunnel's failures cannot delay the others or the legacy tunnels.
	backoff backoff
	log     *slog.Logger

	mu           sync.Mutex
	sessions     []*session
	active       int
	connecting   int
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
		cfg:      cfg,
		enabled:  cfg.RawTunnel.Enabled,
		newRPC:   factory,
		metrics:  metrics,
		hello:    helloFrom(cfg),
		redactor: redactor,
		backoff:  newBackoff(),
		log:      logger,
		started:  make(chan struct{}),
	}
	if !cfg.RawTunnel.Enabled {
		return m, nil
	}
	opener, err := newOpener(
		cfg, redactor, policy, metrics, logger, m.hello.hostname, m.isShutdown,
	)
	if err != nil {
		return nil, err
	}
	m.opener = opener
	m.currentHello()
	return m, nil
}

// currentHello is the hello for a tunnel opening now. The controller learns
// about a rules reload when the connector next opens a tunnel.
func (m *Manager) currentHello() *pb.RawConnectorHello {
	hello := m.hello
	hello.redactionBlocksPipes = m.redactor.HasUnscopedRule()
	if m.blocksPipes.Swap(hello.redactionBlocksPipes) != hello.redactionBlocksPipes &&
		hello.redactionBlocksPipes {
		m.log.Warn(
			"redaction rule has no host filter; raw pipes are refused for every destination",
		)
	}
	return hello.message()
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
	go m.watch(sess, next)
	select {
	case <-next:
		// This goroutine waits out pipes already on the draining tunnel. The
		// replacement is a separate slot, so the active-tunnel limit stays put.
		_ = m.spawnSlot(ctx)
		<-sess.runDone
		m.finish(sess)
		return false
	case <-sess.runDone:
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

// retireDraining closes a drained tunnel once it has no pipes left, or when
// RotationDeadline elapses. Shutdown does not wait on this timer: it closes
// the tunnel after ShutdownGrace, and that close wakes Done. A rotation that
// still has pipes is not a pod shutdown, so the close reason is
// rotation_deadline rather than connector_terminating.
func (m *Manager) retireDraining(sess *session) {
	timer := time.NewTimer(m.cfg.RawTunnel.RotationDeadline)
	defer timer.Stop()
	select {
	case <-sess.mux.Drained():
	case <-timer.C:
	case <-sess.mux.Done():
		return
	}
	// Shutdown drains too. A pod that is already exiting must report
	// connector_terminating even when this rotation timer fires first.
	reason := pb.RawCloseReason_RAW_CLOSE_REASON_ROTATION_DEADLINE
	if m.isShutdown() {
		reason = pb.RawCloseReason_RAW_CLOSE_REASON_CONNECTOR_TERMINATING
	}
	sess.mux.Close(reason)
}

func (m *Manager) openSession(ctx context.Context) (*session, error) {
	if err := m.reserveSession(); err != nil {
		return nil, err
	}
	reserved := true
	defer func() {
		if reserved {
			m.releaseConnecting()
		}
	}()
	rpc, cleanup, err := m.newRPC()
	if err != nil {
		return nil, err
	}
	sessCtx, cancel := context.WithCancel(ctx)
	stream := rpc.RawTunnel(sessCtx)
	stop := sync.OnceFunc(func() { closeClient(cleanup) })
	opener := m.opener
	var mux *rawtunnel.Mux
	mux, err = rawtunnel.New(rawtunnel.Config{
		Role:          rawtunnel.RoleConnector,
		MaxPipes:      m.cfg.RawTunnel.MaxPipesPerTunnel,
		StreamWindow:  m.cfg.RawTunnel.StreamWindow,
		IdleTimeout:   m.cfg.RawTunnel.IdleTimeout,
		MaxLifetime:   m.cfg.RawTunnel.MaxLifetime,
		PingInterval:  m.cfg.RawTunnel.PingInterval,
		Hello:         m.currentHello(),
		OnControlDrop: m.metrics.controlDrop,
		OnReset:       m.metrics.reset,
		Abort: func() {
			cancel()
			stop()
		},
		Accept: func(p *rawtunnel.Pipe, open *pb.RawOpen) {
			opener.accept(mux.TunnelID(), p, open)
		},
	}, rawtunnel.FromChunks(stream))
	if err != nil {
		cancel()
		stop()
		return nil, err
	}
	runDone := make(chan struct{})
	go func() {
		_ = mux.Run(sessCtx)
		close(runDone)
	}()
	select {
	case <-mux.Established():
	case <-mux.Done():
		<-runDone
		cancel()
		stop()
		if err := mux.Err(); err != nil {
			return nil, err
		}
		return nil, errors.New("raw tunnel closed before hello")
	case <-ctx.Done():
		cancel()
		stop()
		<-runDone
		return nil, ctx.Err()
	}
	sess := &session{mux: mux, ctx: sessCtx, cleanup: stop, runDone: runDone}
	m.mu.Lock()
	if m.shuttingDown {
		m.mu.Unlock()
		cancel()
		stop()
		return nil, errShutdown
	}
	m.sessions = append(m.sessions, sess)
	m.connecting--
	m.active++
	reserved = false
	m.mu.Unlock()
	m.metrics.addActive(1)
	m.log.Info("raw tunnel established", "tunnel_id", mux.TunnelID())
	return sess, nil
}

// reserveSession claims one connecting slot. Draining tunnels do not count:
// one closes as soon as its last pipe ends, and its pipes count against
// MaxPipesPerPod, so pipes already bound how many drain and what they buffer.
// Counting them here would let long pipes on every tunnel block replacements.
func (m *Manager) reserveSession() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.shuttingDown {
		return errShutdown
	}
	if m.active+m.connecting >= m.cfg.RawTunnel.MaxTunnels {
		return errSessionCapacity
	}
	m.connecting++
	return nil
}

func (m *Manager) releaseConnecting() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.connecting > 0 {
		m.connecting--
	}
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
	go m.retireDraining(sess)
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

// Shutdown stops admitting pipes, waits the grace period, then closes whatever
// is still open with connector_terminating. When raw tunnels are disabled it
// returns immediately, so process exit timing is unchanged. It is safe to call
// more than once; the second call waits for the first.
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
	sessions := append([]*session(nil), m.sessions...)
	cancel := m.cancel
	grace := m.cfg.RawTunnel.ShutdownGrace
	opener := m.opener
	m.mu.Unlock()
	if opener != nil {
		opener.mu.Lock()
		opener.stop = true
		opener.mu.Unlock()
	}
	for _, sess := range sessions {
		sess.mux.Drain(pb.RawDrainReason_RAW_DRAIN_REASON_SHUTDOWN)
	}
	m.waitGrace(sessions, grace)
	m.mu.Lock()
	sessions = append([]*session(nil), m.sessions...)
	m.mu.Unlock()
	// Close waits out a short flush, then returns. If it does not, the peer
	// has stopped reading and the TCP connection has to be cancelled anyway:
	// waiting here spends the rest of the pod's termination grace.
	closed := make(chan struct{})
	go func() {
		for _, sess := range sessions {
			sess.mux.Close(pb.RawCloseReason_RAW_CLOSE_REASON_CONNECTOR_TERMINATING)
		}
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(closeAttemptTimeout):
		if cancel != nil {
			cancel()
		}
	}
	m.waitDone(sessions, closeFlushTimeout)
	if cancel != nil {
		cancel()
	}
	m.wg.Wait()
	if opener != nil {
		opener.live.Wait()
	}
}

const closeFlushTimeout = time.Second

// closeAttemptTimeout covers Close's own flush waits. Past this, cancel the
// call instead of blocking process exit.
const closeAttemptTimeout = 5 * time.Second

func (m *Manager) waitDone(sessions []*session, limit time.Duration) {
	deadline := time.NewTimer(limit)
	defer deadline.Stop()
	for _, sess := range sessions {
		select {
		case <-sess.mux.Done():
		case <-deadline.C:
			return
		}
	}
}

func (m *Manager) waitGrace(sessions []*session, grace time.Duration) {
	deadline := time.NewTimer(grace)
	defer deadline.Stop()
	for _, sess := range sessions {
		select {
		case <-sess.mux.Drained():
		case <-sess.mux.Done():
		case <-deadline.C:
			return
		}
	}
}

func (m *Manager) isShutdown() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.shuttingDown
}
