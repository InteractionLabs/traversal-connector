// Package tunnels holds the connector's tunnels to Traversal.
//
// Each tunnel is one mutual-TLS connection the connector dials to the
// controller's host on 443 with ALPN x-traversal-tunnel; Traversal's edge
// router sends it to a tunnel gateway. Right after the handshake the
// connector names itself in one preface line, then serves HTTP/2 on the
// connection with the pipe server: the gateway is the client and opens one
// CONNECT stream per pipe. There is one TLS session per tunnel, and no
// process besides connector-core.
//
//	TRAVERSAL-TUNNEL/1 <connector-id>\n
//
// The gateway checks the line against the certificate's org; the
// capability on every pipe binds it to the connector.
//
// A gateway that is about to stop sends a TRAVERSAL-DRAIN request on the
// tunnel: the connector dials a replacement at once, and the old tunnel
// keeps serving its pipes until the gateway closes it.
package tunnels

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/metric"

	"github.com/InteractionLabs/traversal-connector/internal/telemetry"
)

// ALPN is the protocol tunnels offer, which the edge router routes on.
const ALPN = "x-traversal-tunnel"

// Preface starts every tunnel, before HTTP/2: Preface, a space, the
// connector ID and a newline.
const Preface = "TRAVERSAL-TUNNEL/1"

// DrainMethod is the request a draining gateway sends on a tunnel.
const DrainMethod = "TRAVERSAL-DRAIN"

// TunnelPort is the port the connector dials, unless ConnectTo replaces the
// address.
const TunnelPort = 443

// MaxTunnels bounds W.
const MaxTunnels = 8

// InstrumentationName is the OTel meter name for the tunnels.
const InstrumentationName = "traversal-connector/tunnels"

// Redial backoff for one tunnel slot.
const (
	minBackoff = 500 * time.Millisecond
	maxBackoff = 30 * time.Second
	// A tunnel up this long resets its slot's backoff.
	stableAfter = 30 * time.Second
	dialTimeout = 15 * time.Second
	// tcpKeepAlive probes a quiet tunnel's TCP connection; HTTP/2 pings
	// from the gateway find a dead peer sooner.
	tcpKeepAlive = 30 * time.Second
)

// Server serves pipes on one tunnel until it closes. drained is called if
// the gateway asks for a replacement tunnel. pipes.Server satisfies it.
type Server interface {
	ServeConn(nc net.Conn, drained func())
}

// Config configures a Manager.
type Config struct {
	Identity Identity
	// Endpoint is the controller's host: the SNI the connector sends and the
	// name the gateway's certificate must carry.
	Endpoint string
	// ConnectTo, if set, replaces Endpoint:443 as the address dialed
	// (host:port). SNI and certificate checks still use Endpoint.
	ConnectTo string
	// CertPEM and KeyPEM are the connector's client credentials; CAPEM is
	// every root that may sign the gateway's certificate.
	CertPEM, KeyPEM, CAPEM []byte
	// Tunnels is W, how many tunnels to hold.
	Tunnels int
	// Server serves pipes on each tunnel.
	Server Server
	// ReadyGrace is how long readiness waits for tunnels that are down. A
	// connector whose tunnels stay down longer becomes ready anyway, so raw
	// pipes cannot hold up the legacy transport. Zero means one minute.
	ReadyGrace time.Duration
	// MeterProvider records the tunnel metrics. Nil means the global one.
	MeterProvider metric.MeterProvider
}

// Manager holds the connector's tunnels and reports on them.
type Manager struct {
	cfg  Config
	tls  *tls.Config
	addr string
	up   atomic.Int64
	// downSince is when the tunnels last all went down, in Unix nanoseconds,
	// or zero while one is up. It starts at startup.
	downSince atomic.Int64
	draining  atomic.Bool

	mu    sync.Mutex
	conns map[net.Conn]struct{}
}

// New checks cfg and returns a Manager.
func New(cfg Config) (*Manager, error) {
	switch {
	case cfg.Identity.ConnectorID == "" || cfg.Identity.TenantID == "":
		return nil, errors.New("tunnels: a connector identity is required")
	case cfg.Endpoint == "":
		return nil, errors.New("tunnels: an endpoint is required")
	case cfg.Server == nil:
		return nil, errors.New("tunnels: a pipe server is required")
	case cfg.Tunnels <= 0 || cfg.Tunnels > MaxTunnels:
		return nil, fmt.Errorf("tunnels: the tunnel count must be between 1 and %d", MaxTunnels)
	case len(cfg.CertPEM) == 0 || len(cfg.KeyPEM) == 0 || len(cfg.CAPEM) == 0:
		return nil, errors.New("tunnels: client credentials and roots are required")
	}
	cert, err := tls.X509KeyPair(cfg.CertPEM, cfg.KeyPEM)
	if err != nil {
		return nil, fmt.Errorf("tunnels: client certificate: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(cfg.CAPEM) {
		return nil, errors.New("tunnels: no root certificates")
	}
	addr := net.JoinHostPort(cfg.Endpoint, strconv.Itoa(TunnelPort))
	if cfg.ConnectTo != "" {
		if _, _, err := net.SplitHostPort(cfg.ConnectTo); err != nil {
			return nil, fmt.Errorf("tunnels: connect-to: %w", err)
		}
		addr = cfg.ConnectTo
	}
	if cfg.ReadyGrace == 0 {
		cfg.ReadyGrace = time.Minute
	}
	m := &Manager{
		cfg:  cfg,
		addr: addr,
		tls: &tls.Config{
			MinVersion:   tls.VersionTLS13,
			ServerName:   cfg.Endpoint,
			Certificates: []tls.Certificate{cert},
			RootCAs:      roots,
			NextProtos:   []string{ALPN},
		},
		conns: map[net.Conn]struct{}{},
	}
	m.downSince.Store(time.Now().UnixNano())
	if err := m.registerMetrics(cfg.MeterProvider); err != nil {
		return nil, fmt.Errorf("tunnels: metrics: %w", err)
	}
	return m, nil
}

// Run holds the tunnels until ctx is done, then closes them, ending every
// pipe on them; cancel ctx only after open pipes have drained.
func (m *Manager) Run(ctx context.Context) error {
	var wg sync.WaitGroup
	for slot := range m.cfg.Tunnels {
		wg.Go(func() { m.hold(ctx, slot) })
	}
	<-ctx.Done()
	m.mu.Lock()
	for c := range m.conns {
		_ = c.Close()
	}
	m.mu.Unlock()
	wg.Wait()
	return nil
}

// hold keeps one tunnel up: dial, serve until it closes or the gateway asks
// for a replacement, back off, redial.
func (m *Manager) hold(ctx context.Context, slot int) {
	backoff := time.Duration(0)
	for ctx.Err() == nil {
		if m.draining.Load() {
			<-ctx.Done()
			return
		}
		began := time.Now()
		replaced, err := m.serveOne(ctx)
		if ctx.Err() != nil {
			return
		}
		if time.Since(began) >= stableAfter {
			backoff = 0
		}
		backoff = min(max(2*backoff, minBackoff), maxBackoff)
		// Full jitter, so a fleet whose tunnels dropped together doesn't
		// redial together.
		wait := rand.N(backoff) + minBackoff/2 //nolint:gosec // jitter, not security
		if replaced {
			backoff, wait = 0, rand.N(minBackoff) //nolint:gosec // jitter, not security
		}
		slog.InfoContext(ctx, "tunnel down; redialing",
			"slot", slot, "reason", err.Error(), "in", wait.Round(time.Millisecond))
		select {
		case <-time.After(wait):
		case <-ctx.Done():
		}
	}
}

// serveOne dials one tunnel and serves pipes on it. It returns when the
// tunnel closes, or with replaced set as soon as the gateway asks for a
// replacement; the old tunnel then keeps serving until the gateway closes it.
func (m *Manager) serveOne(ctx context.Context) (replaced bool, err error) {
	dctx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()
	d := &tls.Dialer{NetDialer: &net.Dialer{KeepAlive: tcpKeepAlive}, Config: m.tls}
	nc, err := d.DialContext(dctx, "tcp", m.addr)
	if err != nil {
		return false, fmt.Errorf("dial: %w", err)
	}
	tc, ok := nc.(*tls.Conn)
	if !ok || tc.ConnectionState().NegotiatedProtocol != ALPN {
		_ = nc.Close()
		return false, errors.New("the endpoint did not accept the tunnel protocol")
	}
	_ = tc.SetWriteDeadline(time.Now().Add(dialTimeout))
	if _, err := fmt.Fprintf(tc, "%s %s\n", Preface, m.cfg.Identity.ConnectorID); err != nil {
		_ = tc.Close()
		return false, fmt.Errorf("preface: %w", err)
	}
	_ = tc.SetWriteDeadline(time.Time{})
	m.track(tc, true)
	drained := make(chan struct{})
	closed := make(chan struct{})
	var once sync.Once
	go func() {
		defer close(closed)
		defer m.track(tc, false)
		m.cfg.Server.ServeConn(tc, func() { once.Do(func() { close(drained) }) })
	}()
	// Close the tunnel when ctx ends, whenever it was dialed: Run's close
	// sweep can run before a tunnel dialed concurrently is tracked.
	stop := context.AfterFunc(ctx, func() { _ = tc.Close() })
	select {
	case <-drained:
		// The tunnel outlives this call, so its close stays tied to ctx.
		return true, errors.New("the gateway asked for a replacement")
	case <-closed:
		stop()
		return false, errors.New("tunnel closed")
	}
}

func (m *Manager) track(nc net.Conn, add bool) {
	m.mu.Lock()
	if add {
		m.conns[nc] = struct{}{}
	} else {
		delete(m.conns, nc)
	}
	m.mu.Unlock()
	if add {
		if m.up.Add(1) == 1 {
			m.downSince.Store(0)
		}
		return
	}
	if m.up.Add(-1) == 0 {
		m.downSince.CompareAndSwap(0, time.Now().UnixNano())
	}
}

// TunnelsUp reports whether a tunnel is up, and if not, why.
func (m *Manager) TunnelsUp(context.Context) (bool, string) {
	if m.up.Load() > 0 {
		return true, ""
	}
	return false, "no tunnel to " + m.cfg.Endpoint
}

// Status reports whether the connector should take pipes, and if not, why.
//
// A connector is ready when it holds a tunnel, so a rollout waits for a new
// connector pod's tunnels. Tunnels down for longer than ReadyGrace, since
// startup or since they were last up, no longer hold it unready: a network
// that blocks tunnels or a broken gateway never blocks the legacy transport
// or stalls customer rollouts.
func (m *Manager) Status(ctx context.Context) (bool, string) {
	if m.draining.Load() {
		return false, "draining"
	}
	up, why := m.TunnelsUp(ctx)
	if up {
		return true, ""
	}
	if since := m.downSince.Load(); since != 0 &&
		time.Since(time.Unix(0, since)) > m.cfg.ReadyGrace {
		return true, fmt.Sprintf("%s for over %s; serving the legacy transport only",
			why, m.cfg.ReadyGrace)
	}
	return false, why
}

// Drain stops redialing. The pipe server's own drain refuses new pipes on
// the tunnels still up, so the gateway sends them to another connector
// replica; Run's context ending closes the tunnels.
func (m *Manager) Drain(context.Context) error {
	m.draining.Store(true)
	return nil
}

func (m *Manager) registerMetrics(provider metric.MeterProvider) error {
	if provider == nil {
		provider = otel.GetMeterProvider()
	}
	_, err := provider.Meter(InstrumentationName).Int64ObservableGauge(
		telemetry.MetricRawTunnelsActive,
		metric.WithDescription("Tunnels the connector holds to Traversal's tunnel gateway"),
		metric.WithInt64Callback(func(_ context.Context, o metric.Int64Observer) error {
			o.Observe(m.up.Load())
			return nil
		}),
	)
	return err
}
