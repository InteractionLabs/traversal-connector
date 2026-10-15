package pipeserver

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"sync/atomic"
	"time"

	"github.com/cenkalti/backoff/v5"

	"github.com/InteractionLabs/traversal-connector/connector-lib/rawpipe"
)

// Tunnels holds W tunnels to the controller host, serving pipes on each.
type Tunnels struct {
	ConnectorID string
	// Addr is dialed; TLS carries the client certificate, the roots, and the
	// controller host as ServerName.
	Addr   string
	TLS    *tls.Config
	Count  int
	Server *Server
	// Roots and Kids are the capability trust the connector has loaded,
	// reported in the preface: each root's rawpipe.RootFingerprint, and the
	// pinned keys' IDs.
	Roots, Kids []string

	up       atomic.Int64
	downAt   atomic.Int64 // when the last tunnel went down, Unix nanos
	everUp   atomic.Bool  // a tunnel has been up since start
	stopping atomic.Bool
}

// drainGrace is how long a stopping connector lets open pipes finish; it
// stays under the pod's 30 s termination grace period.
const drainGrace = 20 * time.Second

// Start holds the tunnels until ctx is done, then drains: no more redials,
// new pipes refused with connector_draining, open ones given drainGrace. The
// returned channel closes once the tunnels are closed.
func (t *Tunnels) Start(ctx context.Context) <-chan struct{} {
	// The tunnels outlive ctx so pipes already on their way are refused
	// rather than reset.
	transport, closeTunnels := context.WithCancel(context.WithoutCancel(ctx))
	done := make(chan struct{})
	// Before any goroutine: Ready reads it from the moment Start returns.
	t.downAt.Store(time.Now().UnixNano())
	for range t.Count {
		go t.hold(transport)
	}
	go func() {
		defer close(done)
		<-ctx.Done()
		t.stopping.Store(true)
		grace, cancel := context.WithTimeout(transport, drainGrace)
		t.Server.Drain(grace)
		cancel()
		closeTunnels()
	}()
	return done
}

// Ready reports whether the connector should take pipes. It holds a new
// connector unready until its first tunnel is up, for at most a minute after
// start, so a network that blocks tunnels never blocks the legacy transport.
// Later, tunnels flapping (a controller rollout, a lossy proxy) never make it
// unready: that shows in connector.raw_tunnels_up instead.
func (t *Tunnels) Ready(context.Context) (bool, string) {
	if t.up.Load() > 0 || t.everUp.Load() {
		return true, ""
	}
	if time.Since(time.Unix(0, t.downAt.Load())) > time.Minute {
		return true, "no tunnel; serving the legacy transport only"
	}
	return false, "no tunnel"
}

// redialBackoff spaces redials after a failed tunnel: 0.5-1 s, doubling to
// 15-30 s, uniformly jittered.
func redialBackoff() *backoff.ExponentialBackOff {
	return &backoff.ExponentialBackOff{InitialInterval: 750 * time.Millisecond,
		RandomizationFactor: 1.0 / 3, Multiplier: 2, MaxInterval: 22500 * time.Millisecond}
}

func (t *Tunnels) hold(ctx context.Context) {
	retry := redialBackoff()
	for ctx.Err() == nil && !t.stopping.Load() {
		start := time.Now()
		err := t.serveOne(ctx)
		if time.Since(start) > 30*time.Second {
			retry.Reset()
		}
		wait := retry.NextBackOff()
		if err == nil {
			wait = 0 // the edge controller asked for a replacement
		}
		slog.InfoContext(ctx, "tunnel down; redialing", "err", err, "in", wait)
		select {
		case <-time.After(wait):
		case <-ctx.Done():
		}
	}
	<-ctx.Done()
}

// serveOne dials one tunnel and serves it. It returns nil as soon as the
// edge controller asks for a replacement, leaving the old tunnel serving
// until the edge controller closes it, or the tunnel's error when it closes.
func (t *Tunnels) serveOne(ctx context.Context) error {
	dctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	c, err := (&tls.Dialer{Config: t.TLS}).DialContext(dctx, "tcp", t.Addr)
	if err != nil {
		t.Server.metrics.dialed("failed")
		return err
	}
	if c.(*tls.Conn).ConnectionState().NegotiatedProtocol != rawpipe.ALPN { //nolint:forcetypeassert,errcheck // tls.Dialer
		// Something between here and Traversal answered without the tunnel
		// ALPN: most often a TLS-intercepting proxy.
		t.Server.metrics.dialed("no_alpn")
		_ = c.Close()
		return fmt.Errorf("%s did not accept the tunnel protocol", t.Addr)
	}
	if err := rawpipe.WritePreface(c, t.ConnectorID, t.Roots, t.Kids); err != nil {
		_ = c.Close()
		return err
	}
	stop := context.AfterFunc(ctx, func() { _ = c.Close() })
	t.tracked(1)
	replaced := make(chan struct{})
	closed := make(chan struct{})
	go func() {
		defer close(closed)
		defer t.tracked(-1)
		t.Server.ServeConn(c, func() { close(replaced) })
	}()
	t.Server.metrics.dialed("connected")
	select {
	case <-replaced:
		t.Server.metrics.dialed("replaced")
		return nil
	case <-closed:
		stop()
		return net.ErrClosed
	}
}

func (t *Tunnels) tracked(delta int64) {
	t.Server.metrics.tunnelsUp.Add(context.Background(), delta)
	if delta > 0 {
		t.everUp.Store(true)
	}
	if t.up.Add(delta) == 0 {
		t.downAt.Store(time.Now().UnixNano())
	}
}
