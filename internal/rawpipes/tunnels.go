package rawpipes

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net"
	"sync"
	"sync/atomic"
	"time"

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

	up       atomic.Int64
	downAt   atomic.Int64 // when the last tunnel went down, Unix nanos
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
	go t.run(transport)
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

func (t *Tunnels) run(ctx context.Context) {
	t.downAt.Store(time.Now().UnixNano())
	var wg sync.WaitGroup
	for range t.Count {
		wg.Go(func() { t.hold(ctx) })
	}
	wg.Wait()
}

// Ready reports whether the connector should take pipes. Tunnels down for
// over a minute stop holding it unready, so a network that blocks them never
// blocks the legacy transport.
func (t *Tunnels) Ready(context.Context) (bool, string) {
	if t.up.Load() > 0 {
		return true, ""
	}
	if time.Since(time.Unix(0, t.downAt.Load())) > time.Minute {
		return true, "no tunnel; serving the legacy transport only"
	}
	return false, "no tunnel"
}

func (t *Tunnels) hold(ctx context.Context) {
	backoff := time.Second
	for ctx.Err() == nil && !t.stopping.Load() {
		start := time.Now()
		err := t.serveOne(ctx)
		if time.Since(start) > 30*time.Second {
			backoff = time.Second
		}
		wait := backoff/2 + rand.N(backoff/2) //nolint:gosec // jitter
		if err == nil {
			wait = 0 // the gateway asked for a replacement
		}
		slog.InfoContext(ctx, "tunnel down; redialing", "err", err, "in", wait)
		select {
		case <-time.After(wait):
		case <-ctx.Done():
		}
		backoff = min(2*backoff, 30*time.Second)
	}
	<-ctx.Done()
}

// serveOne dials one tunnel and serves it. It returns nil as soon as the
// gateway asks for a replacement, leaving the old tunnel serving until the
// gateway closes it, or the tunnel's error when it closes.
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
	if _, err := fmt.Fprintf(c, "%s %s\n", rawpipe.Preface, t.ConnectorID); err != nil {
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
	t.Server.metrics.tunnel(delta)
	if t.up.Add(delta) == 0 {
		t.downAt.Store(time.Now().UnixNano())
	}
}
