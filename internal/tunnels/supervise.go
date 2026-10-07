package tunnels

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"syscall"
	"time"
)

// envoyStopGrace is how long Envoy may take to exit after SIGTERM.
const envoyStopGrace = 10 * time.Second

// envoyDrainTime is Envoy's drain period (--drain-time-s). With the immediate
// drain strategy every tunnel gets GOAWAY as soon as Drain starts; the drain
// time is then only how long Envoy keeps its listeners before closing them.
// It outlasts connector-core's drain (a 2 s settle, then up to 20 s for open
// pipes) so the tunnel listener stays up while pipes finish, and ends inside
// the pod's 30 s termination grace.
const envoyDrainTime = 25 * time.Second

// envoyArgs is Envoy's command line for bootstrap and the worker count.
func envoyArgs(bootstrap string, workers int) []string {
	return []string{
		"--config-path", bootstrap,
		"--log-level", "warn",
		// Each worker dials its own tunnel.
		"--concurrency", strconv.Itoa(workers),
		// Envoy's own hot-restart shared memory is not needed: core
		// restarts it, and two connectors may share a host network.
		"--disable-hot-restart",
		// GOAWAY on every tunnel at once when draining. Envoy's default,
		// gradual over 600 s, would keep most tunnels taking new pipes
		// long after core starts refusing them as CONNECTOR_DRAINING.
		"--drain-strategy", "immediate",
		"--drain-time-s", strconv.Itoa(int(envoyDrainTime / time.Second)),
	}
}

// supervise runs Envoy with bootstrap and the given worker count until ctx is done,
// restarting it with backoff whenever it exits. On shutdown Envoy gets
// SIGTERM.
func supervise(ctx context.Context, envoyPath, bootstrap string, workers int, out io.Writer) {
	backoff := 500 * time.Millisecond
	for {
		// #nosec G204 -- The Envoy path is operator configuration, not input.
		cmd := exec.CommandContext(ctx, envoyPath, envoyArgs(bootstrap, workers)...)
		cmd.Stdout, cmd.Stderr = out, out
		cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
		cmd.WaitDelay = envoyStopGrace
		started := time.Now()
		err := cmd.Run()
		if ctx.Err() != nil {
			return
		}
		if time.Since(started) > time.Minute {
			backoff = 500 * time.Millisecond
		}
		slog.Warn("envoy exited; restarting", "err", err, "after", backoff)
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = min(2*backoff, 10*time.Second)
	}
}

// admin talks to the supervised Envoy's admin listener.
type admin struct {
	base   string
	client *http.Client
}

func newAdmin(port int) admin {
	return admin{
		base:   "http://" + adminAddress + ":" + strconv.Itoa(port),
		client: &http.Client{Timeout: 2 * time.Second},
	}
}

// drainListeners starts Envoy's graceful drain: its HTTP/2 connections, the
// reverse tunnels included, get GOAWAY at once (see envoyArgs) while open
// streams continue.
func (a admin) drainListeners(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		a.base+"/drain_listeners?graceful&skip_exit", nil)
	if err != nil {
		return err
	}
	resp, err := a.client.Do(req) //nolint:gosec // loopback Envoy admin
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("drain_listeners: %s", resp.Status)
	}
	return nil
}

// connectedStat is the per-worker, per-cluster tunnel gauge Envoy keeps with
// enable_detailed_stats.
var connectedStat = regexp.MustCompile(
	`^downstream_reverse_connection\.worker_\d+\.cluster\.([^.]+)\.connected: (\d+)$`)

// tunnels returns how many tunnels Envoy holds to the tunnel endpoint.
func (a admin) tunnels(ctx context.Context) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		a.base+"/stats?filter=^downstream_reverse_connection", nil)
	if err != nil {
		return 0, err
	}
	resp, err := a.client.Do(req) //nolint:gosec // loopback Envoy admin
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("stats: %s", resp.Status)
	}
	total := 0
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		if m := connectedStat.FindStringSubmatch(sc.Text()); m != nil && m[1] == tunnelCluster {
			n, _ := strconv.Atoi(m[2])
			total += n
		}
	}
	return total, sc.Err()
}

// envoyOutput is where Envoy's own logs go: the connector's stdout, beside
// core's structured lines.
var envoyOutput io.Writer = os.Stdout
