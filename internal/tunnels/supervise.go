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

// supervise runs Envoy with bootstrap and the given worker count until ctx is done,
// restarting it with backoff whenever it exits. On shutdown Envoy gets
// SIGTERM.
func supervise(ctx context.Context, envoyPath, bootstrap string, workers int, out io.Writer) {
	backoff := 500 * time.Millisecond
	for {
		// #nosec G204 -- The Envoy path is operator configuration, not input.
		cmd := exec.CommandContext(ctx, envoyPath,
			"--config-path", bootstrap,
			"--log-level", "warn",
			// Each worker dials its own tunnels to every replica.
			"--concurrency", strconv.Itoa(workers),
			// Envoy's own hot-restart shared memory is not needed: core
			// restarts it, and two connectors may share a host network.
			"--disable-hot-restart",
		)
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
// reverse tunnels included, get GOAWAY while open streams continue.
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

// connectedStat is the per-worker, per-replica tunnel gauge Envoy keeps with
// enable_detailed_stats.
var connectedStat = regexp.MustCompile(
	`^downstream_reverse_connection\.worker_\d+\.cluster\.([^.]+)\.connected: (\d+)$`)

// tunnels returns how many tunnels Envoy holds to each replica it has a
// tunnel gauge for.
func (a admin) tunnels(ctx context.Context) (map[string]int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		a.base+"/stats?filter=^downstream_reverse_connection", nil)
	if err != nil {
		return nil, err
	}
	resp, err := a.client.Do(req) //nolint:gosec // loopback Envoy admin
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("stats: %s", resp.Status)
	}
	perReplica := map[string]int{}
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		if m := connectedStat.FindStringSubmatch(sc.Text()); m != nil {
			n, _ := strconv.Atoi(m[2])
			perReplica[m[1]] += n
		}
	}
	return perReplica, sc.Err()
}

// envoyOutput is where Envoy's own logs go: the connector's stdout, beside
// core's structured lines.
var envoyOutput io.Writer = os.Stdout
