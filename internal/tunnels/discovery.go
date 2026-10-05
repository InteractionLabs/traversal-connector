package tunnels

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"slices"
	"strconv"
)

// Discovery is the set of tunnel endpoint replicas a connector should hold
// tunnels to, as Traversal publishes it.
type Discovery struct {
	// Cell is the group of replicas serving this connector. It is always
	// "0" until Traversal shards connectors into cells.
	Cell string `json:"cell"`
	// Address is the shared tunnels entry point, host:port. Every replica is
	// reached through it, by SNI.
	Address string `json:"address"`
	// Replicas are the SNI names of the warm replicas, such as
	// "t-envoy-3.tunnels.traversal.com".
	Replicas []string `json:"replicas"`
}

// maxReplicas bounds how many replicas one connector dials, so a bad
// discovery answer cannot make it open unbounded tunnels.
const maxReplicas = 64

// maxDiscoveryBytes bounds the discovery response.
const maxDiscoveryBytes = 64 << 10

var dnsName = regexp.MustCompile(
	`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)

func (d Discovery) validate() error {
	host, port, err := net.SplitHostPort(d.Address)
	if err != nil || !dnsName.MatchString(host) {
		return fmt.Errorf("invalid tunnels address %q", d.Address)
	}
	if n, err := strconv.Atoi(port); err != nil || n <= 0 || n > 65535 {
		return fmt.Errorf("invalid tunnels port %q", port)
	}
	if len(d.Replicas) > maxReplicas {
		return fmt.Errorf("%d replicas is more than %d", len(d.Replicas), maxReplicas)
	}
	names := map[string]bool{}
	for _, sni := range d.Replicas {
		if !dnsName.MatchString(sni) || len(sni) > 253 {
			return fmt.Errorf("invalid replica name %q", sni)
		}
		name := replicaName(sni)
		if name == "core" || names[name] {
			return fmt.Errorf("replica name %q is reserved or repeated", name)
		}
		names[name] = true
	}
	return nil
}

// fetchDiscovery asks Traversal which replicas to hold tunnels to.
func fetchDiscovery(ctx context.Context, client *http.Client, url string) (Discovery, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return Discovery{}, err
	}
	req.Header.Set("Accept", "application/json")
	// #nosec G704 -- The controller origin from config; redirects are disabled.
	resp, err := client.Do(req)
	if err != nil {
		return Discovery{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return Discovery{}, fmt.Errorf("tunnel discovery: %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDiscoveryBytes+1))
	if err != nil {
		return Discovery{}, err
	}
	if len(body) > maxDiscoveryBytes {
		return Discovery{}, errors.New("tunnel discovery: response too large")
	}
	var d Discovery
	if err := json.Unmarshal(body, &d); err != nil {
		return Discovery{}, fmt.Errorf("tunnel discovery: %w", err)
	}
	if err := d.validate(); err != nil {
		return Discovery{}, fmt.Errorf("tunnel discovery: %w", err)
	}
	slices.Sort(d.Replicas)
	return d, nil
}
