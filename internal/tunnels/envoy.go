package tunnels

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// The connector's Envoy (the C-Envoy) dials reverse tunnels to Traversal's
// tunnel endpoint and forwards each pipe that arrives through them,
// unchanged, to connector-core on loopback.
//
// Its configuration is static: one listener (the tunnels, one per worker),
// one cluster (how to reach the tunnel endpoint), and one cluster for core.

// HTTP/2 windows for pipes.
//
// A pipe moves at most one stream window per round trip, and a stalled pipe
// (its reader stopped) holds up to one stream window at each hop. So stream
// windows are sized to the hop: the tunnel crosses the internet to Traversal,
// the hop to core is loopback. Connection windows are as large as HTTP/2
// allows a sane value to be, because every stalled pipe also holds its stream
// window of the connection window: a small one lets a few stalled pipes freeze
// every pipe on the tunnel. In kind with 50 ms added, a 2 MiB stream window
// carried a pipe at ~33 MiB/s where 256 KiB managed 2.4.
const (
	DefaultStreamWindow     = 2 << 20
	DefaultConnectionWindow = 1 << 30
	coreStreamWindow        = 256 << 10
	coreConnectionWindow    = 1 << 30
)

// adminAddress is the Envoy admin listener. Loopback only: nothing outside
// the pod reaches it, and the dial policy refuses loopback, so no pipe
// reaches it either.
const adminAddress = "127.0.0.1"

// AdminPort is the Envoy admin port.
const AdminPort = 9901

// files Envoy reads from the run directory.
const (
	bootstrapFile = "envoy.json"
	certFile      = "tls.crt"
	keyFile       = "tls.key"
	caFile        = "ca.crt"
)

// envoyConfig is what the C-Envoy needs to know about this connector.
type envoyConfig struct {
	identity Identity
	// dir holds the bootstrap, resource and credential files.
	dir string
	// coreAddr is connector-core's pipe listener, host:port.
	coreHost string
	corePort int
	// endpoint is the tunnel endpoint.
	endpoint endpoint
	// maxPipes is core's pipe cap.
	maxPipes int64
	// streamWindow and connectionWindow are the HTTP/2 windows, in bytes.
	streamWindow, connectionWindow int
	// innerTLS is whether the tunnels' data leg runs its own TLS.
	innerTLS InnerTLS
}

// endpoint is the Traversal tunnel endpoint the connector holds tunnels to.
type endpoint struct {
	// sni is the name the connector sends and verifies: the controller's
	// host, such as "edge.traversal.com".
	sni string
	// host and port are where the connector connects: sni:443, unless
	// ConnectTo replaced them.
	host string
	port int
}

// tunnelCluster names the tunnel endpoint's cluster, and tunnelListener the
// listener that holds the tunnels.
const (
	tunnelCluster  = "tunnels"
	tunnelListener = "tunnels"
)

// tunnelsPerWorker is how many tunnels each Envoy worker holds. Every worker
// dials its own, so the connector holds workers × tunnelsPerWorker.
const tunnelsPerWorker = 1

// tunnelALPN is the ALPN protocol that tells Traversal's front door a
// connection is a tunnel, not a request for the controller. h2 follows it,
// the protocol the tunnel endpoint actually negotiates.
const tunnelALPN = "x-traversal-tunnel"

func (c envoyConfig) path(name string) string { return filepath.Join(c.dir, name) }

// bootstrap is the C-Envoy's configuration.
func (c envoyConfig) bootstrap() map[string]any {
	return map[string]any{
		"node": map[string]any{"id": c.identity.ConnectorID, "cluster": c.identity.TenantID},
		"bootstrap_extensions": []any{map[string]any{
			"name": "envoy.bootstrap.reverse_tunnel.downstream_socket_interface",
			"typed_config": map[string]any{
				"@type": "type.googleapis.com/envoy.extensions.bootstrap.reverse_tunnel." +
					"downstream_socket_interface.v3.DownstreamReverseConnectionSocketInterface",
				"stat_prefix":           "downstream_reverse_connection",
				"enable_detailed_stats": true,
			},
		}},
		// Let the tunnel end its side of a CONNECT stream before the caller
		// does, so a destination that finishes first does not reset the pipe
		// and drop in-flight bytes.
		"layered_runtime": map[string]any{"layers": []any{map[string]any{
			"name": "static",
			"static_layer": map[string]any{
				"envoy.reloadable_features.allow_multiplexed_upstream_half_close": true,
			},
		}}},
		"admin": map[string]any{"address": socketAddress(adminAddress, AdminPort)},
		"static_resources": map[string]any{
			"listeners": []any{c.listener()},
			"clusters":  []any{c.coreCluster(), c.cluster()},
		},
	}
}

func (c envoyConfig) coreCluster() map[string]any {
	return map[string]any{
		"name":            "core",
		"type":            "STATIC",
		"connect_timeout": "1s",
		// Envoy's defaults (1,024) would answer overflow with an untyped 503
		// before core could refuse with CAPACITY. Refused opens are streams
		// too, so leave room above the cap.
		"circuit_breakers": map[string]any{"thresholds": []any{map[string]any{
			"max_requests":         2 * c.maxPipes,
			"max_pending_requests": 2 * c.maxPipes,
			"max_connections":      2 * c.maxPipes,
		}}},
		"load_assignment": loadAssignment("core", c.coreHost, c.corePort),
		"typed_extension_protocol_options": map[string]any{
			"envoy.extensions.upstreams.http.v3.HttpProtocolOptions": map[string]any{
				"@type": "type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions",
				"explicit_http_config": map[string]any{
					"http2_protocol_options": map[string]any{
						"allow_connect":                  true,
						"initial_stream_window_size":     coreStreamWindow,
						"initial_connection_window_size": coreConnectionWindow,
					},
				},
			},
		},
	}
}

// listener holds the tunnels, one per worker, and hands every pipe they
// carry to core.
func (c envoyConfig) listener() map[string]any {
	id := c.identity
	return map[string]any{
		"name": tunnelListener,
		"address": map[string]any{"socket_address": map[string]any{
			"address": fmt.Sprintf("rc://%s:%s:%s@%s:%d",
				id.ConnectorID, id.TenantID, id.TenantID, tunnelCluster, tunnelsPerWorker),
			"port_value":    0,
			"resolver_name": "envoy.resolvers.reverse_connection",
		}},
		"listener_filters_timeout": "0s",
		"filter_chains":            []any{c.tunnelFilterChain()},
	}
}

// tunnelFilterChain serves the pipes each tunnel carries, over inner TLS
// unless it is disabled.
//
// The drain-aware HCM is the stock HCM plus one behaviour: when the tunnel
// endpoint sends GOAWAY (it is draining the tunnel, for a rollout or
// recycling), Envoy stops counting this tunnel and dials its replacement at
// once, while open pipes finish on the old one. Without it a draining tunnel
// counts as held until its socket closes, which pipes can delay for hours.
func (c envoyConfig) tunnelFilterChain() map[string]any {
	chain := map[string]any{"filters": []any{map[string]any{
		"name": "envoy.filters.network.reverse_tunnel_drain_aware_http_connection_manager",
		"typed_config": map[string]any{
			"@type": "type.googleapis.com/envoy.extensions.filters.network." +
				"reverse_tunnel.v3.DrainAwareHttpConnectionManager",
			"enable_drain_with_goaway": true,
			"hcm_config":               c.pipesHCM(),
		},
	}}}
	if c.innerTLS == InnerTLSRequired {
		chain["transport_socket"] = c.innerTLSContext()
	}
	return chain
}

// innerTLSContext is the connector's side of each tunnel's data-leg TLS.
//
// Envoy duplicates the raw socket once a tunnel registers and drops the
// dial's TLS session (see InnerTLS), so without this the data leg is
// cleartext. This is a second handshake, owned by the listener, with the
// roles reversed: the connector is the TLS server. It presents the
// connector certificate (the dial's client certificate) and requires the
// tunnel endpoint's, signed by the roots the dial already trusts and naming
// the controller's host, the same name the dial verifies.
func (c envoyConfig) innerTLSContext() map[string]any {
	return map[string]any{
		"name": "envoy.transport_sockets.tls",
		"typed_config": map[string]any{
			"@type": "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3." +
				"DownstreamTlsContext",
			"require_client_certificate": true,
			"common_tls_context": map[string]any{
				"tls_params": map[string]any{
					"tls_minimum_protocol_version": "TLSv1_3",
					"tls_maximum_protocol_version": "TLSv1_3",
				},
				// Only h2: the tunnel ALPN selects the front door's route
				// on the dial and means nothing on the data leg.
				"alpn_protocols":     []any{"h2"},
				"tls_certificates":   c.tlsCertificates(),
				"validation_context": c.endpointValidation(),
			},
		},
	}
}

// pipesHCM hands every pipe a tunnel carries to core.
func (c envoyConfig) pipesHCM() map[string]any {
	return map[string]any{
		"stat_prefix":            "pipes",
		"codec_type":             "HTTP2",
		"http2_protocol_options": c.tunnelServerHTTP2Options(),
		"upgrade_configs":        []any{map[string]any{"upgrade_type": "CONNECT"}},
		// Pipes are long-lived and may sit idle (psql, kubectl exec).
		// core enforces the idle timeout and lifetime cap, so a
		// pipe ends with a reason core audits.
		"stream_idle_timeout": "0s",
		// A tunnel with no pipes is still a tunnel. Envoy closes an HTTP/2
		// connection with no active streams after an hour by default, and
		// the reverse tunnel's pings run below HTTP so they do not count as
		// activity: a connector idle for an hour would lose every tunnel and
		// depend on re-dialing to get them back. 0s disables the timeout;
		// TCP keepalive on the tunnel cluster still finds dead peers.
		"common_http_protocol_options": map[string]any{"idle_timeout": "0s"},
		"route_config": map[string]any{"virtual_hosts": []any{map[string]any{
			"name":    "pipes",
			"domains": []any{"*"},
			"routes": []any{map[string]any{
				"match": map[string]any{"connect_matcher": map[string]any{}},
				"route": map[string]any{"cluster": "core", "timeout": "0s"},
			}},
		}}},
		"http_filters": []any{map[string]any{
			"name": "envoy.filters.http.router",
			"typed_config": map[string]any{
				"@type": "type.googleapis.com/envoy.extensions.filters.http.router.v3.Router",
			},
		}},
	}
}

// cluster is how the connector reaches the tunnel endpoint: mutual TLS 1.3
// with the endpoint's name as SNI and verified in its certificate, offering
// the tunnel ALPN.
func (c envoyConfig) cluster() map[string]any {
	e := c.endpoint
	return map[string]any{
		"name":              tunnelCluster,
		"type":              "STRICT_DNS",
		"dns_lookup_family": "V4_PREFERRED",
		"connect_timeout":   "5s",
		"load_assignment":   loadAssignment(tunnelCluster, e.host, e.port),
		"upstream_connection_options": map[string]any{"tcp_keepalive": map[string]any{
			"keepalive_time": 30, "keepalive_interval": 10, "keepalive_probes": 3,
		}},
		"transport_socket": map[string]any{
			"name": "envoy.transport_sockets.tls",
			"typed_config": map[string]any{
				"@type": "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext",
				"sni":   e.sni,
				"common_tls_context": map[string]any{
					// Envoy's upstream TLS defaults to a 1.2 maximum.
					"tls_params": map[string]any{
						"tls_minimum_protocol_version": "TLSv1_3",
						"tls_maximum_protocol_version": "TLSv1_3",
					},
					"alpn_protocols":     []any{tunnelALPN, "h2"},
					"tls_certificates":   c.tlsCertificates(),
					"validation_context": c.endpointValidation(),
				},
			},
		},
	}
}

// tunnelServerHTTP2Options are the tunnel's HTTP/2 settings on the
// connector, which serves it. Every pipe the connector refuses (a closed
// port, a forbidden address) ends with the tunnel endpoint resetting that
// stream, so a burst of refusals is a burst of RST_STREAM frames. Envoy's
// Rapid Reset limiter (CVE-2023-44487: 1,000 resets, then 33 a second) would
// answer it by closing the tunnel with GOAWAY, cutting every pipe on it. The
// only peer is Traversal's tunnel endpoint, authenticated by mutual TLS, so
// the limiter is sized far above any real refusal rate instead.
func (c envoyConfig) tunnelServerHTTP2Options() map[string]any {
	opts := c.http2Options()
	opts["stream_reset_burst"] = streamResetBurst
	opts["stream_reset_rate"] = streamResetRate
	return opts
}

// Rapid Reset limiter bounds for the tunnel, in resets and resets a second.
const (
	streamResetBurst = 1_000_000
	streamResetRate  = 100_000
)

func (c envoyConfig) http2Options() map[string]any {
	return map[string]any{
		"allow_connect":                  true,
		"initial_stream_window_size":     c.streamWindow,
		"initial_connection_window_size": c.connectionWindow,
	}
}

// tlsCertificates is the connector certificate, on the dial and the data
// leg alike.
func (c envoyConfig) tlsCertificates() []any {
	return []any{map[string]any{
		"certificate_chain": map[string]any{"filename": c.path(certFile)},
		"private_key":       map[string]any{"filename": c.path(keyFile)},
	}}
}

// endpointValidation verifies the tunnel endpoint's certificate: signed by
// a trusted root and naming the controller's host.
func (c envoyConfig) endpointValidation() map[string]any {
	return map[string]any{
		"trusted_ca": map[string]any{"filename": c.path(caFile)},
		"match_typed_subject_alt_names": []any{map[string]any{
			"san_type": "DNS",
			"matcher":  map[string]any{"exact": c.endpoint.sni},
		}},
	}
}

func socketAddress(host string, port int) map[string]any {
	return map[string]any{"socket_address": map[string]any{"address": host, "port_value": port}}
}

func loadAssignment(name, host string, port int) map[string]any {
	return map[string]any{
		"cluster_name": name,
		"endpoints": []any{map[string]any{"lb_endpoints": []any{map[string]any{
			"endpoint": map[string]any{"address": socketAddress(host, port)},
		}}}},
	}
}

// writeBootstrap writes Envoy's configuration.
func (c envoyConfig) writeBootstrap() error {
	return writeJSON(c.path(bootstrapFile), c.bootstrap())
}

// writeJSON writes v to path. Run writes every file Envoy reads once, before
// it starts Envoy, so nothing reads a file while it is written.
func writeJSON(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}
