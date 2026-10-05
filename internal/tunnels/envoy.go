package tunnels

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// The connector's Envoy (the C-Envoy) dials reverse tunnels to every
// Traversal tunnel endpoint replica and forwards each pipe that arrives
// through them, unchanged, to connector-core on loopback.
//
// Its bootstrap is static. Each replica gets its own listener (the tunnels)
// and cluster (how to reach it), delivered as files Envoy watches: adding a
// replica adds a listener and removing one removes only that listener, so a
// change to the replica set never touches tunnels that are already up.

// HTTP/2 windows for pipes, on the tunnels and toward core. A stalled pipe
// holds at most one stream window, so it cannot exhaust a tunnel.
const (
	streamWindow     = 256 << 10
	connectionWindow = 1 << 20
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
	listenersFile = "lds.json"
	clustersFile  = "cds.json"
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
	// perWorker is the tunnels each Envoy worker holds to each replica.
	// Every worker dials its own, so a replica gets workers × perWorker.
	perWorker int
}

// replica is one Traversal tunnel endpoint the connector holds tunnels to.
type replica struct {
	// name is the replica's first SNI label, such as "t-envoy-3". It names
	// the replica's Envoy listener and cluster.
	name string
	// sni is the name the connector dials and verifies, such as
	// "t-envoy-3.tunnels.traversal.com".
	sni string
	// host and port are where the connector connects: the shared tunnels
	// entry point, which routes by SNI.
	host string
	port int
}

func (c envoyConfig) path(name string) string { return filepath.Join(c.dir, name) }

// bootstrap is the C-Envoy's static configuration.
func (c envoyConfig) bootstrap() map[string]any {
	watched := map[string]any{"path": c.dir}
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
		"dynamic_resources": map[string]any{
			"lds_config": map[string]any{
				"resource_api_version": "V3",
				"path_config_source": map[string]any{
					"path": c.path(listenersFile), "watched_directory": watched,
				},
			},
			"cds_config": map[string]any{
				"resource_api_version": "V3",
				"path_config_source": map[string]any{
					"path": c.path(clustersFile), "watched_directory": watched,
				},
			},
		},
		"static_resources": map[string]any{"clusters": []any{c.coreCluster()}},
	}
}

func (c envoyConfig) coreCluster() map[string]any {
	return map[string]any{
		"name":            "core",
		"type":            "STATIC",
		"connect_timeout": "1s",
		"load_assignment": loadAssignment("core", c.coreHost, c.corePort),
		"typed_extension_protocol_options": map[string]any{
			"envoy.extensions.upstreams.http.v3.HttpProtocolOptions": map[string]any{
				"@type": "type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions",
				"explicit_http_config": map[string]any{
					"http2_protocol_options": http2Options(),
				},
			},
		},
	}
}

// listener holds W tunnels to one replica and hands every pipe they carry
// to core.
func (c envoyConfig) listener(r replica) map[string]any {
	id := c.identity
	return map[string]any{
		"@type": "type.googleapis.com/envoy.config.listener.v3.Listener",
		"name":  "tunnels-" + r.name,
		"address": map[string]any{"socket_address": map[string]any{
			"address": fmt.Sprintf("rc://%s:%s:%s@%s:%d",
				id.ConnectorID, id.TenantID, id.TenantID, r.name, c.perWorker),
			"port_value":    0,
			"resolver_name": "envoy.resolvers.reverse_connection",
		}},
		"listener_filters_timeout": "0s",
		"filter_chains": []any{map[string]any{"filters": []any{map[string]any{
			"name": "envoy.filters.network.http_connection_manager",
			"typed_config": map[string]any{
				"@type": "type.googleapis.com/envoy.extensions.filters.network." +
					"http_connection_manager.v3.HttpConnectionManager",
				"stat_prefix":            "pipes",
				"codec_type":             "HTTP2",
				"http2_protocol_options": http2Options(),
				"upgrade_configs":        []any{map[string]any{"upgrade_type": "CONNECT"}},
				// Pipes are long-lived and may sit idle (psql, kubectl exec).
				// core enforces any lifetime cap.
				"stream_idle_timeout": "0s",
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
			},
		}}}},
	}
}

// cluster is how the connector reaches one replica: the shared entry point,
// with the replica's SNI, mutual TLS 1.3, and the replica's name verified.
func (c envoyConfig) cluster(r replica) map[string]any {
	return map[string]any{
		"@type":             "type.googleapis.com/envoy.config.cluster.v3.Cluster",
		"name":              r.name,
		"type":              "STRICT_DNS",
		"dns_lookup_family": "V4_PREFERRED",
		"connect_timeout":   "5s",
		"load_assignment":   loadAssignment(r.name, r.host, r.port),
		"upstream_connection_options": map[string]any{"tcp_keepalive": map[string]any{
			"keepalive_time": 30, "keepalive_interval": 10, "keepalive_probes": 3,
		}},
		"transport_socket": map[string]any{
			"name": "envoy.transport_sockets.tls",
			"typed_config": map[string]any{
				"@type": "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext",
				"sni":   r.sni,
				"common_tls_context": map[string]any{
					// Envoy's upstream TLS defaults to a 1.2 maximum.
					"tls_params": map[string]any{
						"tls_minimum_protocol_version": "TLSv1_3",
						"tls_maximum_protocol_version": "TLSv1_3",
					},
					"alpn_protocols": []any{"h2"},
					"tls_certificates": []any{map[string]any{
						"certificate_chain": map[string]any{"filename": c.path(certFile)},
						"private_key":       map[string]any{"filename": c.path(keyFile)},
					}},
					"validation_context": map[string]any{
						"trusted_ca": map[string]any{"filename": c.path(caFile)},
						"match_typed_subject_alt_names": []any{map[string]any{
							"san_type": "DNS",
							"matcher":  map[string]any{"exact": r.sni},
						}},
					},
				},
			},
		},
	}
}

func http2Options() map[string]any {
	return map[string]any{
		"allow_connect":                  true,
		"initial_stream_window_size":     streamWindow,
		"initial_connection_window_size": connectionWindow,
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

// writeBootstrap writes the static configuration and empty resource files,
// so Envoy starts with no tunnels until discovery names the replicas.
func (c envoyConfig) writeBootstrap() error {
	if err := writeJSON(c.path(bootstrapFile), c.bootstrap()); err != nil {
		return err
	}
	if err := c.writeClusters(nil); err != nil {
		return err
	}
	return c.writeListeners(nil)
}

// writeJSON replaces path atomically. Envoy watches the directory for moves,
// so a rename is the only write it ever sees.
func writeJSON(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(path, data, 0o600)
}

func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	// #nosec G703 -- Paths are the connector's own run directory and fixed names.
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }() //nolint:gosec // our own temp file
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path) //nolint:gosec // see CreateTemp above
}

// replicaName is the first label of a replica's SNI.
func replicaName(sni string) string {
	name, _, _ := strings.Cut(sni, ".")
	return name
}
