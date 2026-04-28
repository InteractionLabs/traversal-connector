# Traversal Connector

The Traversal Connector runs inside a private network and exposes its internal
data sources to the Traversal control plane *without* opening any inbound
firewall holes. It dials out to the control plane over gRPC, multiplexes one
or more bidirectional tunnels, and executes HTTP requests it receives on those
tunnels against upstream services on the local network.

```
   ┌────────────────────┐  outbound gRPC tunnels   ┌────────────────────┐  HTTP   ┌──────────────────┐
   │  Traversal control │ ◄──────────────────────► │ Traversal Connector│ ──────► │ upstream services│
   │       plane        │      (h2c or mTLS)       │  (this binary)     │         │ (Prometheus, …)  │
   └────────────────────┘                          └────────────────────┘         └──────────────────┘
```

The wire protocol is defined in
[`connector-lib/proto/connector/v1/connector.proto`](connector-lib/proto/connector/v1/connector.proto).

## Running locally

`ENV_NAME` and `TRAVERSAL_CONTROLLER_URL` are required; everything else has
sensible defaults (see Configuration below). `TRAVERSAL_CONTROLLER_URL` has no
default — startup fails if it's unset.

**Docker Compose (containerized, hot-reload via `air`):**

```bash
TRAVERSAL_CONTROLLER_URL=http://host.docker.internal:9080 docker compose up --build
```

**Native (skip docker, fast iteration):**

```bash
ENV_NAME=dev TRAVERSAL_CONTROLLER_URL=http://localhost:9080 go run ./cmd/connector
```

## Building & testing

```bash
go build ./...        # build all packages
go test ./...         # run the test suite
go vet ./...          # static checks
```

Formatting follows `gofmt` plus
[`golines`](https://github.com/segmentio/golines) at a 100-column limit:

```bash
golines -w -m 100 .
go fmt ./...
```

The protobuf definitions are managed with [`buf`](https://buf.build):

```bash
cd connector-lib && buf lint
cd connector-lib && buf format -w
```

Generated code lives under [`connector-lib/gen/`](connector-lib/gen/) and is
checked in.

## Configuration

### Core

| Variable | Default | Description |
|---|---|---|
| `ENV_NAME` | **required** | Free-form environment name attached to telemetry as `service.namespace` and `deployment.environment` (e.g. `staging`, `production`). Startup fails if unset. |
| `ENV_LEVEL` | `development` | Deployment level (`production` or `development`). The container image bakes in `production`; leave unset for local dev. |
| `HTTP_PORT` | `8080` | Port for the local HTTP server (`/health`, `/readyz`). |
| `ENV_FILE` | (none) | Optional path to a dotenv file (e.g. `/mnt/secrets/connector.env`). Useful when secrets are mounted as a file (e.g. Vault Agent). Process-environment values win over file values; the file only fills in values that are unset. Startup fails if the path is set but unreadable. |

### Control plane connection

| Variable | Default | Description |
|---|---|---|
| `TRAVERSAL_CONTROLLER_URL` | **required** | ConnectRPC URL of the Traversal control plane. Startup fails if unset. |
| `MAX_TUNNELS_ALLOWED` | `2` | Maximum number of concurrent gRPC tunnels this connector opens. |
| `MAX_CONCURRENT_REQUESTS` | `10` | Maximum concurrent in-flight HTTP requests per tunnel when multiplexing is active. |
| `RECONNECT_INTERVAL` | `5s` | Interval for periodic connection rebalancing across control-plane pods. |
| `MAX_BACKOFF_DELAY` | `60s` | Cap for exponential backoff on reconnection attempts. |
| `REQUEST_TIMEOUT` | `60s` | Timeout for individual upstream HTTP requests. |
| `MAX_REQUEST_BODY_SIZE_MB` | `32` | Maximum size of HTTP request bodies sent upstream. |
| `PROXY_URL` | (none) | Optional HTTP forward-proxy URL (e.g. `http://proxy.example.com:3128`). When set, `TRAVERSAL_CONTROLLER_URL` must use `https://` — HTTP/2 over a forward proxy requires TLS. When unset, the connector talks h2c (HTTP/2 cleartext). |

### mTLS to the control plane

All certificate variables accept either raw PEM (starting with
`-----BEGIN`) or base64-encoded PEM.

| Variable | Default | Description |
|---|---|---|
| `TLS_CERT_BASE64` | (none) | Client TLS certificate for mTLS. |
| `TLS_KEY_BASE64` | (none) | Client TLS private key for mTLS. |
| `TLS_CA_BASE64` | (none) | CA certificate used to validate the control plane's server certificate. |
| `TLS_SERVER_NAME` | (none) | Expected server name for TLS verification. |

### Upstream TLS (HTTPS to internal services)

The connector verifies upstream TLS certificates by default. Tune via:

| Variable | Default | Description |
|---|---|---|
| `UPSTREAM_TLS_VERIFY` | `true` | Verify TLS certificates when calling upstream HTTPS services. Set to `false` to accept self-signed. |
| `UPSTREAM_TLS_CA_BASE64` | (none) | CA certificate (raw PEM or base64-encoded) for validating upstream certificates. When set, only certificates signed by this CA are accepted (effectively certificate pinning). |

Examples:

```bash
# Default — verify against the system CA bundle.
UPSTREAM_TLS_VERIFY=true

# Accept self-signed (no verification).
UPSTREAM_TLS_VERIFY=false

# Pin to an internal CA.
UPSTREAM_TLS_VERIFY=true
UPSTREAM_TLS_CA_BASE64="LS0tLS1CRUdJTi..."
```

### Telemetry (OpenTelemetry)

The connector emits OpenTelemetry traces, metrics, and logs. Endpoints are
**unset by default** — when an endpoint is empty, that signal is not exported.

| Variable | Default | Description |
|---|---|---|
| `OTEL_SERVICE_NAME` | `traversal-connector` | Service name reported on all signals. |
| `OTEL_EXPORTER_OTLP_METRICS_ENDPOINT` | (none) | OTLP endpoint for metrics. Full URL or `host:port`. |
| `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` | (none) | OTLP endpoint for traces. |
| `OTEL_EXPORTER_OTLP_LOGS_ENDPOINT` | (none) | OTLP endpoint for logs. When unset, logs go to stdout only. |
| `OTEL_EXPORTER_OTLP_PROTOCOL` | (empty) | `grpc` or `http/protobuf` selects gRPC; `http/json` (or empty) selects HTTP. |

The connector also reads the OTel-standard
[`OTEL_RESOURCE_ATTRIBUTES`](https://opentelemetry.io/docs/specs/otel/resource/sdk/#specifying-resource-information-via-an-environment-variable)
env var and merges those attributes into the resource — useful for attaching
compliance IDs, team names, or any other site-specific metadata.

## Ports

| Port | Description |
|---|---|
| `8080` (container) | HTTP `/health` and `/readyz` endpoints. The compose file maps host `8081` → container `8080`. |

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
