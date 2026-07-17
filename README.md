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

## Setup

Run after cloning:

```bash
./setup.sh
```

Installs `just` and the Go-based CLI tools the recipes depend on.

## Running locally

`ENV_NAME`, `TRAVERSAL_CONTROLLER_URL`, and `TRAVERSAL_CONNECTOR_ID` are
required; everything else has sensible defaults (see Configuration below).
These have no defaults — startup fails if any is unset.

**Docker Compose (containerized, hot-reload via `air`):**

```bash
TRAVERSAL_CONTROLLER_URL=http://host.docker.internal:9080 docker compose up --build
```

**Native (skip docker, fast iteration):**

```bash
ENV_NAME=dev TRAVERSAL_CONNECTOR_ID=local-dev TRAVERSAL_CONTROLLER_URL=http://localhost:9080 go run ./cmd/connector
```

`http://` is rejected when `ENV_LEVEL=production`. In development any
`http://` host is accepted. Production deployments must use `https://` and
configure mTLS, see Configuration below.

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
| `HTTP_PORT` | `8080` | Port for the local HTTP server (`/healthz`, `/readyz`). |
| `ENV_FILE` | (none) | Optional path to a dotenv file (e.g. `/mnt/secrets/connector.env`). Useful when secrets are mounted as a file (e.g. Vault Agent). Process-environment values win over file values; the file only fills in values that are unset. Startup fails if the path is set but unreadable. |

### Control plane connection

| Variable | Default | Description |
|---|---|---|
| `TRAVERSAL_CONTROLLER_URL` | **required** | ConnectRPC URL of the Traversal control plane. `https://` requires mTLS (see below). `http://` is rejected when `ENV_LEVEL=production`. Startup fails if unset or if the scheme/level combination is rejected. |
| `MAX_TUNNELS_ALLOWED` | `2` | Maximum number of concurrent gRPC tunnels this connector opens. |
| `MAX_CONCURRENT_REQUESTS` | `10` | Maximum concurrent in-flight HTTP requests per tunnel when multiplexing is active. |
| `RECONNECT_INTERVAL` | `5s` | Interval for periodic connection rebalancing across control-plane pods. |
| `MAX_BACKOFF_DELAY` | `60s` | Cap for exponential backoff on reconnection attempts. |
| `REQUEST_TIMEOUT` | `60s` | Timeout for individual upstream HTTP requests. |
| `MAX_REQUEST_BODY_SIZE_MB` | `32` | Maximum size of HTTP request bodies sent upstream. |
| `TRAVERSAL_CONNECTOR_ID` | **required** | Identifier stamped on every gRPC request to the control plane via the `X-Traversal-Connector-ID` header, letting it attribute connections to a specific connector instance. Startup fails if unset. |
| `EGRESS_PROXY_URL` | (none) | Optional HTTP forward-proxy URL (e.g. `http://proxy.example.com:3128`) used for **all** connector-initiated egress to the Traversal SaaS — both the bidi controller tunnel and OTLP telemetry export (when mTLS is configured for the OTLP endpoint). When set, `TRAVERSAL_CONTROLLER_URL` must use `https://` — HTTP/2 over a forward proxy requires TLS. When unset, the connector dials its destinations directly (h2c for the controller; default OTLP transport for telemetry). |

### mTLS to the control plane

mTLS is **required** whenever `TRAVERSAL_CONTROLLER_URL` is `https://...`.
The connector refuses to start if `TLS_CERT_BASE64` and `TLS_KEY_BASE64` are
not both provided, or if either fails to parse as valid PEM. mTLS is the only
supported posture for production traffic; there is no "TLS without mTLS"
mode.

All certificate variables accept either raw PEM (starting with
`-----BEGIN`) or base64-encoded PEM.

| Variable | Default | Description |
|---|---|---|
| `TLS_CERT_BASE64` | **required for `https://`** | Client TLS certificate. Must be paired with `TLS_KEY_BASE64`. |
| `TLS_KEY_BASE64` | **required for `https://`** | Client TLS private key. Must match the public key in `TLS_CERT_BASE64`. |
| `TLS_CA_BASE64` | (none) | CA certificate used to validate the control plane's server certificate. When set, replaces the system CA bundle. Leave unset for public CAs (e.g. Let's Encrypt). |

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

### Redaction

The connector can redact sensitive values from upstream response bodies before
they leave the customer network.

| Variable | Default | Description |
|---|---|---|
| `REDACTION_RULES_FILE` | (none) | Path to a TOML file containing redaction rules. When unset, no redaction is applied. The file is periodically reloaded. |

The rules file uses the following format:

```toml
version = "1"
default_replacement = "[REDACTED]"   # optional; defaults to "[REDACTED]"

[[rules]]
name   = "ssn"
type   = "regex"
pattern     = '\b\d{3}-\d{2}-(\d{4})\b'
replacement = "***-**-$1"

[[rules]]
name   = "api-key"
type   = "regex"
pattern     = '(?i)(api[_-]?key\s*[:=]\s*)\S+'
replacement = '$1[REDACTED]'

# Per-field rule for JSON response bodies. Email is only redacted when it
# appears in `body.message` and the response body parses as JSON. On non-JSON
# bodies (or JSON that fails to parse) the rule is skipped entirely.
[[rules]]
name   = "email"
type   = "regex-structured-data"
pattern       = '[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}'
redact_fields = ["body|message"]
# replacement omitted -> falls back to default_replacement

# Host-scoped rule: this token pattern is only redacted for responses from
# GitHub hostnames. Requests to any other upstream pass through untouched.
[[rules]]
name    = "github-token"
type    = "regex"
pattern = 'gh[pousr]_[A-Za-z0-9]{36}'
hosts   = ['.*github\.com']
```

Top-level fields:
- `version` — schema version label (informational only).
- `default_replacement` — fallback replacement string for rules that omit `replacement`. Defaults to `"[REDACTED]"`.
- `rules` — ordered list of redaction rules.

Each rule requires:
- `name` — human-readable label used in log output.
- `type` — `"regex"` for byte-level redaction over the full response body, or `"regex-structured-data"` for per-field redaction over JSON response bodies. Unrecognised types are logged and skipped.
- `pattern` — a [RE2](https://github.com/google/re2/wiki/Syntax) regular expression.
- `replacement` *(optional)* — replacement string; use `$1`, `$2`, … to insert numbered capture groups from the pattern. Falls back to `default_replacement`.
- `hosts` *(optional)* — allowlist of RE2 patterns matched against the request **hostname** (port and userinfo stripped). The rule only fires when the hostname *fully* matches at least one pattern. Defaults to `[".*"]` (every host). Each pattern is anchored to the whole hostname, so `.*github\.com` matches `api.github.com` and `github.com` but **not** `github.com.evil.com`. Applies to both rule types. Listing `.*` anywhere in the list makes the rule match every host.

`regex-structured-data` rules additionally accept:
- `redact_fields` — allowlist of pipe-delimited paths. When set, the rule only fires inside the matching subtrees.
- `skip_fields` — blocklist of pipe-delimited paths. When set, the rule never fires inside the matching subtrees.

Field names use pipe-delimited notation for nested objects: `body|message` matches the `body.message` field. Both filters may be set on the same rule; `skip_fields` wins on overlap.

**Scope is prefix-based on the path.** An entry `body` in `redact_fields` matches `body` itself plus everything underneath it (`body|message`, `body|x|y|z`, every array element under any of those). Once the walk enters an in-scope node, every primary leaf reachable from it is redacted — including map **keys**, map values, and array elements. Numbers are matched against their JSON textual form, so a credit-card or phone-number pattern catches values whether the upstream serialized them as strings or as JSON numbers; when a number actually matches, the field is rewritten as a string in the output (since the redacted text is no longer a valid number). Numbers that don't match are preserved as numbers, and booleans and `null` always pass through unchanged. The addressing key that *brought* you into the subtree lives at the parent scope, so e.g. with `redact_fields = ["data"]` the literal key `"data"` is not redacted, but every nested key inside it is.

How the two rule types are applied:

- **`regex` rules** always run byte-level over the full response body, regardless of `Content-Type` or whether the body parses as JSON. They have no concept of fields, so `redact_fields` / `skip_fields` don't apply.
- **`regex-structured-data` rules** only run when the response has a JSON `Content-Type` *and* the body parses successfully — they fire per-field, honoring `redact_fields` / `skip_fields`. If the body isn't JSON or fails to parse, these rules are **skipped entirely** (their field filters can't be honored on raw bytes, so applying them globally would cross the boundaries the filters were configured to enforce).

If you need a pattern to redact everywhere unconditionally, use `regex`. If you need per-field control, use `regex-structured-data` and ensure the upstream returns valid JSON with the right `Content-Type`.

Rules are applied in order; each rule operates on the output of the previous one.

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
| `8080` (container) | HTTP `/healthz` and `/readyz` endpoints. The compose file maps host `8081` → container `8080`. |

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
