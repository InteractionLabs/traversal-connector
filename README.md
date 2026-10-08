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

### Prerelease test images

Build and load the `production` image for the current host platform with a
default tag of `traversal-connector:prerelease-<short-sha>`:

```bash
just prerelease-image-local
```

An explicit push publishes an unsigned, multi-platform test image to an existing
Amazon ECR repository selected by the caller:

```bash
just prerelease-image-push --region <aws-region> \
  --ecr-repository traversal-connector
```

The AWS account is derived from the active credential chain. Use `--profile` to
select a configured profile; region resolution follows `--region`, `AWS_REGION`,
`AWS_DEFAULT_REGION`, then the AWS CLI configuration. The ECR repository must
already exist. The push refuses to replace an existing tag, so prerelease tags
are immutable by convention.

These images are not signed, are for testing only, and are not supported
releases. The command does not create Git tags, GitHub releases, Helm assets,
stable image tags, or `latest`. Use `--tag prerelease-<name>` to override the
default tag.

The command prints the immutable image reference after publishing. To test its
tag with the existing chart, use the printed registry/repository as the image
repository:

```bash
helm upgrade --install traversal-connector <chart> \
  --set image.repository=<printed-registry/repository> \
  --set image.tag=prerelease-<short-sha>
```

### Paired PR prerelease artifacts

For an internal test build from a pull request, apply the existing
`build:prerelease` label. The dedicated workflow runs only for same-repository
PRs carrying that exact label; fork PRs and ordinary unlabeled PRs never receive
AWS credentials or publish artifacts. A new PR commit cancels an older in-flight
run and builds the exact new head SHA.

The workflow publishes an unsigned, test-only multi-architecture image to the
internal ECR repository as `prerelease-<12-character-head-sha>`. It uploads a
paired Actions artifact named `prerelease-pr-<number>-<short-sha>` containing:

- `traversal-connector-charts-0.0.0-pr.<number>.<short-sha>.tgz`
- the chart's portable `.sha256` file
- `manifest.json`, which binds the full source SHA and PR/run metadata to the
  image's immutable `repository@sha256:...` reference and chart checksum

Actions retains the bundle for seven days. Consumers should pin the immutable
image reference from `manifest.json`, not reconstruct or rely on its tag. The
chart `appVersion` equals the image tag, while its SemVer prerelease version
also carries the PR number and commit. Rerunning the same commit fails clearly
if its immutable ECR tag already exists; a changed commit receives a new tag and
bundle. This path never writes Docker Hub, GitHub Releases, release Git tags, or
the canonical chart OCI registry.

## Installing with Helm

Docker Hub is the canonical public image distribution. Before publishing each
GitHub Release, the workflow also copies the validated OCI index and its existing
signatures, attestations, and SBOMs to an internal Amazon ECR repository.

Each connector release publishes a matching Helm chart and portable SHA-256
checksum as GitHub Release assets. These assets are the canonical and preferred
installation source. The chart version omits the leading `v`; its `appVersion`
and the default connector image tag retain the complete release version.

```bash
VERSION=v0.8.5
CHART="traversal-connector-charts-${VERSION#v}.tgz"
DOWNLOAD_PATH="releases/download"
BASE="https://github.com/InteractionLabs/traversal-connector/${DOWNLOAD_PATH}/${VERSION}"

curl -fLO "${BASE}/${CHART}"
curl -fLO "${BASE}/${CHART}.sha256"

# Linux:
sha256sum --check "${CHART}.sha256"
# macOS alternative:
# shasum -a 256 --check "${CHART}.sha256"

helm upgrade --install traversal-connector "./${CHART}" \
  --namespace traversal-connector \
  --create-namespace \
  -f customer-values.yaml
```

For temporary compatibility with existing OCI-based installations, new release
charts are also mirrored to Docker Hub. OCI versions do not include the leading
`v`:

```bash
CHART_VERSION=0.8.5
OCI_CHART="oci://registry-1.docker.io/traversalext/traversal-connector-charts"

# Pull the mirrored archive locally, or install it directly.
helm pull "$OCI_CHART" --version "$CHART_VERSION"
helm upgrade --install traversal-connector "$OCI_CHART" \
  --version "$CHART_VERSION" \
  --namespace traversal-connector \
  --create-namespace \
  -f customer-values.yaml
```

`image.tag` is empty in the canonical values and therefore falls back to the
chart's `appVersion`, keeping the chart and connector image on the same release.
An explicit `image.tag` override remains supported when a deployment needs to
pin another image.

The chart defaults to non-root containers, read-only root filesystems, no
privilege escalation, no Linux capabilities, and runtime-default seccomp.
See the [chart security settings](charts/traversal-connector/README.md) for
container and pod overrides and writable-volume behavior.

Historical chart availability is intentionally incomplete: release assets are
backfilled only where an authentic version-specific chart exists. Historical
Docker Hub OCI coverage may differ from GitHub Release asset coverage; future
normal releases are mirrored while this transitional compatibility path remains
in place.

### Validating chart installation locally

With Docker, kind, kubectl, Helm, curl, and OpenSSL installed, validate that a
downloaded release chart installs and upgrades in a disposable kind cluster:

```bash
scripts/validate-chart-install.sh \
  ./traversal-connector-charts-0.8.5.tgz \
  --image-ref docker.io/traversalext/traversal-connector:v0.8.5
```

The validator checks `/healthz` rather than Kubernetes readiness. `/readyz`
requires an active tunnel to a real Traversal controller, which the disposable
cluster intentionally does not have. The cluster is always deleted on exit.

This validator is transitional: it will be replaced by the future deploy
system's install-validation flow.

## Verifying a release image

Released images are published as
`docker.io/traversalext/traversal-connector`. Verify the immutable digest, not a
mutable tag. Set `DIGEST` to the release digest (a `sha256:` value), then verify
the image with [Cosign](https://docs.sigstore.dev/cosign/system_config/installation/)
and the public key checked into this repository:

```bash
DIGEST=sha256:<64-lowercase-hex-release-digest>
IMAGE="docker.io/traversalext/traversal-connector@${DIGEST}"
cosign verify --key cosign.pub "$IMAGE"
```

### Inspecting SBOM and provenance attestations

BuildKit publishes a platform-specific SPDX SBOM and provenance alongside each
release image. Choose the platform you will run, then inspect each attestation
separately with Docker Buildx:

```bash
DIGEST=sha256:<64-lowercase-hex-release-digest>
IMAGE="docker.io/traversalext/traversal-connector@${DIGEST}"
PLATFORM=linux/amd64 # or linux/arm64

docker buildx imagetools inspect "$IMAGE" --format '{{ json .SBOM }}' \
  | jq --arg platform "$PLATFORM" '.[$platform]'
docker buildx imagetools inspect "$IMAGE" --format '{{ json .Provenance }}' \
  | jq --arg platform "$PLATFORM" '.[$platform]'
```

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
| `TRAVERSAL_CONTROLLER_CONNECT_TO` | (none) | Optional curl `--connect-to`-style `host:port` override for the controller, for example `edge-istio.traversal-gateways.svc.cluster.local:443`. Only the TCP connection destination changes; the logical controller URL still supplies the scheme, path, HTTP/2 `:authority`, TLS SNI, and certificate verification identity. Cannot be combined with `EGRESS_PROXY_URL`. |
| `MAX_TUNNELS_ALLOWED` | `2` | Maximum number of concurrent gRPC tunnels this connector opens. |
| `MAX_CONCURRENT_REQUESTS` | `10` | Maximum concurrent in-flight HTTP requests per tunnel when multiplexing is active. |
| `RECONNECT_INTERVAL` | `5s` | Interval for periodic connection rebalancing across control-plane pods. |
| `MAX_BACKOFF_DELAY` | `60s` | Cap for exponential backoff on reconnection attempts. |
| `REQUEST_TIMEOUT` | `60s` | Timeout for individual upstream HTTP requests. |
| `MAX_REQUEST_BODY_SIZE_MB` | `32` | Maximum size of HTTP request bodies sent upstream. |
| `MAX_RESPONSE_BODY_SIZE_MB` | `32` | Maximum size read off the wire from an upstream response, before any decoding. Applies to every response, including from hosts no redaction rule targets. A larger response is dropped. |
| `MAX_DECODED_RESPONSE_BODY_SIZE_MB` | `256` | Maximum size a compressed response may expand to when the connector decodes it to redact. A stream that expands past this is dropped rather than decoded further. |
| `TRAVERSAL_CONNECTOR_ID` | **required** | Identifier stamped on every gRPC request to the control plane via the `X-Traversal-Connector-ID` header, letting it attribute connections to a specific connector instance. Startup fails if unset. |
| `EGRESS_PROXY_URL` | (none) | Optional HTTP forward-proxy URL (e.g. `http://proxy.example.com:3128`) used for **all** connector-initiated egress to the Traversal SaaS — both the bidi controller tunnel and OTLP telemetry export (when mTLS is configured for the OTLP endpoint). When set, `TRAVERSAL_CONTROLLER_URL` must use `https://` — HTTP/2 over a forward proxy requires TLS. It cannot be combined with either connect-to override; startup fails rather than silently ignoring a route. |

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
| `TLS_CA_BASE64` | (none) | Additional CA certificate used to validate the control plane's server certificate. When set, it extends the system CA bundle. Leave unset for public CAs (e.g. Let's Encrypt). |

### Upstream TLS (HTTPS to internal services)

The connector verifies upstream TLS certificates by default. Tune via:

| Variable | Default | Description |
|---|---|---|
| `UPSTREAM_TLS_VERIFY` | `true` | Verify TLS certificates when calling upstream HTTPS services. Set to `false` to accept self-signed. |
| `UPSTREAM_TLS_CA_BASE64` | (none) | CA certificate (raw PEM or base64-encoded) for validating upstream certificates. When set, this CA is added to the connector container's system trust store. The connector does not inherit trust from the Kubernetes node. |
| `UPSTREAM_TLS_CA_FILE` | (none) | Path to a PEM CA certificate file (e.g. a mounted Secret or ConfigMap), used the same way as `UPSTREAM_TLS_CA_BASE64`. Mutually exclusive with `UPSTREAM_TLS_CA_BASE64`: setting both fails at startup. |

Examples:

```bash
# Default — verify against the system CA bundle.
UPSTREAM_TLS_VERIFY=true

# Accept self-signed (no verification).
UPSTREAM_TLS_VERIFY=false

# Add an internal CA alongside the container's system CAs.
UPSTREAM_TLS_VERIFY=true
UPSTREAM_TLS_CA_BASE64="LS0tLS1CRUdJTi..."

# Or read the internal CA from a mounted file instead (not both).
UPSTREAM_TLS_VERIFY=true
UPSTREAM_TLS_CA_FILE=/etc/traversal/upstream-ca/ca.crt
```

### Upstream forward proxy

Requests to upstream services honor the standard proxy environment variables
(via Go's `http.ProxyFromEnvironment`), evaluated per request against the target
URL. They are read once at startup, so changes require a restart:

| Variable | Default | Description |
|---|---|---|
| `HTTPS_PROXY` | (none) | Forward proxy for `https://` upstream targets. |
| `HTTP_PROXY` | (none) | Forward proxy for `http://` upstream targets. |
| `NO_PROXY` | (none) | Comma-separated hosts that are dialed directly. `.example.com` (or `example.com`) matches the domain and all subdomains; `host:port` matches one port; CIDRs match only targets addressed by IP, since hostnames are not resolved before matching. Loopback targets always bypass the proxy. |

These apply only to upstream requests. The controller tunnel and OTLP export use
`EGRESS_PROXY_URL` and ignore these variables.

```sh
# Internet-hosted integrations via the corporate proxy; internal services direct.
HTTPS_PROXY=http://proxy.corp.example.com:3128
HTTP_PROXY=http://proxy.corp.example.com:3128
NO_PROXY=.corp.example.com,10.0.0.0/8
```

### Redaction

Choose either a local TOML rules file or S3-backed remote (OTA) configuration.
The two sources are mutually exclusive: setting `REDACTION_RULES_FILE` together
with `TRAVERSAL_CONFIG_ENABLED=true` fails startup. Helm also rejects combining
local redaction sources with `configUpdates.enabled: true`.
If neither source is enabled, the connector runs without redaction.
There is no automatic fallback between sources.

#### Local-file configuration

Set `REDACTION_RULES_FILE` to a readable file inside the connector container.
Leave `TRAVERSAL_CONFIG_ENABLED` unset or `false`; no remote config is fetched.

| Variable | Default | Description |
|---|---|---|
| `REDACTION_RULES_FILE` | (none) | Path to the local TOML rules file. Startup fails if the file cannot be read, parsed, or compiled. |
| `REDACTION_RELOAD_INTERVAL` | `10s` | Positive duration between local-file checks. Used only when a local file is configured. |

Local files use top-level `default_replacement` and `[[rules]]` tables:

```toml
version = "1"
default_replacement = "[REDACTED]"

[[rules]]
name = "ssn"
type = "regex"
pattern = '\b\d{3}-\d{2}-(\d{4})\b'
replacement = "***-**-$1"

[[rules]]
name = "email"
type = "regex-structured-data"
pattern = '[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}'
redact_fields = ["body|message"]
```

The optional `version` string is metadata. Unknown TOML fields are ignored.
OTA documents without top-level local rules are rejected. Every rule must set
`type` to `regex` or `regex-structured-data`; unsupported or omitted types reject
the entire ruleset, retaining any last-known-good rules. Field filters on `regex`
rules are still ignored with a warning.

The initial rules load completes before any tunnels open. Changed file contents
are compiled and applied atomically; unchanged content is not recompiled.
Reload errors retain the last-known-good rules. After three consecutive reload
failures, the connector exits; a successful read resets the failure count.
To disable redaction without changing the selected source, replace the file
with `rules = []`.

In Helm, set `redaction.enabled: true` and exactly one of
`redaction.rulesContent`, `redaction.existingConfigMap`, or
`redaction.existingSecret`. ConfigMaps and Secrets must contain the key
`redaction-rules.toml`. The legacy `redactionRules` inline string also enables
local redaction and cannot be combined with another source.
See the [chart examples](charts/traversal-connector/README.md#redaction-configuration).

#### Remote configuration (S3-backed OTA)

Enable OTA redaction using `TRAVERSAL_CONFIG_ENABLED=true`
(`configUpdates.enabled: true` in Helm). The URL is derived from the validated
controller's scheme, hostname and port, with the absolute path
`/v1/config/<connector-id>`. Controller path prefixes, credentials, queries and
fragments are not copied. There is no endpoint override or new network destination.
When OTA is enabled, the connector ID must be a canonical lowercase UUID,
matching the published object key.
The config HTTP client reuses controller mTLS, additional trust roots,
`EGRESS_PROXY_URL` and `TRAVERSAL_CONTROLLER_CONNECT_TO`; ambient proxy variables
are not used and redirects are refused.

| Variable | Default | Description |
|---|---|---|
| `TRAVERSAL_CONFIG_ENABLED` | `false` | Enable OTA polling and require a valid config document before startup. |
| `TRAVERSAL_CONFIG_REFRESH_INTERVAL` | `30s` | Poll interval, with up to 10% jitter; positive and at most 24h. |

When OTA is enabled, startup requires a valid config document **before opening
any tunnels**. Any initial fetch failure (including 404, 403, 5xx, network errors,
or invalid TOML/regexes) fails startup. Runtime errors or deletion retain the
last-known-good rules **in memory** and emit warnings; there is no persistent
local cache. After a restart, a missing or invalid config blocks startup again.
ETags avoid downloading unchanged configs; unchanged bodies do not recompile
rules. Responses are limited to 1 MiB and requests time out after 15 seconds.
To intentionally run without redaction while retaining OTA polling, publish a
valid empty-rules document; do not delete the object:

```toml
schema_version = 1
[redaction]
rules = []
```

If OTA configuration is not needed, leave `TRAVERSAL_CONFIG_ENABLED=false`
(the default); no remote config fetch is performed. Local-file redaction can
still be enabled independently.

Publish through `ingestion-configs` at
`connector/<env>/<certificate-org-id>/<connector-id>.toml`; the gateway proxies
`connector/<certificate-org-id>/<connector-id>.toml` from S3. Publish the document
before enabling OTA. Rules added to an initially empty document are picked up
by polling.

```toml
schema_version = 1

[redaction]
default_replacement = "[REDACTED]"

[[redaction.rules]]
name = "ssn"
type = "regex"
pattern = '\b\d{3}-\d{2}-(\d{4})\b'
replacement = "***-**-$1"

[[redaction.rules]]
name = "email"
type = "regex-structured-data"
pattern = '[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}'
redact_fields = ["body|message"]
```

Validate a document locally with `go run ./cmd/validate-config < config.toml`.
This uses the same parser and compiler as the running connector, including every
`hosts` expression even when the list also contains `.*`. CI/publication must
pin this validator to a reviewed connector revision. Invalid regexes (including
lookbehind) are rejected without printing rule contents.

Only schema version **1** is supported. Unknown keys, unsupported rule types,
missing `redaction.rules`, empty patterns and duplicate/empty names are rejected.
Rule field filters are only accepted for `regex-structured-data`. Metric
`connector.config_refresh_total` records bounded outcomes (`applied`, `unchanged`,
`error`); missing configs count as errors. `connector.config_rule_count` and
`connector.config_staleness_seconds` expose active rules and time since the last
successful fetch. Applied ETags are logged, not used as metric labels.

#### Switching configuration sources

To switch from local files to OTA, replace the local `version` header with
integer `schema_version = 1`, move `default_replacement` under `[redaction]`,
and rename `[[rules]]` tables to `[[redaction.rules]]`. Publish the document,
then remove the local settings and enable OTA in the same deployment update.
To switch to local files, reverse this document conversion, mount the file,
and disable OTA when enabling the local source. Source selection changes
require restarting the connector; rule updates within a source are polled.

#### Rule fields

Each rule requires:
- `name` — human-readable label used in log output.
- `type` — `"regex"` for byte-level redaction over the full response body, or `"regex-structured-data"` for per-field redaction over JSON response bodies. Unsupported types reject the entire remote update.
- `pattern` — a [RE2](https://github.com/google/re2/wiki/Syntax) regular expression.
- `replacement` *(optional)* — replacement string; use `$1`, `$2`, … to insert numbered capture groups from the pattern. Falls back to `default_replacement`.
- `hosts` *(optional)* — allowlist of RE2 patterns matched against the request **hostname** (port and userinfo stripped). The rule only fires when the hostname *fully* matches at least one pattern. Defaults to `[".*"]` (every host). Each pattern is anchored to the whole hostname, so `.*github\.com` matches `api.github.com` and `github.com` but **not** `github.com.evil.com`. Applies to both rule types. Listing `.*` anywhere in the list makes the rule match every host.

Matching follows DNS rather than byte equality, so one upstream cannot be reached under a spelling that carries a different rule set. Patterns are matched **case-insensitively** (`api\.github\.com` and `API\.GITHUB\.COM` both match `API.github.com`), and a single trailing dot on the requested hostname is ignored, since it only marks the name as already absolute (`github.com.` matches `github\.com`).

Because that dot is removed before matching, the hostname a pattern is compared against never ends in one. **Write the pattern without a trailing dot** — `github\.com`, not `github\.com\.` — since a pattern in the absolute form matches nothing. The pattern text is used exactly as written and is never rewritten, because RE2 can spell a trailing dot several ways and trimming one out would corrupt some patterns rather than fix them.

Case-insensitivity uses Unicode case folding, so it applies to non-ASCII hostnames too.

A non-ASCII hostname is converted to its IDNA ASCII (punycode) form before matching, because that is the form the connection itself uses. **Write the pattern in that ASCII form**, `xn--bcher-kva\.example` rather than `bücher\.example`, since a pattern in the Unicode form matches nothing. Both spellings of one name then select the same rules: a request to `bücher.example` and a request to `xn--bcher-kva.example` are the same host. As with the trailing dot, the pattern text is never converted in turn, because it is a regex and rewriting it could change what it matches. A hostname that is already ASCII is matched as it arrived and is not validated, so a name the conversion would reject, such as one carrying an underscore, still matches a pattern written for it.

`regex-structured-data` rules additionally accept:
- `redact_fields` — allowlist of pipe-delimited paths. When set, the rule only fires inside the matching subtrees.
- `skip_fields` — blocklist of pipe-delimited paths. When set, the rule never fires inside the matching subtrees.

Field names use pipe-delimited notation for nested objects: `body|message` matches the `body.message` field. Both filters may be set on the same rule; `skip_fields` wins on overlap.

**Scope is prefix-based on the path.** An entry `body` in `redact_fields` matches `body` itself plus everything underneath it (`body|message`, `body|x|y|z`, every array element under any of those). Once the walk enters an in-scope node, every primary leaf reachable from it is redacted — including map **keys**, map values, and array elements. Numbers are matched against their JSON textual form, so a credit-card or phone-number pattern catches values whether the upstream serialized them as strings or as JSON numbers; when a number actually matches, the field is rewritten as a string in the output (since the redacted text is no longer a valid number). Numbers that don't match are preserved as numbers, and booleans and `null` always pass through unchanged. The addressing key that *brought* you into the subtree lives at the parent scope, so e.g. with `redact_fields = ["data"]` the literal key `"data"` is not redacted, but every nested key inside it is.

How the two rule types are applied:

- **`regex` rules** always run byte-level over the full response body, regardless of `Content-Type` or whether the body parses as JSON. They have no concept of fields, so `redact_fields` / `skip_fields` don't apply.
- **`regex-structured-data` rules** fire per-field, honoring `redact_fields` / `skip_fields`, and require a JSON `Content-Type`. On any other content type they are **skipped entirely** (their field filters can't be honored on raw bytes, so applying them globally would cross the boundaries the filters were configured to enforce).

When a per-field rule is in scope *and* the response declares a JSON `Content-Type`, the body has to be exactly one complete JSON document, since that is the only way the configured fields can be located. A body that does not parse, or that carries anything beyond its first complete value, is **dropped**: the requester receives an error and `connector.response_refusals_total` records the reason `malformed_json`. Trailing content counts because parsing stops at the end of the first document, so forwarding such a body would silently shorten it to that first value.

A host no per-field rule covers is unaffected. With only `regex` rules in scope nothing needs parsing, so an unparseable body is still forwarded with byte-level redaction applied.

If you need a pattern to redact everywhere unconditionally, use `regex`. If you need per-field control, use `regex-structured-data` and ensure the upstream answers with one complete JSON document under a JSON `Content-Type`.

Rules are applied in order; each rule operates on the output of the previous one.

#### Compressed responses

Redaction patterns run against the plaintext of a response, so the connector has
to reach it. Request headers pass through untouched, which means an upstream may
answer in whatever coding the original caller negotiated, and the connector
handles the response by what actually came back:

| Response `Content-Encoding` | Behavior when a rule targets the host |
|---|---|
| absent, or `identity` | Redacted in place. |
| `gzip` | Decoded, redacted, and re-encoded as `gzip`. |
| anything else | **Dropped.** The response never reaches the requester. |

Anything else covers `deflate`, `zstd`, `br`, a stacked value such as
`gzip, br`, and a `gzip` stream that is corrupt, truncated, or expands past
`MAX_DECODED_RESPONSE_BODY_SIZE_MB`. Forwarding a body the connector cannot scan
would ship the very content the rules exist to remove, so there is no degraded
mode: the requester receives an `UNSUPPORTED_ENCODING` error, and
`connector.response_refusals_total` carries the reason. A `206 Partial Content`
is dropped for the same reason, because a pattern straddling the boundary
between two ranges is invisible to both.

Hosts no rule targets are unaffected: their responses are forwarded byte for
byte, in whatever coding they arrived, with nothing decoded or re-encoded.

Two response headers change when the connector rewrites a body. It sets
`X-Traversal-Redacted: true`, and it strips the headers that fingerprint the
original bytes (`ETag`, `Last-Modified`, `Content-MD5`, and the `Digest` family)
so a client cannot validate a redacted body against them. On hosts with rules it
also stops advertising `Accept-Ranges`, since a range request would be refused.

Regardless of rules, `connector.response_content_encoding_total` reports the
coding of every upstream response, so a deployment can see which of its
upstreams would be affected before configuring anything.

### Raw pipes (preview)

Raw pipes let Traversal reach databases, `kubectl exec`, git, and other
non-HTTP destinations through the connector. Each pipe carries a
Traversal-signed capability that the connector verifies before it dials.
Raw pipes are off by default; the Helm chart's `rawPipes` block turns them on.

The connector holds W outbound tunnels to Traversal, each a TLS connection
on which Traversal's tunnel gateway opens pipes as HTTP/2 streams.

- **Network.** Tunnels dial the host of `TRAVERSAL_CONTROLLER_URL` on port
  443, the same host and port the connector already reaches, with that host as
  TLS SNI and as the name the server certificate must carry. They trust the
  system roots plus `TLS_CA_BASE64`, as the connector's other connections do.
  They offer the TLS ALPN protocol `x-traversal-tunnel`; Traversal's edge
  router sends it to the tunnel gateway and everything else to the controller.
  A TLS-intercepting proxy breaks tunnels, and tunnels through
  `EGRESS_PROXY_URL` are not supported yet: such a connector keeps serving
  HTTP requests only and reports why.
- **Identity.** The connector's certificate must carry exactly one URI SAN, a
  Traversal SPIFFE ID: the org-scoped
  `spiffe://traversal.com/tenant/<org-uuid>/<org-name>` that Traversal issues,
  or a connector-scoped one ending `/connector/<connector-uuid>`, which must
  name `TRAVERSAL_CONNECTOR_ID`. `TRAVERSAL_CONNECTOR_ID` must be a lower-case
  UUID. The tunnel gateway binds each tunnel to the certificate's org, so a
  connector can never claim another org's tunnels. Within an org it trusts the
  connector ID the connector presents: any holder of the org's certificate
  can claim any connector ID in that org. This is a known limit until
  per-connector handshake tokens. Any other certificate keeps raw pipes off,
  with an error saying why.
- **Limits.** A pipe is reset when it has been open for
  `TRAVERSAL_RAW_PIPES_MAX_LIFETIME` or has moved no bytes either way for
  `TRAVERSAL_RAW_PIPES_IDLE_TIMEOUT`. The defaults, 4h and 15m, match
  Traversal's.
- **Readiness.** The pod is ready once a tunnel is up. Tunnels down for longer
  than a minute no longer hold it unready, so a network that blocks tunnels
  never blocks HTTP requests.

| Variable | Default | Description |
|---|---|---|
| `TRAVERSAL_RAW_PIPES` | `disabled` | `enabled` turns raw pipes on. |
| `TRAVERSAL_CAPABILITY_ROOTS` / `TRAVERSAL_CAPABILITY_ROOTS_FILE` | roots or keys required when enabled | PEM bundle (raw or base64) of Traversal's capability root `CERTIFICATE`s. A capability whose `x5c` certificate chains to one and names this connector's controller host is trusted. The chart renders it; see below. |
| `TRAVERSAL_CAPABILITY_KEYS` / `TRAVERSAL_CAPABILITY_KEYS_FILE` | roots or keys required when enabled | PEM bundle (raw or base64) of P-256 `PUBLIC KEY` blocks, each naming its kid in a `Key-ID` header: pinned keys, the earlier trust model. The chart renders it; see below. |
| `TRAVERSAL_CAPABILITY_ISSUER` | required with keys | The `iss` claim pinned-key capabilities must carry, `traversal-raw-tunnel/<environment>`. With roots alone it is unset: each environment's certificate names its issuer. |
| `TRAVERSAL_RAW_PIPES_MAX` | `200` | Most pipes open at once, from 1 to 4096. Opens beyond it are refused with `capacity`. |
| `TRAVERSAL_RAW_PIPES_MAX_LIFETIME` | `4h` | Longest a pipe stays open. `0s` turns the limit off. |
| `TRAVERSAL_RAW_PIPES_IDLE_TIMEOUT` | `15m` | Longest a pipe may move no bytes. `0s` turns the limit off. |
| `TRAVERSAL_TUNNEL_COUNT` | `2` | W, tunnels per connector pod, from 1 to 8. `TRAVERSAL_TUNNELS_PER_REPLICA`, its earlier name, is read when it is unset. |
| `TRAVERSAL_TUNNELS_CONNECT_TO` | (none) | `host:port` the tunnels dial instead of `<controller host>:443`, such as a PrivateLink endpoint. SNI and the certificate check still use the controller's host. |
| `TRAVERSAL_RAW_PIPES_EGRESS_PROXY` | (none) | `http://` or `https://` forward proxy raw pipes reach their destinations through, with HTTP CONNECT (credentials in the URL's user info). `EGRESS_PROXY_URL` and the proxy variables never route pipes. |
| `TRAVERSAL_RAW_PIPES_EGRESS_PROXY_RESOLVES` | `false` | `true` sends hostnames to that proxy, which resolves them and decides which addresses they reach. Off, hostnames are refused (`proxy_checks_delegated`) and only IP literals go through it. Set it only where the proxy refuses loopback, link-local and metadata addresses itself. |

Raw pipe metrics, all with closed label sets: `connector.raw_tunnels_active`,
`connector.raw_pipes_active`, `connector.raw_opens_total` (`result`, `reason`),
`connector.raw_pipe_closes_total` (`reason`), `connector.raw_pipe_bytes`
(`direction`), `connector.raw_pipe_duration`, `connector.raw_resets_total`
(`origin`), `connector.raw_drains_total`,
`connector.raw_capability_verifications_total` (`result`),
`connector.raw_capability_rejections_total` (`code`), and
`connector.raw_key_loads_total`.

#### Raw pipe signing keys

**Traversal's install command (`rawPipes.capabilityKey`).** The connector setup
page in Traversal writes the environment's issuer, key ID and public key into
the `helm install` command, as it does the controller URL, so a connector for
any Traversal environment installs with no chart release. Set, it replaces
that environment's packaged entry in `rawPipes.trustedKeys`. A key rotation is
then a `helm upgrade` with the next key in `rawPipes.capabilityKey.next`
first; roots (below) remove that step.

**Roots (`rawPipes.trustedRoots`).** The chart packages Traversal's
capability root certificates, the current one and, during a root rotation,
the next. Each environment's KMS signing key is certified by a root in a
short-lived environment certificate, which the Integration Proxy sends in
every capability's `x5c` header. The connector verifies that certificate
offline against the roots (no network lookups) and requires it to:

- chain to a packaged root and be within its validity;
- be a code-signing leaf for a P-256 key;
- name, as a DNS SAN, the host in `TRAVERSAL_CONTROLLER_URL`, which binds
  the capability to this connector's environment;
- name, as its one URI SAN, `spiffe://traversal.com/capability-issuer/<env>`,
  the capability's `iss` then being `traversal-raw-tunnel/<env>`.

A new Traversal environment, or a rotated environment key, needs no connector
change: Traversal issues the environment a certificate. A root rotation ships
the next root as `trustedRoots.next` in a chart release ahead of use. Refusals
are `unknown_key`. With roots, `rawPipes.environment` and `trustedKeys` can
stay empty; set both only while moving from pinned keys.

**Pinned keys (`rawPipes.trustedKeys`), the earlier model.**
Each Traversal environment signs capabilities with its own AWS KMS key. The
Helm chart packages every environment's public keys under
`rawPipes.trustedKeys.<environment>`, and `rawPipes.environment` selects one
set. Each key is a PEM `PUBLIC KEY` block, converted from the DER that KMS
`GetPublicKey` returns, and its kid is the bare KMS key ID, not the key's ARN
or an alias. The chart renders the selected keys into
`TRAVERSAL_CAPABILITY_KEYS` and derives the issuer,
`traversal-raw-tunnel/<environment>`. It refuses to render when the selected
environment has no current key, when `next` has only one of `kid` and
`publicKeyPEM`, when `next.kid` reuses `current.kid`, when a kid is an ARN or
alias, or when a key is not a PEM `PUBLIC KEY` block. The connector refuses
capabilities from any other issuer or key with `unknown_key` or
`invalid_capability`.

A rotation needs chart upgrades only, never a new connector binary:

1. Create the next KMS key, ship its public key as `next` in a chart release,
   and add it as the next key on the signer. Both sides now trust both keys.
2. Once connectors run that release, switch the signer to the next key.
3. After the longest capability lifetime, ship a chart release that promotes
   the next key to `current` and drops the old one.

Rotations reach a connector only through the chart's own `trustedKeys`, so do
not override them in your values, and do not upgrade with
`helm upgrade --reuse-values`, which keeps the previous release's keys; use
`--reset-then-reuse-values` to keep your overrides and take the new keys. At
startup the connector logs the key ids it trusts ("trusting capability keys")
and counts them in `connector.raw_key_loads_total`, so you can confirm the
fleet has the next key before the signer switches to it. Removing a key takes
effect only as each connector rolls out the new chart, so revoke a compromised
key on the signer first.

### Telemetry (OpenTelemetry)

The connector emits OpenTelemetry traces, metrics, and logs. Telemetry is the
only view Traversal has into a connector running inside a customer network, so
exporting all three signals is **required**. Outside `ENV_LEVEL=development`,
the connector refuses to start without it.

| Variable | Default | Description |
|---|---|---|
| `OTEL_SERVICE_NAME` | `traversal-connector` | Service name reported on all signals. |
| `OTEL_EXPORTER_OTLP_METRICS_ENDPOINT` | (required) | OTLP endpoint for metrics. Must be an `https://` URL. |
| `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` | (required) | OTLP endpoint for traces. Must be an `https://` URL. |
| `OTEL_EXPORTER_OTLP_LOGS_ENDPOINT` | (required) | OTLP endpoint for logs. Must be an `https://` URL. Logs also always go to stdout. |
| `OTEL_EXPORTER_OTLP_PROTOCOL` | (empty) | `grpc` or `http/protobuf` selects gRPC; `http/json` (or empty) selects HTTP. |
| `OTEL_EXPORTER_OTLP_CONNECT_TO` | (none) | Optional curl `--connect-to`-style `host:port` override shared by metrics, traces, and logs. Only the TCP connection destination changes; logical endpoint scheme and path, HTTP Host/gRPC `:authority`, TLS SNI, and certificate verification remain unchanged. All three endpoints must be reachable through the one socket. Cannot be combined with `EGRESS_PROXY_URL`; it is cleared when telemetry is disabled. |
| `TRAVERSAL_DISABLE_TELEMETRY` | `false` | Opts out of all telemetry export. **Strongly discouraged**. Traversal cannot diagnose or assist with issues in a deployment that reports nothing. |

Point all three endpoints either at a collector you operate or at the ingest
endpoints supplied with your deployment. Their shape follows the protocol: `grpc`
takes a host and port and names the signal in the request
(`https://collector.example.com:4317`), while `http/*` names it in the path
(`https://collector.example.com/v1/metrics`). The deployment chart fills these in;
a deployment that sets the environment directly has to provide them.

Connect-to overrides mirror curl `--connect-to` and support enterprise routing such as PrivateLink, split
DNS, service-mesh gateways, Kubernetes Services, and tunnels without weakening
TLS identity. For example, retain `https://telemetry.traversal.com:4317` as the
logical endpoint while connecting to
`telemetry-istio.traversal-gateways.svc.cluster.local:443`. With direct export,
the connector receives `OTEL_EXPORTER_OTLP_CONNECT_TO`. With the chart's
sidecar enabled, the connector continues exporting to loopback; the override is
applied only to Alloy's remote endpoint while Alloy preserves the logical gRPC
authority and TLS server name. Custom CA material remains additive to system
roots in both modes.

Startup rejects a telemetry configuration that would export nothing or export in
cleartext:

- All three endpoints must be set. A partially configured exporter looks healthy
  from the outside while leaving a gap nobody finds until an incident.
- Each must be an `https://` URL naming a host. A scheme-less `host:port` is
  rejected with `http://`, because the exporters read the scheme to decide
  whether to negotiate TLS at all.
- `http://` is accepted only on loopback: anything in `127.0.0.0/8`,
  `localhost`, `[::1]`, or the IPv4-mapped form. A telemetry forwarder colocated
  with the connector receives it. That hop never leaves the pod's network
  namespace. The forwarder holds the mTLS identity for the egress that does.

Two exemptions: `ENV_LEVEL=development`, and `TRAVERSAL_DISABLE_TELEMETRY=true`,
which drops any endpoints that were configured anyway so the opt-out is absolute.

Note what the first exemption means in practice. `ENV_LEVEL` defaults to
`development`, and only the published container image sets it to `production`
(see the `Dockerfile`), so a connector built from source or repackaged into a
custom image gets no telemetry enforcement at all until `ENV_LEVEL` says
otherwise. This mirrors the exemption that allows an `http://`
`TRAVERSAL_CONTROLLER_URL` in development.

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
