#!/usr/bin/env bash
set -euo pipefail

chart_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
fixtures="$chart_dir/ci"
tmp_dir=$(mktemp -d)
trap 'rm -rf "$tmp_dir"' EXIT

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

assert_contains() {
  local file=$1 expected=$2
  grep -Fq -- "$expected" "$file" || fail "expected '$expected' in $file"
}

assert_not_contains() {
  local file=$1 unexpected=$2
  if grep -Fq -- "$unexpected" "$file"; then
    fail "did not expect '$unexpected' in $file"
  fi
}

render() {
  local name=$1 values=$2
  shift 2
  helm template "$name" "$chart_dir" -f "$values" "$@" > "$tmp_dir/$name.yaml"
}

assert_render_fails() {
  local name=$1 expected=$2
  shift 2
  if helm template "$name" "$chart_dir" "$@" >"$tmp_dir/$name.out" 2>"$tmp_dir/$name.err"; then
    fail "$name unexpectedly rendered"
  fi
  assert_contains "$tmp_dir/$name.err" "$expected"
}

render direct "$fixtures/direct-export-values.yaml"
assert_contains "$tmp_dir/direct.yaml" 'value: "https://telemetry.example.invalid/v1/metrics"'
assert_not_contains "$tmp_dir/direct.yaml" 'name: telemetry-sidecar'
assert_contains "$tmp_dir/direct.yaml" 'kind: ConfigMap'
assert_contains "$tmp_dir/direct.yaml" 'synthetic-token'
assert_contains "$tmp_dir/direct.yaml" 'image: "traversalext/traversal-connector:dev"'

render override "$fixtures/direct-export-values.yaml" --set-string image.tag=v9.8.7
assert_contains "$tmp_dir/override.yaml" 'image: "traversalext/traversal-connector:v9.8.7"'

render upstream-inline "$fixtures/direct-export-values.yaml" --set-string upstreamTLS.caPEM=synthetic-upstream-ca
assert_contains "$tmp_dir/upstream-inline.yaml" $'  name: upstream-inline-traversal-connector-upstream-tls\n'
assert_contains "$tmp_dir/upstream-inline.yaml" '  ca.crt: c3ludGhldGljLXVwc3RyZWFtLWNh'
assert_contains "$tmp_dir/upstream-inline.yaml" $'            - name: UPSTREAM_TLS_VERIFY\n              value: "true"'
assert_contains "$tmp_dir/upstream-inline.yaml" $'            - name: UPSTREAM_TLS_CA_BASE64\n              valueFrom:\n                secretKeyRef:\n                  name: upstream-inline-traversal-connector-upstream-tls\n                  key: ca.crt'

render upstream-existing "$fixtures/direct-export-values.yaml" --set-string upstreamTLS.existingSecret=supplied-upstream-ca --set upstreamTLS.verify=false
assert_contains "$tmp_dir/upstream-existing.yaml" $'            - name: UPSTREAM_TLS_VERIFY\n              value: "false"'
assert_contains "$tmp_dir/upstream-existing.yaml" $'            - name: UPSTREAM_TLS_CA_BASE64\n              valueFrom:\n                secretKeyRef:\n                  name: supplied-upstream-ca\n                  key: ca.crt'
assert_not_contains "$tmp_dir/upstream-existing.yaml" 'name: upstream-existing-traversal-connector-upstream-tls'

render sidecar "$fixtures/sidecar-values.yaml"
assert_contains "$tmp_dir/sidecar.yaml" 'name: telemetry-sidecar'
assert_contains "$tmp_dir/sidecar.yaml" 'name: sidecar-traversal-connector-telemetry-sidecar'
assert_contains "$tmp_dir/sidecar.yaml" 'name: ci-controller-tls'
assert_contains "$tmp_dir/sidecar.yaml" 'value: "http://127.0.0.1:4318/v1/metrics"'

render disabled "$fixtures/telemetry-disabled-values.yaml"
assert_contains "$tmp_dir/disabled.yaml" 'name: TRAVERSAL_DISABLE_TELEMETRY'
assert_contains "$tmp_dir/disabled.yaml" 'value: "true"'
assert_not_contains "$tmp_dir/disabled.yaml" 'OTEL_EXPORTER_OTLP_METRICS_ENDPOINT'
assert_not_contains "$tmp_dir/disabled.yaml" 'name: telemetry-sidecar'

common=(--set envName=ci --set controllerURL=https://controller.example.invalid --set connectorID=ci --set otel.sidecar.enabled=false)
render tls-one "$fixtures/direct-export-values.yaml" \
  --set-string controllerTLS.certPEM=certificate-one \
  --set-string controllerTLS.keyPEM=private-key \
  --set-string podAnnotations.example\\.com/owner=ci
render tls-two "$fixtures/direct-export-values.yaml" \
  --set-string controllerTLS.certPEM=certificate-two \
  --set-string controllerTLS.keyPEM=private-key
checksum_one=$(grep 'checksum/controller-tls:' "$tmp_dir/tls-one.yaml")
checksum_two=$(grep 'checksum/controller-tls:' "$tmp_dir/tls-two.yaml")
[[ "$checksum_one" != "$checksum_two" ]] || fail "controller TLS certificate change did not change the pod-template checksum"
assert_contains "$tmp_dir/tls-one.yaml" 'example.com/owner: ci'
assert_not_contains "$tmp_dir/direct.yaml" 'checksum/controller-tls:'

assert_render_fails missing-env 'envName is required' "${common[@]}" --set envName=
assert_render_fails missing-controller 'controllerURL is required' "${common[@]}" --set controllerURL=
assert_render_fails missing-id 'connectorID is required' "${common[@]}" --set connectorID=
assert_render_fails non-boolean 'disableTelemetry must be a boolean' "${common[@]}" --set-string disableTelemetry=false
assert_render_fails sidecar-no-tls 'otel.sidecar.enabled requires controllerTLS' -f "$fixtures/sidecar-values.yaml" --set controllerTLS.existingSecret=
assert_render_fails divergent-sidecar 'requires a single OTLP egress endpoint' -f "$fixtures/sidecar-values.yaml" --set otel.logsEndpoint=https://logs.example.invalid:4317
assert_render_fails invalid-endpoint 'must be an https:// URL' "${common[@]}" --set otel.logsEndpoint=not-a-url
assert_render_fails insecure-endpoint 'must be an https:// URL' "${common[@]}" --set otel.logsEndpoint=http://telemetry.example.invalid:4317

echo "All chart tests passed."
