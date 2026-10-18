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
  [[ "$(< "$file")" == *"$expected"* ]] || fail "expected '$expected' in $file"
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
assert_not_contains "$tmp_dir/direct.yaml" 'redaction-rules'
assert_not_contains "$tmp_dir/direct.yaml" 'REDACTION_RULES_FILE'
assert_contains "$tmp_dir/direct.yaml" 'name: TRAVERSAL_CONFIG_ENABLED'
assert_not_contains "$tmp_dir/direct.yaml" 'TRAVERSAL_CONFIG_ENDPOINT'
assert_contains "$tmp_dir/direct.yaml" 'image: "traversalext/traversal-connector:dev"'
assert_not_contains "$tmp_dir/direct.yaml" 'TRAVERSAL_CONTROLLER_CONNECT_TO'
assert_not_contains "$tmp_dir/direct.yaml" 'OTEL_EXPORTER_OTLP_CONNECT_TO'

render direct-connect-to "$fixtures/direct-export-values.yaml" \
  --set-string controllerConnectTo=edge-istio.traversal-gateways.svc.cluster.local:443 \
  --set-string otel.connectTo=telemetry-istio.traversal-gateways.svc.cluster.local:443
assert_contains "$tmp_dir/direct-connect-to.yaml" 'name: TRAVERSAL_CONTROLLER_CONNECT_TO'
assert_contains "$tmp_dir/direct-connect-to.yaml" 'value: "edge-istio.traversal-gateways.svc.cluster.local:443"'
assert_contains "$tmp_dir/direct-connect-to.yaml" 'name: OTEL_EXPORTER_OTLP_CONNECT_TO'

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

render upstream-file "$fixtures/direct-export-values.yaml" --set-string upstreamTLS.caFile=/vault/secrets/upstream-ca.crt
assert_contains "$tmp_dir/upstream-file.yaml" $'            - name: UPSTREAM_TLS_CA_FILE\n              value: "/vault/secrets/upstream-ca.crt"'
assert_not_contains "$tmp_dir/upstream-file.yaml" 'UPSTREAM_TLS_CA_BASE64'
assert_not_contains "$tmp_dir/upstream-file.yaml" 'name: upstream-file-traversal-connector-upstream-tls'
assert_not_contains "$tmp_dir/direct.yaml" 'UPSTREAM_TLS_CA_FILE'

render sidecar "$fixtures/sidecar-values.yaml"
assert_contains "$tmp_dir/sidecar.yaml" 'name: telemetry-sidecar'
assert_contains "$tmp_dir/sidecar.yaml" 'name: sidecar-traversal-connector-telemetry-sidecar'
assert_contains "$tmp_dir/sidecar.yaml" 'name: ci-controller-tls'
assert_contains "$tmp_dir/sidecar.yaml" 'value: "http://127.0.0.1:4318/v1/metrics"'

render sidecar-connect-to "$fixtures/sidecar-values.yaml" \
  --set-string otel.connectTo=telemetry-istio.traversal-gateways.svc.cluster.local:443
assert_not_contains "$tmp_dir/sidecar-connect-to.yaml" 'OTEL_EXPORTER_OTLP_CONNECT_TO'
assert_contains "$tmp_dir/sidecar-connect-to.yaml" 'value: "telemetry-istio.traversal-gateways.svc.cluster.local:443"'
assert_contains "$tmp_dir/sidecar-connect-to.yaml" 'value: "telemetry.example.invalid:4317"'
assert_contains "$tmp_dir/sidecar-connect-to.yaml" 'value: "telemetry.example.invalid"'
assert_contains "$tmp_dir/sidecar-connect-to.yaml" 'authority = sys.env("OTLP_EGRESS_AUTHORITY")'
assert_contains "$tmp_dir/sidecar-connect-to.yaml" 'server_name = sys.env("OTLP_EGRESS_SERVER_NAME")'
assert_contains "$tmp_dir/sidecar-connect-to.yaml" 'include_system_ca_certs_pool = true'

render disabled "$fixtures/telemetry-disabled-values.yaml"
assert_contains "$tmp_dir/disabled.yaml" 'name: TRAVERSAL_DISABLE_TELEMETRY'
assert_contains "$tmp_dir/disabled.yaml" 'value: "true"'
assert_not_contains "$tmp_dir/disabled.yaml" 'OTEL_EXPORTER_OTLP_METRICS_ENDPOINT'
assert_not_contains "$tmp_dir/disabled.yaml" 'name: telemetry-sidecar'
render disabled-ignored-connect-to "$fixtures/telemetry-disabled-values.yaml" \
  --set-string otel.connectTo=not-an-address
assert_not_contains "$tmp_dir/disabled-ignored-connect-to.yaml" 'OTEL_EXPORTER_OTLP_CONNECT_TO'

# The fixtures' synthetic capability trust, for scenarios built without them.
trust=(--set-string pipes.capabilityIssuer=traversal-raw-tunnel/ci --set-string "pipes.capabilityKeys=$(awk '$1 == "capabilityKeys:" { print $2 }' "$fixtures/direct-export-values.yaml")")
common=(--set envName=ci --set controllerURL=https://controller.example.invalid --set connectorID=aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee --set-string controllerTLS.existingSecret=ci-controller-tls --set otel.sidecar.enabled=false "${trust[@]}")
render tls-one "$fixtures/direct-export-values.yaml" --set-string controllerTLS.existingSecret= \
  --set-string controllerTLS.certPEM=certificate-one \
  --set-string controllerTLS.keyPEM=private-key \
  --set-string podAnnotations.example\\.com/owner=ci
render tls-two "$fixtures/direct-export-values.yaml" --set-string controllerTLS.existingSecret= \
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
# A 0.9.x values file upgraded to 0.10.x fails at render, not as a crash-looping
# rollout: 0.10.x needs a lower-case UUID connectorID and controllerTLS.
for id in ci AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE aaaaaaaabbbbccccddddeeeeeeeeeeee \
  ' aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee' '{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}'; do
  assert_render_fails non-uuid-id 'connectorID must be the lower-case UUID' "${common[@]}" --set-string "connectorID=$id"
done
assert_render_fails no-controller-tls 'controllerTLS is required' "${common[@]}" --set-string controllerTLS.existingSecret=
assert_render_fails empty-controller-tls 'controllerTLS is required' "${common[@]}" --set-string controllerTLS.existingSecret= \
  --set-string controllerTLS.certPEM= --set-string controllerTLS.keyPEM= --set-string controllerTLS.caPEM=
assert_render_fails controller-ca-only 'controllerTLS is required' "${common[@]}" --set-string controllerTLS.existingSecret= \
  --set-string controllerTLS.caPEM=ca
assert_render_fails controller-cert-only 'controllerTLS is required' "${common[@]}" --set-string controllerTLS.existingSecret= \
  --set-string controllerTLS.certPEM=certificate
render controller-tls-inline "$fixtures/direct-export-values.yaml" --set-string controllerTLS.existingSecret= \
  --set-string controllerTLS.certPEM=certificate --set-string controllerTLS.keyPEM=private-key
assert_contains "$tmp_dir/controller-tls-inline.yaml" 'name: controller-tls-inline-traversal-connector-controller-tls'
assert_contains "$tmp_dir/direct.yaml" $'            - name: TLS_CERT_BASE64\n              valueFrom:\n                secretKeyRef:\n                  name: ci-controller-tls'
assert_render_fails non-boolean 'disableTelemetry must be a boolean' "${common[@]}" --set-string disableTelemetry=false
assert_render_fails sidecar-no-tls 'otel.sidecar.enabled requires controllerTLS' -f "$fixtures/sidecar-values.yaml" --set controllerTLS.existingSecret=
assert_render_fails divergent-sidecar 'requires a single OTLP egress endpoint' -f "$fixtures/sidecar-values.yaml" --set otel.logsEndpoint=https://logs.example.invalid:4317
assert_render_fails invalid-endpoint 'must be an https:// URL' "${common[@]}" --set otel.logsEndpoint=not-a-url
assert_render_fails insecure-endpoint 'must be an https:// URL' "${common[@]}" --set otel.logsEndpoint=http://telemetry.example.invalid:4317
assert_render_fails missing-endpoint-host 'must be an https:// URL' "${common[@]}" --set-string otel.logsEndpoint=https://:4317
assert_render_fails nonnumeric-endpoint-port 'must be an https:// URL' "${common[@]}" --set-string otel.logsEndpoint=https://telemetry.example.invalid:not-a-port
assert_render_fails zero-endpoint-port 'port must be from 1 to 65535' "${common[@]}" --set-string otel.logsEndpoint=https://telemetry.example.invalid:0
assert_render_fails oversized-endpoint-port 'port must be from 1 to 65535' "${common[@]}" --set-string otel.logsEndpoint=https://telemetry.example.invalid:65536
assert_render_fails invalid-controller-connect-to 'controllerConnectTo must be a host:port' "${common[@]}" --set-string controllerConnectTo=https://route.internal:443
assert_render_fails invalid-otel-connect-to 'otel.connectTo port must be from 1 to 65535' "${common[@]}" --set-string otel.connectTo=route.internal:0
# 0.10.x cannot run tunnels through a forward proxy: refused at render, not
# at startup mid-rollout.
assert_render_fails proxy-unsupported 'proxyURL is not supported by connector 0.10.x yet; stay on 0.9.x' "${common[@]}" --set-string proxyURL=http://proxy.internal:3128

assert_render_fails upstream-file-and-pem 'upstreamTLS.caFile cannot be combined' "${common[@]}" --set-string upstreamTLS.caFile=/ca.crt --set-string upstreamTLS.caPEM=pem
assert_render_fails upstream-file-and-secret 'upstreamTLS.caFile cannot be combined' "${common[@]}" --set-string upstreamTLS.caFile=/ca.crt --set-string upstreamTLS.existingSecret=supplied-upstream-ca

local_values=(-f "$fixtures/direct-export-values.yaml" --set configUpdates.enabled=false --set redaction.enabled=true)
for source in rulesContent existingConfigMap existingSecret; do
  scenario="local-$(printf '%s' "$source" | tr '[:upper:]' '[:lower:]')"
  render "$scenario" "$fixtures/direct-export-values.yaml" \
    --set configUpdates.enabled=false --set redaction.enabled=true \
    --set-string "redaction.$source=local-rules" --set-string redaction.reloadInterval=2s
  output="$tmp_dir/$scenario.yaml"
  assert_contains "$output" $'            - name: REDACTION_RULES_FILE\n              value: /etc/traversal/redaction-rules.toml'
  assert_contains "$output" $'            - name: REDACTION_RELOAD_INTERVAL\n              value: "2s"'
  assert_contains "$output" $'              mountPath: /etc/traversal\n              readOnly: true'
  assert_contains "$output" $'              - key: redaction-rules.toml\n                path: redaction-rules.toml'
  assert_not_contains "$output" 'subPath:'
  assert_not_contains "$output" 'TRAVERSAL_CONFIG_ENABLED'
  if [[ "$source" == rulesContent ]]; then
    assert_contains "$output" $'  redaction-rules.toml: |\n    local-rules'
  else
    assert_not_contains "$output" 'kind: ConfigMap'
  fi
done
assert_contains "$tmp_dir/local-existingconfigmap.yaml" $'          configMap:\n            name: "local-rules"'
assert_contains "$tmp_dir/local-existingsecret.yaml" $'          secret:\n            secretName: "local-rules"'
assert_contains "$tmp_dir/local-rulescontent.yaml" $'          configMap:\n            name: "local-rulescontent-traversal-connector-redaction-rules"'

# The connector's redaction concurrency: unset, its default; set, the setting.
assert_not_contains "$tmp_dir/direct.yaml" 'TRAVERSAL_REDACTION_MAX_CONCURRENT'
render redaction-concurrency "$fixtures/direct-export-values.yaml" --set redaction.maxConcurrent=3
assert_contains "$tmp_dir/redaction-concurrency.yaml" $'            - name: TRAVERSAL_REDACTION_MAX_CONCURRENT\n              value: "3"'

render local-legacy "$fixtures/direct-export-values.yaml" \
  --set configUpdates.enabled=false --set-string redactionRules='rules=[]'
assert_contains "$tmp_dir/local-legacy.yaml" 'REDACTION_RULES_FILE'
assert_contains "$tmp_dir/local-legacy.yaml" $'  redaction-rules.toml: |\n    rules=[]'

assert_render_fails local-no-source 'requires exactly one source' "${local_values[@]}"
assert_render_fails local-non-boolean 'redaction.enabled must be a boolean' "${common[@]}" --set-string redaction.enabled=false
assert_render_fails local-disabled 'require redaction.enabled=true' \
  "${common[@]}" --set-string redaction.existingConfigMap=rules
assert_render_fails local-multiple-sources 'requires exactly one source' \
  "${local_values[@]}" --set-string redaction.rulesContent=rules --set-string redaction.existingSecret=rules
assert_render_fails both-sources 'mutually exclusive' \
  "${local_values[@]}" --set configUpdates.enabled=true --set-string redaction.rulesContent=rules
assert_render_fails both-legacy 'mutually exclusive' "${common[@]}" --set configUpdates.enabled=true --set-string redactionRules=rules

# Tunnels: each set pipes value becomes its setting; unset, none renders.
assert_not_contains "$tmp_dir/direct.yaml" 'TRAVERSAL_PIPES'
assert_not_contains "$tmp_dir/direct.yaml" 'MAX_TUNNELS_ALLOWED'
render raw "$fixtures/direct-export-values.yaml" \
  --set-string pipes.capabilityIssuer=traversal-raw-tunnel/ci \
  --set-string pipes.capabilityKeys=a2V5cw== \
  --set pipes.tunnelCount=4 --set pipes.egressProxyResolves=true \
  --set pipes.pipeMaxStreams=50 \
  --set-string 'pipes.forbiddenCIDRs=10.9.0.0/16\,fd00:1::/32'
for want in 'TRAVERSAL_CAPABILITY_ISSUER\n              value: "traversal-raw-tunnel/ci"' \
  'TRAVERSAL_CAPABILITY_KEYS\n              value: "a2V5cw=="' \
  'TRAVERSAL_TUNNELS_COUNT\n              value: "4"' \
  'TRAVERSAL_PIPES_MAX_STREAMS\n              value: "50"' \
  'TRAVERSAL_PIPES_EGRESS_PROXY_RESOLVES\n              value: "true"' \
  'TRAVERSAL_PIPES_FORBIDDEN_CIDRS\n              value: "10.9.0.0/16,fd00:1::/32"'; do
  assert_contains "$tmp_dir/raw.yaml" "$(printf "            - name: $want")"
done
# maxPipes unset renders no TRAVERSAL_PIPES_MAX (TRAVERSAL_PIPES_MAX_STREAMS is set).
if grep -qx -- '            - name: TRAVERSAL_PIPES_MAX' "$tmp_dir/raw.yaml"; then
  fail "did not expect TRAVERSAL_PIPES_MAX in $tmp_dir/raw.yaml"
fi
# Values from before the raw tunnel was the only one still upgrade: they are
# ignored, not refused.
render legacy-values "$fixtures/direct-export-values.yaml" --set pipes.enabled=false \
  --set-string maxTunnelsAllowed=4 \
  --set-string maxConcurrentRequests=4 --set-string reconnectInterval=1s --set-string maxBackoffDelay=1s
for legacy in TRAVERSAL_PIPES MAX_TUNNELS_ALLOWED MAX_CONCURRENT_REQUESTS RECONNECT_INTERVAL \
  MAX_BACKOFF_DELAY; do
  assert_not_contains "$tmp_dir/legacy-values.yaml" "$legacy"
done

# Capability roots: current, then next, as one PEM bundle; none, no setting.
assert_not_contains "$tmp_dir/raw.yaml" 'TRAVERSAL_CAPABILITY_ROOTS'
current_root=$'-----BEGIN CERTIFICATE-----\nY3VycmVudA==\n-----END CERTIFICATE-----\n'
next_root=$'-----BEGIN CERTIFICATE-----\nbmV4dA==\n-----END CERTIFICATE-----\n'
capability_roots() {
  awk '/name: TRAVERSAL_CAPABILITY_ROOTS/ { getline; gsub(/.*value: "|"$/, ""); print }' "$1" | base64 -d
}
no_keys=(--set-string pipes.capabilityKeys= --set-string pipes.capabilityIssuer=)
render raw-roots "$fixtures/direct-export-values.yaml" "${no_keys[@]}" \
  --set-string pipes.trustedRoots.current="$current_root"
[[ "$(capability_roots "$tmp_dir/raw-roots.yaml")" == "${current_root%$'\n'}" ]] ||
  fail "TRAVERSAL_CAPABILITY_ROOTS is not the current root"
assert_not_contains "$tmp_dir/raw-roots.yaml" 'TRAVERSAL_CAPABILITY_KEYS'
render raw-roots-rotation "$fixtures/direct-export-values.yaml" \
  --set-string pipes.trustedRoots.current="$current_root" \
  --set-string pipes.trustedRoots.next="$next_root"
[[ "$(capability_roots "$tmp_dir/raw-roots-rotation.yaml")" == "$current_root${next_root%$'\n'}" ]] ||
  fail "TRAVERSAL_CAPABILITY_ROOTS is not the current root then the next"

# Capability trust is refused at render when the connector would refuse it.
assert_render_fails no-capability-trust 'pipes.trustedRoots.current or pipes.capabilityKeys is required' \
  -f "$fixtures/direct-export-values.yaml" "${no_keys[@]}"
assert_render_fails next-root-only 'pipes.trustedRoots.current or pipes.capabilityKeys is required' \
  -f "$fixtures/direct-export-values.yaml" "${no_keys[@]}" --set-string pipes.trustedRoots.next="$next_root"
assert_render_fails keys-without-issuer 'pipes.capabilityIssuer is required with pipes.capabilityKeys' \
  -f "$fixtures/direct-export-values.yaml" --set-string pipes.capabilityIssuer=

# Config signing keys reach the connector only with OTA on.
render config-signed "$fixtures/direct-export-values.yaml" --set configUpdates.enabled=true \
  --set-string configUpdates.signingKeys=a2V5cw==
assert_contains "$tmp_dir/config-signed.yaml" "$(printf '            - name: TRAVERSAL_CONFIG_KEYS\n              value: "a2V5cw=="')"
render config-unsigned "$fixtures/direct-export-values.yaml" --set configUpdates.enabled=true
assert_not_contains "$tmp_dir/config-unsigned.yaml" 'TRAVERSAL_CONFIG_KEYS'
render config-keys-off "$fixtures/direct-export-values.yaml" --set configUpdates.enabled=false \
  --set-string configUpdates.signingKeys=a2V5cw==
assert_not_contains "$tmp_dir/config-keys-off.yaml" 'TRAVERSAL_CONFIG'

render config-disabled "$fixtures/direct-export-values.yaml" --set configUpdates.enabled=false
assert_not_contains "$tmp_dir/config-disabled.yaml" 'TRAVERSAL_CONFIG_ENABLED'
assert_not_contains "$tmp_dir/config-disabled.yaml" 'REDACTION_RULES_FILE'
assert_render_fails config-boolean 'configUpdates.enabled must be a boolean' "${common[@]}" --set-string configUpdates.enabled=false
assert_render_fails config-override 'configUpdates.endpoint is no longer supported' "${common[@]}" --set-string configUpdates.endpoint=https://other.example.invalid

# Every rendered container must satisfy the same security contract, including
# the optional telemetry sidecar; its writable queue remains on its own volume.
for scenario in direct sidecar disabled; do
  expected=1
  [[ "$scenario" == sidecar ]] && expected=2
  for field in 'runAsNonRoot: true' 'runAsUser: 65532' 'runAsGroup: 65532' \
    'allowPrivilegeEscalation: false' 'readOnlyRootFilesystem: true' 'mountPath: /tmp'; do
    actual=$(grep -Fc "$field" "$tmp_dir/$scenario.yaml")
    [[ "$actual" == "$expected" ]] || fail "$scenario: expected $expected occurrences of $field, got $actual"
  done
  assert_contains "$tmp_dir/$scenario.yaml" 'fsGroup: 65532'
  actual=$(grep -Fc 'type: RuntimeDefault' "$tmp_dir/$scenario.yaml")
  [[ "$actual" == "$((expected + 1))" ]] || fail "$scenario: missing pod or container seccomp profile"
  assert_contains "$tmp_dir/$scenario.yaml" $'          securityContext:\n            allowPrivilegeEscalation: false\n            capabilities:\n              drop:\n              - ALL\n            readOnlyRootFilesystem: true\n            runAsGroup: 65532\n            runAsNonRoot: true\n            runAsUser: 65532\n            seccompProfile:\n              type: RuntimeDefault\n          env:'
done
assert_contains "$tmp_dir/sidecar.yaml" 'mountPath: /var/lib/telemetry-sidecar'

# The pod's grace covers the connector's stop: up to 5 s of HTTP shutdown, 20 s
# of pipe drain, and 5 s of exporter shutdown.
assert_contains "$tmp_dir/direct.yaml" $'      terminationGracePeriodSeconds: 40\n'
render grace "$fixtures/direct-export-values.yaml" --set terminationGracePeriodSeconds=90
assert_contains "$tmp_dir/grace.yaml" $'      terminationGracePeriodSeconds: 90\n'

render security-overrides "$fixtures/direct-export-values.yaml" \
  --set podSecurityContext.runAsGroup=10001 \
  --set securityContext.runAsUser=10001
assert_contains "$tmp_dir/security-overrides.yaml" $'      securityContext:\n        fsGroup: 65532\n        runAsGroup: 10001\n        seccompProfile:\n          type: RuntimeDefault'
assert_contains "$tmp_dir/security-overrides.yaml" $'            readOnlyRootFilesystem: true\n            runAsGroup: 65532\n            runAsNonRoot: true\n            runAsUser: 10001\n            seccompProfile:\n              type: RuntimeDefault\n          env:'

echo "All chart tests passed."
