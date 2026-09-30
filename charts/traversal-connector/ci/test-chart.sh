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
  --set-string proxyURL=http://proxy.internal:3128 \
  --set-string otel.connectTo=not-an-address
assert_not_contains "$tmp_dir/disabled-ignored-connect-to.yaml" 'OTEL_EXPORTER_OTLP_CONNECT_TO'

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
assert_not_contains "$tmp_dir/direct.yaml" 'RAW_TUNNEL_ENABLED'
assert_not_contains "$tmp_dir/direct.yaml" 'terminationGracePeriodSeconds'

render raw-on "$fixtures/direct-export-values.yaml" \
  --set rawTunnel.enabled=true \
  --set-string rawTunnel.environment=ci \
  --set-string 'rawTunnel.allowedSubjects[0]=signer' \
  --set-string rawTunnel.trustedKeys.ci.current.kid=k1 \
  --set-string rawTunnel.trustedKeys.ci.current.publicKeyPEM="$(printf '%s\n' '-----BEGIN PUBLIC KEY-----' 'abc' '-----END PUBLIC KEY-----')"
assert_contains "$tmp_dir/raw-on.yaml" 'name: RAW_TUNNEL_ENABLED'
assert_contains "$tmp_dir/raw-on.yaml" $'            - name: RAW_TUNNEL_OPEN_TIMEOUT\n              value: "30s"'
assert_contains "$tmp_dir/raw-on.yaml" 'terminationGracePeriodSeconds: 45'
assert_contains "$tmp_dir/raw-on.yaml" 'value: "traversal-raw-tunnel/ci"'
assert_not_contains "$tmp_dir/raw-on.yaml" '-----BEGIN PUBLIC KEY-----'
assert_not_contains "$tmp_dir/raw-on.yaml" 'name: HTTPS_PROXY'
assert_not_contains "$tmp_dir/raw-on.yaml" 'name: NO_PROXY'
assert_not_contains "$tmp_dir/raw-on.yaml" 'RAW_TUNNEL_NEXT_KEY_ID'

current_pem="$(printf '%s\n' '-----BEGIN PUBLIC KEY-----' 'abc' '-----END PUBLIC KEY-----')"
next_pem="$(printf '%s\n' '-----BEGIN PUBLIC KEY-----' 'next' '-----END PUBLIC KEY-----')"
current_b64=$(printf '%s' "$current_pem" | base64 | tr -d '\n')
next_b64=$(printf '%s' "$next_pem" | base64 | tr -d '\n')
render raw-wired "$fixtures/direct-export-values.yaml" \
  --set rawTunnel.enabled=true \
  --set rawTunnel.maxTunnels=8 \
  --set rawTunnel.maxPipesPerTunnel=250 \
  --set rawTunnel.maxPipesPerPod=500 \
  --set-string rawTunnel.idleTimeout=45m \
  --set-string rawTunnel.maxLifetime=6h \
  --set-string rawTunnel.openTimeout=20s \
  --set-string rawTunnel.pingInterval=15s \
  --set rawTunnel.shutdownGraceSeconds=20 \
  --set rawTunnel.terminationGraceSeconds=40 \
  --set-string rawTunnel.rotationDeadline=10m \
  --set rawTunnel.streamWindowBytes=65536 \
  --set rawTunnel.outerWindowBytes=1048576 \
  --set-string rawTunnel.environment=wired \
  --set-string 'rawTunnel.allowedSubjects[0]=signer-a' \
  --set-string 'rawTunnel.allowedSubjects[1]=signer-b' \
  --set-string rawTunnel.trustedKeys.wired.current.kid=current-kid \
  --set-string rawTunnel.trustedKeys.wired.current.publicKeyPEM="$current_pem" \
  --set-string rawTunnel.trustedKeys.wired.next.kid=next-kid \
  --set-string rawTunnel.trustedKeys.wired.next.publicKeyPEM="$next_pem" \
  --set-string 'rawTunnel.forbiddenCIDRs[0]=10.0.0.0/8' \
  --set-string 'rawTunnel.forbiddenCIDRs[1]=192.168.0.0/16' \
  --set rawTunnel.allowDelegatedProxyChecks=true
assert_contains "$tmp_dir/raw-wired.yaml" $'            - name: RAW_TUNNEL_ENABLED\n              value: "true"'
assert_contains "$tmp_dir/raw-wired.yaml" $'            - name: RAW_TUNNEL_MAX_TUNNELS\n              value: "8"'
assert_contains "$tmp_dir/raw-wired.yaml" $'            - name: RAW_TUNNEL_MAX_PIPES_PER_TUNNEL\n              value: "250"'
assert_contains "$tmp_dir/raw-wired.yaml" $'            - name: RAW_TUNNEL_MAX_PIPES_PER_POD\n              value: "500"'
assert_contains "$tmp_dir/raw-wired.yaml" $'            - name: RAW_TUNNEL_IDLE_TIMEOUT\n              value: "45m"'
assert_contains "$tmp_dir/raw-wired.yaml" $'            - name: RAW_TUNNEL_MAX_LIFETIME\n              value: "6h"'
assert_contains "$tmp_dir/raw-wired.yaml" $'            - name: RAW_TUNNEL_OPEN_TIMEOUT\n              value: "20s"'
assert_contains "$tmp_dir/raw-wired.yaml" $'            - name: RAW_TUNNEL_PING_INTERVAL\n              value: "15s"'
assert_contains "$tmp_dir/raw-wired.yaml" $'            - name: RAW_TUNNEL_SHUTDOWN_GRACE_SECONDS\n              value: "20"'
assert_contains "$tmp_dir/raw-wired.yaml" $'            - name: RAW_TUNNEL_ROTATION_DEADLINE\n              value: "10m"'
assert_contains "$tmp_dir/raw-wired.yaml" $'            - name: RAW_TUNNEL_STREAM_WINDOW\n              value: "65536"'
assert_contains "$tmp_dir/raw-wired.yaml" $'            - name: RAW_TUNNEL_OUTER_WINDOW\n              value: "1048576"'
assert_contains "$tmp_dir/raw-wired.yaml" 'terminationGracePeriodSeconds: 40'
assert_contains "$tmp_dir/raw-wired.yaml" $'            - name: RAW_TUNNEL_ISSUER\n              value: "traversal-raw-tunnel/wired"'
assert_contains "$tmp_dir/raw-wired.yaml" $'            - name: RAW_TUNNEL_ALLOWED_SUBJECTS\n              value: "signer-a,signer-b"'
assert_contains "$tmp_dir/raw-wired.yaml" $'            - name: RAW_TUNNEL_CURRENT_KEY_ID\n              value: "current-kid"'
assert_contains "$tmp_dir/raw-wired.yaml" $'            - name: RAW_TUNNEL_CURRENT_PUBLIC_KEY\n              value: "'"$current_b64"'"'
assert_contains "$tmp_dir/raw-wired.yaml" $'            - name: RAW_TUNNEL_NEXT_KEY_ID\n              value: "next-kid"'
assert_contains "$tmp_dir/raw-wired.yaml" $'            - name: RAW_TUNNEL_NEXT_PUBLIC_KEY\n              value: "'"$next_b64"'"'
assert_contains "$tmp_dir/raw-wired.yaml" $'            - name: RAW_TUNNEL_FORBIDDEN_CIDRS\n              value: "10.0.0.0/8,192.168.0.0/16"'
assert_contains "$tmp_dir/raw-wired.yaml" $'            - name: RAW_TUNNEL_ALLOW_DELEGATED_PROXY_CHECKS\n              value: "true"'

assert_render_fails missing-env 'envName is required' "${common[@]}" --set envName=
assert_render_fails missing-controller 'controllerURL is required' "${common[@]}" --set controllerURL=
assert_render_fails missing-id 'connectorID is required' "${common[@]}" --set connectorID=
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
assert_render_fails proxy-controller-connect-to 'proxyURL cannot be combined' "${common[@]}" --set-string proxyURL=http://proxy.internal:3128 --set-string controllerConnectTo=route.internal:443
assert_render_fails proxy-otel-connect-to 'proxyURL cannot be combined' "${common[@]}" --set-string proxyURL=http://proxy.internal:3128 --set-string otel.connectTo=route.internal:4317
ci_pem=$(printf '%s\n' '-----BEGIN PUBLIC KEY-----' 'abc' '-----END PUBLIC KEY-----')
raw_enabled=(
  --set rawTunnel.enabled=true
  --set-string rawTunnel.environment=ci
  --set-string 'rawTunnel.allowedSubjects[0]=signer'
  --set-string rawTunnel.trustedKeys.ci.current.kid=k1
  --set-string rawTunnel.trustedKeys.ci.current.publicKeyPEM="$ci_pem"
)
assert_render_fails raw-no-environment 'rawTunnel.environment is required' "${common[@]}" --set rawTunnel.enabled=true
assert_render_fails raw-bad-environment 'rawTunnel.environment is required' "${common[@]}" "${raw_enabled[@]}" --set-string rawTunnel.environment=Prod/x
assert_render_fails raw-unpackaged-environment 'packages no signing key for that environment yet' "${common[@]}" "${raw_enabled[@]}" --set-string rawTunnel.environment=prod
assert_render_fails raw-half-next 'next needs both kid and publicKeyPEM' "${common[@]}" "${raw_enabled[@]}" \
  --set-string rawTunnel.trustedKeys.ci.next.kid=k2
assert_render_fails raw-pipe-cap 'maxPipesPerPod must be at least' "${common[@]}" "${raw_enabled[@]}" \
  --set rawTunnel.maxPipesPerTunnel=100 \
  --set rawTunnel.maxPipesPerPod=10
assert_render_fails raw-duplicate-key 'next.kid must differ from current.kid' "${common[@]}" "${raw_enabled[@]}" \
  --set-string rawTunnel.trustedKeys.ci.next.kid=k1 \
  --set-string rawTunnel.trustedKeys.ci.next.publicKeyPEM="$ci_pem"
assert_render_fails raw-arn-kid 'current.kid must be the bare KMS key ID' "${common[@]}" "${raw_enabled[@]}" \
  --set-string rawTunnel.trustedKeys.ci.current.kid=arn:aws:kms:us-west-2:1:key/k1
assert_render_fails raw-der-key 'next.publicKeyPEM must be a PEM PUBLIC KEY block' "${common[@]}" "${raw_enabled[@]}" \
  --set-string rawTunnel.trustedKeys.ci.next.kid=k2 \
  --set-string rawTunnel.trustedKeys.ci.next.publicKeyPEM=MFkwEw
assert_render_fails raw-null-keys 'packages no signing key for that environment yet' "${common[@]}" \
  --set rawTunnel.enabled=true --set-string rawTunnel.environment=ci --set-string 'rawTunnel.allowedSubjects[0]=signer' \
  --set rawTunnel.trustedKeys=null
assert_render_fails raw-grace 'shutdownGraceSeconds must be less' "${common[@]}" "${raw_enabled[@]}" \
  --set rawTunnel.shutdownGraceSeconds=45 \
  --set rawTunnel.terminationGraceSeconds=45
assert_render_fails raw-tunnels-ceiling 'maxTunnels must be from 1 to 64' "${common[@]}" "${raw_enabled[@]}" \
  --set rawTunnel.maxTunnels=65
assert_render_fails raw-pipes-tunnel-ceiling 'maxPipesPerTunnel must be from 1 to 2048' "${common[@]}" "${raw_enabled[@]}" \
  --set rawTunnel.maxPipesPerTunnel=2049 \
  --set rawTunnel.maxPipesPerPod=4096
assert_render_fails raw-pipes-pod-ceiling 'maxPipesPerPod must be from 1 to 4096' "${common[@]}" "${raw_enabled[@]}" \
  --set rawTunnel.maxPipesPerTunnel=100 \
  --set rawTunnel.maxPipesPerPod=4097

render raw-proxy "$fixtures/direct-export-values.yaml" "${common[@]}" "${raw_enabled[@]}" \
  --set-string rawTunnel.httpsProxy.existingSecret=raw-proxy \
  --set-string rawTunnel.httpsProxy.secretKey=url \
  --set-string rawTunnel.httpsProxy.noProxy=localhost
assert_contains "$tmp_dir/raw-proxy.yaml" $'            - name: HTTPS_PROXY\n              valueFrom:\n                secretKeyRef:\n                  name: "raw-proxy"\n                  key: "url"'
assert_contains "$tmp_dir/raw-proxy.yaml" $'            - name: NO_PROXY\n              value: "localhost"'
assert_not_contains "$tmp_dir/raw-proxy.yaml" 'name: telemetry-sidecar'
assert_render_fails raw-proxy-both 'rawTunnel.httpsProxy.url and rawTunnel.httpsProxy.existingSecret are mutually exclusive' "${common[@]}" "${raw_enabled[@]}" \
  --set-string rawTunnel.httpsProxy.url=http://proxy.internal:3128 \
  --set-string rawTunnel.httpsProxy.existingSecret=raw-proxy
assert_render_fails raw-grace-positive 'shutdownGraceSeconds must be positive' "${common[@]}" "${raw_enabled[@]}" \
  --set rawTunnel.shutdownGraceSeconds=0
assert_render_fails raw-ping-short 'rawTunnel.pingInterval must be at least 1s' "${common[@]}" "${raw_enabled[@]}" \
  --set-string rawTunnel.pingInterval=500ms
assert_render_fails raw-open-short 'rawTunnel.openTimeout must be at least 1s' "${common[@]}" "${raw_enabled[@]}" \
  --set-string rawTunnel.openTimeout=500ms
assert_render_fails raw-idle-short 'rawTunnel.idleTimeout must be at least 1s' "${common[@]}" "${raw_enabled[@]}" \
  --set-string rawTunnel.idleTimeout=500ms
assert_render_fails raw-life-short 'rawTunnel.maxLifetime must be at least 1s' "${common[@]}" "${raw_enabled[@]}" \
  --set-string rawTunnel.maxLifetime=500ms
assert_render_fails raw-idle-exceeds-life 'idleTimeout must not exceed' "${common[@]}" "${raw_enabled[@]}" \
  --set-string rawTunnel.idleTimeout=5h \
  --set-string rawTunnel.maxLifetime=1h
assert_render_fails raw-rotation-short 'rawTunnel.rotationDeadline must be at least 1s' "${common[@]}" "${raw_enabled[@]}" \
  --set-string rawTunnel.rotationDeadline=500ms
assert_render_fails raw-rotation-exceeds-life 'rotationDeadline must not exceed' "${common[@]}" "${raw_enabled[@]}" \
  --set-string rawTunnel.rotationDeadline=5h \
  --set-string rawTunnel.maxLifetime=1h
assert_render_fails raw-stream-window 'streamWindowBytes must be 0 or from 16KiB' "${common[@]}" "${raw_enabled[@]}" \
  --set rawTunnel.streamWindowBytes=1000

assert_render_fails upstream-file-and-pem 'upstreamTLS.caFile cannot be combined' "${common[@]}" --set-string upstreamTLS.caFile=/ca.crt --set-string upstreamTLS.caPEM=pem
assert_render_fails upstream-file-and-secret 'upstreamTLS.caFile cannot be combined' "${common[@]}" --set-string upstreamTLS.caFile=/ca.crt --set-string upstreamTLS.existingSecret=supplied-upstream-ca

echo "All chart tests passed."
