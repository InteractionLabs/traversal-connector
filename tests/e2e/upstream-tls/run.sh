#!/usr/bin/env bash
set -euo pipefail

readonly CHART_REF=oci://registry-1.docker.io/traversalext/traversal-connector-charts
readonly CHART_VERSION=0.8.4
readonly CHART_DIGEST=sha256:8fb0e334a9d456f02cb5570582ce657393a19d89b984457b1334e44c8292f48a
readonly IMAGE_REF=traversalext/traversal-connector:v0.8.4
readonly IMAGE_DIGEST=sha256:1b81b019a76e464e6a9de8d2f34416b85cdf4a3db8db6171fdf9e8412dd8d74c

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

for tool in docker kind kubectl helm openssl go; do
  command -v "$tool" >/dev/null 2>&1 || fail "$tool is required"
done
docker info >/dev/null 2>&1 || fail "Docker daemon is not available"

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
suffix="$(date +%s)-$$-$RANDOM"
cluster="upstream-tls-${suffix}"
context="kind-${cluster}"
namespace=upstream-tls-e2e
controller_image="upstream-tls-controller:${suffix}"
tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/upstream-tls-e2e.XXXXXX")
artifacts="$tmp_dir/artifacts"
mkdir -p "$artifacts"

cleanup() {
  status=$?
  trap - EXIT
  if [[ ${KEEP_CLUSTER:-0} == 1 ]]; then
    echo "KEEP_CLUSTER=1: retained kind cluster $cluster"
    echo "Artifacts and generated credentials: $tmp_dir"
    echo "Cleanup: kind delete cluster --name $cluster && rm -rf '$tmp_dir'"
  else
    kind delete cluster --name "$cluster" >/dev/null 2>&1 || true
    rm -rf "$tmp_dir"
  fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

capture_case() {
  local case_name=$1 case_dir="$artifacts/$1"
  mkdir -p "$case_dir"
  # Deliberately exclude Secrets: failure artifacts must never copy generated
  # private key material out of the ephemeral cluster.
  kubectl --context "$context" -n "$namespace" get all -o yaml \
    >"$case_dir/resources.yaml" 2>&1 || true
  kubectl --context "$context" -n "$namespace" describe pods \
    >"$case_dir/pods.describe.txt" 2>&1 || true
  kubectl --context "$context" -n "$namespace" logs deployment/controller --all-containers \
    >"$case_dir/controller.log" 2>&1 || true
  kubectl --context "$context" -n "$namespace" logs -l app.kubernetes.io/instance=connector \
    --all-containers --prefix >"$case_dir/connector.log" 2>&1 || true
  kubectl --context "$context" -n "$namespace" logs -l app.kubernetes.io/instance=connector \
    --all-containers --prefix --previous >"$case_dir/connector.previous.log" 2>&1 || true
  helm --kube-context "$context" -n "$namespace" get manifest connector \
    >"$case_dir/connector.rendered.yaml" 2>&1 || true
}

current_controller_pod() {
  local pod_hash pods
  pod_hash=$(kubectl --context "$context" -n "$namespace" get replicasets -l app=controller \
    --sort-by=.metadata.creationTimestamp \
    -o jsonpath='{.items[-1].metadata.labels.pod-template-hash}')
  [[ -n "$pod_hash" ]] || fail "current controller ReplicaSet has no pod-template-hash"
  pods=$(kubectl --context "$context" -n "$namespace" get pods \
    -l "app=controller,pod-template-hash=$pod_hash" \
    -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}')
  [[ $(printf '%s\n' "$pods" | awk 'NF { count++ } END { print count+0 }') == 1 ]] || \
    fail "expected exactly one current controller pod after rollout, got: $pods"
  printf '%s' "$pods"
}

wait_for_controller_result() {
  local controller_pod=$1 case_token=$2 deadline=$((SECONDS + 90)) logs
  while (( SECONDS < deadline )); do
    logs=$(kubectl --context "$context" -n "$namespace" logs "pod/$controller_pod" 2>&1 || true)
    if [[ "$logs" == *"CASE_PASS: $case_token:"* ]]; then
      return 0
    fi
    if [[ "$logs" == *"CASE_FAIL: $case_token:"* ]]; then
      echo "$logs" >&2
      return 1
    fi
    sleep 2
  done
  echo "controller did not report a result before timeout" >&2
  return 1
}

run_request_case() {
  local name=$1 verify=$2 ca_file=$3 expectation=$4
  local case_token="${name}-${suffix}" controller_pod
  echo "CASE $name"
  helm --kube-context "$context" -n "$namespace" uninstall connector >/dev/null 2>&1 || true
  kubectl --context "$context" -n "$namespace" set env deployment/controller \
    EXPECT="$expectation" CASE_TOKEN="$case_token" >/dev/null
  kubectl --context "$context" -n "$namespace" rollout status deployment/controller --timeout=60s >/dev/null
  controller_pod=$(current_controller_pod)

  local args=(
    --namespace "$namespace"
    --set-string envName=upstream-tls-e2e
    --set-string envLevel=development
    --set-string controllerURL=http://controller:9080
    --set-string connectorID=upstream-tls-e2e
    --set-string maxTunnelsAllowed=1
    --set-string image.repository=traversalext/traversal-connector
    --set-string image.tag=v0.8.4
    --set-string image.pullPolicy=IfNotPresent
    --set disableTelemetry=true
    --set otel.sidecar.enabled=false
    --set replicaCount=1
    --set upstreamTLS.verify="$verify"
    --set probes.readiness.enabled=false
    --set resources.requests.cpu=10m
    --set resources.requests.memory=32Mi
    --set resources.limits.cpu=250m
    --set resources.limits.memory=256Mi
  )
  if [[ -n "$ca_file" ]]; then
    args+=(--set-file "upstreamTLS.caPEM=$ca_file")
  fi
  helm --kube-context "$context" install connector "$CHART_REF" \
    --version "$CHART_VERSION" "${args[@]}" >"$artifacts/$name.helm.txt"
  if ! wait_for_controller_result "$controller_pod" "$case_token"; then
    capture_case "$name"
    fail "$name"
  fi
  echo "PASS $name"
}

run_malformed_case() {
  local name=06-verify-false-malformed-ca
  echo "CASE $name"
  helm --kube-context "$context" -n "$namespace" uninstall connector >/dev/null 2>&1 || true
  helm --kube-context "$context" install connector "$CHART_REF" --version "$CHART_VERSION" \
    --namespace "$namespace" \
    --set-string envName=upstream-tls-e2e \
    --set-string envLevel=development \
    --set-string controllerURL=http://controller:9080 \
    --set-string connectorID=upstream-tls-e2e \
    --set-string image.repository=traversalext/traversal-connector \
    --set-string image.tag=v0.8.4 \
    --set disableTelemetry=true \
    --set otel.sidecar.enabled=false \
    --set replicaCount=1 \
    --set upstreamTLS.verify=false \
    --set probes.startup.enabled=false \
    --set probes.liveness.enabled=false \
    --set probes.readiness.enabled=false \
    --set-file "upstreamTLS.caPEM=$tmp_dir/malformed-ca.pem" \
    >"$artifacts/$name.helm.txt"

  local deadline=$((SECONDS + 60)) logs="" current_logs previous_logs pod ready restarts state
  while (( SECONDS < deadline )); do
    pod=$(kubectl --context "$context" -n "$namespace" get pods \
      -l app.kubernetes.io/instance=connector \
      -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
    if [[ -z "$pod" ]]; then
      sleep 2
      continue
    fi
    current_logs=$(kubectl --context "$context" -n "$namespace" logs "pod/$pod" \
      --container connector 2>&1 || true)
    previous_logs=$(kubectl --context "$context" -n "$namespace" logs "pod/$pod" \
      --container connector --previous 2>&1 || true)
    logs="$current_logs
$previous_logs"
    ready=$(kubectl --context "$context" -n "$namespace" get pod "$pod" \
      -o jsonpath='{.status.containerStatuses[?(@.name=="connector")].ready}' 2>/dev/null || true)
    restarts=$(kubectl --context "$context" -n "$namespace" get pod "$pod" \
      -o jsonpath='{.status.containerStatuses[?(@.name=="connector")].restartCount}' 2>/dev/null || true)
    state=$(kubectl --context "$context" -n "$namespace" get pod "$pod" \
      -o jsonpath='{.status.containerStatuses[?(@.name=="connector")].state}' 2>/dev/null || true)
    if [[ "$logs" == *"failed to parse upstream CA certificate"* &&
      "$ready" == false && "$restarts" =~ ^[1-9][0-9]*$ &&
      ("$state" == *'"waiting"'* || "$state" == *'"terminated"'*) ]]; then
      echo "PASS $name"
      return 0
    fi
    sleep 2
  done
  capture_case "$name"
  fail "$name: connector was not observably rejected at startup "\
    "(ready=$ready restarts=$restarts state=$state logs=$logs)"
}

cat >"$tmp_dir/cert.conf" <<'EOF'
[req]
distinguished_name=dn
prompt=no
[dn]
CN=upstream-tls
[v3]
basicConstraints=critical,CA:false
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:upstream-tls
EOF

openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=upstream-tls-e2e-ca \
  -keyout "$tmp_dir/ca.key" -out "$tmp_dir/ca.pem" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -config "$tmp_dir/cert.conf" \
  -keyout "$tmp_dir/tls.key" -out "$tmp_dir/tls.csr" >/dev/null 2>&1
openssl x509 -req -days 2 -in "$tmp_dir/tls.csr" -CA "$tmp_dir/ca.pem" \
  -CAkey "$tmp_dir/ca.key" -CAcreateserial -extfile "$tmp_dir/cert.conf" -extensions v3 \
  -out "$tmp_dir/tls.crt" >/dev/null 2>&1
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=wrong-upstream-tls-e2e-ca \
  -keyout "$tmp_dir/wrong-ca.key" -out "$tmp_dir/wrong-ca.pem" >/dev/null 2>&1
printf '%s\n' 'this is not a PEM certificate' >"$tmp_dir/malformed-ca.pem"

echo "Verifying pinned release digests"
pull_output=$(helm pull "$CHART_REF" --version "$CHART_VERSION" --destination "$tmp_dir" 2>&1)
actual_chart_digest=$(printf '%s\n' "$pull_output" | awk '$1 == "Digest:" { print $2; exit }')
[[ -n "$actual_chart_digest" ]] || fail "helm pull did not report an OCI digest: $pull_output"
[[ "$actual_chart_digest" == "$CHART_DIGEST" ]] || \
  fail "chart digest $actual_chart_digest does not match $CHART_DIGEST"
chart_archive="$tmp_dir/traversal-connector-charts-${CHART_VERSION}.tgz"
[[ -f "$chart_archive" ]] || fail "helm pull did not create $chart_archive"
actual_image_digest=$(docker buildx imagetools inspect "$IMAGE_REF" | \
  awk '$1 == "Digest:" { print $2; exit }')
[[ -n "$actual_image_digest" ]] || fail "image inspection did not report a digest for $IMAGE_REF"
[[ "$actual_image_digest" == "$IMAGE_DIGEST" ]] || \
  fail "image digest $actual_image_digest does not match $IMAGE_DIGEST"

echo "Building controller and creating kind cluster $cluster"
docker_arch=$(docker version --format '{{.Server.Arch}}')
case "$docker_arch" in
  amd64|arm64) ;;
  *) fail "unsupported Docker architecture: $docker_arch" ;;
esac
mkdir -p "$tmp_dir/controller-build"
CGO_ENABLED=0 GOOS=linux GOARCH="$docker_arch" go build -trimpath \
  -o "$tmp_dir/controller-build/controller" ./tests/e2e/upstream-tls/controller
docker build -f "$repo_root/tests/e2e/upstream-tls/controller/Dockerfile" \
  -t "$controller_image" "$tmp_dir/controller-build"
kind create cluster --name "$cluster" --wait 90s
kind load docker-image "$controller_image" --name "$cluster"
kubectl --context "$context" create namespace "$namespace"
kubectl --context "$context" -n "$namespace" create secret tls upstream-tls-cert \
  --cert="$tmp_dir/tls.crt" --key="$tmp_dir/tls.key"

cat >"$tmp_dir/controller.yaml" <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: controller
spec:
  replicas: 1
  selector:
    matchLabels: {app: controller}
  template:
    metadata:
      labels: {app: controller}
    spec:
      containers:
        - name: controller
          image: $controller_image
          imagePullPolicy: Never
          env:
            - name: EXPECT
              value: success
            - name: CASE_TOKEN
              value: initial
          ports:
            - {name: controller, containerPort: 9080}
            - {name: upstream-tls, containerPort: 8443}
          volumeMounts:
            - {name: certs, mountPath: /certs, readOnly: true}
      volumes:
        - name: certs
          secret: {secretName: upstream-tls-cert}
---
apiVersion: v1
kind: Service
metadata:
  name: controller
spec:
  selector: {app: controller}
  ports:
    - {name: h2c, port: 9080, targetPort: controller}
---
apiVersion: v1
kind: Service
metadata:
  name: upstream-tls
spec:
  selector: {app: controller}
  ports:
    - {name: https, port: 8443, targetPort: upstream-tls}
EOF
kubectl --context "$context" -n "$namespace" apply -f "$tmp_dir/controller.yaml"
kubectl --context "$context" -n "$namespace" rollout status deployment/controller --timeout=60s

run_request_case 01-verify-true-empty-ca true "" unknown-authority
run_request_case 02-verify-false-empty-ca false "" success
run_request_case 03-verify-true-correct-ca true "$tmp_dir/ca.pem" success
run_request_case 04-verify-true-wrong-ca true "$tmp_dir/wrong-ca.pem" unknown-authority
run_request_case 05-verify-false-correct-ca false "$tmp_dir/ca.pem" success
run_malformed_case

echo "PASS: all six released upstream TLS cases passed"
