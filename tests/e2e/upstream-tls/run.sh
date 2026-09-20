#!/usr/bin/env bash
set -euo pipefail

readonly CHART_REF=oci://registry-1.docker.io/traversalext/traversal-connector-charts
readonly CHART_VERSION=0.8.4
readonly CHART_DIGEST=sha256:8fb0e334a9d456f02cb5570582ce657393a19d89b984457b1334e44c8292f48a

usage() {
  echo "Usage: $0 --image-ref <repository:tag|repository@sha256:digest>" >&2
}

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

image_ref=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --image-ref)
      [[ $# -ge 2 ]] || fail "--image-ref requires a value"
      image_ref=$2
      shift 2
      ;;
    *)
      usage
      fail "unknown argument: $1"
      ;;
  esac
done
[[ -n "$image_ref" ]] || { usage; fail "--image-ref is required"; }

if [[ "$image_ref" =~ ^(.+)@sha256:([[:xdigit:]]{64})$ ]]; then
  repository=${BASH_REMATCH[1]}
elif [[ "$image_ref" != *@* && "${image_ref##*/}" =~ ^[^:]+:[^:]+$ ]]; then
  repository=${image_ref%:*}
else
  fail "--image-ref must contain an explicit tag or sha256 digest: $image_ref"
fi

for tool in docker kind kubectl helm openssl go; do
  command -v "$tool" >/dev/null 2>&1 || fail "$tool is required"
done
docker info >/dev/null 2>&1 || fail "Docker daemon is not available"

suffix="$(date +%s)-$$-$RANDOM"
cluster="upstream-tls-${suffix}"
context="kind-${cluster}"
namespace=upstream-tls-e2e
controller_image="upstream-tls-controller:${suffix}"
connector_image="upstream-tls-connector:${suffix}"
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
  local case_dir="$artifacts/$1"
  mkdir -p "$case_dir"
  # Secrets are excluded so generated private keys never enter artifacts.
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
  local controller_pod=$1 case_token=$2 deadline=$((SECONDS + 180)) logs
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

helm_image_args=(
  --set-string image.repository=upstream-tls-connector
  --set-string "image.tag=$suffix"
  --set-string image.pullPolicy=Never
)

run_request_case() {
  local name=$1 verify=$2 ca_file=$3 expectation=$4
  local case_token="${name}-${suffix}" controller_pod
  echo "CASE $name"
  helm --kube-context "$context" -n "$namespace" uninstall connector >/dev/null 2>&1 || true
  kubectl --context "$context" -n "$namespace" set env deployment/controller \
    EXPECT="$expectation" CASE_TOKEN="$case_token" >/dev/null
  kubectl --context "$context" -n "$namespace" rollout status deployment/controller \
    --timeout=60s >/dev/null
  controller_pod=$(current_controller_pod)

  local args=(
    --namespace "$namespace"
    --set-string envName=upstream-tls-e2e
    --set-string envLevel=development
    --set-string controllerURL=http://controller:9080
    --set-string connectorID=upstream-tls-e2e
    --set-string maxTunnelsAllowed=1
    "${helm_image_args[@]}"
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
  helm --kube-context "$context" install connector "$chart_archive" \
    "${args[@]}" >"$artifacts/$name.helm.txt"
  if ! wait_for_controller_result "$controller_pod" "$case_token"; then
    capture_case "$name"
    fail "$name"
  fi
  capture_case "$name"
  echo "PASS $name"
}

run_malformed_case() {
  local name=07-verify-false-malformed-ca
  echo "CASE $name"
  helm --kube-context "$context" -n "$namespace" uninstall connector >/dev/null 2>&1 || true
  helm --kube-context "$context" install connector "$chart_archive" \
    --namespace "$namespace" \
    --set-string envName=upstream-tls-e2e \
    --set-string envLevel=development \
    --set-string controllerURL=http://controller:9080 \
    --set-string connectorID=upstream-tls-e2e \
    "${helm_image_args[@]}" \
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
      capture_case "$name"
      echo "PASS $name"
      return 0
    fi
    sleep 2
  done
  capture_case "$name"
  fail "$name: connector was not observably rejected at startup "\
    "(ready=$ready restarts=$restarts state=$state logs=$logs)"
}

create_ca_and_server_cert() {
  local name=$1 dns_name=$2
  cat >"$tmp_dir/$name.conf" <<EOF
[req]
distinguished_name=dn
prompt=no
[dn]
CN=$dns_name
[v3]
basicConstraints=critical,CA:false
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:$dns_name
EOF
  openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=$name-e2e-ca" \
    -keyout "$tmp_dir/$name-ca.key" -out "$tmp_dir/$name-ca.pem" >/dev/null 2>&1
  openssl req -newkey rsa:2048 -nodes -config "$tmp_dir/$name.conf" \
    -keyout "$tmp_dir/$name.key" -out "$tmp_dir/$name.csr" >/dev/null 2>&1
  openssl x509 -req -days 2 -in "$tmp_dir/$name.csr" -CA "$tmp_dir/$name-ca.pem" \
    -CAkey "$tmp_dir/$name-ca.key" -CAcreateserial -extfile "$tmp_dir/$name.conf" \
    -extensions v3 -out "$tmp_dir/$name.crt" >/dev/null 2>&1
}

create_ca_and_server_cert custom upstream-tls
create_ca_and_server_cert system system-upstream-tls
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=wrong-upstream-tls-e2e-ca \
  -keyout "$tmp_dir/wrong-ca.key" -out "$tmp_dir/wrong-ca.pem" >/dev/null 2>&1
printf '%s\n' 'this is not a PEM certificate' >"$tmp_dir/malformed-ca.pem"

echo "Verifying and pulling pinned release chart"
pull_output=$(helm pull "$CHART_REF" --version "$CHART_VERSION" --destination "$tmp_dir" 2>&1)
actual_chart_digest=$(printf '%s\n' "$pull_output" | awk '$1 == "Digest:" { print $2; exit }')
[[ "$actual_chart_digest" == "$CHART_DIGEST" ]] || \
  fail "chart digest $actual_chart_digest does not match $CHART_DIGEST"
chart_archive="$tmp_dir/traversal-connector-charts-${CHART_VERSION}.tgz"
[[ -f "$chart_archive" ]] || fail "helm pull did not create $chart_archive"

docker_arch=$(docker version --format '{{.Server.Arch}}')
case "$docker_arch" in
  amd64|arm64) ;;
  *) fail "unsupported Docker architecture: $docker_arch" ;;
esac
platform_digest=$(docker buildx imagetools inspect "$image_ref" --format \
  '{{if .Manifest.Manifests}}{{range .Manifest.Manifests}}{{if and .Platform (eq .Platform.Architecture "'"$docker_arch"'") (eq .Platform.OS "linux")}}{{.Digest}}{{end}}{{end}}{{else}}{{.Manifest.Digest}}{{end}}')
[[ "$platform_digest" == sha256:* ]] || \
  fail "could not resolve a linux/$docker_arch manifest from $image_ref"
platform_ref="${repository}@${platform_digest}"
echo "Pulling exact connector platform image $platform_ref"
docker pull "$platform_ref"
source_image="upstream-tls-source:${suffix}"
docker tag "$platform_ref" "$source_image"

echo "Building fixtures and creating kind cluster $cluster"
cp "$tmp_dir/system-ca.pem" "$tmp_dir/system-ca.crt"
cat >"$tmp_dir/connector.Dockerfile" <<EOF
FROM $source_image AS connector
FROM alpine:3.22.1@sha256:4bcff63911fcb4448bd4fdacec207030997caf25e9bea4045fa6c8c44de311d1 AS certificates
COPY system-ca.crt /tmp/system-ca.crt
RUN cat /tmp/system-ca.crt >> /etc/ssl/certs/ca-certificates.crt
FROM scratch
WORKDIR /app
COPY --from=certificates /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=connector /app/server /app/server
USER 65532:65532
ENV ENV_LEVEL=production
EXPOSE 8080
CMD ["./server"]
EOF
docker build -f "$tmp_dir/connector.Dockerfile" -t "$connector_image" "$tmp_dir"
mkdir -p "$tmp_dir/controller-build"
CGO_ENABLED=0 GOOS=linux GOARCH="$docker_arch" go build -trimpath \
  -o "$tmp_dir/controller-build/controller" ./tests/e2e/upstream-tls/controller
cat >"$tmp_dir/controller-build/Dockerfile" <<'EOF'
FROM scratch
COPY controller /controller
USER 65532:65532
ENTRYPOINT ["/controller"]
EOF
docker build -t "$controller_image" "$tmp_dir/controller-build"
kind create cluster --name "$cluster" --wait 90s
kind load docker-image "$controller_image" "$connector_image" --name "$cluster"
kubectl --context "$context" create namespace "$namespace"
kubectl --context "$context" -n "$namespace" create secret tls custom-upstream-tls-cert \
  --cert="$tmp_dir/custom.crt" --key="$tmp_dir/custom.key"
kubectl --context "$context" -n "$namespace" create secret tls system-upstream-tls-cert \
  --cert="$tmp_dir/system.crt" --key="$tmp_dir/system.key"

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
            - {name: EXPECT, value: success}
            - {name: CASE_TOKEN, value: initial}
          ports:
            - {name: controller, containerPort: 9080}
            - {name: custom-tls, containerPort: 8443}
            - {name: system-tls, containerPort: 8444}
          volumeMounts:
            - {name: custom-certs, mountPath: /certs/custom, readOnly: true}
            - {name: system-certs, mountPath: /certs/system, readOnly: true}
      volumes:
        - name: custom-certs
          secret: {secretName: custom-upstream-tls-cert}
        - name: system-certs
          secret: {secretName: system-upstream-tls-cert}
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
    - {name: https, port: 8443, targetPort: custom-tls}
---
apiVersion: v1
kind: Service
metadata:
  name: system-upstream-tls
spec:
  selector: {app: controller}
  ports:
    - {name: https, port: 8444, targetPort: system-tls}
EOF
kubectl --context "$context" -n "$namespace" apply -f "$tmp_dir/controller.yaml"
kubectl --context "$context" -n "$namespace" rollout status deployment/controller --timeout=60s

run_request_case 01-verify-true-empty-ca true "" unknown-authority
run_request_case 02-verify-false-empty-ca false "" success
run_request_case 03-verify-true-correct-ca true "$tmp_dir/custom-ca.pem" success
run_request_case 04-verify-true-custom-and-system-roots true "$tmp_dir/custom-ca.pem" \
  custom-and-system-success
run_request_case 05-verify-true-wrong-ca true "$tmp_dir/wrong-ca.pem" unknown-authority
run_request_case 06-verify-false-correct-ca false "$tmp_dir/custom-ca.pem" success
run_malformed_case

echo "PASS: all seven upstream TLS cases passed using $image_ref ($platform_digest)"
