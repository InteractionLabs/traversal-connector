#!/usr/bin/env bash
set -euo pipefail

# Transitional install validator. Bash is load-bearing here only because no
# off-the-shelf tool handles this chart's constraints (pods that are Running
# but never Ready without a controller tunnel, a scratch image with no exec
# surface, and gating on a not-yet-tagged signed digest). Replace this script
# with the deploy system's install-validation flow once that exists.

usage() {
  echo "Usage: $0 <chart.tgz> [--image-ref <repository:tag|repository@sha256:digest>]" >&2
}

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

require_tool() {
  local tool=$1 hint=${2:-}
  if ! command -v "$tool" >/dev/null 2>&1; then
    if [[ -n "$hint" ]]; then
      fail "$tool is required ($hint)"
    fi
    fail "$tool is required"
  fi
}

chart=${1:-}
[[ -n "$chart" ]] || { usage; exit 2; }
shift

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

[[ -f "$chart" ]] || fail "chart archive does not exist: $chart"
require_tool kind "install from https://kind.sigs.k8s.io/docs/user/quick-start/#installation"
require_tool kubectl
require_tool helm
require_tool docker
require_tool curl
require_tool openssl
docker info >/dev/null 2>&1 || fail "Docker daemon is not available"

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
values="$repo_root/charts/traversal-connector/ci/install-values.yaml"
[[ -f "$values" ]] || fail "install validation values not found: $values"

suffix="$(date +%s)-$$-$RANDOM"
cluster="chart-validation-${suffix}"
context="kind-chart-validation-${suffix}"
namespace="chart-validation"
release="chart-validation"
tmp_dir=$(mktemp -d)
port_forward_pid=""
local_port=$((20000 + RANDOM % 20000))

cleanup() {
  status=$?
  trap - EXIT
  if [[ -n "$port_forward_pid" ]]; then
    kill "$port_forward_pid" >/dev/null 2>&1 || true
    wait "$port_forward_pid" >/dev/null 2>&1 || true
  fi
  kind delete cluster --name "$cluster" >/dev/null 2>&1 || true
  rm -rf "$tmp_dir"
  if [[ $status -eq 0 ]]; then
    echo "PASS: chart installed, served /healthz, and upgraded successfully"
  else
    echo "FAIL: chart install validation failed" >&2
  fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -subj /CN=chart-install-validation \
  -keyout "$tmp_dir/tls.key" -out "$tmp_dir/tls.crt" >/dev/null 2>&1

echo "Creating disposable kind cluster $cluster"
if [[ -n "${KIND_NODE_IMAGE:-}" ]]; then
  kind create cluster --name "$cluster" --image "$KIND_NODE_IMAGE" --wait 90s
else
  kind create cluster --name "$cluster" --wait 90s
fi

image_args=()
expected_image=""
if [[ -n "$image_ref" ]]; then
  if [[ "$image_ref" == *@sha256:* ]]; then
    # The chart's image field is repository:tag, so a digest cannot be inserted
    # directly. The digest names a multi-platform index whose attestation
    # manifests break `kind load`, so resolve the runner's platform manifest,
    # pull that single manifest, and load it under a local tag.
    echo "Resolving platform manifest for $image_ref"
    arch=$(docker version --format '{{.Server.Arch}}')
    repository=${image_ref%%@*}
    platform_digest=$(docker buildx imagetools inspect "$image_ref" --format \
      '{{range .Manifest.Manifests}}{{if and .Platform (eq .Platform.Architecture "'"$arch"'") (eq .Platform.OS "linux")}}{{.Digest}}{{end}}{{end}}')
    [[ "$platform_digest" == sha256:* ]] || fail "could not resolve a linux/$arch manifest from $image_ref"
    echo "Pulling platform image ${repository}@${platform_digest}"
    docker pull "${repository}@${platform_digest}"
    digest=${platform_digest#sha256:}
    local_repository=traversal-chart-validation
    local_tag="sha-${digest:0:16}"
    expected_image="${local_repository}:${local_tag}"
    docker tag "${repository}@${platform_digest}" "$expected_image"
    image_args=(
      --set-string "image.repository=$local_repository"
      --set-string "image.tag=$local_tag"
      --set-string image.pullPolicy=Never
    )
    kind load docker-image "$expected_image" --name "$cluster"
  else
    # A public tag is pulled by the kind node itself; loading a locally pulled
    # multi-platform image trips over attestation manifests kind cannot import.
    image_tail=${image_ref##*/}
    [[ "$image_tail" == *:* ]] || fail "tagged --image-ref must include an explicit tag"
    expected_image=$image_ref
    image_args=(
      --set-string "image.repository=${image_ref%:*}"
      --set-string "image.tag=${image_ref##*:}"
      --set-string image.pullPolicy=IfNotPresent
    )
  fi
fi

helm_args=(
  --namespace "$namespace"
  --create-namespace
  -f "$values"
  --set-file controllerTLS.certPEM="$tmp_dir/tls.crt"
  --set-file controllerTLS.keyPEM="$tmp_dir/tls.key"
  "${image_args[@]}"
)

deployment="${release}-traversal-connector"
selector="app.kubernetes.io/instance=$release,app.kubernetes.io/name=traversal-connector-charts"

wait_for_running_connector() {
  local requested_pod=${1:-} deadline=$((SECONDS + 120)) pod phase started restarts
  while (( SECONDS < deadline )); do
    if [[ -n "$requested_pod" ]]; then
      pod=$requested_pod
    else
      pod=$(kubectl --context "$context" -n "$namespace" get pods -l "$selector" \
        -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
    fi
    if [[ -n "$pod" ]]; then
      phase=$(kubectl --context "$context" -n "$namespace" get pod "$pod" -o jsonpath='{.status.phase}' 2>/dev/null || true)
      started=$(kubectl --context "$context" -n "$namespace" get pod "$pod" \
        -o jsonpath='{.status.containerStatuses[?(@.name=="connector")].started}' 2>/dev/null || true)
      if [[ "$phase" == Running && "$started" == true ]]; then
        restarts=$(kubectl --context "$context" -n "$namespace" get pod "$pod" \
          -o jsonpath='{.status.containerStatuses[?(@.name=="connector")].restartCount}')
        [[ "$restarts" == 0 ]] || fail "connector restarted $restarts time(s) before validation"
        printf '%s' "$pod"
        return 0
      fi
    fi
    sleep 2
  done
  kubectl --context "$context" -n "$namespace" get pods -l "$selector" -o wide >&2 || true
  kubectl --context "$context" -n "$namespace" describe pods -l "$selector" >&2 || true
  fail "connector container did not start in a Running pod"
}

echo "Installing packaged chart"
helm --kube-context "$context" install "$release" "$chart" "${helm_args[@]}"
pod=$(wait_for_running_connector)

rendered_image=$(kubectl --context "$context" -n "$namespace" get deployment "$deployment" \
  -o jsonpath='{.spec.template.spec.containers[?(@.name=="connector")].image}')
if [[ -z "$expected_image" ]]; then
  expected_image=$rendered_image
fi
[[ "$rendered_image" == "$expected_image" ]] || \
  fail "rendered connector image $rendered_image does not match $expected_image"

# Readiness intentionally remains false without a live controller tunnel. Probe
# liveness through the host instead; the production image is scratch and has no
# shell or HTTP client for kubectl exec.
kubectl --context "$context" -n "$namespace" port-forward "pod/$pod" "$local_port:8080" >"$tmp_dir/port-forward.log" 2>&1 &
port_forward_pid=$!
health_ok=false
for _ in {1..30}; do
  if curl --fail --silent --show-error "http://127.0.0.1:$local_port/healthz" >/dev/null 2>&1; then
    health_ok=true
    break
  fi
  kill -0 "$port_forward_pid" >/dev/null 2>&1 || break
  sleep 1
done
[[ "$health_ok" == true ]] || {
  cat "$tmp_dir/port-forward.log" >&2
  fail "/healthz did not return HTTP 200"
}
kill "$port_forward_pid" >/dev/null 2>&1 || true
wait "$port_forward_pid" >/dev/null 2>&1 || true
port_forward_pid=""

sleep 10
restarts=$(kubectl --context "$context" -n "$namespace" get pod "$pod" \
  -o jsonpath='{.status.containerStatuses[?(@.name=="connector")].restartCount}')
[[ "$restarts" == 0 ]] || fail "connector restarted during the observation window"

old_uid=$(kubectl --context "$context" -n "$namespace" get pod "$pod" -o jsonpath='{.metadata.uid}')
echo "Upgrading the same chart archive with a changed pod annotation"
helm --kube-context "$context" upgrade --install "$release" "$chart" "${helm_args[@]}" \
  --set-string "podAnnotations.installValidation=$suffix"

deadline=$((SECONDS + 120))
new_pod=""
while (( SECONDS < deadline )); do
  candidate=$(kubectl --context "$context" -n "$namespace" get pods -l "$selector" \
    -o jsonpath='{range .items[*]}{.metadata.uid}{" "}{.metadata.name}{"\n"}{end}' 2>/dev/null \
    | awk -v old="$old_uid" '$1 != old { print $2; exit }')
  if [[ -n "$candidate" ]]; then
    new_pod=$candidate
    break
  fi
  sleep 2
done
[[ -n "$new_pod" ]] || fail "upgrade did not replace the pod"
pod=$(wait_for_running_connector "$new_pod")
[[ "$pod" == "$new_pod" ]] || fail "unexpected pod became active after upgrade: $pod"
kubectl --context "$context" -n "$namespace" rollout status "deployment/$deployment" --timeout=120s

upgraded_image=$(kubectl --context "$context" -n "$namespace" get deployment "$deployment" \
  -o jsonpath='{.spec.template.spec.containers[?(@.name=="connector")].image}')
[[ "$upgraded_image" == "$expected_image" ]] || \
  fail "upgraded connector image $upgraded_image does not match $expected_image"
annotation=$(kubectl --context "$context" -n "$namespace" get deployment "$deployment" \
  -o jsonpath='{.spec.template.metadata.annotations.installValidation}')
[[ "$annotation" == "$suffix" ]] || fail "upgrade annotation was not applied"
