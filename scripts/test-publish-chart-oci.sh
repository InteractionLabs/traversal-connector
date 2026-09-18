#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
publisher="$repo_root/scripts/publish-chart-oci.sh"
temp=$(mktemp -d)
trap 'rm -rf "$temp"' EXIT

mkdir -p "$temp/bin" "$temp/registry" "$temp/work"
cat > "$temp/bin/helm" <<'FAKE_HELM'
#!/usr/bin/env bash
set -euo pipefail
case "$1 $2" in
  "show chart")
    if [[ -n ${FAKE_QUOTE_METADATA:-} ]]; then
      tar -xOzf "$3" traversal-connector-charts/Chart.yaml |
        awk '$1 ~ /^(name|version|appVersion):$/ { print $1 " \042" $2 "\042"; next } { print }'
    else
      tar -xOzf "$3" traversal-connector-charts/Chart.yaml
    fi
    ;;
  "pull oci://"*)
    version= destination=
    shift 2
    while [[ $# -gt 0 ]]; do
      case "$1" in
        --version) version=$2; shift 2 ;;
        --destination) destination=$2; shift 2 ;;
        *) shift ;;
      esac
    done
    source="$FAKE_REGISTRY/traversal-connector-charts-${version}.tgz"
    if [[ ! -f "$source" ]]; then
      printf 'manifest unknown: not found\n' >&2
      exit 1
    fi
    cp "$source" "$destination/"
    ;;
  "push "*)
    printf 'push\n' >> "$FAKE_PUSH_LOG"
    cp "$2" "$FAKE_REGISTRY/$(basename "$2")"
    ;;
  *)
    printf 'unexpected fake helm invocation: %q ' "$@" >&2
    exit 2
    ;;
esac
FAKE_HELM
chmod +x "$temp/bin/helm"

export PATH="$temp/bin:$PATH"
export FAKE_REGISTRY="$temp/registry"
export FAKE_PUSH_LOG="$temp/push.log"
export CHART_OCI_REGISTRY=registry.test
export CHART_OCI_NAMESPACE=test

make_chart() {
  local output=$1 name=$2 version=$3 app_version=$4 payload=$5
  local root="$temp/work/$RANDOM/traversal-connector-charts"
  mkdir -p "$root/templates"
  cat > "$root/Chart.yaml" <<EOF
apiVersion: v2
name: $name
version: $version
appVersion: $app_version
EOF
  printf '%s\n' "$payload" > "$root/templates/config.yaml"
  tar -czf "$output" -C "$(dirname "$root")" traversal-connector-charts
}

expect_failure() {
  local description=$1
  shift
  if "$@" >"$temp/failure.out" 2>&1; then
    printf 'FAIL: expected failure: %s\n' "$description" >&2
    exit 1
  fi
}

expect_failure "missing archive" "$publisher" "$temp/missing.tgz"

invalid="$temp/invalid.tgz"
printf 'not a chart' > "$invalid"
expect_failure "invalid archive" "$publisher" "$invalid"

bad_metadata="$temp/traversal-connector-charts-1.2.3.tgz"
make_chart "$bad_metadata" wrong-name 1.2.3 v1.2.3 payload
expect_failure "metadata mismatch" "$publisher" "$bad_metadata"

source_chart="$temp/traversal-connector-charts-1.2.3.tgz"
make_chart "$source_chart" traversal-connector-charts 1.2.3 v1.2.3 original
FAKE_QUOTE_METADATA=1 "$publisher" "$source_chart"
[[ $(wc -l < "$FAKE_PUSH_LOG") -eq 1 ]]
rm -f "$FAKE_REGISTRY/traversal-connector-charts-1.2.3.tgz" "$FAKE_PUSH_LOG"

"$publisher" "$source_chart"
[[ $(wc -l < "$FAKE_PUSH_LOG") -eq 1 ]]
cmp "$source_chart" "$FAKE_REGISTRY/traversal-connector-charts-1.2.3.tgz"

# Identical retry succeeds without a second push.
"$publisher" "$source_chart"
[[ $(wc -l < "$FAKE_PUSH_LOG") -eq 1 ]]

# An existing tag with different bytes is never overwritten.
different="$temp/different.tgz"
make_chart "$different" traversal-connector-charts 1.2.3 v1.2.3 changed
cp "$different" "$FAKE_REGISTRY/traversal-connector-charts-1.2.3.tgz"
expect_failure "different existing chart" "$publisher" "$source_chart"
[[ $(wc -l < "$FAKE_PUSH_LOG") -eq 1 ]]

printf 'All OCI chart publisher tests passed.\n'
