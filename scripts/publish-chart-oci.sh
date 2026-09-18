#!/usr/bin/env bash
set -euo pipefail

# Transitional compatibility mirror. GitHub Release assets remain the canonical
# chart distribution channel; retire this publisher when the future deploy
# system owns artifact propagation.

readonly expected_name=traversal-connector-charts
readonly registry=${CHART_OCI_REGISTRY:-registry-1.docker.io}
readonly namespace=${CHART_OCI_NAMESPACE:-traversalext}
readonly repository="oci://${registry}/${namespace}/${expected_name}"

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

command -v helm >/dev/null 2>&1 || die "helm is required"

[[ $# -eq 1 ]] || die "usage: $0 <chart.tgz>"
archive=$1
[[ -f "$archive" ]] || die "chart archive does not exist: $archive"

chart_field() {
  local chart=$1 field=$2
  helm show chart "$chart" | awk -v field="$field" '
    $1 == field ":" {
      value=$2
      if (value ~ /^".*"$/ || value ~ /^\047.*\047$/) {
        value=substr(value, 2, length(value) - 2)
      }
      print value
      exit
    }
  '
}

validate_chart() {
  local chart=$1 name version app_version
  name=$(chart_field "$chart" name)
  version=$(chart_field "$chart" version)
  app_version=$(chart_field "$chart" appVersion)

  [[ "$name" == "$expected_name" ]] || die "chart name must be $expected_name, got: ${name:-<empty>}"
  [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "chart version must match X.Y.Z, got: ${version:-<empty>}"
  [[ "$app_version" == "v${version}" ]] || die "chart appVersion must be v${version}, got: ${app_version:-<empty>}"
  printf '%s\n' "$version"
}

version=$(validate_chart "$archive")
temp=$(mktemp -d)
trap 'rm -rf "$temp"' EXIT
pulled="$temp/${expected_name}-${version}.tgz"

# Never clobber: a tag that already exists is left untouched. An identical
# retry succeeds as a no-op; anything else is refused rather than replaced.
pull_error="$temp/pull-error"
if helm pull "$repository" --version "$version" --destination "$temp" 2>"$pull_error"; then
  cmp -s "$archive" "$pulled" ||
    die "OCI tag ${version} already exists; refusing to overwrite it"
  printf 'OCI chart %s:%s already contains identical content; skipping push.\n' "$repository" "$version"
  exit 0
fi
grep -Eqi 'manifest unknown|not found' "$pull_error" || {
  cat "$pull_error" >&2
  die "could not preflight OCI chart ${repository}:${version}"
}

helm push "$archive" "oci://${registry}/${namespace}"

helm pull "$repository" --version "$version" --destination "$temp"
cmp -s "$archive" "$pulled" || die "published OCI chart differs from source archive"
printf 'Published and verified OCI chart %s:%s.\n' "$repository" "$version"
