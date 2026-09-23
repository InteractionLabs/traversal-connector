#!/usr/bin/env bash
set -euo pipefail

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

[[ $# -eq 6 ]] || die "usage: $0 PR_NUMBER PR_URL FULL_SHA IMAGE_METADATA_JSON RUN_URL OUTPUT_DIR"

pr_number=$1
pr_url=$2
full_sha=$3
image_metadata=$4
run_url=$5
output_dir=$6

[[ "$pr_number" =~ ^[1-9][0-9]*$ ]] || die "PR number must be a positive integer"
[[ "$full_sha" =~ ^[0-9a-f]{40}$ ]] || die "full SHA must be 40 lowercase hexadecimal characters"
[[ -f "$image_metadata" ]] || die "image metadata file not found: $image_metadata"

for command in helm jq; do
  command -v "$command" >/dev/null 2>&1 || die "$command is required"
done
if command -v sha256sum >/dev/null 2>&1; then
  checksum_command=(sha256sum)
elif command -v shasum >/dev/null 2>&1; then
  checksum_command=(shasum -a 256)
else
  die "sha256sum or shasum is required"
fi

short_sha=${full_sha:0:12}
chart_version="0.0.0-pr.${pr_number}.${short_sha}"
app_version="prerelease-${short_sha}"
archive="traversal-connector-charts-${chart_version}.tgz"

repository=$(jq -er '.repository | select(type == "string" and length > 0)' "$image_metadata")
image_tag=$(jq -er '.tag | select(type == "string")' "$image_metadata")
digest=$(jq -er '.digest | select(test("^sha256:[0-9a-f]{64}$"))' "$image_metadata")
immutable_ref=$(jq -er '.immutable_ref | select(type == "string")' "$image_metadata")
architectures=$(jq -cer '.architectures | select(type == "array") | sort | unique' "$image_metadata")
[[ "$image_tag" == "$app_version" ]] || die "image tag must match chart appVersion: $image_tag != $app_version"
[[ "$immutable_ref" == "${repository}@${digest}" ]] || die "image immutable_ref is inconsistent"
[[ "$architectures" == '["linux/amd64","linux/arm64"]' ]] ||
  die "image architectures must be exactly linux/amd64 and linux/arm64"

mkdir -p "$output_dir"
rm -f "$output_dir/$archive" "$output_dir/$archive.sha256" "$output_dir/manifest.json"

helm package charts/traversal-connector \
  --version "$chart_version" \
  --app-version "$app_version" \
  --destination "$output_dir"

(
  cd "$output_dir"
  "${checksum_command[@]}" "$archive" > "$archive.sha256"
)
chart_sha256=$(awk '{print $1}' "$output_dir/$archive.sha256")

jq -n \
  --slurpfile image "$image_metadata" \
  --arg source_repo "${GITHUB_REPOSITORY:-InteractionLabs/traversal-connector}" \
  --argjson pr_number "$pr_number" \
  --arg pr_url "$pr_url" \
  --arg source_sha "$full_sha" \
  --arg chart_filename "$archive" \
  --arg chart_version "$chart_version" \
  --arg chart_app_version "$app_version" \
  --arg chart_sha256 "$chart_sha256" \
  --arg run_url "$run_url" \
  --arg run_id "${GITHUB_RUN_ID:-local}" \
  '{
    source: {repository: $source_repo, pull_request: {number: $pr_number, url: $pr_url}, sha: $source_sha},
    image: ($image[0] | {tag, repository, digest, immutable_ref, architectures: (.architectures | sort | unique)} + {oci_index_digest: .digest}),
    chart: {filename: $chart_filename, version: $chart_version, app_version: $chart_app_version, sha256: $chart_sha256},
    workflow_run: {url: $run_url, id: $run_id}
  }' > "$output_dir/manifest.json"

jq -e . "$output_dir/manifest.json" >/dev/null
printf 'Packaged paired prerelease artifacts in %s\n' "$output_dir"
