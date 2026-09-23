#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
temp=$(mktemp -d)
trap 'rm -rf "$temp"' EXIT

sha=0123456789abcdef0123456789abcdef01234567
tag=prerelease-0123456789ab
cat > "$temp/image.json" <<EOF
{"repository":"885798945817.dkr.ecr.us-west-2.amazonaws.com/traversal-connector","tag":"$tag","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","immutable_ref":"885798945817.dkr.ecr.us-west-2.amazonaws.com/traversal-connector@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","architectures":["linux/arm64","linux/amd64"]}
EOF

cd "$repo_root"
GITHUB_REPOSITORY=InteractionLabs/traversal-connector GITHUB_RUN_ID=12345 \
  scripts/package-prerelease-artifacts.sh \
  64 https://github.com/InteractionLabs/traversal-connector/pull/64 "$sha" \
  "$temp/image.json" https://github.com/InteractionLabs/traversal-connector/actions/runs/12345 "$temp/out"

archive="$temp/out/traversal-connector-charts-0.0.0-pr.64.0123456789ab.tgz"
test -f "$archive"
test -f "$archive.sha256"
(cd "$temp/out" && shasum -a 256 --check "$(basename "$archive").sha256")
jq -e --arg sha "$sha" '
  .source.sha == $sha and
  .source.pull_request.number == 64 and
  .image.immutable_ref == (.image.repository + "@" + .image.digest) and
  .image.oci_index_digest == .image.digest and
  .image.architectures == ["linux/amd64", "linux/arm64"] and
  .chart.version == "0.0.0-pr.64.0123456789ab" and
  .chart.app_version == .image.tag and
  .workflow_run.id == "12345"
' "$temp/out/manifest.json" >/dev/null

jq '.tag = "prerelease-other"' "$temp/image.json" > "$temp/inconsistent.json"
if scripts/package-prerelease-artifacts.sh \
  64 https://github.com/InteractionLabs/traversal-connector/pull/64 "$sha" \
  "$temp/inconsistent.json" https://github.com/InteractionLabs/traversal-connector/actions/runs/12345 \
  "$temp/bad" >"$temp/failure.out" 2>&1; then
  echo "FAIL: accepted an image tag that does not match the chart/commit" >&2
  exit 1
fi

printf 'All paired prerelease artifact tests passed.\n'
