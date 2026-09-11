#!/usr/bin/env bash
set -euo pipefail

mode=${1:?usage: update_go_dependencies.sh deps|tools}
base=$(git rev-parse HEAD)
mod_backup=$(mktemp)
sum_backup=$(mktemp)
cp go.mod "$mod_backup"
cp go.sum "$sum_backup"
completed=false
cleanup() {
  if [[ "$completed" != "true" ]]; then
    cp "$mod_backup" go.mod
    cp "$sum_backup" go.sum
  fi
  rm -f "$mod_backup" "$sum_backup"
}
trap cleanup EXIT

case "$mode" in
  deps)
    go get -u ./...
    go mod tidy
    ;;
  tools)
    while IFS= read -r tool; do
      go get -u "$tool"
    done < <(awk '$1 == "tool" { print $2 }' go.mod)
    go mod tidy
    ;;
  *)
    echo "unknown update mode: $mode" >&2
    exit 2
    ;;
esac

if ! scripts/go_dependency_policy.py --base "$base"; then
  echo "update rejected; go.mod and go.sum restored to their locked state" >&2
  exit 1
fi
completed=true
