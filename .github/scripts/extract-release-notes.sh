#!/usr/bin/env bash
# Emits the top-level "# Release Notes" section of a PR body read from stdin:
# everything from that H1 header up to (but excluding) the next H1. Shared by
# the release and release-notes-check workflows so the two never drift.
set -euo pipefail

awk '
  /^#[[:space:]]+[Rr]elease[[:space:]]+[Nn]otes[[:space:]]*$/ { found=1; next }
  found && /^#[[:space:]]/ { found=0 }
  found { print }
'
