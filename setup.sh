#!/usr/bin/env bash
# Install dev CLI tools used by the `just` recipes.
# Run once after cloning. Idempotent: skips anything already installed.

set -euo pipefail

echo "==> Installing just..."
if command -v just &>/dev/null; then
    echo "    already installed: $(just --version)"
elif command -v brew &>/dev/null; then
    brew install just
elif command -v cargo &>/dev/null; then
    cargo install just
elif command -v apt-get &>/dev/null; then
    sudo apt-get update && sudo apt-get install -y just
else
    echo "Error: no supported package manager (brew/cargo/apt) found."
    echo "Install just manually: https://github.com/casey/just#installation"
    exit 1
fi

echo "==> Installing golangci-lint..."
go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.10.1

echo "==> Installing golines..."
go install github.com/segmentio/golines@v0.13.0

echo "==> Installing deadcode..."
go install golang.org/x/tools/cmd/deadcode@v0.38.0

echo ""
echo "Done. Run 'just --list' to see available commands."
