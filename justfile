default:
    @just --list

# Run golines with the project's standard wrap width.
# `mode` is "--dry-run" for check, "-w" for write.
_golines mode:
    @golines -m 100 {{mode}} .   # -m 100 = re-wrap any line longer than 100 chars

# Check formatting and run all configured linters
lint:
    #!/usr/bin/env bash
    set -euo pipefail

    # Run every linter declared in .golangci.yml (errcheck, staticcheck, govet, etc.)
    golangci-lint run ./...

    # Capture gofmt diff. Empty = no drift.
    gofmt_drift=$(gofmt -d .)
    if [ -n "$gofmt_drift" ]; then
        echo "gofmt drift, run: just format"
        echo "$gofmt_drift"
        exit 1
    fi

    # Capture unified-diff file headers from `golines --dry-run`. Empty = no drift.
    # `|| true` swallows grep's exit 1 when there are zero matches (with set -e).
    golines_drift=$(just _golines '--dry-run' 2>&1 | grep -E '^(---|\+\+\+)' || true)
    if [ -n "$golines_drift" ]; then
        echo "golines drift, run: just format"
        echo "$golines_drift"
        exit 1
    fi

    echo "All checks passed."

# Format code, auto-fixing lint issues
format:
    @just _golines '-w'              # re-wrap long lines in place
    @gofmt -w .                      # fix common gofmt issues (tabs/spaces, indentation, etc.)
    @golangci-lint run --fix ./...   # auto-fix lint issues that have fixers

# Build the code
build:
    go build ./...

# Run all tests
test:
    go test ./...

# Check for unreachable functions
deadcode:
    #!/usr/bin/env bash
    set -euo pipefail
    # Lists functions never called transitively from any main package.
    out=$(deadcode ./...)
    if [ -n "$out" ]; then
        echo "Dead code detected:"
        echo "$out"
        exit 1
    fi
    echo "No dead code detected."
