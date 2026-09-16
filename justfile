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

dependency-policy-check:
    python3 .github/actions/dependency-policy/repository_invariants.py --repo .

dependency-policy-test:
    python3 -m unittest discover -s .github/actions/dependency-policy -p 'test_*.py'
    just dependency-policy-check

# Lint the canonical Helm chart with a valid direct-export configuration.
chart-lint:
    helm lint charts/traversal-connector -f charts/traversal-connector/ci/direct-export-values.yaml

# Exercise supported chart configurations and validation failures.
chart-test:
    bash charts/traversal-connector/ci/test-chart.sh

# Package a release chart and portable checksum. Usage: just chart-package v0.8.5
chart-package version:
    #!/usr/bin/env bash
    set -euo pipefail
    version='{{version}}'
    if ! [[ "$version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo "Version must match vX.Y.Z, got: $version" >&2
        exit 1
    fi
    just chart-lint
    just chart-test
    chart_version=${version#v}
    archive="traversal-connector-charts-${chart_version}.tgz"
    mkdir -p dist
    rm -f "dist/$archive" "dist/$archive.sha256"
    helm package charts/traversal-connector \
        --version "$chart_version" \
        --app-version "$version" \
        --destination dist
    test -f "dist/$archive"
    if tar -tzf "dist/$archive" | grep -Eq '(^|/)ci(/|$)'; then
        echo "Packaged chart must not contain source-only ci/ files" >&2
        exit 1
    fi
    if command -v sha256sum >/dev/null 2>&1; then
        (cd dist && sha256sum "$archive" > "$archive.sha256")
    elif command -v shasum >/dev/null 2>&1; then
        (cd dist && shasum -a 256 "$archive" > "$archive.sha256")
    else
        echo "sha256sum or shasum is required" >&2
        exit 1
    fi
    echo "Packaged dist/$archive and dist/$archive.sha256"

# Run all tests
test:
    go test ./...
    just dependency-policy-test

# Tag and push a release. Usage: just release v0.4.0
release version:
    #!/usr/bin/env bash
    set -euo pipefail

    # Version must look like vX.Y.Z (semver, no pre-release suffix).
    if ! [[ "{{version}}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo "Version must match vX.Y.Z, got: {{version}}"
        exit 1
    fi

    # Working tree must be clean: no staged, unstaged, or untracked changes.
    if [ -n "$(git status --porcelain)" ]; then
        echo "Working tree is dirty. Commit or stash changes before releasing."
        git status --short
        exit 1
    fi

    # Must be on main.
    branch=$(git rev-parse --abbrev-ref HEAD)
    if [ "$branch" != "main" ]; then
        echo "Must be on main to release, currently on: $branch"
        exit 1
    fi

    # Local HEAD must match origin/main exactly (no ahead/behind drift).
    git fetch origin main --tags
    local_sha=$(git rev-parse HEAD)
    remote_sha=$(git rev-parse origin/main)
    if [ "$local_sha" != "$remote_sha" ]; then
        echo "Local main ($local_sha) does not match origin/main ($remote_sha)."
        echo "Pull or push so they match before releasing."
        exit 1
    fi

    # Tag must not already exist locally or on the remote.
    if git rev-parse -q --verify "refs/tags/{{version}}" >/dev/null; then
        echo "Tag {{version}} already exists locally."
        exit 1
    fi
    if git ls-remote --exit-code --tags origin "refs/tags/{{version}}" >/dev/null 2>&1; then
        echo "Tag {{version}} already exists on origin."
        exit 1
    fi

    git tag -a "{{version}}" -m "Release {{version}}"
    git push origin "refs/tags/{{version}}"
    echo "Released {{version}}."

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
