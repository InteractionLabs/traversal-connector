#!/usr/bin/env python3
"""Reject mutable external tools, workflow actions, and container inputs."""
import re
import sys
from pathlib import Path

SHA = r"[0-9a-f]{40}"
DIGEST = r"sha256:[0-9a-f]{64}"
failures = []

for path in list(Path(".github").rglob("*.yml")) + list(Path(".github").rglob("*.yaml")):
    for number, line in enumerate(path.read_text().splitlines(), 1):
        match = re.search(r"\buses:\s*([^\s#]+)", line)
        if match and not match.group(1).startswith("./"):
            reference = match.group(1)
            if "@" not in reference or not re.search(r"@" + SHA + r"$", reference):
                failures.append(f"{path}:{number}: action/reusable workflow is not pinned to a full SHA: {reference}")

for path in Path(".").glob("**/Dockerfile"):
    for number, line in enumerate(path.read_text().splitlines(), 1):
        match = re.match(r"\s*FROM\s+(?:--platform=[^\s]+\s+)?([^\s]+)", line)
        if match and match.group(1) != "scratch" and not re.search(r"@" + DIGEST + r"$", match.group(1)):
            failures.append(f"{path}:{number}: container base is not pinned to a digest: {match.group(1)}")
        if match and re.search(r":(latest|main|master)@", match.group(1)):
            failures.append(f"{path}:{number}: container base includes a floating tag: {match.group(1)}")
        if re.search(r"\bgo\s+install\s+\S+@(latest|main|master)\b", line):
            failures.append(f"{path}:{number}: floating Go tool install")

for path in [Path("justfile")] + list(Path("scripts").glob("*")):
    if not path.is_file():
        continue
    for number, line in enumerate(path.read_text(errors="ignore").splitlines(), 1):
        if re.search(r"\bgo\s+install\s+\S+@(latest|main|master)\b", line):
            failures.append(f"{path}:{number}: floating Go tool install")

if failures:
    print("immutable dependency input verification failed:", file=sys.stderr)
    for failure in failures:
        print("- " + failure, file=sys.stderr)
    raise SystemExit(1)
print("immutable dependency inputs verified")
