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
    lines = path.read_text().splitlines()
    arguments = {}
    for line in lines:
        argument = re.match(r"\s*ARG\s+([A-Za-z_][A-Za-z0-9_]*)=(\S+)", line)
        if argument:
            arguments[argument.group(1)] = argument.group(2)
    for number, line in enumerate(lines, 1):
        match = re.match(r"\s*FROM\s+(?:--platform=[^\s]+\s+)?([^\s]+)", line)
        image = match.group(1) if match else ""
        variable = re.fullmatch(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}", image)
        resolved = arguments.get(variable.group(1), image) if variable else image
        if match and resolved != "scratch" and not re.search(r"@" + DIGEST + r"$", resolved):
            failures.append(f"{path}:{number}: container base is not pinned to a digest: {image}")
        if match and re.search(r":(latest|main|master)@", resolved):
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
