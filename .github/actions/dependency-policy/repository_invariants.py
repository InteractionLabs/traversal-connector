#!/usr/bin/env python3
"""Validate repository controls that must surround the shared age check.

This owns the exceptions-file and caller-workflow checks. The publication-age
decision itself lives in policy.py (legacy profile) and the `dependency_policy`
package (infrastructure profile).
"""

from __future__ import annotations

import argparse
import os
import re
from pathlib import Path


GITHUB_REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


INFRASTRUCTURE_REPOSITORY = "InteractionLabs/infrastructure"
INFRASTRUCTURE_EXCEPTION_PATH = ".github/actions/dependency-policy/exceptions.json"
CALLER_EXCEPTION_PATH = ".github/dependency-policy/exceptions.json"


def validate_exception_boundary(
    repository: Path, infrastructure: bool = False
) -> list[str]:
    """Require the exceptions file at the path this repository uses."""
    exception_path = (
        INFRASTRUCTURE_EXCEPTION_PATH if infrastructure else CALLER_EXCEPTION_PATH
    )
    if not (repository / exception_path).exists():
        return [f"{exception_path} is required"]
    return []


def validate_caller(
    repository: Path,
    caller_repository: str = "InteractionLabs/infrastructure",
) -> list[str]:
    """Check the caller workflow pins the shared workflow and keeps read-only permissions."""
    if not GITHUB_REPOSITORY.fullmatch(caller_repository):
        return ["the trusted caller repository must use owner/repository form"]
    candidates = [repository / ".github/workflows/dependency-policy.yml"]
    caller = next((path for path in candidates if path.exists()), None)
    if not caller:
        return ["the dependency-policy caller workflow is required"]
    content = caller.read_text()
    failures: list[str] = []
    caller_owner = caller_repository.split("/", 1)[0]
    allowed_version = (
        r"(?:main|[0-9a-f]{40})"
        if caller_owner.casefold() == "interactionlabs"
        else r"[0-9a-f]{40}"
    )
    caller_pattern = re.compile(
        re.escape(caller_repository)
        + r"/\.github/workflows/reusable-(?:infrastructure-)?dependency-policy\.yml@"
        + allowed_version
        + r"(?:\s|#|$)"
    )
    if not caller_pattern.search(content):
        requirement = (
            "main or a full commit SHA"
            if caller_owner.casefold() == "interactionlabs"
            else "a full commit SHA"
        )
        failures.append(f"the shared dependency workflow must use {requirement}")
    if not re.search(r"(?m)^\s*pull_request\s*:", content):
        failures.append("the dependency-policy caller must run for pull requests")
    if not re.search(r"(?m)^\s*contents:\s*read\s*$", content):
        failures.append("the dependency-policy caller must grant contents: read")
    write_permissions = re.findall(r"(?m)^\s*([A-Za-z_-]+):\s*write\s*$", content)
    if write_permissions:
        failures.append("the dependency-policy caller cannot request write permissions")
    if passes_inputs_to_shared_workflow(content):
        failures.append(
            "the dependency-policy caller must not pass inputs to the shared workflow"
        )
    return failures


def passes_inputs_to_shared_workflow(content: str) -> bool:
    """Return whether the job calling the shared workflow has a sibling `with:` key."""
    lines = content.splitlines()
    for index, line in enumerate(lines):
        match = re.match(
            r"^(\s*)uses:\s*\S*reusable-(?:infrastructure-)?dependency-policy\.yml@",
            line,
        )
        if not match:
            continue
        indent = len(match.group(1))
        first = index
        while first > 0 and (
            not lines[first - 1].strip() or indentation(lines[first - 1]) >= indent
        ):
            first -= 1
        last = index
        while last + 1 < len(lines) and (
            not lines[last + 1].strip() or indentation(lines[last + 1]) >= indent
        ):
            last += 1
        if any(
            indentation(sibling) == indent and re.match(r"\s*with\s*:", sibling)
            for sibling in lines[first : last + 1]
        ):
            return True
    return False


def indentation(line: str) -> int:
    """Return the number of leading spaces."""
    return len(line) - len(line.lstrip())


def main() -> int:
    """Run the invariant checks and return the process exit code."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, default=Path("."))
    parser.add_argument("--repository", default=os.environ.get("GITHUB_REPOSITORY", ""))
    parser.add_argument("--require-caller", action="store_true")
    parser.add_argument(
        "--caller-repository",
        default="InteractionLabs/infrastructure",
    )
    arguments = parser.parse_args()
    repository = arguments.repo.resolve()
    failures = validate_exception_boundary(
        repository, arguments.repository == INFRASTRUCTURE_REPOSITORY
    )
    if arguments.require_caller:
        failures.extend(validate_caller(repository, arguments.caller_repository))
    if failures:
        for failure in failures:
            print(f"dependency-policy: {failure}")
        return 1
    print("dependency-policy: repository invariants satisfied")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
