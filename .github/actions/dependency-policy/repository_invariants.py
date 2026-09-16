#!/usr/bin/env python3
"""Validate repository controls that must surround the shared age check."""

from __future__ import annotations

import argparse
import re
from pathlib import Path


GITHUB_REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


def validate_exception_boundary(repository: Path) -> list[str]:
    exception_path = ".github/dependency-policy/exceptions.json"
    if not (repository / exception_path).exists():
        return [f"{exception_path} is required"]
    return []


def validate_caller(
    repository: Path,
    caller_repository: str = "InteractionLabs/infrastructure",
) -> list[str]:
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
        + r"/\.github/workflows/reusable-dependency-policy\.yml@"
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
    write_permissions = re.findall(
        r"(?m)^\s*([A-Za-z_-]+):\s*write\s*$", content
    )
    if write_permissions:
        failures.append("the dependency-policy caller cannot request write permissions")
    return failures


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, default=Path("."))
    parser.add_argument("--require-caller", action="store_true")
    parser.add_argument(
        "--caller-repository",
        default="InteractionLabs/infrastructure",
    )
    arguments = parser.parse_args()
    repository = arguments.repo.resolve()
    failures = validate_exception_boundary(repository)
    if arguments.require_caller:
        failures.extend(
            validate_caller(repository, arguments.caller_repository)
        )
    if failures:
        for failure in failures:
            print(f"dependency-policy: {failure}")
        return 1
    print("dependency-policy: repository invariants satisfied")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
