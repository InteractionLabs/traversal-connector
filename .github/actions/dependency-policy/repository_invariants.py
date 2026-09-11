#!/usr/bin/env python3
"""Validate repository controls that must surround the shared age check."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path


FULL_SHA = re.compile(r"^[0-9a-f]{40}$")
SHA256_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
GITHUB_REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


def validate_renovate(repository: Path) -> list[str]:
    failures: list[str] = []
    path = repository / "renovate.json"
    if not path.exists():
        return ["renovate.json is required"]
    try:
        config = json.loads(path.read_text())
    except json.JSONDecodeError as error:
        return [f"renovate.json is invalid JSON: {error}"]
    required_presets = {"config:recommended", "helpers:pinGitHubActionDigests"}
    if not required_presets.issubset(set(config.get("extends", []))):
        failures.append(
            "renovate.json must extend config:recommended and "
            "helpers:pinGitHubActionDigests"
        )
    expected = {
        "minimumReleaseAge": "7 days",
        "minimumReleaseAgeBehaviour": "timestamp-required",
        "internalChecksFilter": "strict",
        "dependencyDashboard": True,
        "automerge": False,
        "prHourlyLimit": 1,
        "osvVulnerabilityAlerts": False,
    }
    for key, value in expected.items():
        if config.get(key) != value:
            failures.append(f"renovate.json must set {key} to {value!r}")
    if config.get("prConcurrentLimit") not in {1, 2}:
        failures.append("renovate.json prConcurrentLimit must be 1 or 2")
    managers = config.get("enabledManagers")
    if not isinstance(managers, list) or not managers:
        failures.append("renovate.json must use an explicit enabledManagers allowlist")
    if config.get("vulnerabilityAlerts", {}).get("enabled") is not False:
        failures.append("Renovate vulnerability-alert PR creation must be disabled")
    if config.get("lockFileMaintenance", {}).get("enabled") is not False:
        failures.append("Renovate lockfile maintenance must be disabled initially")
    major_rule = any(
        "major" in rule.get("matchUpdateTypes", [])
        and rule.get("dependencyDashboardApproval") is True
        for rule in config.get("packageRules", [])
        if isinstance(rule, dict)
    )
    if not major_rule:
        failures.append("major updates must require Dependency Dashboard approval")
    return failures


def validate_action_pins(repository: Path) -> list[str]:
    failures: list[str] = []
    workflows = repository / ".github"
    if not workflows.exists():
        return failures
    for path in sorted(workflows.rglob("*")):
        if path.suffix not in {".yml", ".yaml"} or not path.is_file():
            continue
        for line_number, line in enumerate(path.read_text().splitlines(), start=1):
            match = re.match(r"\s*(?:-\s*)?uses:\s*([^\s#]+)(.*)$", line)
            if not match:
                continue
            target, suffix = match.groups()
            if target.startswith("./"):
                continue
            if target.startswith("docker://"):
                image = target.removeprefix("docker://")
                if not re.search(r"@sha256:[0-9a-f]{64}$", image):
                    failures.append(
                        f"{path.relative_to(repository)}:{line_number}: "
                        "container actions must use a sha256 digest"
                    )
                continue
            if "@" not in target or not FULL_SHA.fullmatch(target.rsplit("@", 1)[1]):
                failures.append(
                    f"{path.relative_to(repository)}:{line_number}: "
                    "external actions and reusable workflows must use a full SHA"
                )
            elif not suffix.strip().startswith("#"):
                failures.append(
                    f"{path.relative_to(repository)}:{line_number}: "
                    "SHA pins need a readable version comment"
                )
    return failures


def dockerfiles(repository: Path) -> list[Path]:
    ignored = {".git", ".terragrunt-cache", ".venv", "node_modules"}
    return sorted(
        path
        for path in repository.rglob("*")
        if path.is_file()
        and "Dockerfile" in path.name
        and not ignored.intersection(path.relative_to(repository).parts)
    )


def validate_container_pins(repository: Path) -> list[str]:
    failures: list[str] = []
    for path in dockerfiles(repository):
        arguments: dict[str, str] = {}
        stages: set[str] = set()
        relative = path.relative_to(repository)
        for line_number, line in enumerate(
            path.read_text(errors="ignore").splitlines(), start=1
        ):
            argument = re.match(
                r"\s*ARG\s+([A-Za-z_][A-Za-z0-9_]*)=(\S+)", line
            )
            if argument:
                arguments[argument.group(1)] = argument.group(2)
            base = re.match(
                r"\s*FROM\s+(?:--platform=[^\s]+\s+)?([^\s]+)"
                r"(?:\s+AS\s+([^\s]+))?",
                line,
                re.IGNORECASE,
            )
            if not base:
                continue
            image, alias = base.groups()
            if image.lower() == "scratch" or image.lower() in stages:
                if alias:
                    stages.add(alias.lower())
                continue
            variable = re.fullmatch(
                r"\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))",
                image,
            )
            variable_name = (
                next((group for group in variable.groups() if group), None)
                if variable
                else None
            )
            resolved = arguments.get(variable_name, image) if variable_name else image
            digest = resolved.rsplit("@", 1)[1] if "@" in resolved else ""
            if not SHA256_DIGEST.fullmatch(digest):
                failures.append(
                    f"{relative}:{line_number}: container base images must use "
                    "a sha256 digest"
                )
            if re.search(r":(?:latest|main|master)(?:@|$)", resolved):
                failures.append(
                    f"{relative}:{line_number}: container base images cannot use "
                    "a floating tag"
                )
            if alias:
                stages.add(alias.lower())
    return failures


def validate_go_tool_pins(repository: Path) -> list[str]:
    failures: list[str] = []
    paths = [repository / "justfile"]
    scripts = repository / "scripts"
    if scripts.exists():
        paths.extend(path for path in scripts.rglob("*") if path.is_file())
    paths.extend(dockerfiles(repository))
    for path in sorted(set(paths)):
        if not path.is_file():
            continue
        relative = path.relative_to(repository)
        for line_number, line in enumerate(
            path.read_text(errors="ignore").splitlines(), start=1
        ):
            if re.search(r"\bgo\s+install\s+\S+@(?:latest|main|master)\b", line):
                failures.append(
                    f"{relative}:{line_number}: Go tools must use an exact version"
                )
    return failures


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
    caller_pattern = re.compile(
        re.escape(caller_repository)
        + r"/\.github/workflows/reusable-dependency-policy\.yml@"
        + r"[0-9a-f]{40}(?:\s|#|$)"
    )
    if not caller_pattern.search(content):
        failures.append("the shared dependency workflow must use a full commit SHA")
    if not re.search(r"(?m)^\s*pull_request\s*:", content):
        failures.append("the dependency-policy caller must run for pull requests")
    if not re.search(r"(?m)^\s*contents:\s*read\s*$", content):
        failures.append("the dependency-policy caller must grant contents: read")
    if not re.search(r"(?m)^\s*id-token:\s*write\s*$", content):
        failures.append("the dependency-policy caller must grant id-token: write")
    write_permissions = re.findall(
        r"(?m)^\s*([A-Za-z_-]+):\s*write\s*$", content
    )
    if any(permission != "id-token" for permission in write_permissions):
        failures.append(
            "the dependency-policy caller cannot request other write permissions"
        )
    if "DEPENDENCY_EVIDENCE_" in content:
        failures.append("the dependency-policy caller must use OIDC instead of secrets")
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
    failures = [
        *validate_renovate(repository),
        *validate_action_pins(repository),
        *validate_container_pins(repository),
        *validate_go_tool_pins(repository),
        *validate_exception_boundary(repository),
    ]
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
