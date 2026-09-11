#!/usr/bin/env python3
"""Validate repository controls that must surround the shared age check."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path


FULL_SHA = re.compile(r"^[0-9a-f]{40}$")
CALLER = re.compile(
    r"InteractionLabs/infrastructure/\.github/workflows/"
    r"reusable-dependency-policy\.yml@([0-9a-f]{40})(?:\s|#|$)"
)


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


def validate_exception_boundary(repository: Path) -> list[str]:
    exception_path = ".github/dependency-cooldown-exceptions.json"
    if not (repository / exception_path).exists():
        return [f"{exception_path} is required"]
    return []


def validate_caller(repository: Path) -> list[str]:
    candidates = [repository / ".github/workflows/dependency-policy.yml"]
    caller = next((path for path in candidates if path.exists()), None)
    if not caller:
        return ["the dependency-cooldown caller workflow is required"]
    content = caller.read_text()
    failures: list[str] = []
    if not CALLER.search(content):
        failures.append("the shared dependency workflow must use a full commit SHA")
    if not re.search(r"(?m)^\s*pull_request\s*:", content):
        failures.append("the dependency-cooldown caller must run for pull requests")
    if not re.search(r"(?m)^\s*contents:\s*read\s*$", content):
        failures.append("the dependency-cooldown caller must grant contents: read")
    if not re.search(r"(?m)^\s*id-token:\s*write\s*$", content):
        failures.append("the dependency-cooldown caller must grant id-token: write")
    write_permissions = re.findall(
        r"(?m)^\s*([A-Za-z_-]+):\s*write\s*$", content
    )
    if any(permission != "id-token" for permission in write_permissions):
        failures.append(
            "the dependency-cooldown caller cannot request other write permissions"
        )
    if "DEPENDENCY_EVIDENCE_" in content:
        failures.append("the dependency-cooldown caller must use OIDC instead of secrets")
    return failures


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, default=Path("."))
    parser.add_argument("--require-caller", action="store_true")
    arguments = parser.parse_args()
    repository = arguments.repo.resolve()
    failures = [
        *validate_renovate(repository),
        *validate_action_pins(repository),
        *validate_exception_boundary(repository),
    ]
    if arguments.require_caller:
        failures.extend(validate_caller(repository))
    if failures:
        for failure in failures:
            print(f"dependency-policy: {failure}")
        return 1
    print("dependency-policy: repository invariants satisfied")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
