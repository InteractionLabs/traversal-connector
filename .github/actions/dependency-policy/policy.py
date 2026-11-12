#!/usr/bin/env python3
"""Block new third-party dependencies published within the 168-hour cooldown.

This is the legacy checker that the required check runs under stdlib-only
`python3 -I` (no venv), so it must import with the standard library alone.
Keep new runtime imports to the stdlib and put typing-only imports under
`if TYPE_CHECKING:`.

The checker diffs two revisions, finds exact dependency coordinates that head
adds, and asks each ecosystem's registry when the coordinate was published.
Anything younger than the cooldown, unpinned, or without trustworthy
publication evidence fails. The exceptions file can excuse a blocked
coordinate until a stated expiry, and a single `latest` entry can excuse
first-party InteractionLabs references.

Publication evidence is cached only where a registry can't move a coordinate's
publication time later: npm, crates.io, Maven, Go, GitHub commits, and PyPI
when `uv.lock` pins file hashes. `requirements.txt`, `pyproject.toml` and
GitHub releases are never cached, because new files or a recreated release
can appear under an old coordinate. README.md has the full reasoning.

`--profile infrastructure` hands off to `dependency_policy` and runs only for
InteractionLabs/infrastructure; every other repository stays on `legacy`.
"""

from __future__ import annotations

import argparse
import datetime as dt
import email.utils
import fnmatch
import http.client
import json
import math
import os
import random
import re
import shlex
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Iterator
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Optional, Union

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib


UTC = dt.timezone.utc
COOLDOWN = dt.timedelta(hours=168)
CACHE_SCHEMA = 3
USER_AGENT = "dependency-policy/4"
REPOSITORY_ROOT = Path(
    os.environ.get("GITHUB_WORKSPACE", Path(__file__).resolve().parents[3])
).resolve()
GO_PROXY = "https://proxy.golang.org"
GO_INDEX = "https://index.golang.org/index"
GO_INDEX_PAGE_SIZE = 2000
# Pages a coordinate may walk past its seek time before it is reported missing.
GO_INDEX_PAGE_LIMIT = 200
GO_INDEX_SEEK_MARGIN = dt.timedelta(minutes=1)
REQUEST_TIMEOUT_SECONDS = 20
# High enough that the wait budget, not the attempt count, ends a rate-limited lookup.
RETRY_ATTEMPTS = 8
RETRY_BASE_DELAY_SECONDS = 1.0
RETRY_MAX_DELAY_SECONDS = 30.0
# Total time one request may spend waiting between retries.
RETRY_WAIT_BUDGET_SECONDS = 60.0
FULL_SHA = re.compile(r"^[0-9a-f]{40}$")
LATEST_EXCEPTION = "latest"
FIRST_PARTY_EXCEPTION = ("*", "github.com/InteractionLabs/*", LATEST_EXCEPTION)
# Only hosts where the owner segment is the InteractionLabs GitHub org. A bare
# "interactionlabs/x" image resolves to Docker Hub, whose namespace we don't own.
FIRST_PARTY_LOCATION = re.compile(
    r"^(?:github\.com[/:]|ghcr\.io/)interactionlabs/"
    r"(?!\.\.?(?:[/?:@]|$))[A-Za-z0-9_.-]+(?:[/?:@]|$)",
    re.IGNORECASE,
)
GIT_SOURCE_PREFIX = re.compile(r"^(?:git::)?(?:[a-z+]+://)?(?:git@)?")
SHA256_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
UNSAFE_VERSION = re.compile(
    r"(?:^|[^A-Za-z])(latest|main|master)(?:$|[^A-Za-z])|[*<>=^~|,\s]"
)
RELEASE_ASSET_PATTERN = re.compile(
    r"https://github\.com/([^/]+/[^/]+)/releases/download/([^/]+)/([^\s\"']+)"
)
RELEASE_ASSET_GREP_PATTERN = (
    r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/releases/download/"
    r"[^/[:space:]\"']+/[^[:space:]\"']+"
)
UNEXPANDED_REFERENCE = re.compile(r"\$\{\{[^}]*\}\}|\$\{[^}]*\}|\$\([^)]*\)|\$\w+")
VARIABLE_REFERENCE = re.compile(
    r"\$\{\{\s*env\.(?P<env>\w+)\s*\}\}"
    r"|\$\{(?P<braced>[A-Za-z_][\w.]*)\}"
    r"|\$(?P<bare>[A-Za-z_]\w*)"
)
DOCKERFILE_FROM = re.compile(
    r"^\s*FROM\s+(?:--platform=[^\s]+\s+)?([^\s]+)(?:\s+AS\s+([^\s]+))?\s*$",
    re.IGNORECASE,
)
DOCKERFILE_FROM_PREFIX = re.compile(r"^\s*FROM\b", re.IGNORECASE)
DOCKERFILE_ARG = re.compile(r"^\s*ARG\s+(.+)$", re.IGNORECASE)
OVERRIDE_VALUE = re.compile(r"[^\s\"'`\\;&|()<>#${}]+")
OVERRIDE_COMBINATION_LIMIT = 64
NON_TEXT_SUFFIXES = frozenset(
    {
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".webp",
        ".ico",
        ".bmp",
        ".svg",
        ".pdf",
        ".woff",
        ".woff2",
        ".ttf",
        ".otf",
        ".eot",
        ".zip",
        ".gz",
        ".tgz",
        ".bz2",
        ".xz",
        ".zst",
        ".tar",
        ".jar",
        ".whl",
        ".so",
        ".dylib",
        ".dll",
        ".exe",
        ".mp3",
        ".mp4",
        ".mov",
        ".wasm",
        ".pyc",
    }
)
BUILD_ARG_TOKEN = r"((?:\"[^\"]*\"|'[^']*'|[^\s\"']+)+)"
BUILD_ARG_FLAG = re.compile(r"--build-arg(?:\s+|=)" + BUILD_ARG_TOKEN)
BAKE_SET_FLAG = re.compile(r"--set(?:\s+|=)(?:\*|[\w-]+)\.args\." + BUILD_ARG_TOKEN)
BUILD_ARG_KEYS = {"build-args", "build_args", "args"}
BUILD_ARG_ENTRY = re.compile(
    r"^\s*(?:-\s+)?[\"']?([A-Za-z_]\w*)[\"']?(?:\s*[=:]\s*(.*?))?\s*,?\s*$"
)
INLINE_BUILD_ARGS = re.compile(r"\b(?:build[-_]args|args)[\"']?\s*[=:]\s*\{([^}]*)\}")
INLINE_BUILD_ARG_PAIR = re.compile(
    r"[\"']?([A-Za-z_]\w*)[\"']?\s*[=:]\s*(\"[^\"]*\"|'[^']*'|[^,\s]+)"
)
LITERAL_VALUE = re.compile(
    r"(?:\"([^\"$`\\]*)\"|'([^']*)'|([^\s\"'$`\\;&|()<>{}#]+))(?=$|[\s;&|)])"
)
SHELL_ASSIGNMENT = re.compile(r"(?<![\w$.-])([A-Za-z_]\w*)=")
YAML_ENTRY = re.compile(r"^(\s*(?:-\s+)?)([A-Za-z_]\w*):(?:[ \t]+(.*))?$")
TERRAFORM_ENTRY = re.compile(r"^\s+([A-Za-z_]\w*)\s*=\s*(.*)$")
# Only ecosystems whose publication time can never move later for a given
# coordinate. PyPI is cached only when the lockfile pins file hashes (see
# is_cacheable); README.md explains why.
CACHEABLE_ECOSYSTEMS = {
    "npm",
    "crates",
    "maven",
    "github-commit",
    "go",
}
REPOSITORY = Path(".")
LATEST_POLICY_REFERENCE = re.compile(
    r"^(?i:InteractionLabs)/(?P<repository>[A-Za-z0-9_.-]+)/\.github/"
    r"(?P<kind>actions/dependency-policy|"
    r"workflows/reusable-(?:infrastructure-)?dependency-policy\.yml|"
    r"workflows/sign-image\.yaml|"
    r"workflows/customer-name-scan\.yaml|"
    r"workflows/release-component-chart\.yaml)@main$"
)
LATEST_POLICY_PATHS = {
    "actions/dependency-policy": frozenset(
        {
            ".github/workflows/reusable-dependency-policy.yml",
            ".github/workflows/reusable-infrastructure-dependency-policy.yml",
        }
    ),
    "workflows/reusable-dependency-policy.yml": frozenset(
        {".github/workflows/dependency-policy.yml"}
    ),
    "workflows/reusable-infrastructure-dependency-policy.yml": frozenset(
        {".github/workflows/dependency-policy.yml"}
    ),
}
# Org-wide reusable workflows callers may track at @main, same as sign-image.
LATEST_POLICY_WORKFLOWS = frozenset(
    {
        "workflows/sign-image.yaml",
        "workflows/customer-name-scan.yaml",
        # The app-repo chart publish roles trust only this workflow at refs/heads/main.
        "workflows/release-component-chart.yaml",
    }
)
# Composite Action lives at repo root, not under .github/. Only the org-wide
# customer-name-scan workflow may pin it to @main.
LATEST_POLICY_COMPOSITE = re.compile(
    r"^(?i:InteractionLabs)/infrastructure/customer-scan@main$"
)
LATEST_POLICY_COMPOSITE_PATH = ".github/workflows/customer-name-scan.yaml"
# The CVE fixes Renovate proposes, read from this action's own checkout of the
# default branch, so a pull request can't list its own update as a fix.
SECURITY_FIXES = Path(__file__).resolve().parents[3] / "helm/renovate"
FIX_ECOSYSTEMS = {"pep621": "pypi", "npm": "npm", "gomod": "go", "cargo": "crates"}
# Managers whose fix names an exact commit in `to_pin`.
PINNED_FIX_ECOSYSTEMS = {"github-actions": "github-commit"}
URGENT_SEVERITIES = {"HIGH", "CRITICAL"}
SECURITY_FIX_PREFIX = "security fix ("
ADVISORY_API = "https://api.github.com/advisories"
ADVISORY_ECOSYSTEMS = {"pypi": "pip", "npm": "npm", "go": "go", "crates": "rust"}
ADVISORY_PAGE_SIZE = 100
KEV_CATALOG = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,}$", re.ASCII)
GHSA_ID = re.compile(r"^GHSA(?:-[0-9a-z]{4}){3}$")
SEMVER = re.compile(
    r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-((?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*)"
    r"(?:\.(?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*))*))?$",
    re.ASCII,
)
PEP440_RELEASE = re.compile(r"^[0-9]+(?:\.[0-9]+)*$")
RANGE_CONSTRAINT = re.compile(r"^(<=|>=|<|>|=)\s*(\S+)$")


class UnverifiableEvidence(ValueError):
    """Raised when no public registry exposes a publication time for the ecosystem."""

    pass


class RejectedEvidence(ValueError):
    """Raised when a registry answered but the coordinate failed an integrity or resolver check."""

    pass


class NonTextDependencyFile(ValueError):
    """Raised when a dependency file holds binary or non-UTF-8 data we can't parse."""

    pass


# Failures that leave a dependency's evidence unknown rather than aborting the run.
LOOKUP_ERRORS = (
    AssertionError,
    http.client.HTTPException,
    json.JSONDecodeError,
    KeyError,
    OSError,
    TypeError,
    urllib.error.URLError,
    ValueError,
)


@dataclass(frozen=True, order=True)
class Dependency:
    """One pinned third-party coordinate found in a changed file."""

    ecosystem: str
    artifact: str
    version: str
    source: str
    digests: tuple[str, ...] = ()
    note: str = field(default="", compare=False)


@dataclass(frozen=True)
class BuildArgOverride:
    """One place that sets a Docker build argument, with its literal value if it has one."""

    path: str
    first_line: int
    last_line: int
    name: str
    value: Optional[str]


@dataclass(frozen=True)
class NameCheck:
    """The literal override values for a name, and the first occurrence we cannot read."""

    values: tuple[str, ...]
    problem: Optional[str]


OverrideLookup = Callable[[str], NameCheck]


@dataclass(frozen=True)
class PublicationEvidence:
    """When a coordinate was published, when it clears the cooldown, and where we learned both."""

    published_at: dt.datetime
    eligible_at: dt.datetime
    source: str


Lookup = tuple[dt.datetime, str]
LookupOutcome = Union[Lookup, Exception]


@dataclass
class Result:
    """The verdict for one dependency, as written to the JSON report."""

    ecosystem: str
    artifact: str
    version: str
    source: str
    evidence: Optional[str]
    published_at: Optional[str]
    eligible_at: Optional[str]
    status: str
    detail: Optional[str] = None


@dataclass
class EvidenceCache:
    """On-disk cache of publication evidence for cacheable coordinates."""

    path: Optional[Path]
    entries: dict[str, dict[str, str]]
    hits: int = 0
    misses: int = 0
    writes: int = 0

    @classmethod
    def load(cls, path: Optional[Path]) -> EvidenceCache:
        """Read the cache file, starting empty if it's missing, corrupt, or from another schema or cooldown."""
        if path is None:
            return cls(None, {})
        try:
            document = json.loads(path.read_text())
        except (json.JSONDecodeError, OSError):
            return cls(path, {})
        if (
            not isinstance(document, dict)
            or document.get("schema") != CACHE_SCHEMA
            or document.get("cooldown_seconds") != int(COOLDOWN.total_seconds())
            or not isinstance(document.get("entries"), dict)
        ):
            return cls(path, {})
        return cls(path, document["entries"])

    def has(self, dependency: Dependency) -> bool:
        """Say whether a coordinate has a cached entry, without counting a hit or miss."""
        return self.path is not None and evidence_cache_key(dependency) in self.entries

    def get(self, dependency: Dependency) -> Optional[PublicationEvidence]:
        """Return the cached evidence for a dependency, dropping the entry if it's malformed."""
        if self.path is None:
            return None
        key = evidence_cache_key(dependency)
        entry = self.entries.get(key)
        try:
            if not isinstance(entry, dict) or set(entry) != {
                "published_at",
                "eligible_at",
                "evidence",
            }:
                raise ValueError("invalid cache entry")
            published = parse_time(entry["published_at"])
            eligible = parse_time(entry["eligible_at"])
            evidence_source = entry["evidence"]
            if not isinstance(evidence_source, str) or not evidence_source:
                raise ValueError("invalid cache evidence")
        except (KeyError, TypeError, ValueError):
            self.entries.pop(key, None)
            self.misses += 1
            return None
        self.hits += 1
        return PublicationEvidence(published, eligible, evidence_source)

    # Publication timestamps are immutable, so entries never expire; status is
    # always recomputed from eligible_at against the current time.
    def put(self, dependency: Dependency, evidence: PublicationEvidence) -> None:
        """Record evidence for a dependency."""
        if self.path is None:
            return
        self.entries[evidence_cache_key(dependency)] = {
            "published_at": evidence.published_at.isoformat(),
            "eligible_at": evidence.eligible_at.isoformat(),
            "evidence": evidence.source,
        }
        self.writes += 1

    def save(self) -> Optional[str]:
        """Write the cache atomically and return the error text on failure."""
        if self.path is None:
            return None
        document = {
            "schema": CACHE_SCHEMA,
            "cooldown_seconds": int(COOLDOWN.total_seconds()),
            "entries": self.entries,
        }
        temporary = self.path.with_name(f"{self.path.name}.tmp")
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            temporary.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
            temporary.replace(self.path)
        except OSError as error:
            return str(error)
        return None


def is_cacheable(dependency: Dependency) -> bool:
    """Say whether a dependency's publication time can't move later, so a cached value stays sound."""
    return dependency.ecosystem in CACHEABLE_ECOSYSTEMS or (
        dependency.ecosystem == "pypi" and bool(dependency.digests)
    )


def evidence_cache_key(dependency: Dependency) -> str:
    """Build the cache key from ecosystem, name, version, and any locked file hashes."""
    key: list[object] = [
        dependency.ecosystem,
        dependency.artifact,
        dependency.version,
    ]
    if dependency.digests:
        key.append(list(dependency.digests))
    return json.dumps(key, separators=(",", ":"))


def run_git_bytes(*args: str) -> bytes:
    """Run git in the target repository and return raw stdout."""
    return subprocess.run(
        ["git", *args],
        cwd=REPOSITORY,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).stdout


def run_git(*args: str) -> str:
    """Run git in the target repository and return stdout as text."""
    return run_git_bytes(*args).decode("utf-8", errors="surrogateescape")


BINARY_SIGNATURES: tuple[tuple[bytes, str], ...] = (
    (b"\x1f\x8b\x08", "application/gzip"),
    (b"PK\x03\x04", "application/zip"),
    (b"PK\x05\x06", "application/zip"),
    (b"PK\x07\x08", "application/zip"),
    (b"\x89PNG", "image/png"),
    (b"\xff\xd8\xff", "image/jpeg"),
    (b"GIF8", "image/gif"),
    (b"BM", "image/bmp"),
    (b"%PDF-", "application/pdf"),
    (b"\xef\xbb\xbf%PDF-", "application/pdf"),
    (b"%!", "application/postscript"),
    (b"{\\rtf", "application/rtf"),
    (b"MZ", "application/x-msdownload"),
    (b"\x7fELF", "application/x-executable"),
    (b"!<arch>", "application/x-unix-archive"),
    (b"BZh", "application/x-bzip2"),
    (b"\xfd7zXZ\x00", "application/x-xz"),
    (b"7z\xbc\xaf\x27\x1c", "application/x-7z-compressed"),
    (b"Rar!\x1a\x07", "application/x-rar-compressed"),
    (b"\x28\xb5\x2f\xfd", "application/zstd"),
    (b"SQLite format 3\x00", "application/x-sqlite3"),
    (b"\x00asm", "application/wasm"),
)


def binary_format(content: bytes) -> Optional[str]:
    """Name the binary format of the content, or return None for text.

    Signatures cover formats whose headers can pass as UTF-8 text; anything
    else binary is caught by the NUL check or by UTF-8 decoding.
    """
    for signature, mime in BINARY_SIGNATURES:
        if content.startswith(signature):
            return mime
    if content[257:262] == b"ustar":
        return "application/x-tar"
    if b"\0" in content[:8192]:
        return "binary"
    return None


def git_file(revision: str, path: str) -> str:
    """Read a file at a revision, returning an empty string if it doesn't exist there."""
    try:
        content = run_git_bytes("show", f"{revision}:{path}")
    except subprocess.CalledProcessError:
        return ""
    if file_format := binary_format(content):
        raise NonTextDependencyFile(f"{path} contains {file_format} data")
    try:
        return content.decode("utf-8")
    except UnicodeDecodeError as error:
        raise NonTextDependencyFile(f"{path} is not valid UTF-8 text") from error


def parse_time(value: object) -> dt.datetime:
    """Parse an ISO 8601 timestamp that carries a timezone into UTC."""
    parsed = dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include a timezone")
    return parsed.astimezone(UTC)


def add_requirement(found: set[Dependency], requirement: str, source: str) -> None:
    """Add a pypi dependency for an exact `==` requirement line."""
    match = re.match(
        r"^\s*([A-Za-z0-9_.-]+(?:\[[^]]+\])?)\s*==\s*([^;\s]+)",
        requirement,
    )
    if match:
        found.add(
            Dependency(
                "pypi",
                match.group(1).split("[", 1)[0].lower(),
                match.group(2),
                source,
            )
        )


def discover_github_actions(path: str, text: str) -> set[Dependency]:
    """Find `uses:` references in workflow files."""
    found: set[Dependency] = set()
    if not path.startswith(".github/") or not path.endswith((".yml", ".yaml")):
        return found
    for match in re.finditer(r"(?m)^\s*(?:-\s*)?uses:\s*([^\s#]+)", text):
        target = match.group(1).strip("\"'")
        if target.startswith("./"):
            continue
        policy_reference = LATEST_POLICY_REFERENCE.fullmatch(target)
        if (
            policy_reference
            and (
                path in LATEST_POLICY_PATHS.get(policy_reference["kind"], ())
                or (
                    policy_reference["kind"] in LATEST_POLICY_WORKFLOWS
                    and policy_reference["repository"].casefold() == "infrastructure"
                    and path.startswith(".github/workflows/")
                )
            )
        ) or (
            LATEST_POLICY_COMPOSITE.fullmatch(target)
            and path == LATEST_POLICY_COMPOSITE_PATH
        ):
            artifact, version = target.rsplit("@", 1)
            found.add(Dependency("policy-exception", artifact, version, path))
            continue
        if target.startswith("docker://"):
            image = target.removeprefix("docker://")
            if "@" in image and SHA256_DIGEST.fullmatch(image.rsplit("@", 1)[1]):
                artifact, digest = image.rsplit("@", 1)
                found.add(Dependency("oci", artifact, digest, path))
            else:
                found.add(Dependency("mutable", image, target, path))
            continue
        if "@" not in target:
            found.add(Dependency("mutable", target, target, path))
            continue
        artifact, version = target.rsplit("@", 1)
        ecosystem = "github-commit" if FULL_SHA.fullmatch(version) else "mutable"
        found.add(Dependency(ecosystem, artifact, version, path))
    return found


def expand_variables(value: str, values: dict[str, str]) -> tuple[str, list[str]]:
    """Substitute known variables, and list the references that stay unexpanded."""

    def substitute(match: re.Match[str]) -> str:
        name = match.group("env") or match.group("braced") or match.group("bare")
        return values.get(name, match.group(0))

    expanded = VARIABLE_REFERENCE.sub(substitute, value)
    return expanded, UNEXPANDED_REFERENCE.findall(expanded)


def variable_name(reference: str) -> str:
    """Return the bare name inside a `$NAME`, `${NAME}` or `${{ env.NAME }}` reference."""
    match = re.search(r"[A-Za-z_][\w.]*", reference.removeprefix("${{").lstrip(" "))
    name = match.group(0) if match else reference
    return name.removeprefix("env.")


def literal_value(text: str, position: int = 0) -> Optional[str]:
    """Return the quoted or bare literal at a position, or None if the value is computed."""
    match = LITERAL_VALUE.match(text, position)
    if match is None:
        return None
    return next(group for group in match.groups() if group is not None)


def literal_assignments(text: str) -> dict[str, str]:
    """Collect variables a file assigns exactly one literal value, ignoring all others."""
    assigned: dict[str, set[Optional[str]]] = {}

    def record(name: str, value: Optional[str]) -> None:
        assigned.setdefault(name, set()).add(value)

    env_indent: Optional[int] = None
    in_locals = False
    locals_depth = 0
    for line in text.splitlines():
        for match in SHELL_ASSIGNMENT.finditer(line):
            record(match.group(1), literal_value(line, match.end()))
        if re.match(r"^locals\s*\{", line):
            in_locals = True
            locals_depth = 1
            continue
        if in_locals:
            if line.startswith("}"):
                in_locals = False
                continue
            entry = TERRAFORM_ENTRY.match(line)
            if entry and locals_depth == 1:
                record(f"local.{entry.group(1)}", literal_value(entry.group(2)))
            unquoted = re.sub(r'"(?:[^"\\]|\\.)*"', '""', line)
            locals_depth += unquoted.count("{") - unquoted.count("}")
            continue
        entry = YAML_ENTRY.match(line)
        if entry is None:
            continue
        indent = len(entry.group(1))
        if env_indent is not None and indent <= env_indent:
            env_indent = None
        if entry.group(2) == "env" and not entry.group(3):
            env_indent = indent
        elif env_indent is not None:
            record(entry.group(2), literal_value(entry.group(3) or ""))
    literals: dict[str, str] = {}
    for name, values in assigned.items():
        (only,) = values if len(values) == 1 else (None,)
        if only is not None:
            literals[name] = only
    return literals


def override_value(raw: Optional[str], assignments: dict[str, str]) -> Optional[str]:
    """Return an override's literal value, or None if it is absent or computed."""
    if raw is None:
        return None
    value = raw
    single_quoted = len(value) > 1 and value[0] == value[-1] == "'"
    if len(value) > 1 and value[0] == value[-1] and value[0] in "\"'":
        value = value[1:-1]
    if single_quoted and "$" in value:
        return None
    expanded, unexpanded = expand_variables(value, assignments)
    if unexpanded or not OVERRIDE_VALUE.fullmatch(expanded):
        return None
    return expanded


def logical_lines(text: str) -> list[tuple[int, int, str]]:
    """Join backslash-continued lines into `(first line, last line, text)` triples."""
    joined: list[tuple[int, int, str]] = []
    pending: Optional[tuple[int, str]] = None
    for number, line in enumerate(text.splitlines(), 1):
        start = number
        if pending is not None:
            start, line = pending[0], pending[1] + " " + line.strip()
        if line.rstrip().endswith("\\"):
            pending = (start, line.rstrip()[:-1])
            continue
        pending = None
        joined.append((start, number, line))
    if pending is not None:
        joined.append((pending[0], pending[0], pending[1]))
    return joined


def structured_parent_keys(lines: list[str]) -> list[str]:
    """Return, for each line, the key of the nearest enclosing line by indentation."""
    parents: list[str] = []
    stack: list[tuple[int, bool, str]] = []
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            parents.append("")
            continue
        indent = len(line) - len(line.lstrip())
        is_item = stripped.startswith("- ")
        while stack and (
            stack[-1][0] > indent
            or (stack[-1][0] == indent and not (is_item and not stack[-1][1]))
        ):
            stack.pop()
        parents.append(stack[-1][2] if stack else "")
        key = re.match(r"-?\s*[\"']?([\w-]+)[\"']?\s*(?:[:=]|$)", stripped)
        stack.append((indent, is_item, key.group(1) if key else ""))
    return parents


def scan_build_arg_overrides(path: str, text: str) -> list[BuildArgOverride]:
    """Find the places a file sets a Docker build argument in a form we parse."""
    found: list[BuildArgOverride] = []
    assignments = literal_assignments(text)

    def add(first: int, last: int, token: str) -> None:
        if len(token) > 1 and token[0] == token[-1] and token[0] in "\"'":
            token = token[1:-1]
        name, separator, value = token.partition("=")
        found.append(
            BuildArgOverride(
                path,
                first,
                last,
                name,
                override_value(value, assignments) if separator else None,
            )
        )

    for first, last, line in logical_lines(text):
        for match in BUILD_ARG_FLAG.finditer(line):
            add(first, last, match.group(1))
        for match in BAKE_SET_FLAG.finditer(line):
            add(first, last, match.group(1))
    if path.endswith((".yml", ".yaml", ".hcl", ".json")):
        lines = text.splitlines()
        parents = structured_parent_keys(lines)
        for index, line in enumerate(lines):
            number = index + 1
            for match in INLINE_BUILD_ARGS.finditer(line):
                for pair in INLINE_BUILD_ARG_PAIR.finditer(match.group(1)):
                    add(number, number, f"{pair.group(1)}={pair.group(2)}")
            entry = BUILD_ARG_ENTRY.match(line)
            if entry and parents[index] in BUILD_ARG_KEYS:
                found.append(
                    BuildArgOverride(
                        path,
                        number,
                        number,
                        entry.group(1),
                        override_value(entry.group(2), assignments),
                    )
                )
    return found


def is_dockerfile_declaration_or_use(path: str, text: str, name: str) -> bool:
    """Say whether a line is a Dockerfile `ARG`/`ENV` declaration or only references the name."""
    if "Dockerfile" not in Path(path).name:
        return False
    if re.match(r"\s*(?:ARG|ENV)\s", text, re.IGNORECASE):
        return True
    remainder = re.sub(rf"\$\{{{name}[^}}]*\}}|\${name}\b", "", text)
    return re.search(rf"\b{name}\b", remainder) is None


def name_occurrences(revision: str, name: str) -> list[tuple[str, int, str]]:
    """List every `(path, line, text)` where a word occurs in any file at a revision."""
    completed = subprocess.run(
        ["git", "grep", "-n", "-z", "-a", "-w", "-F", "-e", name, revision, "--"],
        cwd=REPOSITORY,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if completed.returncode == 1:
        return []
    if completed.returncode != 0:
        raise subprocess.CalledProcessError(
            completed.returncode,
            completed.args,
            output=completed.stdout,
            stderr=completed.stderr,
        )
    prefix = os.fsencode(f"{revision}:")
    output = completed.stdout
    hits: list[tuple[str, int, str]] = []
    position = 0
    while position < len(output):
        path_end = output.index(b"\0", position)
        line_end = output.index(b"\0", path_end + 1)
        end = output.index(b"\n", line_end)
        if not output.startswith(prefix, position):
            raise ValueError("git grep returned an unexpected source")
        hits.append(
            (
                os.fsdecode(output[position + len(prefix) : path_end]),
                int(output[path_end + 1 : line_end]),
                output[line_end + 1 : end].decode("utf-8", errors="replace"),
            )
        )
        position = end + 1
    return hits


def make_override_lookup(revision: str) -> OverrideLookup:
    """Build a cached lookup that checks every occurrence of a name at a revision."""
    cache: dict[str, NameCheck] = {}
    scans: dict[str, Optional[list[BuildArgOverride]]] = {}

    def scan(path: str) -> Optional[list[BuildArgOverride]]:
        if path not in scans:
            try:
                scans[path] = scan_build_arg_overrides(path, git_file(revision, path))
            except NonTextDependencyFile:
                scans[path] = None
        return scans[path]

    def lookup(name: str) -> NameCheck:
        if name not in cache:
            values: set[str] = set()
            problem: Optional[str] = None
            for path, number, text in name_occurrences(revision, name):
                if path.endswith((".md", ".mdx")) or is_dockerfile_declaration_or_use(
                    path, text, name
                ):
                    continue
                parsed = [
                    o
                    for o in scan(path) or []
                    if o.name == name and o.first_line <= number <= o.last_line
                ]
                if parsed and all(o.value is not None for o in parsed):
                    values.update(o.value for o in parsed if o.value is not None)
                elif problem is None:
                    problem = f"{path}:{number}"
            cache[name] = NameCheck(tuple(sorted(values)), problem)
        return cache[name]

    return lookup


def parse_arg_declarations(line: str) -> list[tuple[str, Optional[str]]]:
    """Return the `(name, default)` pairs declared by one Dockerfile `ARG` line."""
    arg = DOCKERFILE_ARG.match(line)
    if arg is None:
        return []
    try:
        tokens = shlex.split(arg.group(1))
    except ValueError:
        return []
    declarations: list[tuple[str, Optional[str]]] = []
    for token in tokens:
        name, separator, default = token.partition("=")
        declarations.append((name, default if separator else None))
    return declarations


def resolve_global_args(
    declarations: list[tuple[str, Optional[str]]], forced: dict[str, str]
) -> dict[str, str]:
    """Resolve global `ARG` defaults, letting `forced` replace a declared default."""
    defaults: dict[str, str] = {}
    for name, default in declarations:
        if default is None:
            defaults.pop(name, None)
            continue
        expanded, unexpanded = expand_variables(forced.get(name, default), defaults)
        if unexpanded:
            defaults.pop(name, None)
        else:
            defaults[name] = expanded
    return defaults


def arg_dependencies(
    declarations: list[tuple[str, Optional[str]]],
) -> dict[str, set[str]]:
    """Map each global `ARG` to every argument whose value can change it."""
    dependencies: dict[str, set[str]] = {}
    for name, default in declarations:
        references = {
            match.group("env") or match.group("braced") or match.group("bare")
            for match in VARIABLE_REFERENCE.finditer(default or "")
        }
        dependencies[name] = {name}.union(
            *(dependencies.get(reference, {reference}) for reference in references)
        )
    return dependencies


def override_combinations(
    options: dict[str, list[str]],
) -> Optional[list[dict[str, str]]]:
    """Return each way to pick a default or an override per name, or None if too many."""
    if math.prod(len(values) + 1 for values in options.values()) > (
        OVERRIDE_COMBINATION_LIMIT
    ):
        return None
    combinations: list[dict[str, str]] = [{}]
    for name, values in options.items():
        combinations = [
            {**combination, **({name: value} if value is not None else {})}
            for combination in combinations
            for value in [None, *values]
        ]
    return combinations


def container_dependency(path: str, image: str) -> Dependency:
    """Classify one resolved base image as a digest-pinned or mutable coordinate."""
    if "@" in image and SHA256_DIGEST.fullmatch(image.rsplit("@", 1)[1]):
        artifact, digest = image.rsplit("@", 1)
        return Dependency("oci", artifact, digest, path)
    return Dependency("mutable", image.split(":", 1)[0], image, path)


def discover_containers(
    path: str, text: str, overrides: Optional[OverrideLookup] = None
) -> set[Dependency]:
    """Find base images in Dockerfile `FROM` lines.

    A variable resolves from a global `ARG` default only if no file overrides
    the argument in a way we cannot read; literal overrides are judged as further
    coordinates and anything else leaves the `FROM` unresolved.
    """
    found: set[Dependency] = set()
    if "Dockerfile" not in Path(path).name:
        return found
    stages: set[str] = set()
    declarations: list[tuple[str, Optional[str]]] = []
    seen_from = False
    for number, line in enumerate(text.splitlines(), 1):
        match = DOCKERFILE_FROM.match(line)
        if match is None:
            if DOCKERFILE_FROM_PREFIX.match(line):
                seen_from = True
            elif not seen_from:
                declarations.extend(parse_arg_declarations(line))
            continue
        seen_from = True
        written = match.group(1)
        alias = match.group(2)
        referenced = {
            reference.group("env")
            or reference.group("braced")
            or reference.group("bare")
            for reference in VARIABLE_REFERENCE.finditer(written)
        }
        defaults = resolve_global_args(declarations, {})
        dependencies = arg_dependencies(declarations)
        affected = sorted(
            {
                name
                for reference in referenced
                for name in dependencies.get(reference, {reference})
                if name in defaults
            }
        )
        failure: Optional[str] = None
        options: dict[str, list[str]] = {}
        for name in affected:
            check = overrides(name) if overrides else NameCheck((), None)
            options[name] = list(check.values)
            if check.problem is not None and failure is None:
                failure = (
                    f"{check.problem} mentions ARG {name} outside its Dockerfile "
                    "declaration; rename the ARG or pin the FROM literally"
                )
        combinations = override_combinations(options)
        if combinations is None:
            failure = (
                failure or "too many ARG overrides to judge; pin the FROM literally"
            )
            combinations = [{}]
        images: set[str] = set()
        for forced in combinations:
            image, missing = expand_variables(
                written, resolve_global_args(declarations, forced)
            )
            if missing:
                failure = failure or (
                    f"give ARG {variable_name(missing[0])} "
                    "a literal default pinned to a digest"
                )
            else:
                images.add(image)
        for image in images:
            if image.lower() != "scratch" and image.lower() not in stages:
                found.add(container_dependency(path, image))
        if failure is not None:
            found.add(
                Dependency(
                    "unresolved",
                    f"FROM {written}",
                    "",
                    path,
                    note=f"{path}:{number} FROM {written} — {failure}",
                )
            )
        if alias:
            stages.add(alias.lower())
    return found


def uv_lock_digests(package: dict[str, Any]) -> tuple[str, ...]:
    """Return the sorted sha256 hashes of a uv.lock package, or nothing if any is missing or malformed."""
    files = [package.get("sdist"), *package.get("wheels", [])]
    digests = {
        str(item["hash"]).lower()
        for item in files
        if isinstance(item, dict) and item.get("hash")
    }
    if not digests or not all(SHA256_DIGEST.fullmatch(digest) for digest in digests):
        return ()
    return tuple(sorted(digests))


def local_project_requirement(
    requirement: str, sources: dict[str, Any], path: str
) -> bool:
    """Say whether a requirement names a local path project whose pyproject matches the pinned name and version."""
    match = re.fullmatch(r"\s*([A-Za-z0-9_.-]+)\s*==\s*([^;\s]+)\s*", requirement)
    if not match:
        return False
    name, version = match.groups()
    source = sources.get(name, {})
    if not isinstance(source, dict) or set(source) - {"path", "editable"}:
        return False
    location = source.get("path")
    if not isinstance(location, str) or Path(location).is_absolute():
        return False
    target = (
        REPOSITORY_ROOT / Path(path).parent / location / "pyproject.toml"
    ).resolve()
    if not target.is_relative_to(REPOSITORY_ROOT):
        return False
    try:
        project = tomllib.loads(target.read_text()).get("project", {})
    except (OSError, tomllib.TOMLDecodeError):
        return False

    def normalize(value: str) -> str:
        return re.sub(r"[-_.]+", "-", value).lower()

    return (
        isinstance(project.get("name"), str)
        and normalize(project["name"]) == normalize(name)
        and project.get("version") == version
    )


def discover_toml(path: str, text: str) -> set[Dependency]:
    """Find dependencies in uv.lock, pyproject.toml, and mise TOML files."""
    found: set[Dependency] = set()
    if path.endswith("uv.lock"):
        try:
            document = tomllib.loads(text)
        except tomllib.TOMLDecodeError:
            return {Dependency("unparseable", path, "invalid TOML", path)}
        for package in document.get("package", []):
            source = package.get("source", {})
            if isinstance(source, dict) and source.get("registry"):
                found.add(
                    Dependency(
                        "pypi",
                        str(package["name"]).lower(),
                        str(package["version"]),
                        path,
                        uv_lock_digests(package),
                    )
                )
        return found
    if path.endswith("Cargo.lock"):
        try:
            document = tomllib.loads(text)
        except tomllib.TOMLDecodeError:
            return {Dependency("unparseable", path, "invalid TOML", path)}
        for package in document.get("package", []):
            if str(package.get("source", "")).startswith("registry+"):
                found.add(
                    Dependency(
                        "crates",
                        str(package["name"]),
                        str(package["version"]),
                        path,
                    )
                )
        return found
    if Path(path).name in {"mise.toml", ".mise.toml"}:
        try:
            tools = tomllib.loads(text).get("tools", {})
        except tomllib.TOMLDecodeError:
            return {Dependency("unparseable", path, "invalid TOML", path)}
        for name, configured in tools.items():
            versions = configured if isinstance(configured, list) else [configured]
            for version in versions:
                if isinstance(version, str):
                    found.add(Dependency("mise", name, version, path))
        return found
    if path.endswith("pyproject.toml"):
        try:
            document = tomllib.loads(text)
        except tomllib.TOMLDecodeError:
            return {Dependency("unparseable", path, "invalid TOML", path)}
        project = document.get("project", {})
        sources = document.get("tool", {}).get("uv", {}).get("sources", {})

        def add_project_requirement(requirement: str) -> None:
            if not local_project_requirement(requirement, sources, path):
                add_requirement(found, requirement, path)

        for requirement in project.get("dependencies", []):
            add_project_requirement(requirement)
        for requirements in project.get("optional-dependencies", {}).values():
            for requirement in requirements:
                add_project_requirement(requirement)
        for requirements in document.get("dependency-groups", {}).values():
            if isinstance(requirements, list):
                for requirement in requirements:
                    if isinstance(requirement, str):
                        add_project_requirement(requirement)
    return found


def discover_javascript(path: str, text: str) -> set[Dependency]:
    """Find dependencies in npm and pnpm lockfiles."""
    found: set[Dependency] = set()
    if path.endswith(("package-lock.json", "npm-shrinkwrap.json")):
        try:
            document = json.loads(text)
        except json.JSONDecodeError:
            return {Dependency("unparseable", path, "invalid JSON", path)}
        for package_path, package in document.get("packages", {}).items():
            if "node_modules/" not in package_path or not isinstance(package, dict):
                continue
            version = package.get("version")
            if not isinstance(version, str) or version.startswith(("file:", "link:")):
                continue
            name = package_path.rsplit("node_modules/", 1)[1]
            found.add(Dependency("npm", name, version, path))
        return found
    if path.endswith("pnpm-lock.yaml"):
        key = re.compile(
            r"(?m)^\s{2,}['\"]?/?(@?[^@'\"\s:]+(?:/[^@'\"\s:]+)?)@"
            r"([0-9][^('\"\s:]*)"
        )
        for match in key.finditer(text):
            version = match.group(2).rstrip(":")
            if re.match(r"^[0-9]", version):
                found.add(Dependency("npm", match.group(1), version, path))
    return found


def discover_go(path: str, text: str) -> set[Dependency]:
    """Find modules in go.mod and go.sum."""
    found: set[Dependency] = set()
    if not path.endswith(("go.mod", "go.sum")):
        return found
    for line in text.splitlines():
        match = re.match(r"\s*([^\s]+)\s+(v[0-9][^\s/]+)", line)
        if match:
            found.add(Dependency("go", match.group(1), match.group(2), path))
    return found


def discover_terraform(path: str, text: str) -> set[Dependency]:
    """Find Terraform modules and provider lock entries."""
    found: set[Dependency] = set()
    if path.endswith(".tf"):
        block = re.compile(r'(?ms)^\s*module\s+"[^"]+"\s*\{(.*?^\s*\})')
        for match in block.finditer(text):
            body = match.group(1)
            source_match = re.search(r'(?m)^\s*source\s*=\s*"([^"]+)"', body)
            if not source_match:
                continue
            source = source_match.group(1)
            if source.startswith(("./", "../")):
                continue
            version_match = re.search(r'(?m)^\s*version\s*=\s*"([^"]+)"', body)
            if version_match:
                found.add(
                    Dependency(
                        "terraform-module",
                        source,
                        version_match.group(1),
                        path,
                    )
                )
                continue
            parsed = urllib.parse.urlparse(source.removeprefix("git::"))
            reference = urllib.parse.parse_qs(parsed.query).get("ref", [None])[0]
            artifact = source.split("?", 1)[0]
            if reference and FULL_SHA.fullmatch(reference):
                found.add(Dependency("terraform-module", artifact, reference, path))
            else:
                found.add(Dependency("mutable", artifact, source, path))
        return found
    if not path.endswith(".terraform.lock.hcl"):
        return found
    provider: Optional[str] = None
    for line in text.splitlines():
        provider_block = re.match(
            r'\s*provider\s+"registry\.terraform\.io/([^"]+)"\s*{', line
        )
        if provider_block:
            provider = provider_block.group(1)
            continue
        version = re.match(r'\s*version\s*=\s*"([^"]+)"', line)
        if provider and version:
            found.add(
                Dependency("terraform-provider", provider, version.group(1), path)
            )
        if line.strip() == "}":
            provider = None
    return found


def discover_precommit(path: str, text: str) -> set[Dependency]:
    """Find pre-commit hook repositories and their revisions."""
    found: set[Dependency] = set()
    if path != ".pre-commit-config.yaml":
        return found
    repository: Optional[str] = None
    for line in text.splitlines():
        repo = re.search(r"repo:\s*https://github\.com/([^\s]+?)(?:\.git)?\s*$", line)
        if repo:
            repository = repo.group(1).removesuffix(".git")
        revision = re.search(r"rev:\s*([^\s#]+)", line)
        if repository and revision:
            found.add(Dependency("github-tag", repository, revision.group(1), path))
            repository = None
    return found


def discover_charts(path: str, text: str) -> set[Dependency]:
    """Find Helm chart dependencies in Chart.yaml and Chart.lock."""
    found: set[Dependency] = set()
    if not path.endswith(("Chart.yaml", "Chart.lock")):
        return found
    name: Optional[str] = None
    repository = ""
    for line in text.splitlines():
        current_name = re.match(r"\s*-?\s*name:\s*([^\s#]+)", line)
        if current_name:
            name = current_name.group(1)
            repository = ""
            continue
        current_repository = re.match(r"\s*repository:\s*([^\s#]+)", line)
        if current_repository:
            repository = current_repository.group(1)
            continue
        version = re.match(r"\s*version:\s*([^\s#]+)", line)
        if name and repository and version:
            found.add(
                Dependency("helm", f"{name}|{repository}", version.group(1), path)
            )
            name = None
    return found


def discover_release_assets(
    path: str,
    text: str,
    source: Optional[str] = None,
    overrides: Optional[OverrideLookup] = None,
) -> set[Dependency]:
    """Find GitHub release download URLs in text, resolving variables the file assigns literally.

    In a Dockerfile, a variable also resolves only if no file overrides it in a
    way we cannot read.
    """
    found: set[Dependency] = set()
    name = Path(path).name
    is_makefile = name in {"Makefile", "makefile", "GNUmakefile"} or name.endswith(
        ".mk"
    )
    values = (
        literal_assignments(source) if source is not None and not is_makefile else {}
    )
    for match in RELEASE_ASSET_PATTERN.finditer(text):
        written = match.group(0)
        location = path
        if source is not None and written in source:
            line = source[: source.index(written)].count(chr(10)) + 1
            location += f":{line}"
        urls = [written]
        failure: Optional[str] = None
        release = written[: match.start(3) - match.start()]
        if "$" in written:
            options: dict[str, list[str]] = {}
            for reference in VARIABLE_REFERENCE.finditer(written):
                variable = (
                    reference.group("env")
                    or reference.group("braced")
                    or reference.group("bare")
                )
                if variable not in values or variable in options:
                    continue
                check = (
                    overrides(variable)
                    if overrides and "Dockerfile" in name
                    else NameCheck((), None)
                )
                options[variable] = list(check.values)
                if check.problem is not None and failure is None:
                    failure = (
                        f"{location} release URL uses {variable} \u2014 "
                        f"{check.problem} mentions it outside its Dockerfile "
                        "declaration; rename the variable or pin the URL"
                    )
            combinations = override_combinations(options)
            if combinations is None:
                failure = failure or (
                    f"{location} release URL has too many overrides to judge "
                    "\u2014 pin the URL"
                )
                combinations = [{}]
            urls = []
            for forced in combinations:
                expanded, _ = expand_variables(written, {**values, **forced})
                unexpanded = expand_variables(release, {**values, **forced})[1]
                if unexpanded:
                    failure = failure or (
                        f"{location} release URL uses {unexpanded[0]} \u2014 "
                        f"assign {variable_name(unexpanded[0])} a literal value "
                        "in this file or pin the URL"
                    )
                else:
                    urls.append(expanded)
        for url in urls:
            resolved = RELEASE_ASSET_PATTERN.match(url)
            if resolved is None:
                failure = failure or f"{location} release URL could not be resolved"
                continue
            found.add(
                Dependency(
                    "github-release",
                    f"{resolved.group(1)}/{resolved.group(3)}",
                    resolved.group(2),
                    path,
                )
            )
        if failure is not None:
            found.add(
                Dependency(
                    "unresolved",
                    f"{match.group(1)}/{match.group(3)}",
                    match.group(2),
                    path,
                    note=failure,
                )
            )
    return found


def discover_text(
    path: str, text: str, overrides: Optional[OverrideLookup] = None
) -> list[Dependency]:
    """Run every discoverer over a file's text."""
    found: set[Dependency] = set()
    found.update(discover_containers(path, text, overrides))
    for discoverer in (
        discover_github_actions,
        discover_toml,
        discover_javascript,
        discover_go,
        discover_terraform,
        discover_precommit,
        discover_charts,
    ):
        found.update(discoverer(path, text))
    if path.endswith(("requirements.txt", "requirements-dev.txt")):
        for line in text.splitlines():
            add_requirement(found, line, path)
    return sorted(found)


def has_dependency_parser(path: str) -> bool:
    """Say whether any discoverer reads this path."""
    name = Path(path).name
    return (
        (path.startswith(".github/") and path.endswith((".yml", ".yaml")))
        or "Dockerfile" in name
        or path.endswith(
            (
                "uv.lock",
                "Cargo.lock",
                "pyproject.toml",
                "package-lock.json",
                "npm-shrinkwrap.json",
                "pnpm-lock.yaml",
                "go.mod",
                "go.sum",
                ".tf",
                ".terraform.lock.hcl",
                "Chart.yaml",
                "Chart.lock",
                "requirements.txt",
                "requirements-dev.txt",
            )
        )
        or name in {"mise.toml", ".mise.toml"}
        or path == ".pre-commit-config.yaml"
    )


def discover_file(
    revision: str, path: str, overrides: Optional[OverrideLookup] = None
) -> set[Dependency]:
    """Discover dependencies in a file at a revision, flagging unreadable files as unparseable."""
    try:
        return set(discover_text(path, git_file(revision, path), overrides))
    except NonTextDependencyFile as error:
        return {Dependency("unparseable", path, str(error), path)}


def release_asset_dependencies(
    revision: str, paths: list[str], overrides: Optional[OverrideLookup] = None
) -> set[Dependency]:
    """Find release asset URLs in any text file using git grep, which scales to large trees."""
    found: set[Dependency] = set()
    sources: dict[tuple[str, str], Optional[str]] = {}
    revision_prefix = os.fsencode(f"{revision}:")
    for offset in range(0, len(paths), 128):
        pathspecs = [f":(literal){path}" for path in paths[offset : offset + 128]]
        completed = subprocess.run(
            [
                "git",
                "grep",
                "-I",
                "-o",
                "-E",
                "-z",
                RELEASE_ASSET_GREP_PATTERN,
                revision,
                "--",
                *pathspecs,
            ],
            cwd=REPOSITORY,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if completed.returncode == 1:
            continue
        if completed.returncode != 0:
            raise subprocess.CalledProcessError(
                completed.returncode,
                completed.args,
                output=completed.stdout,
                stderr=completed.stderr,
            )
        position = 0
        while position < len(completed.stdout):
            separator = completed.stdout.index(b"\0", position)
            end = completed.stdout.index(b"\n", separator)
            location = completed.stdout[position:separator]
            match = completed.stdout[separator + 1 : end]
            if not location.startswith(revision_prefix):
                raise ValueError("git grep returned an unexpected source")
            path = os.fsdecode(location[len(revision_prefix) :])
            text = match.decode("utf-8", errors="replace")
            source = None
            if "$" in text:
                if (revision, path) not in sources:
                    try:
                        sources[(revision, path)] = git_file(revision, path)
                    except NonTextDependencyFile:
                        sources[(revision, path)] = None
                source = sources[(revision, path)]
            found.update(discover_release_assets(path, text, source, overrides))
            position = end + 1
    return found


def git_grep_output(*arguments: str) -> bytes:
    """Run git grep, treating no match as empty output and any other failure as an error."""
    completed = subprocess.run(
        ["git", "grep", *arguments],
        cwd=REPOSITORY,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if completed.returncode == 1:
        return b""
    if completed.returncode != 0:
        raise subprocess.CalledProcessError(
            completed.returncode,
            completed.args,
            output=completed.stdout,
            stderr=completed.stderr,
        )
    return completed.stdout


def dockerfiles_naming_changed_words(head: str, paths: list[str]) -> list[str]:
    """Find Dockerfiles at head that declare an `ARG` whose name a changed file mentions."""
    paths = [
        path for path in paths if Path(path).suffix.casefold() not in NON_TEXT_SUFFIXES
    ]
    if not paths:
        return []
    prefix = os.fsencode(f"{head}:")
    declared: dict[str, set[str]] = {}
    output = git_grep_output(
        "-n",
        "-z",
        "-a",
        "-i",
        "-E",
        "-e",
        "^[[:space:]]*ARG[[:space:]]",
        head,
        "--",
        ":(glob)**/*Dockerfile*",
    )
    position = 0
    while position < len(output):
        path_end = output.index(b"\0", position)
        line_end = output.index(b"\0", path_end + 1)
        end = output.index(b"\n", line_end)
        path = os.fsdecode(output[position + len(prefix) : path_end])
        text = output[line_end + 1 : end].decode("utf-8", errors="replace")
        for name, _ in parse_arg_declarations(text):
            declared.setdefault(name, set()).add(path)
        position = end + 1
    mentioned: set[str] = set()
    names = sorted(declared)
    for name_offset in range(0, len(names), 200):
        name_arguments = [
            argument
            for name in names[name_offset : name_offset + 200]
            for argument in ("-e", name)
        ]
        for path_offset in range(0, len(paths), 128):
            output = git_grep_output(
                "-o",
                "-z",
                "-a",
                "-w",
                "-F",
                *name_arguments,
                head,
                "--",
                *[
                    f":(literal){path}"
                    for path in paths[path_offset : path_offset + 128]
                ],
            )
            position = 0
            while position < len(output):
                separator = output.index(b"\0", position)
                end = output.index(b"\n", separator)
                mentioned.add(output[separator + 1 : end].decode("utf-8", "replace"))
                position = end + 1
    return sorted({path for name in mentioned for path in declared.get(name, ())})


def previous_versions_of(
    added: set[Dependency], removed: set[Dependency]
) -> dict[Dependency, Union[str, tuple[str, ...]]]:
    """Map each added coordinate to the version of the same package that the change replaced.

    A package that loses several versions in a directory, as when a lockfile
    dedupes them to one, maps to all of them as a sorted tuple. A package that
    gains more than one version is ambiguous and gets no entry, as does a
    package with no removed version.
    """

    def package(dependency: Dependency) -> tuple[str, str, str]:
        return (
            os.path.dirname(dependency.source),
            dependency.ecosystem,
            dependency.artifact,
        )

    new_versions: dict[tuple[str, str, str], set[str]] = {}
    old_versions: dict[tuple[str, str, str], set[str]] = {}
    for dependency in added:
        new_versions.setdefault(package(dependency), set()).add(dependency.version)
    for dependency in removed:
        old_versions.setdefault(package(dependency), set()).add(dependency.version)
    return {
        dependency: (
            next(iter(old_versions[package(dependency)]))
            if len(old_versions[package(dependency)]) == 1
            else tuple(sorted(old_versions[package(dependency)]))
        )
        for dependency in added
        if len(new_versions[package(dependency)]) == 1
        and package(dependency) in old_versions
    }


def dependency_changes(
    base: str, head: str
) -> tuple[list[Dependency], dict[Dependency, Union[str, tuple[str, ...]]]]:
    """Return dependencies present at head but not at base, and the version each one replaced."""
    found: set[Dependency] = set()
    removed: set[Dependency] = set()
    paths = [
        path
        for path in run_git(
            "diff", "--diff-filter=ACMRTUXB", "--name-only", "-z", base, head, "--"
        ).split("\0")
        if path and not path.casefold().endswith(".tgz")
    ]
    base_overrides = make_override_lookup(base)
    head_overrides = make_override_lookup(head)
    candidates = list(
        dict.fromkeys([*paths, *dockerfiles_naming_changed_words(head, paths)])
    )
    for path in candidates:
        if not has_dependency_parser(path):
            continue
        old = discover_file(base, path, base_overrides)
        new = discover_file(head, path, head_overrides)
        found.update(new - old)
        removed.update(old - new)
    previous = previous_versions_of(found, removed)
    found.update(
        release_asset_dependencies(head, candidates, head_overrides)
        - release_asset_dependencies(base, candidates, base_overrides)
    )
    return sorted(found), previous


def dependency_delta(base: str, head: str) -> list[Dependency]:
    """Return dependencies present at head but not at base."""
    return dependency_changes(base, head)[0]


def is_retryable(status: int) -> bool:
    """Say whether an HTTP status is a transient failure worth retrying."""
    return status == 429 or status >= 500


def parse_retry_after(value: str) -> Optional[float]:
    """Parse a Retry-After header, in seconds or as an HTTP date, into a delay."""
    try:
        return max(0.0, float(value))
    except ValueError:
        pass
    try:
        when = email.utils.parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=UTC)
    return max(0.0, (when - dt.datetime.now(UTC)).total_seconds())


def retry_delay(error: urllib.error.URLError | OSError, attempt: int) -> float:
    """Honour Retry-After, else back off exponentially with half jitter."""
    headers = getattr(error, "headers", None)
    retry_after = headers.get("Retry-After") if headers else None
    if (
        retry_after is not None
        and (delay := parse_retry_after(retry_after)) is not None
    ):
        return delay
    ceiling: float = min(RETRY_MAX_DELAY_SECONDS, RETRY_BASE_DELAY_SECONDS * 2**attempt)
    return ceiling / 2 + random.uniform(0, ceiling / 2)


def open_url(
    url: str, headers: dict[str, str], method: str = "GET"
) -> http.client.HTTPResponse:
    """Open a URL, retrying 429, 5xx and dropped connections within a total-wait budget."""
    attempt = 0
    waited = 0.0
    while True:
        try:
            response: http.client.HTTPResponse = urllib.request.urlopen(
                urllib.request.Request(url, headers=headers, method=method),
                timeout=REQUEST_TIMEOUT_SECONDS,
            )
            return response
        except (urllib.error.URLError, TimeoutError, ConnectionError) as error:
            if isinstance(
                getattr(error, "reason", error), ssl.SSLCertVerificationError
            ):
                raise
            # A dropped connection or timeout is as transient as a 429 or 5xx.
            if isinstance(error, urllib.error.HTTPError) and not is_retryable(
                error.code
            ):
                raise
            delay = retry_delay(error, attempt)
            attempt += 1
            if attempt >= RETRY_ATTEMPTS or waited + delay > RETRY_WAIT_BUDGET_SECONDS:
                raise OSError(
                    f"{url}: {error} after {attempt} attempts "
                    f"and {waited:.1f}s of backoff"
                ) from error
            if isinstance(error, urllib.error.HTTPError):
                error.close()
            time.sleep(delay)
            waited += delay


def request_headers(url: str) -> dict[str, str]:
    """Return JSON request headers, sending the GitHub token only to api.github.com."""
    headers = {"Accept": "application/json", "User-Agent": USER_AGENT}
    if token := os.getenv("GITHUB_TOKEN"):
        if urllib.parse.urlparse(url).hostname == "api.github.com":
            headers["Authorization"] = f"Bearer {token}"
    return headers


def request(url: str) -> tuple[object, str]:
    """Fetch a JSON document, retrying transient failures."""
    with open_url(url, request_headers(url)) as response:
        return json.load(response), url


def request_json_lines(url: str) -> tuple[list[dict[str, Any]], str]:
    """Fetch a newline-delimited JSON document."""
    with open_url(url, request_headers(url)) as response:
        return [json.loads(line) for line in response if line.strip()], url


def request_last_modified(url: str) -> Optional[dt.datetime]:
    """Return a URL's Last-Modified time from a HEAD request, if it sends a usable one.

    A missing or malformed header gives None so the caller falls back to another
    source. A time with no zone (or the `-0000` "unknown zone") is read as UTC.
    """
    with open_url(url, request_headers(url), method="HEAD") as response:
        value = response.headers.get("Last-Modified")
    if value is None:
        return None
    try:
        when = email.utils.parsedate_to_datetime(value)
        if when.tzinfo is None:
            when = when.replace(tzinfo=UTC)
        # A year-9999 time with a negative offset overflows converting to UTC.
        return when.astimezone(UTC)
    except (TypeError, ValueError, OverflowError):
        return None


def go_proxy_escape(value: str) -> str:
    """Escape a module path or version the way the Go proxy expects."""
    escaped = "".join(
        f"!{character.lower()}" if "A" <= character <= "Z" else character
        for character in value
    )
    return urllib.parse.quote(escaped, safe="/!")


def format_time(value: dt.datetime) -> str:
    """Format a time the way the Go module index expects it."""
    return value.isoformat().replace("+00:00", "Z")


@dataclass
class GoIndexTarget:
    """Dependencies sharing one Go coordinate, and where its index search starts."""

    dependencies: list[Dependency]
    since: dt.datetime
    pages: int = 0


@dataclass
class GoIndexWalk:
    """The coordinates still being searched for, and the outcome for each one settled."""

    pending: dict[tuple[str, str], GoIndexTarget]
    outcomes: dict[Dependency, LookupOutcome] = field(default_factory=dict)

    def settle(self, key: tuple[str, str], outcome: LookupOutcome) -> None:
        """Record one outcome for every dependency at a coordinate and stop searching for it."""
        for dependency in self.pending.pop(key).dependencies:
            self.outcomes[dependency] = outcome

    def miss(self, key: tuple[str, str], end: str) -> None:
        """Settle a coordinate as not found, naming the pages and time window searched."""
        target = self.pending[key]
        self.settle(
            key,
            ValueError(
                f"Go module index has no entry for {key[0]}@{key[1]} in "
                f"{target.pages} pages from {format_time(target.since)} to {end}"
            ),
        )


def go_index_seek_time(dependency: Dependency) -> dt.datetime:
    """Return where to start reading the module index for a Go version."""
    # Only the index Timestamp is evidence; this only chooses where to start
    # reading. The proxy's Last-Modified for .mod is when it cached the version,
    # which is the index's first-observed time. .info Time is the commit time
    # and can precede that by years. The index lists a coordinate once, so a
    # wrong start can only miss it (unknown), never yield an earlier time.
    base = (
        f"{GO_PROXY}/{go_proxy_escape(dependency.artifact)}/@v/"
        f"{go_proxy_escape(dependency.version)}"
    )
    cached_at = request_last_modified(f"{base}.mod")
    if cached_at is None:
        info, _ = request(f"{base}.info")
        if not isinstance(info, dict) or "Time" not in info:
            raise ValueError("Go proxy returned no version time")
        cached_at = parse_time(info["Time"])
    return cached_at - GO_INDEX_SEEK_MARGIN


def walk_go_index(walk: GoIndexWalk) -> None:
    """Read the module index forward once, settling every pending coordinate."""
    # The index is one chronological feed for every module, so a single cursor
    # serves every coordinate whose seek time it has passed.
    cursor: Optional[dt.datetime] = None
    while walk.pending:
        earliest = min(target.since for target in walk.pending.values())
        if cursor is None or cursor < earliest:
            cursor = earliest
        query = urllib.parse.urlencode(
            {
                "since": format_time(cursor),
                "limit": GO_INDEX_PAGE_SIZE,
                "include": "all",
            }
        )
        try:
            entries, source = request_json_lines(f"{GO_INDEX}?{query}")
            if not entries:
                for key in list(walk.pending):
                    walk.miss(key, "the end of the index")
                return
            for entry in entries:
                key = (str(entry.get("Path")), str(entry.get("Version")))
                if key in walk.pending:
                    walk.settle(key, (parse_time(entry["Timestamp"]), source))
            last = parse_time(entries[-1]["Timestamp"])
        except LOOKUP_ERRORS as error:
            for key in list(walk.pending):
                walk.settle(key, error)
            return
        in_window = [
            key for key, target in walk.pending.items() if target.since <= cursor
        ]
        for key in in_window:
            walk.pending[key].pages += 1
        exhausted = last <= cursor or len(entries) < GO_INDEX_PAGE_SIZE
        for key in in_window:
            if exhausted or walk.pending[key].pages >= GO_INDEX_PAGE_LIMIT:
                walk.miss(key, format_time(last))
        cursor = max(cursor, last)


def go_index_evidence(
    dependencies: list[Dependency],
) -> dict[Dependency, LookupOutcome]:
    """Return each Go dependency's first-observed time, or the error, from one shared index walk."""
    coordinates: dict[tuple[str, str], list[Dependency]] = {}
    for dependency in dependencies:
        coordinates.setdefault((dependency.artifact, dependency.version), []).append(
            dependency
        )
    walk = GoIndexWalk({})
    for key, sharing in coordinates.items():
        try:
            walk.pending[key] = GoIndexTarget(sharing, go_index_seek_time(sharing[0]))
        except LOOKUP_ERRORS as error:
            for dependency in sharing:
                walk.outcomes[dependency] = error
    walk_go_index(walk)
    return walk.outcomes


def unwrap(outcome: LookupOutcome) -> Lookup:
    """Return a successful lookup, or raise the error that settled it."""
    if isinstance(outcome, Exception):
        raise outcome
    return outcome


def github_repository(artifact: str) -> str:
    """Return the owner/repository prefix of a GitHub artifact."""
    parts = artifact.split("/")
    if len(parts) < 2 or not all(parts[:2]):
        raise ValueError("GitHub dependency must use owner/repository form")
    return "/".join(parts[:2])


def is_internal_github_dependency(dependency: Dependency) -> bool:
    """Say whether a GitHub dependency lives in the current repository or its owner's org."""
    if dependency.ecosystem not in {
        "github-commit",
        "github-release",
        "github-tag",
    }:
        return False
    repository = github_repository(dependency.artifact)
    current_repository = os.getenv("GITHUB_REPOSITORY", "")
    current_owner = os.getenv("GITHUB_REPOSITORY_OWNER", "")
    return repository.casefold() == current_repository.casefold() or (
        bool(current_owner)
        and repository.split("/", 1)[0].casefold() == current_owner.casefold()
    )


def first_party_location(dependency: Dependency) -> str:
    """Return the host-qualified location used to match first-party dependencies."""
    artifact = dependency.artifact
    if dependency.ecosystem in {"github-commit", "github-release", "github-tag"} or (
        dependency.ecosystem == "mutable"
        and dependency.source.startswith(".github/")
        and dependency.source.endswith((".yml", ".yaml"))
        and not dependency.version.startswith("docker://")
    ):
        return f"github.com/{artifact}"
    if dependency.ecosystem == "helm":
        artifact = artifact.split("|", 1)[-1]
    if dependency.ecosystem == "mise" and artifact.startswith("github:"):
        return f"github.com/{artifact.removeprefix('github:')}"
    return GIT_SOURCE_PREFIX.sub("", artifact, count=1)


def is_interactionlabs_dependency(dependency: Dependency) -> bool:
    """Say whether a dependency resolves to the InteractionLabs GitHub org."""
    return dependency.ecosystem not in {"unparseable", "unresolved"} and bool(
        FIRST_PARTY_LOCATION.match(first_party_location(dependency))
    )


def is_first_party_excepted(
    dependency: Dependency, exceptions: dict[tuple[str, str, str], dict[str, str]]
) -> bool:
    """Say whether the first-party exception applies to this dependency."""
    return FIRST_PARTY_EXCEPTION in exceptions and is_interactionlabs_dependency(
        dependency
    )


def registry_unreachable(error: Exception) -> bool:
    """Say whether a lookup failed because the registry couldn't be reached, not because it said no.

    Only timeouts, refused, reset or aborted connections, DNS failure, 5xx, 429
    and exhausted retries count. A 404, a missing version or timestamp, an
    unreadable answer, a failed integrity check or a TLS failure (a possible
    interception) means the coordinate isn't on the public registry as locked.
    """
    if isinstance(error, urllib.error.HTTPError):
        return error.code == 429 or error.code >= 500
    if isinstance(error, OSError) and isinstance(error.__cause__, Exception):
        return registry_unreachable(error.__cause__)
    reason = error.reason if isinstance(error, urllib.error.URLError) else error
    if isinstance(reason, ssl.SSLError):
        return False
    return isinstance(reason, (TimeoutError, ConnectionError, socket.gaierror))


def registry_evidence(dependency: Dependency) -> tuple[dt.datetime, str]:
    """Ask the ecosystem's registry when a coordinate was published."""
    quote = urllib.parse.quote
    if dependency.ecosystem == "pypi":
        data, url = request(
            f"https://pypi.org/pypi/{quote(dependency.artifact)}/"
            f"{quote(dependency.version)}/json"
        )
        assert isinstance(data, dict)
        uploads = [
            item.get("upload_time_iso_8601")
            for item in data.get("urls", [])
            if item.get("upload_time_iso_8601")
        ]
        if not uploads:
            raise ValueError("PyPI returned no upload timestamp")
        published_digests = {
            f"sha256:{item.get('digests', {}).get('sha256', '')}".lower()
            for item in data.get("urls", [])
        }
        if missing := set(dependency.digests) - published_digests:
            raise RejectedEvidence(
                f"PyPI has no file for locked hash {sorted(missing)[0]}"
            )
        return max(parse_time(value) for value in uploads), url
    if dependency.ecosystem == "npm":
        data, url = request(
            f"https://registry.npmjs.org/{quote(dependency.artifact, safe='@')}"
        )
        assert isinstance(data, dict)
        published = data.get("time", {}).get(dependency.version)
        if not published:
            raise ValueError("npm returned no publication timestamp")
        return parse_time(published), url
    if dependency.ecosystem == "crates":
        data, url = request(
            f"https://crates.io/api/v1/crates/{quote(dependency.artifact)}/"
            f"{quote(dependency.version)}"
        )
        assert isinstance(data, dict)
        published = data.get("version", {}).get("created_at")
        if not published:
            raise ValueError("crates.io returned no publication timestamp")
        return parse_time(published), url
    if dependency.ecosystem == "maven":
        group, artifact = dependency.artifact.split(":", 1)
        query = quote(f'g:"{group}" AND a:"{artifact}" AND v:"{dependency.version}"')
        data, url = request(
            f"https://search.maven.org/solrsearch/select?rows=1&wt=json&q={query}"
        )
        assert isinstance(data, dict)
        documents = data.get("response", {}).get("docs", [])
        if not documents or not documents[0].get("timestamp"):
            raise ValueError("Maven Central returned no publication timestamp")
        return dt.datetime.fromtimestamp(documents[0]["timestamp"] / 1000, UTC), url
    if dependency.ecosystem == "github-release":
        repository = dependency.artifact.rsplit("/", 1)[0]
        data, url = request(
            f"https://api.github.com/repos/{repository}/releases/tags/"
            f"{quote(dependency.version, safe='')}"
        )
        assert isinstance(data, dict)
        published = data.get("published_at")
        if published:
            return parse_time(published), url
    if dependency.ecosystem == "github-commit":
        repository = github_repository(dependency.artifact)
        data, url = request(
            f"https://api.github.com/repos/"
            f"{quote(repository, safe='/')}/commits/"
            f"{quote(dependency.version, safe='')}"
        )
        assert isinstance(data, dict)
        committed = data.get("commit", {}).get("committer", {}).get("date")
        if not committed:
            raise ValueError("GitHub returned no commit timestamp")
        return parse_time(committed), url
    if dependency.ecosystem == "go":
        return unwrap(go_index_evidence([dependency])[dependency])
    if dependency.ecosystem in {
        "github-tag",
        "helm",
        "mise",
        "oci",
        "terraform-module",
        "terraform-provider",
    }:
        raise UnverifiableEvidence(
            f"no public publication-time resolver for {dependency.ecosystem}"
        )
    raise RejectedEvidence(
        f"no trusted publication-time resolver for {dependency.ecosystem}"
    )


def evidence(dependency: Dependency) -> tuple[dt.datetime, str]:
    """Validate that a version is exact, then fetch its publication evidence."""
    validate_exact_version(dependency.ecosystem, dependency.version)
    return registry_evidence(dependency)


def is_exact_version(dependency: Dependency) -> bool:
    """Say whether a dependency pins one exact immutable version."""
    try:
        validate_exact_version(dependency.ecosystem, dependency.version)
    except ValueError:
        return False
    return True


def validate_exact_version(ecosystem: str, version: str) -> None:
    """Reject versions that aren't one exact immutable coordinate."""
    if ecosystem in {"unparseable", "unresolved"}:
        raise ValueError(version)
    if ecosystem == "github-commit" and not FULL_SHA.fullmatch(version):
        raise ValueError("GitHub commit exception must use a full lowercase SHA")
    if ecosystem == "oci" and not SHA256_DIGEST.fullmatch(version):
        raise ValueError("OCI exception must use a sha256 digest")
    if ecosystem == "mutable" or UNSAFE_VERSION.search(version):
        raise ValueError("exception version must be one exact immutable coordinate")


def rule_proposes(rule: dict[str, Any], fix: dict[str, Any]) -> bool:
    """Say whether an allow rule is the one that makes Renovate propose this fix."""
    if rule.get("matchRepositories") != [fix["repository"]]:
        return False
    if "/^" + re.escape(fix["package"]) + "$/" not in rule.get("matchPackageNames", []):
        return False
    if fix.get("to_pin"):
        quoted = json.dumps(fix["to_pin"])
        return any(
            isinstance(expression, str) and quoted in expression
            for expression in rule.get("matchJsonata", [])
        )
    target = "/^v?" + re.escape(fix["to"].removeprefix("v")) + "$/"
    return bool(rule.get("allowedVersions") == target)


def urgent_fixes(
    allow_rules: list[dict[str, Any]], fixes: list[dict[str, Any]]
) -> Iterator[tuple[dict[str, Any], dict[str, Any]]]:
    """Pair each listed fix of a High, Critical or CISA KEV finding with the allow rule that proposes it."""
    for fix in fixes:
        if fix.get("severity") not in URGENT_SEVERITIES and fix.get("kev") is not True:
            continue
        for rule in allow_rules:
            if rule_proposes(rule, fix):
                yield rule, fix


def fix_key(ecosystem: str, artifact: str, version: str) -> tuple[str, str, str]:
    """Identify a coordinate however its lockfile or the fix list spells it."""
    if ecosystem == "pypi":
        artifact = re.sub(r"[-_.]+", "-", artifact).lower()
    elif ecosystem == "github-commit":
        artifact = "/".join(artifact.split("/")[:2]).casefold()
    elif ecosystem == "oci":
        artifact = ""
    return ecosystem, artifact, version.removeprefix("v")


def fix_coordinate(manager: str, fix: dict[str, Any]) -> Optional[tuple[str, str, str]]:
    """The coordinate a listed fix lifts, or None when the entry doesn't name one exactly."""
    if manager in FIX_ECOSYSTEMS:
        return fix_key(FIX_ECOSYSTEMS[manager], fix["package"], fix["to"])
    ecosystem = PINNED_FIX_ECOSYSTEMS.get(manager)
    pin = fix.get("to_pin")
    pattern = FULL_SHA if ecosystem == "github-commit" else SHA256_DIGEST
    if ecosystem is None or not isinstance(pin, str) or not pattern.fullmatch(pin):
        return None
    return fix_key(ecosystem, fix["package"], pin)


def fixes_are_trusted(directory: Path) -> bool:
    """Say whether the fix list lies outside the checked-out pull request, which could supply its own."""
    resolved = directory.resolve()
    roots = [REPOSITORY.resolve()]
    if workspace := os.environ.get("GITHUB_WORKSPACE"):
        roots.append(Path(workspace).resolve())
    if not any(resolved.is_relative_to(root) for root in roots):
        return True
    if (directory / "patch-tuesday.json").exists():
        print(
            "dependency-policy: ignoring Patch Tuesday fixes found inside the "
            "checked-out repository; only a copy outside it is trusted",
            file=sys.stderr,
        )
    return False


MANIFEST_FAMILIES = (
    ("go.mod", "go.sum"),
    ("pyproject.toml", "uv.lock", "requirements*.txt"),
    ("package.json", "package-lock.json", "pnpm-lock.yaml"),
    ("Cargo.toml", "Cargo.lock"),
)


def fix_path_matches(fix_path: str, source: str) -> bool:
    """Say whether a fix entry's path names the source file or a manifest or lock sibling of it."""
    if fix_path == source:
        return True
    fix_dir, _, fix_name = fix_path.rpartition("/")
    source_dir, _, source_name = source.rpartition("/")
    return fix_dir == source_dir and any(
        any(fnmatch.fnmatchcase(fix_name, pattern) for pattern in family)
        and any(fnmatch.fnmatchcase(source_name, pattern) for pattern in family)
        for family in MANIFEST_FAMILIES
    )


def wiz_fix_applies(
    fix: dict[str, Any], dependency: Dependency, old_version: Optional[str]
) -> bool:
    """Say whether the change replaces an older version with the fix's target.

    An entry that names a `path` lifts only the dependency found in that file
    or in a manifest or lock file beside it.
    Version ecosystems also need NEW > OLD and, when the entry has `from`, OLD
    equal to it. Pinned commits and digests only need a different OLD pin.
    """
    if old_version is None or old_version == dependency.version:
        return False
    fix_path = fix.get("path")
    if fix_path is not None and not (
        isinstance(fix_path, str) and fix_path_matches(fix_path, dependency.source)
    ):
        return False
    if dependency.ecosystem in {"github-commit", "oci"}:
        return True
    new_key = parse_version(dependency.ecosystem, dependency.version)
    old_key = parse_version(dependency.ecosystem, old_version)
    if new_key is None or old_key is None or new_key <= old_key:
        return False
    listed = fix.get("from")
    return listed is None or str(listed).removeprefix("v") == old_version.removeprefix(
        "v"
    )


def wiz_fix_applies_to_all(
    fix: dict[str, Any], dependency: Dependency, old_versions: tuple[str, ...]
) -> bool:
    """Say whether the fix covers a change that replaced every one of the old versions.

    Each old version must be below the target; `from` need only name one of them.
    """
    unrestricted = {key: value for key, value in fix.items() if key != "from"}
    return all(
        wiz_fix_applies(unrestricted, dependency, old) for old in old_versions
    ) and any(wiz_fix_applies(fix, dependency, old) for old in old_versions)


def load_urgent_fixes(
    directory: Path, repository: str
) -> dict[tuple[str, str, str], list[dict[str, Any]]]:
    """The repository's urgent fixes from allow-rules.json and patch-tuesday.json, keyed by fix_key."""
    paths = (directory / "allow-rules.json", directory / "patch-tuesday.json")
    if not all(path.exists() for path in paths):
        return {}
    allow_rules, fixes = (json.loads(path.read_text()) for path in paths)
    loaded: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
    for rule, fix in urgent_fixes(allow_rules, fixes):
        if fix["repository"].casefold() != repository.casefold():
            continue
        for manager in rule.get("matchManagers", []):
            if (coordinate := fix_coordinate(manager, fix)) is not None:
                loaded.setdefault(coordinate, []).append(fix)
    return loaded


def parse_version(ecosystem: str, value: object) -> Optional[tuple[Any, ...]]:
    """Order key for a version in its ecosystem's scheme, or None when we can't read it with certainty.

    PyPI accepts only plain releases (no epoch, pre, post, dev or local parts);
    npm and crates accept SemVer without build metadata; Go accepts SemVer with a
    `v` prefix, pseudo-versions included, and ignores `+incompatible`.
    """
    if not isinstance(value, str):
        return None
    if ecosystem == "pypi":
        if not PEP440_RELEASE.fullmatch(value):
            return None
        release = [int(part) for part in value.split(".")]
        while len(release) > 1 and release[-1] == 0:
            release.pop()
        return tuple(release)
    if ecosystem == "go":
        value = value.removeprefix("v").removesuffix("+incompatible")
    elif ecosystem not in {"npm", "crates"}:
        return None
    match = SEMVER.fullmatch(value)
    if match is None:
        return None
    release_parts = tuple(int(part) for part in match.groups()[:3])
    if match[4] is None:
        return (*release_parts, (1,))
    identifiers = tuple(
        (0, int(part)) if part.isdigit() else (1, part) for part in match[4].split(".")
    )
    return (*release_parts, (0, *identifiers))


def parse_range_bound(ecosystem: str, value: str) -> Optional[tuple[Any, ...]]:
    """Parse a range bound, reading `0` or `1.2` as `0.0.0` or `1.2.0` where SemVer is required."""
    if ecosystem in {"npm", "crates", "go"} and re.fullmatch(
        r"v?(?:0|[1-9]\d*)(?:\.(?:0|[1-9]\d*))?", value, re.ASCII
    ):
        value += ".0" * (2 - value.count("."))
    return parse_version(ecosystem, value)


def version_in_range(
    ecosystem: str, version: object, vulnerable_range: object
) -> Optional[bool]:
    """Say whether a version satisfies an advisory range such as `>= 1.0, < 1.2.3`; None when unsure."""
    key = parse_version(ecosystem, version)
    if key is None or not isinstance(vulnerable_range, str):
        return None
    satisfied = True
    for constraint in vulnerable_range.split(","):
        match = RANGE_CONSTRAINT.fullmatch(constraint.strip())
        bound = parse_range_bound(ecosystem, match[2]) if match else None
        if match is None or bound is None:
            return None
        operator = match[1]
        satisfied = (
            satisfied
            and {
                "<": key < bound,
                "<=": key <= bound,
                ">": key > bound,
                ">=": key >= bound,
                "=": key == bound,
            }[operator]
        )
    return satisfied


def advisory_package_name(ecosystem: str, name: str) -> str:
    """Spell a package name the way advisories and lockfiles agree on."""
    if ecosystem == "pypi":
        return re.sub(r"[-_.]+", "-", name).lower()
    return name.casefold() if ecosystem == "npm" else name


def advisory_cves(advisory: dict[str, Any]) -> list[str]:
    """The well-formed CVE IDs an advisory lists."""
    candidates = [advisory.get("cve_id")]
    identifiers = advisory.get("identifiers")
    if isinstance(identifiers, list):
        candidates += [
            item.get("value")
            for item in identifiers
            if isinstance(item, dict) and item.get("type") == "CVE"
        ]
    cves = {
        item for item in candidates if isinstance(item, str) and CVE_ID.fullmatch(item)
    }
    return sorted(cves)


class AdvisoryLookup:
    """Public advisories for coordinates that would otherwise block, fetched once per run.

    Once a lookup exhausts its retries on a transient failure (429, 5xx, timeout
    or dropped connection), later lookups are skipped and count as no advisory;
    the Wiz Patch Tuesday list stays the primary source.
    """

    def __init__(self) -> None:
        self.advisories: dict[
            tuple[str, str, str], Union[list[dict[str, Any]], Exception]
        ] = {}
        self.known_exploited: Optional[Union[frozenset[str], Exception]] = None
        self.rate_limited: Optional[Exception] = None

    def reviewed_advisories(
        self, dependency: Dependency, old_version: str
    ) -> list[dict[str, Any]]:
        """Reviewed global advisories that list `old_version` of the package as affected."""
        key = (dependency.ecosystem, dependency.artifact, old_version)
        if key not in self.advisories:
            if self.rate_limited is not None:
                raise self.rate_limited
            try:
                self.advisories[key] = self.fetch_advisories(*key)
            except LOOKUP_ERRORS as error:
                self.advisories[key] = error
                if registry_unreachable(error):
                    self.rate_limited = error
        outcome = self.advisories[key]
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    def fetch_advisories(
        self, ecosystem: str, name: str, old_version: str
    ) -> list[dict[str, Any]]:
        """Fetch the first page of GET /advisories for one package version."""
        query = urllib.parse.urlencode(
            {
                "type": "reviewed",
                "ecosystem": ADVISORY_ECOSYSTEMS[ecosystem],
                "affects": f"{name}@{old_version.removeprefix('v')}",
                "per_page": ADVISORY_PAGE_SIZE,
            }
        )
        payload, _ = request(f"{ADVISORY_API}?{query}")
        if not isinstance(payload, list):
            raise ValueError("advisory response must be a list")
        return [item for item in payload if isinstance(item, dict)]

    def kev_ids(self) -> frozenset[str]:
        """The CVE IDs in the CISA Known Exploited Vulnerabilities catalog."""
        if self.known_exploited is None:
            try:
                self.known_exploited = self.fetch_kev()
            except LOOKUP_ERRORS as error:
                self.known_exploited = error
        if isinstance(self.known_exploited, Exception):
            raise self.known_exploited
        return self.known_exploited

    def fetch_kev(self) -> frozenset[str]:
        """Download the catalog and read its CVE IDs."""
        payload, _ = request(KEV_CATALOG)
        if not isinstance(payload, dict) or not isinstance(
            payload.get("vulnerabilities"), list
        ):
            raise ValueError("KEV catalog must list vulnerabilities")
        return frozenset(
            item["cveID"]
            for item in payload["vulnerabilities"]
            if isinstance(item, dict) and isinstance(item.get("cveID"), str)
        )

    def fix_detail_for_all(
        self, dependency: Dependency, old_versions: tuple[str, ...]
    ) -> Optional[str]:
        """The first old version's fix detail, when an advisory qualifies the change for every old version."""
        details = [self.fix_detail(dependency, old) for old in old_versions]
        return details[0] if all(details) else None

    def fix_detail(self, dependency: Dependency, old_version: str) -> Optional[str]:
        """Name the advisory that makes this dependency the first patched version of `old_version`, if one does.

        A lookup failure returns None, so the original status stands.
        """
        ecosystem = dependency.ecosystem
        if ecosystem not in ADVISORY_ECOSYSTEMS:
            return None
        new_key = parse_version(ecosystem, dependency.version)
        if new_key is None or parse_version(ecosystem, old_version) is None:
            return None
        name = advisory_package_name(ecosystem, dependency.artifact)
        try:
            for advisory in self.reviewed_advisories(dependency, old_version):
                detail = self.advisory_detail(
                    advisory, ecosystem, name, old_version, dependency.version, new_key
                )
                if detail:
                    return detail
        except LOOKUP_ERRORS:
            return None
        return None

    def advisory_detail(
        self,
        advisory: dict[str, Any],
        ecosystem: str,
        name: str,
        old_version: str,
        new_version: str,
        new_key: tuple[Any, ...],
    ) -> Optional[str]:
        """The report detail when one reviewed advisory qualifies this old-to-new change."""
        ghsa_id = advisory.get("ghsa_id")
        if (
            advisory.get("type") != "reviewed"
            or advisory.get("withdrawn_at")
            or not isinstance(ghsa_id, str)
            or not GHSA_ID.fullmatch(ghsa_id)
            or not self.first_patched_matches(
                advisory, ecosystem, name, old_version, new_version, new_key
            )
        ):
            return None
        severity = advisory.get("severity")
        if isinstance(severity, str) and severity.lower() in {"high", "critical"}:
            return (
                f"security fix ({ghsa_id}, {severity.title()}): first patched version"
            )
        try:
            known = self.kev_ids()
        except LOOKUP_ERRORS:
            return None
        if listed := [cve for cve in advisory_cves(advisory) if cve in known]:
            return (
                f"security fix ({ghsa_id}, CISA KEV {', '.join(listed)}): "
                "first patched version"
            )
        return None

    @staticmethod
    def first_patched_matches(
        advisory: dict[str, Any],
        ecosystem: str,
        name: str,
        old_version: str,
        new_version: str,
        new_key: tuple[Any, ...],
    ) -> bool:
        """Say whether the new version is the first patched version of a range holding the old one."""
        vulnerabilities = advisory.get("vulnerabilities")
        if not isinstance(vulnerabilities, list):
            return False
        old_key = parse_version(ecosystem, old_version)
        if old_key is None:
            return False
        for entry in vulnerabilities:
            package = entry.get("package") if isinstance(entry, dict) else None
            if (
                not isinstance(package, dict)
                or package.get("ecosystem") != ADVISORY_ECOSYSTEMS[ecosystem]
                or not isinstance(package.get("name"), str)
                or advisory_package_name(ecosystem, package["name"]) != name
            ):
                continue
            vulnerable_range = entry.get("vulnerable_version_range")
            if (
                version_in_range(ecosystem, old_version, vulnerable_range) is True
                and parse_version(ecosystem, entry.get("first_patched_version"))
                == new_key
                and new_key > old_key
                and version_in_range(ecosystem, new_version, vulnerable_range) is False
            ):
                return True
        return False


def security_fix_summary(results: list[Result]) -> Optional[str]:
    """One line for a reviewer when a security fix passed but other coordinates in the change are still blocked."""
    fixes = [result for result in results if is_security_fix(result)]
    blocked = [result for result in results if result.status in {"blocked", "unknown"}]
    if not fixes or not blocked:
        return None
    return (
        f"dependency-policy: {len(blocked)} other dependency "
        f"{'change' if len(blocked) == 1 else 'changes'} still blocked alongside "
        f"{len(fixes)} security {'fix' if len(fixes) == 1 else 'fixes'}. They stay "
        "blocked; if the fix requires them, a reviewer can merge with the "
        "repository bypass."
    )


def is_security_fix(result: Result) -> bool:
    """Say whether a result passed as a security fix."""
    return result.status == "excepted" and (result.detail or "").startswith(
        SECURITY_FIX_PREFIX
    )


def load_exceptions(
    path: Path, now: dt.datetime
) -> dict[tuple[str, str, str], dict[str, str]]:
    """Load and validate the exceptions file, dropping entries that have expired."""
    data = json.loads(path.read_text()) if path.exists() else {"exceptions": []}
    if set(data) != {"exceptions"} or not isinstance(data["exceptions"], list):
        raise ValueError("exception file must contain only an exceptions array")
    required = {
        "ecosystem",
        "artifact",
        "version",
        "reason",
        "reference",
        "approver",
        "created_at",
        "expires_at",
    }
    exceptions: dict[tuple[str, str, str], dict[str, str]] = {}
    for item in data["exceptions"]:
        latest = isinstance(item, dict) and item.get("version") == LATEST_EXCEPTION
        fields = required - {"expires_at"} if latest else required
        if (
            not isinstance(item, dict)
            or set(item) != fields
            or any(
                not isinstance(item[field], str) or not item[field].strip()
                for field in fields
            )
        ):
            raise ValueError(
                "every exception must contain exactly eight non-empty string "
                "fields, or seven with no expires_at for a latest exception"
            )
        created = parse_time(item["created_at"])
        key = (item["ecosystem"], item["artifact"], item["version"])
        if latest:
            if key != FIRST_PARTY_EXCEPTION:
                raise ValueError(
                    "a latest exception must use ecosystem "
                    f"{FIRST_PARTY_EXCEPTION[0]!r} and artifact "
                    f"{FIRST_PARTY_EXCEPTION[1]!r}"
                )
        else:
            validate_exact_version(item["ecosystem"], item["version"])
            expires = parse_time(item["expires_at"])
            if expires <= created:
                raise ValueError("exception expiry must be after creation")
        if key in exceptions:
            raise ValueError(f"duplicate exception for {key}")
        if latest or now < parse_time(item["expires_at"]):
            exceptions[key] = item
    return exceptions


def check(
    dependencies: list[Dependency],
    exceptions: dict[tuple[str, str, str], dict[str, str]],
    now: dt.datetime,
    cache: Optional[EvidenceCache] = None,
    urgent: Optional[dict[tuple[str, str, str], list[dict[str, Any]]]] = None,
    previous_versions: Optional[dict[Dependency, Union[str, tuple[str, ...]]]] = None,
    advisories: Optional[AdvisoryLookup] = None,
) -> list[Result]:
    """Judge each dependency against the cooldown, the exceptions and the security fixes."""
    results: list[Result] = []
    go_evidence = go_index_evidence(
        [
            dependency
            for dependency in dependencies
            if dependency.ecosystem == "go"
            and not is_first_party_excepted(dependency, exceptions)
            and is_exact_version(dependency)
            and not (cache is not None and cache.has(dependency))
        ]
    )
    for dependency in dependencies:
        published: Optional[dt.datetime] = None
        eligible: Optional[dt.datetime] = None
        evidence_source: Optional[str] = None
        detail: Optional[str] = None
        validated = False
        evidence_missing = False
        first_party_exception = exceptions.get(FIRST_PARTY_EXCEPTION)
        try:
            if dependency.ecosystem == "policy-exception":
                status = "excepted"
                detail = "approved first-party main reference"
            elif dependency.ecosystem == "unresolved":
                status = "unresolved"
                detail = dependency.note
            elif first_party_exception and is_first_party_excepted(
                dependency, exceptions
            ):
                status = "excepted"
                detail = (
                    f"InteractionLabs dependency; "
                    f"{first_party_exception['reference']}: "
                    f"{first_party_exception['reason']} "
                    f"(approved by {first_party_exception['approver']})"
                )
            elif is_internal_github_dependency(dependency):
                validate_exact_version(dependency.ecosystem, dependency.version)
                status = "internal"
            else:
                validate_exact_version(dependency.ecosystem, dependency.version)
                validated = True
                cached = (
                    cache.get(dependency)
                    if cache is not None and is_cacheable(dependency)
                    else None
                )
                if cached is not None:
                    publication = cached
                else:
                    published, evidence_source = (
                        unwrap(go_evidence.pop(dependency))
                        if dependency in go_evidence
                        else evidence(dependency)
                    )
                    publication = PublicationEvidence(
                        published,
                        published + COOLDOWN,
                        evidence_source,
                    )
                    if cache is not None and is_cacheable(dependency):
                        cache.put(dependency, publication)
                published = publication.published_at
                eligible = publication.eligible_at
                evidence_source = publication.source
                status = "eligible" if now >= eligible else "blocked"
        except UnverifiableEvidence as error:
            status = "unverifiable"
            detail = str(error)
        except LOOKUP_ERRORS as error:
            status = "unknown"
            detail = str(error)
            evidence_missing = validated and registry_unreachable(error)
        exception = exceptions.get(
            (dependency.ecosystem, dependency.artifact, dependency.version)
        )
        if exception and eligible is not None:
            expiry = parse_time(exception["expires_at"])
            if expiry > eligible:
                status = "unknown"
                detail = "exception expires after normal eligibility"
            elif status == "blocked":
                status = "excepted"
                detail = (
                    f"{exception['reference']}: {exception['reason']} "
                    f"(approved by {exception['approver']})"
                )
        if status == "blocked" or evidence_missing:
            previous = (previous_versions or {}).get(dependency)
            old_versions = (
                (previous,) if isinstance(previous, str) else previous or ()
            )
            fix = next(
                (
                    entry
                    for entry in (urgent or {}).get(
                        fix_key(
                            dependency.ecosystem, dependency.artifact, dependency.version
                        ),
                        [],
                    )
                    if old_versions
                    and wiz_fix_applies_to_all(entry, dependency, old_versions)
                ),
                None,
            )
            advisory_detail = (
                advisories.fix_detail_for_all(dependency, old_versions)
                if advisories and old_versions and not fix
                else None
            )
            if fix:
                finding = (
                    "CISA KEV" if fix.get("kev") is True else fix["severity"].title()
                )
                status = "excepted"
                detail = (
                    f"{SECURITY_FIX_PREFIX}Wiz Patch Tuesday, {finding}): "
                    f"{', '.join(fix['cves'])}"
                )
            elif advisory_detail:
                status = "excepted"
                detail = advisory_detail
            if status == "excepted" and evidence_missing:
                detail = f"{detail}; publication evidence unavailable"
        results.append(
            Result(
                ecosystem=dependency.ecosystem,
                artifact=dependency.artifact,
                version=dependency.version,
                source=dependency.source,
                evidence=evidence_source,
                published_at=published.isoformat() if published else None,
                eligible_at=eligible.isoformat() if eligible else None,
                status=status,
                detail=detail,
            )
        )
    return results


def main() -> int:
    """Run the checker and return the process exit code."""
    global REPOSITORY
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, default=Path("."))
    parser.add_argument("--base", required=True)
    parser.add_argument("--head", default="HEAD")
    parser.add_argument(
        "--exceptions",
        type=Path,
        default=Path(".github/dependency-policy/exceptions.json"),
    )
    parser.add_argument("--output", type=Path)
    parser.add_argument("--cache", type=Path)
    parser.add_argument("--inventory-only", action="store_true")
    parser.add_argument("--full-inventory", action="store_true")
    parser.add_argument("--now", help=argparse.SUPPRESS)
    parser.add_argument(
        "--profile", choices=("legacy", "infrastructure"), default="legacy"
    )
    arguments = parser.parse_args()
    REPOSITORY = arguments.repo.resolve()
    if arguments.profile == "infrastructure":
        from dependency_policy.source import infrastructure_profile

        if not infrastructure_profile(REPOSITORY, os.environ):
            print(
                "dependency-policy: the infrastructure profile is limited to InteractionLabs/infrastructure",
                file=sys.stderr,
            )
            return 2
        from dependency_policy.cli import run

        try:
            return run(arguments)
        except (ValueError, OSError, subprocess.SubprocessError) as error:
            print(f"dependency-policy: {error}", file=sys.stderr)
            return 2
    if arguments.inventory_only or arguments.full_inventory:
        print(
            "dependency-policy: infrastructure inventory flags require the infrastructure profile",
            file=sys.stderr,
        )
        return 2
    now = parse_time(arguments.now) if arguments.now else dt.datetime.now(UTC)
    exception_path = arguments.exceptions
    if not exception_path.is_absolute():
        exception_path = REPOSITORY / exception_path
    cache_path = arguments.cache
    if cache_path is not None and not cache_path.is_absolute():
        cache_path = REPOSITORY / cache_path
    cache = EvidenceCache.load(cache_path)
    try:
        dependencies, previous = dependency_changes(arguments.base, arguments.head)
        exceptions = load_exceptions(exception_path, now)
        urgent = (
            load_urgent_fixes(SECURITY_FIXES, os.getenv("GITHUB_REPOSITORY", ""))
            if fixes_are_trusted(SECURITY_FIXES)
            else {}
        )
        results = check(
            dependencies, exceptions, now, cache, urgent, previous, AdvisoryLookup()
        )
    except (
        json.JSONDecodeError,
        OSError,
        subprocess.CalledProcessError,
        tomllib.TOMLDecodeError,
        ValueError,
    ) as error:
        print(f"dependency-policy: {error}", file=sys.stderr)
        return 2
    if cache_error := cache.save():
        print(
            f"dependency-policy: could not save evidence cache: {cache_error}",
            file=sys.stderr,
        )
    report = {
        "threshold_hours": 168,
        "base": arguments.base,
        "head": arguments.head,
        "results": [asdict(result) for result in results],
    }
    if cache.path is not None:
        report["cache"] = {
            "entries": len(cache.entries),
            "hits": cache.hits,
            "misses": cache.misses,
            "writes": cache.writes,
        }
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if arguments.output:
        arguments.output.write_text(rendered)
    else:
        print(rendered, end="")
    blocked = [
        result
        for result in results
        if result.status in {"blocked", "unknown", "unresolved"}
    ]
    for result in blocked:
        if result.status == "unresolved":
            print(f"unresolved: {result.detail}", file=sys.stderr)
            continue
        print(
            f"{result.status}: {result.ecosystem}:{result.artifact}@"
            f"{result.version} ({result.detail or result.evidence or 'missing evidence'})",
            file=sys.stderr,
        )
    if summary := security_fix_summary(results):
        print(summary, file=sys.stderr)
    return 1 if blocked else 0


if __name__ == "__main__":
    raise SystemExit(main())
