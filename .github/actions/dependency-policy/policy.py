#!/usr/bin/env python3
"""Enforce immutable dependency inputs and a 168-hour cooldown."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Optional

from vendor import filetype

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib


UTC = dt.timezone.utc
COOLDOWN = dt.timedelta(hours=168)
CACHE_SCHEMA = 3
USER_AGENT = "dependency-policy/4"
GO_PROXY = "https://proxy.golang.org"
GO_INDEX = "https://index.golang.org/index"
FULL_SHA = re.compile(r"^[0-9a-f]{40}$")
SHA256_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
UNSAFE_VERSION = re.compile(r"(?:^|[^A-Za-z])(latest|main|master)(?:$|[^A-Za-z])|[*<>=^~|,\s]")
RELEASE_ASSET_PATTERN = re.compile(
    r"https://github\.com/([^/]+/[^/]+)/releases/download/([^/]+)/([^\s\"']+)"
)
RELEASE_ASSET_GREP_PATTERN = (
    r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/releases/download/"
    r"[^/[:space:]\"']+/[^[:space:]\"']+"
)
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
    r"workflows/reusable-dependency-policy\.yml|"
    r"workflows/sign-image\.yaml)@main$"
)
LATEST_POLICY_PATHS = {
    "actions/dependency-policy": ".github/workflows/reusable-dependency-policy.yml",
    "workflows/reusable-dependency-policy.yml": ".github/workflows/dependency-policy.yml",
}


class UnverifiableEvidence(ValueError):
    pass


class NonTextDependencyFile(ValueError):
    pass


@dataclass(frozen=True, order=True)
class Dependency:
    ecosystem: str
    artifact: str
    version: str
    source: str
    digests: tuple[str, ...] = ()


@dataclass(frozen=True)
class PublicationEvidence:
    published_at: dt.datetime
    eligible_at: dt.datetime
    source: str


@dataclass
class Result:
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
    path: Optional[Path]
    entries: dict[str, dict]
    hits: int = 0
    misses: int = 0
    writes: int = 0

    @classmethod
    def load(cls, path: Optional[Path]) -> EvidenceCache:
        if path is None:
            return cls(None, {})
        try:
            document = json.loads(path.read_text())
        except (json.JSONDecodeError, OSError):
            return cls(path, {})
        if (
            not isinstance(document, dict)
            or document.get("schema") != CACHE_SCHEMA
            or document.get("cooldown_seconds")
            != int(COOLDOWN.total_seconds())
            or not isinstance(document.get("entries"), dict)
        ):
            return cls(path, {})
        return cls(path, document["entries"])

    def get(self, dependency: Dependency) -> Optional[PublicationEvidence]:
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
        if self.path is None:
            return
        self.entries[evidence_cache_key(dependency)] = {
            "published_at": evidence.published_at.isoformat(),
            "eligible_at": evidence.eligible_at.isoformat(),
            "evidence": evidence.source,
        }
        self.writes += 1

    def save(self) -> Optional[str]:
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
    return dependency.ecosystem in CACHEABLE_ECOSYSTEMS or (
        dependency.ecosystem == "pypi" and bool(dependency.digests)
    )


def evidence_cache_key(dependency: Dependency) -> str:
    key: list[object] = [
        dependency.ecosystem,
        dependency.artifact,
        dependency.version,
    ]
    if dependency.digests:
        key.append(list(dependency.digests))
    return json.dumps(key, separators=(",", ":"))


def run_git_bytes(*args: str) -> bytes:
    return subprocess.run(
        ["git", *args],
        cwd=REPOSITORY,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).stdout


def run_git(*args: str) -> str:
    return run_git_bytes(*args).decode("utf-8", errors="surrogateescape")


def binary_format(content: bytes) -> Optional[str]:
    if kind := filetype.guess(content):
        return kind.mime
    if b"\0" in content[:8192]:
        return "binary"
    return None


def git_file(revision: str, path: str) -> str:
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
    parsed = dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include a timezone")
    return parsed.astimezone(UTC)


def add_requirement(
    found: set[Dependency], requirement: str, source: str
) -> None:
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
                LATEST_POLICY_PATHS.get(policy_reference["kind"]) == path
                or (
                    policy_reference["kind"] == "workflows/sign-image.yaml"
                    and policy_reference["repository"].casefold()
                    == "infrastructure"
                    and path.startswith(".github/workflows/")
                )
            )
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


def discover_containers(path: str, text: str) -> set[Dependency]:
    found: set[Dependency] = set()
    if "Dockerfile" not in Path(path).name:
        return found
    pattern = re.compile(
        r"(?mi)^\s*FROM\s+(?:--platform=[^\s]+\s+)?([^\s]+)"
        r"(?:\s+AS\s+([^\s]+))?\s*$"
    )
    stages: set[str] = set()
    for match in pattern.finditer(text):
        image = match.group(1)
        alias = match.group(2)
        if image.lower() == "scratch" or image.lower() in stages:
            if alias:
                stages.add(alias.lower())
            continue
        if "@" in image and SHA256_DIGEST.fullmatch(image.rsplit("@", 1)[1]):
            artifact, digest = image.rsplit("@", 1)
            found.add(Dependency("oci", artifact, digest, path))
        else:
            found.add(Dependency("mutable", image.split(":", 1)[0], image, path))
        if alias:
            stages.add(alias.lower())
    return found


def uv_lock_digests(package: dict) -> tuple[str, ...]:
    files = [package.get("sdist"), *package.get("wheels", [])]
    digests = {
        str(item["hash"]).lower()
        for item in files
        if isinstance(item, dict) and item.get("hash")
    }
    if not digests or not all(SHA256_DIGEST.fullmatch(digest) for digest in digests):
        return ()
    return tuple(sorted(digests))


def discover_toml(path: str, text: str) -> set[Dependency]:
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
        for requirement in project.get("dependencies", []):
            add_requirement(found, requirement, path)
        for requirements in project.get("optional-dependencies", {}).values():
            for requirement in requirements:
                add_requirement(found, requirement, path)
        for requirements in document.get("dependency-groups", {}).values():
            if isinstance(requirements, list):
                for requirement in requirements:
                    if isinstance(requirement, str):
                        add_requirement(found, requirement, path)
    return found


def discover_javascript(path: str, text: str) -> set[Dependency]:
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
    found: set[Dependency] = set()
    if not path.endswith(("go.mod", "go.sum")):
        return found
    for line in text.splitlines():
        match = re.match(r"\s*([^\s]+)\s+(v[0-9][^\s/]+)", line)
        if match:
            found.add(Dependency("go", match.group(1), match.group(2), path))
    return found


def discover_terraform(path: str, text: str) -> set[Dependency]:
    found: set[Dependency] = set()
    if path.endswith(".tf"):
        block = re.compile(
            r'(?ms)^\s*module\s+"[^"]+"\s*\{(.*?^\s*\})'
        )
        for match in block.finditer(text):
            body = match.group(1)
            source_match = re.search(
                r'(?m)^\s*source\s*=\s*"([^"]+)"', body
            )
            if not source_match:
                continue
            source = source_match.group(1)
            if source.startswith(("./", "../")):
                continue
            version_match = re.search(
                r'(?m)^\s*version\s*=\s*"([^"]+)"', body
            )
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
                found.add(
                    Dependency("terraform-module", artifact, reference, path)
                )
            else:
                found.add(Dependency("mutable", artifact, source, path))
        return found
    if not path.endswith(".terraform.lock.hcl"):
        return found
    provider: Optional[str] = None
    for line in text.splitlines():
        block = re.match(
            r'\s*provider\s+"registry\.terraform\.io/([^"]+)"\s*{', line
        )
        if block:
            provider = block.group(1)
            continue
        version = re.match(r'\s*version\s*=\s*"([^"]+)"', line)
        if provider and version:
            found.add(Dependency("terraform-provider", provider, version.group(1), path))
        if line.strip() == "}":
            provider = None
    return found


def discover_precommit(path: str, text: str) -> set[Dependency]:
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


def discover_release_assets(path: str, text: str) -> set[Dependency]:
    found: set[Dependency] = set()
    for match in RELEASE_ASSET_PATTERN.finditer(text):
        found.add(
            Dependency(
                "github-release",
                f"{match.group(1)}/{match.group(3)}",
                match.group(2),
                path,
            )
        )
    return found


def discover_text(path: str, text: str) -> list[Dependency]:
    found: set[Dependency] = set()
    for discoverer in (
        discover_github_actions,
        discover_containers,
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


def discover_file(revision: str, path: str) -> set[Dependency]:
    try:
        return set(discover_text(path, git_file(revision, path)))
    except NonTextDependencyFile as error:
        return {Dependency("unparseable", path, str(error), path)}


def release_asset_dependencies(
    revision: str, paths: list[str]
) -> set[Dependency]:
    found: set[Dependency] = set()
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
            found.update(discover_release_assets(path, text))
            position = end + 1
    return found


def dependency_delta(base: str, head: str) -> list[Dependency]:
    found: set[Dependency] = set()
    paths = [
        path
        for path in run_git(
            "diff", "--diff-filter=ACMRTUXB", "--name-only", "-z", base, head, "--"
        ).split("\0")
        if path and not path.casefold().endswith(".tgz")
    ]
    for path in paths:
        if not has_dependency_parser(path):
            continue
        old = discover_file(base, path)
        new = discover_file(head, path)
        found.update(new - old)
    found.update(
        release_asset_dependencies(head, paths)
        - release_asset_dependencies(base, paths)
    )
    return sorted(found)


def request(url: str) -> tuple[object, str]:
    headers = {"Accept": "application/json", "User-Agent": USER_AGENT}
    if token := os.getenv("GITHUB_TOKEN"):
        if urllib.parse.urlparse(url).hostname == "api.github.com":
            headers["Authorization"] = f"Bearer {token}"
    with urllib.request.urlopen(
        urllib.request.Request(url, headers=headers), timeout=20
    ) as response:
        return json.load(response), url


def request_json_lines(url: str) -> tuple[list[dict], str]:
    headers = {"Accept": "application/json", "User-Agent": USER_AGENT}
    with urllib.request.urlopen(
        urllib.request.Request(url, headers=headers), timeout=20
    ) as response:
        return [json.loads(line) for line in response if line.strip()], url


def go_proxy_escape(value: str) -> str:
    escaped = "".join(
        f"!{character.lower()}" if "A" <= character <= "Z" else character
        for character in value
    )
    return urllib.parse.quote(escaped, safe="/!")


def go_index_evidence(dependency: Dependency) -> tuple[dt.datetime, str]:
    module = go_proxy_escape(dependency.artifact)
    version = go_proxy_escape(dependency.version)
    info, _ = request(f"{GO_PROXY}/{module}/@v/{version}.info")
    if not isinstance(info, dict) or "Time" not in info:
        raise ValueError("Go proxy returned no version time")
    since = parse_time(info["Time"]) - dt.timedelta(seconds=1)
    for _ in range(200):
        query = urllib.parse.urlencode(
            {
                "since": since.isoformat().replace("+00:00", "Z"),
                "limit": 2000,
                "include": "all",
            }
        )
        entries, source = request_json_lines(f"{GO_INDEX}?{query}")
        if not entries:
            break
        for entry in entries:
            if (
                entry.get("Path") == dependency.artifact
                and entry.get("Version") == dependency.version
            ):
                return parse_time(entry["Timestamp"]), source
        next_since = parse_time(entries[-1]["Timestamp"])
        if next_since <= since:
            break
        since = next_since
    raise ValueError("Go module index returned no first-observed timestamp")


def github_repository(artifact: str) -> str:
    parts = artifact.split("/")
    if len(parts) < 2 or not all(parts[:2]):
        raise ValueError("GitHub dependency must use owner/repository form")
    return "/".join(parts[:2])


def is_internal_github_dependency(dependency: Dependency) -> bool:
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


def registry_evidence(dependency: Dependency) -> tuple[dt.datetime, str]:
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
            raise ValueError(
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
        query = quote(
            f'g:"{group}" AND a:"{artifact}" AND v:"{dependency.version}"'
        )
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
        return go_index_evidence(dependency)
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
    raise ValueError(
        f"no trusted publication-time resolver for {dependency.ecosystem}"
    )


def evidence(dependency: Dependency) -> tuple[dt.datetime, str]:
    validate_exact_version(dependency.ecosystem, dependency.version)
    return registry_evidence(dependency)


def validate_exact_version(ecosystem: str, version: str) -> None:
    if ecosystem == "unparseable":
        raise ValueError(version)
    if ecosystem == "github-commit" and not FULL_SHA.fullmatch(version):
        raise ValueError("GitHub commit exception must use a full lowercase SHA")
    if ecosystem == "oci" and not SHA256_DIGEST.fullmatch(version):
        raise ValueError("OCI exception must use a sha256 digest")
    if ecosystem == "mutable" or UNSAFE_VERSION.search(version):
        raise ValueError("exception version must be one exact immutable coordinate")


def load_exceptions(path: Path, now: dt.datetime) -> dict[tuple[str, str, str], dict]:
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
    exceptions: dict[tuple[str, str, str], dict] = {}
    for item in data["exceptions"]:
        if (
            not isinstance(item, dict)
            or set(item) != required
            or any(
                not isinstance(item[field], str) or not item[field].strip()
                for field in required
            )
        ):
            raise ValueError(
                "every exception must contain exactly eight non-empty string fields"
            )
        validate_exact_version(item["ecosystem"], item["version"])
        created = parse_time(item["created_at"])
        expires = parse_time(item["expires_at"])
        if expires <= created:
            raise ValueError("exception expiry must be after creation")
        key = (item["ecosystem"], item["artifact"], item["version"])
        if key in exceptions:
            raise ValueError(f"duplicate exception for {key}")
        if now < expires:
            exceptions[key] = item
    return exceptions


def check(
    dependencies: list[Dependency],
    exceptions: dict[tuple[str, str, str], dict],
    now: dt.datetime,
    cache: Optional[EvidenceCache] = None,
) -> list[Result]:
    results: list[Result] = []
    for dependency in dependencies:
        published: Optional[dt.datetime] = None
        eligible: Optional[dt.datetime] = None
        evidence_source: Optional[str] = None
        detail: Optional[str] = None
        try:
            if dependency.ecosystem == "policy-exception":
                status = "excepted"
                detail = "approved first-party main reference"
            elif is_internal_github_dependency(dependency):
                validate_exact_version(dependency.ecosystem, dependency.version)
                status = "internal"
            else:
                validate_exact_version(dependency.ecosystem, dependency.version)
                cached = (
                    cache.get(dependency)
                    if cache is not None and is_cacheable(dependency)
                    else None
                )
                if cached is not None:
                    publication = cached
                else:
                    published, evidence_source = evidence(dependency)
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
        except (
            AssertionError,
            json.JSONDecodeError,
            KeyError,
            OSError,
            TypeError,
            urllib.error.URLError,
            ValueError,
        ) as error:
            status = "unknown"
            detail = str(error)
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
    parser.add_argument("--now", help=argparse.SUPPRESS)
    arguments = parser.parse_args()
    REPOSITORY = arguments.repo.resolve()
    now = parse_time(arguments.now) if arguments.now else dt.datetime.now(UTC)
    exception_path = arguments.exceptions
    if not exception_path.is_absolute():
        exception_path = REPOSITORY / exception_path
    cache_path = arguments.cache
    if cache_path is not None and not cache_path.is_absolute():
        cache_path = REPOSITORY / cache_path
    cache = EvidenceCache.load(cache_path)
    try:
        dependencies = dependency_delta(arguments.base, arguments.head)
        exceptions = load_exceptions(exception_path, now)
        results = check(dependencies, exceptions, now, cache)
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
    blocked = [result for result in results if result.status in {"blocked", "unknown"}]
    for result in blocked:
        print(
            f"{result.status}: {result.ecosystem}:{result.artifact}@"
            f"{result.version} ({result.detail or result.evidence or 'missing evidence'})",
            file=sys.stderr,
        )
    return 1 if blocked else 0


if __name__ == "__main__":
    raise SystemExit(main())
