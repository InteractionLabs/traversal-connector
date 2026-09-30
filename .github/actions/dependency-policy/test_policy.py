from __future__ import annotations

import datetime as dt
import json
import subprocess
from pathlib import Path

import pytest

import policy


NOW = dt.datetime(2026, 9, 9, tzinfo=dt.timezone.utc)
REPOSITORY_ROOT = Path(__file__).resolve().parents[3]


@pytest.fixture
def git_repository(tmp_path):
    def git(*arguments):
        return subprocess.run(
            ["git", *arguments],
            cwd=tmp_path,
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ).stdout.strip()

    git("init")
    return tmp_path, git


def test_user_agent_omits_organization_name():
    assert policy.USER_AGENT == "dependency-policy/4"


def test_vendored_filetype_version():
    assert policy.filetype.__version__ == "1.2.0"


def test_discovers_immutable_and_mutable_workflow_inputs():
    dependencies = policy.discover_text(
        ".github/workflows/ci.yml",
        """
steps:
  - uses: ./local-action
  - uses: owner/action@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa # v1
  - uses: InteractionLabs/infrastructure/.github/workflows/reusable-dependency-policy.yml@bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb # policy-v1
  - uses: owner/mutable@v2
  - uses: docker://alpine:3.22
""",
    )
    assert dependencies == [
        policy.Dependency(
            "github-commit",
            "InteractionLabs/infrastructure/.github/workflows/"
            "reusable-dependency-policy.yml",
            "b" * 40,
            ".github/workflows/ci.yml",
        ),
        policy.Dependency(
            "github-commit",
            "owner/action",
            "a" * 40,
            ".github/workflows/ci.yml",
        ),
        policy.Dependency(
            "mutable", "alpine:3.22", "docker://alpine:3.22", ".github/workflows/ci.yml"
        ),
        policy.Dependency(
            "mutable", "owner/mutable", "v2", ".github/workflows/ci.yml"
        ),
    ]


@pytest.mark.parametrize(
    ("reference", "path"),
    [
        (
            "InteractionLabs/security-controls/.github/actions/dependency-policy@main",
            ".github/workflows/reusable-dependency-policy.yml",
        ),
        (
            "InteractionLabs/another-repository/.github/workflows/"
            "reusable-dependency-policy.yml@main",
            ".github/workflows/dependency-policy.yml",
        ),
    ],
)
def test_latest_policy_references_are_explicit_exceptions(reference, path):
    artifact, version = reference.rsplit("@", 1)
    dependencies = policy.discover_text(
        path,
        f"jobs:\n  policy:\n    uses: {reference}\n",
    )
    assert dependencies == [
        policy.Dependency("policy-exception", artifact, version, path)
    ]
    result = policy.check(dependencies, {}, NOW)[0]
    assert result.status == "excepted"
    assert result.detail == "approved first-party main reference"


def test_latest_sign_image_workflow_is_an_explicit_exception():
    reference = (
        "InteractionLabs/infrastructure/.github/workflows/sign-image.yaml@main"
    )
    artifact, version = reference.rsplit("@", 1)
    dependencies = policy.discover_text(
        ".github/workflows/build-image.yml",
        f"jobs:\n  sign:\n    uses: {reference}\n",
    )
    assert dependencies == [
        policy.Dependency(
            "policy-exception",
            artifact,
            version,
            ".github/workflows/build-image.yml",
        )
    ]
    result = policy.check(dependencies, {}, NOW)[0]
    assert result.status == "excepted"
    assert result.detail == "approved first-party main reference"


def test_latest_sign_image_reference_outside_workflows_remains_mutable():
    reference = (
        "InteractionLabs/infrastructure/.github/workflows/sign-image.yaml@main"
    )
    assert policy.discover_text(
        ".github/actions/example/action.yml",
        f"runs:\n  steps:\n    - uses: {reference}\n",
    ) == [
        policy.Dependency(
            "mutable",
            "InteractionLabs/infrastructure/.github/workflows/sign-image.yaml",
            "main",
            ".github/actions/example/action.yml",
        )
    ]


@pytest.mark.parametrize(
    "reference",
    [
        "AnotherOrg/infrastructure/.github/workflows/sign-image.yaml@main",
        "InteractionLabs/another-repository/.github/workflows/sign-image.yaml@main",
        "InteractionLabs/infrastructure/.github/workflows/sign-image.yaml@MAIN",
        "InteractionLabs/infrastructure/.github/workflows/sign-image.yaml@master",
    ],
)
def test_other_sign_image_references_remain_mutable(reference):
    artifact, version = reference.rsplit("@", 1)
    assert policy.discover_text(
        ".github/workflows/build-image.yml",
        f"jobs:\n  sign:\n    uses: {reference}\n",
    ) == [
        policy.Dependency(
            "mutable",
            artifact,
            version,
            ".github/workflows/build-image.yml",
        )
    ]


def test_other_latest_action_references_remain_mutable():
    assert policy.discover_text(
        ".github/workflows/dependency-policy.yml",
        "jobs:\n  policy:\n    uses: owner/action@main\n",
    ) == [
        policy.Dependency(
            "mutable",
            "owner/action",
            "main",
            ".github/workflows/dependency-policy.yml",
        )
    ]


def test_latest_policy_reference_outside_policy_workflow_remains_mutable():
    reference = (
        "InteractionLabs/infrastructure/.github/actions/dependency-policy@main"
    )
    assert policy.discover_text(
        ".github/workflows/ci.yml",
        f"jobs:\n  policy:\n    uses: {reference}\n",
    ) == [
        policy.Dependency(
            "mutable",
            "InteractionLabs/infrastructure/.github/actions/dependency-policy",
            "main",
            ".github/workflows/ci.yml",
        )
    ]


@pytest.mark.parametrize("version", ["MAIN", "feature", "latest", "master"])
def test_interactionlabs_policy_references_on_other_branches_remain_mutable(
    version,
):
    artifact = (
        "InteractionLabs/security-controls/.github/actions/dependency-policy"
    )
    path = ".github/workflows/reusable-dependency-policy.yml"
    assert policy.discover_text(
        path,
        f"jobs:\n  policy:\n    uses: {artifact}@{version}\n",
    ) == [policy.Dependency("mutable", artifact, version, path)]


def test_discovers_uv_pnpm_go_and_container_transitives():
    uv_dependencies = policy.discover_text(
        "uv.lock",
        """
version = 1
[[package]]
name = "requests"
version = "2.32.5"
source = { registry = "https://pypi.org/simple" }
[[package]]
name = "workspace-package"
version = "0.1.0"
source = { editable = "." }
""",
    )
    pnpm_dependencies = policy.discover_text(
        "pnpm-lock.yaml",
        """
packages:
  '@scope/pkg@1.2.3':
    resolution: {integrity: sha512-test}
  lodash@4.17.21:
    resolution: {integrity: sha512-test}
""",
    )
    go_dependencies = policy.discover_text(
        "go.sum",
        "example.com/direct v1.2.3 h1:x\nexample.com/indirect v0.2.0/go.mod h1:y\n",
    )
    containers = policy.discover_text(
        "services/api/Dockerfile",
        "FROM scratch AS empty\nFROM python:3.13\n"
        "FROM alpine@sha256:" + "b" * 64 + "\n",
    )
    assert uv_dependencies == [
        policy.Dependency("pypi", "requests", "2.32.5", "uv.lock")
    ]
    assert pnpm_dependencies == [
        policy.Dependency("npm", "@scope/pkg", "1.2.3", "pnpm-lock.yaml"),
        policy.Dependency("npm", "lodash", "4.17.21", "pnpm-lock.yaml"),
    ]
    assert go_dependencies == [
        policy.Dependency("go", "example.com/direct", "v1.2.3", "go.sum"),
        policy.Dependency("go", "example.com/indirect", "v0.2.0", "go.sum"),
    ]
    assert containers == [
        policy.Dependency(
            "mutable", "python", "python:3.13", "services/api/Dockerfile"
        ),
        policy.Dependency(
            "oci", "alpine", "sha256:" + "b" * 64, "services/api/Dockerfile"
        ),
    ]


@pytest.mark.parametrize(
    "path",
    [
        "baler/TraversalProcessorDockerfile",
        "baler/AmexDockerfile",
        "services/api/Dockerfile.prebuilt",
    ],
)
def test_discovers_container_inputs_in_supported_dockerfile_names(path):
    assert policy.discover_text(path, "FROM python:3.13\n") == [
        policy.Dependency("mutable", "python", "python:3.13", path)
    ]


def test_ignores_internal_container_stages():
    path = "services/api/Dockerfile"
    assert policy.discover_text(
        path,
        "FROM python:3.13 AS builder\n"
        "FROM builder AS packaged\n"
        "FROM packaged\n",
    ) == [policy.Dependency("mutable", "python", "python:3.13", path)]


def test_chart_discovery_ignores_first_party_chart_version():
    dependencies = policy.discover_text(
        "helm/example/Chart.yaml",
        """
name: example
version: 1.0.0
dependencies:
  - name: postgres
    repository: https://charts.example.com
    version: 2.0.0
""",
    )
    assert dependencies == [
        policy.Dependency(
            "helm",
            "postgres|https://charts.example.com",
            "2.0.0",
            "helm/example/Chart.yaml",
        )
    ]


def test_dependency_delta_skips_deleted_tgz_and_gzip_files(
    monkeypatch, git_repository
):
    repository, git = git_repository
    deleted = repository / "deleted.bin"
    deleted.write_bytes(b"\xff")
    git("add", "deleted.bin")
    git(
        "-c",
        "user.name=Dependency Policy",
        "-c",
        "user.email=dependency-policy@example.com",
        "commit",
        "-m",
        "add binary",
    )
    base = git("rev-parse", "HEAD")
    deleted.unlink()
    (repository / "archive.tgz").write_bytes(b"\xff")
    (repository / "compressed.data").write_bytes(b"\x1f\x8b\xff")
    (repository / "unknown.bin").write_bytes(b"\xff")
    git("add", "--all")
    git(
        "-c",
        "user.name=Dependency Policy",
        "-c",
        "user.email=dependency-policy@example.com",
        "commit",
        "-m",
        "replace binary",
    )

    monkeypatch.setattr(policy, "REPOSITORY", repository)

    assert policy.dependency_delta(base, "HEAD") == []


def test_dependency_delta_does_not_load_irrelevant_blobs(monkeypatch):
    monkeypatch.setattr(policy, "run_git", lambda *unused: "image.png\0")
    monkeypatch.setattr(
        policy, "release_asset_dependencies", lambda unused_revision, unused_paths: set()
    )
    monkeypatch.setattr(
        policy,
        "git_file",
        lambda unused_revision, unused_path: pytest.fail("irrelevant blob loaded"),
    )

    assert policy.dependency_delta("base", "head") == []


def test_dependency_delta_reports_invalid_parser_input(
    monkeypatch, git_repository
):
    repository, git = git_repository
    git(
        "-c",
        "user.name=Dependency Policy",
        "-c",
        "user.email=dependency-policy@example.com",
        "commit",
        "--allow-empty",
        "-m",
        "base",
    )
    base = git("rev-parse", "HEAD")
    (repository / "requirements.txt").write_bytes(b"\xff")
    git("add", "requirements.txt")
    git(
        "-c",
        "user.name=Dependency Policy",
        "-c",
        "user.email=dependency-policy@example.com",
        "commit",
        "-m",
        "add invalid requirements",
    )
    monkeypatch.setattr(policy, "REPOSITORY", repository)

    dependencies = policy.dependency_delta(base, "HEAD")

    assert dependencies == [
        policy.Dependency(
            "unparseable",
            "requirements.txt",
            "requirements.txt is not valid UTF-8 text",
            "requirements.txt",
        )
    ]
    result = policy.check(dependencies, {}, NOW)[0]
    assert result.status == "unknown"
    assert result.detail == "requirements.txt is not valid UTF-8 text"


def test_dependency_delta_finds_release_asset_in_unstructured_text(
    monkeypatch, git_repository
):
    repository, git = git_repository
    git(
        "-c",
        "user.name=Dependency Policy",
        "-c",
        "user.email=dependency-policy@example.com",
        "commit",
        "--allow-empty",
        "-m",
        "base",
    )
    base = git("rev-parse", "HEAD")
    installer = repository / "install.sh"
    installer.write_text(
        "https://github.com/owner/tool/releases/"
        "download/v1.2.3/tool-linux-amd64\n"
    )
    git("add", "install.sh")
    git(
        "-c",
        "user.name=Dependency Policy",
        "-c",
        "user.email=dependency-policy@example.com",
        "commit",
        "-m",
        "add installer",
    )
    monkeypatch.setattr(policy, "REPOSITORY", repository)

    assert policy.dependency_delta(base, "HEAD") == [
        policy.Dependency(
            "github-release",
            "owner/tool/tool-linux-amd64",
            "v1.2.3",
            "install.sh",
        )
    ]


@pytest.mark.parametrize(
    ("content", "expected"),
    [
        (b"\x1f\x8b\x08\x00", "application/gzip"),
        (b"PK\x03\x04" + b"x" * 20, "application/zip"),
        (b"\x89PNG\r\n\x1a\n" + b"x" * 20, "image/png"),
        (b"\xff\xd8\xff" + b"x" * 20, "image/jpeg"),
        (b"%PDF-1.7\n", "application/pdf"),
    ],
)
def test_binary_format_uses_filetype(content, expected):
    assert policy.binary_format(content) == expected


def test_binary_format_recognizes_nul_content():
    assert policy.binary_format(b"text\0content") == "binary"


def test_discovers_terraform_registry_and_git_modules():
    configuration = '''
module "registry" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "6.0.1"
}

module "git" {
  source = "git::https://github.com/example/module.git?ref=GIT_SHA"
}

module "mutable" {
  source = "git::https://github.com/example/other.git?ref=v1.2.3"
}

module "local" {
  source = "../local"
}
'''.replace("GIT_SHA", "a" * 40)
    dependencies = policy.discover_text(
        "modules/example/main.tf",
        configuration,
    )
    assert dependencies == [
        policy.Dependency(
            "mutable",
            "git::https://github.com/example/other.git",
            "git::https://github.com/example/other.git?ref=v1.2.3",
            "modules/example/main.tf",
        ),
        policy.Dependency(
            "terraform-module",
            "git::https://github.com/example/module.git",
            "a" * 40,
            "modules/example/main.tf",
        ),
        policy.Dependency(
            "terraform-module",
            "terraform-aws-modules/vpc/aws",
            "6.0.1",
            "modules/example/main.tf",
        ),
    ]


def test_young_old_and_missing_evidence_fail_closed(monkeypatch):
    dependencies = [
        policy.Dependency("pypi", "young", "1.0", "uv.lock"),
        policy.Dependency("pypi", "old", "1.0", "uv.lock"),
        policy.Dependency("helm", "unknown", "1.0", "Chart.lock"),
    ]

    def fake_evidence(dependency):
        if dependency.artifact == "young":
            return NOW - dt.timedelta(hours=1), "registry"
        if dependency.artifact == "old":
            return NOW - dt.timedelta(hours=169), "registry"
        raise ValueError("missing registry evidence")

    monkeypatch.setattr(policy, "evidence", fake_evidence)
    results = policy.check(dependencies, {}, NOW)
    assert [(result.artifact, result.status) for result in results] == [
        ("young", "blocked"),
        ("old", "eligible"),
        ("unknown", "unknown"),
    ]
    assert results[0].eligible_at == (
        NOW + dt.timedelta(hours=167)
    ).isoformat()


def test_evidence_cache_reuses_successful_lookup(monkeypatch, tmp_path):
    path = tmp_path / "evidence.json"
    dependency = policy.Dependency("npm", "cached", "1.0.0", "package-lock.json")
    published = NOW - dt.timedelta(days=8)
    calls = 0

    def lookup(unused):
        nonlocal calls
        calls += 1
        return published, "https://registry.example/evidence"

    monkeypatch.setattr(policy, "evidence", lookup)
    cache = policy.EvidenceCache.load(path)

    first = policy.check([dependency], {}, NOW, cache)[0]

    assert first.status == "eligible"
    assert calls == 1
    assert cache.hits == 0
    assert cache.misses == 1
    assert cache.writes == 1
    assert cache.save() is None
    document = json.loads(path.read_text())
    assert document["cooldown_seconds"] == int(policy.COOLDOWN.total_seconds())
    cached_entry = document["entries"][policy.evidence_cache_key(dependency)]
    assert cached_entry["eligible_at"] == (
        published + policy.COOLDOWN
    ).isoformat()

    restored = policy.EvidenceCache.load(path)
    monkeypatch.setattr(policy, "COOLDOWN", dt.timedelta(days=30))
    second = policy.check(
        [dependency], {}, NOW + dt.timedelta(hours=1), restored
    )[0]

    assert second.status == "eligible"
    assert second.eligible_at == (published + dt.timedelta(days=7)).isoformat()
    assert calls == 1
    assert restored.hits == 1
    assert restored.misses == 0
    assert restored.writes == 0


def test_evidence_cache_keeps_young_lookup_after_eligibility(
    monkeypatch, tmp_path
):
    path = tmp_path / "evidence.json"
    dependency = policy.Dependency("npm", "young", "1.0.0", "package-lock.json")
    published = NOW - dt.timedelta(days=6)
    calls = 0

    def lookup(unused):
        nonlocal calls
        calls += 1
        return published, "https://registry.example/evidence"

    monkeypatch.setattr(policy, "evidence", lookup)
    cache = policy.EvidenceCache.load(path)
    first = policy.check([dependency], {}, NOW, cache)[0]
    assert first.status == "blocked"
    assert cache.save() is None

    restored = policy.EvidenceCache.load(path)
    second = policy.check(
        [dependency], {}, NOW + dt.timedelta(days=365), restored
    )[0]

    assert second.status == "eligible"
    assert calls == 1
    assert restored.hits == 1
    assert restored.misses == 0


@pytest.mark.parametrize(
    "dependency",
    [
        policy.Dependency("pypi", "mutable-files", "1.0.0", "uv.lock"),
        policy.Dependency(
            "github-release",
            "owner/tool/tool.tar.gz",
            "v1.0.0",
            "Dockerfile",
        ),
    ],
)
def test_evidence_cache_skips_republishable_ecosystems(
    monkeypatch, tmp_path, dependency
):
    calls = 0

    def lookup(unused):
        nonlocal calls
        calls += 1
        return NOW - dt.timedelta(days=8), "https://registry.example/evidence"

    monkeypatch.setattr(policy, "evidence", lookup)
    cache = policy.EvidenceCache.load(tmp_path / "evidence.json")

    policy.check([dependency], {}, NOW, cache)
    policy.check([dependency], {}, NOW, cache)

    assert calls == 2
    assert cache.entries == {}
    assert cache.hits == 0
    assert cache.writes == 0


def test_evidence_cache_does_not_store_failed_lookup(monkeypatch, tmp_path):
    dependency = policy.Dependency("npm", "missing", "1.0.0", "package-lock.json")
    cache = policy.EvidenceCache.load(tmp_path / "evidence.json")
    monkeypatch.setattr(
        policy,
        "evidence",
        lambda unused: (_ for _ in ()).throw(OSError("registry unavailable")),
    )

    result = policy.check([dependency], {}, NOW, cache)[0]

    assert result.status == "unknown"
    assert cache.entries == {}


def test_evidence_cache_ignores_malformed_entry(monkeypatch, tmp_path):
    dependency = policy.Dependency("npm", "cached", "1.0.0", "package-lock.json")
    path = tmp_path / "evidence.json"
    path.write_text(
        json.dumps(
            {
                "schema": policy.CACHE_SCHEMA,
                "cooldown_seconds": int(policy.COOLDOWN.total_seconds()),
                "entries": {
                    policy.evidence_cache_key(dependency): {
                        "published_at": "not-a-time"
                    }
                },
            }
        )
    )
    monkeypatch.setattr(
        policy,
        "evidence",
        lambda unused: (
            NOW - dt.timedelta(days=8),
            "https://registry.example/evidence",
        ),
    )
    cache = policy.EvidenceCache.load(path)

    result = policy.check([dependency], {}, NOW, cache)[0]

    assert result.status == "eligible"
    assert cache.hits == 0
    assert cache.misses == 1


def test_evidence_cache_rejects_another_cooldown(tmp_path):
    path = tmp_path / "evidence.json"
    path.write_text(
        json.dumps(
            {
                "schema": policy.CACHE_SCHEMA,
                "cooldown_seconds": 1,
                "entries": {
                    "stale": {
                        "published_at": NOW.isoformat(),
                        "eligible_at": NOW.isoformat(),
                        "evidence": "https://registry.example/evidence",
                    }
                },
            }
        )
    )

    assert policy.EvidenceCache.load(path).entries == {}


def test_evidence_cache_cannot_bypass_version_validation(tmp_path):
    dependency = policy.Dependency("npm", "unsafe", "latest", "package-lock.json")
    cache = policy.EvidenceCache.load(tmp_path / "evidence.json")
    published = NOW - dt.timedelta(days=8)
    cache.put(
        dependency,
        policy.PublicationEvidence(
            published,
            published + policy.COOLDOWN,
            "https://registry.example/evidence",
        ),
    )

    result = policy.check([dependency], {}, NOW, cache)[0]

    assert result.status == "unknown"
    assert cache.hits == 0
    assert result.detail == "exception version must be one exact immutable coordinate"


def exception_record(**overrides):
    record = {
        "ecosystem": "pypi",
        "artifact": "young",
        "version": "1.0.0",
        "reason": "reviewed security fix",
        "reference": "SEC-123",
        "approver": "security@example.com",
        "created_at": NOW.isoformat(),
        "expires_at": (NOW + dt.timedelta(days=6)).isoformat(),
    }
    record.update(overrides)
    return record


def test_exception_is_exact_and_cannot_outlive_normal_eligibility(
    monkeypatch, tmp_path
):
    path = tmp_path / "exceptions.json"
    record = exception_record()
    path.write_text(json.dumps({"exceptions": [record]}))
    exceptions = policy.load_exceptions(path, NOW)
    assert exceptions[("pypi", "young", "1.0.0")] == record

    dependency = policy.Dependency("pypi", "young", "1.0.0", "uv.lock")
    monkeypatch.setattr(
        policy,
        "evidence",
        lambda unused: (NOW - dt.timedelta(days=2), "registry"),
    )
    result = policy.check([dependency], exceptions, NOW)[0]
    assert result.status == "unknown"
    assert result.detail == "exception expires after normal eligibility"

    record["expires_at"] = (NOW + dt.timedelta(days=4)).isoformat()
    path.write_text(json.dumps({"exceptions": [record]}))
    result = policy.check(
        [dependency], policy.load_exceptions(path, NOW), NOW
    )[0]
    assert result.status == "excepted"


@pytest.mark.parametrize(
    "record",
    [
        exception_record(version="*"),
        exception_record(version=">=1.0"),
        exception_record(version="latest"),
        exception_record(ecosystem="github-commit", version="v4"),
        exception_record(ecosystem="oci", version="alpine:3"),
    ],
)
def test_exception_rejects_broad_or_mutable_coordinates(tmp_path, record):
    path = tmp_path / "exceptions.json"
    path.write_text(json.dumps({"exceptions": [record]}))
    with pytest.raises(ValueError, match="exact|full lowercase SHA|sha256"):
        policy.load_exceptions(path, NOW)


def test_exception_never_overrides_missing_evidence(monkeypatch, tmp_path):
    path = tmp_path / "exceptions.json"
    path.write_text(json.dumps({"exceptions": [exception_record()]}))
    monkeypatch.setattr(
        policy,
        "evidence",
        lambda unused: (_ for _ in ()).throw(OSError("registry outage")),
    )
    result = policy.check(
        [policy.Dependency("pypi", "young", "1.0.0", "uv.lock")],
        policy.load_exceptions(path, NOW),
        NOW,
    )[0]
    assert result.status == "unknown"
    assert "outage" in result.detail


@pytest.mark.parametrize(
    ("dependency", "payload", "expected"),
    [
        (
            policy.Dependency("npm", "left-pad", "1.3.0", "package-lock.json"),
            {"time": {"1.3.0": "2020-01-01T00:00:00Z"}},
            dt.datetime(2020, 1, 1, tzinfo=dt.timezone.utc),
        ),
        (
            policy.Dependency("crates", "serde", "1.0.0", "Cargo.lock"),
            {"version": {"created_at": "2020-01-01T00:00:00Z"}},
            dt.datetime(2020, 1, 1, tzinfo=dt.timezone.utc),
        ),
        (
            policy.Dependency("maven", "org.example:demo", "1.0.0", "pom.xml"),
            {"response": {"docs": [{"timestamp": 1577836800000}]}},
            dt.datetime(2020, 1, 1, tzinfo=dt.timezone.utc),
        ),
    ],
)
def test_registry_evidence_resolvers(monkeypatch, dependency, payload, expected):
    monkeypatch.setattr(policy, "request", lambda url: (payload, url))
    published, source = policy.evidence(dependency)
    assert published == expected
    assert source.startswith("https://")


def test_pypi_uses_newest_distribution_upload(monkeypatch):
    dependency = policy.Dependency("pypi", "demo", "1.0.0", "uv.lock")
    monkeypatch.setattr(
        policy,
        "request",
        lambda url: (
            {
                "urls": [
                    {"upload_time_iso_8601": "2020-01-01T00:00:00Z"},
                    {"upload_time_iso_8601": "2020-01-03T00:00:00Z"},
                ]
            },
            url,
        ),
    )
    published, unused = policy.evidence(dependency)
    assert published == dt.datetime(2020, 1, 3, tzinfo=dt.timezone.utc)


SDIST = "sha256:" + "1" * 64
WHEEL = "sha256:" + "2" * 64
LATE_WHEEL = "sha256:" + "3" * 64


def pypi_files(*files):
    return {
        "urls": [
            {
                "digests": {"sha256": digest.removeprefix("sha256:")},
                "upload_time_iso_8601": uploaded.isoformat(),
            }
            for digest, uploaded in files
        ]
    }


def test_uv_lock_records_file_hashes():
    dependencies = policy.discover_text(
        "uv.lock",
        f"""
[[package]]
name = "Demo"
version = "1.0.0"
source = {{ registry = "https://pypi.org/simple" }}
sdist = {{ url = "https://files.example/demo.tar.gz", hash = "{SDIST.upper().replace("SHA256", "sha256")}" }}
wheels = [
    {{ url = "https://files.example/demo.whl", hash = "{WHEEL}" }},
]
""",
    )

    assert dependencies == [
        policy.Dependency("pypi", "demo", "1.0.0", "uv.lock", (SDIST, WHEEL))
    ]


def test_pypi_rejects_locked_hash_missing_from_registry(monkeypatch):
    dependency = policy.Dependency(
        "pypi", "demo", "1.0.0", "uv.lock", (SDIST, WHEEL)
    )
    monkeypatch.setattr(
        policy,
        "request",
        lambda url: (pypi_files((SDIST, NOW - dt.timedelta(days=30))), url),
    )

    with pytest.raises(ValueError, match="no file for locked hash"):
        policy.evidence(dependency)


def test_pypi_cache_is_keyed_on_locked_hashes(monkeypatch, tmp_path):
    path = tmp_path / "evidence.json"
    old = NOW - dt.timedelta(days=30)
    late = NOW - dt.timedelta(days=1)
    files = [(SDIST, old), (WHEEL, old)]
    calls = 0

    def request(url):
        nonlocal calls
        calls += 1
        return pypi_files(*files), url

    monkeypatch.setattr(policy, "request", request)
    locked = policy.Dependency(
        "pypi", "demo", "1.0.0", "uv.lock", (SDIST, WHEEL)
    )
    cache = policy.EvidenceCache.load(path)
    assert policy.check([locked], {}, NOW, cache)[0].status == "eligible"
    assert cache.save() is None

    files.append((LATE_WHEEL, late))
    restored = policy.EvidenceCache.load(path)
    assert policy.check([locked], {}, NOW, restored)[0].status == "eligible"
    assert calls == 1
    assert restored.hits == 1

    relocked = policy.Dependency(
        "pypi", "demo", "1.0.0", "uv.lock", (SDIST, WHEEL, LATE_WHEEL)
    )
    result = policy.check([relocked], {}, NOW, restored)[0]
    assert result.status == "blocked"
    assert result.published_at == late.isoformat()
    assert calls == 2


def test_dependency_delta_sees_new_file_under_existing_version(
    monkeypatch, git_repository
):
    repository, git = git_repository

    def commit(wheels, message):
        entries = "".join(
            f'    {{ url = "https://files.example/{index}.whl", hash = "{digest}" }},\n'
            for index, digest in enumerate(wheels)
        )
        (repository / "uv.lock").write_text(
            "[[package]]\n"
            'name = "demo"\n'
            'version = "1.0.0"\n'
            'source = { registry = "https://pypi.org/simple" }\n'
            f"wheels = [\n{entries}]\n"
        )
        git("add", "uv.lock")
        git(
            "-c",
            "user.name=Dependency Policy",
            "-c",
            "user.email=dependency-policy@example.com",
            "commit",
            "-m",
            message,
        )
        return git("rev-parse", "HEAD")

    base = commit([WHEEL], "lock one wheel")
    commit([WHEEL, LATE_WHEEL], "lock a late wheel")
    monkeypatch.setattr(policy, "REPOSITORY", repository)

    assert policy.dependency_delta(base, "HEAD") == [
        policy.Dependency(
            "pypi", "demo", "1.0.0", "uv.lock", (WHEEL, LATE_WHEEL)
        )
    ]


def test_go_uses_public_index_timestamp_not_proxy_commit_time(monkeypatch):
    dependency = policy.Dependency(
        "go",
        "example.com/Module",
        "v0.0.0-20200101000000-deadbeef",
        "go.mod",
    )
    monkeypatch.setattr(
        policy,
        "request",
        lambda url: ({"Time": "2020-01-01T00:00:00Z"}, url),
    )
    monkeypatch.setattr(
        policy,
        "request_json_lines",
        lambda url: (
            [
                {
                    "Path": dependency.artifact,
                    "Version": dependency.version,
                    "Timestamp": "2026-09-08T00:00:00Z",
                }
            ],
            url,
        ),
    )

    observed, source = policy.evidence(dependency)

    assert observed == dt.datetime(2026, 9, 8, tzinfo=dt.timezone.utc)
    assert source.startswith("https://index.golang.org/index?")


def test_github_commit_uses_public_commit_timestamp(monkeypatch):
    dependency = policy.Dependency(
        "github-commit",
        "owner/repository/.github/workflows/ci.yml",
        "a" * 40,
        ".github/workflows/ci.yml",
    )
    monkeypatch.setattr(
        policy,
        "request",
        lambda url: (
            {"commit": {"committer": {"date": "2020-01-02T00:00:00Z"}}},
            url,
        ),
    )

    published, source = policy.evidence(dependency)

    assert published == dt.datetime(2020, 1, 2, tzinfo=dt.timezone.utc)
    assert source == (
        "https://api.github.com/repos/owner/repository/commits/" + "a" * 40
    )


@pytest.mark.parametrize(
    "dependency",
    [
        policy.Dependency(
            "github-commit", "owner/shared-policy/action", "a" * 40, "ci.yml"
        ),
        policy.Dependency(
            "github-release",
            "owner/tool/tool-1.2.3.tar.gz",
            "v1.2.3",
            "release.rb",
        ),
    ],
)
def test_same_owner_github_dependency_is_internal_without_api_access(
    monkeypatch, dependency
):
    monkeypatch.setenv("GITHUB_REPOSITORY", "owner/consumer")
    monkeypatch.setenv("GITHUB_REPOSITORY_OWNER", "owner")
    monkeypatch.setattr(
        policy,
        "request",
        lambda url: pytest.fail(f"internal commit requested from {url}"),
    )

    result = policy.check([dependency], {}, NOW)[0]

    assert result.status == "internal"
    assert result.published_at is None
    assert result.evidence is None


def test_unsupported_ecosystem_is_reported_as_unverifiable():
    dependency = policy.Dependency(
        "oci", "example/image", "sha256:" + "a" * 64, "Dockerfile"
    )

    result = policy.check([dependency], {}, NOW)[0]

    assert result.status == "unverifiable"
    assert result.evidence is None
    assert result.detail == "no public publication-time resolver for oci"


def test_workflow_wires_default_branch_evidence_cache():
    workflow = (
        REPOSITORY_ROOT / ".github/workflows/reusable-dependency-policy.yml"
    ).read_text()
    caller = (
        REPOSITORY_ROOT / ".github/workflows/dependency-policy.yml"
    ).read_text()
    action = (
        REPOSITORY_ROOT / ".github/actions/dependency-policy/action.yml"
    ).read_text()

    assert "actions/cache/restore@0057852bfaa89a56745cba8c7296529d2fc39830" in workflow
    assert "actions/cache/save@0057852bfaa89a56745cba8c7296529d2fc39830" in workflow
    assert "dependency-policy-evidence-v3-${{ github.repository_id }}-" in workflow
    assert "cache: ${{ runner.temp }}/dependency-policy-cache/evidence.json" in workflow
    assert "jq -e '.cache.writes > 0'" in workflow
    assert "push:\n    branches: [main]" in caller
    assert "--cache \"$INPUT_CACHE\"" in action
