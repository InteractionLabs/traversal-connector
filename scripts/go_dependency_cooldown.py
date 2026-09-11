#!/usr/bin/env python3
"""Enforce a seven-day cooldown on newly introduced Go module versions."""

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Optional

COOLDOWN = dt.timedelta(days=7)
PROXY = os.getenv("GOPROXY", "https://proxy.golang.org").split(",")[0].rstrip("/")
INDEX = os.getenv("GOINDEX", "https://index.golang.org/index")
PRIVATE_PREFIXES = tuple(filter(None, os.getenv("GOPRIVATE", "github.com/InteractionLabs").split(",")))
DEFAULT_EVIDENCE_BUCKET = "traversal-dependency-evidence-833319601877-us-west-2"
DEFAULT_EVIDENCE_REGION = "us-west-2"
EVIDENCE_REPOSITORY = "InteractionLabs/traversal-connector"


def parse_time(value):
    return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))


def fetch_json(url, token=None):
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=20) as response:
        return json.load(response)


def fetch_json_lines(url):
    with urllib.request.urlopen(urllib.request.Request(url, headers={"Accept": "application/json"}), timeout=20) as response:
        return [json.loads(line) for line in response if line.strip()]


def modules_at(revision: Optional[str]):
    text = subprocess.check_output(["git", "show", "%s:go.mod" % revision], text=True) if revision else Path("go.mod").read_text()
    modules = {}
    for line in text.splitlines():
        match = re.match(r"\s*([^\s()]+)\s+(v[^\s]+)(?:\s+//.*)?$", line)
        if match:
            modules[match.group(1)] = match.group(2)
    return modules


def escape(value):
    return "".join("!" + char.lower() if "A" <= char <= "Z" else char for char in value)


def public_first_observed(module, version):
    try:
        info = fetch_json("%s/%s/@v/%s.info" % (PROXY, escape(module), escape(version)))
    except urllib.error.HTTPError as error:
        if error.code in (404, 410):
            return None
        raise
    # .info Time may be a commit time (notably for pseudo-versions). It is only
    # a search cursor; the append-only Go index Timestamp is the evidence.
    since = parse_time(info["Time"]) - dt.timedelta(seconds=1)
    for _ in range(200):
        url = INDEX + "?" + urllib.parse.urlencode({"since": since.isoformat().replace("+00:00", "Z"), "limit": 2000, "include": "all"})
        entries = fetch_json_lines(url)
        if not entries:
            break
        for entry in entries:
            if entry.get("Path") == module and entry.get("Version") == version:
                return parse_time(entry["Timestamp"])
        next_since = parse_time(entries[-1]["Timestamp"])
        if next_since <= since:
            break
        since = next_since
    raise RuntimeError("Go index has no first-observed record for %s@%s" % (module, version))


def private_first_observed(module, version):
    bucket = os.getenv("DEPENDENCY_EVIDENCE_BUCKET", DEFAULT_EVIDENCE_BUCKET)
    region = os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION", DEFAULT_EVIDENCE_REGION)
    repository = os.getenv("GITHUB_REPOSITORY", EVIDENCE_REPOSITORY)
    coordinate = {"ecosystem": "go", "artifact": module, "version": version}
    canonical = json.dumps(coordinate, sort_keys=True, separators=(",", ":")).encode()
    digest = hashlib.sha256(canonical).hexdigest()
    object_key = "v1/repositories/%s/go/%s.json" % (repository, digest)
    result = subprocess.run(
        [
            "aws",
            "s3api",
            "head-object",
            "--bucket",
            bucket,
            "--key",
            object_key,
            "--region",
            region,
            "--no-cli-pager",
        ],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode != 0:
        raise RuntimeError(
            "private module %s@%s S3 evidence lookup failed: %s"
            % (module, version, result.stderr.strip() or "unknown AWS CLI error")
        )
    metadata = json.loads(result.stdout)
    last_modified = metadata.get("LastModified") if isinstance(metadata, dict) else None
    if not isinstance(last_modified, str):
        raise RuntimeError("private module %s@%s S3 evidence has no LastModified timestamp" % (module, version))
    return parse_time(last_modified)


def exact_exception(module, version, now, eligible=None):
    path = Path(".github/dependency-cooldown-exceptions.json")
    data = json.loads(path.read_text()) if path.exists() else {"exceptions": []}
    if set(data) != {"exceptions"} or not isinstance(data["exceptions"], list):
        raise ValueError("exception file must contain only an exceptions array")
    records = data["exceptions"]
    required = {"ecosystem", "artifact", "version", "reason", "reference", "approver", "created_at", "expires_at"}
    for record in records:
        if set(record) != required:
            raise ValueError("invalid exception record fields for %s" % record.get("artifact", "<unknown>"))
        created, expiry = parse_time(record["created_at"]), parse_time(record["expires_at"])
        if not all(record[key] for key in ("reason", "reference", "approver")):
            raise ValueError("exception review metadata must not be empty")
        if expiry <= created:
            raise ValueError("exception for %s must have a positive lifetime" % record["artifact"])
        if eligible is not None and expiry > eligible:
            raise ValueError("exception for %s expires after normal eligibility" % record["artifact"])
        if record["ecosystem"] == "go" and record["artifact"] == module and record["version"] == version and created <= now < expiry:
            return True
    return False


def verify(base):
    old, new = modules_at(base), modules_at(None)
    changed = sorted((module, version) for module, version in new.items() if old.get(module) != version)
    now, failures = dt.datetime.now(dt.timezone.utc), []
    for module, version in changed:
        try:
            private = any(module == prefix or module.startswith(prefix.rstrip("/") + "/") for prefix in PRIVATE_PREFIXES)
            observed = private_first_observed(module, version) if private else public_first_observed(module, version)
            if observed is None:
                raise RuntimeError("public proxy has no record")
            eligible = observed + COOLDOWN
            if now < eligible and not exact_exception(module, version, now, eligible):
                failures.append("%s@%s is in cooldown until %s" % (module, version, eligible.isoformat()))
        except Exception as error:
            failures.append("%s@%s: missing trustworthy first-observed evidence: %s" % (module, version, error))
    if failures:
        raise SystemExit("dependency cooldown failed:\n" + "\n".join("- " + failure for failure in failures))
    print("dependency cooldown passed (%d changed Go module versions checked)" % len(changed))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", required=True)
    verify(parser.parse_args().base)


if __name__ == "__main__":
    main()
