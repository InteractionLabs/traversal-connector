#!/usr/bin/env python3
"""Enforce a seven-day cooldown on newly introduced Go module versions."""

import argparse
import datetime as dt
import hashlib
import hmac
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
    endpoint = os.getenv("DEPENDENCY_EVIDENCE_URL")
    token = os.getenv("DEPENDENCY_EVIDENCE_TOKEN")
    key = os.getenv("DEPENDENCY_EVIDENCE_HMAC_KEY")
    if not endpoint or not key:
        raise RuntimeError("private module %s@%s requires signed first-observed evidence" % (module, version))
    query = {"ecosystem": "go", "artifact": module, "version": version}
    url = endpoint + ("&" if "?" in endpoint else "?") + urllib.parse.urlencode(query)
    evidence = fetch_json(url, token)
    signed = {**query, "first_observed_at": evidence.get("first_observed_at")}
    if any(evidence.get(field) != value for field, value in signed.items()):
        raise RuntimeError("private evidence response did not exactly match %s@%s" % (module, version))
    payload = json.dumps(signed, sort_keys=True, separators=(",", ":")).encode()
    expected = hmac.new(key.encode(), payload, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(str(evidence.get("signature", "")), expected):
        raise RuntimeError("private evidence response has an invalid signature")
    return parse_time(evidence["first_observed_at"])


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
