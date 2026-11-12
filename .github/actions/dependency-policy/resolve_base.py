"""Resolve the base and head commits the dependency policy compares."""

from __future__ import annotations

import os
import re
import subprocess
import sys
from collections.abc import Mapping

COMMIT = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})")


class BaseUnresolvable(Exception):
    """No trustworthy comparison base could be established."""


def git(*arguments: str) -> subprocess.CompletedProcess[str]:
    """Run git in the working directory without raising on failure."""
    return subprocess.run(
        ["git", *arguments],
        check=False,
        capture_output=True,
        text=True,
    )


def has_commit(revision: str) -> bool:
    """Return whether the revision names a commit in the local object store."""
    return git("cat-file", "-e", f"{revision}^{{commit}}").returncode == 0


def escape(message: str) -> str:
    """Escape a workflow command message."""
    return message.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def notice(message: str) -> None:
    """Emit a workflow notice."""
    print(f"::notice::{escape(message)}")


def fetch_base_branch(base_ref: str) -> str:
    """Fetch the pull request's base branch and return its tracking ref."""
    branch = f"refs/heads/{base_ref}"
    tracking = f"refs/remotes/origin/{base_ref}"
    if git("check-ref-format", branch).returncode != 0:
        raise BaseUnresolvable(
            f"pull request base ref {base_ref!r} is not a branch name"
        )
    fetched = git("fetch", "--no-tags", "origin", f"+{branch}:{tracking}")
    if fetched.returncode != 0:
        raise BaseUnresolvable(
            f"could not fetch base branch {base_ref!r}: {fetched.stderr.strip()}"
        )
    return tracking


def is_ancestor(ancestor: str, descendant: str) -> bool:
    """Return whether ancestor is reachable from descendant."""
    return git("merge-base", "--is-ancestor", ancestor, descendant).returncode == 0


def event_base_is_current(event_base: str, tracking: str, head: str) -> bool:
    """Return whether the event base is a commit the base branch and head both contain."""
    if not has_commit(event_base):
        fetched = git("fetch", "--no-tags", "origin", event_base)
        if fetched.returncode != 0 or not has_commit(event_base):
            return False
    return is_ancestor(event_base, tracking) and is_ancestor(event_base, head)


def resolve_base(explicit_base: str, event_base: str, base_ref: str, head: str) -> str:
    """Return the base commit; a pull request event base is trusted only while the base branch still contains it."""
    if head != "HEAD" and not COMMIT.fullmatch(head):
        raise BaseUnresolvable(f"head {head!r} is not a commit SHA")
    if explicit_base:
        if not COMMIT.fullmatch(explicit_base) or not has_commit(explicit_base):
            raise BaseUnresolvable(f"base commit {explicit_base!r} does not exist")
        return explicit_base
    if not event_base:
        return git("rev-parse", "HEAD^").stdout.strip()
    if not COMMIT.fullmatch(event_base):
        raise BaseUnresolvable(f"pull request base {event_base!r} is not a commit SHA")
    if not base_ref:
        if not has_commit(event_base):
            raise BaseUnresolvable(
                f"pull request base {event_base} is missing and the event names no base branch"
            )
        return event_base
    tracking = fetch_base_branch(base_ref)
    if event_base_is_current(event_base, tracking, head):
        return event_base
    merged = git("merge-base", head, tracking)
    resolved = merged.stdout.strip()
    if merged.returncode != 0 or not has_commit(resolved):
        raise BaseUnresolvable(
            f"{head} and base branch {base_ref!r} share no merge-base"
        )
    notice(
        f"Pull request base {event_base} is gone or no longer in origin/{base_ref}; "
        f"comparing against the merge-base {resolved} of {head} and origin/{base_ref}."
    )
    return resolved


def main(environment: Mapping[str, str] | None = None) -> int:
    """Resolve the commits and write them to the step outputs."""
    env = os.environ if environment is None else environment
    head = env.get("INPUT_HEAD_SHA") or "HEAD"
    try:
        base = resolve_base(
            env.get("INPUT_BASE_SHA", ""),
            env.get("EVENT_BASE_SHA", ""),
            env.get("EVENT_BASE_REF", ""),
            head,
        )
        if not has_commit(base) or not has_commit(head):
            raise BaseUnresolvable("base or head commit does not exist")
    except BaseUnresolvable as error:
        print(
            f"::error::Dependency policy cannot determine what this pull request changes: {escape(str(error))}"
        )
        return 1
    with open(env["GITHUB_OUTPUT"], "a", encoding="utf-8") as outputs:
        outputs.write(f"base={base}\nhead={head}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
