# Dependency cooldowns

Third-party package versions must complete a seven-day (168-hour) cooldown after
publication before use. This applies to runtime and transitive dependencies,
development tools, CI tooling, and container builds.

Do not download, install, or execute a version before its cooldown ends on a
developer laptop, or introduce it into CI, staging, or production. Package install
hooks can execute malicious code during installation, before tests run.

## Security fixes don't wait for the cooldown

If you are resolving a CVE as part of a Patch Tuesday cycle or another remediation
cycle, you do not need a cooldown exception to fix a CISA KEV, Critical or High
vulnerability, or another issue with critical material impact on Traversal's
security. Once such an issue has been established, by a Wiz finding, a published
advisory, or Security's confirmation, update to the fixed version and bypass the
cooldown.

Use the lowest version that fixes the issue, pinned to an exact version, commit SHA
or digest. The wizcli scan gate where it applies, lockfiles, and code-owner review
still apply. If the dependency-policy check still reports the fix as blocked, name
the CVE or advisory in the pull request description and ask a reviewer to merge it;
that is not a reason to wait.

## Everything else

Every other version completes the cooldown. If early use is needed, stop and
escalate to `#security` on Slack. Consult
[Dependency cooldown exceptions](https://app.notion.com/p/3f12fa20e38681c4bf18e5fd27b1efc7?pvs=204)
for the latest guidance on due diligence, isolated security scanning, and
clearance. Escalation, a passing scan, or passing CI is not approval. Approved
exceptions work as before.

Do not bypass cooldown settings, edit lockfiles to evade the cooldown, or create
an exception without explicit Security authorization. If the guide is
inaccessible or the required approval is unclear, report the blocker and do not
proceed.
