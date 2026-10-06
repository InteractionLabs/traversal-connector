# Dependency cooldowns

Third-party package versions must complete a seven-day (168-hour) cooldown after
publication before use. This applies to runtime and transitive dependencies,
development tools, CI tooling, and container builds.

Do not download, install, or execute a version before its cooldown ends on a
developer laptop, or introduce it into CI, staging, or production. Package install
hooks can execute malicious code during installation, before tests run.

If early use is needed, stop and escalate to `#security` on Slack. Consult
[Dependency cooldown exceptions](https://app.notion.com/p/3f12fa20e38681c4bf18e5fd27b1efc7?pvs=204)
for the latest guidance on due diligence, isolated security scanning, and
clearance. Escalation, a passing scan, or passing CI is not approval.

Do not bypass cooldown settings, edit lockfiles to evade the cooldown, or create
an exception without explicit Security authorization. If the guide is
inaccessible or the required approval is unclear, report the blocker and do not
proceed.
