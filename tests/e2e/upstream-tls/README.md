# Upstream TLS black-box suite

This manual suite installs an explicitly selected connector image with the
released `0.8.4` OCI chart into a disposable kind cluster. The image must have
an explicit tag or SHA-256 digest and be available to local Docker:

```bash
just e2e-upstream-tls --image-ref registry.example.com/team/connector:test-build
```

The harness resolves and pulls the exact host-platform manifest, wraps the
production binary with a deterministic test system root, and loads the local
image into kind. Registry credentials are never copied into the cluster.

All seven cases pass only for an image that preserves system roots when adding
a custom upstream CA. The released `v0.8.4` image is a useful pre-change
baseline, but is expected to fail case 04.

The matrix verifies secure-default trust failures, insecure-mode success, raw
private-CA trust, and rejection of malformed CA input. One case configures a
custom private CA and proves that the same running connector trusts both that CA
and a distinct root supplied through its system bundle. Case 6 proves that a
valid `caPEM` remains parseable but does not constrain trust when `verify=false`.
Case 7 requires the exact CA parse error and independently
proves startup was rejected: the connector must remain not Ready and its
container must have terminated and restarted. It does not assume the released
binary exits nonzero.

The harness requires Docker, kind, kubectl, Helm, OpenSSL, and Go. Certificates
and private keys are generated in a temporary directory and are never written
to the repository. The cluster and temporary files are deleted on exit. Set
`KEEP_CLUSTER=1` to retain the cluster and failure artifacts for debugging; the
script prints their paths and the exact cleanup command.

This suite deliberately remains local/manual and is not run in CI. It validates
the immutable chart coordinate and fails before testing if the released chart
digest differs from the pinned value.
