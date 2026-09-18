# Released upstream TLS black-box suite

This manual suite installs the released `v0.8.4` connector image from the
released `0.8.4` OCI chart into a disposable kind cluster. A small in-cluster Go
controller accepts the connector's h2c ConnectRPC tunnel and asks it to call an
HTTPS shim signed by a newly generated private CA.

The matrix verifies secure-default trust failures, insecure-mode success, raw
private-CA trust, and rejection of malformed CA input. In particular, case 5
proves that a valid `caPEM` remains parseable but does not constrain trust when
`verify=false`. Case 6 requires the exact CA parse error and independently
proves startup was rejected: the connector must remain not Ready and its
container must have terminated and restarted. It does not assume the released
binary exits nonzero.

Run all six cases with one command from the repository root:

```bash
just e2e-upstream-tls
```

The harness requires Docker, kind, kubectl, Helm, OpenSSL, and Go. Certificates
and private keys are generated in a temporary directory and are never written
to the repository. The cluster and temporary files are deleted on exit. Set
`KEEP_CLUSTER=1` to retain the cluster and failure artifacts for debugging; the
script prints their paths and the exact cleanup command.

This suite deliberately remains local/manual and is not run in CI. It validates
the immutable release coordinates and fails before testing if the chart or image
digest differs from the pinned `v0.8.4` release.
