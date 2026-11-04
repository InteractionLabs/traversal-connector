# Connector chart

By default, the connector and optional telemetry sidecar run as UID/GID 65532, drop all
Linux capabilities, disable privilege escalation, use `RuntimeDefault`
seccomp, and have read-only root filesystems. Each container has a separate
writable `/tmp` volume. The telemetry sidecar's existing queue volume stays
writable through the pod's `fsGroup: 65532`.

`securityContext` configures the connector container, and `podSecurityContext`
configures the pod, including its default seccomp profile and volume group.
The telemetry sidecar retains its own container security context. When
overriding user or group IDs, keep the writable volumes accessible to both
containers.

## Upgrading

Upgrade the existing release in place:

```bash
helm upgrade <release> <chart> --version <version> -n <namespace> -f <values.yaml>
```

Do not install a new version as a second release next to the old one. Both
releases register the same connector ID. Traversal sends that connector's
traffic to whichever pods hold a 0.10 or later tunnel, so the new release
takes all the traffic as soon as it connects. Workload names, labels and
service accounts are derived from the release name. A second release
therefore does not match network policies, mesh policies or annotations that
were set for the first one.

Settings applied outside this chart, for example sidecar annotations added
with `kubectl patch`, are lost on a fresh install. Move them into
`podAnnotations` and `podLabels` before you upgrade.

## Running inside a service mesh

The connector reaches its destinations from its own pod. If a destination
requires mesh mTLS, for example Istio with a STRICT `PeerAuthentication`, the
connector pod needs a mesh sidecar. A pod without a sidecar sends plaintext,
which the mesh drops: requests to that destination time out, while
destinations outside the mesh keep working.

Enable the sidecar in your values. For Istio:

```yaml
podLabels:
  sidecar.istio.io/inject: "true"
podAnnotations:
  sidecar.istio.io/nativeSidecar: "true"
```

To check, list the pod's init containers. A native sidecar runs as an init
container, not in `spec.containers`.

```bash
kubectl -n <namespace> get pods -l app.kubernetes.io/instance=<release> \
  -o custom-columns=NAME:.metadata.name,INIT:.spec.initContainers[*].name
```

The connector's tunnels to Traversal are TLS on port 443 with their own
mTLS, and the sidecar passes them through unchanged. If the mesh allows only
registered outbound hosts (`outboundTrafficPolicy: REGISTRY_ONLY`), add a
`ServiceEntry` for the controller host.

## Redaction configuration

Enable OTA (`configUpdates.enabled: true`), a local source, both, or neither.
The connector uses one source, never a merge of two:

1. **OTA**, when its first fetch at start succeeds;
2. else the **local rules**, when a local source is enabled;
3. else **no redaction**.

With OTA alone, a failed first fetch stops the connector from starting, so it
never runs unredacted. With a local source as well, it starts on the local
rules and logs a warning instead.

For remote (S3-backed OTA) configuration, the config document should be published
before enabling polling:

```yaml
configUpdates:
  enabled: true
  refreshInterval: "30s"
```

For a local file, provide inline TOML that the chart renders into a ConfigMap:

```yaml
configUpdates:
  enabled: false
redaction:
  enabled: true
  reloadInterval: "10s"
  rulesContent: |
    version = "1"
    [[rules]]
    name = "token"
    type = "regex"
    pattern = 'secret'
    replacement = "[REDACTED]"
    hosts = ['api\.example\.com']
```

Alternatively, leave `rulesContent` empty and set exactly one of
`redaction.existingConfigMap` or `redaction.existingSecret` to a resource in the
release namespace containing the key `redaction-rules.toml`.

See the [connector redaction documentation](../../README.md#redaction) for both
TOML formats, validation, and switching sources.

## TLS failures after restarting a connector

An existing tunnel can survive while new connections fail certificate
validation. Check new pods' readiness and tunnel establishment after an
upgrade, even if Helm reports `deployed`.

Validate the presented chain with the current issuing root and CRL:

```bash
openssl verify -purpose sslclient -CAfile current-root-ca.pem \
  -untrusted client-chain.pem -crl_check -CRLfile current-crl.pem \
  client-chain.pem
```

An older intermediate can lack CRL-signing permission even when the current
CA certificate has it. Refresh the full client chain through the issuing
control plane and validate it again. If validation then reports that the leaf
is revoked, obtain an authorized replacement certificate; do not remove CRL
checking or restore a revoked credential.

Update `controllerTLS.existingSecret` or the inline `controllerTLS.certPEM`
and `keyPEM` values through your existing secret-management workflow. For an
existing Secret, restart the Deployment after updating it: the connector and
sidecar load credentials from environment variables at startup. Inline
certificate changes update the pod-template checksum automatically.
