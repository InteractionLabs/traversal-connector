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

## Redaction configuration

Choose one source, or leave both disabled to run without redaction.
Local sources and `configUpdates.enabled: true` are mutually exclusive.

For remote (S3-backed OTA) configuration, publish the config document before
enabling polling:

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
```

Alternatively, leave `rulesContent` empty and set exactly one of
`redaction.existingConfigMap` or `redaction.existingSecret` to a resource in the
release namespace. It must contain the key `redaction-rules.toml`. Only that
key is mounted, read-only, at `/etc/traversal/redaction-rules.toml`.
The chart mounts the directory without `subPath`, so Kubernetes volume updates
can be picked up by the local-file poller without restarting the pod.
The legacy `redactionRules` inline string is also accepted and enables local
redaction; it cannot be combined with another rules source.

Both sources require a valid initial load before opening tunnels. Local reload
errors retain the last-known-good rules, then stop the connector after three
consecutive failures. OTA refresh errors retain the last-known-good rules in
memory and continue polling. Neither source falls back to the other.
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
