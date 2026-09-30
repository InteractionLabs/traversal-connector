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
