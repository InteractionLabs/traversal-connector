# Connector trust bootstrap

## Decision

A newly enrolled Connector may fetch one trust document from `GET /v1/trust/<connector-id>` over the same authenticated mTLS transport used for controller traffic. It validates the document, creates its state file with exclusive-create semantics, and then uses the pinned capability roots and OTA config keys through the existing verifiers.

The state file is the enrollment boundary. Once it exists, the Connector never replaces it from the network. Deleting the file is explicit re-enrollment. Existing `TRAVERSAL_CAPABILITY_ROOTS`, `TRAVERSAL_CAPABILITY_KEYS`, and `TRAVERSAL_CONFIG_KEYS` deployments continue to work and take precedence.

The bootstrap document is JSON:

```json
{
  "schema_version": 1,
  "capability_roots_pem": "-----BEGIN CERTIFICATE-----...",
  "config_keys_pem": "-----BEGIN PUBLIC KEY-----..."
}
```

The config key bundle uses the existing `Key-ID` PEM headers and `connector-lib/signedconfig` ES256 JWS format. When OTA is enabled, a bootstrapped Connector therefore rejects unsigned configuration from its first fetch onward.

## Durable state

`TRAVERSAL_TRUST_STATE_FILE` must be on storage durable across pod replacement. The Helm integration requires an existing claim because an `emptyDir` silently reopens enrollment after every reschedule. A shared claim also lets replicas of one Connector converge safely: only one creates the pin; concurrent replicas load the winner.

## Rotation follow-up

This change deliberately implements first trust without a network overwrite path. Rotation must not weaken that invariant. The follow-up protocol should publish a versioned, expiring trust bundle signed by a currently pinned root (or carry a cross-certificate from the current root to the next root). The Connector may persist a replacement only after that signature verifies, and must emit a root-change log and metric. Fetch failure or signature failure must retain the last-known-good pin; there is no fetch-only fallback.

The trust publisher and OTA signer must not run in the edge gateway. The gateway only authenticates the Connector and proxies immutable signed objects. The remaining control-plane decision is where the OTA signing key and root-rotation signer live and how their public material is published into the trust object.
