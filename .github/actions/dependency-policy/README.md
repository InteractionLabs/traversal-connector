# Dependency policy action

This repository vendors the shared policy action because a public repository
cannot call actions or reusable workflows from the private infrastructure
repository. `SOURCE` records the exact infrastructure commit, and the vendor
test locks the copied policy files to that revision.

Only the exact dependency-policy caller and action may follow `main`; every
other GitHub Action must use a full commit SHA. The vendor test keeps the public
copy byte-for-byte aligned with its declared infrastructure source.
