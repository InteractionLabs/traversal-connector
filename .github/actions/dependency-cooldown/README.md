# Dependency cooldown action

This repository vendors the shared policy action because a public repository
cannot call actions or reusable workflows from the private infrastructure
repository. `SOURCE` records the exact infrastructure commit, and the vendor
test locks the copied policy files to that revision.

The caller, reusable workflow, and action all use full commit SHAs so pull
requests cannot replace the policy code that receives the evidence-writer OIDC
credential.
