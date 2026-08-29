# CEV1 machine-readable registries v1

Status: **candidate-non-normative**.

These files close the review and code-generation inventory surface for the draft PoCO AI-native v1 protocol. They do not override numbered protocol documents, `status.toml`, `spec-manifest.toml`, machine truth, or release truth.

Files:

- `object-registry-v1.json`
- `domain-registry-v1.json`
- `error-registry-v1.json`
- `operation-registry-v1.json`
- `limit-registry-v1.json`
- `verification-profile-registry-v1.json`

All consumers must run `scripts/ci/check_cev1_registry_spec_v1.py`. Unknown entries, missing operation slots, duplicate domains, enabled profiles, fallback edges, and cross-reference drift fail closed.
