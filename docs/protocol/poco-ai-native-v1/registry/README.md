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

The object registry is an exact, ordered projection of
`schema/object-catalog-v1.toml`: all 53 catalog IDs must be present once, in
catalog order, with the catalog's planning plane. Missing, extra, reordered,
or reclassified objects are `registry_semantic_drift` and fail closed. The
projection remains candidate inventory only; `candidate`/`unassigned` wire
labels do not grant activation authority.

All consumers must run `scripts/ci/check_cev1_registry_spec_v1.py`. Unknown
entries, missing operation slots, duplicate domains, enabled profiles,
fallback edges, malformed JSON, and catalog/registry drift fail closed. Run
`scripts/ci/check_cev1_registry_mutants_v1.sh` to replay the retained
negative-mutant set (10 cases covering object and catalog drift, activation,
operation/profile enablement, and duplicate JSON keys).
