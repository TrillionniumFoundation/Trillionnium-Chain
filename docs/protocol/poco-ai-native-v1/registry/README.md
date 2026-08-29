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

`operation-registry-v1.json` is an exact ordered projection of document 08's
`OperationPayloadV1` table. It retains the requested short display `name` but
binds each row to the exact canonical `body_type`; a short-name or kind drift
is rejected. Its `authority` slugs map to the numeric outer modes as follows:
`existing-agent=0`, `existing-or-self-origin=1`,
`permissionless-trigger=2`,
`externally-signed-object-submitted-by-agent=3`, and
`action-dependent=4`. Kinds 20 and 27 are retained slots with
`status=disabled`/`ERR_OPERATION_DISABLED`; kind 29 is a normal candidate
slot. The registry's `enabled=false` bit remains false for every row and is
not the same field as the reference profile's `OperationLimitV1.enabled`
eligibility. `global_activation=false` is likewise unchanged.

All consumers must run `scripts/ci/check_cev1_registry_spec_v1.py`. Unknown
entries, missing operation slots, duplicate domains, enabled profiles,
fallback edges, malformed JSON, and catalog/registry drift fail closed. Run
`scripts/ci/check_cev1_registry_mutants_v1.sh` to replay the retained
negative-mutant set (17 cases covering object/catalog drift, exact operation
name/body/plane/authority/nonce/status mapping, activation, profile
enablement, and duplicate JSON keys).
