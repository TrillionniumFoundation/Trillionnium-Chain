# M09 Artifact content identity, retention and readback

Revision: invariant-driven revision3. Selected target: `pon-nakamoto-v1`.
[Sole development plan](../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md); [exact invariant registry](../../config/pon/invariants-v2.json).

## Scope and ownership

Current bounded integer model family, not arbitrary neural model hosting.

The claims below apply to their named component and tests, not to an independently accepted full native node.

## PoN State machine

### M09.ValidateArtifact

Read at most65537 bytes; require <=65536 and canonical JSON byte identity, exact fields/shapes/ranges/feature/family. Hash bytes, never mutable path names. No executable object format.

**Atomic/commit boundary:** Content-addressed artifact and manifest owned by the artifact provider.

### M09.FetchWithoutAuthor

Verify each copy hash; remove original author path during controlled test; load from a custodian and bind actual model hash to result. Remote diversified storage and long-term repair are not implied by local copies.

**Atomic/commit boundary:** Retention obligations separate from self-contained historical work certificates.

## M09.ArtifactIdentity

**Invariant:** Replacing model bytes at the same path fails the requested digest before load; malformed or executable-shaped artifacts reject.

**Scope:** Current bounded integer model family, not arbitrary neural model hosting.

**Atomic boundary:** Read at most65537 bytes, check size and expected digest, canonical JSON, family and tensor dimensions before inference.

**Failure schedule:** Change base weights; Wrong family or shape; Extra executable field; Trailing bytes and oversized input.

**Expected result:** Replacing model bytes at the same path fails the requested digest before load; malformed or executable-shaped artifacts reject.

**Resource and retention rule:** This loader accepts64KiB, distinct from the generic64MiB transport target.

## Concrete regression selectors

`formal/pon-nakamoto-v1/test_artifacts.py::ArtifactBindingTests.test_exact_expected_artifact_not_mutable_path`

`formal/pon-nakamoto-v1/test_artifacts.py::ArtifactBindingTests.test_shapes_fields_and_noncanonical_bytes_reject`

`formal/pon-nakamoto-v1/test_artifacts.py::ArtifactBindingTests.test_loader_size_is_bounded_before_json_decode`

`formal/pon-nakamoto-v1/test_model_contract.py::PublicModelContractTests.test_numpy_and_scalar_integer_outputs_match`

These exact functions contain executable assertions. The registry only checks binding; actual outcomes and source/input identities belong to the separate qualification report.

## Module-specific threat and residual work

Parameter substitution, hostile object formats, unavailable custodians and expired shared bases.

Physical-host copies and source-path loss are tested by a scoped campaign; geographic independence, renewal and long-retention responsibility remain unaccepted.

## Current source and verification

- [`formal/pon-nakamoto-v1/model_contract.py`](../../formal/pon-nakamoto-v1/model_contract.py).
- [`formal/pon-nakamoto-v1/experiments/model_loop.py`](../../formal/pon-nakamoto-v1/experiments/model_loop.py).

No test binding or local campaign grants independent acceptance, ordinary Hepta execution or production activation. Preserve the exact source, profile and environment of every outcome.
