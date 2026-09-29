# M09 Artifact content identity, retention and readback

Revision: invariant-driven revision2. The selected target remains `pon-nakamoto-v1`.
[Sole development plan](../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md); [precise invariant/test registry](../../config/pon/invariants-v2.json).

## Scope and ownership

Current bounded integer model family, not arbitrary neural model hosting.

This is an implementation boundary, not a claim of a complete native node or independent acceptance.

## PoN State machine

### M09.ValidateArtifact

Read at most65537 bytes; require <=65536 and canonical JSON byte identity, exact fields/shapes/ranges/feature/family. Hash bytes, never mutable path names. No executable object format.

**Atomic/commit boundary:** Content-addressed artifact and manifest owned by the artifact provider.

### M09.FetchWithoutAuthor

Verify each copy hash; remove original author path during controlled test; load from a custodian and bind actual model hash to result. Remote diversified storage and long-term repair are not implied by local copies.

**Atomic/commit boundary:** Retention obligations separate from self-contained historical work certificates.

## M09.ArtifactIdentity

**Invariant:** Replacing model bytes at the same path fails the requested digest before load; malformed or executable-shaped artifacts reject.

**Preconditions:** Exact installed revision2 context; current local owner and immutable task/evidence identities. Storage-only and controlled-attestation premises are explicitly labelled in their tests.

**Atomic boundary:** Read at most65537 bytes, check size and expected digest, canonical JSON, family and tensor dimensions before inference.

**Failure schedule:** Change base weights; Wrong family or shape; Extra executable field; Trailing bytes and oversized input.

**Expected result:** Replacing model bytes at the same path fails the requested digest before load; malformed or executable-shaped artifacts reject.

**Resource and retention rule:** This loader accepts64KiB, distinct from the generic64MiB transport target.

## Concrete regression selectors

`formal/pon-nakamoto-v1/test_artifacts.py::ArtifactBindingTests.test_exact_expected_artifact_not_mutable_path`

`formal/pon-nakamoto-v1/test_artifacts.py::ArtifactBindingTests.test_shapes_fields_and_noncanonical_bytes_reject`

`formal/pon-nakamoto-v1/test_artifacts.py::ArtifactBindingTests.test_loader_size_is_bounded_before_json_decode`

These selectors identify actual test functions, not a class-name count. A binding checker cannot label a test passed; the separate exact-source command receipt must show execution and outcome.

## Module-specific threat and residual work

Parameter substitution, hostile object formats, unavailable custodians and expired shared bases.

Geographic replication, repair, renewal and long-retention independence remain unexecuted.

No assertion of independent operators, physical durability, ordinary Hepta execution or future model efficacy follows from local fixtures.

## Current source and verification

- [`formal/pon-nakamoto-v1/experiments/model_loop.py`](../../formal/pon-nakamoto-v1/experiments/model_loop.py).

Run the relevant native package and exact Python test selectors through the protocol CI lane. Preserve source hashes, failures, backend, filesystem and process/host scope. Historical evidence is never relabelled as current.
