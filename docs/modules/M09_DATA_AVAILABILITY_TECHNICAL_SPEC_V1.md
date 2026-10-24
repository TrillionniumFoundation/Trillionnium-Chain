# M09 Artifact content identity, retention and readback

Revision: invariant-driven revision3. Selected target: `pon-nakamoto-v1`.
[Sole development plan](../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md); [exact invariant registry](../../config/pon/invariants-v2.json).

## Scope and ownership

The existing model loader remains scoped to its bounded integer family. The
separate [configured-peer cell byte pilot](../protocol/pon-nakamoto-v1/details/CELL_P2P_V1.md)
can retrieve opaque, content-addressed cells for the existing loader owners;
transport success does not qualify arbitrary neural model hosting.

The claims below apply to their named component and tests, not to an independently accepted full native node.

## PoN State machine

### M09.ValidateArtifact

Read at most65537 bytes; require <=65536 and canonical JSON byte identity, exact fields/shapes/ranges/feature/family. Hash bytes, never mutable path names. No executable object format.

That remains the bounded integer-model loader contract. The separate native
`CellManifestV1::decode` / `CellStoreV1::verify_complete` route validates opaque
cell bytes against the caller-pinned TCM1 manifest, all five dependency digests,
ordered chunk lengths/hashes and the complete payload length/hash. It does not
interpret a model format or enlarge the integer loader's acceptance boundary.

**Atomic/commit boundary:** Content-addressed artifact and manifest owned by the artifact provider.

### M09.FetchWithoutAuthor

Verify each copy hash; remove original author path during controlled test; load from a custodian and bind actual model hash to result. Remote diversified storage and long-term repair are not implied by local copies.

The native configured-peer successor uses `fetch_cell` / `serve_cells` and the
ordinary `trnm-cell` CLI. Actual TCP tests remove the origin, fetch from two
retained replicas, repair a corrupt disposable cache and resume only verified
chunks. Absolute connection deadlines, a shared total connection budget and a
shared response-byte budget bound corrupt, absent and byte-dripping peers.
Response accounting includes headers, manifests and rejected/truncated bytes;
`downloaded_bytes` remains verified newly cached payload. Byte-budget exhaustion
returns the actual received count and limit, and concurrent reads reserve bytes
before receiving them. Complete materialization uses
an owner-controlled destination and no-replace publication; byte retrieval
does not select CURRENT, execute a model or establish independent custodians.

Explicit `serve_cells_bounded` adds at most four read-only workers with no
application waiting queue. Overload counts toward the finite connection limit;
the shared actual-write budget charges partial failed responses. Worker errors
stop intake and all admitted threads are joined. The serial default remains;
these controls do not qualify public fairness or independent custody.

**Atomic/commit boundary:** Retention obligations separate from self-contained historical work certificates.

## M09.ArtifactIdentity

**Invariant:** Replacing model bytes at the same path fails the requested digest before load; malformed or executable-shaped artifacts reject.

**Scope:** Current bounded integer model family, not arbitrary neural model hosting.

**Atomic boundary:** Read at most65537 bytes, check size and expected digest, canonical JSON, family and tensor dimensions before inference.

**Failure schedule:** Change base weights; Wrong family or shape; Extra executable field; Trailing bytes and oversized input.

**Expected result:** Replacing model bytes at the same path fails the requested digest before load; malformed or executable-shaped artifacts reject.

**Resource and retention rule:** This integer loader accepts 64 KiB. The separate
TCM1 byte protocol permits at most 64 GiB and 16,384 chunks per cell, with the
smaller bound applying; each fetch also obeys its caller's finite byte and other
resource budgets. The protocol ceiling is not a local memory or storage grant.

## Concrete regression selectors

`formal/pon-nakamoto-v1/test_artifacts.py::ArtifactBindingTests.test_exact_expected_artifact_not_mutable_path`

`formal/pon-nakamoto-v1/test_artifacts.py::ArtifactBindingTests.test_shapes_fields_and_noncanonical_bytes_reject`

`formal/pon-nakamoto-v1/test_artifacts.py::ArtifactBindingTests.test_loader_size_is_bounded_before_json_decode`

`formal/pon-nakamoto-v1/test_model_contract.py::PublicModelContractTests.test_numpy_and_scalar_integer_outputs_match`

These exact functions contain executable assertions. The registry only checks binding; actual outcomes and source/input identities belong to the separate qualification report.

## Module-specific threat and residual work

Parameter substitution, hostile object formats, unavailable custodians and expired shared bases.

Physical-host copies and source-path loss are tested by a scoped campaign; geographic independence, renewal and long-retention responsibility remain unaccepted.

The existing Cell cache uses fresh TCL4/schema4 with mandatory immutable finite
logical-byte/chunk-row/manifest-row limits and a main-DB image/file-length cap.
Every writer reapplies and reads back the persisted cap at fixed 4096-byte pages;
old TCL1/TCL2/TCL3, wrong pages, oversized images and tails fail closed without migration. All ordinary puts and corrupt-cache
deletes share atomic persisted accounting; exact cold reopen checks full schema
and actual bounded occupancy. This PN3/PN4 cache allowance is independent of I05
paid retention, native funding and the 4096 retained obligation identities.
Supported writers now share a zero-WAL admission gate across processes: complete
TRUNCATE before mutation, disabled dirty-page spill, unchanged FULL sync and one
bounded original transaction. A long reader causes pre-write refusal; the same
batch retries after release. WAL and SHM file lengths have separate derived caps
from the immutable main-image cap, including FULL sector padding. The frozen TCL3
449112-byte WAL counterexample remains a historical control. Allocated-block
reservation, new-cache rollback journal, memory/temp/output peaks and global I05
funding remain open; these file-length caps are not total-disk quotas. See the existing
[Cell contract](../protocol/pon-nakamoto-v1/details/CELL_P2P_V1.md).

## Current source and verification

- [`formal/pon-nakamoto-v1/model_contract.py`](../../formal/pon-nakamoto-v1/model_contract.py).
- [`formal/pon-nakamoto-v1/experiments/model_loop.py`](../../formal/pon-nakamoto-v1/experiments/model_loop.py).
- [`trnm-data-availability::cell`](../../trillionnium/crates/trnm-data-availability/src/cell.rs)
  owns a separate manifest/chunk cache, bounded TCP retrieval, no-replace
  materialization and ordinary corrupt-cache repair. Its
  [`trnm-cell` CLI](../../trillionnium/crates/trnm-data-availability/src/bin/trnm-cell.rs)
  has no release, CURRENT, consensus or FinalUse authority.

No test binding or local campaign grants independent acceptance, ordinary Hepta execution or production activation. Preserve the exact source, profile and environment of every outcome.

## Executed evidence and scope

[Responsibility-level evidence navigation](README.md#responsibility-and-evidence) reads
measured commits from immutable receipts. The module's entries in
[module-maturity-v1.json](../../config/pon/module-maturity-v1.json) identify actual callable
owners, controlled entrypoints, backends, persistence and exact observed test selectors.
Run `python3 scripts/ci/report_module_evidence.py --module M09` from the repository
root to see subject-byte and complete recorded-runtime matches separately, plus scenarios
not observed in each package. A byte match is not a new test run or product acceptance.
Historical v1/v3/v4 results are never repinned. The sole plan selects further work.
