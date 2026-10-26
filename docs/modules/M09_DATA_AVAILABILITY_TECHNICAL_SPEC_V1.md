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

PN3's optional `smollm-signed-read-v1` handoff profile exports the same eleven
TCM1 objects and TCR1 release with a separate bounded declaration. The Hepta
consumer owns model interpretation and must independently reconstruct every
original manifest from received bytes before using its existing signed native
owner. M09 supplies no selected CURRENT or installation authority. The default
handoff refusal and original 35-second transfer/readback deadline remain;
complete native loading and I10 acceptance are still required.

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

### PN3/PN4/PN5 interface and acceptance obligations

These are target obligations inside the existing PN0–PN6 plan and I05/I09/I10
interfaces. The current TCM1/TCR1 byte path, TCL4 cache, development rendezvous
and v1 single-manifest retention contract remain their separate implemented
components; none already implements a complete neural release-closure codec.

| Existing stage / owner seam | Required implementation and exit |
| --- | --- |
| PN3 / M10 -> M09 -> Hepta loader -> M17 | Version the complete closure and finite `ResolveReleaseRequest/Result`; bind family/base/tokenizer/layout/shape/dtype/quantization/runtime/router, mandatory Cells/dependencies and selected generation. Reject cycles, absent mandatory bytes and incompatible loaders. Each adopted round requires verified cross-node retrieval, safe installation and next-task loaded-hash readback; no-update reads back the retained parent. The three-round mechanical loop still needs a separate successful cross-node I09/I10 installation cohort including origin loss. |
| PN4 / M09 <-> M12 | Version release-wide funded duty, byte-time tariff, renewal/repair reservation and unknown-effect reconciliation. Reserve physical capacity before ACK; retain original effect/payment fences across restart/reorg. Cache completion is no duty or payment receipt. |
| PN5 / M09/M14 -> M17 | Qualify finite discovery, independent replicas, shared-budget repair and complete-release service during the at-least-72-hour WAN campaign. Initial target is three independent complete replicas; all promised releases must meet the frozen threshold and deadlines. |

The exact target messages, errors and codec compatibility rules live in the
[Cell interface](../protocol/pon-nakamoto-v1/details/CELL_P2P_V1.md#pn3-release-closure-and-real-loader-interface),
[discovery seam](../development/specs/pon/CELL_PROVIDER_DISCOVERY_DEV_V1.md#pn5-extension-seam--target-not-the-dev-v1-codec)
and [retention duty](../development/specs/pon/CELL_RETENTION_V1.md#pn4pn5-release-wide-duty-interface--target).
Implement canonical vectors and negative cross-version refusal before plumbing
the loader or network adapter. Unknown publication/repair outcomes permit only
exact-target reconciliation; retries do not reset reservation or authorization.

Freeze workload/source/profile, numeric latency/resource/sample thresholds and
failure matrix before measurement. Report verified MB/s, complete-release
availability, cold/warm loader latency, repair debt and unique confirmed chain
TPS separately. Compare persistent connections, bounded rare-piece scheduling,
BT v2/DHT or erasure coding only against the same workload and original budgets;
they remain reviewed options until selected, implemented and qualified. GC must
preserve all lease/reorg/rollback roots and shared dependencies. Model integrity,
availability, quality and local installation remain four independently checked
claims, with failed cohorts preserved under their actual source identities.

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
