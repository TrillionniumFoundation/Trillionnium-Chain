# PQ authority source-lock storage continuation

**HOLD. Seven curated interfaces; no new authority or quantum qualification.**

## Current S0 mapping

The active source lock is reviewed against immutable S0
`d9c725f27b197f71208754b0a5ac0717798d3587`, tree `a71a4ede1686baa27c1eb985472928920be41f30`.
Its predecessor is capacity head C3 `06233be630f8eff6cea59cd5111e5941135a4aa5`, tree
`d60319b2c66b274bd982f5c2830d8bd41c414f06`. All 44 paths were obtained from both Git
revisions, checked against their blob IDs, and compared with descriptor-bound
regular-file reads of S0. The previous manifest matches every C3 object.

Only `trillionnium/crates/trnm-pon-node/src/store.rs` changes in this curated
set: its final Linux-only `pub use storage_service::{...}` exposes the new
grouped V3 types, journal and owner entrypoints. No existing function body in
that file changes. Those newly exported implementations are outside the
44-path set; this mapping does not become their dependency closure, runtime
test result or security proof.

The [machine review](../../evidence/pq-authority-storage-source-review-20261109/review.json)
uses a fresh `trnm-pq-authority-storage-source-review.v2` record for C3 to S0,
with all 44 old/new Git blob IDs, byte counts and SHA-256 values and the sole
complete patch. Its `retained_prior_review` embeds the complete original v1
0f-to-C3 review, together with that original artifact's SHA-256. The earlier
[composition review](PQ_COMPOSITION_SOURCE_LOCK_REVIEW_20261108.md) remains
unchanged.

The canonical whole-table SHA-256 for S0 is:

```text
ae9f867bc033569731f77de22045cb00e31c1b9c0df6b53e01f9a6dcc026e3fc
```

The unchanged serialization is sorted compact UTF-8 JSON containing exactly
`{"source_revision": SOURCE_REVISION, "files": source_files_sha256}`.
Manifest, checker and independent literal positive assertion move together.
All eighteen original test methods remain; the existing drift control
additionally refuses C3 as stale while retaining its original 0f refusal.
The old C3 checker actually refused S0 at `store.rs` before this update.
That refusal is retained in the rebind validation archive, not rewritten.

The seven routes, their source categories and effect scopes are unchanged.
Coverage, authenticated provenance, call-graph proof, runtime reachability,
native-test execution, whole-chain PQ qualification and production activation
all remain false. The S0 code checkpoint intentionally preceded this metadata
review; exact final-source/native gates belong to the subsequent S1 candidate.
This source review supplies no new payment, custody, installation, FinalUse,
model-efficacy or production authority.

## Retained 0f-to-C3 review (historical)

The following original section is retained as the earlier review. Its C3
revision and table digest are historical; the active mapping is S0 above.

**HOLD. Seven curated interfaces; no new authority or quantum qualification.**

The capacity continuation changes one file in the existing 44-path authority
register. The previous lock correctly refuses the current source at
`trillionnium/crates/trnm-data-availability/src/cell/discovery/pq.rs`. This
review updates that curated source record without broadening its scope.

## Exact source comparison

The previous baseline is `0f0592ace4b08a1d39e1ffad31beee76ddc4fd66`, tree
`24f08f4a72a7a4be83fa8e5a664642c4e9b6feb0`. The new fixed baseline is the
published capacity head `06233be630f8eff6cea59cd5111e5941135a4aa5`, tree
`d60319b2c66b274bd982f5c2830d8bd41c414f06`. All 44 paths were retrieved at
both fixed revisions. Each content buffer was checked against its Git blob
SHA-1, and every old SHA-256 matched the previous manifest. This checks the
retrieved Git object bytes; it does not independently authenticate their origin.

The [machine review](../../evidence/pq-authority-storage-source-review-20261109/review.json)
retains each old/current blob ID, byte count and SHA-256, including the sole
changed path's complete patch. The remaining 43 curated files are byte-identical.

| Changed path | Review and continuing boundary |
| --- | --- |
| [cell/discovery/pq.rs](../../trillionnium/crates/trnm-data-availability/src/cell/discovery/pq.rs) | Adds `auth`, `epoch` and `epoch_directory` module declarations and their distinct V3 exports. The existing V2 exports, record encoding, signature domain, signing, verification, expiry and endpoint checks are unchanged. The newly exported child modules are outside this curated file set; their implementation and dependency closure do not become qualified by updating this entry-file pin. |

The seven route definitions, 44 required paths and original negative controls
are unchanged. The positive test retains its independent literal revision.
The revision-refusal control also retains the previous active revision as a
specific stale value, alongside its existing malformed/future context cases.

## Reviewed table and limits

The old canonical table digest remains in the original
[composition review](PQ_COMPOSITION_SOURCE_LOCK_REVIEW_20261108.md):

```text
4638bd340c2456dd735418f74ec27e01953432c2495b3db596f57d9fc31acb04
```

The new digest is SHA-256 of sorted compact UTF-8 JSON containing exactly
`{"source_revision": SOURCE_REVISION, "files": source_files_sha256}`:

```text
51f4b646d552b1a1a95372f954b003c82fcbc74a1c9fac78c6ed8c36be9b8ed6
```

The [register](../../config/pon/pq-authority-effects-v1.json),
[checker](../../scripts/ci/pq_authority_effect_register.py) and
[independent controls](../../scripts/ci/test_pq_authority_effect_register.py)
move together. There is no automatic refresh or fallback. The stored schema,
signed domains and route scopes do not change.

Source-consistency success remains `HOLD`: coverage, authenticated provenance,
call-graph proof, runtime reachability, native-test execution, whole-chain PQ
qualification and production activation all remain false. The discovery route
continues to describe provider-directory/content-cache effects; it grants no
payment, custody, installation or FinalUse authority. The review neither reruns
the native tests named by this register nor qualifies any research model run.
