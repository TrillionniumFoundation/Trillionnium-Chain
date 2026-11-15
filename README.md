# Branch consolidation review — 2026-11-15

This package records a read-only review of the current consolidation candidate for
[TrillionniumFoundation/Trillionnium-Chain](https://github.com/TrillionniumFoundation/Trillionnium-Chain).
It is prepared for an independent audit tag. It contains evidence summaries, not
a replacement runtime tree. **This review did not merge into main, delete a branch,
change protection, update candidate code, or rerun CI.** Publishing this package
does not complete those operations.

## Source identities and inventory

| Identity | Exact revision |
|---|---|
| Candidate, [PR #847](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/847) | [3ae705ab542b6446fc9454b465407585346f9846](https://github.com/TrillionniumFoundation/Trillionnium-Chain/tree/3ae705ab542b6446fc9454b465407585346f9846) |
| main | [dd6e1c3cbeacbdc532b0679297835b3a0aac78f0](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/dd6e1c3cbeacbdc532b0679297835b3a0aac78f0) |
| Actual prospective merge | [3323b7cf6669e7142b60002c3b59480b43b693b6](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/3323b7cf6669e7142b60002c3b59480b43b693b6) |
| Candidate and prospective tree | `4c554367bbbff5a8a7183b30eb37a7e321a561cb` |

The captured inventory has **900 branch names / 884 unique tips**. Every captured
tip is already an ancestor of the candidate. All **908 names / 892 tips** in the
older disposition ledger are also retained. The separately paginated open-PR
inventory has **571 PRs**: 560 Draft, 80 targeting main, and 491 stacked on other
branches. These are different inventories; neither count is a count of
independent implementations. The observations are sequential, not an atomic
repository snapshot.

The existing annotated archive tag
`archive/all-branches-20261115-3ae705ab542b` has tag-object SHA
`8fb3933b8bc7fa4dcd5e869976ca89e742aaf0e0` and actual target
[`3ddbb41afb3212f121d51f5f298ad17739ea5e9d`](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/3ddbb41afb3212f121d51f5f298ad17739ea5e9d).
Its archive target preserves the current and historical inventories.
The annotation's canonical name/SHA/protection map matches the captured 900-name
map, digest `95c464e8a2ff075f41649682860ca53b8e834259d33e6a433431208d9c668f69`.
Its name must not be mistaken for its target commit.

## Required checks on the actual source

[Run 43701564881, attempt 1](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/43701564881)
is complete. The **10 head/prospective required-context records comprise eight
successes and two failures**. Adding the four required Rust runtime/quality shards
gives **14 job/source proofs: 12 successes and two failures**.

| Context | Head job / result | Prospective job / result |
|---|---|---|
| repository-truth | [132773973038](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/43701564881/job/132773973038), success | [132773973095](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/43701564881/job/132773973095), success |
| protocol-contract | [132773972962](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/43701564881/job/132773972962), **failure** | [132773972987](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/43701564881/job/132773972987), **failure** |
| fuzz-smoke | [132773972975](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/43701564881/job/132773972975), success | [132773973119](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/43701564881/job/132773973119), success |
| external-evidence-contract | [132773972993](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/43701564881/job/132773972993), success | [132773972998](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/43701564881/job/132773972998), success |
| rust-baseline | [132813899786](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/43701564881/job/132813899786), success | [132813989302](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/43701564881/job/132813989302), success |

The original artifacts behind these summaries were downloaded and checked against
GitHub SHA256 digests and ZIP CRCs. Source receipts bind the executed head or
prospective commit to the shared tree: **41,834 tracked entries / 3,999,565,648
bytes**. Rust shard before/after receipts match. The package contains the small
derived summaries; the original large ZIPs and complete job logs are not bundled.

Both protocol artifacts retain five passing named Rust selectors, followed by
the independent reader's **CONFIRMATION_TARGET** failure. Under the unchanged
**0.25 CPU / 2 GiB / zero swap / 256 PIDs / four-second / 16-worker** service
contract, both pressure phases have seven Submit ACKs, three successful History
network calls, and zero independently confirmed transactions. Their third
independent replay fails **PUBLIC_REQUEST_DEADLINE**, ending at
**4.090942159 s / 4.094630986 s**. Baseline confirms at
**1.816779085 s / 2.774600778 s**. Timing summaries preserve nested CPU/wall
observations; they do not identify a complete causal explanation or authorize
adding overlapping spans.

## ARM64 regression and review state

The separate [ARM64 PQ job 132773623120](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/43701564916/job/132773623120)
runs the original full Node library with all features and one test thread.
Its actual result is **1,631 passed / two failed / 42 ignored, exit 101**:

- `guarded_npq6_submit_recovers_after_invalid_signature_and_independent_process_restart`:
  the first valid Submit after the negative-signature control returns
  ConnectionReset. Worker and child cleanup succeed, but the diagnostic stream
  has reached its process-wide limit; the internal rejection phase is unknown.
- `real_current_resource_cas_stages_preserve_order_deadlines_and_failure_latching`:
  actual `PQ_WITNESS_DEADLINE` precedes the intended `LOST_CAS_REPLY` injection.
  The failing assertion occurs before its event snapshot is printed.

The [exact test source](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/3ae705ab542b6446fc9454b465407585346f9846/trillionnium/crates/trnm-pon-node/src/store/pq_rollback_witness/combined_tests.rs)
retains the 250 ms Witness exchange bound. These are real current-source
failures, separate from the successful protected Rust contexts.

PR #847 has no observed review submissions or unresolved inline review threads.
Both main and `fix/chain-bulk-state-tree-20261017` remain protected. The GitHub
plugin's detailed protection GETs returned **403 Resource not accessible by
integration**. A subsequent, separately authorized read-only administrator
channel authenticated as **ProfHepta** successfully returned both current
protection objects; its original projected readback is included separately.

Current main protection requires the five checks above from app **15368**, with
**strict=true**, **required_linear_history=true**, and
**required_conversation_resolution=true**. Both main and the legacy branch have
**allow_deletions=false** and **allow_force_pushes=false**. Both also report
**enforce_admins=false**; that enforcement setting does not authorize an
administrator bypass. The administrator readback independently confirms that
PR #847 remains open, unmerged, and blocked on the same head/base identities.

## Semantic scope and next steps

The [existing consolidation audit](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/3ae705ab542b6446fc9454b465407585346f9846/docs/development/BRANCH_CONSOLIDATION_AUDIT_20261114.md)
has **296 terminal dispositions** and no unclassified historical branch names.
This review checked reference coverage, reachability, archived maps, existing
dispositions, current CI, original failure evidence, and relevant failure paths.
It does **not** claim a new line-by-line review of every historical source body,
execution of every original test, whole-branch behavioral equivalence, or
production/security qualification. Historical alternatives remain preserved
under their explicit dispositions.

The next implementation work must genuinely repair the original Host protocol
gate and investigate the ARM64 failures, retaining the original deadlines,
resources and assertions. The final candidate then needs passing protected
head/prospective checks and a normal permitted integration. Before cleanup,
verify the archive, merged main tree, and fresh exact branch tips; resolve
protected deletion through repository governance. Only an actual final
single-main branch inventory establishes completion. **Main merge and branch
deletion remain unperformed by this review.**

## Package contents

- `branches-initial.json`: captured 900-name branch/SHA/protection inventory.
- `ancestry-summary.json`: current and historical ancestry, archive, and ledger checks.
- `current-protocol-evidence-summary.json`: original protocol outcomes and source bindings.
- `protocol-timing-summary.json`: selected original phase, CPU reservation, and checkpoint timings.
- `required-lane-source-summary.json`: twelve successful lane artifact/source receipts.
- `pr847-live-gates.json`: current checks, reviews, protection summaries and access errors.
- `admin-protection-readback.jsonl`: subsequent authorized administrator reads of both protection objects and PR #847, retaining the earlier plugin access errors separately.
- `manifest.json`: SHA256 and byte count of each payload file; it excludes itself.

All seven JSON/JSONL evidence files are byte-for-byte copies of this review's local
results. Private machine paths, complete PR bodies, credentials, and large ZIP
archives are excluded. This package has no publication receipt; its future tag
and commit must be confirmed separately.

