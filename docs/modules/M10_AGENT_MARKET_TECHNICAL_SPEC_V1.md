# M10 Contributions, immutable release and actual task lifecycle

Revision: invariant-driven revision2. The selected target remains `pon-nakamoto-v1`.
[Sole development plan](../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md); [precise invariant/test registry](../../config/pon/invariants-v2.json).

## Scope and ownership

Signed controlled development contributions and release transitions, not three measured learning improvements.

This is an implementation boundary, not a claim of a complete native node or independent acceptance.

## PoN State machine

### M10.SubmitContribution

Zero-score history no longer blocks all256 pending slots, and three successor releases can retire old candidates without losing valid claims. Count active current-parent candidates; preserve same-parent duplicate keys; old-parent retirement leaves root-bound release authority intact.

**Atomic/commit boundary:** Count active current-parent candidates; preserve same-parent duplicate keys; old-parent retirement leaves root-bound release authority intact.

### M10.PublishEvaluatedRelease

Verify bundle minimum positive score; bind exact components root, accepted leaf scores/owners and total; recompute release id; debit sponsor; record maturity and claims; only then adopt pointer. Local Hepta use still requires generation admission.

**Atomic/commit boundary:** Same state transition and block delta; reorg reverses pointer/escrow but not historical inference.

## M10.PendingNotHistory

**Invariant:** Zero-score history no longer blocks all256 pending slots, and three successor releases can retire old candidates without losing valid claims.

**Preconditions:** Exact installed revision2 context; current local owner and immutable task/evidence identities. Storage-only and controlled-attestation premises are explicitly labelled in their tests.

**Atomic boundary:** Count active current-parent candidates; preserve same-parent duplicate keys; old-parent retirement leaves root-bound release authority intact.

**Failure schedule:** 257 zero-scored contributions; Same-parent duplicate after retirement; Candidate expiry; Three releases and claims with original rows removed.

**Expected result:** Zero-score history no longer blocks all256 pending slots, and three successor releases can retire old candidates without losing valid claims.

**Resource and retention rule:** Active capacity256; candidate lifetime1000; current-parent tombstones still subject to global state capacity.

## Concrete regression selectors

`formal/pon-nakamoto-v1/test_invariants.py::CapacityTests.test_zero_score_history_does_not_consume_pending_capacity`

`formal/pon-nakamoto-v1/test_invariants.py::CapacityTests.test_expiry_releases_capacity_without_dropping_current_parent_nullifier`

`formal/pon-nakamoto-v1/test_native_execution.py::NativeExecutionTests.test_three_signed_release_generations_preserve_payout_and_retirement`

These selectors identify actual test functions, not a class-name count. A binding checker cannot label a test passed; the separate exact-source command receipt must show execution and outcome.

## Module-specific threat and residual work

Lifetime counters, generation-stale scores, duplicate rewards and unbounded same-parent spam.

Full historical compaction and economic anti-spam policy are not declared solved.

No assertion of independent operators, physical durability, ordinary Hepta execution or future model efficacy follows from local fixtures.

## Current source and verification

- [`formal/pon-nakamoto-v1/ledger.py`](../../formal/pon-nakamoto-v1/ledger.py).
- [`trillionnium/crates/trnm-mvcc-fee/src/pon_executor.rs`](../../trillionnium/crates/trnm-mvcc-fee/src/pon_executor.rs).

Run the relevant native package and exact Python test selectors through the protocol CI lane. Preserve source hashes, failures, backend, filesystem and process/host scope. Historical evidence is never relabelled as current.
