# M10 Contributions, immutable release and actual task lifecycle

Revision: invariant-driven revision3. Selected target: `pon-nakamoto-v1`.
[Sole development plan](../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md); [exact invariant registry](../../config/pon/invariants-v2.json).

## Scope and ownership

Signed experimental contributions and release transitions; public model value and independent evaluator trust are not inferred.

The claims below apply to their named component and tests, not to an independently accepted full native node.

## PoN State machine

### M10.SubmitContribution

Validate the signed128-block intake round, full context-bound contribution id,64-block lifetime,256 active and512 total current-round records. Current-round repeats reject; old-round signed transactions remain invalid after reclamation.

**Atomic/commit boundary:** Count active current-parent candidates; preserve same-parent duplicate keys; old-parent retirement leaves root-bound release authority intact.

### M10.PublishEvaluatedRelease

Verify bundle minimum positive score; bind exact components root, accepted leaf scores/owners and total; recompute release id; debit sponsor; record maturity and claims; only then adopt pointer. Local Hepta use still requires generation admission.

**Atomic/commit boundary:** Same state transition and block delta; reorg reverses pointer/escrow but not historical inference.

## M10.PendingNotHistory

**Invariant:** Inactive contributions cannot exhaust pending capacity forever; signed intake windows bound same-parent history, reject expired-window replay, and preserve independently rooted release claims. Published release metadata retains the exact model artifact/family/parent after candidate reclamation.

**Scope:** Signed experimental contributions and release transitions; public model value and independent evaluator trust are not inferred.

**Atomic boundary:** Revision3 signs submission_round in the fixed 176-byte contribution payload and ID; deterministic window retirement precedes transactions; claims use unchanged release-root membership.

**Failure schedule:** 257 zero-scored contributions; Same-parent duplicate after retirement; Candidate expiry; Three releases and claims with original rows removed; Fill512 zero-score historical records without an adopted model; Cross128-block window with old signed payload; Positive evaluated candidate outlives64-block expiry.

**Expected result:** Inactive contributions cannot exhaust pending capacity forever; signed intake windows bound same-parent history, reject expired-window replay, and preserve independently rooted release claims. Published release metadata retains the exact model artifact/family/parent after candidate reclamation.

**Resource and retention rule:** 256 active candidates, at most512 records per128-block window,64-block candidate lifetime; old-window signatures reject before history is recreated.

## Concrete regression selectors

`formal/pon-nakamoto-v1/test_invariants.py::CapacityTests.test_zero_score_history_does_not_consume_pending_capacity`

`formal/pon-nakamoto-v1/test_invariants.py::CapacityTests.test_expiry_releases_capacity_without_dropping_current_parent_nullifier`

`formal/pon-nakamoto-v1/test_native_execution.py::NativeExecutionTests.test_three_signed_release_generations_preserve_payout_and_retirement`

`formal/pon-nakamoto-v1/test_invariants.py::CandidateWindowTests.test_full_history_window_reopens_without_old_signed_replay`

`formal/pon-nakamoto-v1/test_invariants.py::CandidateWindowTests.test_round_is_part_of_contribution_and_signature_identity`

`formal/pon-nakamoto-v1/test_invariants.py::CandidateWindowTests.test_positive_evaluation_expires_and_cannot_be_adopted_late`

`formal/pon-nakamoto-v1/test_native_execution.py::NativeExecutionTests.test_native_round_boundary_retires_history_and_rejects_old_signature`

These exact functions contain executable assertions. The registry only checks binding; actual outcomes and source/input identities belong to the separate qualification report.

## Module-specific threat and residual work

Lifetime counters, generation-stale scores, duplicate rewards and unbounded same-parent spam.

Per-window capacity may be exhausted temporarily. Account/work-registration history, independent evaluator policy and economic Sybil fairness remain unqualified.

## Current source and verification

- [`formal/pon-nakamoto-v1/ledger.py`](../../formal/pon-nakamoto-v1/ledger.py).
- [`trillionnium/crates/trnm-mvcc-fee/src/pon_executor.rs`](../../trillionnium/crates/trnm-mvcc-fee/src/pon_executor.rs).

No test binding or local campaign grants independent acceptance, ordinary Hepta execution or production activation. Preserve the exact source, profile and environment of every outcome.
