# M02 Work-validated block admission and fork decisions

Revision: invariant-driven revision3. Selected target: `pon-nakamoto-v1`.
[Sole development plan](../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md); [exact invariant registry](../../config/pon/invariants-v2.json).

## Scope and ownership

Existing reference Ledger; native consensus actor remains separate work.

The claims below apply to their named component and tests, not to an independently accepted full native node.

## PoN State machine

### M02.AdmitBlock

Resolve parent, exact height/target/median/profile and parent-admitted task; verify real work and all signatures; execute and compare state/receipt/tx roots; derive required work; persist only complete valid block.

**Atomic/commit boundary:** Single block+deltas transaction owned by M07; no partial accepted header.

### M02.ChooseBranch

A persisted valid higher-work block is selected after restart even if activation intent was never written. Finish existing reorg intent, inspect indexed fully verified tips, then publish strictly heavier state.

**Atomic/commit boundary:** Finish existing reorg intent, inspect indexed fully verified tips, then publish strictly heavier state.

## M02.RecoveredBestChain

**Invariant:** A persisted valid higher-work block is selected after restart even if activation intent was never written.

**Scope:** Existing reference Ledger; native consensus actor remains separate work.

**Atomic boundary:** Finish existing reorg intent, inspect indexed fully verified tips, then publish strictly heavier state.

**Failure schedule:** Close after admit before activate; Repeat recover with no new input; 257 short envelopes before any work/root replay; Exact verified retransmission; Same block id with changed certificate body.

**Expected result:** A persisted valid higher-work block is selected after restart even if activation intent was never written.

**Resource and retention rule:** 512-bit derived chainwork; same work retains current tip.

## Concrete regression selectors

`formal/pon-nakamoto-v1/test_invariants.py::RestartForkTests.test_admitted_before_activation_is_selected_on_restart`

`formal/pon-nakamoto-v1/test_invariants.py::CheapAdmissionTests.test_transaction_count_rejects_before_root_or_work_replay`

`formal/pon-nakamoto-v1/test_invariants.py::DuplicateAdmissionTests.test_exact_verified_duplicate_does_not_repeat_expensive_work`

`formal/pon-nakamoto-v1/test_invariants.py::DuplicateAdmissionTests.test_same_block_id_with_changed_certificate_never_uses_valid_cache`

These exact functions contain executable assertions. The registry only checks binding; actual outcomes and source/input identities belong to the separate qualification report.

## Module-specific threat and residual work

Admission-to-activation gaps, fabricated chainwork, stale parent and partitioned observations.

Native P2P consensus actor, timestamp attack qualification and independently operated network are pending.

## Current source and verification

- [`formal/pon-nakamoto-v1/ledger.py`](../../formal/pon-nakamoto-v1/ledger.py).

No test binding or local campaign grants independent acceptance, ordinary Hepta execution or production activation. Preserve the exact source, profile and environment of every outcome.
