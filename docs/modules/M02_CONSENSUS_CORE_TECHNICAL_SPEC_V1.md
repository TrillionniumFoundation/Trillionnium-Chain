# M02 Work-validated block admission and fork decisions

Revision: invariant-driven revision3. Selected target: `pon-nakamoto-v1`.
[Sole development plan](../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md); [exact invariant registry](../../config/pon/invariants-v2.json).

## Scope and ownership

Native development target/work/admission and branch decisions in trnm-pon-node, with a separate reference Ledger oracle. Authenticated public consensus service remains incomplete.

The claims below apply to their named component and tests, not to an independently accepted full native node.

## PoN State machine

### M02.AdmitBlock

Resolve parent, exact height/target/median/profile and parent-admitted task; verify real work and all signatures; execute and compare state/receipt/tx roots; derive required work; persist only complete valid block.

PNW1 verification recomputes the entire transcript before comparing its submitted final digest; a digest mismatch returns `Transcript` before product corrections, while a matching digest still requires both corrections and the exact product check. This preserves proof bytes and rejection order and does not qualify adversarial ingress cost or public work hardness.

**Atomic/commit boundary:** Single block+deltas transaction owned by M07; no partial accepted header.

### M02.ChooseBranch

A persisted valid higher-work block is selected after restart even if activation intent was never written. Finish existing reorg intent, inspect indexed fully verified tips, then publish strictly heavier state.

**Atomic/commit boundary:** Finish existing reorg intent, inspect indexed fully verified tips, then publish strictly heavier state.

## M02.RecoveredBestChain

**Invariant:** A persisted valid higher-work block is selected after restart even if activation intent was never written.

**Scope:** Native development target/work/admission and branch decisions in trnm-pon-node, with a separate reference Ledger oracle. Authenticated public consensus service remains incomplete.

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

- [`trillionnium/crates/trnm-pon-node/src/consensus.rs`](../../trillionnium/crates/trnm-pon-node/src/consensus.rs).
- [`trillionnium/crates/trnm-pon-node/src/store.rs`](../../trillionnium/crates/trnm-pon-node/src/store.rs).
- [`formal/pon-nakamoto-v1/ledger.py`](../../formal/pon-nakamoto-v1/ledger.py).

No test binding or local campaign grants independent acceptance, ordinary Hepta execution or production activation. Preserve the exact source, profile and environment of every outcome.

## Executed evidence and scope

[Responsibility-level evidence navigation](README.md#responsibility-and-evidence) reads
measured commits from immutable receipts. The module's entries in
[module-maturity-v1.json](../../config/pon/module-maturity-v1.json) identify actual callable
owners, controlled entrypoints, backends, persistence and exact observed test selectors.
Run `python3 scripts/ci/report_module_evidence.py --module M02` from the repository
root to see subject-byte and complete recorded-runtime matches separately, plus scenarios
not observed in each package. A byte match is not a new test run or product acceptance.
Historical v1/v3/v4 results are never repinned. The sole plan selects further work.

## Native development continuation and remaining scope

Native required-target, 512-bit chainwork, full-block admission and heavier-branch decisions now execute in trnm-pon-node consensus/store. Native retarget regression compares a lower-height higher-work branch against a taller branch. Public work hardness and network assumptions remain unqualified.

The current callable mappings remain in `config/pon/module-maturity-v1.json`.
Exact native entry, storage and work behavior is specified by N3 in NETWORK_CLIENT,
the native continuation in STATE_RECOVERY and the prepared-producer section in WORK_PROFILE.
No historical receipt is relabelled as executing this source.
