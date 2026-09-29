# M05 Admission, nonce and branch-aware lifecycle

Revision: invariant-driven revision3. Selected target: `pon-nakamoto-v1`.
[Sole development plan](../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md); [exact invariant registry](../../config/pon/invariants-v2.json).

## Scope and ownership

Signed transactions in native M06 execution; mempool product wiring remains distinct.

The claims below apply to their named component and tests, not to an independently accepted full native node.

## PoN State machine

### M05.ValidateTransaction

Require exact network, signature, nonce=current+1, height<=expiry and sufficient fee/funds before applying command. Invalid input leaves the original parent unchanged; decoded bytes are not reserved balance.

**Atomic/commit boundary:** M06 returns a new state; only M07 can commit it.

### M05.ReconsiderAfterReorg

Invalidate branch-relative inclusion; rerun nonce/grant/funds checks against new state. Never replay an irreversible operation because chain nonce vanished. Native mempool event wiring remains integration work.

**Atomic/commit boundary:** Persistent local effect tombstones stay outside chain undo.

## M05.CanonicalNonce

**Invariant:** Actual disjoint senders avoid false conflicts; hot-sender transactions retry at most once against canonical preceding state.

**Scope:** Signed transactions in native M06 execution; mempool product wiring remains distinct.

**Atomic boundary:** Validate exact key reads and prefix-scan results immediately before canonical patch commit.

**Failure schedule:** Sixteen ordered same-sender nonces; Independent sender and recipient pairs; Speculation sees insufficient preceding funds.

**Expected result:** Actual disjoint senders avoid false conflicts; hot-sender transactions retry at most once against canonical preceding state.

**Resource and retention rule:** Retries at most transaction count; inflight at most configured workers.

## Concrete regression selectors

`formal/pon-nakamoto-v1/test_native_execution.py::NativeExecutionTests.test_hot_sender_degrades_to_serial_without_speculation`

`formal/pon-nakamoto-v1/test_native_execution.py::NativeExecutionTests.test_independent_senders_commit_without_false_conflicts`

`formal/pon-nakamoto-v1/test_native_execution.py::NativeExecutionTests.test_hot_recipient_conflict_reexecutes_once_in_canonical_order`

These exact functions contain executable assertions. The registry only checks binding; actual outcomes and source/input identities belong to the separate qualification report.

## Module-specific threat and residual work

Nonce contention, stale reservations, replay after reorg and hidden shared sponsor keys.

Future-nonce parking, replacement policy and mempool reorg events still require native host integration.

## Current source and verification

- [`trillionnium/crates/trnm-mvcc-fee/src/pon_executor.rs`](../../trillionnium/crates/trnm-mvcc-fee/src/pon_executor.rs).

No test binding or local campaign grants independent acceptance, ordinary Hepta execution or production activation. Preserve the exact source, profile and environment of every outcome.

## Executed evidence and scope

The [current measured package](../../evidence/pon-v3/README.md) includes exact source,
raw command exits and concrete invariant test results. Its verifier distinguishes
runtime byte identity from documentation edits and cannot grant independent acceptance.
Module-specific limitations above remain in force even when the referenced local test
passes. The development plan, not this link or a count of procedures, selects next work.
