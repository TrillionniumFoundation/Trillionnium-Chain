# M05 Admission, nonce and branch-aware lifecycle

Revision: invariant-driven revision2. The selected target remains `pon-nakamoto-v1`.
[Sole development plan](../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md); [precise invariant/test registry](../../config/pon/invariants-v2.json).

## Scope and ownership

Signed transactions in native M06 execution; mempool product wiring remains distinct.

This is an implementation boundary, not a claim of a complete native node or independent acceptance.

## PoN State machine

### M05.ValidateTransaction

Require exact network, signature, nonce=current+1, height<=expiry and sufficient fee/funds before applying command. Invalid input leaves the original parent unchanged; decoded bytes are not reserved balance.

**Atomic/commit boundary:** M06 returns a new state; only M07 can commit it.

### M05.ReconsiderAfterReorg

Invalidate branch-relative inclusion; rerun nonce/grant/funds checks against new state. Never replay an irreversible operation because chain nonce vanished. Native mempool event wiring remains integration work.

**Atomic/commit boundary:** Persistent local effect tombstones stay outside chain undo.

## M05.CanonicalNonce

**Invariant:** Actual disjoint senders avoid false conflicts; hot-sender transactions retry at most once against canonical preceding state.

**Preconditions:** Exact installed revision2 context; current local owner and immutable task/evidence identities. Storage-only and controlled-attestation premises are explicitly labelled in their tests.

**Atomic boundary:** Validate exact key reads and prefix-scan results immediately before canonical patch commit.

**Failure schedule:** Sixteen ordered same-sender nonces; Independent sender and recipient pairs; Speculation sees insufficient preceding funds.

**Expected result:** Actual disjoint senders avoid false conflicts; hot-sender transactions retry at most once against canonical preceding state.

**Resource and retention rule:** Retries at most transaction count; inflight at most configured workers.

## Concrete regression selectors

`formal/pon-nakamoto-v1/test_native_execution.py::NativeExecutionTests.test_hot_sender_degrades_to_serial_without_speculation`

`formal/pon-nakamoto-v1/test_native_execution.py::NativeExecutionTests.test_independent_senders_commit_without_false_conflicts`

These selectors identify actual test functions, not a class-name count. A binding checker cannot label a test passed; the separate exact-source command receipt must show execution and outcome.

## Module-specific threat and residual work

Nonce contention, stale reservations, replay after reorg and hidden shared sponsor keys.

Future-nonce parking, replacement policy and mempool reorg events still require native host integration.

No assertion of independent operators, physical durability, ordinary Hepta execution or future model efficacy follows from local fixtures.

## Current source and verification

- [`trillionnium/crates/trnm-mvcc-fee/src/pon_executor.rs`](../../trillionnium/crates/trnm-mvcc-fee/src/pon_executor.rs).

Run the relevant native package and exact Python test selectors through the protocol CI lane. Preserve source hashes, failures, backend, filesystem and process/host scope. Historical evidence is never relabelled as current.

Additional exact regression: `formal/pon-nakamoto-v1/test_native_execution.py::NativeExecutionTests.test_hot_recipient_conflict_reexecutes_once_in_canonical_order`. Identical senders take a serial lane before speculation; distinct senders sharing one recipient still exercise bounded canonical re-execution.
