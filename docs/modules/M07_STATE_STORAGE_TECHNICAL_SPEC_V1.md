# M07 Branch roots, schema and owner-controlled persistence

Revision: invariant-driven revision2. The selected target remains `pon-nakamoto-v1`.
[Sole development plan](../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md); [precise invariant/test registry](../../config/pon/invariants-v2.json).

## Scope and ownership

Fresh revision2 SQLite namespace, not an in-place historical database upgrade.

This is an implementation boundary, not a claim of a complete native node or independent acceptance.

## PoN State machine

### M07.OpenNamespace

Every owned initialization crash cut can recover; foreign incomplete databases and injected schema objects reject without writable mutation. Fsync exact initialization intent, create schema plus genesis in one transaction, remove marker after commit; compare exact schema projection on reopen.

**Atomic/commit boundary:** Fsync exact initialization intent, create schema plus genesis in one transaction, remove marker after commit; compare exact schema projection on reopen.

### M07.StageBranch

BEGIN IMMEDIATE, insert immutable block, insert changed-key deltas, COMMIT. Any failure rolls back the transaction. A restart reads complete old/new state, not partially visible rows.

**Atomic/commit boundary:** blocks+deltas one transaction; active pointer separate M08 publication.

## M07.OwnedInitialization

**Invariant:** Every owned initialization crash cut can recover; foreign incomplete databases and injected schema objects reject without writable mutation.

**Preconditions:** Exact installed revision2 context; current local owner and immutable task/evidence identities. Storage-only and controlled-attestation premises are explicitly labelled in their tests.

**Atomic boundary:** Fsync exact initialization intent, create schema plus genesis in one transaction, remove marker after commit; compare exact schema projection on reopen.

**Failure schedule:** Intent persisted; Schema staged; Before initialization commit; After commit before marker removal; Unexpected trigger and unmarked empty database.

**Expected result:** Every owned initialization crash cut can recover; foreign incomplete databases and injected schema objects reject without writable mutation.

**Resource and retention rule:** Ordinary append writes only changed keys; one physical state slot, separate logical generation.

## Concrete regression selectors

`formal/pon-nakamoto-v1/test_invariants.py::InitializationTests.test_every_initialization_cut_recovers_only_our_exact_intent`

`formal/pon-nakamoto-v1/test_invariants.py::InitializationTests.test_unmarked_empty_database_is_not_reinitialized`

`formal/pon-nakamoto-v1/test_invariants.py::InitializationTests.test_injected_trigger_rejects_before_writable_open`

`formal/pon-nakamoto-v1/test_invariants.py::RestartForkTests.test_append_retains_one_physical_state_slot`

These selectors identify actual test functions, not a class-name count. A binding checker cannot label a test passed; the separate exact-source command receipt must show execution and outcome.

## Module-specific threat and residual work

Initialization gaps, trigger/schema substitution, disk full, path replacement and unbounded full-state copies.

Full descriptor/sidecar fencing, incremental authenticated native state tree and physical power-loss tests remain pending.

No assertion of independent operators, physical durability, ordinary Hepta execution or future model efficacy follows from local fixtures.

## Current source and verification

- [`formal/pon-nakamoto-v1/ledger.py`](../../formal/pon-nakamoto-v1/ledger.py).

Run the relevant native package and exact Python test selectors through the protocol CI lane. Preserve source hashes, failures, backend, filesystem and process/host scope. Historical evidence is never relabelled as current.
