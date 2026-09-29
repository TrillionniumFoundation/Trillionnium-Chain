# M08 Generation-atomic reorg and coherent confirmation

Revision: invariant-driven revision2. The selected target remains `pon-nakamoto-v1`.
[Sole development plan](../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md); [precise invariant/test registry](../../config/pon/invariants-v2.json).

## Scope and ownership

Reference disk SQLite; process crash is not physical power-loss evidence.

This is an implementation boundary, not a claim of a complete native node or independent acceptance.

## PoN State machine

### M08.PlanReorg

All eight reorg process-crash cuts recover the same root and one event set while irreversible local records survive. Each delta and cursor commit together; final active slot, logical generation, events and old-slot retirement publish atomically.

**Atomic/commit boundary:** Each delta and cursor commit together; final active slot, logical generation, events and old-slot retirement publish atomically.

### M08.RecoverAndPublish

All eight reorg process-crash cuts recover the same root and one event set while irreversible local records survive. Each delta and cursor commit together; final active slot, logical generation, events and old-slot retirement publish atomically.

**Atomic/commit boundary:** Each delta and cursor commit together; final active slot, logical generation, events and old-slot retirement publish atomically.

## M08.ReorgAtomicView

**Invariant:** All eight reorg process-crash cuts recover the same root and one event set while irreversible local records survive.

**Preconditions:** Exact installed revision2 context; current local owner and immutable task/evidence identities. Storage-only and controlled-attestation premises are explicitly labelled in their tests.

**Atomic boundary:** Each delta and cursor commit together; final active slot, logical generation, events and old-slot retirement publish atomically.

**Failure schedule:** Intent; Two detaches; Three attaches; Before publish; After publish; Repeated recovery.

**Expected result:** All eight reorg process-crash cuts recover the same root and one event set while irreversible local records survive.

**Resource and retention rule:** Ordinary append avoids full copies; real forks use a staging slot; readers retain SQLite transaction snapshots.

## Concrete regression selectors

`formal/pon-nakamoto-v1/test_contracts.py::DiskReorgTests.test_every_reorg_process_crash_cut_recovers_exactly`

These selectors identify actual test functions, not a class-name count. A binding checker cannot label a test passed; the separate exact-source command receipt must show execution and outcome.

## Module-specific threat and residual work

Mixed generations, wrong undo values, duplicated notifications and erasing external effects.

Remote target compensation and long-running native node recovery are separate obligations.

No assertion of independent operators, physical durability, ordinary Hepta execution or future model efficacy follows from local fixtures.

## Current source and verification

- [`formal/pon-nakamoto-v1/ledger.py`](../../formal/pon-nakamoto-v1/ledger.py).

Run the relevant native package and exact Python test selectors through the protocol CI lane. Preserve source hashes, failures, backend, filesystem and process/host scope. Historical evidence is never relabelled as current.
