# M08 Generation-atomic reorg and coherent confirmation

Revision: invariant-driven revision3. Selected target: `pon-nakamoto-v1`.
[Sole development plan](../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md); [exact invariant registry](../../config/pon/invariants-v2.json).

## Scope and ownership

Reference disk SQLite; process crash is not physical power-loss evidence.

The claims below apply to their named component and tests, not to an independently accepted full native node.

## PoN State machine

### M08.PlanReorg

All eight reorg process-crash cuts recover the same root and one event set while irreversible local records survive. Each delta and cursor commit together; final active slot, logical generation, events and old-slot retirement publish atomically.

**Atomic/commit boundary:** Each delta and cursor commit together; final active slot, logical generation, events and old-slot retirement publish atomically.

### M08.RecoverAndPublish

All eight reorg process-crash cuts recover the same root and one event set while irreversible local records survive. Each delta and cursor commit together; final active slot, logical generation, events and old-slot retirement publish atomically.

**Atomic/commit boundary:** Each delta and cursor commit together; final active slot, logical generation, events and old-slot retirement publish atomically.

## M08.ReorgAtomicView

**Invariant:** All eight reorg process-crash cuts recover the same root and one event set while irreversible local records survive.

**Scope:** Reference disk SQLite; process crash is not physical power-loss evidence.

**Atomic boundary:** Each delta and cursor commit together; final active slot, logical generation, events and old-slot retirement publish atomically.

**Failure schedule:** Intent; Two detaches; Three attaches; Before publish; After publish; Repeated recovery.

**Expected result:** All eight reorg process-crash cuts recover the same root and one event set while irreversible local records survive.

**Resource and retention rule:** Ordinary append avoids full copies; real forks use a staging slot; readers retain SQLite transaction snapshots.

## Concrete regression selectors

`formal/pon-nakamoto-v1/test_contracts.py::DiskReorgTests.test_every_reorg_process_crash_cut_recovers_exactly`

These exact functions contain executable assertions. The registry only checks binding; actual outcomes and source/input identities belong to the separate qualification report.

## Module-specific threat and residual work

Mixed generations, wrong undo values, duplicated notifications and erasing external effects.

Remote target compensation and long-running native node recovery are separate obligations.

## Current source and verification

- [`formal/pon-nakamoto-v1/ledger.py`](../../formal/pon-nakamoto-v1/ledger.py).

No test binding or local campaign grants independent acceptance, ordinary Hepta execution or production activation. Preserve the exact source, profile and environment of every outcome.

## Executed evidence and scope

The [current measured package](../../evidence/pon-v3/README.md) includes exact source,
raw command exits and concrete invariant test results. Its verifier distinguishes
runtime byte identity from documentation edits and cannot grant independent acceptance.
Module-specific limitations above remain in force even when the referenced local test
passes. The development plan, not this link or a count of procedures, selects next work.
