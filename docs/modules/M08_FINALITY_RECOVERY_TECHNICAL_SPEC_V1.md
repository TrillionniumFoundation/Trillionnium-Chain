# M08 Generation-atomic reorg and coherent confirmation

Revision: invariant-driven revision3. Selected target: `pon-nakamoto-v1`.
[Sole development plan](../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md); [exact invariant registry](../../config/pon/invariants-v2.json).

## Scope and ownership

Reference disk SQLite; process crash is not physical power-loss evidence.

The claims below apply to their named component and tests, not to an independently accepted full native node.

## PoN State machine

### M08.PlanReorg

**Inputs / preconditions:** Ledger exclusive owner; fully verified stored target BlockId; active(old_tip,generation,state_slot); optional crash-cut callback

**Output:** Existing tip for no strictly greater work, direct-extension publication, or committed staging intent consumed by RecoverAndPublish

**Algorithm and actual entry:** This is the planning phase inside Ledger.activate, not a separate public API. Finish an existing staging intent first and reread active state. Compare stored 512-bit work; equal/lower returns old tip without new events. A direct child with no fault callback applies deltas and publishes on the existing slot in one transaction. Otherwise walk old/new ancestry by height to the common ancestor; order detach tip-to-fork and attach fork-to-tip; copy the active slot and write old/new tips, next generation, ordered steps and cursor zero in one IMMEDIATE transaction. Never accept caller-supplied work totals or step lists.

**Atomic/commit boundary:** Direct extension: delta, active tip/generation and attach event commit atomically. Fork: staging copy plus reorg intent commit together before any detach; active pointer remains unchanged.

**Errors:** UNKNOWN_PARENT; UNDO_ROOT or ROOT on direct append; existing-intent GENERATION/SCHEMA failures; propagated SQLite/OSError. Resource exhaustion is a local failure, not consensus-invalid history.

**Retry and resource boundary:** One owner and one pending intent. Actual planning currently holds detach/attach lists and a full staging copy; bounded native planning is not implemented. No fixed depth becomes finality.

### M08.RecoverAndPublish

**Inputs / preconditions:** Ledger._recover_intent reads the persisted singleton(old_tip,new_tip,generation,steps,position,status); optional crash-cut callback

**Output:** No pending/done intent: active tip unchanged. Successful recovery: target tip with coherent generation, root and one ordered remove/add event set

**Algorithm and actual entry:** This is Ledger._recover_intent, called by activate and recover. Require active==(old_tip,generation-1). From persisted cursor, check detach/attach kind and each delta before-image, then apply that step and advance its cursor in one IMMEDIATE transaction. After all steps, recompute the staged target root. Publish active tip/generation/state_slot, events, done status and old-slot retirement in one transaction. Ledger.recover then selects any fully verified indexed strictly heavier tip; completing one intent alone is not best-chain selection.

**Atomic/commit boundary:** Every delta step and cursor commit together; final active tuple, ordered events, done flag and old-slot deletion have a separate single commit. Independent EffectJournal is never part of undo.

**Errors:** GENERATION for stale active tuple; SCHEMA for invalid step kind; UNDO_ROOT for before-image mismatch; ROOT before publication; UNKNOWN_PARENT or propagated SQLite/OSError. Do not label any failure as an executed remote effect.

**Retry and resource boundary:** Resume committed cursor after interruption; done/no intent is idempotent and creates no repeated events. On root/generation corruption retain the intent and fence new admission for diagnosis; do not auto-clear it. Full staged state/root replay and physical power-loss qualification remain open.

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

[Responsibility-level evidence navigation](README.md#responsibility-and-evidence) reads
measured commits from immutable receipts. The module's entries in
[module-maturity-v1.json](../../config/pon/module-maturity-v1.json) identify actual callable
owners, controlled entrypoints, backends, persistence and exact observed test selectors.
Run `python3 scripts/ci/report_module_evidence.py --module M08` from the repository
root to see subject-byte and complete recorded-runtime matches separately, plus scenarios
not observed in each package. A byte match is not a new test run or product acceptance.
Historical v1/v3/v4 results are never repinned. The sole plan selects further work.

## Native development continuation and remaining scope

Node::activate_with_fault plans native ordered steps; Node::resume_intent commits each step/cursor and atomic root-checked publication. Startup additionally selects admitted heavier history. Actual subprocess cuts cover initialization and reorg; no physical power cut or external-effect compensation is inferred.

The current callable mappings remain in `config/pon/module-maturity-v1.json`.
Exact native entry, storage and work behavior is specified by N3 in NETWORK_CLIENT,
the native continuation in STATE_RECOVERY and the prepared-producer section in WORK_PROFILE.
No historical receipt is relabelled as executing this source.
