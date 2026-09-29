# M02 Work-validated block admission and fork decisions

Revision: invariant-driven revision2. The selected target remains `pon-nakamoto-v1`.
[Sole development plan](../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md); [precise invariant/test registry](../../config/pon/invariants-v2.json).

## Scope and ownership

Existing reference Ledger; native consensus actor remains separate work.

This is an implementation boundary, not a claim of a complete native node or independent acceptance.

## PoN State machine

### M02.AdmitBlock

Resolve parent, exact height/target/median/profile and parent-admitted task; verify real work and all signatures; execute and compare state/receipt/tx roots; derive required work; persist only complete valid block.

**Atomic/commit boundary:** Single block+deltas transaction owned by M07; no partial accepted header.

### M02.ChooseBranch

A persisted valid higher-work block is selected after restart even if activation intent was never written. Finish existing reorg intent, inspect indexed fully verified tips, then publish strictly heavier state.

**Atomic/commit boundary:** Finish existing reorg intent, inspect indexed fully verified tips, then publish strictly heavier state.

## M02.RecoveredBestChain

**Invariant:** A persisted valid higher-work block is selected after restart even if activation intent was never written.

**Preconditions:** Exact installed revision2 context; current local owner and immutable task/evidence identities. Storage-only and controlled-attestation premises are explicitly labelled in their tests.

**Atomic boundary:** Finish existing reorg intent, inspect indexed fully verified tips, then publish strictly heavier state.

**Failure schedule:** Close after admit before activate; Repeat recover with no new input.

**Expected result:** A persisted valid higher-work block is selected after restart even if activation intent was never written.

**Resource and retention rule:** 512-bit derived chainwork; same work retains current tip.

## Concrete regression selectors

`formal/pon-nakamoto-v1/test_invariants.py::RestartForkTests.test_admitted_before_activation_is_selected_on_restart`

These selectors identify actual test functions, not a class-name count. A binding checker cannot label a test passed; the separate exact-source command receipt must show execution and outcome.

## Module-specific threat and residual work

Admission-to-activation gaps, fabricated chainwork, stale parent and partitioned observations.

Native P2P consensus actor, timestamp attack qualification and independently operated network are pending.

No assertion of independent operators, physical durability, ordinary Hepta execution or future model efficacy follows from local fixtures.

## Current source and verification

- [`formal/pon-nakamoto-v1/ledger.py`](../../formal/pon-nakamoto-v1/ledger.py).

Run the relevant native package and exact Python test selectors through the protocol CI lane. Preserve source hashes, failures, backend, filesystem and process/host scope. Historical evidence is never relabelled as current.
