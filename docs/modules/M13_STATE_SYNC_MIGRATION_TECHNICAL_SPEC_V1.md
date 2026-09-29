# M13 Validated replay, work history and bounded synchronization

Revision: invariant-driven revision2. The selected target remains `pon-nakamoto-v1`.
[Sole development plan](../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md); [precise invariant/test registry](../../config/pon/invariants-v2.json).

## Scope and ownership

Root-verified local storage replay. The4101-height fixture is not4101 real mined blocks.

This is an implementation boundary, not a claim of a complete native node or independent acceptance.

## PoN State machine

### M13.RebuildBranchState

A height beyond4096 does not alone reject a shallow-fork state reconstruction; local checkpoint contents must match stored block roots. Find verified checkpoint or genesis, follow decreasing heights, verify every delta precondition and resultant root.

**Atomic/commit boundary:** Find verified checkpoint or genesis, follow decreasing heights, verify every delta precondition and resultant root.

### M13.VerifyIncomingHistory

For each block use M02 exact parent work and M06 state validation. Work matrices/certificate remain self-contained; model retention is separate. Never interpret a local checkpoint or old proof as a new finality certificate.

**Atomic/commit boundary:** Append valid branch rows/deltas only; incomplete import not active.

## M13.NoHeightFinality

**Invariant:** A height beyond4096 does not alone reject a shallow-fork state reconstruction; local checkpoint contents must match stored block roots.

**Preconditions:** Exact installed revision2 context; current local owner and immutable task/evidence identities. Storage-only and controlled-attestation premises are explicitly labelled in their tests.

**Atomic boundary:** Find verified checkpoint or genesis, follow decreasing heights, verify every delta precondition and resultant root.

**Failure schedule:** Height4101 replay; Corrupt4096 checkpoint; Missing ancestry and cyclic records.

**Expected result:** A height beyond4096 does not alone reject a shallow-fork state reconstruction; local checkpoint contents must match stored block roots.

**Resource and retention rule:** Checkpoint every128 admitted heights;64 snapshots plus genesis; progress every256 replay records.

## Concrete regression selectors

`formal/pon-nakamoto-v1/test_invariants.py::RestartForkTests.test_storage_replay_beyond_4096_does_not_invent_finality`

These selectors identify actual test functions, not a class-name count. A binding checker cannot label a test passed; the separate exact-source command receipt must show execution and outcome.

## Module-specific threat and residual work

Pruning treated as finality, false checkpoint trust, unavailable profiles and replay memory growth.

Fallback ancestry still materializes in reference memory; native paged WAN synchronization remains to be implemented.

No assertion of independent operators, physical durability, ordinary Hepta execution or future model efficacy follows from local fixtures.

## Current source and verification

- [`formal/pon-nakamoto-v1/ledger.py`](../../formal/pon-nakamoto-v1/ledger.py).

Run the relevant native package and exact Python test selectors through the protocol CI lane. Preserve source hashes, failures, backend, filesystem and process/host scope. Historical evidence is never relabelled as current.
