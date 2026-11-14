# M13 Validated replay, work history and bounded synchronization

Revision: invariant-driven revision3. Selected target: `pon-nakamoto-v1`.
[Sole development plan](../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md); [exact invariant registry](../../config/pon/invariants-v2.json).

## Scope and ownership

Root-verified local storage replay. The4101-height fixture is not4101 real mined blocks.

The claims below apply to their named component and tests, not to an independently accepted full native node.

## PoN State machine

### M13.RebuildBranchState

A height beyond4096 does not alone reject a shallow-fork state reconstruction; local checkpoint contents must match stored block roots. Find verified checkpoint or genesis, follow decreasing heights, verify every delta precondition and resultant root.

**Atomic/commit boundary:** Find verified checkpoint or genesis, follow decreasing heights, verify every delta precondition and resultant root.

### M13.VerifyIncomingHistory

For each block use M02 exact parent work and M06 state validation. Work matrices/certificate remain self-contained; model retention is separate. Never interpret a local checkpoint or old proof as a new finality certificate.

**Atomic/commit boundary:** Append valid branch rows/deltas only; incomplete import not active.

## M13.NoHeightFinality

**Invariant:** A height beyond4096 does not alone reject a shallow-fork state reconstruction; local checkpoint contents must match stored block roots.

**Scope:** Root-verified local storage replay. The4101-height fixture is not4101 real mined blocks.

**Atomic boundary:** Find verified checkpoint or genesis, follow decreasing heights, verify every delta precondition and resultant root.

**Failure schedule:** Height4101 replay; Corrupt4096 checkpoint; Missing ancestry and cyclic records; 4102 storage-authenticated records without a non-genesis checkpoint; cancel after512 ancestry entries then retry.

**Expected result:** A height beyond4096 does not alone reject a shallow-fork state reconstruction; local checkpoint contents must match stored block roots.

**Resource and retention rule:** Checkpoints every128 heights,64 plus genesis; missing-checkpoint ancestry spills above8KiB; per256-record progress can cancel without a permanent height veto.

## Concrete regression selectors

`formal/pon-nakamoto-v1/test_invariants.py::RestartForkTests.test_storage_replay_beyond_4096_does_not_invent_finality`

`formal/pon-nakamoto-v1/test_invariants.py::StreamingReplayTests.test_missing_checkpoints_spill_and_cancel_without_height_veto`

These exact functions contain executable assertions. The registry only checks binding; actual outcomes and source/input identities belong to the separate qualification report.

## Module-specific threat and residual work

Pruning treated as finality, false checkpoint trust, unavailable profiles and replay memory growth.

State maps and root recomputation are still complete reference values; resumable native WAN sync, history storage economics and physical durability remain open.

## Current source and verification

- [`formal/pon-nakamoto-v1/ledger.py`](../../formal/pon-nakamoto-v1/ledger.py).

No test binding or local campaign grants independent acceptance, ordinary Hepta execution or production activation. Preserve the exact source, profile and environment of every outcome.
