# M03 Work attempts, independent local effects and custody

Revision: invariant-driven revision3. Selected target: `pon-nakamoto-v1`.
[Sole development plan](../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md); [exact invariant registry](../../config/pon/invariants-v2.json).

## Scope and ownership

Two SQLite connections to one local operation namespace. This is not physical effect cancellation.

The claims below apply to their named component and tests, not to an independently accepted full native node.

## PoN State machine

### M03.RunWorkAttempt

Freeze all header bytes before work; evaluate full challenge transcript; retry a different nonce with a new computation; cap local reference attempts4096. Parent changes do not relabel an old transcript. Durable mining-attempt recovery is a native integration obligation, not implemented by the CLI.

**Atomic/commit boundary:** Reference mining is in-memory; no claim of durable miner. External publication uses exact idempotent BlockId.

### M03.EnterExternalEffect

If revoke commits before entry, the same operation cannot create an effects row; a committed entry cannot be repeated after crash. BEGIN IMMEDIATE encloses revocation check, duplicate check and insert; revoke uses the same serialization point.

**Atomic/commit boundary:** BEGIN IMMEDIATE encloses revocation check, duplicate check and insert; revoke uses the same serialization point.

## M03.RevokeEntryLinearization

**Invariant:** If revoke commits before entry, the same operation cannot create an effects row; a committed entry cannot be repeated after crash.

**Scope:** Two SQLite connections to one local operation namespace. This is not physical effect cancellation.

**Atomic boundary:** BEGIN IMMEDIATE encloses revocation check, duplicate check and insert; revoke uses the same serialization point.

**Failure schedule:** Revoke commits first; Revoker scheduled between checks and insertion; Crash after entry commit.

**Expected result:** If revoke commits before entry, the same operation cannot create an effects row; a committed entry cannot be repeated after crash.

**Resource and retention rule:** Fixed operation and payload identity, bounded lock wait, explicit generation.

## Concrete regression selectors

`formal/pon-nakamoto-v1/test_invariants.py::EffectLinearizationTests.test_revoke_committed_first_prevents_entry`

`formal/pon-nakamoto-v1/test_invariants.py::EffectLinearizationTests.test_revoker_cannot_commit_inside_entry_transaction`

`formal/pon-nakamoto-v1/test_invariants.py::EffectLinearizationTests.test_crash_after_entry_commit_rejects_replay`

These exact functions contain executable assertions. The registry only checks binding; actual outcomes and source/input identities belong to the separate qualification report.

## Module-specific threat and residual work

Check/use races, ACK loss, owner takeover and coherent rollback of all evidence.

Normal Hepta final-use token, independent rollback frontier and target-side reconciliation remain unjoined.

## Current source and verification

- [`formal/pon-nakamoto-v1/ledger.py`](../../formal/pon-nakamoto-v1/ledger.py).

No test binding or local campaign grants independent acceptance, ordinary Hepta execution or production activation. Preserve the exact source, profile and environment of every outcome.

## Executed evidence and scope

[Responsibility-level evidence navigation](README.md#responsibility-and-evidence) reads
measured commits from immutable receipts. The module's entries in
[module-maturity-v1.json](../../config/pon/module-maturity-v1.json) identify actual callable
owners, controlled entrypoints, backends, persistence and exact observed test selectors.
Run `python3 scripts/ci/report_module_evidence.py --module M03` from the repository
root to see subject-byte and complete recorded-runtime matches separately, plus scenarios
not observed in each package. A byte match is not a new test run or product acceptance.
Historical v1/v3/v4 results are never repinned. The sole plan selects further work.
