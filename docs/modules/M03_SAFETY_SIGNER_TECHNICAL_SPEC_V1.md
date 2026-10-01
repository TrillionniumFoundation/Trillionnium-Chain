# M03 Work attempts, independent local effects and custody

Revision: invariant-driven revision3. Selected target: `pon-nakamoto-v1`.
[Sole development plan](../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md); [exact invariant registry](../../config/pon/invariants-v2.json).

## Scope and ownership

Native bounded development mining plus the separate reference local-effect experiment. Its two SQLite connections demonstrate local entry linearization, not physical effect cancellation or a durable continuous miner.

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

**Scope:** Native bounded development mining plus the separate reference local-effect experiment. Its two SQLite connections demonstrate local entry linearization, not physical effect cancellation or a durable continuous miner.

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

- [`trillionnium/crates/trnm-pon-node/src/store.rs`](../../trillionnium/crates/trnm-pon-node/src/store.rs).
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

## Native development continuation and remaining scope

Node::make uses a bounded prepared-task producer and commits no chain state before validation. CLI output is create-new and synced before local publication. The [finite native miner](../protocol/pon-nakamoto-v1/details/CONTINUOUS_MINING_V1.md) provides cooperative stop and stale parent/generation rejection. Durable in-progress search recovery, wallet custody and provider/effect reconciliation remain unimplemented.

Preparation may share its first checked actual parent state with task eligibility
and execution within that operation, as specified by [M06](M06_EXECUTION_TECHNICAL_SPEC_V1.md).
That parent authority is dropped before unlocked proof search. Full native admission
after search still checks actual state, current parent/generation and the exact pool
batch; a task registered in the candidate cannot authorize that candidate's work.

The current callable mappings remain in `config/pon/module-maturity-v1.json`.
Exact native entry, storage and work behavior is specified by N3 in NETWORK_CLIENT,
the native continuation in STATE_RECOVERY and the prepared-producer section in WORK_PROFILE.
No historical receipt is relabelled as executing this source.
