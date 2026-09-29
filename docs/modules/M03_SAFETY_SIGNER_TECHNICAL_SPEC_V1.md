# M03 Work attempts, independent local effects and custody

Revision: invariant-driven revision2. The selected target remains `pon-nakamoto-v1`.
[Sole development plan](../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md); [precise invariant/test registry](../../config/pon/invariants-v2.json).

## Scope and ownership

Two SQLite connections to one local operation namespace. This is not physical effect cancellation.

This is an implementation boundary, not a claim of a complete native node or independent acceptance.

## PoN State machine

### M03.RunWorkAttempt

Freeze all header bytes before work; evaluate full challenge transcript; retry a different nonce with a new computation; cap local reference attempts4096. Parent changes do not relabel an old transcript. Durable mining-attempt recovery is a native integration obligation, not implemented by the CLI.

**Atomic/commit boundary:** Reference mining is in-memory; no claim of durable miner. External publication uses exact idempotent BlockId.

### M03.EnterExternalEffect

If revoke commits before entry, the same operation cannot create an effects row; a committed entry cannot be repeated after crash. BEGIN IMMEDIATE encloses revocation check, duplicate check and insert; revoke uses the same serialization point.

**Atomic/commit boundary:** BEGIN IMMEDIATE encloses revocation check, duplicate check and insert; revoke uses the same serialization point.

## M03.RevokeEntryLinearization

**Invariant:** If revoke commits before entry, the same operation cannot create an effects row; a committed entry cannot be repeated after crash.

**Preconditions:** Exact installed revision2 context; current local owner and immutable task/evidence identities. Storage-only and controlled-attestation premises are explicitly labelled in their tests.

**Atomic boundary:** BEGIN IMMEDIATE encloses revocation check, duplicate check and insert; revoke uses the same serialization point.

**Failure schedule:** Revoke commits first; Revoker scheduled between checks and insertion; Crash after entry commit.

**Expected result:** If revoke commits before entry, the same operation cannot create an effects row; a committed entry cannot be repeated after crash.

**Resource and retention rule:** Fixed operation and payload identity, bounded lock wait, explicit generation.

## Concrete regression selectors

`formal/pon-nakamoto-v1/test_invariants.py::EffectLinearizationTests.test_revoke_committed_first_prevents_entry`

`formal/pon-nakamoto-v1/test_invariants.py::EffectLinearizationTests.test_revoker_cannot_commit_inside_entry_transaction`

`formal/pon-nakamoto-v1/test_invariants.py::EffectLinearizationTests.test_crash_after_entry_commit_rejects_replay`

These selectors identify actual test functions, not a class-name count. A binding checker cannot label a test passed; the separate exact-source command receipt must show execution and outcome.

## Module-specific threat and residual work

Check/use races, ACK loss, owner takeover and coherent rollback of all evidence.

Normal Hepta final-use token, independent rollback frontier and target-side reconciliation remain unjoined.

No assertion of independent operators, physical durability, ordinary Hepta execution or future model efficacy follows from local fixtures.

## Current source and verification

- [`formal/pon-nakamoto-v1/ledger.py`](../../formal/pon-nakamoto-v1/ledger.py).

Run the relevant native package and exact Python test selectors through the protocol CI lane. Preserve source hashes, failures, backend, filesystem and process/host scope. Historical evidence is never relabelled as current.
