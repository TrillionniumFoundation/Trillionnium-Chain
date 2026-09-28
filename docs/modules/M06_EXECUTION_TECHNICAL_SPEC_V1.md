# M06 Deterministic branch execution and reversible state effects — PoN technical contract

Selected profile: `pon-nakamoto-v1`. Revision: 2026-09-28.
Status: new development contract; runtime, work-security and independent acceptance are not implied.
Primary module: M06; actual source ownership is in `config/portability-inventory-v1.json`.

The [sole development plan](../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md)
and [PoN domain contract](../protocol/pon-nakamoto-v1/RECOVERY_MIGRATION.md) govern new work.
Logical interface names below are proposed contracts, not claims that matching Rust APIs,
wire tags, cryptographic proofs or ordinary product consumers have been implemented.

## PoN Authority

Own parent-relative deterministic execution, resource metering and ordered reversible
application deltas. It validates block roots, not the mining work predicate or preferred branch.
Long training/inference stays in bounded workers.

## PoN Interfaces

ExecuteCandidate(parent_root, ordered_transactions, profile); StageDelta; ValidateRoots;
ApplyBranchDelta; UndoBranchDelta. M10/M11/M12 expose deterministic business transitions through
contracts, never shared database handles.

## PoN State machine

Apply mandatory bounded deadline/refund/retention work first, then canonical transactions.
Record actual read/write conflicts including shared sponsor, nonce, grant and budget rows.
Produce complete forward/undo effects and state/receipt/model/reward roots. Parallel
1/2/4/8-worker execution must equal serial output. A valid proof cannot excuse unavailable
bodies or nondeterministic evaluation.

## PoN Persistence and recovery

M07 owns commits and undo data; M08 coordinates active-chain changes. Persist source/target
block hash/root and exact deltas, with readback. Reexecute only deterministic chain application;
external provider effects remain in their independent journal and are never undone by a database
rollback.

## PoN Resource bounds

Meter proof admission, state accesses, events, tensor metadata and mandatory work. Bound
speculative overlays/undo size and verification queues. No wall clock, remote dataset fetch or
floating evaluator call in deterministic block execution.

## PoN Security

Root substitution, hidden shared resource conflicts, overflow, partial escrow mutation, invalid
undo and noncanonical evaluation aggregation. Old monotonic finalized append assumptions are not
a reorg algorithm.

## PoN Verification and evidence

Serial/parallel root equality, reject-no-write, attach/detach replay equality, conflicting
sponsor/nonces, rewards/model pointers unwound, deep replay and crashes across durable
publication.

## Source disposition

Only consensus-neutral components listed in `config/portability-inventory-v1.json` remain.
The old consensus/runtime/protocol artifacts are deleted from the active tree and are
recoverable only from Git history. This module target is not automatically implemented
by the retained components; ordinary PoN mining, proof verification and reorg remain
explicit future implementation work. Retained local monotonic stores are not yet
branch-aware reorg stores and cannot be advertised as chain-finality authorities.

## Current source and verification

- [`trnm-executor`](../../trillionnium/crates/trnm-executor/README.md): `cargo test --locked -p trnm-executor --all-targets --all-features`.
- [`trnm-mvcc-fee`](../../trillionnium/crates/trnm-mvcc-fee/README.md): `cargo test --locked -p trnm-mvcc-fee --all-targets --all-features`.
