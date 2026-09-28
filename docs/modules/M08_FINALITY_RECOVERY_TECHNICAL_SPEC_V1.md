# M08 Probabilistic confirmations, reorg coordination and recovery — PoN technical contract

Selected profile: `pon-nakamoto-v1`. Revision: 2026-09-28.
Status: new development contract; runtime, work-security and independent acceptance are not implied.
Primary module: M08; actual source ownership is in `config/portability-inventory-v1.json`.

The [sole development plan](../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md)
and [PoN domain contract](../protocol/pon-nakamoto-v1/RECOVERY_MIGRATION.md) govern new work.
Logical interface names below are proposed contracts, not claims that matching Rust APIs,
wire tags, cryptographic proofs or ordinary product consumers have been implemented.

## PoN Authority

Own realization of M02 preferred-branch decisions, consistent confirmation views and recovery
publication. It does not invent finality, select a second fork or use a QC to lock PoN history.
Local policy confirmations remain reversible.

## PoN Interfaces

PlanReorg; PersistReorgIntent; DetachOldBranch; AttachNewBranch; PublishActiveTip;
GetConfirmationReceipt; ReconcileOrphanedEffects. Receipts bind observed tip, included block,
depth, work delta, policy and active generation.

## PoN State machine

Accept only a bound M02 branch decision with all dependencies valid. Determine common ancestor
and ordered detach/attach, persist intent, apply through M06/M07, verify roots, atomically
publish active generation, then send idempotent index/outbox changes. Recompute confirmations
and reward maturity. Crossing a local threshold never turns a valid deeper reorg into invalid
consensus.

## PoN Persistence and recovery

One Node Commit Ledger-style owner coordinates the exact reorg. Reopen by matching predecessor,
intent, old/new roots and durable readback. Unknown commit/ack remains fenced. M03/Hepta effect
and revocation histories are joined for reconciliation, not rolled back. Keep historical
model-output identity.

## PoN Resource bounds

Bound reorg staging, undo load, catch-up service and publication queues. Admit recovery
downloads before ordinary service when necessary; preserve deadlines and explicit backpressure.
Missing deep undo requests authenticated sync.

## PoN Security

False finalized labels, stale confirmation replay, partial mixed-generation RPC, branch swap
with same height, automatic external replay and poisoned model rollback. Compensation is a newly
authorized action with explicit risk, not a fiction of exactly-once external execution.

## PoN Verification and evidence

Deep reorg after payout/model use, crashes during all stages, index ACK loss, failed
replacement, unavailable ancestors, isolated client views, local revoke retained and
authoritative query of already executed remote effects.

## Source disposition

Only consensus-neutral components listed in `config/portability-inventory-v1.json` remain.
The old consensus/runtime/protocol artifacts are deleted from the active tree and are
recoverable only from Git history. This module target is not automatically implemented
by the retained components; ordinary PoN mining, proof verification and reorg remain
explicit future implementation work. Retained local monotonic stores are not yet
branch-aware reorg stores and cannot be advertised as chain-finality authorities.

## Current source and verification

No native implementation is retained for this domain. A contract is not a runnable consensus or reorg implementation.
