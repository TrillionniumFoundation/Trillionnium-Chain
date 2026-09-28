# M07 Branch state, undo history and immutable model storage roots — PoN technical contract

Selected profile: `pon-nakamoto-v1`. Revision: 2026-09-28.
Status: new development contract; runtime, work-security and independent acceptance are not implied.
Primary module: M07; actual source ownership is in `config/portability-inventory-v1.json`.

The [sole development plan](../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md)
and [PoN domain contract](../protocol/pon-nakamoto-v1/RECOVERY_MIGRATION.md) govern new work.
Logical interface names below are proposed contracts, not claims that matching Rust APIs,
wire tags, cryptographic proofs or ordinary product consumers have been implemented.

## PoN Authority

Own canonical state schemas, branch roots, undo/checkpoint storage and authoritative chain-state
writes. It does not select a fork or own local Hepta learning facts. Parameter bytes are
M09/Hepta artifacts referenced by authenticated roots.

## PoN Interfaces

StageBranchDelta; ReadBranchSnapshot; ApplyReorgPlan; PublishActiveGeneration;
ReadBackExactHead; ExportVerifiedSnapshot; RetainOrPruneUndo. Each operation binds full
chain/profile/block/root/schema context.

## PoN State machine

Check descriptor-bound namespace, schema and current writer generation. Validate source root
before staging reversible changes. Retain forward/undo lineage per block hash, then atomically
publish the M08-approved active generation only after exact readback. Rebuild derived indexes
from authenticated state. Do not use height as unique identity or copy all state per small read.

## PoN Persistence and recovery

Use PinnedSqliteNamespace-style identity/fence/sidecar protection and explicit new branch
schema. Chain balances/nonces/model pointers roll back; independent local effect/revocation
anchors do not. Deep reorg beyond retained undo triggers verified rebuild, not permanent
rejection of heavier valid work. Crash recovery must recognize only exact old, intermediate
intent or exact new states.

## PoN Resource bounds

Bound hot branches, undo bytes, snapshots, retained task/evidence obligations, startup scans and
compaction work. Safe pruning preserves a recovery path and old profile availability. Disk-full
must leave old coherent state and visible obligations.

## PoN Security

Coherent rollback, path/sidecar replacement, hidden triggers/schema drift, cross-chain
checkpoint, branch-root substitution, nonce resurrection and deletion of data still needed for
challenges/reorg.

## PoN Verification and evidence

Fault injection at every stage/detach/attach/head/ack cut; two-writer races; same-height
different-root snapshots; old profile replay; prune-depth resync; resource accounting and
bounded query/restart tails.

## Source disposition

Only consensus-neutral components listed in `config/portability-inventory-v1.json` remain.
The old consensus/runtime/protocol artifacts are deleted from the active tree and are
recoverable only from Git history. This module target is not automatically implemented
by the retained components; ordinary PoN mining, proof verification and reorg remain
explicit future implementation work. Retained local monotonic stores are not yet
branch-aware reorg stores and cannot be advertised as chain-finality authorities.

## Current source and verification

No native implementation is retained for this domain. A contract is not a runnable consensus or reorg implementation.
