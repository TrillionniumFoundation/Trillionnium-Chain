# M03 Mining-attempt ownership, identity custody and local fencing — PoN technical contract

Selected profile: `pon-nakamoto-v1`. Revision: 2026-09-28.
Status: new development contract; runtime, work-security and independent acceptance are not implied.
Primary module: M03; actual source ownership is in `config/portability-inventory-v1.json`.

The [sole development plan](../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md)
and [PoN domain contract](../protocol/pon-nakamoto-v1/NEURAL_WORK.md) govern new work.
Logical interface names below are proposed contracts, not claims that matching Rust APIs,
wire tags, cryptographic proofs or ordinary product consumers have been implemented.

## PoN Authority

Own the generation-fenced local mining/identity/effect publication boundary and its durable
attempt journal. Custody authenticates producer/payout and authorized external use; it never
votes, determines target or certifies model usefulness.

## PoN Interfaces

FreezeMiningTemplate; StartQualifiedWork; RecordWorkOutput; VerifyBeforePublish;
PublishExactBlock; CancelStaleAttempt; ReconcileAttempt. Distinguish public work statement,
private key policy and local final-use authority.

## PoN State machine

Bind template/challenge/input/model/profile/resource budget and worker generation before
dispatch. Record physical attempt entry, run bounded work/proving, verify exact output, persist
publication intent and retry identical publication only. New parent/template requires new
charged work. Stale result remains attributable to its old attempt; it may support a separate
model claim but not new chainwork.

## PoN Persistence and recovery

Use one writer per attempt namespace and independent rollback frontier where required. Recover
dispatched unknown work by exact query/readback; do not reset history. Do not copy PoCO
one-vote-per-view restrictions into valid PoW fork behavior. Local capability/revocation/effect
history never rewinds on chain reorg.

## PoN Resource bounds

Reserve GPU/CPU/RAM, output/proof bytes, task slots and completion space before attempt
dispatch. Drain pipes concurrently; bound cancellation/kill and keep unreconciled resources
fenced. Proving cannot starve verification or recovery.

## PoN Security

Separate miner payout, local grant issuer, evaluator and host identities. Hardware/remote
signing keys cannot promote arbitrary work. Stop handling preserves indeterminate external
effects. Unused nonce/payout mutations cannot reuse old expensive work.

## PoN Verification and evidence

Crash before/after dispatch, output, proof, intent and publication; ACK loss; stale parent;
changing payout/body; pipe-capacity output; cancellation; host takeover; coherent store
rollback; duplicate exact retransmission.

## Source disposition

Only consensus-neutral components listed in `config/portability-inventory-v1.json` remain.
The old consensus/runtime/protocol artifacts are deleted from the active tree and are
recoverable only from Git history. This module target is not automatically implemented
by the retained components; ordinary PoN mining, proof verification and reorg remain
explicit future implementation work. Retained local monotonic stores are not yet
branch-aware reorg stores and cannot be advertised as chain-finality authorities.

## Current source and verification

- [`trnm-checkpoint-store`](../../trillionnium/crates/trnm-checkpoint-store/README.md): `cargo test --locked -p trnm-checkpoint-store --all-targets --all-features`.
- [`trnm-checkpoint-types`](../../trillionnium/crates/trnm-checkpoint-types/README.md): `cargo test --locked -p trnm-checkpoint-types --all-targets --all-features`.
