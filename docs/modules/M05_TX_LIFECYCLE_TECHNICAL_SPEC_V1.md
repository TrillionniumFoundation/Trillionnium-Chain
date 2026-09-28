# M05 Reorg-aware transaction and contribution admission — PoN technical contract

Selected profile: `pon-nakamoto-v1`. Revision: 2026-09-28.
Status: new development contract; runtime, work-security and independent acceptance are not implied.
Primary module: M05; actual source ownership is in `config/portability-inventory-v1.json`.

The [sole development plan](../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md)
and [PoN domain contract](../protocol/pon-nakamoto-v1/RECOVERY_MIGRATION.md) govern new work.
Logical interface names below are proposed contracts, not claims that matching Rust APIs,
wire tags, cryptographic proofs or ordinary product consumers have been implemented.

## PoN Authority

Own provisional transaction admission, mempool and branch-aware nonce/reservation handoff.
Inclusion, confirmation, model adoption and external execution are different facts. No mempool
success or local WAL entry certifies a block.

## PoN Interfaces

SubmitTransaction; SubmitParameterCommitment; ReserveNonceAndBudget; ObserveIncluded;
ObserveConfirmed; ObserveReorged; RevalidateForRequeue. Bind principal/capability/session
generation, task/attempt and active-chain generation.

## PoN State machine

Validate signatures/scope/nonce and bounded payload against the exact active state. Reserve
provisionally without changing canonical balances. On block inclusion index its hash, not height
alone. On reorg remove orphan inclusion, release/reconcile provisional state and revalidate
transactions against new balances, nonces, grants and generation before requeue. Do not
automatically create a new external attempt.

## PoN Persistence and recovery

Version existing WAL semantics to distinguish local request history from branch-derived
reservations. Preserve identity and uncertain handoff across restart. A local operation
terminal/effect-entry tombstone cannot disappear just because its chain transaction was
detached.

## PoN Resource bounds

Cap transaction/contribution counts, bytes, per-principal/global pending reservations and
proof/evaluation obligations. Free transactions do not bypass count/CPU caps. Backpressure must
preserve query and recovery capacity.

## PoN Security

Cross-chain/profile replay, duplicate contribution/nonce, changed payload retry, stale grant and
reorg resurrecting an already executed operation. A signed submission is a claim, not evidence
of model quality.

## PoN Verification and evidence

Double submit, changed payload at same key, inclusion and depth regression, nonce conflict after
reorg, sponsor exhaustion, missing history, signed stale authorization and no-side-effect
rejection.

## Source disposition

Only consensus-neutral components listed in `config/portability-inventory-v1.json` remain.
The old consensus/runtime/protocol artifacts are deleted from the active tree and are
recoverable only from Git history. This module target is not automatically implemented
by the retained components; ordinary PoN mining, proof verification and reorg remain
explicit future implementation work. Retained local monotonic stores are not yet
branch-aware reorg stores and cannot be advertised as chain-finality authorities.

## Current source and verification

- [`trnm-mempool`](../../trillionnium/crates/trnm-mempool/README.md): `cargo test --locked -p trnm-mempool --all-targets --all-features`.
