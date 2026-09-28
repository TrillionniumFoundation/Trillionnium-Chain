# M13 Work-verified sync, probabilistic clients and fresh-instance migration — PoN technical contract

Selected profile: `pon-nakamoto-v1`. Revision: 2026-09-28.
Status: new development contract; runtime, work-security and independent acceptance are not implied.
Primary module: M13; actual source ownership is in `config/portability-inventory-v1.json`.

The [sole development plan](../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md)
and [PoN domain contract](../protocol/pon-nakamoto-v1/RECOVERY_MIGRATION.md) govern new work.
Logical interface names below are proposed contracts, not claims that matching Rust APIs,
wire tags, cryptographic proofs or ordinary product consumers have been implemented.

## PoN Authority

Own verification of PoN work/header ancestry and application inclusion/snapshot provenance,
bounded sync and explicit legacy import. It does not trust peer-supplied chainwork or convert
old finality to new work. A light client exposes its availability and full-validation
assumptions.

## PoN Interfaces

VerifyWorkHeaderChain; VerifyConfirmationAndInclusion; FetchVerifiedBranch; RebuildBeyondUndo;
ExportLegacyLiabilities; ReconcileImport; StageFreshPoNGenesis. Trusted genesis/profile is
supplied independently of the proof being checked.

## PoN State machine

Verify every required target/work/profile/time relation along the relevant branch, accumulate
work, compare peers under the accepted light-client model and bind inclusion to an observed best
tip. Header-only/SPV verification does not independently establish complete model-data
availability or execution validity. Full sync fetches/reexecutes missing bodies/state before
service. Export all balances/escrow/nonces/tasks/profiles/retention and classify old proof
strength before fresh-namespace import.

## PoN Persistence and recovery

Persist checkpoint/sync progress with exact chain/root/schema and branch generation; do not
infer finality from a cached tip. Deep reorg beyond pruning triggers authenticated
reconstruction. Legacy key/WAL state remains read-only; fresh PoN identity never resets the same
signing/effect namespace.

## PoN Resource bounds

Limit headers/proofs/chunks/ancestry, total verified work per request, download concurrency,
snapshot expansion and replay/retention. Partial sync cannot publish an authoritative root.
Refuse unavailable required verifier versions and liabilities that the target cannot service.

## PoN Security

Eclipse/SPV false confidence, fabricated accumulated work, snapshot root substitution,
wrong-genesis or QC-as-work import, omitted obligations, old/new double-spend claims and hidden
trusted checkpoints. No BFT signature committee silently supplies PoN finality.

## PoN Verification and evidence

Independent header/work chain and inclusion parser, competing-work views, missing body/data,
deep replay, interrupted import, conserved escrow/retention, separate old/new asset semantics
and old proof-class mislabel rejection.

## Source disposition

Only consensus-neutral components listed in `config/portability-inventory-v1.json` remain.
The old consensus/runtime/protocol artifacts are deleted from the active tree and are
recoverable only from Git history. This module target is not automatically implemented
by the retained components; ordinary PoN mining, proof verification and reorg remain
explicit future implementation work. Retained local monotonic stores are not yet
branch-aware reorg stores and cannot be advertised as chain-finality authorities.

## Current source and verification

- [`trnm-state-import`](../../trillionnium/crates/trnm-state-import/README.md): `cargo test --locked -p trnm-state-import --all-targets --all-features`.
