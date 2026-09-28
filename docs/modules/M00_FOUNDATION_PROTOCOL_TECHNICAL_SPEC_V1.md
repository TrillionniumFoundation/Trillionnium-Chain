# M00 Protocol, canonical neural-work and public-model contracts — PoN technical contract

Selected profile: `pon-nakamoto-v1`. Revision: 2026-09-28.
Status: new development contract; runtime, work-security and independent acceptance are not implied.
Primary module: M00; actual source ownership is in `config/portability-inventory-v1.json`.

The [sole development plan](../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md)
and [PoN domain contract](../protocol/pon-nakamoto-v1/CONSENSUS.md) govern new work.
Logical interface names below are proposed contracts, not claims that matching Rust APIs,
wire tags, cryptographic proofs or ordinary product consumers have been implemented.

## PoN Authority

Own the versioned PoN header/template, work statement, target/parameter, contribution,
evaluation, release, confirmation and reorg-event schemas. The codec does not choose a branch,
issue local capabilities or certify the neural primitive. Preserve historical CEV0/CEV1 decoders
in explicit legacy dispatch; no new value reuses an old tag with stronger meaning.

## PoN Interfaces

HeaderTemplate; NeuralWorkStatement; WorkCertificate; ParameterContribution; EvaluationReceipt;
GlobalModelRelease; ConfirmationReceipt; ReorgEvent. These are proposed logical types until
exact byte registries are frozen, not existing Rust APIs.

## PoN State machine

Resolve installed genesis/chain/profile before decoding. Bound total bytes, lists, depth,
tensors, proof and signature work before allocation. Canonicalize only valid objects; reject
duplicates, unknown mandatory fields, trailing bytes and target/profile substitution. Encode
every challenge-affecting field once. Derive a stable block id from template and canonical
output, not proof randomness. Specify exact signedness, endian, dimensions and output uniqueness
with an independent encoder.

## PoN Persistence and recovery

Codec owns no store. Persisted schemas are separate from public wire schemas; M07/M03 own
migrations. A historical decode returns its original proof class. State/error/limit registry
changes require explicit profile version and consumer requalification, never parser fallback.

## PoN Resource bounds

Register checked 256-bit targets with wider intermediate and cumulative-work arithmetic. Give
concrete byte/count/tensor/shape/proof ceilings before activation. Unknown ceilings or algorithm
identifiers reject, rather than assuming unlimited capacity.

## PoN Security

Attack cross-chain/header/payout replay, proof malleability, duplicate fields and arbitrary
executable model payloads. Crypto-verified types cannot be created by decoding a boolean. An
unqualified work profile remains non-activatable.

## PoN Verification and evidence

Independent positive/negative codec vectors, every truncated prefix, appended bytes, maximum and
maximum+1, target overflow, changed model/base/schema and old-QC-as-work rejection. Test every
consensus-affecting field against the same challenge relation.

## Source disposition

Only consensus-neutral components listed in `config/portability-inventory-v1.json` remain.
The old consensus/runtime/protocol artifacts are deleted from the active tree and are
recoverable only from Git history. This module target is not automatically implemented
by the retained components; ordinary PoN mining, proof verification and reorg remain
explicit future implementation work. Retained local monotonic stores are not yet
branch-aware reorg stores and cannot be advertised as chain-finality authorities.

## Current source and verification

- [`trnm-types`](../../trillionnium/crates/trnm-types/README.md): `cargo test --locked -p trnm-types --all-targets --all-features`.
- [`trnm-protocol`](../../trillionnium/crates/trnm-protocol/README.md): `cargo test --locked -p trnm-protocol --all-targets --all-features`.
