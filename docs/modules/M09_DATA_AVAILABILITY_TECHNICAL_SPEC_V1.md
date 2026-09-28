# M09 Public parameter and evidence availability — PoN technical contract

Selected profile: `pon-nakamoto-v1`. Revision: 2026-09-28.
Status: new development contract; runtime, work-security and independent acceptance are not implied.
Primary module: M09; actual source ownership is in `config/portability-inventory-v1.json`.

The [sole development plan](../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md)
and [PoN domain contract](../protocol/pon-nakamoto-v1/MODEL_COMMONS.md) govern new work.
Logical interface names below are proposed contracts, not claims that matching Rust APIs,
wire tags, cryptographic proofs or ordinary product consumers have been implemented.

## PoN Authority

Own bounded artifact publication, availability, repair and retention responsibilities. A model
root or receipt is not the model bytes, and storage attestations do not choose a ledger branch.
Parameters must remain usable without the contributor online.

## PoN Interfaces

PublishParameterManifest; VerifyChunk; ReconstructArtifact; ReserveRetention; FetchExactRelease;
RepairReplica; ReleaseRetention. Bind content hash, codec, size, task/contribution/release
identity, permissions and responsibility horizon.

## PoN State machine

Validate canonical bounded manifest and permissible data format, reserve storage/repair
obligations, receive and verify actual chunks, reconstruct exact bytes and attest only the
declared availability statement. Global adoption requires all base/expert/router/calibration
dependencies available under the chosen profile. Replicate across declared independent
custodians and check retrieval rather than counting URLs or signatures.

## PoN Persistence and recovery

Retain content-addressed bytes and responsibility records through evaluation/challenge/reward
horizons and accepted replay policy. A chain reorg may change entitlement but cannot justify
deleting evidence still needed for unresolved disputes or recovery. Reference-aware garbage
collection never deletes shared base weights still used by another release.

## PoN Resource bounds

Per-artifact, chunk, reconstruction, peer, storage and global retention caps; bandwidth and
repair deadlines; bounded replication queues. Capacity is reserved before accepting obligations.
New model uploads cannot starve block-body/proof availability or historical replay.

## PoN Security

Malicious tensor containers, path traversal, missing chunks, incorrect reconstruction,
self-attested replicas, author disappearance and data-consent mismatch. Hashes do not imply
confidentiality. Publicly downloaded weights cannot be recalled from every replica by deleting a
chain row.

## PoN Verification and evidence

Author-offline retrieval, one/multiple replica failures, malicious manifests/chunks, exact size
bounds, repair exhaustion, shared-base GC, reorged release retention and privacy/use-policy
rejection.

## Source disposition

Only consensus-neutral components listed in `config/portability-inventory-v1.json` remain.
The old consensus/runtime/protocol artifacts are deleted from the active tree and are
recoverable only from Git history. This module target is not automatically implemented
by the retained components; ordinary PoN mining, proof verification and reorg remain
explicit future implementation work. Retained local monotonic stores are not yet
branch-aware reorg stores and cannot be advertised as chain-finality authorities.

## Current source and verification

- [`trnm-data-availability`](../../trillionnium/crates/trnm-data-availability/README.md): `cargo test --locked -p trnm-data-availability --all-targets --all-features`.
