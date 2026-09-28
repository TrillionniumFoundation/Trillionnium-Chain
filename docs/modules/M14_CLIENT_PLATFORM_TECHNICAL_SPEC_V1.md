# M14 Proof-aware clients, shared model discovery and free inference — PoN technical contract

Selected profile: `pon-nakamoto-v1`. Revision: 2026-09-28.
Status: new development contract; runtime, work-security and independent acceptance are not implied.
Primary module: M14; actual source ownership is in `config/portability-inventory-v1.json`.

The [sole development plan](../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md)
and [PoN domain contract](../protocol/pon-nakamoto-v1/MODEL_COMMONS.md) govern new work.
Logical interface names below are proposed contracts, not claims that matching Rust APIs,
wire tags, cryptographic proofs or ordinary product consumers have been implemented.

## PoN Authority

Own non-authoritative RPC/indexer/SDK/CLI and public model-use surfaces. User-visible states are
submitted, included, policy-confirmed, reorged and adopted-under-profile, not unconditional
finalized. A UI cannot elevate an attestation into a work or local authority proof.

## PoN Interfaces

GetPoNCapabilities; SubmitContribution; QueryConfirmation; SubscribeReorg; DiscoverModelRelease;
DownloadExactBundle; RequestSponsoredInference; QueryReward. Return chain/profile, exact
artifact/release, observed tip, generation, evidence class, freshness and bounds.

## PoN State machine

Read the verified active-chain view and index contiguous add/remove events idempotently. Verify
confirmations/inclusion through M13, expose reorg and stale observations, and refuse unknown
proof classes. Serve reproducible release manifests and parameter bytes through M09. Bind each
inference request to a supported deployment profile and reserved free quota; do not hide missing
experts or mutable backend switches.

## PoN Persistence and recovery

Indexer/cache/projection is rebuildable and never authoritative for balances or adoption. Reorg
updates remove/add entries atomically by generation. Persist client requests and exact returned
model identity when needed; a retry cannot turn a past execution into a fresh free request
silently.

## PoN Resource bounds

Bound queries/pages/proof bytes/model-download rates/free queues and response sizes. Report
honest queue/availability/partial-coverage states. Local model download is free under accepted
policy; hosted compute remains capacity/funding limited.

## PoN Security

False green finality, outdated adopted model, source/payload swapping, quota farming, metadata
privacy leakage and unsafe loader. Do not infer training/export permission from using a free
endpoint or carrying a valid chain receipt.

## PoN Verification and evidence

SDK independently checks new proof classes, reorged rewards/model pointers, incomplete bundles,
author offline, reduced deployment profile labeling, stale cache, free-tier overload and exact
inference model binding.

## Source disposition

Only consensus-neutral components listed in `config/portability-inventory-v1.json` remain.
The old consensus/runtime/protocol artifacts are deleted from the active tree and are
recoverable only from Git history. This module target is not automatically implemented
by the retained components; ordinary PoN mining, proof verification and reorg remain
explicit future implementation work. Retained local monotonic stores are not yet
branch-aware reorg stores and cannot be advertised as chain-finality authorities.

## Current source and verification

No native implementation is retained for this domain. A contract is not a runnable consensus or reorg implementation.
