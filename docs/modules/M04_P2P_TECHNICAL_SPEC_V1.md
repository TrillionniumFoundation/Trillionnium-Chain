# M04 Permissionless bounded block, proof and parameter network — PoN technical contract

Selected profile: `pon-nakamoto-v1`. Revision: 2026-09-28.
Status: new development contract; runtime, work-security and independent acceptance are not implied.
Primary module: M04; actual source ownership is in `config/portability-inventory-v1.json`.

The [sole development plan](../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md)
and [PoN domain contract](../protocol/pon-nakamoto-v1/CONSENSUS.md) govern new work.
Logical interface names below are proposed contracts, not claims that matching Rust APIs,
wire tags, cryptographic proofs or ordinary product consumers have been implemented.

## PoN Authority

Own transport, discovery, bounded dissemination and authenticated resource/session context, not
mining eligibility or consensus decisions. Peer identity authenticates a session, not stake,
work, personhood or a right to exclude valid miners.

## PoN Interfaces

AnnounceHeader; FetchBody; FetchWorkProof; FetchParameterChunks; AnnounceContribution;
PeerCapabilities; CancelFetch. All are versioned and bounded; M02/M01/M09 independently decide
their domain validity.

## PoN State machine

Admit cheap length/version/rate/session checks before proof work. Separate queues for
headers/control, transaction data, large parameter chunks and proofs. Fetch competing branches
from diverse sources. Return exact request/generation-bound results; a corrupt peer copy does
not classify all copies invalid. Gossip verified blocks promptly without waiting for global
model adoption.

## PoN Persistence and recovery

Retain replay/session and download cursors under their declared owner. Restart must not replay
an obsolete response into a new attempt. Index parameters by exact content and codec, not
mutable URL. Preserve partial-download checks and repair obligations.

## PoN Resource bounds

Independent global and per-peer byte/item/in-flight/proof budgets. Chunk large weights with
finite reconstruction size, bandwidth and wall-clock deadlines; reserve consensus/control
capacity. Peer churn cannot reset global budgets.

## PoN Security

Eclipse/partition, Sybil connection churn, decompression/allocation bombs, proof floods,
unavailable-model adverts and withholding are explicit threats. No static validator allowlist is
inherited as PoN eligibility; transport permissions do not change fork choice.

## PoN Verification and evidence

Independent-host partition/heal, different-work forks, malformed chunks/proofs, stale sessions,
adversarial peers, source diversity, author offline, bounded memory/queues and measured
propagation/verification tails.

## Source disposition

Only consensus-neutral components listed in `config/portability-inventory-v1.json` remain.
The old consensus/runtime/protocol artifacts are deleted from the active tree and are
recoverable only from Git history. This module target is not automatically implemented
by the retained components; ordinary PoN mining, proof verification and reorg remain
explicit future implementation work. Retained local monotonic stores are not yet
branch-aware reorg stores and cannot be advertised as chain-finality authorities.

## Current source and verification

- [`trnm-peer-lease`](../../trillionnium/crates/trnm-peer-lease/README.md): `cargo test --locked -p trnm-peer-lease --all-targets --all-features`.
- [`trnm-transport`](../../trillionnium/crates/trnm-transport/README.md): `cargo test --locked -p trnm-transport --all-targets --all-features`.
