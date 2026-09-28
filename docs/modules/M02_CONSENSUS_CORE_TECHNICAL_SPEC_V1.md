# M02 Nakamoto consensus, target and cumulative-work fork choice — PoN technical contract

Selected profile: `pon-nakamoto-v1`. Revision: 2026-09-28.
Status: new development contract; runtime, work-security and independent acceptance are not implied.
Primary module: M02; actual source ownership is in `config/portability-inventory-v1.json`.

The [sole development plan](../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md)
and [PoN domain contract](../protocol/pon-nakamoto-v1/CONSENSUS.md) govern new work.
Logical interface names below are proposed contracts, not claims that matching Rust APIs,
wire tags, cryptographic proofs or ordinary product consumers have been implemented.

## PoN Authority

Own the single deterministic PoN consensus state machine. Retire Vote, TimeoutVote, QC, TC,
locked/high-QC and weighted validator scheduling from the target. No majority model score or
application settlement can choose a fork.

## PoN Interfaces

AdmitHeader; WorkValidationCompleted; BodyExecutionCompleted; PreferredBranchChanged;
ReorgApplied; ParentUnavailable. These named contracts use immutable context/generation and
event/effect separation; they are implementation targets.

## PoN State machine

Validate parent/height/profile, exact branch-derived DAA target and median-time rule. Join M01
work and M06 body/state validity, then derive work=floor(2^256/(target+1)) from required target,
not lucky digest. Accumulate exact chainwork. Adopt only a fully validated strictly heavier
branch; equal work retains the current valid tip. Header-only chains request missing
dependencies and cannot publish application state. M08 receives a bound reorg decision, not an
unsigned tip suggestion.

## PoN Persistence and recovery

M07 stores branch nodes/roots/work and M08 owns durable active-tip changes. On recovery
recompute work/target from verified ancestry before preferred-tip publication. Missing deep
history triggers resync. A consumer confirmation depth is not a permanent fork lock.

## PoN Resource bounds

Bound pending headers, alternative branches, proof-validation obligations, per-peer/global
queues and ancestor retrieval. Avoid cloning complete model/body graphs per transition. Use
checked arithmetic; never truncate chainwork or accept peer totals.

## PoN Security

Threat model is adversarial effective work, propagation/verification delay and qualified
primitive hardness. Less-than-one-third PoCO safety and old seven-node evidence do not apply.
Time-warp, selfish mining, proof withholding, easy tasks and eclipse attacks require explicit
analysis.

## PoN Verification and evidence

PON-C01 through PON-C12: higher-height/lower-work forks, target mutation, lucky output, DAA
boundary, equal work, unavailable body, future-time deferral, workload exhaustion and
adversarial work reuse. Formal common-prefix/chain-growth model plus real network evidence
remain separate.

## Source disposition

Only consensus-neutral components listed in `config/portability-inventory-v1.json` remain.
The old consensus/runtime/protocol artifacts are deleted from the active tree and are
recoverable only from Git history. This module target is not automatically implemented
by the retained components; ordinary PoN mining, proof verification and reorg remain
explicit future implementation work. Retained local monotonic stores are not yet
branch-aware reorg stores and cannot be advertised as chain-finality authorities.

## Current source and verification

No native implementation is retained for this domain. A contract is not a runnable consensus or reorg implementation.
