# M10 Parameter contributions, evaluation jobs and shared-model releases — PoN technical contract

Selected profile: `pon-nakamoto-v1`. Revision: 2026-09-28.
Status: new development contract; runtime, work-security and independent acceptance are not implied.
Primary module: M10; actual source ownership is in `config/portability-inventory-v1.json`.

The [sole development plan](../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md)
and [PoN domain contract](../protocol/pon-nakamoto-v1/MODEL_COMMONS.md) govern new work.
Logical interface names below are proposed contracts, not claims that matching Rust APIs,
wire tags, cryptographic proofs or ordinary product consumers have been implemented.

## PoN Authority

Own the deterministic chain lifecycle for parameter contributions, evaluation/composition jobs
and public release proposals. Hepta remains owner of local training and private task data. M10
cannot self-certify a useful model, mint reward or issue local execution permission.

## PoN Interfaces

ParameterContribution; EvaluationPlan; CompositionCandidate; GlobalModelRelease;
SponsoredInferenceTask; CancelOrExpire; ObserveReorg. Reuse current task/lease/attempt/resource
owner contracts behind explicitly versioned extensions, not a second marketplace database.

## PoN State machine

Admit exact parent model, compatible family/layers/ranks/numeric profile, real parameter bytes
and publication/use conditions. Reserve evaluation/retention obligations and lock the evaluation
plan before results. Consume M11 typed evidence and whole-model composition outcomes, then
propose a reproducible release and M12 allocation. Mining success alone cannot admit a model.
Non-miners may contribute useful trained updates.

## PoN Persistence and recovery

Chain lifecycle and adopted-release pointers are branch-derived; local training/artifact lineage
and actual effect records remain with Hepta. Reorg transitions invalidate current
adoption/entitlement without rewriting historical model outputs. Every retry binds the same
original identity or an explicitly new authorized attempt.

## PoN Resource bounds

Caps on contributions, experts per candidate, tensor metadata, evaluation/composition jobs,
retries, graph depth, in-flight tasks and future obligations. No free task bypasses global
resource caps. An empty improvement queue does not stop block production or invent a new gain.

## PoN Security

Parent/tokenizer substitution, invented training provenance, benchmark overfit,
duplicated/perturbed contribution, self-service rewards and schema-incompatible experts.
Permission to process a task is not permission to export training parameters or publish personal
data.

## PoN Verification and evidence

Real task to parameter to independent evaluation to composed model to independent free consumer
and next contribution. Test incompatible bundles, duplicate attempts, cancel/late receipt,
author loss, complementary experts, no improvement and model-release reorg.

## Source disposition

Only consensus-neutral components listed in `config/portability-inventory-v1.json` remain.
The old consensus/runtime/protocol artifacts are deleted from the active tree and are
recoverable only from Git history. This module target is not automatically implemented
by the retained components; ordinary PoN mining, proof verification and reorg remain
explicit future implementation work. Retained local monotonic stores are not yet
branch-aware reorg stores and cannot be advertised as chain-finality authorities.

## Current source and verification

- [`trnm-worker-agent`](../../trillionnium/crates/trnm-worker-agent/README.md): `cargo test --locked -p trnm-worker-agent --all-targets --all-features`.
- [`trnm-research-protocol`](../../trillionnium/crates/trnm-research-protocol/README.md): `cargo test --locked -p trnm-research-protocol --all-targets --all-features`.
- [`trnm-task-kernel`](../../trillionnium/crates/trnm-task-kernel/README.md): `cargo test --locked -p trnm-task-kernel --all-targets --all-features`.
