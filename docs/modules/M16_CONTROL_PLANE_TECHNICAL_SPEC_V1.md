# M16 Advisory model composition, routing and resource planning — PoN technical contract

Selected profile: `pon-nakamoto-v1`. Revision: 2026-09-28.
Status: new development contract; runtime, work-security and independent acceptance are not implied.
Primary module: M16; actual source ownership is in `config/portability-inventory-v1.json`.

The [sole development plan](../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md)
and [PoN domain contract](../protocol/pon-nakamoto-v1/MODEL_COMMONS.md) govern new work.
Logical interface names below are proposed contracts, not claims that matching Rust APIs,
wire tags, cryptographic proofs or ordinary product consumers have been implemented.

## PoN Authority

The global control plane is advisory. It can propose composition/router/resource choices and
summarize measurements; it cannot set chainwork, choose forks, issue capabilities, alter
difficulty at runtime or automatically activate code/models.

## PoN Interfaces

ObservePublicModelMetrics; ProposeCompatibleComposition; SuggestResourceAllocation;
SubmitEvaluationJob; CompareCandidates; RequestGovernedAdoption. Bind objective, model/reference
versions, constraints, uncertainty and resource allowance.

## PoN State machine

Read permitted source-bound observations and fixed public evaluation plans. Generate bounded
expert/graph/router or distillation candidates within registered interfaces, including
reuse/no-change. Submit through M10/M11 for independent evaluation. Hepta retains local NDU
objectives and four subject levels; no mandatory global RPC on Cell/reflex paths.

## PoN Persistence and recovery

Keep proposal lineage and non-authoritative telemetry with exact versions; canonical parameters,
release state, budgets and learning facts stay with existing owners. A reorg invalidates
chain-derived proposal context, not local history; recompute/revalidate without elevating
caches.

## PoN Resource bounds

Limit candidate sets, search/training/evaluation budgets, graph edits, message size and planning
time. Reserve safety/foreground resources first. Routing quality includes end-to-end latency,
loaded experts and uncertainty rather than raw parameter count.

## PoN Security

Reward hacking, selecting evaluation data after results, authority encoded in latent tensors,
hidden centralized operator, automatic hard-boundary mutation and biased resource allocation.
Utility never compensates for privacy/truth/local authority constraints.

## PoN Verification and evidence

No-change and abstain paths, compatible/invalid composition proposals, whole-system gains vs
local optima, missed windows, failed model proposal, stale/reorged context and continued system
safety with this service disabled.

## Source disposition

Only consensus-neutral components listed in `config/portability-inventory-v1.json` remain.
The old consensus/runtime/protocol artifacts are deleted from the active tree and are
recoverable only from Git history. This module target is not automatically implemented
by the retained components; ordinary PoN mining, proof verification and reorg remain
explicit future implementation work. Retained local monotonic stores are not yet
branch-aware reorg stores and cannot be advertised as chain-finality authorities.

## Current source and verification

- [`trnm-control-plane`](../../trillionnium/crates/trnm-control-plane/README.md): `cargo test --locked -p trnm-control-plane --all-targets --all-features`.
