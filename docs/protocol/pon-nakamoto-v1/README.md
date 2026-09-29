# PoN / Hepta-PoH: Nakamoto-style neural-work protocol

Status: selected development architecture; candidate specification, not a deployed consensus.
Decision date: 2026-09-28. Primary owner M00; consensus M02; cross-module consumers M01-M17.
The sole work sequence remains the [development plan](../../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md).
Machine contract: [pon-nakamoto-v1.json](../../../config/pon-nakamoto-v1.json).

## Architectural decision

PoN means Proof of Neuron. Hepta-PoH names the surrounding shared-intelligence system,
not Solana's Proof of History and not a second voting algorithm. The selected ledger
uses permissionless work competition, independently checked block validity, cumulative
verified work fork choice, target adjustment and probabilistic confirmations. PoCO-BFT,
consumption-derived validator weights, QC/TC locks, three-certified-block finality and
old/new-validator-set handoff are RETIRED AS DEVELOPMENT TARGETS.

No BFT checkpoint/finality committee or consumption/stake vote is hidden in PoN.
Old PoCO source, protocol decoders, byte registries and runtime launchers are deleted
from the active tree. Git retains history; only inventoried neutral components remain.
A new PoN runtime and proof format remain to be built.

## The product, not just a compute market

Hepta nodes learn compatible local parameters from authorized real tasks. Contributors
publish actual parameter bytes and lineage. Other nodes independently evaluate them.
Composition workers train/calibrate routers and connectors, test whole-model effects,
and propose a reproducible public model release. Network rewards follow adopted,
measured contributions; public parameters and bounded subsidized inference return the
benefit to users, whose newly authorized experience feeds the next generation.

One chain supports two distinguishable proofs: fresh neural-work proof for block
competition, and reusable model-improvement evidence for commons rewards. Historical
fine-tuning is not fresh anti-replay mining work. Quality, ownership signatures, proof
of execution, data availability and chain inclusion each assert different statements.

## Read the complete domain contract

- [Consensus](CONSENSUS.md): challenge/header binding, validity, work, forks and time.
- [Neural work](NEURAL_WORK.md): real useful-work attempt and proof qualification.
- [Model commons](MODEL_COMMONS.md): compatible updates, evaluation, composition and use.
- [Economics](ECONOMICS.md): mining, contribution and hosting pools; bounded free use.
- [Recovery and migration](RECOVERY_MIGRATION.md): reorgs, irreversible effects and legacy retirement.
- [Security and acceptance](SECURITY_ACCEPTANCE.md): executable cases and remaining obligations.
- [Research references](REFERENCES.md): primary evidence, including negative results.

## Implementation truth

The architecture choice and a concrete executable experimental profile are defined;
cryptographic public-network work qualification is not.
The shared executable details now include exact work, ledger, recovery, model and peer
contracts, native/Python vectors, real disk crash cuts, and controlled model experiments.
None implies deployed native consensus, external independent acceptance, unseen future
model efficacy or production activation. The cheap-forgery verification asymmetry is
measured and remains a public-network blocker, not a hidden fallback.

## Implementable detail index

[W1 work relation](details/WORK_PROFILE.md) · [L1 ledger bytes/state](details/LEDGER_WIRE.md) ·
[S1 persistence/reorg](details/STATE_RECOVERY.md) · [M1 model/evaluation](details/MODEL_EVALUATION.md) ·
[N1 network/clients](details/NETWORK_CLIENT.md) · [P1 performance/acceptance](details/PERFORMANCE_ACCEPTANCE.md).

[Procedure registry](../../../config/pon/module-contracts-v1.json) has36 typed operations
for all18 existing modules. [Maturity](../../../config/pon/module-maturity-v1.json)
separates document, component, executable contract, native product and independent acceptance.

## Revision2 invariant continuation

[Exact invariant/test bindings](../../../config/pon/invariants-v2.json),
[native execution](details/EXECUTION_PARALLEL.md), [recovery](details/STATE_RECOVERY.md),
[proof admission boundary](details/ADMISSION_SECURITY.md) and
[Hepta owner handoff](details/HEPTA_HANDOFF.md) supersede the affected experimental lifecycle
rules. New genesis parameters and storage schema require fresh namespaces. The work relation
itself remains experimental and unqualified; all production/independent acceptance is false.

[Immutable evaluation inputs and full service consent](details/EVALUATION_BUNDLE.md)
bind actual producer/evaluator/settlement calls; they do not grant export or deployment authority.
