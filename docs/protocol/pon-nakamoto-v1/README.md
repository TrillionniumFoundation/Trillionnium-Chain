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

The architecture choice is made; cryptographic work-profile qualification is not.
The concrete neural-work circuit/program, byte registry, economic parameters,
independent implementations and real network have no acceptance receipt in this change.
The machine contract deliberately records an unqualified work profile and all runtime,
mainnet, model-efficacy and release flags false. No guessed circuit, signature quorum,
synthetic model score or SHA-only fallback may fill that gap at runtime.
