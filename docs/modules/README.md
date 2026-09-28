# Trillionnium Chain module specifications — PoN / Hepta-PoH

All 18 module designs select `pon-nakamoto-v1`. PoCO is retired as the development target.
The [sole plan](../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md) owns sequence;
[the protocol suite](../protocol/pon-nakamoto-v1/README.md) owns consensus/model contracts.
The [authority resolver](../architecture/TRNM_DOCUMENTATION_AUTHORITY_V1.md) separates
new target, existing legacy implementation, historical proofs and activation.

Each technical specification starts with module-specific PoN authority, interfaces,
algorithm, persistence/reorg, limits, security, tests and source migration. Its clearly
marked legacy appendix preserves existing implementation details and frozen references;
these are not evidence of new implementation or an active PoCO completion plan.

| Module | Technical specification | New responsibility |
|---|---|---|
| M00 | [M00_FOUNDATION_PROTOCOL_TECHNICAL_SPEC_V1.md](M00_FOUNDATION_PROTOCOL_TECHNICAL_SPEC_V1.md) | Protocol, canonical neural-work and public-model contracts |
| M01 | [M01_CRYPTO_IDENTITY_TECHNICAL_SPEC_V1.md](M01_CRYPTO_IDENTITY_TECHNICAL_SPEC_V1.md) | Cryptography, neural-work verification and local identity |
| M02 | [M02_CONSENSUS_CORE_TECHNICAL_SPEC_V1.md](M02_CONSENSUS_CORE_TECHNICAL_SPEC_V1.md) | Nakamoto consensus, target and cumulative-work fork choice |
| M03 | [M03_SAFETY_SIGNER_TECHNICAL_SPEC_V1.md](M03_SAFETY_SIGNER_TECHNICAL_SPEC_V1.md) | Mining-attempt ownership, identity custody and local fencing |
| M04 | [M04_P2P_TECHNICAL_SPEC_V1.md](M04_P2P_TECHNICAL_SPEC_V1.md) | Permissionless bounded block, proof and parameter network |
| M05 | [M05_TX_LIFECYCLE_TECHNICAL_SPEC_V1.md](M05_TX_LIFECYCLE_TECHNICAL_SPEC_V1.md) | Reorg-aware transaction and contribution admission |
| M06 | [M06_EXECUTION_TECHNICAL_SPEC_V1.md](M06_EXECUTION_TECHNICAL_SPEC_V1.md) | Deterministic branch execution and reversible state effects |
| M07 | [M07_STATE_STORAGE_TECHNICAL_SPEC_V1.md](M07_STATE_STORAGE_TECHNICAL_SPEC_V1.md) | Branch state, undo history and immutable model storage roots |
| M08 | [M08_FINALITY_RECOVERY_TECHNICAL_SPEC_V1.md](M08_FINALITY_RECOVERY_TECHNICAL_SPEC_V1.md) | Probabilistic confirmations, reorg coordination and recovery |
| M09 | [M09_DATA_AVAILABILITY_TECHNICAL_SPEC_V1.md](M09_DATA_AVAILABILITY_TECHNICAL_SPEC_V1.md) | Public parameter and evidence availability |
| M10 | [M10_AGENT_MARKET_TECHNICAL_SPEC_V1.md](M10_AGENT_MARKET_TECHNICAL_SPEC_V1.md) | Parameter contributions, evaluation jobs and shared-model releases |
| M11 | [M11_VERIFICATION_CHALLENGE_TECHNICAL_SPEC_V1.md](M11_VERIFICATION_CHALLENGE_TECHNICAL_SPEC_V1.md) | Independent model evaluation and qualified work verification profiles |
| M12 | [M12_SETTLEMENT_TECHNICAL_SPEC_V1.md](M12_SETTLEMENT_TECHNICAL_SPEC_V1.md) | Mining rewards, model contribution allocation and free-use budgets |
| M13 | [M13_STATE_SYNC_MIGRATION_TECHNICAL_SPEC_V1.md](M13_STATE_SYNC_MIGRATION_TECHNICAL_SPEC_V1.md) | Work-verified sync, probabilistic clients and fresh-instance migration |
| M14 | [M14_CLIENT_PLATFORM_TECHNICAL_SPEC_V1.md](M14_CLIENT_PLATFORM_TECHNICAL_SPEC_V1.md) | Proof-aware clients, shared model discovery and free inference |
| M15 | [M15_NODE_RELEASE_TECHNICAL_SPEC_V1.md](M15_NODE_RELEASE_TECHNICAL_SPEC_V1.md) | Ordinary PoN node, Hepta integration and release composition |
| M16 | [M16_CONTROL_PLANE_TECHNICAL_SPEC_V1.md](M16_CONTROL_PLANE_TECHNICAL_SPEC_V1.md) | Advisory model composition, routing and resource planning |
| M17 | [M17_EVIDENCE_SECURITY_TECHNICAL_SPEC_V1.md](M17_EVIDENCE_SECURITY_TECHNICAL_SPEC_V1.md) | Neural-work security, model efficacy and reorg evidence |

## Shared contracts

| Contract | Producer / consumers | Required distinction |
|---|---|---|
| Fresh neural work | M00/M01/M03 -> M02 | Old trained parameters and evaluator scores cannot create new parent-bound work |
| Fork choice / confirmation | M02 -> M07/M08/M13/M14 | Required cumulative work, not height or QC; depth is not irreversible finality |
| Reorganization | M08 with M06/M07 -> all clients | Chain state unwinds; local execution and revocation history does not |
| Model commons | M09/M10/M11 -> M12/M14/Hepta | Real parameter availability, compatibility, whole-model gain and local adoption are separate |
| Reward and public use | M12 with M10/M11 | Finite mining/model/service budgets; funded free basic access, not unlimited GPU supply |
| Evidence | All -> M17 | Exact source, work security, actual runtime and future-model efficacy have different acceptance |

## Source ownership and retained supplements

[Technical reference](TRNM_MODULE_TECHNICAL_REFERENCE_V1.md) and
[implementation guide](TRNM_MODULE_IMPLEMENTATION_GUIDE_V1.md) keep all M00-M17 source
traces. [Coverage](../../config/module-coverage-v1.toml) maps every current crate to its
actual owner; [target contract](../../config/pon-nakamoto-v1.json) binds new responsibilities
without pretending the Cargo graph changed. The [acceptance matrix](TRNM_MODULE_IMPLEMENTATION_ACCEPTANCE_MATRIX_V1.md),
[foundation operations](TRNM_FOUNDATION_OPERATION_CONTRACTS_V1.md),
[closure design](TRNM_TARGET_CLOSURE_DESIGN_V1.md) and other retained supplements carry
explicit legacy applicability where they describe old stored operations or signatures.

New acceptance includes independent work/canonical encoders, deeper higher-work forks,
every reorg crash cut, external-effect reconciliation, compatible real trained experts,
whole-model composition, future-window free consumption and exact reward conservation.
The existing representative operation traces remain legacy regressions, not PoN passes.
