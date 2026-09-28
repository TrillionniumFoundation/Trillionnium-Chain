# Trillionnium Chain module specifications

Selected target: `pon-nakamoto-v1`. Retired consensus source, protocols, launchers,
legacy appendices and jobs are removed; Git alone retains historical content.
[The sole plan](../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md),
[protocol suite](../protocol/pon-nakamoto-v1/README.md) and
[actual source inventory](../../config/portability-inventory-v1.json) govern this tree.

| Module | Technical specification | Native reusable packages (not product integration) |
|---|---|---|
| M00 | [M00_FOUNDATION_PROTOCOL_TECHNICAL_SPEC_V1.md](M00_FOUNDATION_PROTOCOL_TECHNICAL_SPEC_V1.md) | `trnm-types`, `trnm-protocol` |
| M01 | [M01_CRYPTO_IDENTITY_TECHNICAL_SPEC_V1.md](M01_CRYPTO_IDENTITY_TECHNICAL_SPEC_V1.md) | `trnm-crypto-primitives`, `trnm-governance-guard` |
| M02 | [M02_CONSENSUS_CORE_TECHNICAL_SPEC_V1.md](M02_CONSENSUS_CORE_TECHNICAL_SPEC_V1.md) | None; target unimplemented |
| M03 | [M03_SAFETY_SIGNER_TECHNICAL_SPEC_V1.md](M03_SAFETY_SIGNER_TECHNICAL_SPEC_V1.md) | `trnm-checkpoint-store`, `trnm-checkpoint-types` |
| M04 | [M04_P2P_TECHNICAL_SPEC_V1.md](M04_P2P_TECHNICAL_SPEC_V1.md) | `trnm-peer-lease`, `trnm-transport` |
| M05 | [M05_TX_LIFECYCLE_TECHNICAL_SPEC_V1.md](M05_TX_LIFECYCLE_TECHNICAL_SPEC_V1.md) | `trnm-mempool` |
| M06 | [M06_EXECUTION_TECHNICAL_SPEC_V1.md](M06_EXECUTION_TECHNICAL_SPEC_V1.md) | `trnm-executor`, `trnm-mvcc-fee` |
| M07 | [M07_STATE_STORAGE_TECHNICAL_SPEC_V1.md](M07_STATE_STORAGE_TECHNICAL_SPEC_V1.md) | None; target unimplemented |
| M08 | [M08_FINALITY_RECOVERY_TECHNICAL_SPEC_V1.md](M08_FINALITY_RECOVERY_TECHNICAL_SPEC_V1.md) | None; target unimplemented |
| M09 | [M09_DATA_AVAILABILITY_TECHNICAL_SPEC_V1.md](M09_DATA_AVAILABILITY_TECHNICAL_SPEC_V1.md) | `trnm-data-availability` |
| M10 | [M10_AGENT_MARKET_TECHNICAL_SPEC_V1.md](M10_AGENT_MARKET_TECHNICAL_SPEC_V1.md) | `trnm-worker-agent`, `trnm-research-protocol`, `trnm-task-kernel` |
| M11 | [M11_VERIFICATION_CHALLENGE_TECHNICAL_SPEC_V1.md](M11_VERIFICATION_CHALLENGE_TECHNICAL_SPEC_V1.md) | `trnm-oracle`, `trnm-verification-profiles` |
| M12 | [M12_SETTLEMENT_TECHNICAL_SPEC_V1.md](M12_SETTLEMENT_TECHNICAL_SPEC_V1.md) | `trnm-service-settlement`, `trnm-escrow-vault` |
| M13 | [M13_STATE_SYNC_MIGRATION_TECHNICAL_SPEC_V1.md](M13_STATE_SYNC_MIGRATION_TECHNICAL_SPEC_V1.md) | `trnm-state-import` |
| M14 | [M14_CLIENT_PLATFORM_TECHNICAL_SPEC_V1.md](M14_CLIENT_PLATFORM_TECHNICAL_SPEC_V1.md) | None; target unimplemented |
| M15 | [M15_NODE_RELEASE_TECHNICAL_SPEC_V1.md](M15_NODE_RELEASE_TECHNICAL_SPEC_V1.md) | `trnm-release-bundle` |
| M16 | [M16_CONTROL_PLANE_TECHNICAL_SPEC_V1.md](M16_CONTROL_PLANE_TECHNICAL_SPEC_V1.md) | `trnm-control-plane` |
| M17 | [M17_EVIDENCE_SECURITY_TECHNICAL_SPEC_V1.md](M17_EVIDENCE_SECURITY_TECHNICAL_SPEC_V1.md) | `trnm-bench`, `trnm-audit-events` |

## Executable detail and maturity

[36 typed procedures](../../config/pon/module-contracts-v1.json) bind all18 modules to
exact shared wire, work, state/recovery, model/evaluation and network/acceptance details.
[Per-module maturity](../../config/pon/module-maturity-v1.json) separates documented,
native component, executable reference, native product integration and independent acceptance.
Empty native source does not mean the design lacks executable conformance, nor does a
reference implementation mean the native production owner has been completed.
