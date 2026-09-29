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

## Invariants, not document counts

[Concrete invariant and failure schedules](../../config/pon/invariants-v2.json) bind every module to actual test functions and source. Binding verification is not a test pass. M06 now contains native twelve-command execution; complete native consensus/persistence/Hepta host and independent acceptance remain absent.

## Responsibility and evidence

Module-level flags describe inventory, not percent complete. The existing
[module maturity file](../../config/pon/module-maturity-v1.json) now maps every registered
procedure to actual callable symbols, its controlled entrypoint, backend, persistent
owner, exact test selectors and remaining scope. `ordinary_product_entrypoint: null`
means the normal native product route has not been supplied. A reusable checkpoint,
release or import package does not fill that null. A specified-only responsibility may
name a prerequisite without pretending that prerequisite is the missing consumer.

Use the read-only reporter from a checkout with the declared evidence Git objects:

```bash
python3 scripts/ci/prepare_evidence_sources.py
python3 scripts/ci/report_module_evidence.py --module M08 --format markdown
python3 scripts/ci/report_module_evidence.py --format json
```

The report derives measured source identities from the original manifests and receipts,
checks their artifact hashes and original source bytes, and keeps these facts separate:

- **Subject bytes match:** only the explicitly named owner/entry/persistence source and
  installed parameters match. This is not a claim about all transitive dependencies.
- **Complete recorded runtime matches:** the recorded formal/native runtime, parameters
  and tracked/untracked candidate runtime inventory all match. Changed or newly added
  runtime code makes this false, even when a narrow subject stayed byte-identical.
- **Exact selectors observed:** the declared file invocation and exact class/method
  occur in a successful bounded receipt log. Missing/new selectors stay unobserved.

Empty selector lists mean no registered per-procedure execution claim. They are not a
pass. Campaign-specific results, such as author disappearance, training, network service
and physical-host cost, must still be read in their own artifacts and validated by the
existing package-specific checkers. This reporter does not reexecute those campaigns.
A current regression-support result requires all declared selectors and the complete
recorded runtime match; it never grants integration, independence or production use.

| Package | Actual retained scope | Current applicability |
|---|---|---|
| [v1](../../evidence/pon-v1/README.md) | Original work/model/ledger/network experiments, including failure | Historical only. Keep measured implementation separate from its original publication/archive source snapshot. |
| [v3](../../evidence/pon-v3/README.md) | Invariants, actual long history, work costs, controlled owned hosts | Derive byte comparisons; do not inherit its host or work measurements into changed inputs. |
| [v4](../../evidence/pon-v4/README.md) | Block-scoped native comparison and same-admin binary parity | Same source can support that recorded observation, not a newly measured machine or public TPS. |
| [E3](../../evidence/pon-evaluation-bundle-v1/README.md) | Frozen evaluation, full consent, no adoption/reward, owned-host evaluation | Compare the current source; no future-window or independent-operator authority. |

The reporter never writes a new SHA into any historical report. Current PR/head/merge
checks for changed development tooling remain new observations, not old logs relabelled.

The [contract/tooling delivery](../../evidence/pon-contract-authority-v1/README.md) has its
own exact-source new test/cost observations, including a failed fixture preparation and
a successful same-source native rerun. It does not overwrite any of the four runtime
package identities above or make current documentation edits into new model experiments.
