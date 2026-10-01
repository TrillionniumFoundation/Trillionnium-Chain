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
| M02 | [M02_CONSENSUS_CORE_TECHNICAL_SPEC_V1.md](M02_CONSENSUS_CORE_TECHNICAL_SPEC_V1.md) | `trnm-pon-node` development component; full public target incomplete |
| M03 | [M03_SAFETY_SIGNER_TECHNICAL_SPEC_V1.md](M03_SAFETY_SIGNER_TECHNICAL_SPEC_V1.md) | `trnm-checkpoint-store`, `trnm-checkpoint-types` |
| M04 | [M04_P2P_TECHNICAL_SPEC_V1.md](M04_P2P_TECHNICAL_SPEC_V1.md) | `trnm-peer-lease`, `trnm-transport`, `trnm-pon-node` development ingress |
| M05 | [M05_TX_LIFECYCLE_TECHNICAL_SPEC_V1.md](M05_TX_LIFECYCLE_TECHNICAL_SPEC_V1.md) | `trnm-mempool` |
| M06 | [M06_EXECUTION_TECHNICAL_SPEC_V1.md](M06_EXECUTION_TECHNICAL_SPEC_V1.md) | `trnm-executor`, `trnm-mvcc-fee` |
| M07 | [M07_STATE_STORAGE_TECHNICAL_SPEC_V1.md](M07_STATE_STORAGE_TECHNICAL_SPEC_V1.md) | `trnm-pon-node` development component; full public target incomplete |
| M08 | [M08_FINALITY_RECOVERY_TECHNICAL_SPEC_V1.md](M08_FINALITY_RECOVERY_TECHNICAL_SPEC_V1.md) | `trnm-pon-node` development component; full public target incomplete |
| M09 | [M09_DATA_AVAILABILITY_TECHNICAL_SPEC_V1.md](M09_DATA_AVAILABILITY_TECHNICAL_SPEC_V1.md) | `trnm-data-availability` |
| M10 | [M10_AGENT_MARKET_TECHNICAL_SPEC_V1.md](M10_AGENT_MARKET_TECHNICAL_SPEC_V1.md) | `trnm-worker-agent`, `trnm-research-protocol`, `trnm-task-kernel` |
| M11 | [M11_VERIFICATION_CHALLENGE_TECHNICAL_SPEC_V1.md](M11_VERIFICATION_CHALLENGE_TECHNICAL_SPEC_V1.md) | `trnm-oracle`, `trnm-verification-profiles` |
| M12 | [M12_SETTLEMENT_TECHNICAL_SPEC_V1.md](M12_SETTLEMENT_TECHNICAL_SPEC_V1.md) | `trnm-service-settlement`, `trnm-escrow-vault` |
| M13 | [M13_STATE_SYNC_MIGRATION_TECHNICAL_SPEC_V1.md](M13_STATE_SYNC_MIGRATION_TECHNICAL_SPEC_V1.md) | `trnm-state-import` |
| M14 | [M14_CLIENT_PLATFORM_TECHNICAL_SPEC_V1.md](M14_CLIENT_PLATFORM_TECHNICAL_SPEC_V1.md) | `trnm-pon-node` development component; full public target incomplete |
| M15 | [M15_NODE_RELEASE_TECHNICAL_SPEC_V1.md](M15_NODE_RELEASE_TECHNICAL_SPEC_V1.md) | `trnm-release-bundle`, `trnm-pon-node` development composition |
| M16 | [M16_CONTROL_PLANE_TECHNICAL_SPEC_V1.md](M16_CONTROL_PLANE_TECHNICAL_SPEC_V1.md) | `trnm-control-plane` |
| M17 | [M17_EVIDENCE_SECURITY_TECHNICAL_SPEC_V1.md](M17_EVIDENCE_SECURITY_TECHNICAL_SPEC_V1.md) | `trnm-bench`, `trnm-audit-events` |

## Executable detail and maturity

[38 typed procedures](../../config/pon/module-contracts-v1.json) bind all18 modules to
exact shared wire, work, state/recovery, model/evaluation and network/acceptance details.
[Per-module maturity](../../config/pon/module-maturity-v1.json) separates documented,
native component, executable reference, native product integration and independent acceptance.
Empty native source does not mean the design lacks executable conformance, nor does a
reference implementation mean the native production owner has been completed.

## Invariants, not document counts

[Concrete invariant and failure schedules](../../config/pon/invariants-v2.json) bind every module to actual test functions and source. Binding verification is not a test pass. M06 contains the historical twelve-command core
plus explicit profile-gated signed task13, native evaluation14..17 and lifecycle tags:
18 OPEN, 19 standalone RENEW only in V2, 20 REVOKE, 21 REGISTER, and 22 atomic renewal
in [V3](../protocol/pon-nakamoto-v1/details/QUALIFIED_TASK_LIFECYCLE_V3.md) and
[V4](../protocol/pon-nakamoto-v1/details/QUALIFIED_TASK_LIFECYCLE_V4.md).
V3/V4 refuse standalone19; V4 selects fresh revision9 signed-overlap semantics.
Historical parity measurements keep their original scope. The native development
composition adds M02 decisions, the distinct M07/M08 SQLite owner and signed private
ingress/outbox. It also implements an explicitly enabled [bounded local pool](../protocol/pon-nakamoto-v1/details/LOCAL_MEMPOOL_LIFECYCLE.md),
[finite continuous miner](../protocol/pon-nakamoto-v1/details/CONTINUOUS_MINING_V1.md),
[public-development V3 transaction intake](../protocol/pon-nakamoto-v1/details/PUBLIC_POOL_INTAKE_V3.md)
and [operator-pinned peer following](../protocol/pon-nakamoto-v1/details/PINNED_PEER_POLLING.md)
under that same owner. [Operator actors](../protocol/pon-nakamoto-v1/details/OPERATOR_ACTORS_V1.md)
and source/task profiles remain explicit fresh-context gates. These implemented development
components do not complete ordinary Hepta integration or independent qualification.
Open public discovery/gossip, confidential transport and public/WAN readiness remain
unqualified; bounded development networking does not supply those acceptances.

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
| [E3](../../evidence/pon-evaluation-bundle-v1/README.md) | Frozen evaluation, full consent, no adoption/reward, owned-host evaluation | Historical model observations on their recorded source; later client/session qualification does not rerun this experiment. |
| [Client](../../evidence/pon-client-confirmation-v1/README.md) | Receiver-verified history and confirmation on its original implementation | Historical after the native-session changes; component equality and observed selectors remain separate from current whole-runtime matching. |
| [Native session](../../evidence/pon-native-session-v1/README.md) | Bounded compute cache, incremental in-memory roots, early proof rejection and controlled receiver confirmation | Derive complete-runtime equality and executed selectors from this receipt. Neither in-memory state nor controlled confirmation establishes a full native node. |
| [Native-session work costs](../../evidence/pon-native-session-v1/work-cost/README.md) | New same-target native CPU measurements on a separately named clean source | Its cost verifier requires the measured input inventory to match; source freshness does not qualify fastest-adversary cost or public admission. |

The reporter never writes a new SHA into any historical report. Current PR/head/merge
checks for changed development tooling remain new observations, not old logs relabelled.

The [contract/tooling delivery](../../evidence/pon-contract-authority-v1/README.md) has its
own exact-source new test/cost observations, including a failed fixture preparation and
a successful same-source native rerun. It does not overwrite any historical runtime
package identity above or make current documentation edits into new model experiments.

The client and native-session qualifications are registered as `client_confirmation`
and `native_session` in the same maturity inventory. The former remains tied to its
original runtime; the latter covers the added cache, commitment and receiver changes.
Run the reporter to derive applicability for the actual checkout rather than treating
this navigation order or a package label as a current-source pass. Original model and
physical-host observations remain historical; neither receipt remeasures model benefit,
public consensus, physical power loss or ordinary Hepta integration.

## Native composition inventory clarification

`trnm-pon-node` is the M15 composition package and the native home of the previously
reference-only M02/M07/M08 and single-confirmation M14 responsibilities. Existing native
M00/M01/M06 are reused. Component presence, a development CLI, complete public-host
integration and independent acceptance remain separate facts. The responsibility map
binds the actual functions and exact native integration tests; no new roadmap exists.

The [native development receipt](../../evidence/pon-native-node-v1/README.md) is registered as `native_node` in the same reporter. It records the native owner, bounded CLI/socket batches and a separately replayed current model supplement; no historical package is repinned.
