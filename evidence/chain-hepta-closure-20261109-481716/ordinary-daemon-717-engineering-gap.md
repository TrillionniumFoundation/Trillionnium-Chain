# Fixed Hepta 717 ordinary-daemon implementation handoff

## Disposition and source

The fixed source candidate is `71738345326b98d88b738250d2b84ecbcb466eb8` (PR #5509), tree `bfd8384241bf09fcf79daa94f2ef9c9438f92ee4`. The ordinary authenticated-task / learning / selected next-task / cold-daemon-recovery chain is **NOT_ESTABLISHED**. Configuration alone cannot complete this chain: the shipped main does not construct the concrete ordinary task and learning-stage owners required by its existing production interfaces. This is an implementation and deployment-material gap, not a missing report field.

This note reads committed source at that exact SHA. It does not use either mirror's dirty working files. Actual-model/native execution evidence remains bound to `f070113bb61cda492d2668b3afbbcda13e11fa52`; it is not a binary execution of the delivered 717 commit. Production binary, model, loader, evaluator and independent deployment evidence remain absent where the candidate manifest records null.

## Smallest production composition seam

`codex-rs/hepta-agentd/src/main.rs` receives `(config, production)` from `AgentdProductionStartup::receive`, loads the existing explicit runtime configuration, and eventually calls `launch.run(config, arg0_paths)` or `run(config, arg0_paths)`. It never calls `with_root_learning_stage_owners` or `with_circuit_task_bootstrap`.

The next implementation belongs in an explicit admitted-host composition at that boundary, before `launch.run` / `run`. Reuse `AgentdConfig::with_root_learning_stage_owners(stages, verifier, capacity)` in `config_root_learning.rs`: it consumes the received original Root learning inputs, uses `AgentdLearningCheckpointClientV1::with_stage_owners`, and retains the original scoped request/checkpoint. Do not construct a second checkpoint writer or register a replacement operation.

`AgentdProductionLaunch::run` and `runtime::run_with_shutdown` already call `require_root_learning_assembled`. The latter also requires the governed plasticity owner and an ordinary Circuit task profile for Circuit learning delivery. Those checks must remain. `production_launcher_inputs.rs::{Profile, PrimaryInputs}` currently enumerates only Android, Notes and Desktop. A supported ordinary Circuit entry needs explicit production composition and admission; a new flag by itself cannot supply executable owners or their capabilities. `config_circuit_task.rs` deliberately rejects mixtures with incompatible Notes/Desktop/thread/intelligence profiles.

## Concrete work to connect existing owners

| Responsibility | Existing production seam / owner API | Remaining implementation |
| --- | --- | --- |
| Ordinary task and durable result | `state_circuit_task.rs`: `AgentdCircuitTaskInvocationProviderV1::{build,publish_result}`, `AgentdState::execute_circuit_task_record`; `config_circuit_task.rs`: `AgentdConfig::with_circuit_task_bootstrap` | Implement the host's stable task mapping and idempotent original result publisher. ACK retry must reuse the same committed result, not start another inference. The in-repository concrete `Invocation` is in `circuit_task_ingress_tests.rs`. |
| Exact input and actual inference | `circuit_task.rs`: `CircuitTaskInputProviderV1::resolve`; `circuit_task_runtime.rs`: `circuit_task_channel_v1`; existing `CircuitCellRepresentationEncoderV1` | Supply real `CellStateOwnerV1`, `NeuronInferenceControlPort + CellInferenceReadbackPortV1`, input encoder, clock and durable input owner. Prepare records exact task bytes, source frontier, clocks and masks; Readback reopens that record after restart. The concrete `Inputs` implementations are test fixtures. The research `ProcessControl` implements Generation V2, not the Feature V1 ports required here. |
| Experience, dataset, training, evaluation | `learning_iteration_ports.rs`: `LearningIterationStageOwnerPortsV1::execute_stage` | Implement a non-test adapter to original owners for the same operation. Bind actual completed task, dataset/frontier, trainer job, frozen update scope, candidate artifact and evaluator profile. Reconcile an existing trainer/evaluator job on retry; do not mutate CURRENT during training or resubmit under a fresh operation after uncertainty. `StageOwners` in `learning_iteration_checkpoint_ports_tests.rs` is a fixture, not this implementation. |
| Authenticated proposal | `LearningIterationStageOwnerPortsV1::prepare_proposal`; `learning_iteration_proposal.rs::submit_iteration_proposal_v1`; `AgentdState::{submit_parameter_plasticity_v1,submit_topology_plasticity_v1}` | Resolve the actual authenticated candidate/evaluation and return a supported production payload tied to the exact snapshot head. Production payloads are Parameter and Topology. `ResearchExternalTrainedArtifact` is explicitly `cfg(all(test, unix))`; it cannot be promoted by wiring the research process into main. |
| Evaluation and original evidence | `neuron_cell_evaluation.rs`: `freeze_cell_evaluation_plan_v1`, `CellEvaluationRunnerV1::{evaluate,qualification_bundle,qualify_and_persist}` | Connect the actual final-holdout provider/CAS, original candidate/baseline journals, pinned evaluator trust and durable qualification sink. These APIs already perform binding and qualification; a locally generated matching digest or synthetic attestation does not replace their evidence. |
| Selection, installation and distinct next use | `neuron_generation_update.rs`: `prepare_agentd_generation_update_v1`, `prepare_agentd_generation_same_model_task_v1`, `PreparedAgentdGenerationUpdateV1::publish`; `neuron_generation_update_learning.rs`: `ReadyAgentdGenerationUpdateV1::{read_learning_selection,read_learning_next_use}` | Supply the production caller connecting the actual learning decision to original CURRENT, then dispatch a distinct ordinary task through the admitted owner. Selection/NextUse stage receipts are observations of those original owners. NoUpdate retains the baseline but still needs real Selection and committed distinct NextUse. No production FinalUse follows merely from these API names or a completed join. |
| Attestation and cold recovery | `LearningIterationStageOwnerPortsV1::{receipt_attestation,validate_recovery}`; `learning_iteration_checkpoint_ports.rs::CheckpointedIterationPorts` | Resolve authentic original stage signers/readback capabilities and independently current trust, revocation/withdrawal and owner heads. Reopen the same protected checkpoint and owner stores after an actual daemon restart. Recheck empty, NoUpdate and completed snapshots; proposal must reconcile its durable owner/anchor. Do not renew deadlines, re-sign historical work or substitute the current model. |

The four methods on the existing stage-owner trait are the implementation contract. A new report interface or a fixture implementation would not close any row above.

## Ordering constraint for the first real operation

Complete the ordinary source task first. Freeze/register its exact actual completion receipt with the original owner, then recover the durable outbox from original Objective and Automation journals. Do not predict a future completion hash or rerun the source task to make one fit.

`circuit_learning_delivery.rs::{deliver_circuit_learning_v1,reconcile_circuit_learning_v1}` already bind the original operation, completed-task receipt, objective and initial request head. A durable claim permits only readback. Missing or partial backend checkpoint remains `CommitUncertain`; absence is not proof of no work and must not authorize automatic replay. NoUpdate without committed distinct NextUse remains incomplete. A future resume mechanism, if necessary, needs original-owner admission/fencing or verifiable not-started evidence rather than weakened replay rules.

## Why the retained executions do not close this work

`neuron_generation_real_learning_tests.rs::ResearchPorts` implements the full `LearningIterationOwnerPortsV1`, owns a local research checkpoint and uses `ResearchTrust` plus generation-publication `test_support::Fixture`. It is not the concrete production `LearningIterationStageOwnerPortsV1` assembled through the received Root capability. Its process port is explicitly research Generation V2. Its external-trained-artifact proposal path is test-only.

The retained actual-model run exercised real optimizer/model work and a NoUpdate outcome; its result explicitly records `native_daemon_os_restart=false`, `research_keys_and_custody=true`, `independent_operator_custody=false`, `production_root_capability=false`, `production_final_use=false`, `production_activation=false`, and `HOLD_NO_GO`. Reopened workers/generation owners are useful scoped evidence but do not constitute ordinary daemon OS restart and independent production custody. The separate Root tests use synthetic qualification custody; concatenating their receipts with model-run receipts does not create one deployed operation.

The deployed original Root writer/checkpoint capability and lifetime, actual AuthBus trust/replay/objective/source frontier, selected model CURRENT/material, original authorized stage signers/readback owners and independent selector/observer/witness material are still required. These capabilities cannot be created from JSON declarations or copied research receipts.

## Immutable source references

All links below point to the fixed source, not a moving branch:

- [Ordinary binary main](https://github.com/TrillionniumFoundation/hepta-private-ci/blob/71738345326b98d88b738250d2b84ecbcb466eb8/codex-rs/hepta-agentd/src/main.rs), blob `133a0c12daa683e16cdb79f902dea88092ebfb52`.
- [Root learning composition](https://github.com/TrillionniumFoundation/hepta-private-ci/blob/71738345326b98d88b738250d2b84ecbcb466eb8/codex-rs/hepta-agentd/src/config_root_learning.rs), blob `792703744b84ab6df841035f1e6652e3c7bd71ad`.
- [Stage-owner contract](https://github.com/TrillionniumFoundation/hepta-private-ci/blob/71738345326b98d88b738250d2b84ecbcb466eb8/codex-rs/hepta-agentd/src/learning_iteration_ports.rs), blob `eb4e26648b44fe57bb5e21d6b3f84d3f7bac8220`.
- [Ordinary Circuit task profile](https://github.com/TrillionniumFoundation/hepta-private-ci/blob/71738345326b98d88b738250d2b84ecbcb466eb8/codex-rs/hepta-agentd/src/config_circuit_task.rs), blob `585796c337eda12b490fc72a69337d8c4ca40db4`.
- [Root launcher profiles](https://github.com/TrillionniumFoundation/hepta-private-ci/blob/71738345326b98d88b738250d2b84ecbcb466eb8/codex-rs/hepta-agentd/src/production_launcher_inputs.rs), blob `707345d2cab002009f3f46466e77bf7f9c7bce02`.
- [Original proposal submission](https://github.com/TrillionniumFoundation/hepta-private-ci/blob/71738345326b98d88b738250d2b84ecbcb466eb8/codex-rs/hepta-agentd/src/learning_iteration_proposal.rs), blob `c013194e0c652e25782db1f68ab4b580d70447d4`.
- [Durable learning delivery](https://github.com/TrillionniumFoundation/hepta-private-ci/blob/71738345326b98d88b738250d2b84ecbcb466eb8/codex-rs/hepta-agentd/src/circuit_learning_delivery.rs), blob `b4b6aec41ee13e6aa983145bba633b276344b473`.
- [Actual-model research implementation and explicit limits](https://github.com/TrillionniumFoundation/hepta-private-ci/blob/71738345326b98d88b738250d2b84ecbcb466eb8/codex-rs/hepta-agentd/src/neuron_generation_real_learning_tests.rs), blob `800354c9857a6afe89f032dd5cabbbf5fef3cb6a`.
- [Published qualification inventory, `full_P0`](https://github.com/TrillionniumFoundation/hepta-private-ci/blob/71738345326b98d88b738250d2b84ecbcb466eb8/qualification/cell-common-20261109-e1c98/CURRENT.json), blob `1e41d32b3453b5cc48063a930c12c77bc32d6c44`.

No production code was changed for this handoff. It defines the next concrete implementation; it does not qualify that implementation or promote source-level checks into deployment evidence.
