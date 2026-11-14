//! Isolated codec interoperability fixture; no optimizer, evaluator or daemon runs.
//! The two library crates and native-codec.rs are unchanged f97f3c90 Git blobs.
use codex_hepta_learning_artifacts::*;
use codex_hepta_types::{Digest32, StableId};
use serde_json::json;

#[derive(Debug)]
pub enum LearningIterationCheckpointErrorV1 {
    Capacity,
    InvalidRecord,
    Snapshot(LearningIterationError),
}

// The error carrier above is test plumbing. Every encoding/decoding byte and
// state transition below comes from the original codec/coordinator source.
#[path = "../../native-codec.rs"]
mod codec;

fn id(value: &str) -> StableId {
    StableId::new(value).unwrap()
}
fn digest(value: &str) -> Digest32 {
    Digest32::of_bytes(value.as_bytes())
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn encoded(coordinator: &LearningIterationCoordinatorV1) -> Vec<u8> {
    let raw = codec::encode(coordinator.snapshot()).unwrap();
    assert_eq!(codec::decode(&raw).unwrap(), *coordinator.snapshot());
    raw
}
fn append(
    coordinator: &mut LearningIterationCoordinatorV1,
    scope: &FrozenLearningScopeV2,
    observation: LearningIterationObservationV1,
    evidence_name: &str,
) -> String {
    let snapshot = coordinator.snapshot();
    let receipt = LearningIterationReceiptV1 {
        operation_id: snapshot.request.operation_id.clone(),
        predecessor: snapshot.head_digest,
        actor_id: snapshot.owners.owner(observation.stage()).clone(),
        evidence_digest: digest(evidence_name),
        observed_unix_seconds: 100,
        observation,
    };
    scope.validate_observation(&receipt.observation).unwrap();
    let signing = learning_iteration_receipt_signing_bytes_v1(&receipt).unwrap();
    coordinator.record(receipt, 100).unwrap();
    scope.validate_snapshot(coordinator.snapshot()).unwrap();
    assert_eq!(Digest32::of_bytes(&signing), coordinator.snapshot().head_digest);
    hex(&signing)
}

fn main() {
    let path = std::env::args().nth(1).expect("original initial checkpoint path");
    let original = std::fs::read(path).unwrap();
    let mut initial = codec::decode(&original).unwrap();
    assert!(initial.receipts.is_empty());
    initial.request.operation_id = id("chain-heplcp03-codec-fixture-v1");
    initial.request.source_run_id = id("chain-heplcp03-source-fixture");
    initial.request.completed_task_receipt = digest("chain-heplcp03-source-task-fixture");
    let mut coordinator = LearningIterationCoordinatorV1::new(initial.request, initial.owners).unwrap();
    let baseline = coordinator.snapshot().request.selected_bundle.digest().unwrap();
    let rule = digest("chain-heplcp03-update-rule-fixture");
    let dataset = digest("chain-heplcp03-dataset-fixture");
    let episode = digest("chain-heplcp03-episode-fixture");
    let selection = digest("chain-heplcp03-selection-fixture");
    let scope = FrozenLearningScopeV2::freeze(
        &coordinator.snapshot().request, &coordinator.snapshot().owners,
        LearningUpdateScopeV2::Cell, rule,
    ).unwrap();
    let initial_raw = encoded(&coordinator);
    let initial_head = coordinator.snapshot().head_digest;
    let mut signing_payloads = Vec::new();
    let completed_task_receipt = coordinator.snapshot().request.completed_task_receipt;
    signing_payloads.push(append(&mut coordinator, &scope,
        LearningIterationObservationV1::Experience { episode_digest: episode, completed_task_receipt },
        "chain-heplcp03-experience-evidence-fixture"));
    signing_payloads.push(append(&mut coordinator, &scope,
        LearningIterationObservationV1::Dataset { snapshot_digest: dataset, episode_digest: episode,
            withdrawal_frontier: digest("chain-heplcp03-withdrawal-fixture"), rows: 1, bytes: 16 },
        "chain-heplcp03-dataset-evidence-fixture"));
    let dataset_raw = encoded(&coordinator);
    signing_payloads.push(append(&mut coordinator, &scope,
        LearningIterationObservationV1::TrainingNoUpdateV2(LearningTrainingNoUpdateV2 {
            retained_bundle: baseline, dataset, update_rule: rule, steps: 2, milliseconds: 10,
            reason: LearningTrainingNoUpdateReasonV2::QuantizedWeightsUnchanged,
        }), "chain-heplcp03-training-evidence-fixture"));
    assert!(coordinator.candidate().is_none());
    assert_eq!(coordinator.next_stage(), Some(LearningIterationStageV1::Selection));
    assert_eq!(coordinator.disposition(), LearningIterationDispositionV1::NoUpdate);
    let training_raw = encoded(&coordinator);
    signing_payloads.push(append(&mut coordinator, &scope,
        LearningIterationObservationV1::Selection { candidate_bundle: baseline, selection_digest: selection },
        "chain-heplcp03-selection-evidence-fixture"));
    let selection_raw = encoded(&coordinator);
    let request = &coordinator.snapshot().request;
    let partition = CellStatePartitionV1 { principal_id: request.principal_id.clone(),
        agent_id: request.agent_id.clone(), cell_id: request.cell_id.clone(),
        run_id: id("chain-heplcp03-next-task-fixture") };
    signing_payloads.push(append(&mut coordinator, &scope,
        LearningIterationObservationV1::RetainedModelNextUse {
            retained_bundle: baseline, state_partition: partition,
            checkpoint_digest: digest("chain-heplcp03-checkpoint-fixture"), selection_digest: selection,
            committed_step_receipt: digest("chain-heplcp03-step-fixture"),
            task_owner_publication: digest("chain-heplcp03-publication-fixture"),
        }, "chain-heplcp03-next-use-evidence-fixture"));
    assert_eq!(coordinator.next_stage(), None);
    assert_eq!(coordinator.disposition(), LearningIterationDispositionV1::UsedByNextTask);
    let completed_raw = encoded(&coordinator);
    println!("{}", json!({
        "schema": "trnm-heplcp03-native-codec-fixture-v1",
        "scope": "exact-native-codec-and-coordinator-engineering-fixture-only",
        "hepta_source_commit": "f97f3c90ac1ac3d5171fd9f25b3e34431f44a367",
        "original_initial_sha256": Digest32::of_bytes(&original).to_string(),
        "initial_hex": hex(&initial_raw), "dataset_hex": hex(&dataset_raw),
        "training_hex": hex(&training_raw), "selection_hex": hex(&selection_raw),
        "completed_hex": hex(&completed_raw), "initial_head": initial_head.to_string(),
        "completed_head": coordinator.snapshot().head_digest.to_string(),
        "selected_bundle": baseline.to_string(), "update_rule": rule.to_string(),
        "scope_binding": scope.binding().to_string(), "receipt_signing_payloads_hex": signing_payloads,
        "native_roundtrip_verified": true, "ordinary_task_executed": false,
        "actual_training_executed": false, "evaluation_executed": false,
        "actual_next_use_executed": false, "hepta_final_use_accepted": false,
        "production_activation": false, "qualification": "HOLD_NO_GO"
    }));
}
