//! Exact native codec/coordinator interoperability; synthetic local policy/use.
use codex_hepta_learning_artifacts::*;
use codex_hepta_types::Digest32;
use serde_json::json;

#[derive(Debug)]
pub enum LearningIterationCheckpointErrorV1 {
    Capacity,
    InvalidRecord,
    Snapshot(LearningIterationError),
}
#[path = "../../native-codec.rs"]
mod codec;

fn digest(value: &str) -> Digest32 {
    Digest32::of_bytes(value.as_bytes())
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn encoded(c: &LearningIterationCoordinatorV1) -> String {
    let raw = codec::encode(c.snapshot()).unwrap();
    assert_eq!(codec::decode(&raw).unwrap(), *c.snapshot());
    hex(&raw)
}
fn append(c: &mut LearningIterationCoordinatorV1, scope: &FrozenLearningScopeV2,
          observation: LearningIterationObservationV1, name: &str) -> String {
    let s = c.snapshot();
    let receipt = LearningIterationReceiptV1 {
        operation_id: s.request.operation_id.clone(), predecessor: s.head_digest,
        actor_id: s.owners.owner(observation.stage()).clone(),
        evidence_digest: digest(name),
        observed_unix_seconds: s.receipts.last().unwrap().observed_unix_seconds,
        observation,
    };
    scope.validate_observation(&receipt.observation).unwrap();
    let bytes = learning_iteration_receipt_signing_bytes_v1(&receipt).unwrap();
    c.record(receipt.clone(), receipt.observed_unix_seconds).unwrap();
    scope.validate_snapshot(c.snapshot()).unwrap();
    assert_eq!(Digest32::of_bytes(&bytes), c.snapshot().head_digest);
    hex(&bytes)
}
fn main() {
    let original = std::fs::read(std::env::args().nth(1).expect("HEPLCP02 completed input")).unwrap();
    let source = codec::decode(&original).unwrap();
    assert_eq!(source.receipts.len(), 7);
    let mut cases = Vec::new();
    for choice in [LearningLocalDispositionV2::AdoptCandidate,
                   LearningLocalDispositionV2::DeferCandidate,
                   LearningLocalDispositionV2::RetainParent] {
        let mut c = LearningIterationCoordinatorV1::new(source.request.clone(), source.owners.clone()).unwrap();
        let initial = encoded(&c);
        let candidate = match &source.receipts[2].observation {
            LearningIterationObservationV1::Training { candidate, .. } => candidate.clone(),
            _ => panic!("original trained candidate required"),
        };
        let baseline = source.request.selected_bundle.digest().unwrap();
        let candidate_digest = candidate.digest().unwrap();
        let rule = candidate.training_lineage.as_ref().unwrap().update_rule;
        let scope = FrozenLearningScopeV2::freeze(&source.request, &source.owners,
                                                 LearningUpdateScopeV2::Cell, rule).unwrap();
        let mut payloads = Vec::new();
        for receipt in &source.receipts[..5] {
            payloads.push(hex(&learning_iteration_receipt_signing_bytes_v1(receipt).unwrap()));
            c.record(receipt.clone(), receipt.observed_unix_seconds).unwrap();
            scope.validate_snapshot(c.snapshot()).unwrap();
        }
        let proposal = encoded(&c);
        let selected = if choice == LearningLocalDispositionV2::AdoptCandidate {
            candidate_digest
        } else { baseline };
        let local = LearningIterationObservationV1::LocalDecisionV2(LearningLocalDecisionV2 {
            proposal_head: c.snapshot().head_digest, candidate_bundle: candidate_digest,
            selected_bundle: selected, policy_digest: digest("synthetic-local-policy-v4"),
            reason_digest: digest("synthetic-local-reason-v4"), disposition: choice,
        });
        payloads.push(append(&mut c, &scope, local, "synthetic-local-decision-evidence-v4"));
        assert_eq!(c.next_stage(), Some(LearningIterationStageV1::Selection));
        let decision = encoded(&c);
        let selection_digest = digest("synthetic-publication-selection-v4");
        payloads.push(append(&mut c, &scope, LearningIterationObservationV1::Selection {
            candidate_bundle: selected, selection_digest,
        }, "synthetic-selection-evidence-v4"));
        let selection = encoded(&c);
        let partition = match &source.receipts[6].observation {
            LearningIterationObservationV1::NextUse { state_partition, .. } => state_partition.clone(),
            _ => panic!("original next-use shape required"),
        };
        let next_use = if choice == LearningLocalDispositionV2::AdoptCandidate {
            LearningIterationObservationV1::NextUse {
                candidate_bundle: selected, state_partition: partition,
                checkpoint_digest: digest("synthetic-owner-checkpoint-v4"), selection_digest,
                committed_step_receipt: digest("synthetic-committed-step-v4"),
                state_cutover_receipt: digest("synthetic-state-cutover-v4"),
            }
        } else {
            LearningIterationObservationV1::RetainedModelNextUse {
                retained_bundle: selected, state_partition: partition,
                checkpoint_digest: digest("synthetic-owner-checkpoint-v4"), selection_digest,
                committed_step_receipt: digest("synthetic-committed-step-v4"),
                task_owner_publication: digest("synthetic-owner-publication-v4"),
            }
        };
        payloads.push(append(&mut c, &scope, next_use, "synthetic-next-use-evidence-v4"));
        assert_eq!(c.next_stage(), None);
        assert_eq!(c.disposition(), LearningIterationDispositionV1::UsedByNextTask);
        cases.push(json!({
            "choice": format!("{choice:?}"), "initial_hex": initial, "proposal_hex": proposal,
            "local_hex": decision, "selection_hex": selection, "completed_hex": encoded(&c),
            "completed_head": c.snapshot().head_digest.to_string(),
            "selected_bundle": selected.to_string(), "update_rule": rule.to_string(),
            "scope_binding": scope.binding().to_string(), "receipt_signing_payloads_hex": payloads,
        }));
    }
    println!("{}", json!({
        "schema": "trnm-heplcp04-native-codec-fixture-v1",
        "scope": "exact-native-codec-and-coordinator-engineering-fixture-only",
        "hepta_source_commit": "afd2c91b3b9ef75ab9a174e3af772ad322118f7a",
        "original_input_sha256": Digest32::of_bytes(&original).to_string(),
        "cases": cases, "native_roundtrip_verified": true,
        "ordinary_task_executed": false, "actual_training_executed": false,
        "evaluation_executed": false, "actual_next_use_executed": false,
        "hepta_final_use_accepted": false, "production_activation": false, "qualification": "HOLD_NO_GO"
    }));
}
