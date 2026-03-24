use super::*;
use super::support::mock_task;
use trnm_types::ProofType;

#[test]
fn proof_verification_observation_from_task_is_canonicalized() {
    let mut task = mock_task();
    task.task_id = 42;
    task.proof_type = ProofType::Tee;

    let observation = ProofVerificationObservation::from_task(
        &task,
        &VerificationResult::Indeterminate("backend timeout".into()),
        " tee-backend ",
        128,
        999,
    );

    assert_eq!(observation.task_id, 42);
    assert_eq!(observation.proof_type, "tee");
    assert_eq!(observation.verifier_id, "tee-backend");
    assert_eq!(observation.outcome, "indeterminate");
    assert_eq!(observation.payload_bytes, 128);
    assert_eq!(observation.timestamp_ms, 999);
}

#[test]
fn proof_verification_observation_labels_are_stable() {
    let mut task = mock_task();
    task.proof_type = ProofType::Zk;

    let observation =
        ProofVerificationObservation::from_task(&task, &VerificationResult::Valid, "", 64, 123);
    let labels = observation.labels();

    assert_eq!(labels.get("proof_type"), Some(&"zk".to_string()));
    assert_eq!(
        labels.get("verifier_id"),
        Some(&"unknown-verifier".to_string())
    );
    assert_eq!(labels.get("outcome"), Some(&"valid".to_string()));
}
