use super::*;
use super::support::mock_task;
use trnm_types::ProofType;

#[test]
fn verification_receipt_json_roundtrip_preserves_fields() {
    let receipt = VerificationReceipt::new(
        42,
        "tee",
        VerificationResult::Valid,
        "tee-sgx-sim",
        1_706_000_000_000,
    );

    let encoded = serde_json::to_string(&receipt).expect("serialize receipt");
    let decoded: VerificationReceipt = serde_json::from_str(&encoded).expect("deserialize receipt");

    assert_eq!(decoded, receipt);
}

#[test]
fn verification_receipt_new_normalizes_fields() {
    let receipt = VerificationReceipt::new(7, " TEE ", VerificationResult::Valid, "   ", 123);

    assert_eq!(receipt.task_id, 7);
    assert_eq!(receipt.proof_type, "tee");
    assert_eq!(receipt.verifier_id, "unknown-verifier");
    assert_eq!(receipt.timestamp_ms, 123);
}

#[test]
fn verification_receipt_new_defaults_unknown_proof_type_when_blank() {
    let receipt = VerificationReceipt::new(
        9,
        " \n\t ",
        VerificationResult::Indeterminate("deferred".into()),
        "tee-verifier-1",
        456,
    );

    assert_eq!(receipt.proof_type, "unknown");
    assert_eq!(receipt.verifier_id, "tee-verifier-1");
    assert!(matches!(
        receipt.result,
        VerificationResult::Indeterminate(msg) if msg == "deferred"
    ));
}

#[test]
fn proof_type_key_returns_canonical_router_keys() {
    assert_eq!(proof_type_key(ProofType::Fraud), "fraud");
    assert_eq!(proof_type_key(ProofType::Tee), "tee");
    assert_eq!(proof_type_key(ProofType::Zk), "zk");
}

#[test]
fn verification_receipt_from_task_uses_canonical_proof_key_and_task_id() {
    let mut task = mock_task();
    task.task_id = 77;
    task.proof_type = ProofType::Tee;

    let receipt =
        VerificationReceipt::from_task(&task, VerificationResult::Valid, " tee-verifier ", 789);

    assert_eq!(receipt.task_id, 77);
    assert_eq!(receipt.proof_type, "tee");
    assert_eq!(receipt.verifier_id, "tee-verifier");
    assert_eq!(receipt.timestamp_ms, 789);
    assert_eq!(receipt.result, VerificationResult::Valid);
}
