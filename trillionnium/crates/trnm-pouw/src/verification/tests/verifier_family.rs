use super::*;
use super::support::mock_task;

#[test]
fn test_mock_verifier_success() {
    let verifier = MockVerifier::new("fraud", true);
    let task = mock_task();
    let result = verifier.verify_proof(&task, &[]);
    assert_eq!(result, VerificationResult::Valid);
    assert_eq!(verifier.proof_type(), "fraud");
}

#[test]
fn test_mock_verifier_failure() {
    let verifier = MockVerifier::new("zk", false);
    let task = mock_task();
    let result = verifier.verify_proof(&task, &[]);
    assert!(matches!(result, VerificationResult::Invalid(msg) if msg.contains("zk")));
}
