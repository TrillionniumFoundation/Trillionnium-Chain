use crate::verification::{ProofVerifier, VerificationResult};
use trnm_types::TaskObject;

use super::verify_bound_envelope;

pub struct TeeVerifier;

impl ProofVerifier for TeeVerifier {
    fn proof_type(&self) -> &str {
        "tee"
    }

    fn verify_proof(&self, task: &TaskObject, proof_data: &[u8]) -> VerificationResult {
        verify_bound_envelope(task, proof_data, b"TEE:", "TEE receipt")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use trnm_types::{ProofType, TaskObject, TaskStatus};

    fn mock_task() -> TaskObject {
        TaskObject {
            task_id: 42,
            creator: "alice".into(),
            bounty: 1,
            status: TaskStatus::Committed,
            proof_type: ProofType::Tee,
            metadata: None,
            worker: Some("worker1".into()),
            committed_hash: None,
            result_hash: Some([0xabu8; 32]),
            reveal_salt: None,
            committed_at_height: None,
            reveal_deadline_height: None,
            challenge_deadline_height: None,
            challenge_window_blocks_snapshot: None,
            challenged_at_height: None,
            resolve_deadline_height: None,
            challenge_bond: None,
            challenger: None,
            challenge_bond_forfeited: None,
            version: 1,
        }
    }

    #[test]
    fn tee_verifier_accepts_bound_task_id() {
        let verifier = TeeVerifier;
        let task = mock_task();

        assert_eq!(
            verifier.verify_proof(
                &task,
                b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,quote=abc"
            ),
            VerificationResult::Valid
        );
    }

    #[test]
    fn tee_verifier_rejects_task_id_mismatch() {
        let verifier = TeeVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(&task, b"TEE:task_id=99,worker=worker1,proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,quote=abc"),
            VerificationResult::Invalid(msg) if msg.contains("task_id mismatch")
        ));
    }

    #[test]
    fn tee_verifier_rejects_missing_task_id_binding() {
        let verifier = TeeVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(&task, b"TEE:quote=abc,nonce=1,proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab"),
            VerificationResult::Invalid(msg) if msg.contains("missing task_id binding")
        ));
    }

    #[test]
    fn tee_verifier_rejects_task_id_identifier_spoof() {
        let verifier = TeeVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"TEE:xtask_id=42,worker=worker1,proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,quote=abc"
            ),
            VerificationResult::Invalid(msg) if msg.contains("missing task_id binding")
        ));
    }

    #[test]
    fn tee_verifier_rejects_duplicate_task_id_binding_fail_closed() {
        let verifier = TeeVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"TEE:task_id=42,task_id=42,worker=worker1,proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,quote=abc"
            ),
            VerificationResult::Invalid(msg) if msg.contains("duplicate task_id binding")
        ));
    }

    #[test]
    fn tee_verifier_rejects_duplicate_task_id_binding_with_quoted_trailing_space_fail_closed() {
        let verifier = TeeVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"TEE:task_id=\"42 \",task_id=42,worker=worker1,proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,quote=abc"
            ),
            VerificationResult::Invalid(msg) if msg.contains("duplicate task_id binding")
        ));
    }

    #[test]
    fn tee_verifier_rejects_proof_type_mismatch_when_present() {
        let verifier = TeeVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(&task, b"TEE:task_id=42,worker=worker1,proof_type=zk,result_hash=abababababababababababababababababababababababababababababababab"),
            VerificationResult::Invalid(msg) if msg.contains("proof_type mismatch")
        ));
    }

    #[test]
    fn tee_verifier_rejects_missing_proof_type_binding() {
        let verifier = TeeVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(&task, b"TEE:task_id=42,worker=worker1,result_hash=abababababababababababababababababababababababababababababababab,quote=abc"),
            VerificationResult::Invalid(msg) if msg.contains("missing proof_type binding")
        ));
    }

    #[test]
    fn tee_verifier_rejects_case_variant_duplicate_proof_type_binding_fail_closed() {
        let verifier = TeeVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"TEE:task_id=42,worker=worker1,proof_type=tee,Proof_Type=tee,result_hash=abababababababababababababababababababababababababababababababab,quote=abc"
            ),
            VerificationResult::Invalid(msg) if msg.contains("duplicate proof_type binding")
        ));
    }

    #[test]
    fn tee_verifier_rejects_missing_result_hash_binding() {
        let verifier = TeeVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(&task, b"TEE:task_id=42,worker=worker1,proof_type=tee,quote=abc"),
            VerificationResult::Invalid(msg) if msg.contains("missing result_hash binding")
        ));
    }

    #[test]
    fn tee_verifier_rejects_result_hash_mismatch_fail_closed() {
        let verifier = TeeVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd,quote=abc"
            ),
            VerificationResult::Invalid(msg) if msg.contains("result_hash mismatch")
        ));
    }

    #[test]
    fn tee_verifier_rejects_case_variant_duplicate_result_hash_binding_fail_closed() {
        let verifier = TeeVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,Result_Hash=abababababababababababababababababababababababababababababababab,quote=abc"
            ),
            VerificationResult::Invalid(msg) if msg.contains("duplicate result_hash binding")
        ));
    }

    #[test]
    fn tee_verifier_rejects_unexpected_result_hash_binding_without_context_fail_closed() {
        let verifier = TeeVerifier;
        let mut task = mock_task();
        task.result_hash = None;

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,quote=abc"
            ),
            VerificationResult::Invalid(msg) if msg.contains("unexpected result_hash binding")
        ));
    }

    #[test]
    fn tee_verifier_rejects_missing_worker_binding() {
        let verifier = TeeVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(&task, b"TEE:task_id=42,proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,quote=abc"),
            VerificationResult::Invalid(msg) if msg.contains("missing worker binding")
        ));
    }

    #[test]
    fn tee_verifier_rejects_worker_binding_identifier_spoof() {
        let verifier = TeeVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"TEE:task_id=42,networker=worker1,proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,quote=abc"
            ),
            VerificationResult::Invalid(msg) if msg.contains("missing worker binding")
        ));
    }

    #[test]
    fn tee_verifier_rejects_worker_case_mismatch() {
        let verifier = TeeVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"TEE:task_id=42,worker=Worker1,proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,quote=abc"
            ),
            VerificationResult::Invalid(msg) if msg.contains("worker mismatch")
        ));
    }

    #[test]
    fn tee_verifier_rejects_duplicate_worker_binding_fail_closed() {
        let verifier = TeeVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,worker=worker1,quote=abc"
            ),
            VerificationResult::Invalid(msg) if msg.contains("duplicate worker binding")
        ));
    }

    #[test]
    fn tee_verifier_accepts_legacy_receipt_proof_type_alias() {
        let verifier = TeeVerifier;
        let task = mock_task();

        assert_eq!(
            verifier.verify_proof(
                &task,
                b"TEE:task_id=42,worker=worker1,proof_type=tee_receipt,result_hash=abababababababababababababababababababababababababababababababab,quote=abc"
            ),
            VerificationResult::Valid
        );
    }
}
