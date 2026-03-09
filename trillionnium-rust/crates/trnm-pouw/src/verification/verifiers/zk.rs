use crate::verification::{ProofVerifier, VerificationResult};
use trnm_types::TaskObject;

use super::verify_bound_envelope;

pub struct ZkVerifier;

impl ProofVerifier for ZkVerifier {
    fn proof_type(&self) -> &str {
        "zk"
    }

    fn verify_proof(&self, task: &TaskObject, proof_data: &[u8]) -> VerificationResult {
        let verification = verify_bound_envelope(task, proof_data, b"ZK:", "ZK proof");
        if matches!(verification, VerificationResult::Valid) && task.result_hash.is_none() {
            return VerificationResult::Invalid(
                "Invalid ZK proof envelope: missing task result_hash binding context".to_string(),
            );
        }

        verification
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use trnm_types::{ProofType, TaskObject, TaskStatus};

    fn mock_task() -> TaskObject {
        TaskObject {
            task_id: 99,
            creator: "alice".into(),
            bounty: 1,
            status: TaskStatus::Committed,
            proof_type: ProofType::Zk,
            metadata: None,
            worker: Some("worker-zk".into()),
            committed_hash: None,
            result_hash: Some([0x11; 32]),
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
    fn zk_verifier_accepts_bound_task_id() {
        let verifier = ZkVerifier;
        let task = mock_task();

        assert_eq!(
            verifier.verify_proof(
                &task,
                b"ZK:{\"task_id\":99,\"worker\":\"worker-zk\",\"proof_type\":\"zk\",\"result_hash\":\"1111111111111111111111111111111111111111111111111111111111111111\",\"proof\":\"...\"}"
            ),
            VerificationResult::Valid
        );
    }

    #[test]
    fn zk_verifier_accepts_legacy_proof_type_alias() {
        let verifier = ZkVerifier;
        let task = mock_task();

        assert_eq!(
            verifier.verify_proof(
                &task,
                b"ZK:task_id=99,worker=worker-zk,proof_type=zk_snark,result_hash=1111111111111111111111111111111111111111111111111111111111111111,proof=ok"
            ),
            VerificationResult::Valid
        );
    }

    #[test]
    fn zk_verifier_rejects_task_id_mismatch() {
        let verifier = ZkVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(&task, b"ZK:{\"task_id\":1,\"worker\":\"worker-zk\"}"),
            VerificationResult::Invalid(msg) if msg.contains("task_id mismatch")
        ));
    }

    #[test]
    fn zk_verifier_rejects_missing_task_id_binding() {
        let verifier = ZkVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(&task, b"ZK:{\"proof\":\"...\",\"public_inputs\":[1,2]}"),
            VerificationResult::Invalid(msg) if msg.contains("missing task_id binding")
        ));
    }

    #[test]
    fn zk_verifier_rejects_prefix_only_payload() {
        let verifier = ZkVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(&task, b"ZK:   \n\t"),
            VerificationResult::Invalid(msg) if msg.contains("Invalid ZK proof envelope")
        ));
    }

    #[test]
    fn zk_verifier_rejects_proof_type_mismatch_when_present() {
        let verifier = ZkVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"ZK:{\"task_id\":99,\"worker\":\"worker-zk\",\"proof_type\":\"fraud\",\"result_hash\":\"1111111111111111111111111111111111111111111111111111111111111111\"}"
            ),
            VerificationResult::Invalid(msg) if msg.contains("proof_type mismatch")
        ));
    }

    #[test]
    fn zk_verifier_rejects_missing_proof_type_binding_fail_closed() {
        let verifier = ZkVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"ZK:{\"task_id\":99,\"worker\":\"worker-zk\",\"result_hash\":\"1111111111111111111111111111111111111111111111111111111111111111\"}"
            ),
            VerificationResult::Invalid(msg) if msg.contains("missing proof_type binding")
        ));
    }

    #[test]
    fn zk_verifier_rejects_missing_result_hash_binding_when_expected() {
        let verifier = ZkVerifier;
        let mut task = mock_task();
        task.result_hash = Some([0x11; 32]);

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"ZK:{\"task_id\":99,\"worker\":\"worker-zk\",\"proof_type\":\"zk\"}"
            ),
            VerificationResult::Invalid(msg) if msg.contains("missing result_hash binding")
        ));
    }

    #[test]
    fn zk_verifier_rejects_result_hash_mismatch_fail_closed() {
        let verifier = ZkVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"ZK:{\"task_id\":99,\"worker\":\"worker-zk\",\"proof_type\":\"zk\",\"result_hash\":\"2222222222222222222222222222222222222222222222222222222222222222\",\"proof\":\"...\"}"
            ),
            VerificationResult::Invalid(msg) if msg.contains("result_hash mismatch")
        ));
    }

    #[test]
    fn zk_verifier_rejects_missing_worker_binding_when_worker_is_present() {
        let verifier = ZkVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(&task, b"ZK:{\"task_id\":99,\"proof_type\":\"zk\"}"),
            VerificationResult::Invalid(msg) if msg.contains("missing worker binding")
        ));
    }

    #[test]
    fn zk_verifier_rejects_worker_binding_identifier_spoof() {
        let verifier = ZkVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"ZK:{\"task_id\":99,\"networker\":\"worker-zk\",\"proof_type\":\"zk\",\"result_hash\":\"1111111111111111111111111111111111111111111111111111111111111111\"}"
            ),
            VerificationResult::Invalid(msg) if msg.contains("missing worker binding")
        ));
    }

    #[test]
    fn zk_verifier_rejects_worker_mismatch_when_worker_is_present() {
        let verifier = ZkVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"ZK:{\"task_id\":99,\"worker\":\"worker-evil\",\"proof_type\":\"zk\"}"
            ),
            VerificationResult::Invalid(msg) if msg.contains("worker mismatch")
        ));
    }

    #[test]
    fn zk_verifier_rejects_worker_case_mismatch_when_worker_is_present() {
        let verifier = ZkVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"ZK:{\"task_id\":99,\"worker\":\"WORKER-zk\",\"proof_type\":\"zk\",\"result_hash\":\"1111111111111111111111111111111111111111111111111111111111111111\"}"
            ),
            VerificationResult::Invalid(msg) if msg.contains("worker mismatch")
        ));
    }

    #[test]
    fn zk_verifier_rejects_missing_result_hash_binding_context_fail_closed() {
        let verifier = ZkVerifier;
        let mut task = mock_task();
        task.result_hash = None;

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"ZK:{\"task_id\":99,\"worker\":\"worker-zk\",\"proof_type\":\"zk\",\"proof\":\"...\"}"
            ),
            VerificationResult::Invalid(msg)
                if msg.contains("missing task result_hash binding context")
        ));
    }

    #[test]
    fn zk_verifier_rejects_duplicate_worker_binding_fail_closed() {
        let verifier = ZkVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"ZK:{\"task_id\":99,\"worker\":\"worker-zk\",\"Worker\":\"worker-zk\",\"proof_type\":\"zk\",\"result_hash\":\"1111111111111111111111111111111111111111111111111111111111111111\"}"
            ),
            VerificationResult::Invalid(msg)
                if msg.contains("duplicate worker binding")
        ));
    }

    #[test]
    fn zk_verifier_rejects_case_variant_duplicate_worker_binding_fail_closed() {
        let verifier = ZkVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"ZK:{\"task_id\":99,\"worker\":\"worker-zk\",\"WoRkEr\":\"worker-zk\",\"proof_type\":\"zk\",\"result_hash\":\"1111111111111111111111111111111111111111111111111111111111111111\"}"
            ),
            VerificationResult::Invalid(msg)
                if msg.contains("duplicate worker binding")
        ));
    }

    #[test]
    fn zk_verifier_rejects_duplicate_worker_binding_with_single_quoted_trailing_space_fail_closed()
    {
        let verifier = ZkVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"ZK:task_id=99,worker=worker-zk,'worker'='worker-zk ',proof_type=zk,result_hash=1111111111111111111111111111111111111111111111111111111111111111,proof=ok"
            ),
            VerificationResult::Invalid(msg)
                if msg.contains("duplicate worker binding")
        ));
    }

    #[test]
    fn zk_verifier_rejects_duplicate_worker_binding_with_single_quoted_leading_space_fail_closed() {
        let verifier = ZkVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"ZK:task_id=99,worker=worker-zk,'worker'=' worker-zk',proof_type=zk,result_hash=1111111111111111111111111111111111111111111111111111111111111111,proof=ok"
            ),
            VerificationResult::Invalid(msg)
                if msg.contains("duplicate worker binding")
        ));
    }

    #[test]
    fn zk_verifier_rejects_duplicate_worker_binding_with_double_quoted_alias_fail_closed() {
        let verifier = ZkVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"ZK:task_id=99,worker=worker-zk,\"worker\"=worker-zk,proof_type=zk,result_hash=1111111111111111111111111111111111111111111111111111111111111111,proof=ok"
            ),
            VerificationResult::Invalid(msg)
                if msg.contains("duplicate worker binding")
        ));
    }

    #[test]
    fn zk_verifier_rejects_duplicate_worker_binding_with_unclosed_quoted_alias_fail_closed() {
        let verifier = ZkVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"ZK:task_id=99,worker=worker-zk,\"worker=worker-zk,proof_type=zk,result_hash=1111111111111111111111111111111111111111111111111111111111111111,proof=ok"
            ),
            VerificationResult::Invalid(msg)
                if msg.contains("duplicate worker binding")
        ));
    }

    #[test]
    fn zk_verifier_rejects_duplicate_proof_type_binding_fail_closed() {
        let verifier = ZkVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"ZK:{\"task_id\":99,\"worker\":\"worker-zk\",\"proof_type\":\"zk\",\"proof_type\":\"zk\",\"result_hash\":\"1111111111111111111111111111111111111111111111111111111111111111\"}"
            ),
            VerificationResult::Invalid(msg)
                if msg.contains("duplicate proof_type binding")
        ));
    }

    #[test]
    fn zk_verifier_rejects_case_variant_duplicate_proof_type_binding_fail_closed() {
        let verifier = ZkVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"ZK:{\"task_id\":99,\"worker\":\"worker-zk\",\"proof_type\":\"zk\",\"Proof_Type\":\"zk\",\"result_hash\":\"1111111111111111111111111111111111111111111111111111111111111111\"}"
            ),
            VerificationResult::Invalid(msg)
                if msg.contains("duplicate proof_type binding")
        ));
    }

    #[test]
    fn zk_verifier_rejects_duplicate_proof_type_binding_with_quoted_trailing_space_fail_closed() {
        let verifier = ZkVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"ZK:{\"task_id\":99,\"worker\":\"worker-zk\",\"proof_type\":\"zk \",\"proof_type\":\"zk\",\"result_hash\":\"1111111111111111111111111111111111111111111111111111111111111111\"}"
            ),
            VerificationResult::Invalid(msg)
                if msg.contains("duplicate proof_type binding")
        ));
    }

    #[test]
    fn zk_verifier_rejects_duplicate_proof_type_binding_with_quoted_leading_space_fail_closed() {
        let verifier = ZkVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"ZK:{\"task_id\":99,\"worker\":\"worker-zk\",\"proof_type\":\" zk\",\"proof_type\":\"zk\",\"result_hash\":\"1111111111111111111111111111111111111111111111111111111111111111\"}"
            ),
            VerificationResult::Invalid(msg)
                if msg.contains("duplicate proof_type binding")
        ));
    }

    #[test]
    fn zk_verifier_rejects_duplicate_proof_type_binding_with_single_quoted_trailing_space_fail_closed(
    ) {
        let verifier = ZkVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"ZK:task_id=99,worker=worker-zk,proof_type='zk ',proof_type=zk,result_hash=1111111111111111111111111111111111111111111111111111111111111111,proof=ok"
            ),
            VerificationResult::Invalid(msg)
                if msg.contains("duplicate proof_type binding")
        ));
    }

    #[test]
    fn zk_verifier_rejects_duplicate_proof_type_binding_with_single_quoted_leading_space_fail_closed(
    ) {
        let verifier = ZkVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"ZK:task_id=99,worker=worker-zk,proof_type=' zk',proof_type=zk,result_hash=1111111111111111111111111111111111111111111111111111111111111111,proof=ok"
            ),
            VerificationResult::Invalid(msg)
                if msg.contains("duplicate proof_type binding")
        ));
    }

    #[test]
    fn zk_verifier_rejects_duplicate_task_id_binding_fail_closed() {
        let verifier = ZkVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"ZK:{\"task_id\":99,\"worker\":\"worker-zk\",\"proof_type\":\"zk\",\"task_id\":99,\"result_hash\":\"1111111111111111111111111111111111111111111111111111111111111111\"}"
            ),
            VerificationResult::Invalid(msg)
                if msg.contains("duplicate task_id binding")
        ));
    }

    #[test]
    fn zk_verifier_rejects_case_variant_duplicate_task_id_binding_fail_closed() {
        let verifier = ZkVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"ZK:{\"task_id\":99,\"worker\":\"worker-zk\",\"proof_type\":\"zk\",\"Task_ID\":99,\"result_hash\":\"1111111111111111111111111111111111111111111111111111111111111111\"}"
            ),
            VerificationResult::Invalid(msg)
                if msg.contains("duplicate task_id binding")
        ));
    }

    #[test]
    fn zk_verifier_rejects_duplicate_task_id_binding_with_quoted_trailing_space_fail_closed() {
        let verifier = ZkVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"ZK:{\"task_id\":\"99 \",\"worker\":\"worker-zk\",\"proof_type\":\"zk\",\"task_id\":99,\"result_hash\":\"1111111111111111111111111111111111111111111111111111111111111111\"}"
            ),
            VerificationResult::Invalid(msg)
                if msg.contains("duplicate task_id binding")
        ));
    }

    #[test]
    fn zk_verifier_rejects_duplicate_task_id_binding_with_quoted_leading_space_fail_closed() {
        let verifier = ZkVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"ZK:{\"task_id\":\" 99\",\"worker\":\"worker-zk\",\"proof_type\":\"zk\",\"task_id\":99,\"result_hash\":\"1111111111111111111111111111111111111111111111111111111111111111\"}"
            ),
            VerificationResult::Invalid(msg)
                if msg.contains("duplicate task_id binding")
        ));
    }

    #[test]
    fn zk_verifier_rejects_duplicate_task_id_binding_with_single_quoted_leading_space_fail_closed() {
        let verifier = ZkVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"ZK:task_id=' 99',worker=worker-zk,proof_type=zk,task_id=99,result_hash=1111111111111111111111111111111111111111111111111111111111111111,proof=ok"
            ),
            VerificationResult::Invalid(msg)
                if msg.contains("duplicate task_id binding")
        ));
    }

    #[test]
    fn zk_verifier_rejects_case_variant_duplicate_result_hash_binding_fail_closed() {
        let verifier = ZkVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"ZK:{\"task_id\":99,\"worker\":\"worker-zk\",\"proof_type\":\"zk\",\"result_hash\":\"1111111111111111111111111111111111111111111111111111111111111111\",\"Result_Hash\":\"1111111111111111111111111111111111111111111111111111111111111111\"}"
            ),
            VerificationResult::Invalid(msg)
                if msg.contains("duplicate result_hash binding")
        ));
    }

    #[test]
    fn zk_verifier_rejects_duplicate_result_hash_binding_fail_closed() {
        let verifier = ZkVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"ZK:{\"task_id\":99,\"worker\":\"worker-zk\",\"proof_type\":\"zk\",\"result_hash\":\"1111111111111111111111111111111111111111111111111111111111111111\",\"result_hash\":\"1111111111111111111111111111111111111111111111111111111111111111\"}"
            ),
            VerificationResult::Invalid(msg)
                if msg.contains("duplicate result_hash binding")
        ));
    }

    #[test]
    fn zk_verifier_rejects_duplicate_result_hash_binding_with_quoted_trailing_space_fail_closed() {
        let verifier = ZkVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"ZK:{\"task_id\":99,\"worker\":\"worker-zk\",\"proof_type\":\"zk\",\"result_hash\":\"1111111111111111111111111111111111111111111111111111111111111111 \",\"result_hash\":\"1111111111111111111111111111111111111111111111111111111111111111\"}"
            ),
            VerificationResult::Invalid(msg)
                if msg.contains("duplicate result_hash binding")
        ));
    }

    #[test]
    fn zk_verifier_rejects_duplicate_result_hash_binding_with_quoted_leading_space_fail_closed() {
        let verifier = ZkVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"ZK:{\"task_id\":99,\"worker\":\"worker-zk\",\"proof_type\":\"zk\",\"result_hash\":\" 1111111111111111111111111111111111111111111111111111111111111111\",\"result_hash\":\"1111111111111111111111111111111111111111111111111111111111111111\"}"
            ),
            VerificationResult::Invalid(msg)
                if msg.contains("duplicate result_hash binding")
        ));
    }

    #[test]
    fn zk_verifier_rejects_fullwidth_equals_unexpected_worker_binding_without_context_fail_closed() {
        let verifier = ZkVerifier;
        let mut task = mock_task();
        task.worker = None;

        assert!(matches!(
            verifier.verify_proof(
                &task,
                "ZK:task_id=99,proof_type=zk,result_hash=1111111111111111111111111111111111111111111111111111111111111111,worker＝worker-zk,proof=ok"
                    .as_bytes()
            ),
            VerificationResult::Invalid(msg) if msg.contains("unexpected worker binding")
        ));
    }

    #[test]
    fn zk_verifier_rejects_fullwidth_equals_then_ascii_result_hash_binding_fail_closed() {
        let verifier = ZkVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                "ZK:task_id=99,worker=worker-zk,proof_type=zk,result_hash＝1111111111111111111111111111111111111111111111111111111111111111,result_hash=1111111111111111111111111111111111111111111111111111111111111111,proof=ok"
                    .as_bytes()
            ),
            VerificationResult::Invalid(msg) if msg.contains("duplicate result_hash binding")
        ));
    }

    #[test]
    fn zk_verifier_rejects_fullwidth_equals_then_ascii_worker_binding_fail_closed() {
        let verifier = ZkVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                "ZK:task_id=99,worker＝worker-zk,proof_type=zk,result_hash=1111111111111111111111111111111111111111111111111111111111111111,worker=worker-zk,proof=ok"
                    .as_bytes()
            ),
            VerificationResult::Invalid(msg) if msg.contains("duplicate worker binding")
        ));
    }
}
