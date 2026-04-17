use crate::verification::{ProofVerifier, VerificationResult};
use trnm_types::TaskObject;

use super::verify_bound_envelope;

/// Fraud stays as a semantic verifier in the V1 verification platform.
///
/// Unlike TEE/ZK, Fraud does not dispatch into a configurable cryptographic
/// backend family: verification is the fail-closed envelope/binding check
/// itself until a real fraud-proof backend contract exists.
pub struct FraudVerifier;

impl ProofVerifier for FraudVerifier {
    fn proof_type(&self) -> &str {
        "fraud"
    }

    fn verify_proof(&self, task: &TaskObject, proof_data: &[u8]) -> VerificationResult {
        verify_bound_envelope(task, proof_data, b"FRAUD:", "fraud proof")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use trnm_types::{ProofType, TaskObject, TaskStatus};

    fn mock_task() -> TaskObject {
        TaskObject {
            task_id: 7,
            creator: "alice".into(),
            bounty: 1,
            status: TaskStatus::Challenged,
            proof_type: ProofType::Fraud,
            metadata: None,
            worker: Some("worker-fraud".into()),
            committed_hash: None,
            result_hash: None,
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
    fn fraud_verifier_accepts_bound_task_id() {
        let verifier = FraudVerifier;
        let task = mock_task();

        assert_eq!(
            verifier.verify_proof(
                &task,
                b"FRAUD:{\"task_id\":7,\"worker\":\"worker-fraud\",\"proof_type\":\"fraud\"}"
            ),
            VerificationResult::Valid
        );
    }

    #[test]
    fn fraud_verifier_accepts_uppercase_proof_type_and_result_hash_prefix_bindings() {
        let verifier = FraudVerifier;
        let mut task = mock_task();
        task.result_hash = Some([9u8; 32]);

        assert_eq!(
            verifier.verify_proof(
                &task,
                b"FRAUD:{\"task_id\":7,\"worker\":\"worker-fraud\",\"proof_type\":\"FRAUD\",\"result_hash\":\"0X0909090909090909090909090909090909090909090909090909090909090909\"}"
            ),
            VerificationResult::Valid
        );
    }

    #[test]
    fn fraud_verifier_accepts_case_insensitive_prefix_when_bindings_match() {
        let verifier = FraudVerifier;
        let task = mock_task();

        assert_eq!(
            verifier.verify_proof(
                &task,
                b"fRaUd:{\"task_id\":7,\"worker\":\"worker-fraud\",\"proof_type\":\"fraud\"}"
            ),
            VerificationResult::Valid
        );
    }

    #[test]
    fn fraud_verifier_accepts_utf8_bom_prefixed_payload_when_bindings_match() {
        let verifier = FraudVerifier;
        let task = mock_task();

        assert_eq!(
            verifier.verify_proof(
                &task,
                b"\xef\xbb\xbfFRAUD:{\"task_id\":7,\"worker\":\"worker-fraud\",\"proof_type\":\"fraud\"}"
            ),
            VerificationResult::Valid
        );
    }

    #[test]
    fn fraud_verifier_rejects_prefix_without_visible_body_fail_closed() {
        let verifier = FraudVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(&task, b"\xef\xbb\xbfFRAUD:\n\t"),
            VerificationResult::Invalid(msg) if msg.contains("Invalid fraud proof envelope")
        ));
    }

    #[test]
    fn fraud_verifier_rejects_task_id_mismatch() {
        let verifier = FraudVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(&task, b"FRAUD:{\"task_id\":8,\"worker\":\"worker-fraud\"}"),
            VerificationResult::Invalid(msg) if msg.contains("task_id mismatch")
        ));
    }

    #[test]
    fn fraud_verifier_rejects_missing_task_id_binding() {
        let verifier = FraudVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(&task, b"FRAUD:{\"challenge\":\"ok\"}"),
            VerificationResult::Invalid(msg) if msg.contains("missing task_id binding")
        ));
    }

    #[test]
    fn fraud_verifier_rejects_worker_mismatch_when_worker_is_present() {
        let verifier = FraudVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(&task, b"FRAUD:{\"task_id\":7,\"worker\":\"worker-x\"}"),
            VerificationResult::Invalid(msg) if msg.contains("worker mismatch")
        ));
    }

    #[test]
    fn fraud_verifier_rejects_missing_worker_binding_when_worker_is_present() {
        let verifier = FraudVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(&task, b"FRAUD:{\"task_id\":7,\"proof_type\":\"fraud\"}"),
            VerificationResult::Invalid(msg) if msg.contains("missing worker binding")
        ));
    }

    #[test]
    fn fraud_verifier_rejects_zero_width_worker_binding_spoof_fail_closed() {
        let verifier = FraudVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                "FRAUD:{\"task_id\":7,\"worker\":\"worke\u{200b}r-fraud\",\"proof_type\":\"fraud\"}"
                    .as_bytes()
            ),
            VerificationResult::Invalid(msg) if msg.contains("missing worker binding")
        ));
    }

    #[test]
    fn fraud_verifier_rejects_noncanonical_worker_binding_context_fail_closed() {
        let verifier = FraudVerifier;
        let mut task = mock_task();
        task.worker = Some(" worker-fraud ".into());

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"FRAUD:{\"task_id\":7,\"worker\":\"worker-fraud\",\"proof_type\":\"fraud\"}"
            ),
            VerificationResult::Invalid(msg) if msg.contains("non-canonical worker binding context")
        ));
    }

    #[test]
    fn fraud_verifier_rejects_unexpected_worker_binding_without_worker_context_fail_closed() {
        let verifier = FraudVerifier;
        let mut task = mock_task();
        task.worker = None;

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"FRAUD:{\"task_id\":7,\"worker\":\"worker-fraud\",\"proof_type\":\"fraud\"}"
            ),
            VerificationResult::Invalid(msg) if msg.contains("unexpected worker binding")
        ));
    }

    #[test]
    fn fraud_verifier_rejects_case_variant_duplicate_task_id_binding_fail_closed() {
        let verifier = FraudVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"FRAUD:{\"task_id\":7,\"Task_Id\":7,\"worker\":\"worker-fraud\",\"proof_type\":\"fraud\"}"
            ),
            VerificationResult::Invalid(msg) if msg.contains("duplicate task_id binding")
        ));
    }

    #[test]
    fn fraud_verifier_rejects_duplicate_task_id_binding_with_quoted_leading_space_fail_closed() {
        let verifier = FraudVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"FRAUD:{\"task_id\":7,\"task_id\":\" 7\",\"worker\":\"worker-fraud\",\"proof_type\":\"fraud\"}"
            ),
            VerificationResult::Invalid(msg) if msg.contains("duplicate task_id binding")
        ));
    }

    #[test]
    fn fraud_verifier_rejects_duplicate_task_id_binding_with_quoted_trailing_space_fail_closed() {
        let verifier = FraudVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"FRAUD:{\"task_id\":7,\"task_id\":\"7 \",\"worker\":\"worker-fraud\",\"proof_type\":\"fraud\"}"
            ),
            VerificationResult::Invalid(msg) if msg.contains("duplicate task_id binding")
        ));
    }

    #[test]
    fn fraud_verifier_rejects_duplicate_task_id_binding_with_single_quoted_alias_fail_closed() {
        let verifier = FraudVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"FRAUD:{\"task_id\":7,\"task_id\":'7',\"worker\":\"worker-fraud\",\"proof_type\":\"fraud\"}"
            ),
            VerificationResult::Invalid(msg) if msg.contains("duplicate task_id binding")
        ));
    }

    #[test]
    fn fraud_verifier_rejects_duplicate_task_id_binding_with_double_quoted_alias_fail_closed() {
        let verifier = FraudVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"FRAUD:{\"task_id\":7,\"task_id\":\"7\",\"worker\":\"worker-fraud\",\"proof_type\":\"fraud\"}"
            ),
            VerificationResult::Invalid(msg) if msg.contains("duplicate task_id binding")
        ));
    }

    #[test]
    fn fraud_verifier_rejects_fullwidth_comma_delimited_duplicate_task_id_binding_fail_closed() {
        let verifier = FraudVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"FRAUD:{\"task_id\":7\xef\xbc\x8c\"task_id\":7,\"worker\":\"worker-fraud\",\"proof_type\":\"fraud\"}"
            ),
            VerificationResult::Invalid(msg) if msg.contains("duplicate task_id binding")
        ));
    }

    #[test]
    fn fraud_verifier_rejects_fullwidth_semicolon_delimited_duplicate_task_id_binding_fail_closed()
    {
        let verifier = FraudVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"FRAUD:{\"task_id\":7\xef\xbc\x9b\"task_id\":7,\"worker\":\"worker-fraud\",\"proof_type\":\"fraud\"}"
            ),
            VerificationResult::Invalid(msg) if msg.contains("duplicate task_id binding")
        ));
    }

    #[test]
    fn fraud_verifier_rejects_semicolon_delimited_duplicate_task_id_binding_fail_closed() {
        let verifier = FraudVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"FRAUD:{\"task_id\":7;\"task_id\":7,\"worker\":\"worker-fraud\",\"proof_type\":\"fraud\"}"
            ),
            VerificationResult::Invalid(msg) if msg.contains("duplicate task_id binding")
        ));
    }

    #[test]
    fn fraud_verifier_rejects_proof_type_mismatch_when_present() {
        let verifier = FraudVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"FRAUD:{\"task_id\":7,\"worker\":\"worker-fraud\",\"proof_type\":\"tee\"}"
            ),
            VerificationResult::Invalid(msg) if msg.contains("proof_type mismatch")
        ));
    }

    #[test]
    fn fraud_verifier_rejects_legacy_receipt_alias_on_default_launch_path() {
        let verifier = FraudVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"FRAUD:{\"task_id\":7,\"worker\":\"worker-fraud\",\"proof_type\":\"fraud_proof\"}"
            ),
            VerificationResult::Invalid(msg) if msg.contains("proof_type mismatch")
        ));
    }

    #[test]
    fn fraud_verifier_rejects_worker_binding_with_cyrillic_homoglyph_spoof_fail_closed() {
        let verifier = FraudVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                "FRAUD:{\"task_id\":7,\"worker\":\"wоrker-fraud\",\"proof_type\":\"fraud\"}"
                    .as_bytes()
            ),
            VerificationResult::Invalid(msg) if msg.contains("missing worker binding")
        ));
    }

    #[test]
    fn fraud_verifier_rejects_missing_proof_type_binding_fail_closed() {
        let verifier = FraudVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(&task, b"FRAUD:{\"task_id\":7,\"worker\":\"worker-fraud\"}"),
            VerificationResult::Invalid(msg) if msg.contains("missing proof_type binding")
        ));
    }

    #[test]
    fn fraud_verifier_rejects_duplicate_worker_binding_fail_closed() {
        let verifier = FraudVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"FRAUD:{\"task_id\":7,\"worker\":\"worker-fraud\",\"Worker\":\"worker-fraud\",\"proof_type\":\"fraud\"}"
            ),
            VerificationResult::Invalid(msg) if msg.contains("duplicate worker binding")
        ));
    }

    #[test]
    fn fraud_verifier_rejects_duplicate_worker_binding_with_quoted_trailing_space_fail_closed() {
        let verifier = FraudVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"FRAUD:{\"task_id\":7,\"worker\":\"worker-fraud\",\"worker\":\"worker-fraud \",\"proof_type\":\"fraud\"}"
            ),
            VerificationResult::Invalid(msg) if msg.contains("duplicate worker binding")
        ));
    }

    #[test]
    fn fraud_verifier_rejects_duplicate_worker_binding_with_quoted_leading_space_fail_closed() {
        let verifier = FraudVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"FRAUD:{\"task_id\":7,\"worker\":\"worker-fraud\",\"worker\":\" worker-fraud\",\"proof_type\":\"fraud\"}"
            ),
            VerificationResult::Invalid(msg) if msg.contains("duplicate worker binding")
        ));
    }

    #[test]
    fn fraud_verifier_rejects_duplicate_worker_binding_with_single_quoted_alias_fail_closed() {
        let verifier = FraudVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"FRAUD:{\"task_id\":7,\"worker\":\"worker-fraud\",'worker':\"worker-fraud\",\"proof_type\":\"fraud\"}"
            ),
            VerificationResult::Invalid(msg) if msg.contains("duplicate worker binding")
        ));
    }

    #[test]
    fn fraud_verifier_rejects_duplicate_worker_binding_with_double_quoted_alias_fail_closed() {
        let verifier = FraudVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"FRAUD:{\"task_id\":7,\"worker\":\"worker-fraud\",\"worker\":\"worker-fraud\",\"proof_type\":\"fraud\"}"
            ),
            VerificationResult::Invalid(msg) if msg.contains("duplicate worker binding")
        ));
    }

    #[test]
    fn fraud_verifier_rejects_duplicate_worker_binding_with_unclosed_quoted_alias_fail_closed() {
        let verifier = FraudVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"FRAUD:{\"task_id\":7,\"worker\":\"worker-fraud\",\"worker:\"worker-fraud\",\"proof_type\":\"fraud\"}"
            ),
            VerificationResult::Invalid(msg) if msg.contains("duplicate worker binding")
        ));
    }

    #[test]
    fn fraud_verifier_rejects_case_variant_duplicate_worker_binding_fail_closed() {
        let verifier = FraudVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"FRAUD:{\"task_id\":7,\"worker\":\"worker-fraud\",\"WORKER\":\"worker-fraud\",\"proof_type\":\"fraud\"}"
            ),
            VerificationResult::Invalid(msg) if msg.contains("duplicate worker binding")
        ));
    }

    #[test]
    fn fraud_verifier_rejects_duplicate_proof_type_binding_fail_closed() {
        let verifier = FraudVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"FRAUD:{\"task_id\":7,\"worker\":\"worker-fraud\",\"proof_type\":\"fraud\",\"proof_type\":\"fraud\"}"
            ),
            VerificationResult::Invalid(msg) if msg.contains("duplicate proof_type binding")
        ));
    }

    #[test]
    fn fraud_verifier_rejects_duplicate_proof_type_binding_with_quoted_trailing_space_fail_closed()
    {
        let verifier = FraudVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"FRAUD:{\"task_id\":7,\"worker\":\"worker-fraud\",\"proof_type\":\"fraud \",\"proof_type\":\"fraud\"}"
            ),
            VerificationResult::Invalid(msg) if msg.contains("duplicate proof_type binding")
        ));
    }

    #[test]
    fn fraud_verifier_rejects_duplicate_proof_type_binding_with_quoted_leading_space_fail_closed() {
        let verifier = FraudVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"FRAUD:{\"task_id\":7,\"worker\":\"worker-fraud\",\"proof_type\":\" fraud\",\"proof_type\":\"fraud\"}"
            ),
            VerificationResult::Invalid(msg) if msg.contains("duplicate proof_type binding")
        ));
    }

    #[test]
    fn fraud_verifier_rejects_case_variant_duplicate_proof_type_binding_fail_closed() {
        let verifier = FraudVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"FRAUD:{\"task_id\":7,\"worker\":\"worker-fraud\",\"proof_type\":\"fraud\",\"Proof_Type\":\"fraud\"}"
            ),
            VerificationResult::Invalid(msg) if msg.contains("duplicate proof_type binding")
        ));
    }

    #[test]
    fn fraud_verifier_rejects_duplicate_proof_type_binding_with_single_quoted_alias_fail_closed() {
        let verifier = FraudVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"FRAUD:{\"task_id\":7,\"worker\":\"worker-fraud\",\"proof_type\":\"fraud\",'proof_type':\"fraud\"}"
            ),
            VerificationResult::Invalid(msg) if msg.contains("duplicate proof_type binding")
        ));
    }

    #[test]
    fn fraud_verifier_rejects_missing_result_hash_binding_when_expected() {
        let verifier = FraudVerifier;
        let mut task = mock_task();
        task.result_hash = Some([9u8; 32]);

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"FRAUD:{\"task_id\":7,\"worker\":\"worker-fraud\",\"proof_type\":\"fraud\"}"
            ),
            VerificationResult::Invalid(msg) if msg.contains("missing result_hash binding")
        ));
    }

    #[test]
    fn fraud_verifier_rejects_case_variant_duplicate_result_hash_binding_fail_closed() {
        let verifier = FraudVerifier;
        let mut task = mock_task();
        task.result_hash = Some([9u8; 32]);

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"FRAUD:{\"task_id\":7,\"worker\":\"worker-fraud\",\"proof_type\":\"fraud\",\"result_hash\":\"0909090909090909090909090909090909090909090909090909090909090909\",\"Result_Hash\":\"0909090909090909090909090909090909090909090909090909090909090909\"}"
            ),
            VerificationResult::Invalid(msg) if msg.contains("duplicate result_hash binding")
        ));
    }

    #[test]
    fn fraud_verifier_rejects_duplicate_result_hash_binding_with_quoted_trailing_space_fail_closed()
    {
        let verifier = FraudVerifier;
        let mut task = mock_task();
        task.result_hash = Some([9u8; 32]);

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"FRAUD:{\"task_id\":7,\"worker\":\"worker-fraud\",\"proof_type\":\"fraud\",\"result_hash\":\"0909090909090909090909090909090909090909090909090909090909090909\",\"result_hash\":\"0909090909090909090909090909090909090909090909090909090909090909 \"}"
            ),
            VerificationResult::Invalid(msg) if msg.contains("duplicate result_hash binding")
        ));
    }

    #[test]
    fn fraud_verifier_rejects_duplicate_result_hash_binding_with_quoted_leading_space_fail_closed()
    {
        let verifier = FraudVerifier;
        let mut task = mock_task();
        task.result_hash = Some([9u8; 32]);

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"FRAUD:{\"task_id\":7,\"worker\":\"worker-fraud\",\"proof_type\":\"fraud\",\"result_hash\":\"0909090909090909090909090909090909090909090909090909090909090909\",\"result_hash\":\" 0909090909090909090909090909090909090909090909090909090909090909\"}"
            ),
            VerificationResult::Invalid(msg) if msg.contains("duplicate result_hash binding")
        ));
    }

    #[test]
    fn fraud_verifier_rejects_duplicate_result_hash_binding_with_unclosed_quoted_alias_fail_closed()
    {
        let verifier = FraudVerifier;
        let mut task = mock_task();
        task.result_hash = Some([9u8; 32]);

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"FRAUD:{\"task_id\":7,\"worker\":\"worker-fraud\",\"proof_type\":\"fraud\",\"result_hash\":\"0909090909090909090909090909090909090909090909090909090909090909\",\"result_hash\":\"0909090909090909090909090909090909090909090909090909090909090909}"
            ),
            VerificationResult::Invalid(msg) if msg.contains("duplicate result_hash binding")
        ));
    }

    #[test]
    fn fraud_verifier_rejects_duplicate_result_hash_binding_with_single_quoted_alias_fail_closed() {
        let verifier = FraudVerifier;
        let mut task = mock_task();
        task.result_hash = Some([9u8; 32]);

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"FRAUD:{\"task_id\":7,\"worker\":\"worker-fraud\",\"proof_type\":\"fraud\",\"result_hash\":\"0909090909090909090909090909090909090909090909090909090909090909\",'result_hash':\"0909090909090909090909090909090909090909090909090909090909090909\"}"
            ),
            VerificationResult::Invalid(msg) if msg.contains("duplicate result_hash binding")
        ));
    }

    #[test]
    fn fraud_verifier_rejects_duplicate_result_hash_binding_with_double_quoted_alias_fail_closed() {
        let verifier = FraudVerifier;
        let mut task = mock_task();
        task.result_hash = Some([9u8; 32]);

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"FRAUD:{\"task_id\":7,\"worker\":\"worker-fraud\",\"proof_type\":\"fraud\",\"result_hash\":\"0909090909090909090909090909090909090909090909090909090909090909\",\"result_hash\":\"0909090909090909090909090909090909090909090909090909090909090909\"}"
            ),
            VerificationResult::Invalid(msg) if msg.contains("duplicate result_hash binding")
        ));
    }

    #[test]
    fn fraud_verifier_rejects_duplicate_result_hash_binding_with_uppercase_prefixed_alias_fail_closed(
    ) {
        let verifier = FraudVerifier;
        let mut task = mock_task();
        task.result_hash = Some([9u8; 32]);

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"FRAUD:{\"task_id\":7,\"worker\":\"worker-fraud\",\"proof_type\":\"fraud\",\"result_hash\":\"0909090909090909090909090909090909090909090909090909090909090909\",\"result_hash\":\"0X0909090909090909090909090909090909090909090909090909090909090909\"}"
            ),
            VerificationResult::Invalid(msg) if msg.contains("duplicate result_hash binding")
        ));
    }

    #[test]
    fn fraud_verifier_rejects_unexpected_result_hash_binding_without_context_fail_closed() {
        let verifier = FraudVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"FRAUD:{\"task_id\":7,\"worker\":\"worker-fraud\",\"proof_type\":\"fraud\",\"result_hash\":\"0909090909090909090909090909090909090909090909090909090909090909\"}"
            ),
            VerificationResult::Invalid(msg) if msg.contains("unexpected result_hash binding")
        ));
    }

    #[test]
    fn fraud_verifier_rejects_signed_task_id_binding_fail_closed() {
        let verifier = FraudVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"FRAUD:{\"task_id\":+7,\"worker\":\"worker-fraud\",\"proof_type\":\"fraud\"}"
            ),
            VerificationResult::Invalid(msg) if msg.contains("missing task_id binding")
        ));
    }

    #[test]
    fn fraud_verifier_rejects_negative_signed_task_id_binding_fail_closed() {
        let verifier = FraudVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"FRAUD:{\"task_id\":-7,\"worker\":\"worker-fraud\",\"proof_type\":\"fraud\"}"
            ),
            VerificationResult::Invalid(msg) if msg.contains("missing task_id binding")
        ));
    }

    #[test]
    fn fraud_verifier_rejects_fullwidth_plus_signed_task_id_binding_fail_closed() {
        let verifier = FraudVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"FRAUD:{\"task_id\":\xef\xbc\x8b7,\"worker\":\"worker-fraud\",\"proof_type\":\"fraud\"}"
            ),
            VerificationResult::Invalid(msg) if msg.contains("missing task_id binding")
        ));
    }

    #[test]
    fn fraud_verifier_rejects_fullwidth_underscore_task_id_identifier_spoof_fail_closed() {
        let verifier = FraudVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"FRAUD:{\"task\xef\xbc\xbfid\":7,\"worker\":\"worker-fraud\",\"proof_type\":\"fraud\"}"
            ),
            VerificationResult::Invalid(msg) if msg.contains("missing task_id binding")
        ));
    }

    #[test]
    fn fraud_verifier_rejects_fullwidth_underscore_proof_type_identifier_spoof_fail_closed() {
        let verifier = FraudVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"FRAUD:{\"task_id\":7,\"worker\":\"worker-fraud\",\"proof\xef\xbc\xbftype\":\"fraud\"}"
            ),
            VerificationResult::Invalid(msg) if msg.contains("missing proof_type binding")
        ));
    }

    #[test]
    fn fraud_verifier_rejects_fullwidth_underscore_worker_identifier_spoof_fail_closed() {
        let verifier = FraudVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"FRAUD:{\"task_id\":7,\"worker\xef\xbc\xbf\":\"worker-fraud\",\"proof_type\":\"fraud\"}"
            ),
            VerificationResult::Invalid(msg) if msg.contains("missing worker binding")
        ));
    }

    #[test]
    fn fraud_verifier_rejects_fullwidth_underscore_result_hash_identifier_spoof_fail_closed() {
        let verifier = FraudVerifier;
        let mut task = mock_task();
        task.result_hash = Some([9u8; 32]);

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"FRAUD:{\"task_id\":7,\"worker\":\"worker-fraud\",\"proof_type\":\"fraud\",\"result\xef\xbc\xbfhash\":\"0909090909090909090909090909090909090909090909090909090909090909\"}"
            ),
            VerificationResult::Invalid(msg) if msg.contains("missing result_hash binding")
        ));
    }

    #[test]
    fn fraud_verifier_rejects_fullwidth_equals_then_ascii_proof_type_binding_fail_closed() {
        let verifier = FraudVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"FRAUD:{\"task_id\":7,\"worker\":\"worker-fraud\",\"proof_type\"\xef\xbc\x9a\"fraud\",\"proof_type\":\"fraud\"}"
            ),
            VerificationResult::Invalid(msg) if msg.contains("duplicate proof_type binding")
        ));
    }

    #[test]
    fn fraud_verifier_rejects_fullwidth_equals_then_ascii_task_id_binding_fail_closed() {
        let verifier = FraudVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"FRAUD:{\"task_id\"\xef\xbc\x9a7,\"task_id\":7,\"worker\":\"worker-fraud\",\"proof_type\":\"fraud\"}"
            ),
            VerificationResult::Invalid(msg) if msg.contains("duplicate task_id binding")
        ));
    }

    #[test]
    fn fraud_verifier_rejects_fullwidth_colon_then_ascii_task_id_binding_fail_closed() {
        let verifier = FraudVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"FRAUD:{\"task_id\"\xef\xbc\x9a7,\"task_id\":7,\"worker\":\"worker-fraud\",\"proof_type\":\"fraud\"}"
            ),
            VerificationResult::Invalid(msg) if msg.contains("duplicate task_id binding")
        ));
    }

    #[test]
    fn fraud_verifier_rejects_fullwidth_equals_then_ascii_worker_binding_fail_closed() {
        let verifier = FraudVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"FRAUD:{\"task_id\":7,\"worker\"\xef\xbc\x9a\"worker-fraud\",\"worker\":\"worker-fraud\",\"proof_type\":\"fraud\"}"
            ),
            VerificationResult::Invalid(msg) if msg.contains("duplicate worker binding")
        ));
    }

    #[test]
    fn fraud_verifier_rejects_fullwidth_colon_then_ascii_worker_binding_fail_closed() {
        let verifier = FraudVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"FRAUD:{\"task_id\":7,\"worker\"\xef\xbc\x9a\"worker-fraud\",\"worker\":\"worker-fraud\",\"proof_type\":\"fraud\"}"
            ),
            VerificationResult::Invalid(msg) if msg.contains("duplicate worker binding")
        ));
    }

    #[test]
    fn fraud_verifier_rejects_fullwidth_equals_then_ascii_result_hash_binding_fail_closed() {
        let verifier = FraudVerifier;
        let mut task = mock_task();
        task.result_hash = Some([9u8; 32]);

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"FRAUD:{\"task_id\":7,\"worker\":\"worker-fraud\",\"proof_type\":\"fraud\",\"result_hash\"\xef\xbc\x9a\"0909090909090909090909090909090909090909090909090909090909090909\",\"result_hash\":\"0909090909090909090909090909090909090909090909090909090909090909\"}"
            ),
            VerificationResult::Invalid(msg) if msg.contains("duplicate result_hash binding")
        ));
    }

    #[test]
    fn fraud_verifier_rejects_result_hash_with_repeated_hex_prefix_fail_closed() {
        let verifier = FraudVerifier;
        let mut task = mock_task();
        task.result_hash = Some([9u8; 32]);

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"FRAUD:{\"task_id\":7,\"worker\":\"worker-fraud\",\"proof_type\":\"fraud\",\"result_hash\":\"0x0x0909090909090909090909090909090909090909090909090909090909090909\"}"
            ),
            VerificationResult::Invalid(msg) if msg.contains("result_hash mismatch")
        ));
    }

    #[test]
    fn fraud_verifier_rejects_fullwidth_comma_delimited_duplicate_worker_binding_fail_closed() {
        let verifier = FraudVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"FRAUD:{\"task_id\":7,\"worker\":\"worker-fraud\"\xef\xbc\x8c\"worker\":\"worker-fraud\",\"proof_type\":\"fraud\"}"
            ),
            VerificationResult::Invalid(msg) if msg.contains("duplicate worker binding")
        ));
    }

    #[test]
    fn fraud_verifier_rejects_fullwidth_semicolon_delimited_duplicate_worker_binding_fail_closed() {
        let verifier = FraudVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"FRAUD:{\"task_id\":7,\"worker\":\"worker-fraud\"\xef\xbc\x9b\"worker\":\"worker-fraud\",\"proof_type\":\"fraud\"}"
            ),
            VerificationResult::Invalid(msg) if msg.contains("duplicate worker binding")
        ));
    }

    #[test]
    fn fraud_verifier_rejects_fullwidth_semicolon_delimited_duplicate_proof_type_binding_fail_closed(
    ) {
        let verifier = FraudVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"FRAUD:{\"task_id\":7,\"worker\":\"worker-fraud\",\"proof_type\":\"fraud\"\xef\xbc\x9b\"proof_type\":\"fraud\"}"
            ),
            VerificationResult::Invalid(msg) if msg.contains("duplicate proof_type binding")
        ));
    }

    #[test]
    fn fraud_verifier_rejects_fullwidth_comma_delimited_duplicate_proof_type_binding_fail_closed() {
        let verifier = FraudVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"FRAUD:{\"task_id\":7,\"worker\":\"worker-fraud\",\"proof_type\":\"fraud\"\xef\xbc\x8c\"proof_type\":\"fraud\"}"
            ),
            VerificationResult::Invalid(msg) if msg.contains("duplicate proof_type binding")
        ));
    }

    #[test]
    fn fraud_verifier_rejects_semicolon_delimited_duplicate_proof_type_binding_fail_closed() {
        let verifier = FraudVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"FRAUD:{\"task_id\":7;\"worker\":\"worker-fraud\";\"proof_type\":\"fraud\";\"proof_type\":\"fraud\"}"
            ),
            VerificationResult::Invalid(msg) if msg.contains("duplicate proof_type binding")
        ));
    }

    #[test]
    fn fraud_verifier_rejects_comma_delimited_duplicate_proof_type_binding_fail_closed() {
        let verifier = FraudVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"FRAUD:{\"task_id\":7,\"worker\":\"worker-fraud\",\"proof_type\":\"fraud\",\"proof_type\":\"fraud\"}"
            ),
            VerificationResult::Invalid(msg) if msg.contains("duplicate proof_type binding")
        ));
    }

    #[test]
    fn fraud_verifier_rejects_fullwidth_comma_delimited_duplicate_result_hash_binding_fail_closed()
    {
        let verifier = FraudVerifier;
        let mut task = mock_task();
        task.result_hash = Some([9u8; 32]);

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"FRAUD:{\"task_id\":7,\"worker\":\"worker-fraud\",\"proof_type\":\"fraud\",\"result_hash\":\"0909090909090909090909090909090909090909090909090909090909090909\"\xef\xbc\x8c\"result_hash\":\"0909090909090909090909090909090909090909090909090909090909090909\"}"
            ),
            VerificationResult::Invalid(msg) if msg.contains("duplicate result_hash binding")
        ));
    }

    #[test]
    fn fraud_verifier_rejects_fullwidth_semicolon_delimited_duplicate_result_hash_binding_fail_closed(
    ) {
        let verifier = FraudVerifier;
        let mut task = mock_task();
        task.result_hash = Some([9u8; 32]);

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"FRAUD:{\"task_id\":7,\"worker\":\"worker-fraud\",\"proof_type\":\"fraud\",\"result_hash\":\"0909090909090909090909090909090909090909090909090909090909090909\"\xef\xbc\x9b\"result_hash\":\"0909090909090909090909090909090909090909090909090909090909090909\"}"
            ),
            VerificationResult::Invalid(msg) if msg.contains("duplicate result_hash binding")
        ));
    }

    #[test]
    fn fraud_verifier_rejects_fullwidth_colon_unexpected_result_hash_binding_without_context_fail_closed(
    ) {
        let verifier = FraudVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"FRAUD:{\"task_id\":7,\"worker\":\"worker-fraud\",\"proof_type\":\"fraud\",\"result_hash\"\xef\xbc\x9a\"0909090909090909090909090909090909090909090909090909090909090909\"}"
            ),
            VerificationResult::Invalid(msg) if msg.contains("unexpected result_hash binding")
        ));
    }

    #[test]
    fn fraud_verifier_rejects_fullwidth_colon_proof_type_binding_fail_closed() {
        let verifier = FraudVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"FRAUD:{\"task_id\":7,\"worker\":\"worker-fraud\",\"proof_type\"\xef\xbc\x9a\"fraud\"}"
            ),
            VerificationResult::Invalid(msg) if msg.contains("missing proof_type binding")
        ));
    }

    #[test]
    fn fraud_verifier_rejects_fullwidth_colon_task_id_binding_fail_closed() {
        let verifier = FraudVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"FRAUD:{\"task_id\"\xef\xbc\x9a7,\"worker\":\"worker-fraud\",\"proof_type\":\"fraud\"}"
            ),
            VerificationResult::Invalid(msg) if msg.contains("missing task_id binding")
        ));
    }

    #[test]
    fn fraud_verifier_rejects_fullwidth_colon_worker_binding_fail_closed() {
        let verifier = FraudVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"FRAUD:{\"task_id\":7,\"worker\"\xef\xbc\x9a\"worker-fraud\",\"proof_type\":\"fraud\"}"
            ),
            VerificationResult::Invalid(msg) if msg.contains("missing worker binding")
        ));
    }

    #[test]
    fn fraud_verifier_rejects_fullwidth_colon_result_hash_binding_fail_closed() {
        let verifier = FraudVerifier;
        let mut task = mock_task();
        task.result_hash = Some([9u8; 32]);

        assert!(matches!(
            verifier.verify_proof(
                &task,
                b"FRAUD:{\"task_id\":7,\"worker\":\"worker-fraud\",\"proof_type\":\"fraud\",\"result_hash\"\xef\xbc\x9a\"0909090909090909090909090909090909090909090909090909090909090909\"}"
            ),
            VerificationResult::Invalid(msg) if msg.contains("missing result_hash binding")
        ));
    }
}
