use crate::verification::{ProofVerifier, VerificationResult};
use trnm_types::TaskObject;

pub struct FraudVerifier;

impl ProofVerifier for FraudVerifier {
    fn proof_type(&self) -> &str {
        "fraud"
    }

    fn verify_proof(&self, _task: &TaskObject, proof_data: &[u8]) -> VerificationResult {
        if proof_data.is_empty() {
            return VerificationResult::Invalid("Fraud proof payload is empty".to_string());
        }

        // V1 micro-patch: require explicit fraud-proof envelope marker.
        // Accept case-insensitive variants to tolerate client casing drift.
        // Accepted examples: "FRAUD:...", "fraud:...".
        let has_prefix = proof_data.len() >= 6 && proof_data[..6].eq_ignore_ascii_case(b"FRAUD:");
        let has_non_whitespace_body = proof_data
            .get(6..)
            .map(|suffix| {
                std::str::from_utf8(suffix)
                    .map(|s| s.chars().any(|c| !c.is_whitespace() && !c.is_control()))
                    .unwrap_or_else(|_| {
                        suffix
                            .iter()
                            .any(|b| !b.is_ascii_whitespace() && !b.is_ascii_control())
                    })
            })
            .unwrap_or(false);

        if has_prefix && has_non_whitespace_body {
            VerificationResult::Valid
        } else {
            VerificationResult::Invalid("Invalid fraud proof envelope".to_string())
        }
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
    fn fraud_verifier_rejects_empty_payload() {
        let verifier = FraudVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(&task, b""),
            VerificationResult::Invalid(msg) if msg.contains("empty")
        ));
    }

    #[test]
    fn fraud_verifier_accepts_prefixed_envelope() {
        let verifier = FraudVerifier;
        let task = mock_task();

        assert_eq!(
            verifier.verify_proof(&task, b"FRAUD:challenge-proof"),
            VerificationResult::Valid
        );
    }

    #[test]
    fn fraud_verifier_accepts_lowercase_prefixed_envelope() {
        let verifier = FraudVerifier;
        let task = mock_task();

        assert_eq!(
            verifier.verify_proof(&task, b"fraud:challenge-proof"),
            VerificationResult::Valid
        );
    }

    #[test]
    fn fraud_verifier_accepts_mixed_case_prefixed_envelope() {
        let verifier = FraudVerifier;
        let task = mock_task();

        assert_eq!(
            verifier.verify_proof(&task, b"FrAuD:challenge-proof"),
            VerificationResult::Valid
        );
    }

    #[test]
    fn fraud_verifier_rejects_non_prefixed_payload() {
        let verifier = FraudVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(&task, b"challenge-proof"),
            VerificationResult::Invalid(msg) if msg.contains("envelope")
        ));
    }

    #[test]
    fn fraud_verifier_rejects_prefix_only_without_body() {
        let verifier = FraudVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(&task, b"FRAUD:"),
            VerificationResult::Invalid(msg) if msg.contains("envelope")
        ));
    }

    #[test]
    fn fraud_verifier_rejects_lowercase_prefix_only_without_body() {
        let verifier = FraudVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(&task, b"fraud:"),
            VerificationResult::Invalid(msg) if msg.contains("envelope")
        ));
    }

    #[test]
    fn fraud_verifier_rejects_whitespace_only_body_after_prefix() {
        let verifier = FraudVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(&task, b"FRAUD:   \n\t"),
            VerificationResult::Invalid(msg) if msg.contains("envelope")
        ));
    }

    #[test]
    fn fraud_verifier_rejects_unicode_whitespace_only_body_after_prefix() {
        let verifier = FraudVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(&task, "FRAUD:\u{00a0}\u{3000}".as_bytes()),
            VerificationResult::Invalid(msg) if msg.contains("envelope")
        ));
    }

    #[test]
    fn fraud_verifier_rejects_ascii_control_only_body_after_prefix() {
        let verifier = FraudVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(&task, b"FRAUD:\x00\x1f\x7f"),
            VerificationResult::Invalid(msg) if msg.contains("envelope")
        ));
    }

    #[test]
    fn fraud_verifier_accepts_non_utf8_binary_body_when_it_contains_visible_byte() {
        let verifier = FraudVerifier;
        let task = mock_task();

        assert_eq!(
            verifier.verify_proof(&task, b"FRAUD:\xff\xfeA"),
            VerificationResult::Valid
        );
    }
}
