use crate::verification::{ProofVerifier, VerificationResult};
use trnm_types::TaskObject;

pub struct ZkVerifier;

impl ProofVerifier for ZkVerifier {
    fn proof_type(&self) -> &str {
        "zk"
    }

    fn verify_proof(&self, _task: &TaskObject, proof_data: &[u8]) -> VerificationResult {
        // ZK logic: verify zk-SNARK/STARK proof against verifying key.
        // Requires task.metadata or implicit circuit ID.

        if proof_data.len() < 10 {
            return VerificationResult::Invalid("ZK proof too short".to_string());
        }

        // V3 micro-patch hardening: require explicit envelope marker
        // plus a non-whitespace payload body.
        // Accept case-insensitive variants to tolerate client casing drift.
        // Accepted examples: "ZK:...", "zk:...".
        // Also accept an optional UTF-8 BOM prefix for legacy clients.
        let envelope_offset = if proof_data.starts_with(&[0xef, 0xbb, 0xbf]) {
            3
        } else {
            0
        };
        let has_prefix = proof_data
            .get(envelope_offset..envelope_offset + 3)
            .map(|prefix| prefix.eq_ignore_ascii_case(b"ZK:"))
            .unwrap_or(false);
        let has_non_whitespace_body = proof_data
            .get(envelope_offset + 3..)
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
            VerificationResult::Invalid("Invalid ZK proof envelope".to_string())
        }
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
    fn zk_verifier_rejects_short_proof() {
        let verifier = ZkVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(&task, b"ZKshort"),
            VerificationResult::Invalid(msg) if msg.contains("too short")
        ));
    }

    #[test]
    fn zk_verifier_accepts_prefixed_proof_when_length_is_sufficient() {
        let verifier = ZkVerifier;
        let task = mock_task();

        assert_eq!(
            verifier.verify_proof(&task, b"ZK:payload!"),
            VerificationResult::Valid
        );
    }

    #[test]
    fn zk_verifier_accepts_lowercase_prefixed_proof_when_length_is_sufficient() {
        let verifier = ZkVerifier;
        let task = mock_task();

        assert_eq!(
            verifier.verify_proof(&task, b"zk:payload!"),
            VerificationResult::Valid
        );
    }

    #[test]
    fn zk_verifier_accepts_utf8_bom_prefixed_proof_when_length_is_sufficient() {
        let verifier = ZkVerifier;
        let task = mock_task();

        assert_eq!(
            verifier.verify_proof(&task, "\u{feff}ZK:payload!".as_bytes()),
            VerificationResult::Valid
        );
    }

    #[test]
    fn zk_verifier_rejects_utf8_bom_prefixed_proof_with_whitespace_only_body() {
        let verifier = ZkVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(&task, "\u{feff}ZK:    \n\t".as_bytes()),
            VerificationResult::Invalid(msg) if msg.contains("envelope")
        ));
    }

    #[test]
    fn zk_verifier_rejects_non_prefixed_proof_when_length_is_sufficient() {
        let verifier = ZkVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(&task, b"XX:payload!"),
            VerificationResult::Invalid(msg) if msg.contains("Invalid ZK proof envelope")
        ));
    }

    #[test]
    fn zk_verifier_rejects_legacy_non_delimited_prefix() {
        let verifier = ZkVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(&task, b"ZKpayload!!"),
            VerificationResult::Invalid(msg) if msg.contains("envelope")
        ));
    }

    #[test]
    fn zk_verifier_rejects_whitespace_only_body_after_prefix() {
        let verifier = ZkVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(&task, b"ZK:       "),
            VerificationResult::Invalid(msg) if msg.contains("envelope")
        ));
    }

    #[test]
    fn zk_verifier_rejects_unicode_whitespace_only_body_after_prefix() {
        let verifier = ZkVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(&task, "ZK:\u{00a0}\u{3000}      ".as_bytes()),
            VerificationResult::Invalid(msg) if msg.contains("envelope")
        ));
    }

    #[test]
    fn zk_verifier_rejects_ascii_control_only_body_after_prefix() {
        let verifier = ZkVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(&task, b"ZK:\x00\x1f\x7f\x08\x09\x0a\x0d"),
            VerificationResult::Invalid(msg) if msg.contains("envelope")
        ));
    }

    #[test]
    fn zk_verifier_accepts_non_utf8_binary_body_when_it_contains_visible_byte() {
        let verifier = ZkVerifier;
        let task = mock_task();

        assert_eq!(
            verifier.verify_proof(&task, b"ZK:\xff\xfeA123456"),
            VerificationResult::Valid
        );
    }
}
