use crate::verification::{ProofVerifier, VerificationResult};
use trnm_types::TaskObject;

pub struct TeeVerifier;

fn is_invisible_format_char(c: char) -> bool {
    matches!(
        c,
        '\u{200b}' // zero-width space
            | '\u{200c}' // zero-width non-joiner
            | '\u{200d}' // zero-width joiner
            | '\u{2060}' // word joiner
            | '\u{feff}' // zero-width no-break space / BOM
    )
}

impl ProofVerifier for TeeVerifier {
    fn proof_type(&self) -> &str {
        "tee"
    }

    fn verify_proof(&self, _task: &TaskObject, proof_data: &[u8]) -> VerificationResult {
        // V2 micro patch hardening: require explicit TEE receipt prefix
        // plus a non-whitespace payload body.
        // Accept case-insensitive variants to avoid client-side casing drift.
        // Accepted examples: "TEE:...", "tee:...".
        let has_prefix = proof_data.len() >= 4 && proof_data[..4].eq_ignore_ascii_case(b"TEE:");
        let has_non_whitespace_body = proof_data
            .get(4..)
            .map(|suffix| {
                std::str::from_utf8(suffix)
                    .map(|s| {
                        s.chars()
                            .any(|c| !c.is_whitespace() && !c.is_control() && !is_invisible_format_char(c))
                    })
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
            VerificationResult::Invalid("Invalid TEE receipt envelope".to_string())
        }
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
    fn tee_verifier_rejects_too_short_prefix_fragment() {
        let verifier = TeeVerifier;
        let task = mock_task();
        assert!(matches!(
            verifier.verify_proof(&task, b"TE"),
            VerificationResult::Invalid(msg) if msg.contains("envelope")
        ));
    }

    #[test]
    fn tee_verifier_accepts_minimal_non_whitespace_payload_after_prefix() {
        let verifier = TeeVerifier;
        let task = mock_task();

        assert_eq!(
            verifier.verify_proof(&task, b"TEE:a"),
            VerificationResult::Valid
        );
    }

    #[test]
    fn tee_verifier_accepts_explicit_prefix_receipts_when_length_is_sufficient() {
        let verifier = TeeVerifier;
        let task = mock_task();

        assert_eq!(
            verifier.verify_proof(&task, b"TEE:quote"),
            VerificationResult::Valid
        );
    }

    #[test]
    fn tee_verifier_accepts_lowercase_prefix_receipts_when_length_is_sufficient() {
        let verifier = TeeVerifier;
        let task = mock_task();

        assert_eq!(
            verifier.verify_proof(&task, b"tee:quote"),
            VerificationResult::Valid
        );
    }

    #[test]
    fn tee_verifier_accepts_mixed_case_prefix_receipts_when_length_is_sufficient() {
        let verifier = TeeVerifier;
        let task = mock_task();

        assert_eq!(
            verifier.verify_proof(&task, b"TeE:quote"),
            VerificationResult::Valid
        );
    }

    #[test]
    fn tee_verifier_rejects_legacy_prefix_receipts() {
        let verifier = TeeVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(&task, b"TElegacy!"),
            VerificationResult::Invalid(msg) if msg.contains("envelope")
        ));
    }

    #[test]
    fn tee_verifier_rejects_unknown_prefix_even_if_receipt_is_long_enough() {
        let verifier = TeeVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(&task, b"XXreceipt"),
            VerificationResult::Invalid(msg) if msg.contains("envelope")
        ));
    }

    #[test]
    fn tee_verifier_rejects_whitespace_only_body_after_prefix() {
        let verifier = TeeVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(&task, b"TEE:    \n\t"),
            VerificationResult::Invalid(msg) if msg.contains("envelope")
        ));
    }

    #[test]
    fn tee_verifier_rejects_unicode_whitespace_only_body_after_prefix() {
        let verifier = TeeVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(&task, "TEE:\u{00a0}\u{3000}".as_bytes()),
            VerificationResult::Invalid(msg) if msg.contains("envelope")
        ));
    }

    #[test]
    fn tee_verifier_rejects_zero_width_format_only_body_after_prefix() {
        let verifier = TeeVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(&task, "TEE:\u{200b}\u{200d}\u{feff}".as_bytes()),
            VerificationResult::Invalid(msg) if msg.contains("envelope")
        ));
    }

    #[test]
    fn tee_verifier_rejects_ascii_control_only_body_after_prefix() {
        let verifier = TeeVerifier;
        let task = mock_task();

        assert!(matches!(
            verifier.verify_proof(&task, b"TEE:\x00\x1f\x7f"),
            VerificationResult::Invalid(msg) if msg.contains("envelope")
        ));
    }

    #[test]
    fn tee_verifier_accepts_non_utf8_binary_body_when_it_contains_visible_byte() {
        let verifier = TeeVerifier;
        let task = mock_task();

        assert_eq!(
            verifier.verify_proof(&task, b"TEE:\xff\xfeA"),
            VerificationResult::Valid
        );
    }
}
