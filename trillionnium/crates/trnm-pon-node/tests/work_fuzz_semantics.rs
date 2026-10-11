//! Exercise the same semantic arms as libFuzzer in the ordinary native test lane.
#[path = "../../../../tests/fuzz/fuzz_targets/support/work_certificate.rs"]
mod checks;

use trnm_crypto_primitives::pon_work::{VerificationError, VerificationProgress, WorkError};

#[test]
fn retained_winner_accepts_at_its_exact_ticket() {
    let observation = checks::check_structured(&[0]);
    assert!(observation.verdict.is_ok());
    assert_eq!(
        observation.points.last(),
        Some(&VerificationProgress::BeforeVerifiedWork)
    );
}

#[test]
fn target_predecessor_and_wrong_task_reject_before_replay() {
    for (control, expected) in [(1, WorkError::Target), (2, WorkError::Task)] {
        let observation = checks::check_structured(&[control]);
        assert_eq!(
            observation.verdict,
            Err(VerificationError::Relation(expected))
        );
        assert!(observation.points.is_empty());
    }
}

#[test]
fn challenge_and_transcript_mutations_reject_before_product() {
    for control in [3, 5] {
        let observation = checks::check_structured(&[control, 31, 255, 254]);
        assert_eq!(
            observation.verdict,
            Err(VerificationError::Relation(WorkError::Transcript))
        );
        assert!(observation
            .points
            .contains(&VerificationProgress::BeforeReplay));
        assert!(!observation
            .points
            .contains(&VerificationProgress::BeforeProduct));
    }
}

#[test]
fn canonical_product_mutations_reach_product_without_verification_authority() {
    for selector in [0_u16, 4095, 65535] {
        let [low, high] = selector.to_le_bytes();
        let observation = checks::check_structured(&[4, low, high]);
        assert_eq!(
            observation.verdict,
            Err(VerificationError::Relation(WorkError::Product))
        );
        assert!(observation
            .points
            .contains(&VerificationProgress::BeforeProduct));
        assert!(!observation
            .points
            .contains(&VerificationProgress::BeforeVerifiedWork));
    }
}

#[test]
fn cancellation_is_identical_at_early_middle_and_last_observation() {
    let complete = checks::check_structured(&[0]);
    for index in [0, complete.points.len() / 2, complete.points.len() - 1] {
        assert!(index < 2048);
        let [low, high] = (index as u16).to_le_bytes();
        let stopped = checks::check_structured(&[6, low, high]);
        assert_eq!(stopped.verdict, Err(VerificationError::Cancelled(index)));
        assert_eq!(stopped.points, complete.points[..=index]);
    }
    let last = checks::check_structured(&[7]);
    assert_eq!(
        last.verdict,
        Err(VerificationError::Cancelled(complete.points.len() - 1))
    );
    assert_eq!(last.points, complete.points);
}

#[test]
fn raw_malformed_certificates_are_not_replaced_by_semantic_fixtures() {
    for bytes in [Vec::new(), vec![0; 17], vec![0; 49_189]] {
        let observation = checks::check_raw(&bytes);
        assert_eq!(
            observation.verdict,
            Err(VerificationError::Relation(WorkError::Length))
        );
        assert!(observation.points.is_empty());
    }
}
