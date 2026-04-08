use super::*;
use trnm_types::{ProofType, TaskObject, TaskStatus};

pub(super) fn mock_task() -> TaskObject {
    TaskObject {
        task_id: 1,
        creator: "alice".into(),
        bounty: 100,
        status: TaskStatus::Open,
        proof_type: ProofType::Fraud,
        metadata: None,
        worker: None,
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
fn verification_result_observability_helpers_expose_stable_labels() {
    assert_eq!(
        VerificationResult::Valid.outcome_label(),
        VerificationOutcomeLabel::Valid
    );
    assert_eq!(
        VerificationResult::Invalid("bad proof".into()).outcome_label(),
        VerificationOutcomeLabel::Invalid
    );
    assert_eq!(
        VerificationResult::Indeterminate("backend offline".into()).outcome_label(),
        VerificationOutcomeLabel::Indeterminate
    );
    assert_eq!(VerificationResult::Valid.reason(), None);
    assert_eq!(
        VerificationResult::Invalid("bad proof".into()).reason(),
        Some("bad proof")
    );
}
