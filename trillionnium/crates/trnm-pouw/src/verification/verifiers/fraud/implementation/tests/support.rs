use super::*;
use trnm_types::{ProofType, TaskObject, TaskStatus};

pub(super) fn mock_task() -> TaskObject {
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
