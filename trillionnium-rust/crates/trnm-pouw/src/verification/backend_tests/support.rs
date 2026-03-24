use std::sync::Arc;

use super::*;
use trnm_types::{ProofType, TaskObject, TaskStatus};

pub(super) fn mock_task() -> TaskObject {
    TaskObject {
        task_id: 4242,
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

pub(super) struct MockRegistryBackend {
    pub(super) backend_id: &'static str,
}

impl ZkBackend for MockRegistryBackend {
    fn backend_id(&self) -> &str {
        self.backend_id
    }

    fn verify(
        &self,
        _request: BackendVerificationRequest<'_>,
    ) -> Result<BackendVerificationSuccess, BackendExecutionError> {
        Ok(BackendVerificationSuccess {
            backend_id: self.backend_id.into(),
        })
    }
}
