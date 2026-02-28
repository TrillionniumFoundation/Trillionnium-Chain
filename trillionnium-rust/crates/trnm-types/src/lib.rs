mod interop_identity;
mod relay;
mod request_status;
mod transcript;
mod transfer;

use serde::{Deserialize, Serialize};

pub use interop_identity::{
    AuditAction, AuditEvent, BridgeRoute, CapabilityScope, CapabilityToken, DidRecord,
    IdentityRegistry, InteropIdentityError, SettlementRecord, SettlementStatus,
};
pub use relay::{
    RelayAuthEnvelope, RelayAuthError, RelayAuthVerifier, RelayEnvelope, RelaySession,
    RelaySessionStatus,
};
pub use request_status::{RequestStateError, RequestStatus};
pub use transcript::{
    relay_auth_envelope_hash, transcript_segment_proof, transcript_segment_proofs,
    transcript_segment_root, transcript_segment_tree, verify_proof, MerkleDirection,
    TranscriptError, TranscriptMerkleTree, TranscriptProof,
};
pub use transfer::{TransferTx, TransferTxValidationError};

pub type Hash32 = [u8; 32];

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ObjectRef {
    pub id: u64,
    pub version: u64,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TaskStatus {
    Open = 0,
    Assigned = 1,
    Committed = 2,
    Revealed = 3,
    Challenged = 4,
    Completed = 5,
    Slashed = 6,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum ProofType {
    #[default]
    Fraud = 0,
    Tee = 1,
    Zk = 2,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct TaskMetadata {
    #[serde(default)]
    pub note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskObject {
    pub task_id: u64,
    pub creator: String,
    pub bounty: u128,
    pub status: TaskStatus,
    #[serde(default)]
    pub proof_type: ProofType,
    #[serde(default)]
    pub metadata: Option<TaskMetadata>,
    pub worker: Option<String>,
    pub committed_hash: Option<Hash32>,
    pub result_hash: Option<Hash32>,
    pub reveal_salt: Option<[u8; 32]>,
    pub committed_at_height: Option<u64>,
    pub reveal_deadline_height: Option<u64>,
    #[serde(default)]
    pub challenge_deadline_height: Option<u64>,
    /// Snapshot of challenge/resolve window semantics captured at reveal.
    /// Kept optional for backward-compatible deserialization of pre-upgrade tasks.
    #[serde(default)]
    pub challenge_window_blocks_snapshot: Option<u64>,
    pub challenged_at_height: Option<u64>,
    pub resolve_deadline_height: Option<u64>,
    pub challenge_bond: Option<u128>,
    pub challenger: Option<String>,
    /// true = challenger bond forfeited/slashed; false = refunded
    pub challenge_bond_forfeited: Option<bool>,
    pub version: u64,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GovProposalStatus {
    Draft = 0,
    Voting = 1,
    Passed = 2,
    Rejected = 3,
    Executed = 4,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovProposalObject {
    pub proposal_id: u64,
    pub title: String,
    pub proposer: String,
    pub status: GovProposalStatus,
    pub version: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovParamObject {
    pub key_id: u64,
    pub key: String,
    pub value: String,
    pub version: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tx {
    pub id: u64,
    pub read_set: Vec<ObjectRef>,
    pub write_set: Vec<ObjectRef>,
    pub payload: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_structs() {
        let tx = Tx {
            id: 1,
            read_set: vec![ObjectRef { id: 7, version: 1 }],
            write_set: vec![ObjectRef { id: 8, version: 2 }],
            payload: vec![1, 2, 3],
        };
        assert_eq!(tx.id, 1);
        assert_eq!(TaskStatus::Open, TaskStatus::Open);
        assert_eq!(GovProposalStatus::Draft, GovProposalStatus::Draft);
    }
}
