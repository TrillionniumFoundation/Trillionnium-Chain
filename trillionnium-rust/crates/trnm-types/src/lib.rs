mod interop_identity;
mod market_reputation;
mod relay;
mod request_status;
mod transcript;
mod transfer;

use serde::{Deserialize, Serialize};

pub use interop_identity::{
    AuditAction, AuditEvent, BridgeRoute, CapabilityScope, CapabilityToken, DidRecord,
    IdentityRegistry, InteropIdentityError, SettlementRecord, SettlementStatus,
};
pub use market_reputation::{
    classify_reputation_tier, compute_reputation_score_bps, MarketReputationInput, ReputationTier,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PrivacyTier {
    Public,
    Internal,
    Restricted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct TaskModelMetadata {
    #[serde(default)]
    pub model_id: Option<String>,
    #[serde(default)]
    pub model_digest: Option<String>,
    #[serde(default)]
    pub version: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct TaskProvenanceMetadata {
    #[serde(default)]
    pub producer_did: Option<String>,
    #[serde(default)]
    pub produced_at: Option<String>,
    #[serde(default)]
    pub provenance_index: Option<String>,
    #[serde(default)]
    pub privacy_tier: Option<PrivacyTier>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct TaskMetadata {
    #[serde(default)]
    pub note: Option<String>,
    #[serde(default)]
    pub task_type: Option<String>,
    #[serde(default)]
    pub input_hash: Option<String>,
    #[serde(default)]
    pub model: Option<TaskModelMetadata>,
    #[serde(default)]
    pub provenance: Option<TaskProvenanceMetadata>,
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

    #[test]
    fn task_metadata_backward_compatible_with_legacy_note_only_payload() {
        let metadata: TaskMetadata = serde_json::from_str(r#"{"note":"legacy"}"#)
            .expect("legacy payload should deserialize");
        assert_eq!(metadata.note.as_deref(), Some("legacy"));
        assert!(metadata.task_type.is_none());
        assert!(metadata.input_hash.is_none());
        assert!(metadata.model.is_none());
        assert!(metadata.provenance.is_none());
    }

    #[test]
    fn task_metadata_roundtrip_with_schema_core_fields() {
        let metadata = TaskMetadata {
            note: Some("interop".into()),
            task_type: Some("inference".into()),
            input_hash: Some("a".repeat(64)),
            model: Some(TaskModelMetadata {
                model_id: Some("trnm-vision-base".into()),
                model_digest: Some("b".repeat(64)),
                version: Some("v1.0.0".into()),
            }),
            provenance: Some(TaskProvenanceMetadata {
                producer_did: Some("did:trnm:org:lane-dae".into()),
                produced_at: Some("2026-03-01T01:00:00Z".into()),
                provenance_index: Some("prov:lane-dae:task-20260301-0001".into()),
                privacy_tier: Some(PrivacyTier::Internal),
            }),
        };

        let raw = serde_json::to_string(&metadata).expect("serialize metadata");
        let decoded: TaskMetadata = serde_json::from_str(&raw).expect("deserialize metadata");
        assert_eq!(decoded, metadata);
    }
}
