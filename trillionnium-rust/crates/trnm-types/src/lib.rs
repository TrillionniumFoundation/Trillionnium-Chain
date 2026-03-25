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

fn default_task_metering_policy_snapshot_version() -> u8 {
    0
}

fn default_task_metering_ratio_denominator() -> u128 {
    1
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskMeteringSnapshot {
    pub workload_class: String,
    pub metering_schema: String,
    #[serde(default = "default_task_metering_policy_snapshot_version")]
    pub policy_snapshot_version: u8,
    pub receipt_hash: String,
    pub prompt_tokens: u64,
    pub generated_tokens: u64,
    pub decode_steps: u64,
    pub kv_bytes_moved: u64,
    pub normalized_work_units: u128,
    pub prompt_token_weight: u128,
    pub generated_token_weight: u128,
    pub decode_step_weight: u128,
    pub kv_byte_weight: u128,
    #[serde(default)]
    pub min_accept_work_units: u128,
    #[serde(default)]
    pub challenge_success_bounty_base: u128,
    #[serde(default)]
    pub challenge_success_bounty_per_work_unit_num: u128,
    #[serde(default = "default_task_metering_ratio_denominator")]
    pub challenge_success_bounty_per_work_unit_den: u128,
    #[serde(default)]
    pub worker_completion_bonus_per_work_unit_num: u128,
    #[serde(default = "default_task_metering_ratio_denominator")]
    pub worker_completion_bonus_per_work_unit_den: u128,
    #[serde(default)]
    pub worker_slash_rebate_per_work_unit_num: u128,
    #[serde(default = "default_task_metering_ratio_denominator")]
    pub worker_slash_rebate_per_work_unit_den: u128,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct TaskMetadataCompatibility {
    pub legacy_note_only: bool,
    pub canonical_core_fields: bool,
    pub complete_metering_snapshot: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskMetadataCompatibilityFinding {
    LegacyNoteOnlyPayload,
    NonCanonicalCoreFields,
    IncompleteMeteringSnapshot,
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
    #[serde(default)]
    pub metering: Option<TaskMeteringSnapshot>,
}

fn has_canonical_metadata_atom(value: &str) -> bool {
    let trimmed = value.trim();
    !trimmed.is_empty() && trimmed == value
}

impl TaskMeteringSnapshot {
    pub fn has_complete_core_fields(&self) -> bool {
        has_canonical_metadata_atom(&self.workload_class)
            && has_canonical_metadata_atom(&self.metering_schema)
            && has_canonical_metadata_atom(&self.receipt_hash)
    }
}

impl TaskMetadata {
    pub fn compatibility_profile(&self) -> TaskMetadataCompatibility {
        let legacy_note_only = self.note.is_some()
            && self.task_type.is_none()
            && self.input_hash.is_none()
            && self.model.is_none()
            && self.provenance.is_none()
            && self.metering.is_none();

        let canonical_core_fields = self
            .note
            .as_deref()
            .map(has_canonical_metadata_atom)
            .unwrap_or(true)
            && self
                .task_type
                .as_deref()
                .map(has_canonical_metadata_atom)
                .unwrap_or(true)
            && self
                .input_hash
                .as_deref()
                .map(has_canonical_metadata_atom)
                .unwrap_or(true)
            && self
                .model
                .as_ref()
                .map(|model| {
                    model
                        .model_id
                        .as_deref()
                        .map(has_canonical_metadata_atom)
                        .unwrap_or(true)
                        && model
                            .model_digest
                            .as_deref()
                            .map(has_canonical_metadata_atom)
                            .unwrap_or(true)
                        && model
                            .version
                            .as_deref()
                            .map(has_canonical_metadata_atom)
                            .unwrap_or(true)
                })
                .unwrap_or(true)
            && self
                .provenance
                .as_ref()
                .map(|provenance| {
                    provenance
                        .producer_did
                        .as_deref()
                        .map(has_canonical_metadata_atom)
                        .unwrap_or(true)
                        && provenance
                            .produced_at
                            .as_deref()
                            .map(has_canonical_metadata_atom)
                            .unwrap_or(true)
                        && provenance
                            .provenance_index
                            .as_deref()
                            .map(has_canonical_metadata_atom)
                            .unwrap_or(true)
                })
                .unwrap_or(true)
            && self
                .metering
                .as_ref()
                .map(TaskMeteringSnapshot::has_complete_core_fields)
                .unwrap_or(true);

        let complete_metering_snapshot = self
            .metering
            .as_ref()
            .map(TaskMeteringSnapshot::has_complete_core_fields)
            .unwrap_or(true);

        TaskMetadataCompatibility {
            legacy_note_only,
            canonical_core_fields,
            complete_metering_snapshot,
        }
    }

    pub fn compatibility_findings(&self) -> Vec<TaskMetadataCompatibilityFinding> {
        let compatibility = self.compatibility_profile();
        let mut findings = Vec::new();
        if compatibility.legacy_note_only {
            findings.push(TaskMetadataCompatibilityFinding::LegacyNoteOnlyPayload);
        }
        if !compatibility.canonical_core_fields {
            findings.push(TaskMetadataCompatibilityFinding::NonCanonicalCoreFields);
        }
        if !compatibility.complete_metering_snapshot {
            findings.push(TaskMetadataCompatibilityFinding::IncompleteMeteringSnapshot);
        }
        findings
    }
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
        assert!(metadata.metering.is_none());
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
            metering: Some(TaskMeteringSnapshot {
                workload_class: "llm_inference".into(),
                metering_schema: "llm_token_meter_v1".into(),
                policy_snapshot_version: 1,
                receipt_hash: "abc123".into(),
                prompt_tokens: 10,
                generated_tokens: 20,
                decode_steps: 20,
                kv_bytes_moved: 4096,
                normalized_work_units: 30,
                prompt_token_weight: 1,
                generated_token_weight: 1,
                decode_step_weight: 1,
                kv_byte_weight: 0,
                min_accept_work_units: 5,
                challenge_success_bounty_base: 1,
                challenge_success_bounty_per_work_unit_num: 1,
                challenge_success_bounty_per_work_unit_den: 192,
                worker_completion_bonus_per_work_unit_num: 1,
                worker_completion_bonus_per_work_unit_den: 256,
                worker_slash_rebate_per_work_unit_num: 1,
                worker_slash_rebate_per_work_unit_den: 384,
            }),
        };

        let raw = serde_json::to_string(&metadata).expect("serialize metadata");
        let decoded: TaskMetadata = serde_json::from_str(&raw).expect("deserialize metadata");
        assert_eq!(decoded, metadata);

        let compatibility = decoded.compatibility_profile();
        assert!(!compatibility.legacy_note_only);
        assert!(compatibility.canonical_core_fields);
        assert!(compatibility.complete_metering_snapshot);
    }

    #[test]
    fn task_metadata_compatibility_profile_marks_legacy_note_only_payload() {
        let metadata: TaskMetadata = serde_json::from_str(r#"{"note":"legacy"}"#)
            .expect("legacy payload should deserialize");
        let compatibility = metadata.compatibility_profile();
        assert!(compatibility.legacy_note_only);
        assert!(compatibility.canonical_core_fields);
        assert!(compatibility.complete_metering_snapshot);
        assert_eq!(
            metadata.compatibility_findings(),
            vec![TaskMetadataCompatibilityFinding::LegacyNoteOnlyPayload]
        );
    }

    #[test]
    fn task_metadata_compatibility_profile_rejects_non_canonical_model_and_provenance_fields() {
        let metadata = TaskMetadata {
            model: Some(TaskModelMetadata {
                model_id: Some(" trnm-vision-base".into()),
                model_digest: Some("b".repeat(64)),
                version: Some("v1.0.0 ".into()),
            }),
            provenance: Some(TaskProvenanceMetadata {
                producer_did: Some("did:trnm:org:lane-dae".into()),
                produced_at: Some("2026-03-01T01:00:00Z".into()),
                provenance_index: Some(" prov:lane-dae:task-20260301-0001".into()),
                privacy_tier: Some(PrivacyTier::Internal),
            }),
            ..TaskMetadata::default()
        };

        let compatibility = metadata.compatibility_profile();
        assert!(!compatibility.legacy_note_only);
        assert!(!compatibility.canonical_core_fields);
        assert!(compatibility.complete_metering_snapshot);
        assert_eq!(
            metadata.compatibility_findings(),
            vec![TaskMetadataCompatibilityFinding::NonCanonicalCoreFields]
        );
    }

    #[test]
    fn task_metadata_compatibility_profile_rejects_non_canonical_metering_core_fields() {
        let metadata = TaskMetadata {
            metering: Some(TaskMeteringSnapshot {
                workload_class: " llm_inference".into(),
                metering_schema: "llm_token_meter_v1".into(),
                policy_snapshot_version: 1,
                receipt_hash: " ".into(),
                prompt_tokens: 1,
                generated_tokens: 1,
                decode_steps: 1,
                kv_bytes_moved: 1,
                normalized_work_units: 1,
                prompt_token_weight: 1,
                generated_token_weight: 1,
                decode_step_weight: 1,
                kv_byte_weight: 1,
                min_accept_work_units: 0,
                challenge_success_bounty_base: 0,
                challenge_success_bounty_per_work_unit_num: 0,
                challenge_success_bounty_per_work_unit_den: 1,
                worker_completion_bonus_per_work_unit_num: 0,
                worker_completion_bonus_per_work_unit_den: 1,
                worker_slash_rebate_per_work_unit_num: 0,
                worker_slash_rebate_per_work_unit_den: 1,
            }),
            ..TaskMetadata::default()
        };

        let compatibility = metadata.compatibility_profile();
        assert!(!compatibility.legacy_note_only);
        assert!(!compatibility.canonical_core_fields);
        assert!(!compatibility.complete_metering_snapshot);
        assert_eq!(
            metadata.compatibility_findings(),
            vec![
                TaskMetadataCompatibilityFinding::NonCanonicalCoreFields,
                TaskMetadataCompatibilityFinding::IncompleteMeteringSnapshot,
            ]
        );
    }

    #[test]
    fn task_object_defaults_proof_type_when_legacy_payload_omits_it() {
        let raw = r#"{
            "task_id": 7,
            "creator": "did:trnm:worker:legacy",
            "bounty": 100,
            "status": "Open",
            "version": 1
        }"#;

        let task: TaskObject =
            serde_json::from_str(raw).expect("legacy task payload should deserialize");
        assert_eq!(task.proof_type, ProofType::Fraud);
        assert!(task.metadata.is_none());
    }
}
