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

fn default_task_settlement_schema() -> String {
    "poco_v1".to_string()
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskSettlementSnapshot {
    #[serde(default = "default_task_settlement_schema")]
    pub settlement_schema: String,
    pub tokenizer_id: String,
    pub tokenizer_version: String,
    pub output_hash: String,
    pub output_token_count: u64,
    #[serde(default)]
    pub output_root: Option<String>,
    #[serde(default)]
    pub output_span_commitment: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct TaskMetadataCompatibility {
    pub legacy_note_only: bool,
    pub canonical_core_fields: bool,
    pub complete_metering_snapshot: bool,
    pub complete_settlement_snapshot: bool,
}

impl TaskMetadataCompatibility {
    pub fn is_runtime_compatible(&self) -> bool {
        self.canonical_core_fields
            && self.complete_metering_snapshot
            && self.complete_settlement_snapshot
    }

    pub fn requires_governance_upgrade(&self) -> bool {
        self.legacy_note_only || !self.is_runtime_compatible()
    }

    /// Stable typed ordering for query/report surfaces that need deterministic
    /// governance-upgrade diagnostics without re-encoding precedence rules.
    pub fn findings(&self) -> Vec<TaskMetadataCompatibilityFinding> {
        let mut findings = Vec::new();
        if self.legacy_note_only {
            findings.push(TaskMetadataCompatibilityFinding::LegacyNoteOnlyPayload);
        }
        if !self.canonical_core_fields {
            findings.push(TaskMetadataCompatibilityFinding::NonCanonicalCoreFields);
        }
        if !self.complete_metering_snapshot {
            findings.push(TaskMetadataCompatibilityFinding::IncompleteMeteringSnapshot);
        }
        if !self.complete_settlement_snapshot {
            findings.push(TaskMetadataCompatibilityFinding::IncompleteSettlementSnapshot);
        }
        findings
    }

    pub fn primary_finding(&self) -> Option<TaskMetadataCompatibilityFinding> {
        self.findings().into_iter().next()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskMetadataCompatibilityFinding {
    LegacyNoteOnlyPayload,
    NonCanonicalCoreFields,
    IncompleteMeteringSnapshot,
    IncompleteSettlementSnapshot,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskMetadataCompatibilityReport {
    pub compatibility: TaskMetadataCompatibility,
    pub requires_governance_upgrade: bool,
    pub findings: Vec<TaskMetadataCompatibilityFinding>,
}

impl TaskMetadataCompatibilityReport {
    /// Deterministic headline reason for query surfaces that want a single,
    /// stable governance-upgrade classification without re-encoding precedence.
    pub fn primary_finding(&self) -> Option<TaskMetadataCompatibilityFinding> {
        self.compatibility.primary_finding()
    }

    /// Query-facing helper so downstream surfaces can omit empty arrays without
    /// re-encoding the governance-upgrade finding rules themselves.
    pub fn findings_nonempty(&self) -> Option<Vec<TaskMetadataCompatibilityFinding>> {
        (!self.findings.is_empty()).then_some(self.findings.clone())
    }
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settlement: Option<TaskSettlementSnapshot>,
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

impl TaskSettlementSnapshot {
    pub fn has_complete_core_fields(&self) -> bool {
        let output_root_canonical = self
            .output_root
            .as_deref()
            .map(has_canonical_metadata_atom)
            .unwrap_or(false);
        let output_span_commitment_canonical = self
            .output_span_commitment
            .as_deref()
            .map(has_canonical_metadata_atom)
            .unwrap_or(false);

        has_canonical_metadata_atom(&self.settlement_schema)
            && has_canonical_metadata_atom(&self.tokenizer_id)
            && has_canonical_metadata_atom(&self.tokenizer_version)
            && has_canonical_metadata_atom(&self.output_hash)
            && self
                .output_root
                .as_deref()
                .map(has_canonical_metadata_atom)
                .unwrap_or(true)
            && self
                .output_span_commitment
                .as_deref()
                .map(has_canonical_metadata_atom)
                .unwrap_or(true)
            && (output_root_canonical || output_span_commitment_canonical)
    }
}

impl TaskMetadata {
    pub fn compatibility_report(&self) -> TaskMetadataCompatibilityReport {
        self.compatibility_report_with_settlement_snapshot(self.settlement.as_ref())
    }

    pub fn compatibility_report_with_settlement_snapshot(
        &self,
        settlement: Option<&TaskSettlementSnapshot>,
    ) -> TaskMetadataCompatibilityReport {
        let settlement = settlement.or(self.settlement.as_ref());
        let legacy_note_only = self.note.is_some()
            && self.task_type.is_none()
            && self.input_hash.is_none()
            && self.model.is_none()
            && self.provenance.is_none()
            && self.metering.is_none()
            && settlement.is_none();

        // Keep top-level metadata canonicality distinct from the metering snapshot verdict.
        // This makes governance-upgrade diagnostics clearer at query time: malformed
        // metering no longer masquerades as a generic core-field failure.
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
                .unwrap_or(true);

        let complete_metering_snapshot = self
            .metering
            .as_ref()
            .map(TaskMeteringSnapshot::has_complete_core_fields)
            .unwrap_or(true);
        let complete_settlement_snapshot = settlement
            .map(TaskSettlementSnapshot::has_complete_core_fields)
            .unwrap_or(true);

        let compatibility = TaskMetadataCompatibility {
            legacy_note_only,
            canonical_core_fields,
            complete_metering_snapshot,
            complete_settlement_snapshot,
        };

        let findings = compatibility.findings();

        TaskMetadataCompatibilityReport {
            requires_governance_upgrade: compatibility.requires_governance_upgrade(),
            compatibility,
            findings,
        }
    }

    pub fn compatibility_profile(&self) -> TaskMetadataCompatibility {
        self.compatibility_report().compatibility
    }

    pub fn compatibility_findings(&self) -> Vec<TaskMetadataCompatibilityFinding> {
        self.compatibility_report().findings
    }

    pub fn compatibility_findings_nonempty(&self) -> Option<Vec<TaskMetadataCompatibilityFinding>> {
        self.compatibility_report().findings_nonempty()
    }

    pub fn primary_compatibility_finding(&self) -> Option<TaskMetadataCompatibilityFinding> {
        self.compatibility_report().primary_finding()
    }

    pub fn requires_runtime_metadata_upgrade(&self) -> bool {
        self.compatibility_report().requires_governance_upgrade
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

pub const EMERGENCY_PAUSE_KEY_ID: u64 = 7_999;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GovParamKey {
    MaxBlockMs,
    MaxParallelWorkers,
    MinWorkerStake,
    ChallengeMinBond,
    ChallengeMinBondBountyBps,
    ChallengeMinBondWorkerStakeBps,
    ChallengeWindowBlocks,
    ChallengeSuccessBounty,
    LlmMeterPromptTokenWeight,
    LlmMeterGeneratedTokenWeight,
    LlmMeterDecodeStepWeight,
    LlmMeterKvByteWeight,
    LlmMeterMinAcceptWorkUnits,
    LlmMeterChallengeSuccessBountyPerWorkUnitNum,
    LlmMeterChallengeSuccessBountyPerWorkUnitDen,
    LlmMeterWorkerCompletionBonusPerWorkUnitNum,
    LlmMeterWorkerCompletionBonusPerWorkUnitDen,
    LlmMeterWorkerSlashRebatePerWorkUnitNum,
    LlmMeterWorkerSlashRebatePerWorkUnitDen,
    ResolveAuthority,
    EmergencyPause,
    MonetaryPolicyTickIntervalBlocks,
    MonetaryPolicyTickCooldownBlocks,
    MonetaryBaseIssuancePerTick,
    MonetaryBaseBurnPerTick,
}

impl GovParamKey {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MaxBlockMs => "max_block_ms",
            Self::MaxParallelWorkers => "max_parallel_workers",
            Self::MinWorkerStake => "min_worker_stake",
            Self::ChallengeMinBond => "challenge_min_bond",
            Self::ChallengeMinBondBountyBps => "challenge_min_bond_bounty_bps",
            Self::ChallengeMinBondWorkerStakeBps => "challenge_min_bond_worker_stake_bps",
            Self::ChallengeWindowBlocks => "challenge_window_blocks",
            Self::ChallengeSuccessBounty => "challenge_success_bounty",
            Self::LlmMeterPromptTokenWeight => "llm_meter_prompt_token_weight",
            Self::LlmMeterGeneratedTokenWeight => "llm_meter_generated_token_weight",
            Self::LlmMeterDecodeStepWeight => "llm_meter_decode_step_weight",
            Self::LlmMeterKvByteWeight => "llm_meter_kv_byte_weight",
            Self::LlmMeterMinAcceptWorkUnits => "llm_meter_min_accept_work_units",
            Self::LlmMeterChallengeSuccessBountyPerWorkUnitNum => {
                "llm_meter_challenge_success_bounty_per_work_unit_num"
            }
            Self::LlmMeterChallengeSuccessBountyPerWorkUnitDen => {
                "llm_meter_challenge_success_bounty_per_work_unit_den"
            }
            Self::LlmMeterWorkerCompletionBonusPerWorkUnitNum => {
                "llm_meter_worker_completion_bonus_per_work_unit_num"
            }
            Self::LlmMeterWorkerCompletionBonusPerWorkUnitDen => {
                "llm_meter_worker_completion_bonus_per_work_unit_den"
            }
            Self::LlmMeterWorkerSlashRebatePerWorkUnitNum => {
                "llm_meter_worker_slash_rebate_per_work_unit_num"
            }
            Self::LlmMeterWorkerSlashRebatePerWorkUnitDen => {
                "llm_meter_worker_slash_rebate_per_work_unit_den"
            }
            Self::ResolveAuthority => "resolve_authority",
            Self::EmergencyPause => "emergency_pause",
            Self::MonetaryPolicyTickIntervalBlocks => "monetary_policy_tick_interval_blocks",
            Self::MonetaryPolicyTickCooldownBlocks => "monetary_policy_tick_cooldown_blocks",
            Self::MonetaryBaseIssuancePerTick => "monetary_base_issuance_per_tick",
            Self::MonetaryBaseBurnPerTick => "monetary_base_burn_per_tick",
        }
    }

    pub fn canonical_key_id(self) -> Option<u64> {
        match self {
            Self::EmergencyPause => Some(EMERGENCY_PAUSE_KEY_ID),
            _ => None,
        }
    }

    pub fn from_str(key: &str) -> Option<Self> {
        Some(match key {
            "max_block_ms" => Self::MaxBlockMs,
            "max_parallel_workers" => Self::MaxParallelWorkers,
            "min_worker_stake" => Self::MinWorkerStake,
            "challenge_min_bond" => Self::ChallengeMinBond,
            "challenge_min_bond_bounty_bps" => Self::ChallengeMinBondBountyBps,
            "challenge_min_bond_worker_stake_bps" => Self::ChallengeMinBondWorkerStakeBps,
            "challenge_window_blocks" => Self::ChallengeWindowBlocks,
            "challenge_success_bounty" => Self::ChallengeSuccessBounty,
            "llm_meter_prompt_token_weight" => Self::LlmMeterPromptTokenWeight,
            "llm_meter_generated_token_weight" => Self::LlmMeterGeneratedTokenWeight,
            "llm_meter_decode_step_weight" => Self::LlmMeterDecodeStepWeight,
            "llm_meter_kv_byte_weight" => Self::LlmMeterKvByteWeight,
            "llm_meter_min_accept_work_units" => Self::LlmMeterMinAcceptWorkUnits,
            "llm_meter_challenge_success_bounty_per_work_unit_num" => {
                Self::LlmMeterChallengeSuccessBountyPerWorkUnitNum
            }
            "llm_meter_challenge_success_bounty_per_work_unit_den" => {
                Self::LlmMeterChallengeSuccessBountyPerWorkUnitDen
            }
            "llm_meter_worker_completion_bonus_per_work_unit_num" => {
                Self::LlmMeterWorkerCompletionBonusPerWorkUnitNum
            }
            "llm_meter_worker_completion_bonus_per_work_unit_den" => {
                Self::LlmMeterWorkerCompletionBonusPerWorkUnitDen
            }
            "llm_meter_worker_slash_rebate_per_work_unit_num" => {
                Self::LlmMeterWorkerSlashRebatePerWorkUnitNum
            }
            "llm_meter_worker_slash_rebate_per_work_unit_den" => {
                Self::LlmMeterWorkerSlashRebatePerWorkUnitDen
            }
            "resolve_authority" => Self::ResolveAuthority,
            "emergency_pause" => Self::EmergencyPause,
            "monetary_policy_tick_interval_blocks" => Self::MonetaryPolicyTickIntervalBlocks,
            "monetary_policy_tick_cooldown_blocks" => Self::MonetaryPolicyTickCooldownBlocks,
            "monetary_base_issuance_per_tick" => Self::MonetaryBaseIssuancePerTick,
            "monetary_base_burn_per_tick" => Self::MonetaryBaseBurnPerTick,
            _ => return None,
        })
    }

    pub fn validate_key_id(self, key_id: u64) -> Result<(), String> {
        if let Some(expected_key_id) = self.canonical_key_id() {
            if key_id != expected_key_id {
                return Err(format!(
                    "governance key id mismatch for {}: expected_id={}, attempted_id={}",
                    self.as_str(),
                    expected_key_id,
                    key_id
                ));
            }
        }
        Ok(())
    }
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
    fn task_settlement_snapshot_core_fields_accept_output_root_binding() {
        let snapshot = TaskSettlementSnapshot {
            settlement_schema: "poco_v1".into(),
            tokenizer_id: "llama3-tokenizer".into(),
            tokenizer_version: "1.0.0".into(),
            output_hash: format!("0x{}", "a".repeat(64)),
            output_token_count: 512,
            output_root: Some(format!("0x{}", "b".repeat(64))),
            output_span_commitment: None,
        };

        assert!(snapshot.has_complete_core_fields());
    }

    #[test]
    fn task_settlement_snapshot_core_fields_accept_output_span_commitment_binding() {
        let snapshot = TaskSettlementSnapshot {
            settlement_schema: "poco_v1".into(),
            tokenizer_id: "llama3-tokenizer".into(),
            tokenizer_version: "1.0.0".into(),
            output_hash: format!("0x{}", "c".repeat(64)),
            output_token_count: 512,
            output_root: None,
            output_span_commitment: Some(format!("0x{}", "d".repeat(64))),
        };

        assert!(snapshot.has_complete_core_fields());
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
        assert!(metadata.settlement.is_none());
        assert!(
            metadata
                .compatibility_profile()
                .complete_settlement_snapshot
        );
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
            settlement: Some(TaskSettlementSnapshot {
                settlement_schema: "poco_v1".into(),
                tokenizer_id: "llama3-tokenizer".into(),
                tokenizer_version: "1.0.0".into(),
                output_hash: format!("0x{}", "e".repeat(64)),
                output_token_count: 512,
                output_root: Some(format!("0x{}", "f".repeat(64))),
                output_span_commitment: None,
            }),
        };

        let raw = serde_json::to_string(&metadata).expect("serialize metadata");
        let decoded: TaskMetadata = serde_json::from_str(&raw).expect("deserialize metadata");
        assert_eq!(decoded, metadata);

        let compatibility = decoded.compatibility_profile();
        assert!(!compatibility.legacy_note_only);
        assert!(compatibility.canonical_core_fields);
        assert!(compatibility.complete_metering_snapshot);
        assert!(compatibility.complete_settlement_snapshot);
        assert!(compatibility.is_runtime_compatible());
        assert!(!compatibility.requires_governance_upgrade());
        assert!(!decoded.requires_runtime_metadata_upgrade());
        assert_eq!(decoded.compatibility_findings_nonempty(), None);
    }

    #[test]
    fn task_metadata_compatibility_report_stays_consistent_with_helper_accessors() {
        let metadata = TaskMetadata {
            note: Some(" legacy ".into()),
            task_type: None,
            input_hash: None,
            model: None,
            provenance: None,
            metering: Some(TaskMeteringSnapshot {
                workload_class: "llm_inference".into(),
                metering_schema: "llm_token_meter_v1".into(),
                receipt_hash: "".into(),
                prompt_tokens: 0,
                generated_tokens: 0,
                decode_steps: 0,
                kv_bytes_moved: 0,
                normalized_work_units: 0,
                prompt_token_weight: 1,
                generated_token_weight: 1,
                decode_step_weight: 1,
                kv_byte_weight: 0,
                policy_snapshot_version: 1,
                min_accept_work_units: 0,
                challenge_success_bounty_base: 0,
                challenge_success_bounty_per_work_unit_num: 0,
                challenge_success_bounty_per_work_unit_den: 1,
                worker_completion_bonus_per_work_unit_num: 0,
                worker_completion_bonus_per_work_unit_den: 1,
                worker_slash_rebate_per_work_unit_num: 0,
                worker_slash_rebate_per_work_unit_den: 1,
            }),
            settlement: None,
        };

        let report = metadata.compatibility_report();
        assert_eq!(report.compatibility, metadata.compatibility_profile());
        assert_eq!(
            report.requires_governance_upgrade,
            metadata.requires_runtime_metadata_upgrade()
        );
        assert_eq!(report.findings, metadata.compatibility_findings());
        assert_eq!(
            report.findings,
            vec![
                TaskMetadataCompatibilityFinding::NonCanonicalCoreFields,
                TaskMetadataCompatibilityFinding::IncompleteMeteringSnapshot,
            ]
        );
        assert_eq!(
            report.primary_finding(),
            Some(TaskMetadataCompatibilityFinding::NonCanonicalCoreFields)
        );
        assert_eq!(
            metadata.primary_compatibility_finding(),
            Some(TaskMetadataCompatibilityFinding::NonCanonicalCoreFields)
        );
    }

    #[test]
    fn task_metadata_compatibility_profile_marks_legacy_note_only_payload() {
        let metadata: TaskMetadata = serde_json::from_str(r#"{"note":"legacy"}"#)
            .expect("legacy payload should deserialize");
        let compatibility = metadata.compatibility_profile();
        assert!(compatibility.legacy_note_only);
        assert!(compatibility.canonical_core_fields);
        assert!(compatibility.complete_metering_snapshot);
        assert!(compatibility.complete_settlement_snapshot);
        assert!(compatibility.is_runtime_compatible());
        assert!(compatibility.requires_governance_upgrade());
        assert!(metadata.requires_runtime_metadata_upgrade());
        assert_eq!(
            metadata.compatibility_findings(),
            vec![TaskMetadataCompatibilityFinding::LegacyNoteOnlyPayload]
        );
        assert_eq!(
            metadata.compatibility_findings_nonempty(),
            Some(vec![
                TaskMetadataCompatibilityFinding::LegacyNoteOnlyPayload
            ])
        );
        assert_eq!(
            metadata.primary_compatibility_finding(),
            Some(TaskMetadataCompatibilityFinding::LegacyNoteOnlyPayload)
        );
    }

    #[test]
    fn task_metadata_compatibility_helpers_preserve_typed_finding_order() {
        let compatibility = TaskMetadataCompatibility {
            legacy_note_only: true,
            canonical_core_fields: false,
            complete_metering_snapshot: false,
            complete_settlement_snapshot: false,
        };

        assert_eq!(
            compatibility.findings(),
            vec![
                TaskMetadataCompatibilityFinding::LegacyNoteOnlyPayload,
                TaskMetadataCompatibilityFinding::NonCanonicalCoreFields,
                TaskMetadataCompatibilityFinding::IncompleteMeteringSnapshot,
                TaskMetadataCompatibilityFinding::IncompleteSettlementSnapshot,
            ]
        );
        assert_eq!(
            compatibility.primary_finding(),
            Some(TaskMetadataCompatibilityFinding::LegacyNoteOnlyPayload)
        );
    }

    #[test]
    fn task_metadata_compatibility_findings_serialize_with_stable_query_facing_names() {
        assert_eq!(
            serde_json::to_value(TaskMetadataCompatibilityFinding::LegacyNoteOnlyPayload)
                .expect("serialize finding"),
            serde_json::json!("legacy_note_only_payload")
        );
        assert_eq!(
            serde_json::to_value(TaskMetadataCompatibilityFinding::NonCanonicalCoreFields)
                .expect("serialize finding"),
            serde_json::json!("non_canonical_core_fields")
        );
        assert_eq!(
            serde_json::to_value(TaskMetadataCompatibilityFinding::IncompleteMeteringSnapshot)
                .expect("serialize finding"),
            serde_json::json!("incomplete_metering_snapshot")
        );
        assert_eq!(
            serde_json::to_value(TaskMetadataCompatibilityFinding::IncompleteSettlementSnapshot)
                .expect("serialize finding"),
            serde_json::json!("incomplete_settlement_snapshot")
        );
    }

    #[test]
    fn task_metadata_compatibility_report_serializes_with_stable_query_facing_shape() {
        let report = TaskMetadataCompatibilityReport {
            compatibility: TaskMetadataCompatibility {
                legacy_note_only: true,
                canonical_core_fields: false,
                complete_metering_snapshot: false,
                complete_settlement_snapshot: false,
            },
            requires_governance_upgrade: true,
            findings: vec![
                TaskMetadataCompatibilityFinding::LegacyNoteOnlyPayload,
                TaskMetadataCompatibilityFinding::NonCanonicalCoreFields,
                TaskMetadataCompatibilityFinding::IncompleteMeteringSnapshot,
                TaskMetadataCompatibilityFinding::IncompleteSettlementSnapshot,
            ],
        };

        assert_eq!(
            report.primary_finding(),
            Some(TaskMetadataCompatibilityFinding::LegacyNoteOnlyPayload)
        );
        assert_eq!(
            report.findings_nonempty(),
            Some(vec![
                TaskMetadataCompatibilityFinding::LegacyNoteOnlyPayload,
                TaskMetadataCompatibilityFinding::NonCanonicalCoreFields,
                TaskMetadataCompatibilityFinding::IncompleteMeteringSnapshot,
                TaskMetadataCompatibilityFinding::IncompleteSettlementSnapshot,
            ])
        );
        assert_eq!(
            serde_json::to_value(&report).expect("serialize report"),
            serde_json::json!({
                "compatibility": {
                    "legacy_note_only": true,
                    "canonical_core_fields": false,
                    "complete_metering_snapshot": false,
                    "complete_settlement_snapshot": false
                },
                "requires_governance_upgrade": true,
                "findings": [
                    "legacy_note_only_payload",
                    "non_canonical_core_fields",
                    "incomplete_metering_snapshot",
                    "incomplete_settlement_snapshot"
                ]
            })
        );
    }

    #[test]
    fn task_metadata_compatibility_report_omits_empty_findings_array() {
        let report = TaskMetadataCompatibilityReport {
            compatibility: TaskMetadataCompatibility {
                legacy_note_only: false,
                canonical_core_fields: true,
                complete_metering_snapshot: true,
                complete_settlement_snapshot: true,
            },
            requires_governance_upgrade: false,
            findings: Vec::new(),
        };

        assert_eq!(report.primary_finding(), None);
        assert_eq!(report.findings_nonempty(), None);
    }

    #[test]
    fn task_metadata_compatibility_profile_flags_non_canonical_legacy_note_only_payload() {
        let metadata: TaskMetadata = serde_json::from_str(r#"{"note":" legacy "}"#)
            .expect("legacy payload should deserialize");
        let compatibility = metadata.compatibility_profile();
        assert!(compatibility.legacy_note_only);
        assert!(!compatibility.canonical_core_fields);
        assert!(compatibility.complete_metering_snapshot);
        assert!(compatibility.complete_settlement_snapshot);
        assert!(!compatibility.is_runtime_compatible());
        assert!(compatibility.requires_governance_upgrade());
        assert!(metadata.requires_runtime_metadata_upgrade());
        assert_eq!(
            metadata.compatibility_findings(),
            vec![
                TaskMetadataCompatibilityFinding::LegacyNoteOnlyPayload,
                TaskMetadataCompatibilityFinding::NonCanonicalCoreFields,
            ]
        );
        assert_eq!(
            metadata.compatibility_findings_nonempty(),
            Some(vec![
                TaskMetadataCompatibilityFinding::LegacyNoteOnlyPayload,
                TaskMetadataCompatibilityFinding::NonCanonicalCoreFields,
            ])
        );
        assert_eq!(
            metadata.primary_compatibility_finding(),
            Some(TaskMetadataCompatibilityFinding::LegacyNoteOnlyPayload)
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
        assert!(compatibility.complete_settlement_snapshot);
        assert!(!compatibility.is_runtime_compatible());
        assert!(compatibility.requires_governance_upgrade());
        assert!(metadata.requires_runtime_metadata_upgrade());
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
        assert!(compatibility.canonical_core_fields);
        assert!(!compatibility.complete_metering_snapshot);
        assert!(compatibility.complete_settlement_snapshot);
        assert!(!compatibility.is_runtime_compatible());
        assert!(compatibility.requires_governance_upgrade());
        assert!(metadata.requires_runtime_metadata_upgrade());
        assert_eq!(
            metadata.compatibility_findings(),
            vec![TaskMetadataCompatibilityFinding::IncompleteMeteringSnapshot]
        );
    }

    #[test]
    fn task_metadata_compatibility_profile_flags_incomplete_metering_even_when_other_fields_are_canonical(
    ) {
        let metadata = TaskMetadata {
            note: Some("interop".into()),
            task_type: Some("inference".into()),
            input_hash: Some("a".repeat(64)),
            metering: Some(TaskMeteringSnapshot {
                workload_class: "llm_inference".into(),
                metering_schema: " ".into(),
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
            ..TaskMetadata::default()
        };

        let compatibility = metadata.compatibility_profile();
        assert!(!compatibility.legacy_note_only);
        assert!(compatibility.canonical_core_fields);
        assert!(!compatibility.complete_metering_snapshot);
        assert!(compatibility.complete_settlement_snapshot);
        assert!(!compatibility.is_runtime_compatible());
        assert!(compatibility.requires_governance_upgrade());
        assert!(metadata.requires_runtime_metadata_upgrade());
        assert_eq!(
            metadata.compatibility_findings(),
            vec![TaskMetadataCompatibilityFinding::IncompleteMeteringSnapshot]
        );
        assert_eq!(
            metadata.compatibility_findings_nonempty(),
            Some(vec![
                TaskMetadataCompatibilityFinding::IncompleteMeteringSnapshot
            ])
        );
        assert_eq!(
            metadata.primary_compatibility_finding(),
            Some(TaskMetadataCompatibilityFinding::IncompleteMeteringSnapshot)
        );
    }

    #[test]
    fn task_metadata_compatibility_report_with_settlement_snapshot_keeps_settlement_verdict_distinct(
    ) {
        let metadata = TaskMetadata {
            note: Some("interop".into()),
            task_type: Some("inference".into()),
            input_hash: Some("a".repeat(64)),
            ..TaskMetadata::default()
        };
        let settlement = TaskSettlementSnapshot {
            settlement_schema: "poco_v1".into(),
            tokenizer_id: "llama3-tokenizer".into(),
            tokenizer_version: "1.0.0".into(),
            output_hash: format!("0x{}", "e".repeat(64)),
            output_token_count: 512,
            output_root: None,
            output_span_commitment: None,
        };

        let report = metadata.compatibility_report_with_settlement_snapshot(Some(&settlement));

        assert!(!report.compatibility.legacy_note_only);
        assert!(report.compatibility.canonical_core_fields);
        assert!(report.compatibility.complete_metering_snapshot);
        assert!(!report.compatibility.complete_settlement_snapshot);
        assert!(!report.compatibility.is_runtime_compatible());
        assert!(report.requires_governance_upgrade);
        assert_eq!(
            report.findings,
            vec![TaskMetadataCompatibilityFinding::IncompleteSettlementSnapshot]
        );
        assert_eq!(
            report.primary_finding(),
            Some(TaskMetadataCompatibilityFinding::IncompleteSettlementSnapshot)
        );
    }

    #[test]
    fn task_metadata_compatibility_report_uses_inline_settlement_snapshot() {
        let metadata = TaskMetadata {
            note: Some("interop".into()),
            task_type: Some("inference".into()),
            input_hash: Some("a".repeat(64)),
            settlement: Some(TaskSettlementSnapshot {
                settlement_schema: "poco_v1".into(),
                tokenizer_id: "llama3-tokenizer".into(),
                tokenizer_version: "1.0.0".into(),
                output_hash: format!("0x{}", "1".repeat(64)),
                output_token_count: 512,
                output_root: None,
                output_span_commitment: None,
            }),
            ..TaskMetadata::default()
        };

        let report = metadata.compatibility_report();

        assert!(!report.compatibility.legacy_note_only);
        assert!(report.compatibility.canonical_core_fields);
        assert!(report.compatibility.complete_metering_snapshot);
        assert!(!report.compatibility.complete_settlement_snapshot);
        assert!(!report.compatibility.is_runtime_compatible());
        assert!(report.requires_governance_upgrade);
        assert_eq!(
            report.findings,
            vec![TaskMetadataCompatibilityFinding::IncompleteSettlementSnapshot]
        );
        assert_eq!(
            report.primary_finding(),
            Some(TaskMetadataCompatibilityFinding::IncompleteSettlementSnapshot)
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

    #[test]
    fn gov_param_key_roundtrips_canonical_registry_strings() {
        let cases = [
            (GovParamKey::MaxBlockMs, "max_block_ms", None),
            (GovParamKey::ResolveAuthority, "resolve_authority", None),
            (
                GovParamKey::EmergencyPause,
                "emergency_pause",
                Some(EMERGENCY_PAUSE_KEY_ID),
            ),
            (
                GovParamKey::MonetaryBaseBurnPerTick,
                "monetary_base_burn_per_tick",
                None,
            ),
        ];

        for (key, expected_str, expected_key_id) in cases {
            assert_eq!(key.as_str(), expected_str);
            assert_eq!(GovParamKey::from_str(expected_str), Some(key));
            assert_eq!(key.canonical_key_id(), expected_key_id);
        }

        assert_eq!(GovParamKey::from_str("EmergencyPause"), None);
        assert_eq!(GovParamKey::from_str("algorand_governance_key_id"), None);
    }

    #[test]
    fn gov_param_key_enforces_reserved_key_id_bindings_fail_closed() {
        GovParamKey::EmergencyPause
            .validate_key_id(EMERGENCY_PAUSE_KEY_ID)
            .expect("reserved binding should accept the canonical key id");

        let err = GovParamKey::EmergencyPause
            .validate_key_id(EMERGENCY_PAUSE_KEY_ID + 1)
            .expect_err("reserved binding should reject mismatched key ids");
        assert!(
            err.contains("governance key id mismatch for emergency_pause"),
            "unexpected mismatch error: {err}"
        );

        GovParamKey::ResolveAuthority
            .validate_key_id(EMERGENCY_PAUSE_KEY_ID)
            .expect("unpinned keys should not invent a reserved key-id policy here");
    }
}
