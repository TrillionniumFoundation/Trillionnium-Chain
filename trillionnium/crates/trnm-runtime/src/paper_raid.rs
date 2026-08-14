use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use trnm_protocol::{
    account_key, fee_policy_key,
    paper_raid_finality_applied_command_key as protocol_paper_raid_finality_applied_command_key,
    paper_raid_finality_applied_command_key_v3 as protocol_paper_raid_finality_applied_command_key_v3,
    paper_raid_finality_applied_command_key_v4 as protocol_paper_raid_finality_applied_command_key_v4,
    paper_raid_finality_commitment_key as protocol_paper_raid_finality_commitment_key,
    paper_raid_finality_commitment_key_v3 as protocol_paper_raid_finality_commitment_key_v3,
    paper_raid_finality_commitment_key_v4 as protocol_paper_raid_finality_commitment_key_v4,
    research_domain_object_key, AccountV1, CanonicalPaperRaidFinalityTxV2,
    CanonicalPaperRaidFinalityTxV3, CanonicalPaperRaidFinalityTxV4, FeePolicyV1,
    PaperRaidFinalityAppliedRecordV2, PaperRaidFinalityAppliedRecordV3,
    PaperRaidFinalityAppliedRecordV4, ACCOUNT_OBJECT_TYPE_V1, FEE_COLLECTOR_ACCOUNT_V1,
    FEE_POLICY_OBJECT_TYPE_V1, PAPER_RAID_FINALITY_APPLIED_COMMAND_OBJECT_TYPE_V2,
    PAPER_RAID_FINALITY_APPLIED_COMMAND_OBJECT_TYPE_V3,
    PAPER_RAID_FINALITY_APPLIED_COMMAND_OBJECT_TYPE_V4, RESEARCH_DOMAIN_OBJECT_TYPE_V1,
};
use trnm_research_protocol::{
    canonical_hash, AuthorityRole, CanonicalCbor, ExternalKey, ObjectRefV1,
    PaperRaidFinalityCommitmentV2, PaperRaidFinalityCommitmentV3, PaperRaidFinalityCommitmentV4,
    PaperRaidReworkLineageV1, ResearchDomainObjectV1, ResearchObjectKind,
    SignedPaperRaidFinalityCommandV2, SignedPaperRaidFinalityCommandV3,
    SignedPaperRaidFinalityCommandV4,
};

use super::research::load_research_authorities_for_extension;
use super::{
    ensure_type, ExecutionContext, ResourceEstimate, RuntimeError, RuntimeEvent, RuntimeMutation,
    RuntimeReceipt, RuntimeState, StateObject, StateView,
};

pub const PAPER_RAID_FINALITY_COMMITMENT_OBJECT_TYPE_V2: &str =
    "trnm.paper-raid.finality-commitment.v2";
pub const PAPER_RAID_FINALITY_SUBMISSION_INDEX_OBJECT_TYPE_V2: &str =
    "trnm.paper-raid.finality-submission-index.v2";
pub const PAPER_RAID_FINALITY_EVALUATION_INDEX_OBJECT_TYPE_V2: &str =
    "trnm.paper-raid.finality-evaluation-index.v2";
pub const PAPER_RAID_FINALITY_COMMITMENT_OBJECT_TYPE_V3: &str =
    "trnm.paper-raid.finality-commitment.v3";
pub const PAPER_RAID_FINALITY_SUBMISSION_INDEX_OBJECT_TYPE_V3: &str =
    "trnm.paper-raid.finality-submission-index.v3";
pub const PAPER_RAID_FINALITY_EVALUATION_INDEX_OBJECT_TYPE_V3: &str =
    "trnm.paper-raid.finality-evaluation-index.v3";
pub const PAPER_RAID_FINALITY_COMMITMENT_OBJECT_TYPE_V4: &str =
    "trnm.paper-raid.finality-commitment.v4";
pub const PAPER_RAID_FINALITY_SUBMISSION_INDEX_OBJECT_TYPE_V4: &str =
    "trnm.paper-raid.finality-submission-index.v4";
pub const PAPER_RAID_FINALITY_EVALUATION_INDEX_OBJECT_TYPE_V4: &str =
    "trnm.paper-raid.finality-evaluation-index.v4";
pub const PAPER_RAID_FINALITY_REWORK_INDEX_OBJECT_TYPE_V4: &str =
    "trnm.paper-raid.finality-rework-index.v4";

const PAPER_RAID_FINALITY_OPERATION_GAS: u64 = 8_000;
const PAPER_RAID_FINALITY_OBJECT_TOUCH_GAS: u64 = 750;
const MAX_PAPER_RAID_FINALITY_COMMITMENT_BYTES: usize = 128 * 1024;
const MAX_PAPER_RAID_FINALITY_INDEX_RECORD_BYTES: usize = 8 * 1024;
const MAX_MATCH_EVIDENCE_OBJECT_BYTES: usize = 1024 * 1024;
// Account JSON size depends on the fee itself. Charging this proven upper bound
// for both sender and collector writes avoids a gas/serialized-size fixed-point
// while remaining conservative for the protocol's 192-byte signer limit.
const MAX_ACCOUNT_MUTATION_METER_BYTES: u64 = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum PaperRaidFinalityIndexKindV2 {
    Submission,
    Evaluation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PaperRaidFinalityIndexRecordV2 {
    schema: String,
    index_kind: PaperRaidFinalityIndexKindV2,
    paper_project_id: String,
    submission_id: String,
    evaluation_id: String,
    commitment_id: String,
    commitment_object_key_hex: String,
    payload_hash_hex: String,
}

impl PaperRaidFinalityIndexRecordV2 {
    fn from_signed(
        signed: &SignedPaperRaidFinalityCommandV2,
        index_kind: PaperRaidFinalityIndexKindV2,
        commitment_object_key_hex: String,
    ) -> Self {
        Self {
            schema: "trnm_paper_raid_finality_index_record_v2".to_string(),
            index_kind,
            paper_project_id: signed.commitment.paper_project_id.to_hex(),
            submission_id: signed.commitment.submission_id.to_hex(),
            evaluation_id: signed.commitment.evaluation_id.to_hex(),
            commitment_id: signed.commitment.commitment_id.to_hex(),
            commitment_object_key_hex,
            payload_hash_hex: digest_hex(signed.payload_hash()),
        }
    }

    fn canonical_bytes(&self) -> Result<Vec<u8>, RuntimeError> {
        self.validate()?;
        let bytes = serde_json::to_vec(self)
            .map_err(|error| RuntimeError::EncodeObject(error.to_string()))?;
        if bytes.len() > MAX_PAPER_RAID_FINALITY_INDEX_RECORD_BYTES {
            return Err(RuntimeError::PaperRaidFinalityState(
                "Paper Raid finality index record exceeds the runtime byte limit".to_string(),
            ));
        }
        Ok(bytes)
    }

    fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, RuntimeError> {
        if bytes.is_empty() || bytes.len() > MAX_PAPER_RAID_FINALITY_INDEX_RECORD_BYTES {
            return Err(RuntimeError::PaperRaidFinalityState(
                "Paper Raid finality index record is outside the runtime byte limit".to_string(),
            ));
        }
        let record: Self = serde_json::from_slice(bytes).map_err(|error| {
            RuntimeError::PaperRaidFinalityState(format!(
                "decode Paper Raid finality index record: {error}"
            ))
        })?;
        record.validate()?;
        let canonical = serde_json::to_vec(&record)
            .map_err(|error| RuntimeError::EncodeObject(error.to_string()))?;
        if canonical != bytes {
            return Err(RuntimeError::PaperRaidFinalityState(
                "Paper Raid finality index record is not canonical".to_string(),
            ));
        }
        Ok(record)
    }

    fn validate(&self) -> Result<(), RuntimeError> {
        if self.schema != "trnm_paper_raid_finality_index_record_v2"
            || !is_hash_hex(&self.paper_project_id)
            || !is_hash_hex(&self.submission_id)
            || !is_hash_hex(&self.evaluation_id)
            || !is_hash_hex(&self.commitment_id)
            || !is_hash_hex(&self.commitment_object_key_hex)
            || !is_hash_hex(&self.payload_hash_hex)
        {
            return Err(RuntimeError::PaperRaidFinalityState(
                "Paper Raid finality index record is invalid".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PaperRaidFinalityIndexRecordV3 {
    schema: String,
    index_kind: PaperRaidFinalityIndexKindV2,
    paper_project_id: String,
    submission_id: String,
    evaluation_id: String,
    commitment_id: String,
    commitment_object_key_hex: String,
    payload_hash_hex: String,
}

impl PaperRaidFinalityIndexRecordV3 {
    fn from_signed(
        signed: &SignedPaperRaidFinalityCommandV3,
        index_kind: PaperRaidFinalityIndexKindV2,
        commitment_object_key_hex: String,
    ) -> Self {
        Self {
            schema: "trnm_paper_raid_finality_index_record_v3".to_string(),
            index_kind,
            paper_project_id: signed.commitment.paper_project_id.to_hex(),
            submission_id: signed.commitment.submission_id.to_hex(),
            evaluation_id: signed.commitment.evaluation_id.to_hex(),
            commitment_id: signed.commitment.commitment_id.to_hex(),
            commitment_object_key_hex,
            payload_hash_hex: digest_hex(signed.payload_hash()),
        }
    }

    fn canonical_bytes(&self) -> Result<Vec<u8>, RuntimeError> {
        self.validate()?;
        let bytes = serde_json::to_vec(self)
            .map_err(|error| RuntimeError::EncodeObject(error.to_string()))?;
        if bytes.len() > MAX_PAPER_RAID_FINALITY_INDEX_RECORD_BYTES {
            return Err(RuntimeError::PaperRaidFinalityState(
                "Paper Raid V3 finality index record exceeds the runtime byte limit".to_string(),
            ));
        }
        Ok(bytes)
    }

    fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, RuntimeError> {
        if bytes.is_empty() || bytes.len() > MAX_PAPER_RAID_FINALITY_INDEX_RECORD_BYTES {
            return Err(RuntimeError::PaperRaidFinalityState(
                "Paper Raid V3 finality index record is outside the runtime byte limit".to_string(),
            ));
        }
        let record: Self = serde_json::from_slice(bytes).map_err(|error| {
            RuntimeError::PaperRaidFinalityState(format!(
                "decode Paper Raid V3 finality index record: {error}"
            ))
        })?;
        record.validate()?;
        let canonical = serde_json::to_vec(&record)
            .map_err(|error| RuntimeError::EncodeObject(error.to_string()))?;
        if canonical != bytes {
            return Err(RuntimeError::PaperRaidFinalityState(
                "Paper Raid V3 finality index record is not canonical".to_string(),
            ));
        }
        Ok(record)
    }

    fn validate(&self) -> Result<(), RuntimeError> {
        if self.schema != "trnm_paper_raid_finality_index_record_v3"
            || !is_hash_hex(&self.paper_project_id)
            || !is_hash_hex(&self.submission_id)
            || !is_hash_hex(&self.evaluation_id)
            || !is_hash_hex(&self.commitment_id)
            || !is_hash_hex(&self.commitment_object_key_hex)
            || !is_hash_hex(&self.payload_hash_hex)
        {
            return Err(RuntimeError::PaperRaidFinalityState(
                "Paper Raid V3 finality index record is invalid".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PaperRaidFinalityIndexRecordV4 {
    schema: String,
    index_kind: PaperRaidFinalityIndexKindV2,
    paper_project_id: String,
    submission_id: String,
    evaluation_id: String,
    commitment_id: String,
    commitment_object_key_hex: String,
    payload_hash_hex: String,
}

impl PaperRaidFinalityIndexRecordV4 {
    fn from_signed(
        signed: &SignedPaperRaidFinalityCommandV4,
        index_kind: PaperRaidFinalityIndexKindV2,
        commitment_object_key_hex: String,
    ) -> Self {
        Self {
            schema: "trnm_paper_raid_finality_index_record_v4".to_string(),
            index_kind,
            paper_project_id: signed.commitment.paper_project_id.to_hex(),
            submission_id: signed.commitment.submission_id.to_hex(),
            evaluation_id: signed.commitment.evaluation_id.to_hex(),
            commitment_id: signed.commitment.commitment_id.to_hex(),
            commitment_object_key_hex,
            payload_hash_hex: digest_hex(signed.payload_hash()),
        }
    }

    fn canonical_bytes(&self) -> Result<Vec<u8>, RuntimeError> {
        self.validate()?;
        let bytes = serde_json::to_vec(self)
            .map_err(|error| RuntimeError::EncodeObject(error.to_string()))?;
        if bytes.len() > MAX_PAPER_RAID_FINALITY_INDEX_RECORD_BYTES {
            return Err(RuntimeError::PaperRaidFinalityState(
                "Paper Raid V4 finality index record exceeds the runtime byte limit".to_string(),
            ));
        }
        Ok(bytes)
    }

    fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, RuntimeError> {
        if bytes.is_empty() || bytes.len() > MAX_PAPER_RAID_FINALITY_INDEX_RECORD_BYTES {
            return Err(RuntimeError::PaperRaidFinalityState(
                "Paper Raid V4 finality index record is outside the runtime byte limit".to_string(),
            ));
        }
        let record: Self = serde_json::from_slice(bytes).map_err(|error| {
            RuntimeError::PaperRaidFinalityState(format!(
                "decode Paper Raid V4 finality index record: {error}"
            ))
        })?;
        record.validate()?;
        let canonical = serde_json::to_vec(&record)
            .map_err(|error| RuntimeError::EncodeObject(error.to_string()))?;
        if canonical != bytes {
            return Err(RuntimeError::PaperRaidFinalityState(
                "Paper Raid V4 finality index record is not canonical".to_string(),
            ));
        }
        Ok(record)
    }

    fn validate(&self) -> Result<(), RuntimeError> {
        if self.schema != "trnm_paper_raid_finality_index_record_v4"
            || !is_hash_hex(&self.paper_project_id)
            || !is_hash_hex(&self.submission_id)
            || !is_hash_hex(&self.evaluation_id)
            || !is_hash_hex(&self.commitment_id)
            || !is_hash_hex(&self.commitment_object_key_hex)
            || !is_hash_hex(&self.payload_hash_hex)
        {
            return Err(RuntimeError::PaperRaidFinalityState(
                "Paper Raid V4 finality index record is invalid".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PaperRaidFinalityReworkIndexRecordV4 {
    schema: String,
    rework_id: String,
    commitment_id: String,
    commitment_object_key_hex: String,
    payload_hash_hex: String,
}

impl PaperRaidFinalityReworkIndexRecordV4 {
    fn from_signed(
        signed: &SignedPaperRaidFinalityCommandV4,
        lineage: &PaperRaidReworkLineageV1,
        commitment_object_key_hex: String,
    ) -> Self {
        Self {
            schema: "trnm_paper_raid_finality_rework_index_record_v4".to_string(),
            rework_id: lineage.rework_id.to_hex(),
            commitment_id: signed.commitment.commitment_id.to_hex(),
            commitment_object_key_hex,
            payload_hash_hex: digest_hex(signed.payload_hash()),
        }
    }

    fn canonical_bytes(&self) -> Result<Vec<u8>, RuntimeError> {
        self.validate()?;
        let bytes = serde_json::to_vec(self)
            .map_err(|error| RuntimeError::EncodeObject(error.to_string()))?;
        if bytes.len() > MAX_PAPER_RAID_FINALITY_INDEX_RECORD_BYTES {
            return Err(RuntimeError::PaperRaidFinalityState(
                "Paper Raid V4 finality rework index exceeds the runtime byte limit".to_string(),
            ));
        }
        Ok(bytes)
    }

    fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, RuntimeError> {
        if bytes.is_empty() || bytes.len() > MAX_PAPER_RAID_FINALITY_INDEX_RECORD_BYTES {
            return Err(RuntimeError::PaperRaidFinalityState(
                "Paper Raid V4 finality rework index is outside the runtime byte limit".to_string(),
            ));
        }
        let record: Self = serde_json::from_slice(bytes).map_err(|error| {
            RuntimeError::PaperRaidFinalityState(format!(
                "decode Paper Raid V4 finality rework index: {error}"
            ))
        })?;
        record.validate()?;
        let canonical = serde_json::to_vec(&record)
            .map_err(|error| RuntimeError::EncodeObject(error.to_string()))?;
        if canonical != bytes {
            return Err(RuntimeError::PaperRaidFinalityState(
                "Paper Raid V4 finality rework index is not canonical".to_string(),
            ));
        }
        Ok(record)
    }

    fn validate(&self) -> Result<(), RuntimeError> {
        if self.schema != "trnm_paper_raid_finality_rework_index_record_v4"
            || !is_hash_hex(&self.rework_id)
            || !is_hash_hex(&self.commitment_id)
            || !is_hash_hex(&self.commitment_object_key_hex)
            || !is_hash_hex(&self.payload_hash_hex)
        {
            return Err(RuntimeError::PaperRaidFinalityState(
                "Paper Raid V4 finality rework index is invalid".to_string(),
            ));
        }
        Ok(())
    }
}

/// Runtime error-mapped wrapper around the shared protocol key derivation.
pub fn paper_raid_finality_commitment_key(
    commitment_id: ExternalKey,
) -> Result<String, RuntimeError> {
    protocol_paper_raid_finality_commitment_key(commitment_id)
        .map_err(|error| RuntimeError::PaperRaidFinalityState(error.to_string()))
}

/// Runtime error-mapped wrapper around the shared protocol replay-key
/// derivation used independently by Receipt V2 verification.
pub fn paper_raid_finality_applied_command_key(
    command_id: ExternalKey,
) -> Result<String, RuntimeError> {
    protocol_paper_raid_finality_applied_command_key(command_id)
        .map_err(|error| RuntimeError::PaperRaidFinalityState(error.to_string()))
}

pub fn paper_raid_finality_commitment_key_v3(
    commitment_id: ExternalKey,
) -> Result<String, RuntimeError> {
    protocol_paper_raid_finality_commitment_key_v3(commitment_id)
        .map_err(|error| RuntimeError::PaperRaidFinalityState(error.to_string()))
}

pub fn paper_raid_finality_applied_command_key_v3(
    command_id: ExternalKey,
) -> Result<String, RuntimeError> {
    protocol_paper_raid_finality_applied_command_key_v3(command_id)
        .map_err(|error| RuntimeError::PaperRaidFinalityState(error.to_string()))
}

pub fn paper_raid_finality_commitment_key_v4(
    commitment_id: ExternalKey,
) -> Result<String, RuntimeError> {
    protocol_paper_raid_finality_commitment_key_v4(commitment_id)
        .map_err(|error| RuntimeError::PaperRaidFinalityState(error.to_string()))
}

pub fn paper_raid_finality_applied_command_key_v4(
    command_id: ExternalKey,
) -> Result<String, RuntimeError> {
    protocol_paper_raid_finality_applied_command_key_v4(command_id)
        .map_err(|error| RuntimeError::PaperRaidFinalityState(error.to_string()))
}

/// Unique scientific-finality index for one Paper submission. A new command or
/// commitment ID cannot create a second finality for the same Paper/submission
/// tuple.
pub fn paper_raid_finality_submission_index_key(
    paper_project_id: ExternalKey,
    submission_id: ExternalKey,
) -> Result<String, RuntimeError> {
    ensure_nonzero_key("paper_project_id", paper_project_id)?;
    ensure_nonzero_key("submission_id", submission_id)?;
    let mut scope = [0u8; 64];
    scope[..32].copy_from_slice(paper_project_id.as_bytes());
    scope[32..].copy_from_slice(submission_id.as_bytes());
    Ok(digest_hex(canonical_hash(
        "trnm.paper-raid.finality-submission-index.object-key.v2",
        &scope,
    )))
}

/// Unique scientific-finality index for one evaluation identity.
pub fn paper_raid_finality_evaluation_index_key(
    evaluation_id: ExternalKey,
) -> Result<String, RuntimeError> {
    paper_raid_key(
        "trnm.paper-raid.finality-evaluation-index.object-key.v2",
        "evaluation_id",
        evaluation_id,
    )
}

pub fn paper_raid_finality_submission_index_key_v3(
    paper_project_id: ExternalKey,
    submission_id: ExternalKey,
) -> Result<String, RuntimeError> {
    ensure_nonzero_key("paper_project_id", paper_project_id)?;
    ensure_nonzero_key("submission_id", submission_id)?;
    let mut scope = [0u8; 64];
    scope[..32].copy_from_slice(paper_project_id.as_bytes());
    scope[32..].copy_from_slice(submission_id.as_bytes());
    Ok(digest_hex(canonical_hash(
        "trnm.paper-raid.finality-submission-index.object-key.v3",
        &scope,
    )))
}

pub fn paper_raid_finality_evaluation_index_key_v3(
    evaluation_id: ExternalKey,
) -> Result<String, RuntimeError> {
    paper_raid_key(
        "trnm.paper-raid.finality-evaluation-index.object-key.v3",
        "evaluation_id",
        evaluation_id,
    )
}

pub fn paper_raid_finality_submission_index_key_v4(
    paper_project_id: ExternalKey,
    submission_id: ExternalKey,
) -> Result<String, RuntimeError> {
    ensure_nonzero_key("paper_project_id", paper_project_id)?;
    ensure_nonzero_key("submission_id", submission_id)?;
    let mut scope = [0u8; 64];
    scope[..32].copy_from_slice(paper_project_id.as_bytes());
    scope[32..].copy_from_slice(submission_id.as_bytes());
    Ok(digest_hex(canonical_hash(
        "trnm.paper-raid.finality-submission-index.object-key.v4",
        &scope,
    )))
}

pub fn paper_raid_finality_evaluation_index_key_v4(
    evaluation_id: ExternalKey,
) -> Result<String, RuntimeError> {
    paper_raid_key(
        "trnm.paper-raid.finality-evaluation-index.object-key.v4",
        "evaluation_id",
        evaluation_id,
    )
}

pub fn paper_raid_finality_rework_index_key_v4(
    rework_id: ExternalKey,
) -> Result<String, RuntimeError> {
    paper_raid_key(
        "trnm.paper-raid.finality-rework-index.object-key.v4",
        "rework_id",
        rework_id,
    )
}

#[derive(Clone, Copy)]
enum PaperRaidFinalityTxRef<'a> {
    V2(&'a CanonicalPaperRaidFinalityTxV2),
    V3(&'a CanonicalPaperRaidFinalityTxV3),
    V4(&'a CanonicalPaperRaidFinalityTxV4),
}

impl PaperRaidFinalityTxRef<'_> {
    fn sender(self) -> String {
        match self {
            Self::V2(tx) => tx.sender.clone(),
            Self::V3(tx) => tx.sender.clone(),
            Self::V4(tx) => tx.sender.clone(),
        }
    }

    fn nonce(self) -> u64 {
        match self {
            Self::V2(tx) => tx.nonce,
            Self::V3(tx) => tx.nonce,
            Self::V4(tx) => tx.nonce,
        }
    }

    fn max_gas(self) -> u64 {
        match self {
            Self::V2(tx) => tx.max_gas,
            Self::V3(tx) => tx.max_gas,
            Self::V4(tx) => tx.max_gas,
        }
    }

    fn fee_limit(self) -> u128 {
        match self {
            Self::V2(tx) => tx.fee_limit,
            Self::V3(tx) => tx.fee_limit,
            Self::V4(tx) => tx.fee_limit,
        }
    }
}

#[derive(Debug, Clone)]
enum VersionedPaperRaidFinalityCommand {
    V2(SignedPaperRaidFinalityCommandV2),
    V3(SignedPaperRaidFinalityCommandV3),
    V4(SignedPaperRaidFinalityCommandV4),
}

impl VersionedPaperRaidFinalityCommand {
    fn chain_id(&self) -> &str {
        match self {
            Self::V2(signed) => &signed.chain_id,
            Self::V3(signed) => &signed.chain_id,
            Self::V4(signed) => &signed.chain_id,
        }
    }

    fn signer_did(&self) -> &str {
        match self {
            Self::V2(signed) => &signed.signer_did,
            Self::V3(signed) => &signed.signer_did,
            Self::V4(signed) => &signed.signer_did,
        }
    }

    fn signer_role(&self) -> AuthorityRole {
        match self {
            Self::V2(signed) => signed.signer_role,
            Self::V3(signed) => signed.signer_role,
            Self::V4(signed) => signed.signer_role,
        }
    }

    fn public_key(&self) -> [u8; 32] {
        match self {
            Self::V2(signed) => signed.public_key,
            Self::V3(signed) => signed.public_key,
            Self::V4(signed) => signed.public_key,
        }
    }

    fn command_id(&self) -> ExternalKey {
        match self {
            Self::V2(signed) => signed.command_id,
            Self::V3(signed) => signed.command_id,
            Self::V4(signed) => signed.command_id,
        }
    }

    fn commitment_id(&self) -> ExternalKey {
        match self {
            Self::V2(signed) => signed.commitment.commitment_id,
            Self::V3(signed) => signed.commitment.commitment_id,
            Self::V4(signed) => signed.commitment.commitment_id,
        }
    }

    fn paper_project_id(&self) -> ExternalKey {
        match self {
            Self::V2(signed) => signed.commitment.paper_project_id,
            Self::V3(signed) => signed.commitment.paper_project_id,
            Self::V4(signed) => signed.commitment.paper_project_id,
        }
    }

    fn submission_id(&self) -> ExternalKey {
        match self {
            Self::V2(signed) => signed.commitment.submission_id,
            Self::V3(signed) => signed.commitment.submission_id,
            Self::V4(signed) => signed.commitment.submission_id,
        }
    }

    fn evaluation_id(&self) -> ExternalKey {
        match self {
            Self::V2(signed) => signed.commitment.evaluation_id,
            Self::V3(signed) => signed.commitment.evaluation_id,
            Self::V4(signed) => signed.commitment.evaluation_id,
        }
    }

    fn match_evidence_ref(&self) -> ObjectRefV1 {
        match self {
            Self::V2(signed) => signed.commitment.match_evidence_ref,
            Self::V3(signed) => signed.commitment.match_evidence_ref,
            Self::V4(signed) => signed.commitment.match_evidence_ref,
        }
    }

    fn appeal_window_closes_at_unix_s(&self) -> u64 {
        match self {
            Self::V2(signed) => signed.commitment.appeal_window_closes_at_unix_s,
            Self::V3(signed) => signed.commitment.appeal_window_closes_at_unix_s,
            Self::V4(signed) => signed.commitment.appeal_window_closes_at_unix_s,
        }
    }

    fn finalized_at_unix_s(&self) -> u64 {
        match self {
            Self::V2(signed) => signed.commitment.finalized_at_unix_s,
            Self::V3(signed) => signed.commitment.finalized_at_unix_s,
            Self::V4(signed) => signed.commitment.finalized_at_unix_s,
        }
    }

    fn any_eligibility(&self) -> bool {
        match self {
            Self::V2(signed) => {
                signed.commitment.score_eligible
                    || signed.commitment.ranking_eligible
                    || signed.commitment.reward_eligible
                    || signed.commitment.economic_eligible
            }
            Self::V3(signed) => {
                signed.commitment.score_eligible
                    || signed.commitment.ranking_eligible
                    || signed.commitment.reward_eligible
                    || signed.commitment.economic_eligible
            }
            Self::V4(signed) => {
                signed.commitment.score_eligible
                    || signed.commitment.ranking_eligible
                    || signed.commitment.reward_eligible
                    || signed.commitment.economic_eligible
            }
        }
    }

    fn canonical_bytes(&self) -> Vec<u8> {
        match self {
            Self::V2(signed) => signed.canonical_bytes(),
            Self::V3(signed) => signed.canonical_bytes(),
            Self::V4(signed) => signed.canonical_bytes(),
        }
    }

    fn commitment_bytes(&self) -> Vec<u8> {
        match self {
            Self::V2(signed) => signed.commitment.canonical_bytes(),
            Self::V3(signed) => signed.commitment.canonical_bytes(),
            Self::V4(signed) => signed.commitment.canonical_bytes(),
        }
    }

    fn command_fingerprint(&self) -> [u8; 32] {
        match self {
            Self::V2(signed) => signed.command_fingerprint(),
            Self::V3(signed) => signed.command_fingerprint(),
            Self::V4(signed) => signed.command_fingerprint(),
        }
    }

    fn payload_hash(&self) -> [u8; 32] {
        match self {
            Self::V2(signed) => signed.payload_hash(),
            Self::V3(signed) => signed.payload_hash(),
            Self::V4(signed) => signed.payload_hash(),
        }
    }

    fn is_v3(&self) -> bool {
        matches!(self, Self::V3(_))
    }

    fn is_v4(&self) -> bool {
        matches!(self, Self::V4(_))
    }

    fn has_rework_lineage(&self) -> bool {
        matches!(self, Self::V4(signed) if signed.commitment.rework_lineage.is_some())
    }
}

/// Execute the independent Paper Raid V2 scientific-finality ingress without
/// changing the frozen generic Research V1 command or snapshot layouts.
pub fn execute_paper_raid_finality(
    tx: &CanonicalPaperRaidFinalityTxV2,
    context: ExecutionContext<'_>,
    block_time_unix_s: u64,
    view: &dyn StateView,
) -> Result<RuntimeReceipt, RuntimeError> {
    execute_versioned_paper_raid_finality(
        PaperRaidFinalityTxRef::V2(tx),
        context,
        block_time_unix_s,
        view,
    )
}

pub fn execute_paper_raid_finality_v3(
    tx: &CanonicalPaperRaidFinalityTxV3,
    context: ExecutionContext<'_>,
    block_time_unix_s: u64,
    view: &dyn StateView,
) -> Result<RuntimeReceipt, RuntimeError> {
    execute_versioned_paper_raid_finality(
        PaperRaidFinalityTxRef::V3(tx),
        context,
        block_time_unix_s,
        view,
    )
}

pub fn execute_paper_raid_finality_v4(
    tx: &CanonicalPaperRaidFinalityTxV4,
    context: ExecutionContext<'_>,
    block_time_unix_s: u64,
    view: &dyn StateView,
) -> Result<RuntimeReceipt, RuntimeError> {
    execute_versioned_paper_raid_finality(
        PaperRaidFinalityTxRef::V4(tx),
        context,
        block_time_unix_s,
        view,
    )
}

fn execute_versioned_paper_raid_finality(
    tx: PaperRaidFinalityTxRef<'_>,
    context: ExecutionContext<'_>,
    block_time_unix_s: u64,
    view: &dyn StateView,
) -> Result<RuntimeReceipt, RuntimeError> {
    let signed = validate_transaction_context(tx, context)?;
    for required_unix_s in [
        signed.appeal_window_closes_at_unix_s(),
        signed.finalized_at_unix_s(),
    ] {
        if block_time_unix_s < required_unix_s {
            return Err(RuntimeError::PaperRaidFinalityTimeNotReached {
                block_time_unix_s,
                required_unix_s,
            });
        }
    }
    if signed.any_eligibility() {
        // The V2 commitment wire deliberately reserves future settlement
        // facts, but this candidate has no independent Receipt-V2-verified
        // activation command. Scientific finality cannot self-activate score,
        // ranking, reward, or economic eligibility.
        return Err(RuntimeError::PaperRaidFinalityEligibilityLocked);
    }
    let (authorities, authority_read_bytes, authority_touched_keys) =
        load_research_authorities_for_extension(view)?;
    let authorized = authorities
        .hepta_authorities
        .binary_search_by(|identity| {
            (identity.signer_did.as_str(), identity.public_key)
                .cmp(&(signed.signer_did(), signed.public_key()))
        })
        .is_ok();
    if !authorized {
        return Err(RuntimeError::PaperRaidFinalityUnauthorizedAuthority);
    }
    let same_version_terminal = defer_paper_raid_collision(reject_applied_replay(view, &signed))?;
    let cross_version_terminal = scan_cross_version_collisions(view, &signed)?;
    if let Some(error) = same_version_terminal.or(cross_version_terminal) {
        // Even an ordinary applied/cross-version terminal may coexist with an
        // independently addressed same-version commitment or index. Validate
        // those surfaces before returning the terminal so damaged state is
        // never masked by replay/collision precedence.
        let commitment_key = versioned_commitment_key(&signed)?;
        scan_same_version_collision_surfaces(view, &signed, &commitment_key)?;
        return Err(error);
    }

    let mut economic_state = RuntimeState::new(view);
    let policy = economic_state.policy()?.value.clone();
    let policy_read_bytes = metered_read_or_default(
        view,
        &fee_policy_key(),
        FEE_POLICY_OBJECT_TYPE_V1,
        &serde_json::to_vec(&FeePolicyV1::default())
            .map_err(|error| RuntimeError::EncodeObject(error.to_string()))?,
    )?;
    let sender_read_bytes = metered_read_or_default(
        view,
        &account_key(&tx.sender()),
        ACCOUNT_OBJECT_TYPE_V1,
        &serde_json::to_vec(&AccountV1 {
            account: tx.sender(),
            balance: 0,
            nonce: 0,
        })
        .map_err(|error| RuntimeError::EncodeObject(error.to_string()))?,
    )?;
    let signed_validation_bytes = u64::try_from(signed.canonical_bytes().len())
        .map_err(|_| RuntimeError::ArithmeticOverflow)?;
    let lower_state_bytes = authority_read_bytes
        .checked_add(policy_read_bytes)
        .and_then(|bytes| bytes.checked_add(sender_read_bytes))
        .and_then(|bytes| bytes.checked_add(signed_validation_bytes))
        .ok_or(RuntimeError::ArithmeticOverflow)?;
    // Authority loading touches both the legacy-snapshot sentinel and the
    // immutable authority object. The lower bound also covers policy, sender,
    // and the applied-record replay lookup.
    let lower_touched_keys = authority_touched_keys
        .checked_add(3)
        .ok_or(RuntimeError::ArithmeticOverflow)?;
    let lower_bound = estimate_resources(context, &policy, lower_state_bytes, lower_touched_keys)?;
    enforce_limits(tx, lower_bound)?;
    let (expected_nonce, available_balance) = account_nonce_and_balance(&mut economic_state, tx)?;
    if tx.nonce() != expected_nonce {
        return Err(RuntimeError::NonceMismatch {
            expected: expected_nonce,
            received: tx.nonce(),
        });
    }
    if available_balance < lower_bound.fee_estimate {
        return Err(RuntimeError::InsufficientBalance {
            account: tx.sender(),
            required: lower_bound.fee_estimate,
            available: available_balance,
        });
    }

    let commitment_key = versioned_commitment_key(&signed)?;
    if let Some(error) = scan_same_version_collision_surfaces(view, &signed, &commitment_key)? {
        return Err(error);
    }
    let submission_index_key = versioned_submission_index_key(&signed)?;
    let evaluation_index_key = versioned_evaluation_index_key(&signed)?;
    let rework_index = match &signed {
        VersionedPaperRaidFinalityCommand::V4(v4) => match &v4.commitment.rework_lineage {
            Some(lineage) => {
                let key = paper_raid_finality_rework_index_key_v4(lineage.rework_id)?;
                Some((
                    key,
                    PaperRaidFinalityReworkIndexRecordV4::from_signed(
                        v4,
                        lineage,
                        commitment_key.clone(),
                    )
                    .canonical_bytes()?,
                ))
            }
            None => None,
        },
        VersionedPaperRaidFinalityCommand::V2(_) | VersionedPaperRaidFinalityCommand::V3(_) => None,
    };
    let rework_index_event_key = rework_index
        .as_ref()
        .map(|(object_key_hex, _)| object_key_hex.clone());
    let match_evidence_bytes = validate_match_evidence_ref(view, signed.match_evidence_ref())?;
    let commitment_bytes = signed.commitment_bytes();
    if commitment_bytes.len() > MAX_PAPER_RAID_FINALITY_COMMITMENT_BYTES {
        return Err(RuntimeError::PaperRaidFinalityState(
            "Paper Raid finality commitment exceeds the runtime byte limit".to_string(),
        ));
    }
    let applied_key = versioned_applied_key(&signed)?;
    let applied_record_bytes = versioned_applied_record_bytes(&signed)?;
    let submission_index_record_bytes = versioned_index_record_bytes(
        &signed,
        PaperRaidFinalityIndexKindV2::Submission,
        commitment_key.clone(),
    )?;
    let evaluation_index_record_bytes = versioned_index_record_bytes(
        &signed,
        PaperRaidFinalityIndexKindV2::Evaluation,
        commitment_key.clone(),
    )?;
    let collector_read_bytes = metered_read_or_default(
        view,
        &account_key(FEE_COLLECTOR_ACCOUNT_V1),
        ACCOUNT_OBJECT_TYPE_V1,
        &serde_json::to_vec(&AccountV1 {
            account: FEE_COLLECTOR_ACCOUNT_V1.to_string(),
            balance: 0,
            nonce: 0,
        })
        .map_err(|error| RuntimeError::EncodeObject(error.to_string()))?,
    )?;
    let commitment_write_bytes = metered_object_bytes(
        &commitment_key,
        versioned_commitment_object_type(&signed),
        &commitment_bytes,
    )?;
    let applied_write_bytes = metered_object_bytes(
        &applied_key,
        versioned_applied_object_type(&signed),
        &applied_record_bytes,
    )?;
    let submission_index_write_bytes = metered_object_bytes(
        &submission_index_key,
        versioned_index_object_type(&signed, PaperRaidFinalityIndexKindV2::Submission),
        &submission_index_record_bytes,
    )?;
    let evaluation_index_write_bytes = metered_object_bytes(
        &evaluation_index_key,
        versioned_index_object_type(&signed, PaperRaidFinalityIndexKindV2::Evaluation),
        &evaluation_index_record_bytes,
    )?;
    let rework_index_write_bytes = match &rework_index {
        Some((key, bytes)) => {
            metered_object_bytes(key, PAPER_RAID_FINALITY_REWORK_INDEX_OBJECT_TYPE_V4, bytes)?
        }
        None => 0,
    };
    let account_write_bytes = MAX_ACCOUNT_MUTATION_METER_BYTES
        .checked_mul(2)
        .ok_or(RuntimeError::ArithmeticOverflow)?;
    let state_bytes = lower_state_bytes
        .checked_add(collector_read_bytes)
        .and_then(|bytes| bytes.checked_add(match_evidence_bytes))
        .and_then(|bytes| bytes.checked_add(commitment_write_bytes))
        .and_then(|bytes| bytes.checked_add(applied_write_bytes))
        .and_then(|bytes| bytes.checked_add(submission_index_write_bytes))
        .and_then(|bytes| bytes.checked_add(evaluation_index_write_bytes))
        .and_then(|bytes| bytes.checked_add(rework_index_write_bytes))
        .and_then(|bytes| bytes.checked_add(account_write_bytes))
        .ok_or(RuntimeError::ArithmeticOverflow)?;
    // Unique keys: legacy sentinel, authority, fee policy, sender, collector,
    // applied record, commitment, submission/evaluation indexes, optional V4
    // rework index, and referenced MatchEvidence.
    let touched_keys = authority_touched_keys
        .checked_add(if signed.has_rework_lineage() { 9 } else { 8 })
        .ok_or(RuntimeError::ArithmeticOverflow)?;
    let estimate = estimate_resources(context, &policy, state_bytes, touched_keys)?;
    enforce_limits(tx, estimate)?;
    if available_balance < estimate.fee_estimate {
        return Err(RuntimeError::InsufficientBalance {
            account: tx.sender(),
            required: estimate.fee_estimate,
            available: available_balance,
        });
    }

    economic_state.debit(&tx.sender(), estimate.fee_estimate)?;
    economic_state.credit(FEE_COLLECTOR_ACCOUNT_V1, estimate.fee_estimate)?;
    let sender = economic_state.account(&tx.sender())?;
    sender.value.nonce = tx.nonce();
    sender.dirty = true;

    let mut mutations = economic_state.into_mutations()?;
    mutations.push(RuntimeMutation {
        object_key_hex: commitment_key.clone(),
        object_type: versioned_commitment_object_type(&signed).to_string(),
        expected_version: None,
        next_version: 1,
        value_bytes: commitment_bytes,
    });
    mutations.push(RuntimeMutation {
        object_key_hex: applied_key.clone(),
        object_type: versioned_applied_object_type(&signed).to_string(),
        expected_version: None,
        next_version: 1,
        value_bytes: applied_record_bytes,
    });
    mutations.push(RuntimeMutation {
        object_key_hex: submission_index_key,
        object_type: versioned_index_object_type(&signed, PaperRaidFinalityIndexKindV2::Submission)
            .to_string(),
        expected_version: None,
        next_version: 1,
        value_bytes: submission_index_record_bytes,
    });
    mutations.push(RuntimeMutation {
        object_key_hex: evaluation_index_key,
        object_type: versioned_index_object_type(&signed, PaperRaidFinalityIndexKindV2::Evaluation)
            .to_string(),
        expected_version: None,
        next_version: 1,
        value_bytes: evaluation_index_record_bytes,
    });
    if let Some((object_key_hex, value_bytes)) = rework_index {
        mutations.push(RuntimeMutation {
            object_key_hex,
            object_type: PAPER_RAID_FINALITY_REWORK_INDEX_OBJECT_TYPE_V4.to_string(),
            expected_version: None,
            next_version: 1,
            value_bytes,
        });
    }
    mutations.sort_by(|left, right| left.object_key_hex.cmp(&right.object_key_hex));
    validate_mutations(&mutations)?;

    Ok(RuntimeReceipt {
        gas_used: estimate.gas_used,
        fee_charged: estimate.fee_estimate,
        events: vec![paper_raid_event(
            &signed,
            &commitment_key,
            &applied_key,
            rework_index_event_key.as_deref(),
        )],
        mutations,
    })
}

fn validate_transaction_context(
    tx: PaperRaidFinalityTxRef<'_>,
    context: ExecutionContext<'_>,
) -> Result<VersionedPaperRaidFinalityCommand, RuntimeError> {
    let signed = match tx {
        PaperRaidFinalityTxRef::V2(tx) => {
            tx.validate()
                .map_err(|error| RuntimeError::Protocol(error.to_string()))?;
            VersionedPaperRaidFinalityCommand::V2(
                tx.signed_paper_raid_finality_command()
                    .map_err(|error| RuntimeError::Protocol(error.to_string()))?,
            )
        }
        PaperRaidFinalityTxRef::V3(tx) => {
            tx.validate()
                .map_err(|error| RuntimeError::Protocol(error.to_string()))?;
            VersionedPaperRaidFinalityCommand::V3(
                tx.signed_paper_raid_finality_command()
                    .map_err(|error| RuntimeError::Protocol(error.to_string()))?,
            )
        }
        PaperRaidFinalityTxRef::V4(tx) => {
            tx.validate()
                .map_err(|error| RuntimeError::Protocol(error.to_string()))?;
            VersionedPaperRaidFinalityCommand::V4(
                tx.signed_paper_raid_finality_command()
                    .map_err(|error| RuntimeError::Protocol(error.to_string()))?,
            )
        }
    };
    if tx.sender() != context.signer_id {
        return Err(RuntimeError::SenderMismatch);
    }
    if tx.sender() == FEE_COLLECTOR_ACCOUNT_V1 {
        return Err(RuntimeError::ReservedSystemAccount);
    }
    if signed.chain_id() != context.chain_id {
        return Err(RuntimeError::PaperRaidFinalityChainMismatch);
    }
    if signed.signer_role() != AuthorityRole::HeptaAuthority || context.signer_role != "hepta" {
        return Err(RuntimeError::PaperRaidFinalityRoleMismatch);
    }
    Ok(signed)
}

fn account_nonce_and_balance(
    state: &mut RuntimeState<'_>,
    tx: PaperRaidFinalityTxRef<'_>,
) -> Result<(u64, u128), RuntimeError> {
    let sender = state.account(&tx.sender())?;
    Ok((
        sender
            .value
            .nonce
            .checked_add(1)
            .ok_or(RuntimeError::NonceExhausted)?,
        sender.value.balance,
    ))
}

fn estimate_resources(
    context: ExecutionContext<'_>,
    policy: &FeePolicyV1,
    state_bytes: u64,
    touched_objects: u64,
) -> Result<ResourceEstimate, RuntimeError> {
    let payload_gas = u64::try_from(context.payload_len)
        .unwrap_or(u64::MAX)
        .checked_mul(policy.byte_gas)
        .ok_or(RuntimeError::ArithmeticOverflow)?;
    let state_byte_gas = state_bytes
        .checked_mul(policy.byte_gas)
        .ok_or(RuntimeError::ArithmeticOverflow)?;
    let touch_gas = touched_objects
        .checked_mul(PAPER_RAID_FINALITY_OBJECT_TOUCH_GAS)
        .ok_or(RuntimeError::ArithmeticOverflow)?;
    let gas_used = policy
        .base_gas
        .checked_add(payload_gas)
        .and_then(|gas| gas.checked_add(PAPER_RAID_FINALITY_OPERATION_GAS))
        .and_then(|gas| gas.checked_add(state_byte_gas))
        .and_then(|gas| gas.checked_add(touch_gas))
        .ok_or(RuntimeError::ArithmeticOverflow)?;
    let fee_estimate = u128::from(gas_used)
        .checked_mul(policy.gas_price)
        .ok_or(RuntimeError::ArithmeticOverflow)?;
    Ok(ResourceEstimate {
        gas_used,
        fee_estimate,
    })
}

fn enforce_limits(
    tx: PaperRaidFinalityTxRef<'_>,
    estimate: ResourceEstimate,
) -> Result<(), RuntimeError> {
    if estimate.gas_used > tx.max_gas() {
        return Err(RuntimeError::GasLimitExceeded {
            required: estimate.gas_used,
            limit: tx.max_gas(),
        });
    }
    if estimate.fee_estimate > tx.fee_limit() {
        return Err(RuntimeError::FeeLimitExceeded {
            required: estimate.fee_estimate,
            limit: tx.fee_limit(),
        });
    }
    Ok(())
}

fn reject_applied_replay(
    view: &dyn StateView,
    signed: &VersionedPaperRaidFinalityCommand,
) -> Result<(), RuntimeError> {
    match signed {
        VersionedPaperRaidFinalityCommand::V2(signed) => reject_applied_replay_v2(view, signed),
        VersionedPaperRaidFinalityCommand::V3(signed) => reject_applied_replay_v3(view, signed),
        VersionedPaperRaidFinalityCommand::V4(signed) => reject_applied_replay_v4(view, signed),
    }
}

fn reject_applied_replay_v2(
    view: &dyn StateView,
    signed: &SignedPaperRaidFinalityCommandV2,
) -> Result<(), RuntimeError> {
    let applied_key = paper_raid_finality_applied_command_key(signed.command_id)?;
    let Some(stored) = view.get(&applied_key) else {
        return Ok(());
    };
    ensure_type(
        &applied_key,
        &stored,
        PAPER_RAID_FINALITY_APPLIED_COMMAND_OBJECT_TYPE_V2,
    )?;
    if stored.version != 1 {
        return Err(RuntimeError::PaperRaidFinalityMirrorMismatch(applied_key));
    }
    let record = PaperRaidFinalityAppliedRecordV2::from_canonical_bytes(&stored.value_bytes)
        .map_err(|_| RuntimeError::PaperRaidFinalityMirrorMismatch(applied_key.clone()))?;
    if record.command_id != signed.command_id.to_hex() {
        return Err(RuntimeError::PaperRaidFinalityMirrorMismatch(applied_key));
    }
    validate_record_commitment_v2(view, &record)?;
    if record.command_fingerprint_hex != digest_hex(signed.command_fingerprint()) {
        return Err(RuntimeError::PaperRaidFinalityAlteredReplay);
    }
    let commitment_key = paper_raid_finality_commitment_key(signed.commitment.commitment_id)?;
    if record.commitment_id != signed.commitment.commitment_id.to_hex()
        || record.commitment_object_key_hex != commitment_key
        || record.payload_hash_hex != digest_hex(signed.payload_hash())
    {
        return Err(RuntimeError::PaperRaidFinalityMirrorMismatch(applied_key));
    }
    let commitment = view
        .get(&commitment_key)
        .ok_or_else(|| RuntimeError::PaperRaidFinalityMirrorMismatch(commitment_key.clone()))?;
    ensure_type(
        &commitment_key,
        &commitment,
        PAPER_RAID_FINALITY_COMMITMENT_OBJECT_TYPE_V2,
    )?;
    if commitment.version != 1
        || commitment.value_bytes.len() > MAX_PAPER_RAID_FINALITY_COMMITMENT_BYTES
    {
        return Err(RuntimeError::PaperRaidFinalityMirrorMismatch(
            commitment_key,
        ));
    }
    let decoded = PaperRaidFinalityCommitmentV2::from_canonical_bytes(&commitment.value_bytes)
        .map_err(|_| RuntimeError::PaperRaidFinalityMirrorMismatch(commitment_key.clone()))?;
    if decoded != signed.commitment {
        return Err(RuntimeError::PaperRaidFinalityMirrorMismatch(
            commitment_key,
        ));
    }
    let submission_index_key = paper_raid_finality_submission_index_key(
        signed.commitment.paper_project_id,
        signed.commitment.submission_id,
    )?;
    validate_expected_index_mirror(
        view,
        signed,
        PaperRaidFinalityIndexKindV2::Submission,
        &submission_index_key,
        &commitment_key,
    )?;
    let evaluation_index_key =
        paper_raid_finality_evaluation_index_key(signed.commitment.evaluation_id)?;
    validate_expected_index_mirror(
        view,
        signed,
        PaperRaidFinalityIndexKindV2::Evaluation,
        &evaluation_index_key,
        &commitment_key,
    )?;
    Err(RuntimeError::PaperRaidFinalityCommandReplay)
}

fn reject_applied_replay_v3(
    view: &dyn StateView,
    signed: &SignedPaperRaidFinalityCommandV3,
) -> Result<(), RuntimeError> {
    let applied_key = paper_raid_finality_applied_command_key_v3(signed.command_id)?;
    let Some(stored) = view.get(&applied_key) else {
        return Ok(());
    };
    ensure_type(
        &applied_key,
        &stored,
        PAPER_RAID_FINALITY_APPLIED_COMMAND_OBJECT_TYPE_V3,
    )?;
    if stored.version != 1 {
        return Err(RuntimeError::PaperRaidFinalityMirrorMismatch(applied_key));
    }
    let record = PaperRaidFinalityAppliedRecordV3::from_canonical_bytes(&stored.value_bytes)
        .map_err(|_| RuntimeError::PaperRaidFinalityMirrorMismatch(applied_key.clone()))?;
    if record.command_id != signed.command_id.to_hex() {
        return Err(RuntimeError::PaperRaidFinalityMirrorMismatch(applied_key));
    }
    validate_record_commitment_v3(view, &record)?;
    if record.command_fingerprint_hex != digest_hex(signed.command_fingerprint()) {
        return Err(RuntimeError::PaperRaidFinalityAlteredReplay);
    }
    let commitment_key = paper_raid_finality_commitment_key_v3(signed.commitment.commitment_id)?;
    if record.commitment_id != signed.commitment.commitment_id.to_hex()
        || record.commitment_object_key_hex != commitment_key
        || record.payload_hash_hex != digest_hex(signed.payload_hash())
    {
        return Err(RuntimeError::PaperRaidFinalityMirrorMismatch(applied_key));
    }
    let commitment = view
        .get(&commitment_key)
        .ok_or_else(|| RuntimeError::PaperRaidFinalityMirrorMismatch(commitment_key.clone()))?;
    ensure_type(
        &commitment_key,
        &commitment,
        PAPER_RAID_FINALITY_COMMITMENT_OBJECT_TYPE_V3,
    )?;
    if commitment.version != 1
        || commitment.value_bytes.len() > MAX_PAPER_RAID_FINALITY_COMMITMENT_BYTES
    {
        return Err(RuntimeError::PaperRaidFinalityMirrorMismatch(
            commitment_key,
        ));
    }
    let decoded = PaperRaidFinalityCommitmentV3::from_canonical_bytes(&commitment.value_bytes)
        .map_err(|_| RuntimeError::PaperRaidFinalityMirrorMismatch(commitment_key.clone()))?;
    if decoded != signed.commitment {
        return Err(RuntimeError::PaperRaidFinalityMirrorMismatch(
            commitment_key,
        ));
    }
    let submission_index_key = paper_raid_finality_submission_index_key_v3(
        signed.commitment.paper_project_id,
        signed.commitment.submission_id,
    )?;
    validate_expected_index_mirror_v3(
        view,
        signed,
        PaperRaidFinalityIndexKindV2::Submission,
        &submission_index_key,
        &commitment_key,
    )?;
    let evaluation_index_key =
        paper_raid_finality_evaluation_index_key_v3(signed.commitment.evaluation_id)?;
    validate_expected_index_mirror_v3(
        view,
        signed,
        PaperRaidFinalityIndexKindV2::Evaluation,
        &evaluation_index_key,
        &commitment_key,
    )?;
    Err(RuntimeError::PaperRaidFinalityCommandReplay)
}

fn reject_applied_replay_v4(
    view: &dyn StateView,
    signed: &SignedPaperRaidFinalityCommandV4,
) -> Result<(), RuntimeError> {
    let applied_key = paper_raid_finality_applied_command_key_v4(signed.command_id)?;
    let Some(stored) = view.get(&applied_key) else {
        return Ok(());
    };
    ensure_type(
        &applied_key,
        &stored,
        PAPER_RAID_FINALITY_APPLIED_COMMAND_OBJECT_TYPE_V4,
    )?;
    if stored.version != 1 {
        return Err(RuntimeError::PaperRaidFinalityMirrorMismatch(applied_key));
    }
    let record = PaperRaidFinalityAppliedRecordV4::from_canonical_bytes(&stored.value_bytes)
        .map_err(|_| RuntimeError::PaperRaidFinalityMirrorMismatch(applied_key.clone()))?;
    if record.command_id != signed.command_id.to_hex() {
        return Err(RuntimeError::PaperRaidFinalityMirrorMismatch(applied_key));
    }
    validate_record_commitment_v4(view, &record)?;
    if record.command_fingerprint_hex != digest_hex(signed.command_fingerprint()) {
        return Err(RuntimeError::PaperRaidFinalityAlteredReplay);
    }
    let commitment_key = paper_raid_finality_commitment_key_v4(signed.commitment.commitment_id)?;
    if record.commitment_id != signed.commitment.commitment_id.to_hex()
        || record.commitment_object_key_hex != commitment_key
        || record.payload_hash_hex != digest_hex(signed.payload_hash())
    {
        return Err(RuntimeError::PaperRaidFinalityMirrorMismatch(applied_key));
    }
    let commitment = view
        .get(&commitment_key)
        .ok_or_else(|| RuntimeError::PaperRaidFinalityMirrorMismatch(commitment_key.clone()))?;
    ensure_type(
        &commitment_key,
        &commitment,
        PAPER_RAID_FINALITY_COMMITMENT_OBJECT_TYPE_V4,
    )?;
    if commitment.version != 1
        || commitment.value_bytes.len() > MAX_PAPER_RAID_FINALITY_COMMITMENT_BYTES
    {
        return Err(RuntimeError::PaperRaidFinalityMirrorMismatch(
            commitment_key,
        ));
    }
    let decoded = PaperRaidFinalityCommitmentV4::from_canonical_bytes(&commitment.value_bytes)
        .map_err(|_| RuntimeError::PaperRaidFinalityMirrorMismatch(commitment_key.clone()))?;
    if decoded != signed.commitment {
        return Err(RuntimeError::PaperRaidFinalityMirrorMismatch(
            commitment_key,
        ));
    }
    let submission_index_key = paper_raid_finality_submission_index_key_v4(
        signed.commitment.paper_project_id,
        signed.commitment.submission_id,
    )?;
    validate_expected_index_mirror_v4(
        view,
        signed,
        PaperRaidFinalityIndexKindV2::Submission,
        &submission_index_key,
        &commitment_key,
    )?;
    let evaluation_index_key =
        paper_raid_finality_evaluation_index_key_v4(signed.commitment.evaluation_id)?;
    validate_expected_index_mirror_v4(
        view,
        signed,
        PaperRaidFinalityIndexKindV2::Evaluation,
        &evaluation_index_key,
        &commitment_key,
    )?;
    if let Some(lineage) = &signed.commitment.rework_lineage {
        let rework_index_key = paper_raid_finality_rework_index_key_v4(lineage.rework_id)?;
        validate_expected_rework_index_mirror_v4(view, signed, &rework_index_key, &commitment_key)?;
    }
    Err(RuntimeError::PaperRaidFinalityCommandReplay)
}

fn versioned_commitment_key(
    signed: &VersionedPaperRaidFinalityCommand,
) -> Result<String, RuntimeError> {
    match signed {
        VersionedPaperRaidFinalityCommand::V2(signed) => {
            paper_raid_finality_commitment_key(signed.commitment.commitment_id)
        }
        VersionedPaperRaidFinalityCommand::V3(signed) => {
            paper_raid_finality_commitment_key_v3(signed.commitment.commitment_id)
        }
        VersionedPaperRaidFinalityCommand::V4(signed) => {
            paper_raid_finality_commitment_key_v4(signed.commitment.commitment_id)
        }
    }
}

fn versioned_applied_key(
    signed: &VersionedPaperRaidFinalityCommand,
) -> Result<String, RuntimeError> {
    match signed {
        VersionedPaperRaidFinalityCommand::V2(signed) => {
            paper_raid_finality_applied_command_key(signed.command_id)
        }
        VersionedPaperRaidFinalityCommand::V3(signed) => {
            paper_raid_finality_applied_command_key_v3(signed.command_id)
        }
        VersionedPaperRaidFinalityCommand::V4(signed) => {
            paper_raid_finality_applied_command_key_v4(signed.command_id)
        }
    }
}

fn versioned_submission_index_key(
    signed: &VersionedPaperRaidFinalityCommand,
) -> Result<String, RuntimeError> {
    if signed.is_v4() {
        paper_raid_finality_submission_index_key_v4(
            signed.paper_project_id(),
            signed.submission_id(),
        )
    } else if signed.is_v3() {
        paper_raid_finality_submission_index_key_v3(
            signed.paper_project_id(),
            signed.submission_id(),
        )
    } else {
        paper_raid_finality_submission_index_key(signed.paper_project_id(), signed.submission_id())
    }
}

fn versioned_evaluation_index_key(
    signed: &VersionedPaperRaidFinalityCommand,
) -> Result<String, RuntimeError> {
    if signed.is_v4() {
        paper_raid_finality_evaluation_index_key_v4(signed.evaluation_id())
    } else if signed.is_v3() {
        paper_raid_finality_evaluation_index_key_v3(signed.evaluation_id())
    } else {
        paper_raid_finality_evaluation_index_key(signed.evaluation_id())
    }
}

fn versioned_commitment_object_type(signed: &VersionedPaperRaidFinalityCommand) -> &'static str {
    if signed.is_v4() {
        PAPER_RAID_FINALITY_COMMITMENT_OBJECT_TYPE_V4
    } else if signed.is_v3() {
        PAPER_RAID_FINALITY_COMMITMENT_OBJECT_TYPE_V3
    } else {
        PAPER_RAID_FINALITY_COMMITMENT_OBJECT_TYPE_V2
    }
}

fn versioned_applied_object_type(signed: &VersionedPaperRaidFinalityCommand) -> &'static str {
    if signed.is_v4() {
        PAPER_RAID_FINALITY_APPLIED_COMMAND_OBJECT_TYPE_V4
    } else if signed.is_v3() {
        PAPER_RAID_FINALITY_APPLIED_COMMAND_OBJECT_TYPE_V3
    } else {
        PAPER_RAID_FINALITY_APPLIED_COMMAND_OBJECT_TYPE_V2
    }
}

fn versioned_index_object_type(
    signed: &VersionedPaperRaidFinalityCommand,
    index_kind: PaperRaidFinalityIndexKindV2,
) -> &'static str {
    if signed.is_v4() {
        paper_raid_index_object_type_v4(index_kind)
    } else if signed.is_v3() {
        paper_raid_index_object_type_v3(index_kind)
    } else {
        paper_raid_index_object_type(index_kind)
    }
}

fn versioned_applied_record_bytes(
    signed: &VersionedPaperRaidFinalityCommand,
) -> Result<Vec<u8>, RuntimeError> {
    match signed {
        VersionedPaperRaidFinalityCommand::V2(signed) => {
            PaperRaidFinalityAppliedRecordV2::from_signed(signed)
                .and_then(|record| record.canonical_bytes())
                .map_err(|error| RuntimeError::PaperRaidFinalityState(error.to_string()))
        }
        VersionedPaperRaidFinalityCommand::V3(signed) => {
            PaperRaidFinalityAppliedRecordV3::from_signed(signed)
                .and_then(|record| record.canonical_bytes())
                .map_err(|error| RuntimeError::PaperRaidFinalityState(error.to_string()))
        }
        VersionedPaperRaidFinalityCommand::V4(signed) => {
            PaperRaidFinalityAppliedRecordV4::from_signed(signed)
                .and_then(|record| record.canonical_bytes())
                .map_err(|error| RuntimeError::PaperRaidFinalityState(error.to_string()))
        }
    }
}

fn versioned_index_record_bytes(
    signed: &VersionedPaperRaidFinalityCommand,
    index_kind: PaperRaidFinalityIndexKindV2,
    commitment_key: String,
) -> Result<Vec<u8>, RuntimeError> {
    match signed {
        VersionedPaperRaidFinalityCommand::V2(signed) => {
            PaperRaidFinalityIndexRecordV2::from_signed(signed, index_kind, commitment_key)
                .canonical_bytes()
        }
        VersionedPaperRaidFinalityCommand::V3(signed) => {
            PaperRaidFinalityIndexRecordV3::from_signed(signed, index_kind, commitment_key)
                .canonical_bytes()
        }
        VersionedPaperRaidFinalityCommand::V4(signed) => {
            PaperRaidFinalityIndexRecordV4::from_signed(signed, index_kind, commitment_key)
                .canonical_bytes()
        }
    }
}

fn defer_paper_raid_collision(
    result: Result<(), RuntimeError>,
) -> Result<Option<RuntimeError>, RuntimeError> {
    match result {
        Ok(()) => Ok(None),
        Err(
            error @ (RuntimeError::PaperRaidFinalityCommandReplay
            | RuntimeError::PaperRaidFinalityAlteredReplay
            | RuntimeError::PaperRaidFinalityCommitmentExists
            | RuntimeError::PaperRaidFinalitySubmissionExists
            | RuntimeError::PaperRaidFinalityEvaluationExists
            | RuntimeError::PaperRaidFinalityReworkExists),
        ) => Ok(Some(error)),
        Err(error) => Err(error),
    }
}

fn collect_paper_raid_collision(
    terminal: &mut Option<RuntimeError>,
    result: Result<(), RuntimeError>,
) -> Result<(), RuntimeError> {
    if let Some(error) = defer_paper_raid_collision(result)? {
        if terminal.is_none() {
            *terminal = Some(error);
        }
    }
    Ok(())
}

fn scan_same_version_collision_surfaces(
    view: &dyn StateView,
    signed: &VersionedPaperRaidFinalityCommand,
    commitment_key: &str,
) -> Result<Option<RuntimeError>, RuntimeError> {
    let mut terminal = None;
    collect_paper_raid_collision(
        &mut terminal,
        ensure_new_commitment_absent(view, signed, commitment_key),
    )?;
    collect_paper_raid_collision(
        &mut terminal,
        ensure_new_index_absent(view, signed, PaperRaidFinalityIndexKindV2::Submission),
    )?;
    collect_paper_raid_collision(
        &mut terminal,
        ensure_new_index_absent(view, signed, PaperRaidFinalityIndexKindV2::Evaluation),
    )?;
    if let VersionedPaperRaidFinalityCommand::V4(signed_v4) = signed {
        if let Some(lineage) = &signed_v4.commitment.rework_lineage {
            let rework_key = paper_raid_finality_rework_index_key_v4(lineage.rework_id)?;
            collect_paper_raid_collision(
                &mut terminal,
                ensure_new_rework_index_absent_v4(view, &rework_key),
            )?;
        }
    }
    Ok(terminal)
}

fn scan_cross_version_collisions(
    view: &dyn StateView,
    signed: &VersionedPaperRaidFinalityCommand,
) -> Result<Option<RuntimeError>, RuntimeError> {
    let mut terminal = None;
    match signed {
        VersionedPaperRaidFinalityCommand::V2(signed) => {
            collect_paper_raid_collision(
                &mut terminal,
                validate_opposite_applied_v3(view, signed.command_id),
            )?;
            collect_paper_raid_collision(
                &mut terminal,
                validate_opposite_applied_v4(view, signed.command_id),
            )?;
            collect_paper_raid_collision(
                &mut terminal,
                validate_opposite_commitment_v3(view, signed.commitment.commitment_id),
            )?;
            collect_paper_raid_collision(
                &mut terminal,
                validate_opposite_commitment_v4(view, signed.commitment.commitment_id),
            )?;
            collect_paper_raid_collision(
                &mut terminal,
                ensure_new_index_absent_v3(
                    view,
                    PaperRaidFinalityIndexKindV2::Submission,
                    &paper_raid_finality_submission_index_key_v3(
                        signed.commitment.paper_project_id,
                        signed.commitment.submission_id,
                    )?,
                ),
            )?;
            collect_paper_raid_collision(
                &mut terminal,
                ensure_new_index_absent_v3(
                    view,
                    PaperRaidFinalityIndexKindV2::Evaluation,
                    &paper_raid_finality_evaluation_index_key_v3(signed.commitment.evaluation_id)?,
                ),
            )?;
            collect_paper_raid_collision(
                &mut terminal,
                ensure_new_index_absent_v4(
                    view,
                    PaperRaidFinalityIndexKindV2::Submission,
                    &paper_raid_finality_submission_index_key_v4(
                        signed.commitment.paper_project_id,
                        signed.commitment.submission_id,
                    )?,
                ),
            )?;
            collect_paper_raid_collision(
                &mut terminal,
                ensure_new_index_absent_v4(
                    view,
                    PaperRaidFinalityIndexKindV2::Evaluation,
                    &paper_raid_finality_evaluation_index_key_v4(signed.commitment.evaluation_id)?,
                ),
            )?;
        }
        VersionedPaperRaidFinalityCommand::V3(signed) => {
            collect_paper_raid_collision(
                &mut terminal,
                validate_opposite_applied_v2(view, signed.command_id),
            )?;
            collect_paper_raid_collision(
                &mut terminal,
                validate_opposite_applied_v4(view, signed.command_id),
            )?;
            collect_paper_raid_collision(
                &mut terminal,
                validate_opposite_commitment_v2(view, signed.commitment.commitment_id),
            )?;
            collect_paper_raid_collision(
                &mut terminal,
                validate_opposite_commitment_v4(view, signed.commitment.commitment_id),
            )?;
            collect_paper_raid_collision(
                &mut terminal,
                ensure_new_index_absent_v2(
                    view,
                    PaperRaidFinalityIndexKindV2::Submission,
                    &paper_raid_finality_submission_index_key(
                        signed.commitment.paper_project_id,
                        signed.commitment.submission_id,
                    )?,
                ),
            )?;
            collect_paper_raid_collision(
                &mut terminal,
                ensure_new_index_absent_v2(
                    view,
                    PaperRaidFinalityIndexKindV2::Evaluation,
                    &paper_raid_finality_evaluation_index_key(signed.commitment.evaluation_id)?,
                ),
            )?;
            collect_paper_raid_collision(
                &mut terminal,
                ensure_new_index_absent_v4(
                    view,
                    PaperRaidFinalityIndexKindV2::Submission,
                    &paper_raid_finality_submission_index_key_v4(
                        signed.commitment.paper_project_id,
                        signed.commitment.submission_id,
                    )?,
                ),
            )?;
            collect_paper_raid_collision(
                &mut terminal,
                ensure_new_index_absent_v4(
                    view,
                    PaperRaidFinalityIndexKindV2::Evaluation,
                    &paper_raid_finality_evaluation_index_key_v4(signed.commitment.evaluation_id)?,
                ),
            )?;
        }
        VersionedPaperRaidFinalityCommand::V4(signed) => {
            collect_paper_raid_collision(
                &mut terminal,
                validate_opposite_applied_v2(view, signed.command_id),
            )?;
            collect_paper_raid_collision(
                &mut terminal,
                validate_opposite_applied_v3(view, signed.command_id),
            )?;
            collect_paper_raid_collision(
                &mut terminal,
                validate_opposite_commitment_v2(view, signed.commitment.commitment_id),
            )?;
            collect_paper_raid_collision(
                &mut terminal,
                validate_opposite_commitment_v3(view, signed.commitment.commitment_id),
            )?;
            collect_paper_raid_collision(
                &mut terminal,
                ensure_new_index_absent_v2(
                    view,
                    PaperRaidFinalityIndexKindV2::Submission,
                    &paper_raid_finality_submission_index_key(
                        signed.commitment.paper_project_id,
                        signed.commitment.submission_id,
                    )?,
                ),
            )?;
            collect_paper_raid_collision(
                &mut terminal,
                ensure_new_index_absent_v2(
                    view,
                    PaperRaidFinalityIndexKindV2::Evaluation,
                    &paper_raid_finality_evaluation_index_key(signed.commitment.evaluation_id)?,
                ),
            )?;
            collect_paper_raid_collision(
                &mut terminal,
                ensure_new_index_absent_v3(
                    view,
                    PaperRaidFinalityIndexKindV2::Submission,
                    &paper_raid_finality_submission_index_key_v3(
                        signed.commitment.paper_project_id,
                        signed.commitment.submission_id,
                    )?,
                ),
            )?;
            collect_paper_raid_collision(
                &mut terminal,
                ensure_new_index_absent_v3(
                    view,
                    PaperRaidFinalityIndexKindV2::Evaluation,
                    &paper_raid_finality_evaluation_index_key_v3(signed.commitment.evaluation_id)?,
                ),
            )?;
        }
    }
    Ok(terminal)
}

fn validate_opposite_applied_v2(
    view: &dyn StateView,
    command_id: ExternalKey,
) -> Result<(), RuntimeError> {
    let key = paper_raid_finality_applied_command_key(command_id)?;
    let Some(stored) = view.get(&key) else {
        return Ok(());
    };
    ensure_type(
        &key,
        &stored,
        PAPER_RAID_FINALITY_APPLIED_COMMAND_OBJECT_TYPE_V2,
    )?;
    if stored.version != 1 {
        return Err(RuntimeError::PaperRaidFinalityMirrorMismatch(key));
    }
    let record = PaperRaidFinalityAppliedRecordV2::from_canonical_bytes(&stored.value_bytes)
        .map_err(|_| RuntimeError::PaperRaidFinalityMirrorMismatch(key.clone()))?;
    if record.command_id != command_id.to_hex() {
        return Err(RuntimeError::PaperRaidFinalityMirrorMismatch(key));
    }
    validate_record_commitment_v2(view, &record)?;
    Err(RuntimeError::PaperRaidFinalityCommandReplay)
}

fn validate_opposite_applied_v3(
    view: &dyn StateView,
    command_id: ExternalKey,
) -> Result<(), RuntimeError> {
    let key = paper_raid_finality_applied_command_key_v3(command_id)?;
    let Some(stored) = view.get(&key) else {
        return Ok(());
    };
    ensure_type(
        &key,
        &stored,
        PAPER_RAID_FINALITY_APPLIED_COMMAND_OBJECT_TYPE_V3,
    )?;
    if stored.version != 1 {
        return Err(RuntimeError::PaperRaidFinalityMirrorMismatch(key));
    }
    let record = PaperRaidFinalityAppliedRecordV3::from_canonical_bytes(&stored.value_bytes)
        .map_err(|_| RuntimeError::PaperRaidFinalityMirrorMismatch(key.clone()))?;
    if record.command_id != command_id.to_hex() {
        return Err(RuntimeError::PaperRaidFinalityMirrorMismatch(key));
    }
    validate_record_commitment_v3(view, &record)?;
    Err(RuntimeError::PaperRaidFinalityCommandReplay)
}

fn validate_opposite_applied_v4(
    view: &dyn StateView,
    command_id: ExternalKey,
) -> Result<(), RuntimeError> {
    let key = paper_raid_finality_applied_command_key_v4(command_id)?;
    let Some(stored) = view.get(&key) else {
        return Ok(());
    };
    ensure_type(
        &key,
        &stored,
        PAPER_RAID_FINALITY_APPLIED_COMMAND_OBJECT_TYPE_V4,
    )?;
    if stored.version != 1 {
        return Err(RuntimeError::PaperRaidFinalityMirrorMismatch(key));
    }
    let record = PaperRaidFinalityAppliedRecordV4::from_canonical_bytes(&stored.value_bytes)
        .map_err(|_| RuntimeError::PaperRaidFinalityMirrorMismatch(key.clone()))?;
    if record.command_id != command_id.to_hex() {
        return Err(RuntimeError::PaperRaidFinalityMirrorMismatch(key));
    }
    validate_record_commitment_v4(view, &record)?;
    Err(RuntimeError::PaperRaidFinalityCommandReplay)
}

fn validate_record_commitment_v2(
    view: &dyn StateView,
    record: &PaperRaidFinalityAppliedRecordV2,
) -> Result<(), RuntimeError> {
    validate_commitment_pointer_v2(
        view,
        &record.commitment_id,
        &record.commitment_object_key_hex,
        &record.payload_hash_hex,
    )
}

fn validate_commitment_pointer_v2(
    view: &dyn StateView,
    commitment_id_hex: &str,
    commitment_object_key_hex: &str,
    payload_hash_hex: &str,
) -> Result<(), RuntimeError> {
    let commitment_id = external_key_from_hash_hex(commitment_id_hex)
        .ok_or_else(|| RuntimeError::PaperRaidFinalityState("invalid V2 commitment id".into()))?;
    let key = paper_raid_finality_commitment_key(commitment_id)?;
    if key != commitment_object_key_hex {
        return Err(RuntimeError::PaperRaidFinalityMirrorMismatch(key));
    }
    let stored = view
        .get(&key)
        .ok_or_else(|| RuntimeError::PaperRaidFinalityMirrorMismatch(key.clone()))?;
    ensure_type(&key, &stored, PAPER_RAID_FINALITY_COMMITMENT_OBJECT_TYPE_V2)?;
    if stored.version != 1 || stored.value_bytes.len() > MAX_PAPER_RAID_FINALITY_COMMITMENT_BYTES {
        return Err(RuntimeError::PaperRaidFinalityMirrorMismatch(key));
    }
    let commitment = PaperRaidFinalityCommitmentV2::from_canonical_bytes(&stored.value_bytes)
        .map_err(|_| RuntimeError::PaperRaidFinalityMirrorMismatch(key.clone()))?;
    if commitment.commitment_id != commitment_id
        || digest_hex(commitment.canonical_hash("trnm-paper-raid-finality-commitment-v2"))
            != payload_hash_hex
    {
        return Err(RuntimeError::PaperRaidFinalityMirrorMismatch(key));
    }
    validate_complete_index_mirrors_v2(view, &commitment, &key)
}

fn validate_record_commitment_v3(
    view: &dyn StateView,
    record: &PaperRaidFinalityAppliedRecordV3,
) -> Result<(), RuntimeError> {
    validate_commitment_pointer_v3(
        view,
        &record.commitment_id,
        &record.commitment_object_key_hex,
        &record.payload_hash_hex,
    )
}

fn validate_commitment_pointer_v3(
    view: &dyn StateView,
    commitment_id_hex: &str,
    commitment_object_key_hex: &str,
    payload_hash_hex: &str,
) -> Result<(), RuntimeError> {
    let commitment_id = external_key_from_hash_hex(commitment_id_hex)
        .ok_or_else(|| RuntimeError::PaperRaidFinalityState("invalid V3 commitment id".into()))?;
    let key = paper_raid_finality_commitment_key_v3(commitment_id)?;
    if key != commitment_object_key_hex {
        return Err(RuntimeError::PaperRaidFinalityMirrorMismatch(key));
    }
    let stored = view
        .get(&key)
        .ok_or_else(|| RuntimeError::PaperRaidFinalityMirrorMismatch(key.clone()))?;
    ensure_type(&key, &stored, PAPER_RAID_FINALITY_COMMITMENT_OBJECT_TYPE_V3)?;
    if stored.version != 1 || stored.value_bytes.len() > MAX_PAPER_RAID_FINALITY_COMMITMENT_BYTES {
        return Err(RuntimeError::PaperRaidFinalityMirrorMismatch(key));
    }
    let commitment = PaperRaidFinalityCommitmentV3::from_canonical_bytes(&stored.value_bytes)
        .map_err(|_| RuntimeError::PaperRaidFinalityMirrorMismatch(key.clone()))?;
    if commitment.commitment_id != commitment_id
        || digest_hex(commitment.canonical_hash("trnm-paper-raid-finality-commitment-v3"))
            != payload_hash_hex
    {
        return Err(RuntimeError::PaperRaidFinalityMirrorMismatch(key));
    }
    validate_complete_index_mirrors_v3(view, &commitment, &key)
}

fn validate_record_commitment_v4(
    view: &dyn StateView,
    record: &PaperRaidFinalityAppliedRecordV4,
) -> Result<(), RuntimeError> {
    validate_commitment_pointer_v4(
        view,
        &record.commitment_id,
        &record.commitment_object_key_hex,
        &record.payload_hash_hex,
    )
}

fn validate_commitment_pointer_v4(
    view: &dyn StateView,
    commitment_id_hex: &str,
    commitment_object_key_hex: &str,
    payload_hash_hex: &str,
) -> Result<(), RuntimeError> {
    let commitment_id = external_key_from_hash_hex(commitment_id_hex)
        .ok_or_else(|| RuntimeError::PaperRaidFinalityState("invalid V4 commitment id".into()))?;
    let key = paper_raid_finality_commitment_key_v4(commitment_id)?;
    if key != commitment_object_key_hex {
        return Err(RuntimeError::PaperRaidFinalityMirrorMismatch(key));
    }
    let stored = view
        .get(&key)
        .ok_or_else(|| RuntimeError::PaperRaidFinalityMirrorMismatch(key.clone()))?;
    ensure_type(&key, &stored, PAPER_RAID_FINALITY_COMMITMENT_OBJECT_TYPE_V4)?;
    if stored.version != 1 || stored.value_bytes.len() > MAX_PAPER_RAID_FINALITY_COMMITMENT_BYTES {
        return Err(RuntimeError::PaperRaidFinalityMirrorMismatch(key));
    }
    let commitment = PaperRaidFinalityCommitmentV4::from_canonical_bytes(&stored.value_bytes)
        .map_err(|_| RuntimeError::PaperRaidFinalityMirrorMismatch(key.clone()))?;
    if commitment.commitment_id != commitment_id
        || digest_hex(commitment.canonical_hash("trnm-paper-raid-finality-commitment-v4"))
            != payload_hash_hex
    {
        return Err(RuntimeError::PaperRaidFinalityMirrorMismatch(key));
    }
    validate_complete_index_mirrors_v4(view, &commitment, &key)
}

fn validate_complete_index_mirrors_v2(
    view: &dyn StateView,
    commitment: &PaperRaidFinalityCommitmentV2,
    commitment_key: &str,
) -> Result<(), RuntimeError> {
    let submission_key = paper_raid_finality_submission_index_key(
        commitment.paper_project_id,
        commitment.submission_id,
    )?;
    let submission = view
        .get(&submission_key)
        .ok_or_else(|| RuntimeError::PaperRaidFinalityMirrorMismatch(submission_key.clone()))?;
    validate_stored_index_mirror(
        view,
        PaperRaidFinalityIndexKindV2::Submission,
        &submission_key,
        &submission,
    )?;
    let evaluation_key = paper_raid_finality_evaluation_index_key(commitment.evaluation_id)?;
    let evaluation = view
        .get(&evaluation_key)
        .ok_or_else(|| RuntimeError::PaperRaidFinalityMirrorMismatch(evaluation_key.clone()))?;
    validate_stored_index_mirror(
        view,
        PaperRaidFinalityIndexKindV2::Evaluation,
        &evaluation_key,
        &evaluation,
    )?;
    if commitment_key != paper_raid_finality_commitment_key(commitment.commitment_id)? {
        return Err(RuntimeError::PaperRaidFinalityMirrorMismatch(
            commitment_key.to_string(),
        ));
    }
    Ok(())
}

fn validate_complete_index_mirrors_v3(
    view: &dyn StateView,
    commitment: &PaperRaidFinalityCommitmentV3,
    commitment_key: &str,
) -> Result<(), RuntimeError> {
    let submission_key = paper_raid_finality_submission_index_key_v3(
        commitment.paper_project_id,
        commitment.submission_id,
    )?;
    let submission = view
        .get(&submission_key)
        .ok_or_else(|| RuntimeError::PaperRaidFinalityMirrorMismatch(submission_key.clone()))?;
    validate_stored_index_mirror_v3(
        view,
        PaperRaidFinalityIndexKindV2::Submission,
        &submission_key,
        &submission,
    )?;
    let evaluation_key = paper_raid_finality_evaluation_index_key_v3(commitment.evaluation_id)?;
    let evaluation = view
        .get(&evaluation_key)
        .ok_or_else(|| RuntimeError::PaperRaidFinalityMirrorMismatch(evaluation_key.clone()))?;
    validate_stored_index_mirror_v3(
        view,
        PaperRaidFinalityIndexKindV2::Evaluation,
        &evaluation_key,
        &evaluation,
    )?;
    if commitment_key != paper_raid_finality_commitment_key_v3(commitment.commitment_id)? {
        return Err(RuntimeError::PaperRaidFinalityMirrorMismatch(
            commitment_key.to_string(),
        ));
    }
    Ok(())
}

fn validate_complete_index_mirrors_v4(
    view: &dyn StateView,
    commitment: &PaperRaidFinalityCommitmentV4,
    commitment_key: &str,
) -> Result<(), RuntimeError> {
    let submission_key = paper_raid_finality_submission_index_key_v4(
        commitment.paper_project_id,
        commitment.submission_id,
    )?;
    let submission = view
        .get(&submission_key)
        .ok_or_else(|| RuntimeError::PaperRaidFinalityMirrorMismatch(submission_key.clone()))?;
    validate_stored_index_mirror_v4(
        view,
        PaperRaidFinalityIndexKindV2::Submission,
        &submission_key,
        &submission,
    )?;
    let evaluation_key = paper_raid_finality_evaluation_index_key_v4(commitment.evaluation_id)?;
    let evaluation = view
        .get(&evaluation_key)
        .ok_or_else(|| RuntimeError::PaperRaidFinalityMirrorMismatch(evaluation_key.clone()))?;
    validate_stored_index_mirror_v4(
        view,
        PaperRaidFinalityIndexKindV2::Evaluation,
        &evaluation_key,
        &evaluation,
    )?;
    if let Some(lineage) = &commitment.rework_lineage {
        let rework_key = paper_raid_finality_rework_index_key_v4(lineage.rework_id)?;
        let rework = view
            .get(&rework_key)
            .ok_or_else(|| RuntimeError::PaperRaidFinalityMirrorMismatch(rework_key.clone()))?;
        validate_stored_rework_index_mirror_v4(view, &rework_key, &rework)?;
    }
    if commitment_key != paper_raid_finality_commitment_key_v4(commitment.commitment_id)? {
        return Err(RuntimeError::PaperRaidFinalityMirrorMismatch(
            commitment_key.to_string(),
        ));
    }
    Ok(())
}

fn validate_opposite_commitment_v2(
    view: &dyn StateView,
    commitment_id: ExternalKey,
) -> Result<(), RuntimeError> {
    let key = paper_raid_finality_commitment_key(commitment_id)?;
    let Some(stored) = view.get(&key) else {
        return Ok(());
    };
    ensure_type(&key, &stored, PAPER_RAID_FINALITY_COMMITMENT_OBJECT_TYPE_V2)?;
    if stored.version != 1 || stored.value_bytes.len() > MAX_PAPER_RAID_FINALITY_COMMITMENT_BYTES {
        return Err(RuntimeError::PaperRaidFinalityMirrorMismatch(key));
    }
    let decoded = PaperRaidFinalityCommitmentV2::from_canonical_bytes(&stored.value_bytes)
        .map_err(|_| RuntimeError::PaperRaidFinalityMirrorMismatch(key.clone()))?;
    if decoded.commitment_id != commitment_id {
        return Err(RuntimeError::PaperRaidFinalityMirrorMismatch(key));
    }
    validate_complete_index_mirrors_v2(view, &decoded, &key)?;
    Err(RuntimeError::PaperRaidFinalityCommitmentExists)
}

fn validate_opposite_commitment_v3(
    view: &dyn StateView,
    commitment_id: ExternalKey,
) -> Result<(), RuntimeError> {
    let key = paper_raid_finality_commitment_key_v3(commitment_id)?;
    let Some(stored) = view.get(&key) else {
        return Ok(());
    };
    ensure_type(&key, &stored, PAPER_RAID_FINALITY_COMMITMENT_OBJECT_TYPE_V3)?;
    if stored.version != 1 || stored.value_bytes.len() > MAX_PAPER_RAID_FINALITY_COMMITMENT_BYTES {
        return Err(RuntimeError::PaperRaidFinalityMirrorMismatch(key));
    }
    let decoded = PaperRaidFinalityCommitmentV3::from_canonical_bytes(&stored.value_bytes)
        .map_err(|_| RuntimeError::PaperRaidFinalityMirrorMismatch(key.clone()))?;
    if decoded.commitment_id != commitment_id {
        return Err(RuntimeError::PaperRaidFinalityMirrorMismatch(key));
    }
    validate_complete_index_mirrors_v3(view, &decoded, &key)?;
    Err(RuntimeError::PaperRaidFinalityCommitmentExists)
}

fn validate_opposite_commitment_v4(
    view: &dyn StateView,
    commitment_id: ExternalKey,
) -> Result<(), RuntimeError> {
    let key = paper_raid_finality_commitment_key_v4(commitment_id)?;
    let Some(stored) = view.get(&key) else {
        return Ok(());
    };
    ensure_type(&key, &stored, PAPER_RAID_FINALITY_COMMITMENT_OBJECT_TYPE_V4)?;
    if stored.version != 1 || stored.value_bytes.len() > MAX_PAPER_RAID_FINALITY_COMMITMENT_BYTES {
        return Err(RuntimeError::PaperRaidFinalityMirrorMismatch(key));
    }
    let decoded = PaperRaidFinalityCommitmentV4::from_canonical_bytes(&stored.value_bytes)
        .map_err(|_| RuntimeError::PaperRaidFinalityMirrorMismatch(key.clone()))?;
    if decoded.commitment_id != commitment_id {
        return Err(RuntimeError::PaperRaidFinalityMirrorMismatch(key));
    }
    validate_complete_index_mirrors_v4(view, &decoded, &key)?;
    Err(RuntimeError::PaperRaidFinalityCommitmentExists)
}

fn ensure_new_commitment_absent(
    view: &dyn StateView,
    signed: &VersionedPaperRaidFinalityCommand,
    commitment_key: &str,
) -> Result<(), RuntimeError> {
    match signed {
        VersionedPaperRaidFinalityCommand::V2(signed) => {
            ensure_new_commitment_absent_v2(view, &signed.commitment, commitment_key)
        }
        VersionedPaperRaidFinalityCommand::V3(signed) => {
            ensure_new_commitment_absent_v3(view, &signed.commitment, commitment_key)
        }
        VersionedPaperRaidFinalityCommand::V4(signed) => {
            ensure_new_commitment_absent_v4(view, &signed.commitment, commitment_key)
        }
    }
}

fn ensure_new_commitment_absent_v2(
    view: &dyn StateView,
    expected: &PaperRaidFinalityCommitmentV2,
    commitment_key: &str,
) -> Result<(), RuntimeError> {
    let Some(stored) = view.get(commitment_key) else {
        return Ok(());
    };
    ensure_type(
        commitment_key,
        &stored,
        PAPER_RAID_FINALITY_COMMITMENT_OBJECT_TYPE_V2,
    )?;
    if stored.version != 1 || stored.value_bytes.len() > MAX_PAPER_RAID_FINALITY_COMMITMENT_BYTES {
        return Err(RuntimeError::PaperRaidFinalityMirrorMismatch(
            commitment_key.to_string(),
        ));
    }
    let decoded = PaperRaidFinalityCommitmentV2::from_canonical_bytes(&stored.value_bytes)
        .map_err(|_| RuntimeError::PaperRaidFinalityMirrorMismatch(commitment_key.to_string()))?;
    if decoded.commitment_id != expected.commitment_id {
        return Err(RuntimeError::PaperRaidFinalityMirrorMismatch(
            commitment_key.to_string(),
        ));
    }
    validate_complete_index_mirrors_v2(view, &decoded, commitment_key)?;
    Err(RuntimeError::PaperRaidFinalityCommitmentExists)
}

fn ensure_new_commitment_absent_v3(
    view: &dyn StateView,
    expected: &PaperRaidFinalityCommitmentV3,
    commitment_key: &str,
) -> Result<(), RuntimeError> {
    let Some(stored) = view.get(commitment_key) else {
        return Ok(());
    };
    ensure_type(
        commitment_key,
        &stored,
        PAPER_RAID_FINALITY_COMMITMENT_OBJECT_TYPE_V3,
    )?;
    if stored.version != 1 || stored.value_bytes.len() > MAX_PAPER_RAID_FINALITY_COMMITMENT_BYTES {
        return Err(RuntimeError::PaperRaidFinalityMirrorMismatch(
            commitment_key.to_string(),
        ));
    }
    let decoded = PaperRaidFinalityCommitmentV3::from_canonical_bytes(&stored.value_bytes)
        .map_err(|_| RuntimeError::PaperRaidFinalityMirrorMismatch(commitment_key.to_string()))?;
    if decoded.commitment_id != expected.commitment_id {
        return Err(RuntimeError::PaperRaidFinalityMirrorMismatch(
            commitment_key.to_string(),
        ));
    }
    validate_complete_index_mirrors_v3(view, &decoded, commitment_key)?;
    Err(RuntimeError::PaperRaidFinalityCommitmentExists)
}

fn ensure_new_commitment_absent_v4(
    view: &dyn StateView,
    expected: &PaperRaidFinalityCommitmentV4,
    commitment_key: &str,
) -> Result<(), RuntimeError> {
    let Some(stored) = view.get(commitment_key) else {
        return Ok(());
    };
    ensure_type(
        commitment_key,
        &stored,
        PAPER_RAID_FINALITY_COMMITMENT_OBJECT_TYPE_V4,
    )?;
    if stored.version != 1 || stored.value_bytes.len() > MAX_PAPER_RAID_FINALITY_COMMITMENT_BYTES {
        return Err(RuntimeError::PaperRaidFinalityMirrorMismatch(
            commitment_key.to_string(),
        ));
    }
    let decoded = PaperRaidFinalityCommitmentV4::from_canonical_bytes(&stored.value_bytes)
        .map_err(|_| RuntimeError::PaperRaidFinalityMirrorMismatch(commitment_key.to_string()))?;
    if decoded.commitment_id != expected.commitment_id {
        return Err(RuntimeError::PaperRaidFinalityMirrorMismatch(
            commitment_key.to_string(),
        ));
    }
    validate_complete_index_mirrors_v4(view, &decoded, commitment_key)?;
    Err(RuntimeError::PaperRaidFinalityCommitmentExists)
}

fn ensure_new_index_absent(
    view: &dyn StateView,
    signed: &VersionedPaperRaidFinalityCommand,
    index_kind: PaperRaidFinalityIndexKindV2,
) -> Result<(), RuntimeError> {
    if signed.is_v4() {
        let key = match index_kind {
            PaperRaidFinalityIndexKindV2::Submission => {
                paper_raid_finality_submission_index_key_v4(
                    signed.paper_project_id(),
                    signed.submission_id(),
                )?
            }
            PaperRaidFinalityIndexKindV2::Evaluation => {
                paper_raid_finality_evaluation_index_key_v4(signed.evaluation_id())?
            }
        };
        ensure_new_index_absent_v4(view, index_kind, &key)
    } else if signed.is_v3() {
        let key = match index_kind {
            PaperRaidFinalityIndexKindV2::Submission => {
                paper_raid_finality_submission_index_key_v3(
                    signed.paper_project_id(),
                    signed.submission_id(),
                )?
            }
            PaperRaidFinalityIndexKindV2::Evaluation => {
                paper_raid_finality_evaluation_index_key_v3(signed.evaluation_id())?
            }
        };
        ensure_new_index_absent_v3(view, index_kind, &key)
    } else {
        let key = match index_kind {
            PaperRaidFinalityIndexKindV2::Submission => paper_raid_finality_submission_index_key(
                signed.paper_project_id(),
                signed.submission_id(),
            )?,
            PaperRaidFinalityIndexKindV2::Evaluation => {
                paper_raid_finality_evaluation_index_key(signed.evaluation_id())?
            }
        };
        ensure_new_index_absent_v2(view, index_kind, &key)
    }
}

fn ensure_new_index_absent_v2(
    view: &dyn StateView,
    index_kind: PaperRaidFinalityIndexKindV2,
    index_key: &str,
) -> Result<(), RuntimeError> {
    let Some(stored) = view.get(index_key) else {
        return Ok(());
    };
    let record = validate_stored_index_mirror(view, index_kind, index_key, &stored)?;
    validate_commitment_pointer_v2(
        view,
        &record.commitment_id,
        &record.commitment_object_key_hex,
        &record.payload_hash_hex,
    )?;
    Err(match index_kind {
        PaperRaidFinalityIndexKindV2::Submission => RuntimeError::PaperRaidFinalitySubmissionExists,
        PaperRaidFinalityIndexKindV2::Evaluation => RuntimeError::PaperRaidFinalityEvaluationExists,
    })
}

fn ensure_new_index_absent_v3(
    view: &dyn StateView,
    index_kind: PaperRaidFinalityIndexKindV2,
    index_key: &str,
) -> Result<(), RuntimeError> {
    let Some(stored) = view.get(index_key) else {
        return Ok(());
    };
    let record = validate_stored_index_mirror_v3(view, index_kind, index_key, &stored)?;
    validate_commitment_pointer_v3(
        view,
        &record.commitment_id,
        &record.commitment_object_key_hex,
        &record.payload_hash_hex,
    )?;
    Err(match index_kind {
        PaperRaidFinalityIndexKindV2::Submission => RuntimeError::PaperRaidFinalitySubmissionExists,
        PaperRaidFinalityIndexKindV2::Evaluation => RuntimeError::PaperRaidFinalityEvaluationExists,
    })
}

fn ensure_new_index_absent_v4(
    view: &dyn StateView,
    index_kind: PaperRaidFinalityIndexKindV2,
    index_key: &str,
) -> Result<(), RuntimeError> {
    let Some(stored) = view.get(index_key) else {
        return Ok(());
    };
    let record = validate_stored_index_mirror_v4(view, index_kind, index_key, &stored)?;
    validate_commitment_pointer_v4(
        view,
        &record.commitment_id,
        &record.commitment_object_key_hex,
        &record.payload_hash_hex,
    )?;
    Err(match index_kind {
        PaperRaidFinalityIndexKindV2::Submission => RuntimeError::PaperRaidFinalitySubmissionExists,
        PaperRaidFinalityIndexKindV2::Evaluation => RuntimeError::PaperRaidFinalityEvaluationExists,
    })
}

fn ensure_new_rework_index_absent_v4(
    view: &dyn StateView,
    index_key: &str,
) -> Result<(), RuntimeError> {
    let Some(stored) = view.get(index_key) else {
        return Ok(());
    };
    let record = validate_stored_rework_index_mirror_v4(view, index_key, &stored)?;
    validate_commitment_pointer_v4(
        view,
        &record.commitment_id,
        &record.commitment_object_key_hex,
        &record.payload_hash_hex,
    )?;
    Err(RuntimeError::PaperRaidFinalityReworkExists)
}

fn validate_expected_index_mirror(
    view: &dyn StateView,
    signed: &SignedPaperRaidFinalityCommandV2,
    index_kind: PaperRaidFinalityIndexKindV2,
    index_key: &str,
    commitment_key: &str,
) -> Result<(), RuntimeError> {
    let stored = view
        .get(index_key)
        .ok_or_else(|| RuntimeError::PaperRaidFinalityMirrorMismatch(index_key.to_string()))?;
    let record = validate_stored_index_mirror(view, index_kind, index_key, &stored)?;
    let expected =
        PaperRaidFinalityIndexRecordV2::from_signed(signed, index_kind, commitment_key.to_string());
    if record != expected {
        return Err(RuntimeError::PaperRaidFinalityMirrorMismatch(
            index_key.to_string(),
        ));
    }
    Ok(())
}

fn validate_expected_index_mirror_v3(
    view: &dyn StateView,
    signed: &SignedPaperRaidFinalityCommandV3,
    index_kind: PaperRaidFinalityIndexKindV2,
    index_key: &str,
    commitment_key: &str,
) -> Result<(), RuntimeError> {
    let stored = view
        .get(index_key)
        .ok_or_else(|| RuntimeError::PaperRaidFinalityMirrorMismatch(index_key.to_string()))?;
    let record = validate_stored_index_mirror_v3(view, index_kind, index_key, &stored)?;
    let expected =
        PaperRaidFinalityIndexRecordV3::from_signed(signed, index_kind, commitment_key.to_string());
    if record != expected {
        return Err(RuntimeError::PaperRaidFinalityMirrorMismatch(
            index_key.to_string(),
        ));
    }
    Ok(())
}

fn validate_expected_index_mirror_v4(
    view: &dyn StateView,
    signed: &SignedPaperRaidFinalityCommandV4,
    index_kind: PaperRaidFinalityIndexKindV2,
    index_key: &str,
    commitment_key: &str,
) -> Result<(), RuntimeError> {
    let stored = view
        .get(index_key)
        .ok_or_else(|| RuntimeError::PaperRaidFinalityMirrorMismatch(index_key.to_string()))?;
    let record = validate_stored_index_mirror_v4(view, index_kind, index_key, &stored)?;
    let expected =
        PaperRaidFinalityIndexRecordV4::from_signed(signed, index_kind, commitment_key.to_string());
    if record != expected {
        return Err(RuntimeError::PaperRaidFinalityMirrorMismatch(
            index_key.to_string(),
        ));
    }
    Ok(())
}

fn validate_expected_rework_index_mirror_v4(
    view: &dyn StateView,
    signed: &SignedPaperRaidFinalityCommandV4,
    index_key: &str,
    commitment_key: &str,
) -> Result<(), RuntimeError> {
    let stored = view
        .get(index_key)
        .ok_or_else(|| RuntimeError::PaperRaidFinalityMirrorMismatch(index_key.to_string()))?;
    let record = validate_stored_rework_index_mirror_v4(view, index_key, &stored)?;
    let lineage = signed
        .commitment
        .rework_lineage
        .as_ref()
        .ok_or_else(|| RuntimeError::PaperRaidFinalityMirrorMismatch(index_key.to_string()))?;
    let expected = PaperRaidFinalityReworkIndexRecordV4::from_signed(
        signed,
        lineage,
        commitment_key.to_string(),
    );
    if record != expected {
        return Err(RuntimeError::PaperRaidFinalityMirrorMismatch(
            index_key.to_string(),
        ));
    }
    Ok(())
}

fn validate_stored_index_mirror(
    view: &dyn StateView,
    index_kind: PaperRaidFinalityIndexKindV2,
    index_key: &str,
    stored: &StateObject,
) -> Result<PaperRaidFinalityIndexRecordV2, RuntimeError> {
    ensure_type(index_key, stored, paper_raid_index_object_type(index_kind))
        .map_err(|_| paper_raid_mirror_error(index_key))?;
    if stored.version != 1 || stored.value_bytes.len() > MAX_PAPER_RAID_FINALITY_INDEX_RECORD_BYTES
    {
        return Err(paper_raid_mirror_error(index_key));
    }
    let record = PaperRaidFinalityIndexRecordV2::from_canonical_bytes(&stored.value_bytes)
        .map_err(|_| paper_raid_mirror_error(index_key))?;
    if record.index_kind != index_kind {
        return Err(paper_raid_mirror_error(index_key));
    }
    let paper_project_id = external_key_from_hash_hex(&record.paper_project_id)
        .ok_or_else(|| paper_raid_mirror_error(index_key))?;
    let submission_id = external_key_from_hash_hex(&record.submission_id)
        .ok_or_else(|| paper_raid_mirror_error(index_key))?;
    let evaluation_id = external_key_from_hash_hex(&record.evaluation_id)
        .ok_or_else(|| paper_raid_mirror_error(index_key))?;
    let commitment_id = external_key_from_hash_hex(&record.commitment_id)
        .ok_or_else(|| paper_raid_mirror_error(index_key))?;
    let expected_index_key = match index_kind {
        PaperRaidFinalityIndexKindV2::Submission => {
            paper_raid_finality_submission_index_key(paper_project_id, submission_id)
        }
        PaperRaidFinalityIndexKindV2::Evaluation => {
            paper_raid_finality_evaluation_index_key(evaluation_id)
        }
    }
    .map_err(|_| paper_raid_mirror_error(index_key))?;
    if expected_index_key != index_key {
        return Err(paper_raid_mirror_error(index_key));
    }
    let commitment_key = paper_raid_finality_commitment_key(commitment_id)
        .map_err(|_| paper_raid_mirror_error(index_key))?;
    if commitment_key != record.commitment_object_key_hex {
        return Err(paper_raid_mirror_error(index_key));
    }
    let commitment_object = view
        .get(&commitment_key)
        .ok_or_else(|| paper_raid_mirror_error(index_key))?;
    ensure_type(
        &commitment_key,
        &commitment_object,
        PAPER_RAID_FINALITY_COMMITMENT_OBJECT_TYPE_V2,
    )
    .map_err(|_| paper_raid_mirror_error(index_key))?;
    if commitment_object.version != 1
        || commitment_object.value_bytes.len() > MAX_PAPER_RAID_FINALITY_COMMITMENT_BYTES
    {
        return Err(paper_raid_mirror_error(index_key));
    }
    let commitment =
        PaperRaidFinalityCommitmentV2::from_canonical_bytes(&commitment_object.value_bytes)
            .map_err(|_| paper_raid_mirror_error(index_key))?;
    if commitment.paper_project_id != paper_project_id
        || commitment.submission_id != submission_id
        || commitment.evaluation_id != evaluation_id
        || commitment.commitment_id != commitment_id
        || digest_hex(commitment.canonical_hash("trnm-paper-raid-finality-commitment-v2"))
            != record.payload_hash_hex
    {
        return Err(paper_raid_mirror_error(index_key));
    }
    Ok(record)
}

fn validate_stored_index_mirror_v3(
    view: &dyn StateView,
    index_kind: PaperRaidFinalityIndexKindV2,
    index_key: &str,
    stored: &StateObject,
) -> Result<PaperRaidFinalityIndexRecordV3, RuntimeError> {
    ensure_type(
        index_key,
        stored,
        paper_raid_index_object_type_v3(index_kind),
    )
    .map_err(|_| paper_raid_mirror_error(index_key))?;
    if stored.version != 1 || stored.value_bytes.len() > MAX_PAPER_RAID_FINALITY_INDEX_RECORD_BYTES
    {
        return Err(paper_raid_mirror_error(index_key));
    }
    let record = PaperRaidFinalityIndexRecordV3::from_canonical_bytes(&stored.value_bytes)
        .map_err(|_| paper_raid_mirror_error(index_key))?;
    if record.index_kind != index_kind {
        return Err(paper_raid_mirror_error(index_key));
    }
    let paper_project_id = external_key_from_hash_hex(&record.paper_project_id)
        .ok_or_else(|| paper_raid_mirror_error(index_key))?;
    let submission_id = external_key_from_hash_hex(&record.submission_id)
        .ok_or_else(|| paper_raid_mirror_error(index_key))?;
    let evaluation_id = external_key_from_hash_hex(&record.evaluation_id)
        .ok_or_else(|| paper_raid_mirror_error(index_key))?;
    let commitment_id = external_key_from_hash_hex(&record.commitment_id)
        .ok_or_else(|| paper_raid_mirror_error(index_key))?;
    let expected_index_key = match index_kind {
        PaperRaidFinalityIndexKindV2::Submission => {
            paper_raid_finality_submission_index_key_v3(paper_project_id, submission_id)
        }
        PaperRaidFinalityIndexKindV2::Evaluation => {
            paper_raid_finality_evaluation_index_key_v3(evaluation_id)
        }
    }
    .map_err(|_| paper_raid_mirror_error(index_key))?;
    if expected_index_key != index_key {
        return Err(paper_raid_mirror_error(index_key));
    }
    let commitment_key = paper_raid_finality_commitment_key_v3(commitment_id)
        .map_err(|_| paper_raid_mirror_error(index_key))?;
    if commitment_key != record.commitment_object_key_hex {
        return Err(paper_raid_mirror_error(index_key));
    }
    let commitment_object = view
        .get(&commitment_key)
        .ok_or_else(|| paper_raid_mirror_error(index_key))?;
    ensure_type(
        &commitment_key,
        &commitment_object,
        PAPER_RAID_FINALITY_COMMITMENT_OBJECT_TYPE_V3,
    )
    .map_err(|_| paper_raid_mirror_error(index_key))?;
    if commitment_object.version != 1
        || commitment_object.value_bytes.len() > MAX_PAPER_RAID_FINALITY_COMMITMENT_BYTES
    {
        return Err(paper_raid_mirror_error(index_key));
    }
    let commitment =
        PaperRaidFinalityCommitmentV3::from_canonical_bytes(&commitment_object.value_bytes)
            .map_err(|_| paper_raid_mirror_error(index_key))?;
    if commitment.paper_project_id != paper_project_id
        || commitment.submission_id != submission_id
        || commitment.evaluation_id != evaluation_id
        || commitment.commitment_id != commitment_id
        || digest_hex(commitment.canonical_hash("trnm-paper-raid-finality-commitment-v3"))
            != record.payload_hash_hex
    {
        return Err(paper_raid_mirror_error(index_key));
    }
    Ok(record)
}

fn validate_stored_index_mirror_v4(
    view: &dyn StateView,
    index_kind: PaperRaidFinalityIndexKindV2,
    index_key: &str,
    stored: &StateObject,
) -> Result<PaperRaidFinalityIndexRecordV4, RuntimeError> {
    ensure_type(
        index_key,
        stored,
        paper_raid_index_object_type_v4(index_kind),
    )
    .map_err(|_| paper_raid_mirror_error(index_key))?;
    if stored.version != 1 || stored.value_bytes.len() > MAX_PAPER_RAID_FINALITY_INDEX_RECORD_BYTES
    {
        return Err(paper_raid_mirror_error(index_key));
    }
    let record = PaperRaidFinalityIndexRecordV4::from_canonical_bytes(&stored.value_bytes)
        .map_err(|_| paper_raid_mirror_error(index_key))?;
    if record.index_kind != index_kind {
        return Err(paper_raid_mirror_error(index_key));
    }
    let paper_project_id = external_key_from_hash_hex(&record.paper_project_id)
        .ok_or_else(|| paper_raid_mirror_error(index_key))?;
    let submission_id = external_key_from_hash_hex(&record.submission_id)
        .ok_or_else(|| paper_raid_mirror_error(index_key))?;
    let evaluation_id = external_key_from_hash_hex(&record.evaluation_id)
        .ok_or_else(|| paper_raid_mirror_error(index_key))?;
    let commitment_id = external_key_from_hash_hex(&record.commitment_id)
        .ok_or_else(|| paper_raid_mirror_error(index_key))?;
    let expected_index_key = match index_kind {
        PaperRaidFinalityIndexKindV2::Submission => {
            paper_raid_finality_submission_index_key_v4(paper_project_id, submission_id)
        }
        PaperRaidFinalityIndexKindV2::Evaluation => {
            paper_raid_finality_evaluation_index_key_v4(evaluation_id)
        }
    }
    .map_err(|_| paper_raid_mirror_error(index_key))?;
    if expected_index_key != index_key {
        return Err(paper_raid_mirror_error(index_key));
    }
    let commitment_key = paper_raid_finality_commitment_key_v4(commitment_id)
        .map_err(|_| paper_raid_mirror_error(index_key))?;
    if commitment_key != record.commitment_object_key_hex {
        return Err(paper_raid_mirror_error(index_key));
    }
    let commitment_object = view
        .get(&commitment_key)
        .ok_or_else(|| paper_raid_mirror_error(index_key))?;
    ensure_type(
        &commitment_key,
        &commitment_object,
        PAPER_RAID_FINALITY_COMMITMENT_OBJECT_TYPE_V4,
    )
    .map_err(|_| paper_raid_mirror_error(index_key))?;
    if commitment_object.version != 1
        || commitment_object.value_bytes.len() > MAX_PAPER_RAID_FINALITY_COMMITMENT_BYTES
    {
        return Err(paper_raid_mirror_error(index_key));
    }
    let commitment =
        PaperRaidFinalityCommitmentV4::from_canonical_bytes(&commitment_object.value_bytes)
            .map_err(|_| paper_raid_mirror_error(index_key))?;
    if commitment.paper_project_id != paper_project_id
        || commitment.submission_id != submission_id
        || commitment.evaluation_id != evaluation_id
        || commitment.commitment_id != commitment_id
        || digest_hex(commitment.canonical_hash("trnm-paper-raid-finality-commitment-v4"))
            != record.payload_hash_hex
    {
        return Err(paper_raid_mirror_error(index_key));
    }
    Ok(record)
}

fn validate_stored_rework_index_mirror_v4(
    view: &dyn StateView,
    index_key: &str,
    stored: &StateObject,
) -> Result<PaperRaidFinalityReworkIndexRecordV4, RuntimeError> {
    ensure_type(
        index_key,
        stored,
        PAPER_RAID_FINALITY_REWORK_INDEX_OBJECT_TYPE_V4,
    )
    .map_err(|_| paper_raid_mirror_error(index_key))?;
    if stored.version != 1 || stored.value_bytes.len() > MAX_PAPER_RAID_FINALITY_INDEX_RECORD_BYTES
    {
        return Err(paper_raid_mirror_error(index_key));
    }
    let record = PaperRaidFinalityReworkIndexRecordV4::from_canonical_bytes(&stored.value_bytes)
        .map_err(|_| paper_raid_mirror_error(index_key))?;
    let rework_id = external_key_from_hash_hex(&record.rework_id)
        .ok_or_else(|| paper_raid_mirror_error(index_key))?;
    let commitment_id = external_key_from_hash_hex(&record.commitment_id)
        .ok_or_else(|| paper_raid_mirror_error(index_key))?;
    let expected_index_key = paper_raid_finality_rework_index_key_v4(rework_id)
        .map_err(|_| paper_raid_mirror_error(index_key))?;
    if expected_index_key != index_key {
        return Err(paper_raid_mirror_error(index_key));
    }
    let commitment_key = paper_raid_finality_commitment_key_v4(commitment_id)
        .map_err(|_| paper_raid_mirror_error(index_key))?;
    if commitment_key != record.commitment_object_key_hex {
        return Err(paper_raid_mirror_error(index_key));
    }
    let commitment_object = view
        .get(&commitment_key)
        .ok_or_else(|| paper_raid_mirror_error(index_key))?;
    ensure_type(
        &commitment_key,
        &commitment_object,
        PAPER_RAID_FINALITY_COMMITMENT_OBJECT_TYPE_V4,
    )
    .map_err(|_| paper_raid_mirror_error(index_key))?;
    if commitment_object.version != 1
        || commitment_object.value_bytes.len() > MAX_PAPER_RAID_FINALITY_COMMITMENT_BYTES
    {
        return Err(paper_raid_mirror_error(index_key));
    }
    let commitment =
        PaperRaidFinalityCommitmentV4::from_canonical_bytes(&commitment_object.value_bytes)
            .map_err(|_| paper_raid_mirror_error(index_key))?;
    if commitment
        .rework_lineage
        .as_ref()
        .is_none_or(|lineage| lineage.rework_id != rework_id)
        || commitment.commitment_id != commitment_id
        || digest_hex(commitment.canonical_hash("trnm-paper-raid-finality-commitment-v4"))
            != record.payload_hash_hex
    {
        return Err(paper_raid_mirror_error(index_key));
    }
    Ok(record)
}

fn paper_raid_mirror_error(index_key: &str) -> RuntimeError {
    RuntimeError::PaperRaidFinalityMirrorMismatch(index_key.to_string())
}

fn paper_raid_index_object_type(index_kind: PaperRaidFinalityIndexKindV2) -> &'static str {
    match index_kind {
        PaperRaidFinalityIndexKindV2::Submission => {
            PAPER_RAID_FINALITY_SUBMISSION_INDEX_OBJECT_TYPE_V2
        }
        PaperRaidFinalityIndexKindV2::Evaluation => {
            PAPER_RAID_FINALITY_EVALUATION_INDEX_OBJECT_TYPE_V2
        }
    }
}

fn paper_raid_index_object_type_v3(index_kind: PaperRaidFinalityIndexKindV2) -> &'static str {
    match index_kind {
        PaperRaidFinalityIndexKindV2::Submission => {
            PAPER_RAID_FINALITY_SUBMISSION_INDEX_OBJECT_TYPE_V3
        }
        PaperRaidFinalityIndexKindV2::Evaluation => {
            PAPER_RAID_FINALITY_EVALUATION_INDEX_OBJECT_TYPE_V3
        }
    }
}

fn paper_raid_index_object_type_v4(index_kind: PaperRaidFinalityIndexKindV2) -> &'static str {
    match index_kind {
        PaperRaidFinalityIndexKindV2::Submission => {
            PAPER_RAID_FINALITY_SUBMISSION_INDEX_OBJECT_TYPE_V4
        }
        PaperRaidFinalityIndexKindV2::Evaluation => {
            PAPER_RAID_FINALITY_EVALUATION_INDEX_OBJECT_TYPE_V4
        }
    }
}

fn external_key_from_hash_hex(value: &str) -> Option<ExternalKey> {
    if !is_hash_hex(value) {
        return None;
    }
    let mut bytes = [0u8; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).ok()?;
    }
    Some(ExternalKey::from_bytes(bytes))
}

fn metered_read_or_default(
    view: &dyn StateView,
    key: &str,
    object_type: &str,
    default_value_bytes: &[u8],
) -> Result<u64, RuntimeError> {
    match view.get(key) {
        Some(stored) => {
            ensure_type(key, &stored, object_type)?;
            metered_object_bytes(key, &stored.object_type, &stored.value_bytes)
        }
        None => metered_object_bytes(key, object_type, default_value_bytes),
    }
}

fn metered_object_bytes(
    key: &str,
    object_type: &str,
    value_bytes: &[u8],
) -> Result<u64, RuntimeError> {
    key.len()
        .checked_add(object_type.len())
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<u64>()))
        .and_then(|bytes| bytes.checked_add(value_bytes.len()))
        .and_then(|bytes| u64::try_from(bytes).ok())
        .ok_or(RuntimeError::ArithmeticOverflow)
}

fn validate_match_evidence_ref(
    view: &dyn StateView,
    object_ref: ObjectRefV1,
) -> Result<u64, RuntimeError> {
    if object_ref.kind != ResearchObjectKind::MatchEvidence || object_ref.object_version == 0 {
        return Err(RuntimeError::PaperRaidFinalityState(
            "Paper Raid finality must reference MatchEvidence".to_string(),
        ));
    }
    let key = research_domain_object_key(object_ref.kind, object_ref.key)
        .map_err(|error| RuntimeError::Protocol(error.to_string()))?;
    let stored = view
        .get(&key)
        .ok_or_else(|| RuntimeError::PaperRaidFinalityMirrorMismatch(key.clone()))?;
    ensure_type(&key, &stored, RESEARCH_DOMAIN_OBJECT_TYPE_V1)?;
    if stored.version != object_ref.object_version
        || stored.value_bytes.len() > MAX_MATCH_EVIDENCE_OBJECT_BYTES
    {
        return Err(RuntimeError::PaperRaidFinalityMirrorMismatch(key));
    }
    let decoded = ResearchDomainObjectV1::from_canonical_bytes(
        ResearchObjectKind::MatchEvidence,
        &stored.value_bytes,
    )
    .map_err(|_| RuntimeError::PaperRaidFinalityMirrorMismatch(key.clone()))?;
    if decoded.object_ref() != object_ref {
        return Err(RuntimeError::PaperRaidFinalityMirrorMismatch(key));
    }
    metered_object_bytes(&key, &stored.object_type, &stored.value_bytes)
}

fn validate_mutations(mutations: &[RuntimeMutation]) -> Result<(), RuntimeError> {
    for mutation in mutations {
        let expected_next = mutation
            .expected_version
            .unwrap_or(0)
            .checked_add(1)
            .ok_or(RuntimeError::ObjectVersionExhausted)?;
        if mutation.next_version != expected_next {
            return Err(RuntimeError::PaperRaidFinalityState(format!(
                "Paper Raid finality mutation {} does not advance exactly one version",
                mutation.object_key_hex
            )));
        }
    }
    if mutations
        .windows(2)
        .any(|pair| pair[0].object_key_hex == pair[1].object_key_hex)
    {
        return Err(RuntimeError::PaperRaidFinalityState(
            "Paper Raid finality mutation keys are not unique".to_string(),
        ));
    }
    Ok(())
}

fn paper_raid_event(
    signed: &VersionedPaperRaidFinalityCommand,
    commitment_key: &str,
    applied_key: &str,
    rework_index_key: Option<&str>,
) -> RuntimeEvent {
    let (scientific_finality, score_eligible, ranking_eligible, reward_eligible, economic_eligible) =
        match signed {
            VersionedPaperRaidFinalityCommand::V2(signed) => (
                signed.commitment.scientific_finality,
                signed.commitment.score_eligible,
                signed.commitment.ranking_eligible,
                signed.commitment.reward_eligible,
                signed.commitment.economic_eligible,
            ),
            VersionedPaperRaidFinalityCommand::V3(signed) => (
                signed.commitment.scientific_finality,
                signed.commitment.score_eligible,
                signed.commitment.ranking_eligible,
                signed.commitment.reward_eligible,
                signed.commitment.economic_eligible,
            ),
            VersionedPaperRaidFinalityCommand::V4(signed) => (
                signed.commitment.scientific_finality,
                signed.commitment.score_eligible,
                signed.commitment.ranking_eligible,
                signed.commitment.reward_eligible,
                signed.commitment.economic_eligible,
            ),
        };
    let mut attributes = BTreeMap::from([
        ("command_id".to_string(), signed.command_id().to_hex()),
        (
            "command_fingerprint_hex".to_string(),
            digest_hex(signed.command_fingerprint()),
        ),
        (
            "applied_command_object_key_hex".to_string(),
            applied_key.to_string(),
        ),
        ("commitment_id".to_string(), signed.commitment_id().to_hex()),
        (
            "commitment_object_key_hex".to_string(),
            commitment_key.to_string(),
        ),
        (
            "payload_hash_hex".to_string(),
            digest_hex(signed.payload_hash()),
        ),
        (
            "scientific_finality".to_string(),
            scientific_finality.to_string(),
        ),
        ("score_eligible".to_string(), score_eligible.to_string()),
        ("ranking_eligible".to_string(), ranking_eligible.to_string()),
        ("reward_eligible".to_string(), reward_eligible.to_string()),
        (
            "economic_eligible".to_string(),
            economic_eligible.to_string(),
        ),
    ]);
    if let VersionedPaperRaidFinalityCommand::V4(v4) = signed {
        if let Some(lineage) = &v4.commitment.rework_lineage {
            attributes.extend([
                ("rework_id".to_string(), lineage.rework_id.to_hex()),
                ("rework_cycle".to_string(), lineage.rework_cycle.to_string()),
                (
                    "rework_index_object_key_hex".to_string(),
                    rework_index_key.unwrap_or_default().to_string(),
                ),
                (
                    "rejected_submission_id".to_string(),
                    lineage.rejected_submission_id.to_hex(),
                ),
                (
                    "replacement_submission_id".to_string(),
                    lineage.replacement_submission_id.to_hex(),
                ),
                (
                    "rejected_revision_id".to_string(),
                    lineage.rejected_revision_id.to_hex(),
                ),
                (
                    "replacement_revision_id".to_string(),
                    lineage.replacement_revision_id.to_hex(),
                ),
                (
                    "rejected_release_candidate_hash_hex".to_string(),
                    digest_hex(lineage.rejected_release_candidate_hash),
                ),
                (
                    "replacement_release_candidate_hash_hex".to_string(),
                    digest_hex(lineage.replacement_release_candidate_hash),
                ),
                (
                    "rejected_paper_bundle_hash_hex".to_string(),
                    digest_hex(lineage.rejected_paper_bundle_hash),
                ),
                (
                    "replacement_paper_bundle_hash_hex".to_string(),
                    digest_hex(lineage.replacement_paper_bundle_hash),
                ),
                (
                    "rejected_rework_content_commitment_sha256_hex".to_string(),
                    digest_hex(lineage.rejected_rework_content_commitment_sha256),
                ),
                (
                    "replacement_rework_content_commitment_sha256_hex".to_string(),
                    digest_hex(lineage.replacement_rework_content_commitment_sha256),
                ),
            ]);
        }
    }
    RuntimeEvent {
        kind: if signed.is_v4() {
            "trnm.paper-raid.finality.applied.v4"
        } else if signed.is_v3() {
            "trnm.paper-raid.finality.applied.v3"
        } else {
            "trnm.paper-raid.finality.applied.v2"
        }
        .to_string(),
        attributes,
    }
}

fn paper_raid_key(
    domain: &str,
    label: &'static str,
    external_key: ExternalKey,
) -> Result<String, RuntimeError> {
    ensure_nonzero_key(label, external_key)?;
    Ok(digest_hex(canonical_hash(domain, external_key.as_bytes())))
}

fn ensure_nonzero_key(label: &'static str, external_key: ExternalKey) -> Result<(), RuntimeError> {
    if external_key.as_bytes() == &[0; 32] {
        return Err(RuntimeError::PaperRaidFinalityState(format!(
            "{label} must be non-zero"
        )));
    }
    Ok(())
}

fn digest_hex(digest: [u8; 32]) -> String {
    ExternalKey::from_bytes(digest).to_hex()
}

fn is_hash_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use ed25519_dalek::{Signer, SigningKey};
    use trnm_protocol::{
        CANONICAL_PAPER_RAID_FINALITY_TX_PAYLOAD_TYPE_V2,
        CANONICAL_PAPER_RAID_FINALITY_TX_PAYLOAD_TYPE_V3,
        CANONICAL_PAPER_RAID_FINALITY_TX_PAYLOAD_TYPE_V4,
        CANONICAL_PAPER_RAID_FINALITY_TX_SCHEMA_V2, CANONICAL_PAPER_RAID_FINALITY_TX_SCHEMA_V3,
        CANONICAL_PAPER_RAID_FINALITY_TX_SCHEMA_V4,
    };
    use trnm_research_protocol::{
        AuthorityIdentityV1, AuthoritySetV1, MatchEvidenceCommitmentV1, MatchEvidenceObjectV1,
        PaperRaidAppealStatusV2, PaperRaidAppealStatusV3, PaperRaidReworkLineageV1,
    };

    use super::*;
    use crate::{research_genesis_mutation, StateObject};

    const CHAIN_ID: &str = "trnm-paper-raid-test";
    const HEPTA_DID: &str = "did:trnm:hepta-authority";
    const HEPTA_SEED: [u8; 32] = [0x22; 32];
    const FINALIZED_AT_UNIX_S: u64 = 1_753_450_001;

    #[derive(Default, Clone)]
    struct MemoryView(BTreeMap<String, StateObject>);

    impl StateView for MemoryView {
        fn get(&self, object_key_hex: &str) -> Option<StateObject> {
            self.0.get(object_key_hex).cloned()
        }
    }

    impl MemoryView {
        fn apply_mutations(&mut self, mutations: Vec<RuntimeMutation>) {
            for mutation in mutations {
                assert_eq!(
                    self.0
                        .get(&mutation.object_key_hex)
                        .map(|object| object.version),
                    mutation.expected_version
                );
                self.0.insert(
                    mutation.object_key_hex,
                    StateObject {
                        object_type: mutation.object_type,
                        version: mutation.next_version,
                        value_bytes: mutation.value_bytes,
                    },
                );
            }
        }

        fn account(&self, account: &str) -> AccountV1 {
            serde_json::from_slice(&self.0[&account_key(account)].value_bytes).unwrap()
        }
    }

    fn external_key(namespace: &str, id: &str) -> ExternalKey {
        ExternalKey::from_external_id(namespace, id).unwrap()
    }

    fn match_evidence() -> (ObjectRefV1, ResearchDomainObjectV1) {
        let commitment = MatchEvidenceCommitmentV1 {
            commitment_id: external_key("nakama.commitment", "paper-raid-match-001"),
            match_id: external_key("nakama.match", "paper-raid-match-001"),
            challenge_id: external_key("hepta.challenge", "paper-raid-challenge-001"),
            event_root: [0x10; 32],
            roster_root: [0x11; 32],
            ruleset_hash: [0x12; 32],
            dataset_hash: [0x13; 32],
            archive_hash: [0x14; 32],
            event_count: 42,
            completed_at_unix_s: 1_753_449_600,
        };
        let object_ref = commitment.object_ref();
        (
            object_ref,
            ResearchDomainObjectV1::MatchEvidence(MatchEvidenceObjectV1 {
                object_ref,
                commitment,
            }),
        )
    }

    fn valid_commitment(match_evidence_ref: ObjectRefV1) -> PaperRaidFinalityCommitmentV2 {
        PaperRaidFinalityCommitmentV2 {
            commitment_id: external_key("hepta.paper-raid.finality", "finality-001"),
            paper_project_id: external_key("hepta.paper", "paper-001"),
            submission_id: external_key("hepta.submission", "submission-001"),
            match_evidence_ref,
            release_candidate_hash: [0x21; 32],
            paper_bundle_hash: [0x22; 32],
            submission_commitment_hash: [0x23; 32],
            author_consent_set_hash: [0x24; 32],
            tolerance_policy_hash: [0x25; 32],
            evaluation_id: external_key("hepta.evaluation", "evaluation-001"),
            evaluation_hash: [0x26; 32],
            evaluation_score_bps: 8_500,
            evaluation_accepted: true,
            evaluation_completed_at_unix_s: 1_753_449_700,
            latest_reproduction_id: external_key("hepta.reproduction", "reproduction-001"),
            latest_reproduction_hash: [0x27; 32],
            latest_reproduction_accepted: true,
            latest_reproduction_completed_at_unix_s: 1_753_449_800,
            evaluation_superseded_by: None,
            reproduction_superseded_by: None,
            appeal_status: PaperRaidAppealStatusV2::ClosedNoAppeal,
            appeal_id: None,
            appeal_resolution_hash: None,
            appeal_window_closes_at_unix_s: 1_753_450_000,
            settlement_policy_hash: [0x28; 32],
            scientific_finality: true,
            score_eligible: false,
            ranking_eligible: false,
            reward_eligible: false,
            economic_eligible: false,
            finalized_at_unix_s: FINALIZED_AT_UNIX_S,
        }
    }

    fn valid_commitment_v3(match_evidence_ref: ObjectRefV1) -> PaperRaidFinalityCommitmentV3 {
        let v2 = valid_commitment(match_evidence_ref);
        PaperRaidFinalityCommitmentV3 {
            commitment_id: v2.commitment_id,
            paper_project_id: v2.paper_project_id,
            submission_id: v2.submission_id,
            match_evidence_ref: v2.match_evidence_ref,
            release_candidate_hash: v2.release_candidate_hash,
            paper_bundle_hash: v2.paper_bundle_hash,
            submission_commitment_hash: v2.submission_commitment_hash,
            author_consent_set_hash: v2.author_consent_set_hash,
            tolerance_policy_hash: v2.tolerance_policy_hash,
            evaluation_id: v2.evaluation_id,
            evaluation_hash: v2.evaluation_hash,
            evaluation_score_bps: v2.evaluation_score_bps,
            evaluation_accepted: v2.evaluation_accepted,
            evaluation_completed_at_unix_s: v2.evaluation_completed_at_unix_s,
            latest_reproduction_id: v2.latest_reproduction_id,
            latest_reproduction_hash: v2.latest_reproduction_hash,
            latest_reproduction_accepted: v2.latest_reproduction_accepted,
            latest_reproduction_completed_at_unix_s: v2.latest_reproduction_completed_at_unix_s,
            evaluation_supersedes: None,
            evaluation_superseded_by: v2.evaluation_superseded_by,
            reproduction_superseded_by: v2.reproduction_superseded_by,
            appeal_status: PaperRaidAppealStatusV3::ClosedNoAppeal,
            appeal_id: v2.appeal_id,
            appealed_evaluation_id: None,
            appeal_resolution_hash: v2.appeal_resolution_hash,
            appeal_window_closes_at_unix_s: v2.appeal_window_closes_at_unix_s,
            settlement_policy_hash: v2.settlement_policy_hash,
            scientific_finality: v2.scientific_finality,
            score_eligible: v2.score_eligible,
            ranking_eligible: v2.ranking_eligible,
            reward_eligible: v2.reward_eligible,
            economic_eligible: v2.economic_eligible,
            finalized_at_unix_s: v2.finalized_at_unix_s,
        }
    }

    fn valid_commitment_v4(match_evidence_ref: ObjectRefV1) -> PaperRaidFinalityCommitmentV4 {
        let v3 = valid_commitment_v3(match_evidence_ref);
        PaperRaidFinalityCommitmentV4 {
            commitment_id: v3.commitment_id,
            paper_project_id: v3.paper_project_id,
            submission_id: v3.submission_id,
            match_evidence_ref: v3.match_evidence_ref,
            release_candidate_hash: v3.release_candidate_hash,
            paper_bundle_hash: v3.paper_bundle_hash,
            submission_commitment_hash: v3.submission_commitment_hash,
            author_consent_set_hash: v3.author_consent_set_hash,
            tolerance_policy_hash: v3.tolerance_policy_hash,
            evaluation_id: v3.evaluation_id,
            evaluation_hash: v3.evaluation_hash,
            evaluation_score_bps: v3.evaluation_score_bps,
            evaluation_accepted: v3.evaluation_accepted,
            evaluation_completed_at_unix_s: v3.evaluation_completed_at_unix_s,
            latest_reproduction_id: v3.latest_reproduction_id,
            latest_reproduction_hash: v3.latest_reproduction_hash,
            latest_reproduction_accepted: v3.latest_reproduction_accepted,
            latest_reproduction_completed_at_unix_s: v3.latest_reproduction_completed_at_unix_s,
            evaluation_supersedes: v3.evaluation_supersedes,
            evaluation_superseded_by: v3.evaluation_superseded_by,
            reproduction_superseded_by: v3.reproduction_superseded_by,
            appeal_status: v3.appeal_status,
            appeal_id: v3.appeal_id,
            appealed_evaluation_id: v3.appealed_evaluation_id,
            appeal_resolution_hash: v3.appeal_resolution_hash,
            appeal_window_closes_at_unix_s: v3.appeal_window_closes_at_unix_s,
            settlement_policy_hash: v3.settlement_policy_hash,
            scientific_finality: v3.scientific_finality,
            score_eligible: v3.score_eligible,
            ranking_eligible: v3.ranking_eligible,
            reward_eligible: v3.reward_eligible,
            economic_eligible: v3.economic_eligible,
            finalized_at_unix_s: v3.finalized_at_unix_s,
            rework_lineage: Some(PaperRaidReworkLineageV1 {
                rework_id: external_key("hepta.rework", "rework-001"),
                rework_cycle: 2,
                rejected_submission_id: external_key("hepta.submission", "submission-000"),
                replacement_submission_id: v3.submission_id,
                rejected_revision_id: external_key("hepta.revision", "revision-000"),
                replacement_revision_id: external_key("hepta.revision", "revision-001"),
                rejected_release_candidate_hash: [0x31; 32],
                replacement_release_candidate_hash: v3.release_candidate_hash,
                rejected_paper_bundle_hash: [0x32; 32],
                replacement_paper_bundle_hash: v3.paper_bundle_hash,
                rejected_rework_content_commitment_sha256: [0x33; 32],
                replacement_rework_content_commitment_sha256: [0x34; 32],
            }),
        }
    }

    fn fixture(
        balance: u128,
    ) -> (
        MemoryView,
        SigningKey,
        SignedPaperRaidFinalityCommandV2,
        CanonicalPaperRaidFinalityTxV2,
    ) {
        let hepta_key = SigningKey::from_bytes(&HEPTA_SEED);
        let authorities = AuthoritySetV1::new(
            Vec::new(),
            vec![AuthorityIdentityV1::new(
                HEPTA_DID.to_string(),
                hepta_key.verifying_key().to_bytes(),
            )
            .unwrap()],
        )
        .unwrap();
        let mut view = MemoryView::default();
        view.apply_mutations(vec![research_genesis_mutation(authorities).unwrap()]);
        view.0.insert(
            account_key(HEPTA_DID),
            StateObject {
                object_type: ACCOUNT_OBJECT_TYPE_V1.to_string(),
                version: 1,
                value_bytes: serde_json::to_vec(&AccountV1 {
                    account: HEPTA_DID.to_string(),
                    balance,
                    nonce: 0,
                })
                .unwrap(),
            },
        );
        let (match_ref, match_object) = match_evidence();
        view.0.insert(
            research_domain_object_key(match_ref.kind, match_ref.key).unwrap(),
            StateObject {
                object_type: RESEARCH_DOMAIN_OBJECT_TYPE_V1.to_string(),
                version: match_ref.object_version,
                value_bytes: match_object.canonical_bytes(),
            },
        );
        let signed = SignedPaperRaidFinalityCommandV2::sign(
            CHAIN_ID.to_string(),
            external_key("trnm.command", "paper-raid-finality-001"),
            HEPTA_DID.to_string(),
            1,
            valid_commitment(match_ref),
            &hepta_key,
        )
        .unwrap();
        let tx = CanonicalPaperRaidFinalityTxV2::from_signed_command(&signed, 1_000_000, 1_000_000)
            .unwrap();
        (view, hepta_key, signed, tx)
    }

    fn fixture_v3(
        balance: u128,
    ) -> (
        MemoryView,
        SigningKey,
        SignedPaperRaidFinalityCommandV3,
        CanonicalPaperRaidFinalityTxV3,
    ) {
        let (view, hepta_key, signed_v2, _) = fixture(balance);
        let signed = SignedPaperRaidFinalityCommandV3::sign(
            CHAIN_ID.to_string(),
            signed_v2.command_id,
            HEPTA_DID.to_string(),
            signed_v2.nonce,
            valid_commitment_v3(signed_v2.commitment.match_evidence_ref),
            &hepta_key,
        )
        .unwrap();
        let tx = CanonicalPaperRaidFinalityTxV3::from_signed_command(&signed, 1_000_000, 1_000_000)
            .unwrap();
        (view, hepta_key, signed, tx)
    }

    fn fixture_v4(
        balance: u128,
    ) -> (
        MemoryView,
        SigningKey,
        SignedPaperRaidFinalityCommandV4,
        CanonicalPaperRaidFinalityTxV4,
    ) {
        let (view, hepta_key, signed_v2, _) = fixture(balance);
        let signed = SignedPaperRaidFinalityCommandV4::sign(
            CHAIN_ID.to_string(),
            signed_v2.command_id,
            HEPTA_DID.to_string(),
            signed_v2.nonce,
            valid_commitment_v4(signed_v2.commitment.match_evidence_ref),
            &hepta_key,
        )
        .unwrap();
        let tx = CanonicalPaperRaidFinalityTxV4::from_signed_command(&signed, 1_000_000, 1_000_000)
            .unwrap();
        (view, hepta_key, signed, tx)
    }

    fn context<'a>(
        payload: &'a [u8],
        signer_id: &'a str,
        signer_role: &'a str,
    ) -> ExecutionContext<'a> {
        ExecutionContext {
            height: 1,
            chain_id: CHAIN_ID,
            signer_id,
            signer_role,
            payload_len: payload.len(),
        }
    }

    fn execute_at_finality(
        tx: &CanonicalPaperRaidFinalityTxV2,
        context: ExecutionContext<'_>,
        view: &dyn StateView,
    ) -> Result<RuntimeReceipt, RuntimeError> {
        execute_paper_raid_finality(tx, context, FINALIZED_AT_UNIX_S, view)
    }

    fn raw_tx(signed: &SignedPaperRaidFinalityCommandV2) -> CanonicalPaperRaidFinalityTxV2 {
        CanonicalPaperRaidFinalityTxV2 {
            schema: CANONICAL_PAPER_RAID_FINALITY_TX_SCHEMA_V2.to_string(),
            payload_type: CANONICAL_PAPER_RAID_FINALITY_TX_PAYLOAD_TYPE_V2.to_string(),
            command_id: signed.command_id.to_hex(),
            sender: signed.signer_did.clone(),
            nonce: signed.nonce,
            max_gas: 1_000_000,
            fee_limit: 1_000_000,
            signed_paper_raid_finality_command_cbor_hex: hex::encode(signed.canonical_bytes()),
        }
    }

    fn raw_tx_v3(signed: &SignedPaperRaidFinalityCommandV3) -> CanonicalPaperRaidFinalityTxV3 {
        CanonicalPaperRaidFinalityTxV3 {
            schema: CANONICAL_PAPER_RAID_FINALITY_TX_SCHEMA_V3.to_string(),
            payload_type: CANONICAL_PAPER_RAID_FINALITY_TX_PAYLOAD_TYPE_V3.to_string(),
            command_id: signed.command_id.to_hex(),
            sender: signed.signer_did.clone(),
            nonce: signed.nonce,
            max_gas: 1_000_000,
            fee_limit: 1_000_000,
            signed_paper_raid_finality_command_cbor_hex: hex::encode(signed.canonical_bytes()),
        }
    }

    fn execute_at_finality_v3(
        tx: &CanonicalPaperRaidFinalityTxV3,
        context: ExecutionContext<'_>,
        view: &dyn StateView,
    ) -> Result<RuntimeReceipt, RuntimeError> {
        execute_paper_raid_finality_v3(tx, context, FINALIZED_AT_UNIX_S, view)
    }

    fn raw_tx_v4(signed: &SignedPaperRaidFinalityCommandV4) -> CanonicalPaperRaidFinalityTxV4 {
        CanonicalPaperRaidFinalityTxV4 {
            schema: CANONICAL_PAPER_RAID_FINALITY_TX_SCHEMA_V4.to_string(),
            payload_type: CANONICAL_PAPER_RAID_FINALITY_TX_PAYLOAD_TYPE_V4.to_string(),
            command_id: signed.command_id.to_hex(),
            sender: signed.signer_did.clone(),
            nonce: signed.nonce,
            max_gas: 1_000_000,
            fee_limit: 1_000_000,
            signed_paper_raid_finality_command_cbor_hex: hex::encode(signed.canonical_bytes()),
        }
    }

    fn execute_at_finality_v4(
        tx: &CanonicalPaperRaidFinalityTxV4,
        context: ExecutionContext<'_>,
        view: &dyn StateView,
    ) -> Result<RuntimeReceipt, RuntimeError> {
        execute_paper_raid_finality_v4(tx, context, FINALIZED_AT_UNIX_S, view)
    }

    fn resign(
        mut signed: SignedPaperRaidFinalityCommandV2,
        signing_key: &SigningKey,
    ) -> SignedPaperRaidFinalityCommandV2 {
        signed.signature = signing_key
            .sign(&signed.signing_bytes())
            .to_bytes()
            .to_vec();
        signed
    }

    #[derive(Clone, Copy, Debug)]
    enum CrossVersionConflict {
        Command,
        Commitment,
        Submission,
        Evaluation,
    }

    fn set_account_state(view: &mut MemoryView, balance: u128, nonce: u64) {
        let account = view.0.get_mut(&account_key(HEPTA_DID)).unwrap();
        account.value_bytes = serde_json::to_vec(&AccountV1 {
            account: HEPTA_DID.to_string(),
            balance,
            nonce,
        })
        .unwrap();
    }

    fn assert_cross_version_conflict(error: RuntimeError, conflict: CrossVersionConflict) {
        assert!(
            matches!(
                (&error, conflict),
                (
                    RuntimeError::PaperRaidFinalityCommandReplay,
                    CrossVersionConflict::Command
                ) | (
                    RuntimeError::PaperRaidFinalityCommitmentExists,
                    CrossVersionConflict::Commitment
                ) | (
                    RuntimeError::PaperRaidFinalitySubmissionExists,
                    CrossVersionConflict::Submission
                ) | (
                    RuntimeError::PaperRaidFinalityEvaluationExists,
                    CrossVersionConflict::Evaluation
                )
            ),
            "unexpected {conflict:?} error: {error:?}"
        );
    }

    fn isolated_v3_conflict(
        baseline: &SignedPaperRaidFinalityCommandV2,
        conflict: CrossVersionConflict,
    ) -> (ExternalKey, PaperRaidFinalityCommitmentV3) {
        let mut commitment = valid_commitment_v3(baseline.commitment.match_evidence_ref);
        commitment.commitment_id = external_key("hepta.paper-raid.finality", "v3-unique");
        commitment.paper_project_id = external_key("hepta.paper", "v3-unique");
        commitment.submission_id = external_key("hepta.submission", "v3-unique");
        commitment.evaluation_id = external_key("hepta.evaluation", "v3-unique");
        let mut command_id = external_key("trnm.command", "v3-unique");
        match conflict {
            CrossVersionConflict::Command => command_id = baseline.command_id,
            CrossVersionConflict::Commitment => {
                commitment.commitment_id = baseline.commitment.commitment_id
            }
            CrossVersionConflict::Submission => {
                commitment.paper_project_id = baseline.commitment.paper_project_id;
                commitment.submission_id = baseline.commitment.submission_id;
            }
            CrossVersionConflict::Evaluation => {
                commitment.evaluation_id = baseline.commitment.evaluation_id
            }
        }
        (command_id, commitment)
    }

    fn isolated_v2_conflict(
        baseline: &SignedPaperRaidFinalityCommandV3,
        conflict: CrossVersionConflict,
    ) -> (ExternalKey, PaperRaidFinalityCommitmentV2) {
        let mut commitment = valid_commitment(baseline.commitment.match_evidence_ref);
        commitment.commitment_id = external_key("hepta.paper-raid.finality", "v2-unique");
        commitment.paper_project_id = external_key("hepta.paper", "v2-unique");
        commitment.submission_id = external_key("hepta.submission", "v2-unique");
        commitment.evaluation_id = external_key("hepta.evaluation", "v2-unique");
        let mut command_id = external_key("trnm.command", "v2-unique");
        match conflict {
            CrossVersionConflict::Command => command_id = baseline.command_id,
            CrossVersionConflict::Commitment => {
                commitment.commitment_id = baseline.commitment.commitment_id
            }
            CrossVersionConflict::Submission => {
                commitment.paper_project_id = baseline.commitment.paper_project_id;
                commitment.submission_id = baseline.commitment.submission_id;
            }
            CrossVersionConflict::Evaluation => {
                commitment.evaluation_id = baseline.commitment.evaluation_id
            }
        }
        (command_id, commitment)
    }

    #[allow(clippy::too_many_arguments)]
    fn isolated_v4_conflict(
        baseline_command_id: ExternalKey,
        baseline_commitment_id: ExternalKey,
        baseline_paper_project_id: ExternalKey,
        baseline_submission_id: ExternalKey,
        baseline_evaluation_id: ExternalKey,
        match_evidence_ref: ObjectRefV1,
        conflict: CrossVersionConflict,
    ) -> (ExternalKey, PaperRaidFinalityCommitmentV4) {
        let mut commitment = valid_commitment_v4(match_evidence_ref);
        commitment.commitment_id = external_key("hepta.paper-raid.finality", "v4-unique");
        commitment.paper_project_id = external_key("hepta.paper", "v4-unique");
        commitment.submission_id = external_key("hepta.submission", "v4-unique");
        commitment.evaluation_id = external_key("hepta.evaluation", "v4-unique");
        commitment.rework_lineage.as_mut().unwrap().rework_id =
            external_key("hepta.rework", "v4-unique");
        let mut command_id = external_key("trnm.command", "v4-unique");
        match conflict {
            CrossVersionConflict::Command => command_id = baseline_command_id,
            CrossVersionConflict::Commitment => commitment.commitment_id = baseline_commitment_id,
            CrossVersionConflict::Submission => {
                commitment.paper_project_id = baseline_paper_project_id;
                commitment.submission_id = baseline_submission_id;
            }
            CrossVersionConflict::Evaluation => commitment.evaluation_id = baseline_evaluation_id,
        }
        commitment
            .rework_lineage
            .as_mut()
            .unwrap()
            .replacement_submission_id = commitment.submission_id;
        (command_id, commitment)
    }

    fn isolated_v2_conflict_from_v4(
        baseline: &SignedPaperRaidFinalityCommandV4,
        conflict: CrossVersionConflict,
    ) -> (ExternalKey, PaperRaidFinalityCommitmentV2) {
        let mut commitment = valid_commitment(baseline.commitment.match_evidence_ref);
        commitment.commitment_id = external_key("hepta.paper-raid.finality", "v2-from-v4-unique");
        commitment.paper_project_id = external_key("hepta.paper", "v2-from-v4-unique");
        commitment.submission_id = external_key("hepta.submission", "v2-from-v4-unique");
        commitment.evaluation_id = external_key("hepta.evaluation", "v2-from-v4-unique");
        let mut command_id = external_key("trnm.command", "v2-from-v4-unique");
        match conflict {
            CrossVersionConflict::Command => command_id = baseline.command_id,
            CrossVersionConflict::Commitment => {
                commitment.commitment_id = baseline.commitment.commitment_id
            }
            CrossVersionConflict::Submission => {
                commitment.paper_project_id = baseline.commitment.paper_project_id;
                commitment.submission_id = baseline.commitment.submission_id;
            }
            CrossVersionConflict::Evaluation => {
                commitment.evaluation_id = baseline.commitment.evaluation_id
            }
        }
        (command_id, commitment)
    }

    fn insert_v3_finality_mirrors(
        view: &mut MemoryView,
        signed: &SignedPaperRaidFinalityCommandV3,
    ) {
        let commitment_key =
            paper_raid_finality_commitment_key_v3(signed.commitment.commitment_id).unwrap();
        view.0.insert(
            commitment_key.clone(),
            StateObject {
                object_type: PAPER_RAID_FINALITY_COMMITMENT_OBJECT_TYPE_V3.to_string(),
                version: 1,
                value_bytes: signed.commitment.canonical_bytes(),
            },
        );
        view.0.insert(
            paper_raid_finality_applied_command_key_v3(signed.command_id).unwrap(),
            StateObject {
                object_type: PAPER_RAID_FINALITY_APPLIED_COMMAND_OBJECT_TYPE_V3.to_string(),
                version: 1,
                value_bytes: PaperRaidFinalityAppliedRecordV3::from_signed(signed)
                    .unwrap()
                    .canonical_bytes()
                    .unwrap(),
            },
        );
        for (index_kind, key, object_type) in [
            (
                PaperRaidFinalityIndexKindV2::Submission,
                paper_raid_finality_submission_index_key_v3(
                    signed.commitment.paper_project_id,
                    signed.commitment.submission_id,
                )
                .unwrap(),
                PAPER_RAID_FINALITY_SUBMISSION_INDEX_OBJECT_TYPE_V3,
            ),
            (
                PaperRaidFinalityIndexKindV2::Evaluation,
                paper_raid_finality_evaluation_index_key_v3(signed.commitment.evaluation_id)
                    .unwrap(),
                PAPER_RAID_FINALITY_EVALUATION_INDEX_OBJECT_TYPE_V3,
            ),
        ] {
            view.0.insert(
                key,
                StateObject {
                    object_type: object_type.to_string(),
                    version: 1,
                    value_bytes: PaperRaidFinalityIndexRecordV3::from_signed(
                        signed,
                        index_kind,
                        commitment_key.clone(),
                    )
                    .canonical_bytes()
                    .unwrap(),
                },
            );
        }
    }

    fn isolated_v3_conflict_from_v4(
        baseline: &SignedPaperRaidFinalityCommandV4,
        conflict: CrossVersionConflict,
    ) -> (ExternalKey, PaperRaidFinalityCommitmentV3) {
        let mut commitment = valid_commitment_v3(baseline.commitment.match_evidence_ref);
        commitment.commitment_id = external_key("hepta.paper-raid.finality", "v3-from-v4-unique");
        commitment.paper_project_id = external_key("hepta.paper", "v3-from-v4-unique");
        commitment.submission_id = external_key("hepta.submission", "v3-from-v4-unique");
        commitment.evaluation_id = external_key("hepta.evaluation", "v3-from-v4-unique");
        let mut command_id = external_key("trnm.command", "v3-from-v4-unique");
        match conflict {
            CrossVersionConflict::Command => command_id = baseline.command_id,
            CrossVersionConflict::Commitment => {
                commitment.commitment_id = baseline.commitment.commitment_id
            }
            CrossVersionConflict::Submission => {
                commitment.paper_project_id = baseline.commitment.paper_project_id;
                commitment.submission_id = baseline.commitment.submission_id;
            }
            CrossVersionConflict::Evaluation => {
                commitment.evaluation_id = baseline.commitment.evaluation_id
            }
        }
        (command_id, commitment)
    }

    #[test]
    fn finality_execution_is_atomic_and_exact_replays_fail_closed() {
        let (mut view, hepta_key, signed, tx) = fixture(10_000_000);
        let payload = tx.canonical_bytes().unwrap();
        let before = view.account(HEPTA_DID);
        let receipt =
            execute_at_finality(&tx, context(&payload, HEPTA_DID, "hepta"), &view).unwrap();
        assert!(receipt.fee_charged > 0);
        assert_eq!(
            receipt.events[0].kind,
            "trnm.paper-raid.finality.applied.v2"
        );
        assert!(receipt.mutations.iter().any(|mutation| {
            mutation.object_type == PAPER_RAID_FINALITY_COMMITMENT_OBJECT_TYPE_V2
        }));
        assert!(receipt.mutations.iter().any(|mutation| {
            mutation.object_type == PAPER_RAID_FINALITY_APPLIED_COMMAND_OBJECT_TYPE_V2
        }));
        assert!(receipt.mutations.iter().any(|mutation| {
            mutation.object_type == PAPER_RAID_FINALITY_SUBMISSION_INDEX_OBJECT_TYPE_V2
        }));
        assert!(receipt.mutations.iter().any(|mutation| {
            mutation.object_type == PAPER_RAID_FINALITY_EVALUATION_INDEX_OBJECT_TYPE_V2
        }));
        let actual_write_bytes = receipt
            .mutations
            .iter()
            .map(|mutation| {
                metered_object_bytes(
                    &mutation.object_key_hex,
                    &mutation.object_type,
                    &mutation.value_bytes,
                )
                .unwrap()
            })
            .sum::<u64>();
        let policy = FeePolicyV1::default();
        let write_only_gas_floor = policy
            .base_gas
            .checked_add(
                u64::try_from(payload.len())
                    .unwrap()
                    .checked_mul(policy.byte_gas)
                    .unwrap(),
            )
            .and_then(|gas| gas.checked_add(PAPER_RAID_FINALITY_OPERATION_GAS))
            .and_then(|gas| gas.checked_add(actual_write_bytes * policy.byte_gas))
            .and_then(|gas| gas.checked_add(10 * PAPER_RAID_FINALITY_OBJECT_TOUCH_GAS))
            .unwrap();
        assert!(receipt.gas_used >= write_only_gas_floor);
        let charged = receipt.fee_charged;
        view.apply_mutations(receipt.mutations);
        let after = view.account(HEPTA_DID);
        assert_eq!(after.nonce, 1);
        assert_eq!(after.balance, before.balance - charged);

        assert!(matches!(
            execute_at_finality(&tx, context(&payload, HEPTA_DID, "hepta"), &view,),
            Err(RuntimeError::PaperRaidFinalityCommandReplay)
        ));

        let mut altered_commitment = signed.commitment.clone();
        altered_commitment.evaluation_hash = [0x99; 32];
        let altered_signed = SignedPaperRaidFinalityCommandV2::sign(
            CHAIN_ID.to_string(),
            signed.command_id,
            HEPTA_DID.to_string(),
            1,
            altered_commitment,
            &hepta_key,
        )
        .unwrap();
        let altered_tx = CanonicalPaperRaidFinalityTxV2::from_signed_command(
            &altered_signed,
            1_000_000,
            1_000_000,
        )
        .unwrap();
        let altered_payload = altered_tx.canonical_bytes().unwrap();
        assert!(matches!(
            execute_at_finality(
                &altered_tx,
                context(&altered_payload, HEPTA_DID, "hepta"),
                &view,
            ),
            Err(RuntimeError::PaperRaidFinalityAlteredReplay)
        ));
        assert_eq!(view.account(HEPTA_DID), after);
    }

    #[test]
    fn consensus_time_must_reach_appeal_close_and_finalized_boundaries() {
        let (view, hepta_key, signed, tx) = fixture(10_000_000);
        let payload = tx.canonical_bytes().unwrap();
        let finalized_at = signed.commitment.finalized_at_unix_s;
        assert!(execute_paper_raid_finality(
            &tx,
            context(&payload, HEPTA_DID, "hepta"),
            finalized_at,
            &view,
        )
        .is_ok());

        let before = view.0.clone();
        let error = execute_paper_raid_finality(
            &tx,
            context(&payload, HEPTA_DID, "hepta"),
            finalized_at - 1,
            &view,
        )
        .expect_err("a block one second before finalized_at must fail closed");
        assert!(matches!(
            error,
            RuntimeError::PaperRaidFinalityTimeNotReached {
                block_time_unix_s,
                required_unix_s,
            } if block_time_unix_s == finalized_at - 1 && required_unix_s == finalized_at
        ));
        assert_eq!(view.0, before);

        let mut future_commitment = signed.commitment;
        future_commitment.appeal_window_closes_at_unix_s = finalized_at + 100;
        future_commitment.finalized_at_unix_s = finalized_at + 101;
        let future_signed = SignedPaperRaidFinalityCommandV2::sign(
            CHAIN_ID.to_string(),
            external_key("trnm.command", "paper-raid-finality-future-window"),
            HEPTA_DID.to_string(),
            1,
            future_commitment,
            &hepta_key,
        )
        .unwrap();
        let future_tx = CanonicalPaperRaidFinalityTxV2::from_signed_command(
            &future_signed,
            1_000_000,
            1_000_000,
        )
        .unwrap();
        let future_payload = future_tx.canonical_bytes().unwrap();
        let error = execute_paper_raid_finality(
            &future_tx,
            context(&future_payload, HEPTA_DID, "hepta"),
            finalized_at,
            &view,
        )
        .expect_err("a future appeal window must not finalize early");
        assert!(matches!(
            error,
            RuntimeError::PaperRaidFinalityTimeNotReached {
                block_time_unix_s,
                required_unix_s,
            } if block_time_unix_s == finalized_at && required_unix_s == finalized_at + 100
        ));
        assert_eq!(view.0, before);
    }

    #[test]
    fn submission_and_evaluation_indexes_reject_conflicting_finalities_atomically() {
        let (mut view, hepta_key, signed, tx) = fixture(10_000_000);
        let payload = tx.canonical_bytes().unwrap();
        let receipt = execute_at_finality(&tx, context(&payload, HEPTA_DID, "hepta"), &view)
            .expect("initial finality must apply");
        view.apply_mutations(receipt.mutations);
        let after_initial = view.0.clone();

        let mut submission_conflict = signed.commitment.clone();
        submission_conflict.commitment_id =
            external_key("hepta.paper-raid.finality", "finality-submission-conflict");
        submission_conflict.evaluation_id =
            external_key("hepta.evaluation", "evaluation-submission-conflict");
        let submission_signed = SignedPaperRaidFinalityCommandV2::sign(
            CHAIN_ID.to_string(),
            external_key("trnm.command", "paper-raid-submission-conflict"),
            HEPTA_DID.to_string(),
            2,
            submission_conflict,
            &hepta_key,
        )
        .unwrap();
        let submission_tx = CanonicalPaperRaidFinalityTxV2::from_signed_command(
            &submission_signed,
            1_000_000,
            1_000_000,
        )
        .unwrap();
        let submission_payload = submission_tx.canonical_bytes().unwrap();
        assert!(matches!(
            execute_at_finality(
                &submission_tx,
                context(&submission_payload, HEPTA_DID, "hepta"),
                &view,
            ),
            Err(RuntimeError::PaperRaidFinalitySubmissionExists)
        ));
        assert_eq!(view.0, after_initial);
        assert!(view
            .get(
                &paper_raid_finality_commitment_key(submission_signed.commitment.commitment_id)
                    .unwrap()
            )
            .is_none());
        assert!(view
            .get(&paper_raid_finality_applied_command_key(submission_signed.command_id).unwrap())
            .is_none());
        assert!(view
            .get(
                &paper_raid_finality_evaluation_index_key(
                    submission_signed.commitment.evaluation_id
                )
                .unwrap()
            )
            .is_none());

        let mut evaluation_conflict = signed.commitment.clone();
        evaluation_conflict.commitment_id =
            external_key("hepta.paper-raid.finality", "finality-evaluation-conflict");
        evaluation_conflict.submission_id =
            external_key("hepta.submission", "submission-evaluation-conflict");
        let evaluation_signed = SignedPaperRaidFinalityCommandV2::sign(
            CHAIN_ID.to_string(),
            external_key("trnm.command", "paper-raid-evaluation-conflict"),
            HEPTA_DID.to_string(),
            2,
            evaluation_conflict,
            &hepta_key,
        )
        .unwrap();
        let evaluation_tx = CanonicalPaperRaidFinalityTxV2::from_signed_command(
            &evaluation_signed,
            1_000_000,
            1_000_000,
        )
        .unwrap();
        let evaluation_payload = evaluation_tx.canonical_bytes().unwrap();
        assert!(matches!(
            execute_at_finality(
                &evaluation_tx,
                context(&evaluation_payload, HEPTA_DID, "hepta"),
                &view,
            ),
            Err(RuntimeError::PaperRaidFinalityEvaluationExists)
        ));
        assert_eq!(view.0, after_initial);
        assert!(view
            .get(
                &paper_raid_finality_submission_index_key(
                    evaluation_signed.commitment.paper_project_id,
                    evaluation_signed.commitment.submission_id,
                )
                .unwrap()
            )
            .is_none());

        let evaluation_index_key =
            paper_raid_finality_evaluation_index_key(signed.commitment.evaluation_id).unwrap();
        view.0
            .get_mut(&evaluation_index_key)
            .unwrap()
            .value_bytes
            .push(b' ');
        assert!(matches!(
            execute_at_finality(&tx, context(&payload, HEPTA_DID, "hepta"), &view),
            Err(RuntimeError::PaperRaidFinalityMirrorMismatch(key))
                if key == evaluation_index_key
        ));
    }

    #[test]
    fn non_hepta_and_unregistered_hepta_authorities_are_rejected() {
        let (view, _, signed, tx) = fixture(10_000_000);
        let payload = tx.canonical_bytes().unwrap();
        assert!(matches!(
            execute_at_finality(&tx, context(&payload, HEPTA_DID, "nakama"), &view,),
            Err(RuntimeError::PaperRaidFinalityRoleMismatch)
        ));

        let unknown_key = SigningKey::from_bytes(&[0x33; 32]);
        let unknown_signed = SignedPaperRaidFinalityCommandV2::sign(
            CHAIN_ID.to_string(),
            signed.command_id,
            "did:trnm:unknown-hepta".to_string(),
            1,
            signed.commitment,
            &unknown_key,
        )
        .unwrap();
        let unknown_tx = CanonicalPaperRaidFinalityTxV2::from_signed_command(
            &unknown_signed,
            1_000_000,
            1_000_000,
        )
        .unwrap();
        let unknown_payload = unknown_tx.canonical_bytes().unwrap();
        assert!(matches!(
            execute_at_finality(
                &unknown_tx,
                context(&unknown_payload, "did:trnm:unknown-hepta", "hepta"),
                &view,
            ),
            Err(RuntimeError::PaperRaidFinalityUnauthorizedAuthority)
        ));
    }

    #[test]
    fn open_appeal_superseded_facts_and_rejected_eligibility_emit_no_mutations() {
        let (view, hepta_key, signed, _) = fixture(10_000_000);
        let before_account = view.account(HEPTA_DID);
        let mut invalid_commitments = Vec::new();

        let mut open_appeal = signed.commitment.clone();
        open_appeal.appeal_status = PaperRaidAppealStatusV2::Open;
        invalid_commitments.push(open_appeal);

        let mut superseded = signed.commitment.clone();
        superseded.evaluation_superseded_by = Some(external_key(
            "hepta.evaluation",
            "evaluation-replacement-001",
        ));
        invalid_commitments.push(superseded);

        let mut rejected_eligibility = signed.commitment.clone();
        rejected_eligibility.evaluation_accepted = false;
        rejected_eligibility.latest_reproduction_accepted = false;
        rejected_eligibility.score_eligible = true;
        invalid_commitments.push(rejected_eligibility);

        for commitment in invalid_commitments {
            let invalid_signed = resign(
                SignedPaperRaidFinalityCommandV2 {
                    commitment,
                    signature: Vec::new(),
                    ..signed.clone()
                },
                &hepta_key,
            );
            let invalid_tx = raw_tx(&invalid_signed);
            let raw_payload = serde_json::to_vec(&invalid_tx).unwrap();
            assert!(matches!(
                execute_at_finality(
                    &invalid_tx,
                    context(&raw_payload, HEPTA_DID, "hepta"),
                    &view,
                ),
                Err(RuntimeError::Protocol(_))
            ));
            assert_eq!(view.account(HEPTA_DID), before_account);
            assert!(view
                .get(&paper_raid_finality_applied_command_key(signed.command_id).unwrap())
                .is_none());
        }
    }

    #[test]
    fn v3_rejected_evaluation_and_accepted_reproduction_remain_independent_final_facts() {
        let (view, hepta_key, signed, _) = fixture_v3(10_000_000);
        let mut commitment = signed.commitment.clone();
        commitment.evaluation_accepted = false;
        commitment.evaluation_score_bps = 0;
        commitment.latest_reproduction_accepted = true;
        commitment.score_eligible = false;
        commitment.ranking_eligible = false;
        commitment.reward_eligible = false;
        commitment.economic_eligible = false;
        let independent_signed = SignedPaperRaidFinalityCommandV3::sign(
            CHAIN_ID.to_string(),
            signed.command_id,
            HEPTA_DID.to_string(),
            signed.nonce,
            commitment.clone(),
            &hepta_key,
        )
        .unwrap();
        let tx = raw_tx_v3(&independent_signed);
        let payload = tx.canonical_bytes().unwrap();
        let receipt = execute_at_finality_v3(&tx, context(&payload, HEPTA_DID, "hepta"), &view)
            .expect("independent rejected-evaluation/reproduced facts must finalize");
        let stored = receipt
            .mutations
            .iter()
            .find(|mutation| mutation.object_type == PAPER_RAID_FINALITY_COMMITMENT_OBJECT_TYPE_V3)
            .expect("finality commitment mutation");
        assert_eq!(
            PaperRaidFinalityCommitmentV3::from_canonical_bytes(&stored.value_bytes).unwrap(),
            commitment
        );
    }

    #[test]
    fn v3_execution_uses_only_v3_events_objects_and_exact_replay_state() {
        let (mut view, _, signed, tx) = fixture_v3(10_000_000);
        let payload = tx.canonical_bytes().unwrap();
        let receipt =
            execute_at_finality_v3(&tx, context(&payload, HEPTA_DID, "hepta"), &view).unwrap();
        assert_eq!(
            receipt.events[0].kind,
            "trnm.paper-raid.finality.applied.v3"
        );
        for expected in [
            PAPER_RAID_FINALITY_COMMITMENT_OBJECT_TYPE_V3,
            PAPER_RAID_FINALITY_APPLIED_COMMAND_OBJECT_TYPE_V3,
            PAPER_RAID_FINALITY_SUBMISSION_INDEX_OBJECT_TYPE_V3,
            PAPER_RAID_FINALITY_EVALUATION_INDEX_OBJECT_TYPE_V3,
        ] {
            assert!(receipt
                .mutations
                .iter()
                .any(|mutation| mutation.object_type == expected));
        }
        assert!(receipt.mutations.iter().all(|mutation| {
            !matches!(
                mutation.object_type.as_str(),
                PAPER_RAID_FINALITY_COMMITMENT_OBJECT_TYPE_V2
                    | PAPER_RAID_FINALITY_APPLIED_COMMAND_OBJECT_TYPE_V2
                    | PAPER_RAID_FINALITY_SUBMISSION_INDEX_OBJECT_TYPE_V2
                    | PAPER_RAID_FINALITY_EVALUATION_INDEX_OBJECT_TYPE_V2
            )
        }));
        view.apply_mutations(receipt.mutations);
        assert!(matches!(
            execute_at_finality_v3(&tx, context(&payload, HEPTA_DID, "hepta"), &view),
            Err(RuntimeError::PaperRaidFinalityCommandReplay)
        ));

        let evaluation_index =
            paper_raid_finality_evaluation_index_key_v3(signed.commitment.evaluation_id).unwrap();
        view.0
            .get_mut(&evaluation_index)
            .unwrap()
            .value_bytes
            .push(b' ');
        assert!(matches!(
            execute_at_finality_v3(
                &tx,
                context(&payload, HEPTA_DID, "hepta"),
                &view
            ),
            Err(RuntimeError::PaperRaidFinalityMirrorMismatch(key)) if key == evaluation_index
        ));
    }

    #[test]
    fn v2_then_v3_overlay_conflicts_precede_bad_nonce_and_zero_balance_without_mutation() {
        let conflicts = [
            CrossVersionConflict::Command,
            CrossVersionConflict::Commitment,
            CrossVersionConflict::Submission,
            CrossVersionConflict::Evaluation,
        ];
        for conflict in conflicts {
            let (mut view, hepta_key, baseline, tx) = fixture(10_000_000);
            let payload = tx.canonical_bytes().unwrap();
            let receipt =
                execute_at_finality(&tx, context(&payload, HEPTA_DID, "hepta"), &view).unwrap();
            view.apply_mutations(receipt.mutations);
            set_account_state(&mut view, 0, 41);
            let before = view.0.clone();

            let (command_id, commitment) = isolated_v3_conflict(&baseline, conflict);
            let signed = SignedPaperRaidFinalityCommandV3::sign(
                CHAIN_ID.to_string(),
                command_id,
                HEPTA_DID.to_string(),
                99,
                commitment,
                &hepta_key,
            )
            .unwrap();
            let tx = raw_tx_v3(&signed);
            let payload = tx.canonical_bytes().unwrap();
            let error = execute_at_finality_v3(&tx, context(&payload, HEPTA_DID, "hepta"), &view)
                .unwrap_err();
            assert_cross_version_conflict(error, conflict);
            assert_eq!(view.0, before);
        }
    }

    #[test]
    fn v3_then_v2_overlay_conflicts_precede_bad_nonce_and_zero_balance_without_mutation() {
        let conflicts = [
            CrossVersionConflict::Command,
            CrossVersionConflict::Commitment,
            CrossVersionConflict::Submission,
            CrossVersionConflict::Evaluation,
        ];
        for conflict in conflicts {
            let (mut view, hepta_key, baseline, tx) = fixture_v3(10_000_000);
            let payload = tx.canonical_bytes().unwrap();
            let receipt =
                execute_at_finality_v3(&tx, context(&payload, HEPTA_DID, "hepta"), &view).unwrap();
            view.apply_mutations(receipt.mutations);
            set_account_state(&mut view, 0, 41);
            let before = view.0.clone();

            let (command_id, commitment) = isolated_v2_conflict(&baseline, conflict);
            let signed = SignedPaperRaidFinalityCommandV2::sign(
                CHAIN_ID.to_string(),
                command_id,
                HEPTA_DID.to_string(),
                99,
                commitment,
                &hepta_key,
            )
            .unwrap();
            let tx = raw_tx(&signed);
            let payload = tx.canonical_bytes().unwrap();
            let error =
                execute_at_finality(&tx, context(&payload, HEPTA_DID, "hepta"), &view).unwrap_err();
            assert_cross_version_conflict(error, conflict);
            assert_eq!(view.0, before);
        }
    }

    #[test]
    fn frozen_v2_same_version_commitment_and_indexes_remain_after_nonce_validation() {
        let (view, hepta_key, signed, tx) = fixture(10_000_000);
        let payload = tx.canonical_bytes().unwrap();
        let receipt =
            execute_at_finality(&tx, context(&payload, HEPTA_DID, "hepta"), &view).unwrap();
        for object_types in [
            vec![PAPER_RAID_FINALITY_COMMITMENT_OBJECT_TYPE_V2],
            vec![
                PAPER_RAID_FINALITY_COMMITMENT_OBJECT_TYPE_V2,
                PAPER_RAID_FINALITY_SUBMISSION_INDEX_OBJECT_TYPE_V2,
            ],
            vec![
                PAPER_RAID_FINALITY_COMMITMENT_OBJECT_TYPE_V2,
                PAPER_RAID_FINALITY_EVALUATION_INDEX_OBJECT_TYPE_V2,
            ],
        ] {
            let mut case_view = view.clone();
            case_view.apply_mutations(
                receipt
                    .mutations
                    .iter()
                    .filter(|mutation| object_types.contains(&mutation.object_type.as_str()))
                    .cloned()
                    .collect(),
            );
            let bad_nonce_signed = SignedPaperRaidFinalityCommandV2::sign(
                CHAIN_ID.to_string(),
                signed.command_id,
                HEPTA_DID.to_string(),
                99,
                signed.commitment.clone(),
                &hepta_key,
            )
            .unwrap();
            let bad_nonce_tx = raw_tx(&bad_nonce_signed);
            let bad_nonce_payload = bad_nonce_tx.canonical_bytes().unwrap();
            assert!(matches!(
                execute_at_finality(
                    &bad_nonce_tx,
                    context(&bad_nonce_payload, HEPTA_DID, "hepta"),
                    &case_view,
                ),
                Err(RuntimeError::NonceMismatch {
                    expected: 1,
                    received: 99,
                })
            ));
        }
    }

    #[test]
    fn candidate_finality_ingress_keeps_all_settlement_eligibility_locked() {
        let (view, hepta_key, signed, _) = fixture(10_000_000);
        let before_account = view.account(HEPTA_DID);
        let flag_sets = [
            (true, false, false, false),
            (true, true, false, false),
            (true, true, true, true),
        ];

        for (score, ranking, reward, economic) in flag_sets {
            let mut commitment = signed.commitment.clone();
            commitment.score_eligible = score;
            commitment.ranking_eligible = ranking;
            commitment.reward_eligible = reward;
            commitment.economic_eligible = economic;
            let eligibility_signed = SignedPaperRaidFinalityCommandV2::sign(
                CHAIN_ID.to_string(),
                signed.command_id,
                HEPTA_DID.to_string(),
                1,
                commitment,
                &hepta_key,
            )
            .unwrap();
            let eligibility_tx = CanonicalPaperRaidFinalityTxV2::from_signed_command(
                &eligibility_signed,
                1_000_000,
                1_000_000,
            )
            .unwrap();
            let payload = eligibility_tx.canonical_bytes().unwrap();
            let error = execute_at_finality(
                &eligibility_tx,
                context(&payload, HEPTA_DID, "hepta"),
                &view,
            )
            .unwrap_err();
            assert_eq!(error.code(), "paper_raid_finality_eligibility_locked");
            assert!(matches!(
                error,
                RuntimeError::PaperRaidFinalityEligibilityLocked
            ));
            assert_eq!(view.account(HEPTA_DID), before_account);
            assert!(view
                .get(
                    &paper_raid_finality_commitment_key(
                        eligibility_signed.commitment.commitment_id,
                    )
                    .unwrap()
                )
                .is_none());
            assert!(view
                .get(&paper_raid_finality_applied_command_key(signed.command_id).unwrap())
                .is_none());
        }
    }

    #[test]
    fn insufficient_balance_does_not_advance_nonce_or_store_finality() {
        let (view, _, signed, tx) = fixture(0);
        let payload = tx.canonical_bytes().unwrap();
        let before = view.account(HEPTA_DID);
        assert!(matches!(
            execute_at_finality(&tx, context(&payload, HEPTA_DID, "hepta"), &view,),
            Err(RuntimeError::InsufficientBalance { .. })
        ));
        assert_eq!(view.account(HEPTA_DID), before);
        assert!(view
            .get(&paper_raid_finality_commitment_key(signed.commitment.commitment_id).unwrap())
            .is_none());
        assert!(view
            .get(&paper_raid_finality_applied_command_key(signed.command_id).unwrap())
            .is_none());
    }

    #[test]
    fn v4_execution_stores_all_mirrors_and_exact_replay_is_idempotent_fail_closed() {
        let (mut view, _, signed, tx) = fixture_v4(10_000_000);
        let payload = tx.canonical_bytes().unwrap();
        let before = view.0.clone();
        let receipt =
            execute_at_finality_v4(&tx, context(&payload, HEPTA_DID, "hepta"), &view).unwrap();
        let lineage = signed.commitment.rework_lineage.as_ref().unwrap();
        assert_eq!(
            receipt.events[0].kind,
            "trnm.paper-raid.finality.applied.v4"
        );
        assert_eq!(
            receipt.events[0].attributes["rework_id"],
            lineage.rework_id.to_hex()
        );
        assert_eq!(receipt.events[0].attributes["rework_cycle"], "2");
        assert_eq!(
            receipt.events[0].attributes["rework_index_object_key_hex"],
            paper_raid_finality_rework_index_key_v4(lineage.rework_id).unwrap()
        );
        assert_eq!(
            receipt.events[0].attributes["replacement_rework_content_commitment_sha256_hex"],
            digest_hex(lineage.replacement_rework_content_commitment_sha256)
        );
        for expected in [
            PAPER_RAID_FINALITY_COMMITMENT_OBJECT_TYPE_V4,
            PAPER_RAID_FINALITY_APPLIED_COMMAND_OBJECT_TYPE_V4,
            PAPER_RAID_FINALITY_SUBMISSION_INDEX_OBJECT_TYPE_V4,
            PAPER_RAID_FINALITY_EVALUATION_INDEX_OBJECT_TYPE_V4,
            PAPER_RAID_FINALITY_REWORK_INDEX_OBJECT_TYPE_V4,
        ] {
            assert!(receipt
                .mutations
                .iter()
                .any(|mutation| mutation.object_type == expected));
        }
        assert_eq!(
            view.0, before,
            "execution planning must not mutate the view"
        );
        view.apply_mutations(receipt.mutations);
        let after = view.0.clone();
        assert!(matches!(
            execute_at_finality_v4(&tx, context(&payload, HEPTA_DID, "hepta"), &view),
            Err(RuntimeError::PaperRaidFinalityCommandReplay)
        ));
        assert_eq!(view.0, after);

        let rework_key = paper_raid_finality_rework_index_key_v4(
            signed.commitment.rework_lineage.as_ref().unwrap().rework_id,
        )
        .unwrap();
        view.0.get_mut(&rework_key).unwrap().value_bytes.push(b' ');
        assert!(matches!(
            execute_at_finality_v4(&tx, context(&payload, HEPTA_DID, "hepta"), &view),
            Err(RuntimeError::PaperRaidFinalityMirrorMismatch(key)) if key == rework_key
        ));
    }

    #[test]
    fn v4_original_submission_never_touches_rework_index_or_event_surface() {
        let (mut view, hepta_key, baseline, _) = fixture_v4(10_000_000);
        let dormant_rework_key = paper_raid_finality_rework_index_key_v4(
            baseline
                .commitment
                .rework_lineage
                .as_ref()
                .unwrap()
                .rework_id,
        )
        .unwrap();
        view.0.insert(
            dormant_rework_key.clone(),
            StateObject {
                object_type: PAPER_RAID_FINALITY_REWORK_INDEX_OBJECT_TYPE_V4.to_string(),
                version: 99,
                value_bytes: vec![0xff],
            },
        );
        let mut original = baseline.commitment;
        original.rework_lineage = None;
        let signed = SignedPaperRaidFinalityCommandV4::sign(
            CHAIN_ID.to_string(),
            external_key("trnm.command", "paper-raid-original-finality"),
            HEPTA_DID.to_string(),
            1,
            original,
            &hepta_key,
        )
        .unwrap();
        let tx = raw_tx_v4(&signed);
        let payload = tx.canonical_bytes().unwrap();
        let receipt =
            execute_at_finality_v4(&tx, context(&payload, HEPTA_DID, "hepta"), &view).unwrap();
        assert_eq!(
            receipt
                .mutations
                .iter()
                .filter(|mutation| mutation
                    .object_type
                    .starts_with("trnm.paper-raid.finality-"))
                .count(),
            4
        );
        assert!(receipt.mutations.iter().all(
            |mutation| mutation.object_type != PAPER_RAID_FINALITY_REWORK_INDEX_OBJECT_TYPE_V4
        ));
        assert!(receipt.events[0]
            .attributes
            .keys()
            .all(|key| !key.contains("rework")
                && !key.starts_with("rejected_")
                && !key.starts_with("replacement_")));
        assert_eq!(view.0[&dormant_rework_key].version, 99);

        view.apply_mutations(receipt.mutations);
        assert!(matches!(
            execute_at_finality_v4(&tx, context(&payload, HEPTA_DID, "hepta"), &view),
            Err(RuntimeError::PaperRaidFinalityCommandReplay)
        ));
        assert_eq!(view.0[&dormant_rework_key].version, 99);
    }

    #[test]
    fn v4_ingress_rejects_complete_v2_and_v3_opposite_mirrors_before_economics() {
        let conflicts = [
            CrossVersionConflict::Command,
            CrossVersionConflict::Commitment,
            CrossVersionConflict::Submission,
            CrossVersionConflict::Evaluation,
        ];
        for conflict in conflicts {
            let (mut view, hepta_key, baseline, tx) = fixture(10_000_000);
            let payload = tx.canonical_bytes().unwrap();
            let receipt =
                execute_at_finality(&tx, context(&payload, HEPTA_DID, "hepta"), &view).unwrap();
            view.apply_mutations(receipt.mutations);
            set_account_state(&mut view, 0, 41);
            let before = view.0.clone();
            let (command_id, commitment) = isolated_v4_conflict(
                baseline.command_id,
                baseline.commitment.commitment_id,
                baseline.commitment.paper_project_id,
                baseline.commitment.submission_id,
                baseline.commitment.evaluation_id,
                baseline.commitment.match_evidence_ref,
                conflict,
            );
            let signed = SignedPaperRaidFinalityCommandV4::sign(
                CHAIN_ID.to_string(),
                command_id,
                HEPTA_DID.to_string(),
                99,
                commitment,
                &hepta_key,
            )
            .unwrap();
            let tx = raw_tx_v4(&signed);
            let payload = tx.canonical_bytes().unwrap();
            let error = execute_at_finality_v4(&tx, context(&payload, HEPTA_DID, "hepta"), &view)
                .unwrap_err();
            assert_cross_version_conflict(error, conflict);
            assert_eq!(view.0, before);

            let (mut view, hepta_key, baseline, tx) = fixture_v3(10_000_000);
            let payload = tx.canonical_bytes().unwrap();
            let receipt =
                execute_at_finality_v3(&tx, context(&payload, HEPTA_DID, "hepta"), &view).unwrap();
            view.apply_mutations(receipt.mutations);
            set_account_state(&mut view, 0, 41);
            let before = view.0.clone();
            let (command_id, commitment) = isolated_v4_conflict(
                baseline.command_id,
                baseline.commitment.commitment_id,
                baseline.commitment.paper_project_id,
                baseline.commitment.submission_id,
                baseline.commitment.evaluation_id,
                baseline.commitment.match_evidence_ref,
                conflict,
            );
            let signed = SignedPaperRaidFinalityCommandV4::sign(
                CHAIN_ID.to_string(),
                command_id,
                HEPTA_DID.to_string(),
                99,
                commitment,
                &hepta_key,
            )
            .unwrap();
            let tx = raw_tx_v4(&signed);
            let payload = tx.canonical_bytes().unwrap();
            let error = execute_at_finality_v4(&tx, context(&payload, HEPTA_DID, "hepta"), &view)
                .unwrap_err();
            assert_cross_version_conflict(error, conflict);
            assert_eq!(view.0, before);
        }
    }

    #[test]
    fn legacy_runtime_helpers_reject_complete_v4_opposite_mirrors_before_economics() {
        let conflicts = [
            CrossVersionConflict::Command,
            CrossVersionConflict::Commitment,
            CrossVersionConflict::Submission,
            CrossVersionConflict::Evaluation,
        ];
        for conflict in conflicts {
            let (mut view, hepta_key, baseline, tx) = fixture_v4(10_000_000);
            let payload = tx.canonical_bytes().unwrap();
            let receipt =
                execute_at_finality_v4(&tx, context(&payload, HEPTA_DID, "hepta"), &view).unwrap();
            view.apply_mutations(receipt.mutations);
            set_account_state(&mut view, 0, 41);
            let before = view.0.clone();

            let (command_id, commitment) = isolated_v2_conflict_from_v4(&baseline, conflict);
            let signed = SignedPaperRaidFinalityCommandV2::sign(
                CHAIN_ID.to_string(),
                command_id,
                HEPTA_DID.to_string(),
                99,
                commitment,
                &hepta_key,
            )
            .unwrap();
            let tx = raw_tx(&signed);
            let payload = tx.canonical_bytes().unwrap();
            let error =
                execute_at_finality(&tx, context(&payload, HEPTA_DID, "hepta"), &view).unwrap_err();
            assert_cross_version_conflict(error, conflict);
            assert_eq!(view.0, before);

            let (command_id, commitment) = isolated_v3_conflict_from_v4(&baseline, conflict);
            let signed = SignedPaperRaidFinalityCommandV3::sign(
                CHAIN_ID.to_string(),
                command_id,
                HEPTA_DID.to_string(),
                99,
                commitment,
                &hepta_key,
            )
            .unwrap();
            let tx = raw_tx_v3(&signed);
            let payload = tx.canonical_bytes().unwrap();
            let error = execute_at_finality_v3(&tx, context(&payload, HEPTA_DID, "hepta"), &view)
                .unwrap_err();
            assert_cross_version_conflict(error, conflict);
            assert_eq!(view.0, before);
        }
    }

    #[test]
    fn cross_version_collisions_validate_every_opposite_mirror_before_terminal_errors() {
        // A V4 command-ID collision cannot hide a missing V4 rework mirror
        // behind the ordinary cross-version replay result.
        let (mut view, hepta_key, baseline, tx) = fixture_v4(10_000_000);
        let payload = tx.canonical_bytes().unwrap();
        let receipt =
            execute_at_finality_v4(&tx, context(&payload, HEPTA_DID, "hepta"), &view).unwrap();
        view.apply_mutations(receipt.mutations);
        let missing_rework_key = paper_raid_finality_rework_index_key_v4(
            baseline
                .commitment
                .rework_lineage
                .as_ref()
                .unwrap()
                .rework_id,
        )
        .unwrap();
        view.0.remove(&missing_rework_key).unwrap();
        // The V3 opposite is complete and scanned first. Its ordinary replay
        // terminal must be deferred so the later damaged V4 sibling is still
        // discovered.
        let (v3_command_id, v3_commitment) =
            isolated_v3_conflict_from_v4(&baseline, CrossVersionConflict::Command);
        let valid_first_opposite = SignedPaperRaidFinalityCommandV3::sign(
            CHAIN_ID.to_string(),
            v3_command_id,
            HEPTA_DID.to_string(),
            77,
            v3_commitment,
            &hepta_key,
        )
        .unwrap();
        insert_v3_finality_mirrors(&mut view, &valid_first_opposite);
        let (command_id, commitment) =
            isolated_v2_conflict_from_v4(&baseline, CrossVersionConflict::Command);
        let signed = SignedPaperRaidFinalityCommandV2::sign(
            CHAIN_ID.to_string(),
            command_id,
            HEPTA_DID.to_string(),
            99,
            commitment,
            &hepta_key,
        )
        .unwrap();
        let incoming = raw_tx(&signed);
        let incoming_payload = incoming.canonical_bytes().unwrap();
        assert!(matches!(
            execute_at_finality(
                &incoming,
                context(&incoming_payload, HEPTA_DID, "hepta"),
                &view,
            ),
            Err(RuntimeError::PaperRaidFinalityMirrorMismatch(key)) if key == missing_rework_key
        ));

        // A V3 commitment-ID collision likewise validates both V3 identity
        // mirrors before reporting that the commitment already exists.
        let (mut view, hepta_key, baseline, tx) = fixture_v3(10_000_000);
        let payload = tx.canonical_bytes().unwrap();
        let receipt =
            execute_at_finality_v3(&tx, context(&payload, HEPTA_DID, "hepta"), &view).unwrap();
        view.apply_mutations(receipt.mutations);
        let missing_evaluation_key =
            paper_raid_finality_evaluation_index_key_v3(baseline.commitment.evaluation_id).unwrap();
        view.0.remove(&missing_evaluation_key).unwrap();
        let (command_id, commitment) = isolated_v4_conflict(
            baseline.command_id,
            baseline.commitment.commitment_id,
            baseline.commitment.paper_project_id,
            baseline.commitment.submission_id,
            baseline.commitment.evaluation_id,
            baseline.commitment.match_evidence_ref,
            CrossVersionConflict::Commitment,
        );
        let signed = SignedPaperRaidFinalityCommandV4::sign(
            CHAIN_ID.to_string(),
            command_id,
            HEPTA_DID.to_string(),
            99,
            commitment,
            &hepta_key,
        )
        .unwrap();
        let incoming = raw_tx_v4(&signed);
        let incoming_payload = incoming.canonical_bytes().unwrap();
        assert!(matches!(
            execute_at_finality_v4(
                &incoming,
                context(&incoming_payload, HEPTA_DID, "hepta"),
                &view,
            ),
            Err(RuntimeError::PaperRaidFinalityMirrorMismatch(key))
                if key == missing_evaluation_key
        ));

        // A V2 submission-index collision validates the companion evaluation
        // mirror before returning SubmissionExists.
        let (mut view, hepta_key, baseline, tx) = fixture(10_000_000);
        let payload = tx.canonical_bytes().unwrap();
        let receipt =
            execute_at_finality(&tx, context(&payload, HEPTA_DID, "hepta"), &view).unwrap();
        view.apply_mutations(receipt.mutations);
        let missing_evaluation_key =
            paper_raid_finality_evaluation_index_key(baseline.commitment.evaluation_id).unwrap();
        view.0.remove(&missing_evaluation_key).unwrap();
        let mut commitment = valid_commitment_v3(baseline.commitment.match_evidence_ref);
        commitment.commitment_id =
            external_key("hepta.paper-raid.finality", "v3-submission-only-conflict");
        commitment.paper_project_id = baseline.commitment.paper_project_id;
        commitment.submission_id = baseline.commitment.submission_id;
        commitment.evaluation_id = external_key("hepta.evaluation", "v3-submission-only-conflict");
        let signed = SignedPaperRaidFinalityCommandV3::sign(
            CHAIN_ID.to_string(),
            external_key("trnm.command", "v3-submission-only-conflict"),
            HEPTA_DID.to_string(),
            99,
            commitment,
            &hepta_key,
        )
        .unwrap();
        let incoming = raw_tx_v3(&signed);
        let incoming_payload = incoming.canonical_bytes().unwrap();
        assert!(matches!(
            execute_at_finality_v3(
                &incoming,
                context(&incoming_payload, HEPTA_DID, "hepta"),
                &view,
            ),
            Err(RuntimeError::PaperRaidFinalityMirrorMismatch(key))
                if key == missing_evaluation_key
        ));
    }

    #[test]
    fn damaged_v4_sibling_mirror_precedes_altered_replay_and_commitment_exists() {
        let (mut view, hepta_key, baseline, tx) = fixture_v4(10_000_000);
        let payload = tx.canonical_bytes().unwrap();
        let receipt =
            execute_at_finality_v4(&tx, context(&payload, HEPTA_DID, "hepta"), &view).unwrap();
        view.apply_mutations(receipt.mutations);
        let missing_rework_key = paper_raid_finality_rework_index_key_v4(
            baseline
                .commitment
                .rework_lineage
                .as_ref()
                .unwrap()
                .rework_id,
        )
        .unwrap();
        view.0.remove(&missing_rework_key).unwrap();

        let altered = SignedPaperRaidFinalityCommandV4::sign(
            CHAIN_ID.to_string(),
            baseline.command_id,
            HEPTA_DID.to_string(),
            2,
            baseline.commitment.clone(),
            &hepta_key,
        )
        .unwrap();
        let altered_tx = raw_tx_v4(&altered);
        let altered_payload = altered_tx.canonical_bytes().unwrap();
        assert!(matches!(
            execute_at_finality_v4(
                &altered_tx,
                context(&altered_payload, HEPTA_DID, "hepta"),
                &view,
            ),
            Err(RuntimeError::PaperRaidFinalityMirrorMismatch(key)) if key == missing_rework_key
        ));

        let (command_id, commitment) = isolated_v4_conflict(
            baseline.command_id,
            baseline.commitment.commitment_id,
            baseline.commitment.paper_project_id,
            baseline.commitment.submission_id,
            baseline.commitment.evaluation_id,
            baseline.commitment.match_evidence_ref,
            CrossVersionConflict::Commitment,
        );
        let conflicting = SignedPaperRaidFinalityCommandV4::sign(
            CHAIN_ID.to_string(),
            command_id,
            HEPTA_DID.to_string(),
            2,
            commitment,
            &hepta_key,
        )
        .unwrap();
        let conflicting_tx = raw_tx_v4(&conflicting);
        let conflicting_payload = conflicting_tx.canonical_bytes().unwrap();
        assert!(matches!(
            execute_at_finality_v4(
                &conflicting_tx,
                context(&conflicting_payload, HEPTA_DID, "hepta"),
                &view,
            ),
            Err(RuntimeError::PaperRaidFinalityMirrorMismatch(key)) if key == missing_rework_key
        ));
    }

    #[test]
    fn same_version_collisions_scan_later_independent_mirrors_before_exists() {
        for (conflict, damaged_kind) in [
            (
                CrossVersionConflict::Submission,
                PaperRaidFinalityIndexKindV2::Evaluation,
            ),
            (
                CrossVersionConflict::Commitment,
                PaperRaidFinalityIndexKindV2::Submission,
            ),
        ] {
            let (mut view, hepta_key, baseline, tx) = fixture_v4(10_000_000);
            let payload = tx.canonical_bytes().unwrap();
            let receipt =
                execute_at_finality_v4(&tx, context(&payload, HEPTA_DID, "hepta"), &view).unwrap();
            view.apply_mutations(receipt.mutations);
            let (command_id, commitment) = isolated_v4_conflict(
                baseline.command_id,
                baseline.commitment.commitment_id,
                baseline.commitment.paper_project_id,
                baseline.commitment.submission_id,
                baseline.commitment.evaluation_id,
                baseline.commitment.match_evidence_ref,
                conflict,
            );
            let damaged_key = match damaged_kind {
                PaperRaidFinalityIndexKindV2::Submission => {
                    paper_raid_finality_submission_index_key_v4(
                        commitment.paper_project_id,
                        commitment.submission_id,
                    )
                    .unwrap()
                }
                PaperRaidFinalityIndexKindV2::Evaluation => {
                    paper_raid_finality_evaluation_index_key_v4(commitment.evaluation_id).unwrap()
                }
            };
            view.0.insert(
                damaged_key.clone(),
                StateObject {
                    object_type: paper_raid_index_object_type_v4(damaged_kind).to_string(),
                    version: 99,
                    value_bytes: vec![0xff],
                },
            );
            let signed = SignedPaperRaidFinalityCommandV4::sign(
                CHAIN_ID.to_string(),
                command_id,
                HEPTA_DID.to_string(),
                2,
                commitment,
                &hepta_key,
            )
            .unwrap();
            let incoming = raw_tx_v4(&signed);
            let incoming_payload = incoming.canonical_bytes().unwrap();
            assert!(matches!(
                execute_at_finality_v4(
                    &incoming,
                    context(&incoming_payload, HEPTA_DID, "hepta"),
                    &view,
                ),
                Err(RuntimeError::PaperRaidFinalityMirrorMismatch(key)) if key == damaged_key
            ));
        }
    }

    #[test]
    fn v4_rework_id_is_globally_unique_across_distinct_finalities() {
        let (mut view, hepta_key, baseline, tx) = fixture_v4(10_000_000);
        let payload = tx.canonical_bytes().unwrap();
        let receipt =
            execute_at_finality_v4(&tx, context(&payload, HEPTA_DID, "hepta"), &view).unwrap();
        view.apply_mutations(receipt.mutations);
        let after = view.0.clone();

        let mut conflict = baseline.commitment.clone();
        conflict.commitment_id = external_key("hepta.paper-raid.finality", "finality-rework-002");
        conflict.paper_project_id = external_key("hepta.paper", "paper-rework-002");
        conflict.submission_id = external_key("hepta.submission", "submission-rework-002");
        conflict.evaluation_id = external_key("hepta.evaluation", "evaluation-rework-002");
        conflict
            .rework_lineage
            .as_mut()
            .unwrap()
            .replacement_submission_id = conflict.submission_id;
        // The globally unique rework_id intentionally remains unchanged.
        let conflict_signed = SignedPaperRaidFinalityCommandV4::sign(
            CHAIN_ID.to_string(),
            external_key("trnm.command", "paper-raid-finality-rework-002"),
            HEPTA_DID.to_string(),
            2,
            conflict,
            &hepta_key,
        )
        .unwrap();
        let conflict_tx = CanonicalPaperRaidFinalityTxV4::from_signed_command(
            &conflict_signed,
            1_000_000,
            1_000_000,
        )
        .unwrap();
        let conflict_payload = conflict_tx.canonical_bytes().unwrap();
        assert!(matches!(
            execute_at_finality_v4(
                &conflict_tx,
                context(&conflict_payload, HEPTA_DID, "hepta"),
                &view,
            ),
            Err(RuntimeError::PaperRaidFinalityReworkExists)
        ));
        assert_eq!(view.0, after);
        assert!(view
            .get(
                &paper_raid_finality_commitment_key_v4(conflict_signed.commitment.commitment_id)
                    .unwrap()
            )
            .is_none());
        assert!(view
            .get(&paper_raid_finality_applied_command_key_v4(conflict_signed.command_id).unwrap())
            .is_none());
    }

    #[test]
    fn v4_malformed_existing_rework_mirror_precedes_rework_conflict() {
        let (mut view, hepta_key, baseline, tx) = fixture_v4(10_000_000);
        let payload = tx.canonical_bytes().unwrap();
        let receipt =
            execute_at_finality_v4(&tx, context(&payload, HEPTA_DID, "hepta"), &view).unwrap();
        view.apply_mutations(receipt.mutations);
        let rework_key = paper_raid_finality_rework_index_key_v4(
            baseline
                .commitment
                .rework_lineage
                .as_ref()
                .unwrap()
                .rework_id,
        )
        .unwrap();
        view.0.get_mut(&rework_key).unwrap().version = 2;
        let before = view.0.clone();

        let mut conflict = baseline.commitment;
        conflict.commitment_id = external_key("hepta.paper-raid.finality", "finality-rework-bad");
        conflict.submission_id = external_key("hepta.submission", "submission-rework-bad");
        conflict.evaluation_id = external_key("hepta.evaluation", "evaluation-rework-bad");
        conflict
            .rework_lineage
            .as_mut()
            .unwrap()
            .replacement_submission_id = conflict.submission_id;
        let signed = SignedPaperRaidFinalityCommandV4::sign(
            CHAIN_ID.to_string(),
            external_key("trnm.command", "paper-raid-finality-rework-bad"),
            HEPTA_DID.to_string(),
            2,
            conflict,
            &hepta_key,
        )
        .unwrap();
        let tx = raw_tx_v4(&signed);
        let payload = tx.canonical_bytes().unwrap();
        assert!(matches!(
            execute_at_finality_v4(&tx, context(&payload, HEPTA_DID, "hepta"), &view),
            Err(RuntimeError::PaperRaidFinalityMirrorMismatch(key)) if key == rework_key
        ));
        assert_eq!(view.0, before);
    }

    #[test]
    fn conservative_account_write_meter_covers_maximum_protocol_account() {
        let maximum_signer = format!("did:{}", "a".repeat(188));
        let maximum_escaped_signer = format!("did:{}", "\\".repeat(188));
        assert_eq!(maximum_signer.len(), 192);
        assert_eq!(maximum_escaped_signer.len(), 192);
        for account in [
            maximum_signer,
            maximum_escaped_signer,
            FEE_COLLECTOR_ACCOUNT_V1.to_string(),
        ] {
            let value_bytes = serde_json::to_vec(&AccountV1 {
                account: account.clone(),
                balance: u128::MAX,
                nonce: u64::MAX,
            })
            .unwrap();
            let metered =
                metered_object_bytes(&account_key(&account), ACCOUNT_OBJECT_TYPE_V1, &value_bytes)
                    .unwrap();
            assert!(metered <= MAX_ACCOUNT_MUTATION_METER_BYTES);
        }
    }

    #[test]
    fn paper_raid_finality_object_keys_are_stable_and_domain_separated() {
        let key = ExternalKey::from_bytes([1; 32]);
        let v2_commitment = paper_raid_finality_commitment_key(key).unwrap();
        let v2_applied = paper_raid_finality_applied_command_key(key).unwrap();
        let v2_submission = paper_raid_finality_submission_index_key(key, key).unwrap();
        let v2_evaluation = paper_raid_finality_evaluation_index_key(key).unwrap();
        assert_eq!(
            v2_commitment,
            "65df7e72b34c74bdeb173fe44e3626ca9956514453567cd2173d16dfad7affd7"
        );
        assert_eq!(
            v2_applied,
            "693163b6f4062b004999a5855675bf6b1688d15ca8309bca073fb064a87b1014"
        );
        assert_eq!(
            v2_submission,
            "b489b346e8be3de67fc758534e35ab6a8e7f49ed6fb0e8479d603680bcf260bd"
        );
        assert_eq!(
            v2_evaluation,
            "7e68f559f81810bfdc136061fa4dd38cb93547b216a55b107583c71c5047bf26"
        );
        let v3_commitment = paper_raid_finality_commitment_key_v3(key).unwrap();
        let v3_applied = paper_raid_finality_applied_command_key_v3(key).unwrap();
        let v3_submission = paper_raid_finality_submission_index_key_v3(key, key).unwrap();
        let v3_evaluation = paper_raid_finality_evaluation_index_key_v3(key).unwrap();
        for (v2, v3) in [
            (&v2_commitment, &v3_commitment),
            (&v2_applied, &v3_applied),
            (&v2_submission, &v3_submission),
            (&v2_evaluation, &v3_evaluation),
        ] {
            assert_ne!(v2, v3);
        }
        let v4_commitment = paper_raid_finality_commitment_key_v4(key).unwrap();
        let v4_applied = paper_raid_finality_applied_command_key_v4(key).unwrap();
        let v4_submission = paper_raid_finality_submission_index_key_v4(key, key).unwrap();
        let v4_evaluation = paper_raid_finality_evaluation_index_key_v4(key).unwrap();
        let v4_rework = paper_raid_finality_rework_index_key_v4(key).unwrap();
        let mut all = std::collections::BTreeSet::new();
        for derived in [
            v2_commitment,
            v2_applied,
            v2_submission,
            v2_evaluation,
            v3_commitment,
            v3_applied,
            v3_submission,
            v3_evaluation,
            v4_commitment,
            v4_applied,
            v4_submission,
            v4_evaluation,
            v4_rework,
        ] {
            assert!(all.insert(derived));
        }
        assert!(paper_raid_finality_commitment_key(ExternalKey::from_bytes([0; 32])).is_err());
        assert!(paper_raid_finality_applied_command_key(ExternalKey::from_bytes([0; 32])).is_err());
        assert!(
            paper_raid_finality_submission_index_key(ExternalKey::from_bytes([0; 32]), key,)
                .is_err()
        );
        assert!(
            paper_raid_finality_evaluation_index_key(ExternalKey::from_bytes([0; 32])).is_err()
        );
        assert!(paper_raid_finality_commitment_key_v4(ExternalKey::from_bytes([0; 32])).is_err());
        assert!(
            paper_raid_finality_applied_command_key_v4(ExternalKey::from_bytes([0; 32])).is_err()
        );
        assert!(paper_raid_finality_rework_index_key_v4(ExternalKey::from_bytes([0; 32])).is_err());
    }
}
