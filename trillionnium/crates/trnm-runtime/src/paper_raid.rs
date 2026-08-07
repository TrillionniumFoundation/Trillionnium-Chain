use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use trnm_protocol::{
    account_key, fee_policy_key, research_domain_object_key, AccountV1,
    CanonicalPaperRaidFinalityTxV2, FeePolicyV1, ACCOUNT_OBJECT_TYPE_V1, FEE_COLLECTOR_ACCOUNT_V1,
    FEE_POLICY_OBJECT_TYPE_V1, RESEARCH_DOMAIN_OBJECT_TYPE_V1,
};
use trnm_research_protocol::{
    canonical_hash, AuthorityRole, CanonicalCbor, ExternalKey, ObjectRefV1,
    PaperRaidFinalityCommitmentV2, ResearchDomainObjectV1, ResearchObjectKind,
    SignedPaperRaidFinalityCommandV2,
};

use super::research::load_research_authorities_for_extension;
use super::{
    ensure_type, ExecutionContext, ResourceEstimate, RuntimeError, RuntimeEvent, RuntimeMutation,
    RuntimeReceipt, RuntimeState, StateObject, StateView,
};

pub const PAPER_RAID_FINALITY_COMMITMENT_OBJECT_TYPE_V2: &str =
    "trnm.paper-raid.finality-commitment.v2";
pub const PAPER_RAID_FINALITY_APPLIED_COMMAND_OBJECT_TYPE_V2: &str =
    "trnm.paper-raid.finality-applied-command.v2";
pub const PAPER_RAID_FINALITY_SUBMISSION_INDEX_OBJECT_TYPE_V2: &str =
    "trnm.paper-raid.finality-submission-index.v2";
pub const PAPER_RAID_FINALITY_EVALUATION_INDEX_OBJECT_TYPE_V2: &str =
    "trnm.paper-raid.finality-evaluation-index.v2";

const PAPER_RAID_FINALITY_APPLIED_RECORD_SCHEMA_V2: &str =
    "trnm_paper_raid_finality_applied_record_v2";
const PAPER_RAID_FINALITY_OPERATION_GAS: u64 = 8_000;
const PAPER_RAID_FINALITY_OBJECT_TOUCH_GAS: u64 = 750;
const MAX_PAPER_RAID_FINALITY_COMMITMENT_BYTES: usize = 128 * 1024;
const MAX_PAPER_RAID_FINALITY_APPLIED_RECORD_BYTES: usize = 8 * 1024;
const MAX_PAPER_RAID_FINALITY_INDEX_RECORD_BYTES: usize = 8 * 1024;
const MAX_MATCH_EVIDENCE_OBJECT_BYTES: usize = 1024 * 1024;
// Account JSON size depends on the fee itself. Charging this proven upper bound
// for both sender and collector writes avoids a gas/serialized-size fixed-point
// while remaining conservative for the protocol's 192-byte signer limit.
const MAX_ACCOUNT_MUTATION_METER_BYTES: u64 = 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PaperRaidFinalityAppliedRecordV2 {
    schema: String,
    command_id: String,
    command_fingerprint_hex: String,
    commitment_id: String,
    commitment_object_key_hex: String,
    payload_hash_hex: String,
}

impl PaperRaidFinalityAppliedRecordV2 {
    fn from_signed(
        signed: &SignedPaperRaidFinalityCommandV2,
        commitment_object_key_hex: String,
    ) -> Self {
        Self {
            schema: PAPER_RAID_FINALITY_APPLIED_RECORD_SCHEMA_V2.to_string(),
            command_id: signed.command_id.to_hex(),
            command_fingerprint_hex: digest_hex(signed.command_fingerprint()),
            commitment_id: signed.commitment.commitment_id.to_hex(),
            commitment_object_key_hex,
            payload_hash_hex: digest_hex(signed.payload_hash()),
        }
    }

    fn canonical_bytes(&self) -> Result<Vec<u8>, RuntimeError> {
        self.validate()?;
        let bytes = serde_json::to_vec(self)
            .map_err(|error| RuntimeError::EncodeObject(error.to_string()))?;
        if bytes.len() > MAX_PAPER_RAID_FINALITY_APPLIED_RECORD_BYTES {
            return Err(RuntimeError::PaperRaidFinalityState(
                "Paper Raid finality applied record exceeds the runtime byte limit".to_string(),
            ));
        }
        Ok(bytes)
    }

    fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, RuntimeError> {
        if bytes.is_empty() || bytes.len() > MAX_PAPER_RAID_FINALITY_APPLIED_RECORD_BYTES {
            return Err(RuntimeError::PaperRaidFinalityState(
                "Paper Raid finality applied record is outside the runtime byte limit".to_string(),
            ));
        }
        let record: Self = serde_json::from_slice(bytes).map_err(|error| {
            RuntimeError::PaperRaidFinalityState(format!(
                "decode Paper Raid finality applied record: {error}"
            ))
        })?;
        record.validate()?;
        let canonical = serde_json::to_vec(&record)
            .map_err(|error| RuntimeError::EncodeObject(error.to_string()))?;
        if canonical != bytes {
            return Err(RuntimeError::PaperRaidFinalityState(
                "Paper Raid finality applied record is not canonical".to_string(),
            ));
        }
        Ok(record)
    }

    fn validate(&self) -> Result<(), RuntimeError> {
        if self.schema != PAPER_RAID_FINALITY_APPLIED_RECORD_SCHEMA_V2
            || !is_hash_hex(&self.command_id)
            || !is_hash_hex(&self.command_fingerprint_hex)
            || !is_hash_hex(&self.commitment_id)
            || !is_hash_hex(&self.commitment_object_key_hex)
            || !is_hash_hex(&self.payload_hash_hex)
        {
            return Err(RuntimeError::PaperRaidFinalityState(
                "Paper Raid finality applied record is invalid".to_string(),
            ));
        }
        Ok(())
    }
}

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

/// Stable authenticated-state key for one immutable Paper Raid V2 finality
/// commitment. It is domain-separated from every frozen Research V1 object.
pub fn paper_raid_finality_commitment_key(
    commitment_id: ExternalKey,
) -> Result<String, RuntimeError> {
    paper_raid_key(
        "trnm.paper-raid.finality-commitment.object-key.v2",
        "commitment_id",
        commitment_id,
    )
}

/// Stable authenticated-state key for the exact-replay record of one Paper
/// Raid V2 finality command.
pub fn paper_raid_finality_applied_command_key(
    command_id: ExternalKey,
) -> Result<String, RuntimeError> {
    paper_raid_key(
        "trnm.paper-raid.finality-applied-command.object-key.v2",
        "command_id",
        command_id,
    )
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

/// Execute the independent Paper Raid V2 scientific-finality ingress without
/// changing the frozen generic Research V1 command or snapshot layouts.
pub fn execute_paper_raid_finality(
    tx: &CanonicalPaperRaidFinalityTxV2,
    context: ExecutionContext<'_>,
    block_time_unix_s: u64,
    view: &dyn StateView,
) -> Result<RuntimeReceipt, RuntimeError> {
    let signed = validate_transaction_context(tx, context)?;
    for required_unix_s in [
        signed.commitment.appeal_window_closes_at_unix_s,
        signed.commitment.finalized_at_unix_s,
    ] {
        if block_time_unix_s < required_unix_s {
            return Err(RuntimeError::PaperRaidFinalityTimeNotReached {
                block_time_unix_s,
                required_unix_s,
            });
        }
    }
    if signed.commitment.score_eligible
        || signed.commitment.ranking_eligible
        || signed.commitment.reward_eligible
        || signed.commitment.economic_eligible
    {
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
            (&identity.signer_did, identity.public_key)
                .cmp(&(&signed.signer_did, signed.public_key))
        })
        .is_ok();
    if !authorized {
        return Err(RuntimeError::PaperRaidFinalityUnauthorizedAuthority);
    }
    reject_applied_replay(view, &signed)?;

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
        &account_key(&tx.sender),
        ACCOUNT_OBJECT_TYPE_V1,
        &serde_json::to_vec(&AccountV1 {
            account: tx.sender.clone(),
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
    if tx.nonce != expected_nonce {
        return Err(RuntimeError::NonceMismatch {
            expected: expected_nonce,
            received: tx.nonce,
        });
    }
    if available_balance < lower_bound.fee_estimate {
        return Err(RuntimeError::InsufficientBalance {
            account: tx.sender.clone(),
            required: lower_bound.fee_estimate,
            available: available_balance,
        });
    }

    let commitment_key = paper_raid_finality_commitment_key(signed.commitment.commitment_id)?;
    ensure_new_commitment_absent(view, &signed.commitment, &commitment_key)?;
    let submission_index_key = paper_raid_finality_submission_index_key(
        signed.commitment.paper_project_id,
        signed.commitment.submission_id,
    )?;
    ensure_new_index_absent(
        view,
        PaperRaidFinalityIndexKindV2::Submission,
        &submission_index_key,
    )?;
    let evaluation_index_key =
        paper_raid_finality_evaluation_index_key(signed.commitment.evaluation_id)?;
    ensure_new_index_absent(
        view,
        PaperRaidFinalityIndexKindV2::Evaluation,
        &evaluation_index_key,
    )?;
    let match_evidence_bytes =
        validate_match_evidence_ref(view, signed.commitment.match_evidence_ref)?;
    let commitment_bytes = signed.commitment.canonical_bytes();
    if commitment_bytes.len() > MAX_PAPER_RAID_FINALITY_COMMITMENT_BYTES {
        return Err(RuntimeError::PaperRaidFinalityState(
            "Paper Raid finality commitment exceeds the runtime byte limit".to_string(),
        ));
    }
    let applied_key = paper_raid_finality_applied_command_key(signed.command_id)?;
    let applied_record =
        PaperRaidFinalityAppliedRecordV2::from_signed(&signed, commitment_key.clone());
    let applied_record_bytes = applied_record.canonical_bytes()?;
    let submission_index_record = PaperRaidFinalityIndexRecordV2::from_signed(
        &signed,
        PaperRaidFinalityIndexKindV2::Submission,
        commitment_key.clone(),
    );
    let submission_index_record_bytes = submission_index_record.canonical_bytes()?;
    let evaluation_index_record = PaperRaidFinalityIndexRecordV2::from_signed(
        &signed,
        PaperRaidFinalityIndexKindV2::Evaluation,
        commitment_key.clone(),
    );
    let evaluation_index_record_bytes = evaluation_index_record.canonical_bytes()?;
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
        PAPER_RAID_FINALITY_COMMITMENT_OBJECT_TYPE_V2,
        &commitment_bytes,
    )?;
    let applied_write_bytes = metered_object_bytes(
        &applied_key,
        PAPER_RAID_FINALITY_APPLIED_COMMAND_OBJECT_TYPE_V2,
        &applied_record_bytes,
    )?;
    let submission_index_write_bytes = metered_object_bytes(
        &submission_index_key,
        PAPER_RAID_FINALITY_SUBMISSION_INDEX_OBJECT_TYPE_V2,
        &submission_index_record_bytes,
    )?;
    let evaluation_index_write_bytes = metered_object_bytes(
        &evaluation_index_key,
        PAPER_RAID_FINALITY_EVALUATION_INDEX_OBJECT_TYPE_V2,
        &evaluation_index_record_bytes,
    )?;
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
        .and_then(|bytes| bytes.checked_add(account_write_bytes))
        .ok_or(RuntimeError::ArithmeticOverflow)?;
    // Unique keys: legacy sentinel, authority, fee policy, sender, collector,
    // applied record, commitment, submission/evaluation indexes, and referenced
    // MatchEvidence.
    let touched_keys = authority_touched_keys
        .checked_add(8)
        .ok_or(RuntimeError::ArithmeticOverflow)?;
    let estimate = estimate_resources(context, &policy, state_bytes, touched_keys)?;
    enforce_limits(tx, estimate)?;
    if available_balance < estimate.fee_estimate {
        return Err(RuntimeError::InsufficientBalance {
            account: tx.sender.clone(),
            required: estimate.fee_estimate,
            available: available_balance,
        });
    }

    economic_state.debit(&tx.sender, estimate.fee_estimate)?;
    economic_state.credit(FEE_COLLECTOR_ACCOUNT_V1, estimate.fee_estimate)?;
    let sender = economic_state.account(&tx.sender)?;
    sender.value.nonce = tx.nonce;
    sender.dirty = true;

    let mut mutations = economic_state.into_mutations()?;
    mutations.push(RuntimeMutation {
        object_key_hex: commitment_key.clone(),
        object_type: PAPER_RAID_FINALITY_COMMITMENT_OBJECT_TYPE_V2.to_string(),
        expected_version: None,
        next_version: 1,
        value_bytes: commitment_bytes,
    });
    mutations.push(RuntimeMutation {
        object_key_hex: applied_key.clone(),
        object_type: PAPER_RAID_FINALITY_APPLIED_COMMAND_OBJECT_TYPE_V2.to_string(),
        expected_version: None,
        next_version: 1,
        value_bytes: applied_record_bytes,
    });
    mutations.push(RuntimeMutation {
        object_key_hex: submission_index_key,
        object_type: PAPER_RAID_FINALITY_SUBMISSION_INDEX_OBJECT_TYPE_V2.to_string(),
        expected_version: None,
        next_version: 1,
        value_bytes: submission_index_record_bytes,
    });
    mutations.push(RuntimeMutation {
        object_key_hex: evaluation_index_key,
        object_type: PAPER_RAID_FINALITY_EVALUATION_INDEX_OBJECT_TYPE_V2.to_string(),
        expected_version: None,
        next_version: 1,
        value_bytes: evaluation_index_record_bytes,
    });
    mutations.sort_by(|left, right| left.object_key_hex.cmp(&right.object_key_hex));
    validate_mutations(&mutations)?;

    Ok(RuntimeReceipt {
        gas_used: estimate.gas_used,
        fee_charged: estimate.fee_estimate,
        events: vec![paper_raid_event(&signed, &commitment_key, &applied_key)],
        mutations,
    })
}

fn validate_transaction_context(
    tx: &CanonicalPaperRaidFinalityTxV2,
    context: ExecutionContext<'_>,
) -> Result<SignedPaperRaidFinalityCommandV2, RuntimeError> {
    tx.validate()
        .map_err(|error| RuntimeError::Protocol(error.to_string()))?;
    if tx.sender != context.signer_id {
        return Err(RuntimeError::SenderMismatch);
    }
    if tx.sender == FEE_COLLECTOR_ACCOUNT_V1 {
        return Err(RuntimeError::ReservedSystemAccount);
    }
    let signed = tx
        .signed_paper_raid_finality_command()
        .map_err(|error| RuntimeError::Protocol(error.to_string()))?;
    if signed.chain_id != context.chain_id {
        return Err(RuntimeError::PaperRaidFinalityChainMismatch);
    }
    if signed.signer_role != AuthorityRole::HeptaAuthority || context.signer_role != "hepta" {
        return Err(RuntimeError::PaperRaidFinalityRoleMismatch);
    }
    Ok(signed)
}

fn account_nonce_and_balance(
    state: &mut RuntimeState<'_>,
    tx: &CanonicalPaperRaidFinalityTxV2,
) -> Result<(u64, u128), RuntimeError> {
    let sender = state.account(&tx.sender)?;
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
    tx: &CanonicalPaperRaidFinalityTxV2,
    estimate: ResourceEstimate,
) -> Result<(), RuntimeError> {
    if estimate.gas_used > tx.max_gas {
        return Err(RuntimeError::GasLimitExceeded {
            required: estimate.gas_used,
            limit: tx.max_gas,
        });
    }
    if estimate.fee_estimate > tx.fee_limit {
        return Err(RuntimeError::FeeLimitExceeded {
            required: estimate.fee_estimate,
            limit: tx.fee_limit,
        });
    }
    Ok(())
}

fn reject_applied_replay(
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

fn ensure_new_commitment_absent(
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
    Err(RuntimeError::PaperRaidFinalityCommitmentExists)
}

fn ensure_new_index_absent(
    view: &dyn StateView,
    index_kind: PaperRaidFinalityIndexKindV2,
    index_key: &str,
) -> Result<(), RuntimeError> {
    let Some(stored) = view.get(index_key) else {
        return Ok(());
    };
    validate_stored_index_mirror(view, index_kind, index_key, &stored)?;
    Err(match index_kind {
        PaperRaidFinalityIndexKindV2::Submission => RuntimeError::PaperRaidFinalitySubmissionExists,
        PaperRaidFinalityIndexKindV2::Evaluation => RuntimeError::PaperRaidFinalityEvaluationExists,
    })
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
    signed: &SignedPaperRaidFinalityCommandV2,
    commitment_key: &str,
    applied_key: &str,
) -> RuntimeEvent {
    RuntimeEvent {
        kind: "trnm.paper-raid.finality.applied.v2".to_string(),
        attributes: BTreeMap::from([
            ("command_id".to_string(), signed.command_id.to_hex()),
            (
                "command_fingerprint_hex".to_string(),
                digest_hex(signed.command_fingerprint()),
            ),
            (
                "applied_command_object_key_hex".to_string(),
                applied_key.to_string(),
            ),
            (
                "commitment_id".to_string(),
                signed.commitment.commitment_id.to_hex(),
            ),
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
                signed.commitment.scientific_finality.to_string(),
            ),
            (
                "score_eligible".to_string(),
                signed.commitment.score_eligible.to_string(),
            ),
            (
                "ranking_eligible".to_string(),
                signed.commitment.ranking_eligible.to_string(),
            ),
            (
                "reward_eligible".to_string(),
                signed.commitment.reward_eligible.to_string(),
            ),
            (
                "economic_eligible".to_string(),
                signed.commitment.economic_eligible.to_string(),
            ),
        ]),
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
        CANONICAL_PAPER_RAID_FINALITY_TX_SCHEMA_V2,
    };
    use trnm_research_protocol::{
        AuthorityIdentityV1, AuthoritySetV1, MatchEvidenceCommitmentV1, MatchEvidenceObjectV1,
        PaperRaidAppealStatusV2,
    };

    use super::*;
    use crate::{research_genesis_mutation, StateObject};

    const CHAIN_ID: &str = "trnm-paper-raid-test";
    const HEPTA_DID: &str = "did:trnm:hepta-authority";
    const HEPTA_SEED: [u8; 32] = [0x22; 32];
    const FINALIZED_AT_UNIX_S: u64 = 1_753_450_001;

    #[derive(Default)]
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
        assert_eq!(
            paper_raid_finality_commitment_key(key).unwrap(),
            "65df7e72b34c74bdeb173fe44e3626ca9956514453567cd2173d16dfad7affd7"
        );
        assert_eq!(
            paper_raid_finality_applied_command_key(key).unwrap(),
            "693163b6f4062b004999a5855675bf6b1688d15ca8309bca073fb064a87b1014"
        );
        assert_eq!(
            paper_raid_finality_submission_index_key(key, key).unwrap(),
            "b489b346e8be3de67fc758534e35ab6a8e7f49ed6fb0e8479d603680bcf260bd"
        );
        assert_eq!(
            paper_raid_finality_evaluation_index_key(key).unwrap(),
            "7e68f559f81810bfdc136061fa4dd38cb93547b216a55b107583c71c5047bf26"
        );
        assert!(paper_raid_finality_commitment_key(ExternalKey::from_bytes([0; 32])).is_err());
        assert!(paper_raid_finality_applied_command_key(ExternalKey::from_bytes([0; 32])).is_err());
        assert!(
            paper_raid_finality_submission_index_key(ExternalKey::from_bytes([0; 32]), key,)
                .is_err()
        );
        assert!(
            paper_raid_finality_evaluation_index_key(ExternalKey::from_bytes([0; 32])).is_err()
        );
    }
}
