use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use trnm_state::{ConsumptionRecord, ConsumptionRecordKey, ConsumptionRecordStatus, StateStore, TaskConsumptionSummary};
use trnm_types::{TaskMeteringSnapshot, TaskObject, TaskStatus};

use crate::{
    is_canonical_actor_id, reject_if_deadline_exceeded_optional, require_canonical_actor_id,
    require_canonical_actor_id_state, resolve_authority_account, validate_task_metering_snapshot,
    PouwError,
};

pub const POCO_V1_SETTLEMENT_SCHEMA: &str = "poco_v1";

fn default_settlement_schema() -> String {
    POCO_V1_SETTLEMENT_SCHEMA.to_string()
}

fn normalize_hex(raw: &str) -> &str {
    let trimmed = raw.trim();
    trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed)
}

fn require_non_empty(value: &str, field: &'static str) -> Result<(), ConsumptionError> {
    if value.trim().is_empty() {
        Err(ConsumptionError::MissingField(field))
    } else {
        Ok(())
    }
}

fn map_consumption_err(err: ConsumptionError) -> PouwError {
    PouwError::State(format!("poco consumption error: {}", err))
}

fn current_summary(st: &StateStore, task_id: u64) -> TaskConsumptionSummary {
    st.task_consumption_summary(task_id)
        .unwrap_or_else(|| TaskConsumptionSummary {
            task_id,
            ..TaskConsumptionSummary::default()
        })
}

fn authority_members(st: &StateStore) -> Result<Vec<String>, PouwError> {
    let authority = resolve_authority_account(st);
    let members: Vec<String> = authority
        .split(',')
        .map(str::trim)
        .filter(|member: &&str| !member.is_empty())
        .map(|member| member.to_string())
        .collect();
    if members.is_empty() || !members.iter().all(|member| is_canonical_actor_id(member)) {
        return Err(PouwError::Unauthorized);
    }
    Ok(members)
}

fn validate_resolver(st: &StateStore, resolver: &str, signer: &str) -> Result<(), PouwError> {
    require_canonical_actor_id(resolver)?;
    require_canonical_actor_id(signer)?;
    if resolver != signer {
        return Err(PouwError::Unauthorized);
    }
    let members = authority_members(st)?;
    if !members.iter().any(|member| member == signer) {
        return Err(PouwError::Unauthorized);
    }
    Ok(())
}

fn task_snapshot_for_poco(task: &TaskObject) -> Result<TaskMeteringSnapshot, PouwError> {
    validate_task_metering_snapshot(task)?
        .ok_or_else(|| PouwError::State("poco requires task metering snapshot".into()))
}

fn validate_receipt_against_task(
    task: &TaskObject,
    receipt: &ConsumptionReceipt,
) -> Result<TaskMeteringSnapshot, PouwError> {
    if !matches!(task.status, TaskStatus::Revealed | TaskStatus::Completed) {
        return Err(PouwError::InvalidTransition);
    }
    if task.task_id != receipt.task_id {
        return Err(PouwError::State("poco task_id mismatch".into()));
    }
    let worker = task.worker.as_ref().ok_or(PouwError::MissingWorker)?;
    require_canonical_actor_id_state(worker, "worker account")?;
    if worker != &receipt.worker_id {
        return Err(PouwError::Unauthorized);
    }

    let snapshot = task_snapshot_for_poco(task)?;
    receipt
        .validate(Some(snapshot.generated_tokens))
        .map_err(map_consumption_err)?;

    require_canonical_actor_id(&receipt.consumer_id)?;
    require_canonical_actor_id(&receipt.worker_id)?;

    if receipt.consumer_nonce == 0 {
        return Err(PouwError::State(
            "poco consumer_nonce must be non-zero".into(),
        ));
    }

    if let Some(result_hash) = task.result_hash {
        let expected_output_hash = hex::encode(result_hash);
        let actual_output_hash = normalize_hex(&receipt.output_hash).to_ascii_lowercase();
        if actual_output_hash != expected_output_hash {
            return Err(PouwError::State(
                "poco output_hash does not match task result_hash".into(),
            ));
        }
    }

    Ok(snapshot)
}

pub fn claimed_consumption_units(receipt: &ConsumptionReceipt) -> u128 {
    receipt.consumed_token_count as u128
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsumptionResolveDecision {
    Accept,
    Discount,
    Reject,
    Slash,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ConsumptionError {
    #[error("missing field: {0}")]
    MissingField(&'static str),
    #[error("invalid settlement schema: expected {expected}, got {actual}")]
    InvalidSettlementSchema {
        expected: &'static str,
        actual: String,
    },
    #[error("invalid counter: {0}")]
    InvalidCounter(&'static str),
    #[error("invalid consumption receipt: {0}")]
    InvalidReceipt(&'static str),
    #[error("receipt hash mismatch: expected {expected}, got {actual}")]
    ReceiptHashMismatch { expected: String, actual: String },
    #[error("canonicalization error: {0}")]
    Canonicalization(String),
    #[error("serde error: {0}")]
    Serde(String),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ConsumptionReplayKey {
    pub task_id: u64,
    pub consumer_id: String,
    pub output_hash: String,
    pub billing_window_id: String,
}

impl ConsumptionReplayKey {
    pub fn storage_key(&self) -> String {
        format!(
            "{}:{}:{}:{}",
            self.task_id, self.consumer_id, self.output_hash, self.billing_window_id
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsumptionReceipt {
    #[serde(default = "default_settlement_schema")]
    pub settlement_schema: String,
    pub task_id: u64,
    pub worker_id: String,
    pub consumer_id: String,
    pub billing_window_id: String,
    pub tokenizer_id: String,
    pub tokenizer_version: String,
    pub output_hash: String,
    pub consumed_token_count: u64,
    pub consumed_spans_root: String,
    pub consumer_class: String,
    pub consumer_nonce: u64,
    pub accepted_at_unix_ms: u64,
    pub consumer_signature: String,
    pub receipt_hash: String,
}

#[derive(Serialize)]
struct CanonicalConsumptionReceipt<'a> {
    settlement_schema: &'a str,
    task_id: u64,
    worker_id: &'a str,
    consumer_id: &'a str,
    billing_window_id: &'a str,
    tokenizer_id: &'a str,
    tokenizer_version: &'a str,
    output_hash: &'a str,
    consumed_token_count: u64,
    consumed_spans_root: &'a str,
    consumer_class: &'a str,
    consumer_nonce: u64,
    accepted_at_unix_ms: u64,
    consumer_signature: &'a str,
}

impl ConsumptionReceipt {
    fn canonical_view(&self) -> CanonicalConsumptionReceipt<'_> {
        CanonicalConsumptionReceipt {
            settlement_schema: &self.settlement_schema,
            task_id: self.task_id,
            worker_id: &self.worker_id,
            consumer_id: &self.consumer_id,
            billing_window_id: &self.billing_window_id,
            tokenizer_id: &self.tokenizer_id,
            tokenizer_version: &self.tokenizer_version,
            output_hash: &self.output_hash,
            consumed_token_count: self.consumed_token_count,
            consumed_spans_root: &self.consumed_spans_root,
            consumer_class: &self.consumer_class,
            consumer_nonce: self.consumer_nonce,
            accepted_at_unix_ms: self.accepted_at_unix_ms,
            consumer_signature: &self.consumer_signature,
        }
    }

    pub fn replay_key(&self) -> ConsumptionReplayKey {
        ConsumptionReplayKey {
            task_id: self.task_id,
            consumer_id: self.consumer_id.clone(),
            output_hash: self.output_hash.clone(),
            billing_window_id: self.billing_window_id.clone(),
        }
    }

    pub fn canonical_receipt_hash(&self) -> Result<String, ConsumptionError> {
        let payload = serde_json::to_vec(&self.canonical_view())
            .map_err(|err| ConsumptionError::Canonicalization(err.to_string()))?;
        let mut hasher = Sha256::new();
        hasher.update(payload);
        Ok(hex::encode(hasher.finalize()))
    }

    pub fn with_computed_receipt_hash(mut self) -> Result<Self, ConsumptionError> {
        self.receipt_hash = self.canonical_receipt_hash()?;
        Ok(self)
    }

    pub fn validate_receipt_hash(&self) -> Result<(), ConsumptionError> {
        require_non_empty(&self.receipt_hash, "receipt_hash")?;
        let expected = self.canonical_receipt_hash()?;
        let actual = normalize_hex(&self.receipt_hash).to_ascii_lowercase();
        if actual != expected {
            return Err(ConsumptionError::ReceiptHashMismatch { expected, actual });
        }
        Ok(())
    }

    pub fn validate(&self, output_token_count: Option<u64>) -> Result<(), ConsumptionError> {
        if self.settlement_schema != POCO_V1_SETTLEMENT_SCHEMA {
            return Err(ConsumptionError::InvalidSettlementSchema {
                expected: POCO_V1_SETTLEMENT_SCHEMA,
                actual: self.settlement_schema.clone(),
            });
        }

        require_non_empty(&self.worker_id, "worker_id")?;
        require_non_empty(&self.consumer_id, "consumer_id")?;
        require_non_empty(&self.billing_window_id, "billing_window_id")?;
        require_non_empty(&self.tokenizer_id, "tokenizer_id")?;
        require_non_empty(&self.tokenizer_version, "tokenizer_version")?;
        require_non_empty(&self.output_hash, "output_hash")?;
        require_non_empty(&self.consumed_spans_root, "consumed_spans_root")?;
        require_non_empty(&self.consumer_class, "consumer_class")?;
        require_non_empty(&self.consumer_signature, "consumer_signature")?;

        if self.worker_id == self.consumer_id {
            return Err(ConsumptionError::InvalidReceipt(
                "self consumption is not allowed",
            ));
        }
        if self.consumed_token_count == 0 {
            return Err(ConsumptionError::InvalidCounter("consumed_token_count"));
        }
        if self.consumer_nonce == 0 {
            return Err(ConsumptionError::InvalidCounter("consumer_nonce"));
        }
        if self.accepted_at_unix_ms == 0 {
            return Err(ConsumptionError::InvalidReceipt(
                "accepted_at_unix_ms must be non-zero",
            ));
        }
        if let Some(output_token_count) = output_token_count {
            if self.consumed_token_count > output_token_count {
                return Err(ConsumptionError::InvalidReceipt(
                    "consumed_token_count exceeds revealed output_token_count",
                ));
            }
        }

        self.validate_receipt_hash()
    }
}

pub fn parse_consumption_receipt_json(raw: &str) -> Result<ConsumptionReceipt, ConsumptionError> {
    serde_json::from_str(raw).map_err(|err| ConsumptionError::Serde(err.to_string()))
}

pub fn parse_and_validate_consumption_receipt_json(
    raw: &str,
    output_token_count: Option<u64>,
) -> Result<ConsumptionReceipt, ConsumptionError> {
    let receipt = parse_consumption_receipt_json(raw)?;
    receipt.validate(output_token_count)?;
    Ok(receipt)
}

pub fn submit_consumption_receipt(
    st: &mut StateStore,
    receipt: ConsumptionReceipt,
    signer: String,
) -> Result<ConsumptionRecord, PouwError> {
    submit_consumption_receipt_at_height(st, receipt, signer, 0)
}

pub fn submit_consumption_receipt_at_height(
    st: &mut StateStore,
    receipt: ConsumptionReceipt,
    signer: String,
    current_height: u64,
) -> Result<ConsumptionRecord, PouwError> {
    require_canonical_actor_id(&signer)?;
    let task = st
        .get_task(receipt.task_id)
        .ok_or_else(|| PouwError::State("task not found".into()))?;
    if task.status == TaskStatus::Revealed {
        reject_if_deadline_exceeded_optional(task.challenge_deadline_height, current_height)?;
    }
    let _snapshot = validate_receipt_against_task(&task, &receipt)?;
    if signer != receipt.consumer_id {
        return Err(PouwError::Unauthorized);
    }
    if st
        .consumer_consumption_nonce(&receipt.consumer_id)
        .is_some_and(|nonce| receipt.consumer_nonce <= nonce)
    {
        return Err(PouwError::State(
            "poco consumer_nonce must be strictly monotonic".into(),
        ));
    }

    let key = ConsumptionRecordKey {
        task_id: receipt.task_id,
        consumer_id: receipt.consumer_id.clone(),
        output_hash: receipt.output_hash.clone(),
        billing_window_id: receipt.billing_window_id.clone(),
    };
    if st.consumption_record(&key).is_some() {
        return Err(PouwError::State(
            "poco duplicate consumption receipt replay key".into(),
        ));
    }

    let claimed_units = claimed_consumption_units(&receipt);
    let record = ConsumptionRecord {
        key: key.clone(),
        worker_id: receipt.worker_id.clone(),
        tokenizer_id: receipt.tokenizer_id.clone(),
        tokenizer_version: receipt.tokenizer_version.clone(),
        consumer_class: receipt.consumer_class.clone(),
        consumed_spans_root: receipt.consumed_spans_root.clone(),
        consumed_token_count: receipt.consumed_token_count,
        claimed_consumption_units: claimed_units,
        credited_consumption_units: None,
        consumer_nonce: receipt.consumer_nonce,
        accepted_at_unix_ms: receipt.accepted_at_unix_ms,
        status: ConsumptionRecordStatus::Submitted,
        resolution_code: None,
    };

    st.put_consumption_record(record.clone());
    st.set_consumer_consumption_nonce(&receipt.consumer_id, receipt.consumer_nonce);

    let mut summary = current_summary(st, receipt.task_id);
    summary.receipt_count = summary.receipt_count.saturating_add(1);
    summary.total_consumed_tokens = summary
        .total_consumed_tokens
        .saturating_add(receipt.consumed_token_count as u128);
    summary.total_claimed_consumption_units = summary
        .total_claimed_consumption_units
        .saturating_add(claimed_units);
    st.set_task_consumption_summary(summary);

    Ok(record)
}

pub fn challenge_consumption_receipt(
    st: &mut StateStore,
    key: ConsumptionReplayKey,
    challenger: String,
    signer: String,
) -> Result<ConsumptionRecord, PouwError> {
    challenge_consumption_receipt_at_height(st, key, challenger, signer, 0)
}

pub fn challenge_consumption_receipt_at_height(
    st: &mut StateStore,
    key: ConsumptionReplayKey,
    challenger: String,
    signer: String,
    current_height: u64,
) -> Result<ConsumptionRecord, PouwError> {
    require_canonical_actor_id(&challenger)?;
    require_canonical_actor_id(&signer)?;
    if challenger != signer {
        return Err(PouwError::Unauthorized);
    }

    let task = st
        .get_task(key.task_id)
        .ok_or_else(|| PouwError::State("task not found".into()))?;
    if task.status == TaskStatus::Revealed {
        reject_if_deadline_exceeded_optional(task.challenge_deadline_height, current_height)?;
    }

    let record_key = ConsumptionRecordKey {
        task_id: key.task_id,
        consumer_id: key.consumer_id,
        output_hash: key.output_hash,
        billing_window_id: key.billing_window_id,
    };
    let mut record = st
        .consumption_record(&record_key)
        .ok_or_else(|| PouwError::State("poco consumption record not found".into()))?;
    match record.status {
        ConsumptionRecordStatus::Submitted => {}
        _ => return Err(PouwError::InvalidTransition),
    }

    record.status = ConsumptionRecordStatus::Challenged;
    record.resolution_code = Some(format!("challenged_by:{}", challenger));
    st.put_consumption_record(record.clone());

    let mut summary = current_summary(st, record.key.task_id);
    summary.challenged_receipt_count = summary.challenged_receipt_count.saturating_add(1);
    st.set_task_consumption_summary(summary);

    Ok(record)
}

pub fn resolve_consumption_receipt(
    st: &mut StateStore,
    key: ConsumptionReplayKey,
    decision: ConsumptionResolveDecision,
    credited_consumption_units: Option<u128>,
    resolution_code: Option<String>,
    resolver: String,
    signer: String,
) -> Result<ConsumptionRecord, PouwError> {
    resolve_consumption_receipt_at_height(
        st,
        key,
        decision,
        credited_consumption_units,
        resolution_code,
        resolver,
        signer,
        0,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn resolve_consumption_receipt_at_height(
    st: &mut StateStore,
    key: ConsumptionReplayKey,
    decision: ConsumptionResolveDecision,
    credited_consumption_units: Option<u128>,
    resolution_code: Option<String>,
    resolver: String,
    signer: String,
    current_height: u64,
) -> Result<ConsumptionRecord, PouwError> {
    validate_resolver(st, &resolver, &signer)?;

    let task = st
        .get_task(key.task_id)
        .ok_or_else(|| PouwError::State("task not found".into()))?;
    if task.status == TaskStatus::Revealed {
        reject_if_deadline_exceeded_optional(task.challenge_deadline_height, current_height)?;
    }

    let record_key = ConsumptionRecordKey {
        task_id: key.task_id,
        consumer_id: key.consumer_id,
        output_hash: key.output_hash,
        billing_window_id: key.billing_window_id,
    };
    let mut record = st
        .consumption_record(&record_key)
        .ok_or_else(|| PouwError::State("poco consumption record not found".into()))?;
    match record.status {
        ConsumptionRecordStatus::Submitted | ConsumptionRecordStatus::Challenged => {}
        _ => return Err(PouwError::InvalidTransition),
    }

    let claimed_units = record.claimed_consumption_units;
    let (next_status, credited_units, default_code): (
        ConsumptionRecordStatus,
        Option<u128>,
        &'static str,
    ) = match decision {
        ConsumptionResolveDecision::Accept => {
            let credited = credited_consumption_units.unwrap_or(claimed_units);
            if credited != claimed_units {
                return Err(PouwError::State(
                    "poco accept requires credited_consumption_units == claimed_consumption_units"
                        .into(),
                ));
            }
            (ConsumptionRecordStatus::Accepted, Some(credited), "accepted")
        }
        ConsumptionResolveDecision::Discount => {
            let credited = credited_consumption_units.ok_or_else(|| {
                PouwError::State("poco discount requires credited_consumption_units".into())
            })?;
            if credited == 0 || credited >= claimed_units {
                return Err(PouwError::State(
                    "poco discount requires 0 < credited_consumption_units < claimed_consumption_units"
                        .into(),
                ));
            }
            (ConsumptionRecordStatus::Discounted, Some(credited), "accepted_discounted")
        }
        ConsumptionResolveDecision::Reject => {
            if credited_consumption_units.unwrap_or(0) != 0 {
                return Err(PouwError::State(
                    "poco reject requires zero credited_consumption_units".into(),
                ));
            }
            (ConsumptionRecordStatus::Rejected, None, "rejected_invalid_receipt")
        }
        ConsumptionResolveDecision::Slash => {
            if credited_consumption_units.unwrap_or(0) != 0 {
                return Err(PouwError::State(
                    "poco slash requires zero credited_consumption_units".into(),
                ));
            }
            (ConsumptionRecordStatus::Slashed, None, "slashed_fraudulent_receipt")
        }
    };

    record.status = next_status;
    record.credited_consumption_units = credited_units;
    record.resolution_code = Some(
        resolution_code
            .and_then(|code| {
                let trimmed = code.trim().to_string();
                (!trimmed.is_empty()).then_some(trimmed)
            })
            .unwrap_or_else(|| default_code.to_string()),
    );
    st.put_consumption_record(record.clone());

    let mut summary = current_summary(st, record.key.task_id);
    if matches!(record.status, ConsumptionRecordStatus::Accepted | ConsumptionRecordStatus::Discounted) {
        summary.accepted_receipt_count = summary.accepted_receipt_count.saturating_add(1);
        summary.total_credited_consumption_units = summary
            .total_credited_consumption_units
            .saturating_add(record.credited_consumption_units.unwrap_or(0));
    }
    summary.last_settlement_height = Some(current_height);
    st.set_task_consumption_summary(summary);

    Ok(record)
}

#[cfg(test)]
mod tests {
    use super::*;
    use trnm_types::{ProofType, TaskMetadata, TaskObject};

    fn sample_result_hash() -> [u8; 32] {
        [0x11; 32]
    }

    fn sample_output_hash_hex() -> String {
        hex::encode(sample_result_hash())
    }

    fn sample_metering() -> TaskMeteringSnapshot {
        TaskMeteringSnapshot {
            workload_class: "llm_inference".to_string(),
            metering_schema: "llm_token_meter_v1".to_string(),
            policy_snapshot_version: 1,
            receipt_hash: "receipt-hash".to_string(),
            prompt_tokens: 10,
            generated_tokens: 20,
            decode_steps: 20,
            kv_bytes_moved: 0,
            normalized_work_units: 50,
            prompt_token_weight: 1,
            generated_token_weight: 1,
            decode_step_weight: 1,
            kv_byte_weight: 0,
            min_accept_work_units: 0,
            challenge_success_bounty_base: 0,
            challenge_success_bounty_per_work_unit_num: 0,
            challenge_success_bounty_per_work_unit_den: 1,
            worker_completion_bonus_per_work_unit_num: 0,
            worker_completion_bonus_per_work_unit_den: 1,
            worker_slash_rebate_per_work_unit_num: 0,
            worker_slash_rebate_per_work_unit_den: 1,
        }
    }

    fn sample_task(status: TaskStatus) -> TaskObject {
        TaskObject {
            task_id: 42,
            creator: "creator-1".to_string(),
            bounty: 100,
            status,
            proof_type: ProofType::Fraud,
            metadata: Some(TaskMetadata {
                note: None,
                task_type: Some("llm_inference".to_string()),
                input_hash: None,
                model: None,
                provenance: None,
                metering: Some(sample_metering()),
                settlement: None,
            }),
            worker: Some("worker-alpha".to_string()),
            committed_hash: None,
            result_hash: Some(sample_result_hash()),
            reveal_salt: None,
            committed_at_height: None,
            reveal_deadline_height: None,
            challenge_deadline_height: Some(100),
            challenge_window_blocks_snapshot: Some(100),
            challenged_at_height: None,
            resolve_deadline_height: None,
            challenge_bond: None,
            challenger: None,
            challenge_bond_forfeited: None,
            version: 0,
        }
    }

    fn sample_receipt() -> ConsumptionReceipt {
        ConsumptionReceipt {
            settlement_schema: POCO_V1_SETTLEMENT_SCHEMA.to_string(),
            task_id: 42,
            worker_id: "worker-alpha".to_string(),
            consumer_id: "consumer-bravo".to_string(),
            billing_window_id: "bw-1".to_string(),
            tokenizer_id: "llama3-tokenizer".to_string(),
            tokenizer_version: "1.0.0".to_string(),
            output_hash: sample_output_hash_hex(),
            consumed_token_count: 17,
            consumed_spans_root: "def456".to_string(),
            consumer_class: "bonded_api_client".to_string(),
            consumer_nonce: 7,
            accepted_at_unix_ms: 1_775_683_200_123,
            consumer_signature: "sig789".to_string(),
            receipt_hash: String::new(),
        }
        .with_computed_receipt_hash()
        .expect("hash")
    }

    #[test]
    fn consumption_receipt_hash_roundtrip_validates() {
        let receipt = sample_receipt();
        assert!(receipt.validate(Some(20)).is_ok());
        assert_eq!(
            receipt.replay_key().storage_key(),
            format!("42:consumer-bravo:{}:bw-1", sample_output_hash_hex())
        );
    }

    #[test]
    fn consumption_receipt_rejects_self_consumption() {
        let mut receipt = sample_receipt();
        receipt.consumer_id = receipt.worker_id.clone();
        receipt = receipt.with_computed_receipt_hash().expect("hash");
        assert_eq!(
            receipt.validate(Some(20)),
            Err(ConsumptionError::InvalidReceipt(
                "self consumption is not allowed"
            ))
        );
    }

    #[test]
    fn consumption_receipt_rejects_consumed_token_overflow() {
        let receipt = sample_receipt();
        assert_eq!(
            receipt.validate(Some(16)),
            Err(ConsumptionError::InvalidReceipt(
                "consumed_token_count exceeds revealed output_token_count"
            ))
        );
    }

    #[test]
    fn submit_consumption_receipt_persists_record_and_summary() {
        let mut st = StateStore::default();
        st.put_task_new(sample_task(TaskStatus::Revealed)).expect("task");

        let record = submit_consumption_receipt_at_height(
            &mut st,
            sample_receipt(),
            "consumer-bravo".to_string(),
            10,
        )
        .expect("submit receipt");

        assert_eq!(record.status, ConsumptionRecordStatus::Submitted);
        assert_eq!(st.consumer_consumption_nonce("consumer-bravo"), Some(7));
        let summary = st.task_consumption_summary(42).expect("summary");
        assert_eq!(summary.receipt_count, 1);
        assert_eq!(summary.total_claimed_consumption_units, 17);
    }

    #[test]
    fn submit_consumption_receipt_rejects_nonce_replay() {
        let mut st = StateStore::default();
        st.put_task_new(sample_task(TaskStatus::Revealed)).expect("task");
        submit_consumption_receipt_at_height(
            &mut st,
            sample_receipt(),
            "consumer-bravo".to_string(),
            10,
        )
        .expect("submit receipt");

        let mut replay = sample_receipt();
        replay.billing_window_id = "bw-2".to_string();
        replay = replay.with_computed_receipt_hash().expect("hash");
        let err = submit_consumption_receipt_at_height(
            &mut st,
            replay,
            "consumer-bravo".to_string(),
            11,
        )
        .expect_err("nonce replay should fail");
        assert!(matches!(err, PouwError::State(_)));
    }

    #[test]
    fn challenge_and_resolve_consumption_receipt_updates_status_and_summary() {
        let mut st = StateStore::default();
        let _ = st.set_gov_param_bootstrap_unchecked(
            9_500,
            "resolve_authority".into(),
            "resolver-1,resolver-2".into(),
        );
        st.put_task_new(sample_task(TaskStatus::Completed))
            .expect("task");
        let receipt = sample_receipt();
        let key = receipt.replay_key();
        submit_consumption_receipt(&mut st, receipt, "consumer-bravo".to_string())
            .expect("submit receipt");

        let challenged = challenge_consumption_receipt(
            &mut st,
            key.clone(),
            "auditor-1".to_string(),
            "auditor-1".to_string(),
        )
        .expect("challenge receipt");
        assert_eq!(challenged.status, ConsumptionRecordStatus::Challenged);

        let resolved = resolve_consumption_receipt_at_height(
            &mut st,
            key,
            ConsumptionResolveDecision::Discount,
            Some(9),
            None,
            "resolver-1".to_string(),
            "resolver-1".to_string(),
            77,
        )
        .expect("resolve receipt");
        assert_eq!(resolved.status, ConsumptionRecordStatus::Discounted);
        assert_eq!(resolved.credited_consumption_units, Some(9));
        let summary = st.task_consumption_summary(42).expect("summary");
        assert_eq!(summary.challenged_receipt_count, 1);
        assert_eq!(summary.accepted_receipt_count, 1);
        assert_eq!(summary.total_credited_consumption_units, 9);
        assert_eq!(summary.last_settlement_height, Some(77));
    }
}
