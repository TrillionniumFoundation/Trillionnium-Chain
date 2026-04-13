use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use trnm_state::{
    ConsumptionRecord, ConsumptionRecordKey, ConsumptionRecordStatus, StateStore,
    TaskConsumptionSummary,
};
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

const SUMMARY_SETTLEMENT_MARKER_WITHOUT_RECEIPTS: &str =
    "poco summary settlement marker requires at least one receipt";

fn summary_has_inconsistent_terminal_marker(summary: &TaskConsumptionSummary) -> bool {
    summary.receipt_count == 0 && summary.last_settlement_height.is_some()
}

fn summary_unproven_receipt_count(summary: TaskConsumptionSummary) -> u64 {
    if summary.receipt_count == 0 {
        return 0;
    }

    if summary.accepted_receipt_count > summary.receipt_count {
        return summary.receipt_count;
    }

    if summary.last_settlement_height.is_none() {
        return summary.receipt_count;
    }

    if summary.receipt_count == 1 {
        return 0;
    }

    if summary.accepted_receipt_count == summary.receipt_count {
        return 0;
    }

    // Promotion step: summary-only settlement metadata does not retain
    // terminal counts for rejected/slashed receipts, so multi-receipt states
    // with fewer accepted receipts than submitted receipts cannot prove that
    // PoCO settlement fully finalized. Fail closed until canonical per-receipt
    // records are present or richer summary accounting lands.
    summary
        .receipt_count
        .saturating_sub(summary.accepted_receipt_count)
}

pub(crate) fn reject_if_primary_settlement_pending(
    st: &StateStore,
    task_id: u64,
) -> Result<(), PouwError> {
    let records = st.consumption_records_for_task(task_id);
    let unresolved_receipt_count = unresolved_receipt_count(&records) as u64;
    let summary_pending_reason = if records.is_empty() {
        st.task_consumption_summary(task_id).and_then(|summary| {
            if summary_has_inconsistent_terminal_marker(&summary) {
                Some(SUMMARY_SETTLEMENT_MARKER_WITHOUT_RECEIPTS.to_string())
            } else {
                let unresolved_receipt_count = summary_unproven_receipt_count(summary);
                (unresolved_receipt_count > 0).then(|| {
                    format!(
                        "{} unresolved consumption receipt{}",
                        unresolved_receipt_count,
                        if unresolved_receipt_count == 1 {
                            ""
                        } else {
                            "s"
                        }
                    )
                })
            }
        })
    } else {
        None
    };

    if unresolved_receipt_count > 0 {
        return Err(PouwError::State(format!(
            "poco primary settlement pending: {} unresolved consumption receipt{}",
            unresolved_receipt_count,
            if unresolved_receipt_count == 1 {
                ""
            } else {
                "s"
            }
        )));
    }

    if let Some(reason) = summary_pending_reason {
        return Err(PouwError::State(format!(
            "poco primary settlement pending: {}",
            reason
        )));
    }

    Ok(())
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

fn reject_if_settlement_window_closed(
    task: &TaskObject,
    current_height: u64,
) -> Result<(), PouwError> {
    match task.status {
        TaskStatus::Revealed | TaskStatus::Completed => {
            let challenge_deadline = task.challenge_deadline_height.ok_or_else(|| {
                PouwError::State("poco settlement window requires challenge_deadline_height".into())
            })?;
            // Promotion step: once the canonical PoCO settlement window closes,
            // all receipt settlement paths fail closed, even if the legacy task
            // lifecycle already advanced to Completed. Missing canonical window
            // metadata also fails closed instead of silently re-opening settlement.
            reject_if_deadline_exceeded_optional(Some(challenge_deadline), current_height)?;
        }
        TaskStatus::Challenged => {
            let resolve_deadline = task.resolve_deadline_height.ok_or_else(|| {
                PouwError::State("poco settlement window requires resolve_deadline_height".into())
            })?;
            // Promotion step: once the task enters the challenged dispute path,
            // receipt challenge/resolve must stay bounded by the canonical
            // resolve window instead of drifting indefinitely as a sidecar flow.
            reject_if_deadline_exceeded_optional(Some(resolve_deadline), current_height)?;
        }
        _ => {}
    }
    Ok(())
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

fn unresolved_receipt_count(records: &[ConsumptionRecord]) -> usize {
    records
        .iter()
        .filter(|record| {
            matches!(
                record.status,
                ConsumptionRecordStatus::Submitted | ConsumptionRecordStatus::Challenged
            )
        })
        .count()
}

fn total_credited_consumption_units(records: &[ConsumptionRecord]) -> u128 {
    records
        .iter()
        .filter(|record| {
            matches!(
                record.status,
                ConsumptionRecordStatus::Accepted | ConsumptionRecordStatus::Discounted
            )
        })
        .map(|record| record.credited_consumption_units.unwrap_or(0))
        .sum()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PrimaryPayoutWorkUnitPreview {
    MeteringEvidence {
        metering_work_units: u128,
    },
    PocoPendingSettlement {
        unresolved_receipt_count: u64,
        metering_work_units: u128,
    },
    PocoInconsistentSummary {
        reason: &'static str,
        metering_work_units: u128,
    },
    PocoResolvedCredits {
        credited_work_units: u128,
        payout_work_units: u128,
    },
    PocoResolvedZeroCredit,
}

fn preview_primary_payout_work_units_from_summary(
    summary: TaskConsumptionSummary,
    metering_work_units: u128,
) -> PrimaryPayoutWorkUnitPreview {
    if summary_has_inconsistent_terminal_marker(&summary) {
        // Promotion step: a summary-only settlement marker without any
        // submitted receipt must fail closed instead of letting legacy
        // metering reassert itself as sole payout authority.
        return PrimaryPayoutWorkUnitPreview::PocoInconsistentSummary {
            reason: SUMMARY_SETTLEMENT_MARKER_WITHOUT_RECEIPTS,
            metering_work_units,
        };
    }

    let unproven_receipt_count = summary_unproven_receipt_count(summary.clone());
    if unproven_receipt_count > 0 {
        // Promotion step: summary-only partial settlement must not authorize
        // payout when it cannot prove every submitted receipt reached a
        // terminal PoCO outcome. Fail closed until canonical receipt records
        // or richer summary accounting can show the full settlement result.
        PrimaryPayoutWorkUnitPreview::PocoPendingSettlement {
            unresolved_receipt_count: unproven_receipt_count,
            metering_work_units,
        }
    } else if summary.accepted_receipt_count > 0 {
        let credited_work_units = summary.total_credited_consumption_units;
        // Promotion step: once PoCO accepts credited consumption, that
        // settlement becomes the primary payout authority and legacy
        // metering/proof work units remain only as the evidence ceiling.
        PrimaryPayoutWorkUnitPreview::PocoResolvedCredits {
            credited_work_units,
            payout_work_units: metering_work_units.min(credited_work_units),
        }
    } else if summary.receipt_count > 0 && summary.last_settlement_height.is_some() {
        // Promotion step: a resolved zero-credit PoCO settlement must
        // fail closed instead of falling back to legacy metering as the
        // sole payout authority.
        PrimaryPayoutWorkUnitPreview::PocoResolvedZeroCredit
    } else {
        PrimaryPayoutWorkUnitPreview::MeteringEvidence {
            metering_work_units,
        }
    }
}

fn preview_primary_payout_work_units(
    st: &StateStore,
    task: &TaskObject,
    metering_work_units: u128,
) -> PrimaryPayoutWorkUnitPreview {
    let records = st.consumption_records_for_task(task.task_id);
    if !records.is_empty() {
        let unresolved_receipt_count = unresolved_receipt_count(&records) as u64;
        if unresolved_receipt_count > 0 {
            return PrimaryPayoutWorkUnitPreview::PocoPendingSettlement {
                unresolved_receipt_count,
                metering_work_units,
            };
        }

        let credited_work_units = total_credited_consumption_units(&records);
        return if credited_work_units > 0 {
            PrimaryPayoutWorkUnitPreview::PocoResolvedCredits {
                credited_work_units,
                payout_work_units: metering_work_units.min(credited_work_units),
            }
        } else {
            PrimaryPayoutWorkUnitPreview::PocoResolvedZeroCredit
        };
    }

    st.task_consumption_summary(task.task_id)
        .map(|summary| preview_primary_payout_work_units_from_summary(summary, metering_work_units))
        .unwrap_or(PrimaryPayoutWorkUnitPreview::MeteringEvidence {
            metering_work_units,
        })
}

fn finalize_primary_payout_work_units(preview: PrimaryPayoutWorkUnitPreview) -> u128 {
    match preview {
        PrimaryPayoutWorkUnitPreview::MeteringEvidence {
            metering_work_units,
        } => metering_work_units,
        PrimaryPayoutWorkUnitPreview::PocoPendingSettlement { .. }
        | PrimaryPayoutWorkUnitPreview::PocoInconsistentSummary { .. } => {
            // Promotion step: once PoCO settlement has started, or summary-only
            // settlement metadata is internally inconsistent, fail closed until
            // the receipt path reaches an explicit canonical outcome.
            // Legacy metering/proof data remains evidence for the eventual cap,
            // not the sole payout authority while settlement is pending.
            0
        }
        PrimaryPayoutWorkUnitPreview::PocoResolvedCredits {
            payout_work_units, ..
        } => payout_work_units,
        PrimaryPayoutWorkUnitPreview::PocoResolvedZeroCredit => 0,
    }
}

pub(crate) fn primary_payout_work_units(
    st: &StateStore,
    task: &TaskObject,
    metering_work_units: u128,
) -> u128 {
    finalize_primary_payout_work_units(preview_primary_payout_work_units(
        st,
        task,
        metering_work_units,
    ))
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
    reject_if_settlement_window_closed(&task, current_height)?;
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
    reject_if_settlement_window_closed(&task, current_height)?;

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
    reject_if_settlement_window_closed(&task, current_height)?;

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
            (
                ConsumptionRecordStatus::Accepted,
                Some(credited),
                "accepted",
            )
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
            (
                ConsumptionRecordStatus::Discounted,
                Some(credited),
                "accepted_discounted",
            )
        }
        ConsumptionResolveDecision::Reject => {
            if credited_consumption_units.unwrap_or(0) != 0 {
                return Err(PouwError::State(
                    "poco reject requires zero credited_consumption_units".into(),
                ));
            }
            (
                ConsumptionRecordStatus::Rejected,
                None,
                "rejected_invalid_receipt",
            )
        }
        ConsumptionResolveDecision::Slash => {
            if credited_consumption_units.unwrap_or(0) != 0 {
                return Err(PouwError::State(
                    "poco slash requires zero credited_consumption_units".into(),
                ));
            }
            (
                ConsumptionRecordStatus::Slashed,
                None,
                "slashed_fraudulent_receipt",
            )
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
    if matches!(
        record.status,
        ConsumptionRecordStatus::Accepted | ConsumptionRecordStatus::Discounted
    ) {
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
    use crate::{apply_resolve_at_height, apply_timeout};
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

    fn sample_record(
        consumer_id: &str,
        billing_window_id: &str,
        status: ConsumptionRecordStatus,
        credited_consumption_units: Option<u128>,
    ) -> ConsumptionRecord {
        ConsumptionRecord {
            key: ConsumptionRecordKey {
                task_id: 42,
                consumer_id: consumer_id.to_string(),
                output_hash: sample_output_hash_hex(),
                billing_window_id: billing_window_id.to_string(),
            },
            worker_id: "worker-alpha".to_string(),
            tokenizer_id: "llama3-tokenizer".to_string(),
            tokenizer_version: "1.0.0".to_string(),
            consumer_class: "bonded_api_client".to_string(),
            consumed_spans_root: "def456".to_string(),
            consumed_token_count: 17,
            claimed_consumption_units: 17,
            credited_consumption_units,
            consumer_nonce: 7,
            accepted_at_unix_ms: 1_775_683_200_123,
            status,
            resolution_code: None,
        }
    }

    fn mark_task_challenged(task: &mut TaskObject) {
        task.status = TaskStatus::Challenged;
        task.challenge_bond = Some(10);
        task.challenger = Some("auditor-1".to_string());
        task.challenged_at_height = Some(95);
        task.resolve_deadline_height = Some(110);
        task.challenge_bond_forfeited = None;
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
        st.put_task_new(sample_task(TaskStatus::Revealed))
            .expect("task");

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
        st.put_task_new(sample_task(TaskStatus::Revealed))
            .expect("task");
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
        let err =
            submit_consumption_receipt_at_height(&mut st, replay, "consumer-bravo".to_string(), 11)
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

    #[test]
    fn primary_payout_work_units_falls_back_to_metering_without_accepted_receipts() {
        let st = StateStore::default();
        let task = sample_task(TaskStatus::Completed);

        assert_eq!(primary_payout_work_units(&st, &task, 50), 50);
    }

    #[test]
    fn primary_payout_work_units_caps_metering_by_credited_consumption_units() {
        let mut st = StateStore::default();
        let task = sample_task(TaskStatus::Completed);
        st.set_task_consumption_summary(TaskConsumptionSummary {
            task_id: task.task_id,
            receipt_count: 2,
            accepted_receipt_count: 2,
            challenged_receipt_count: 0,
            total_consumed_tokens: 17,
            total_claimed_consumption_units: 17,
            total_credited_consumption_units: 9,
            last_settlement_height: Some(77),
        });

        assert_eq!(primary_payout_work_units(&st, &task, 50), 9);
        assert_eq!(primary_payout_work_units(&st, &task, 7), 7);
    }

    #[test]
    fn primary_payout_work_units_zeroes_metering_after_resolved_zero_credit_settlement() {
        let mut st = StateStore::default();
        let task = sample_task(TaskStatus::Completed);
        st.set_task_consumption_summary(TaskConsumptionSummary {
            task_id: task.task_id,
            receipt_count: 1,
            accepted_receipt_count: 0,
            challenged_receipt_count: 1,
            total_consumed_tokens: 17,
            total_claimed_consumption_units: 17,
            total_credited_consumption_units: 0,
            last_settlement_height: Some(77),
        });

        assert_eq!(primary_payout_work_units(&st, &task, 50), 0);
        assert_eq!(primary_payout_work_units(&st, &task, 7), 0);
    }

    #[test]
    fn primary_payout_work_units_fail_closed_while_poco_settlement_is_pending() {
        let mut st = StateStore::default();
        let task = sample_task(TaskStatus::Completed);
        st.set_task_consumption_summary(TaskConsumptionSummary {
            task_id: task.task_id,
            receipt_count: 1,
            accepted_receipt_count: 0,
            challenged_receipt_count: 0,
            total_consumed_tokens: 17,
            total_claimed_consumption_units: 17,
            total_credited_consumption_units: 0,
            last_settlement_height: None,
        });

        assert_eq!(primary_payout_work_units(&st, &task, 50), 0);
    }

    #[test]
    fn preview_primary_payout_work_units_marks_pending_poco_settlement() {
        let mut st = StateStore::default();
        let task = sample_task(TaskStatus::Completed);
        st.set_task_consumption_summary(TaskConsumptionSummary {
            task_id: task.task_id,
            receipt_count: 1,
            accepted_receipt_count: 0,
            challenged_receipt_count: 0,
            total_consumed_tokens: 17,
            total_claimed_consumption_units: 17,
            total_credited_consumption_units: 0,
            last_settlement_height: None,
        });

        assert_eq!(
            preview_primary_payout_work_units(&st, &task, 50),
            PrimaryPayoutWorkUnitPreview::PocoPendingSettlement {
                unresolved_receipt_count: 1,
                metering_work_units: 50,
            }
        );
    }

    #[test]
    fn preview_primary_payout_work_units_marks_resolved_poco_credit_authority() {
        let mut st = StateStore::default();
        let task = sample_task(TaskStatus::Completed);
        st.set_task_consumption_summary(TaskConsumptionSummary {
            task_id: task.task_id,
            receipt_count: 2,
            accepted_receipt_count: 2,
            challenged_receipt_count: 0,
            total_consumed_tokens: 17,
            total_claimed_consumption_units: 17,
            total_credited_consumption_units: 9,
            last_settlement_height: Some(77),
        });

        assert_eq!(
            preview_primary_payout_work_units(&st, &task, 50),
            PrimaryPayoutWorkUnitPreview::PocoResolvedCredits {
                credited_work_units: 9,
                payout_work_units: 9,
            }
        );
    }

    #[test]
    fn preview_primary_payout_work_units_prefers_pending_records_over_stale_summary_credit() {
        let mut st = StateStore::default();
        let task = sample_task(TaskStatus::Completed);
        st.set_task_consumption_summary(TaskConsumptionSummary {
            task_id: task.task_id,
            receipt_count: 2,
            accepted_receipt_count: 1,
            challenged_receipt_count: 0,
            total_consumed_tokens: 34,
            total_claimed_consumption_units: 34,
            total_credited_consumption_units: 9,
            last_settlement_height: Some(77),
        });
        st.put_consumption_record(sample_record(
            "consumer-bravo",
            "bw-1",
            ConsumptionRecordStatus::Accepted,
            Some(9),
        ));
        st.put_consumption_record(sample_record(
            "consumer-charlie",
            "bw-2",
            ConsumptionRecordStatus::Submitted,
            None,
        ));

        assert_eq!(
            preview_primary_payout_work_units(&st, &task, 50),
            PrimaryPayoutWorkUnitPreview::PocoPendingSettlement {
                unresolved_receipt_count: 1,
                metering_work_units: 50,
            }
        );
        assert_eq!(primary_payout_work_units(&st, &task, 50), 0);
    }

    #[test]
    fn reject_if_primary_settlement_pending_counts_challenged_receipts_from_records() {
        let mut st = StateStore::default();
        st.put_consumption_record(sample_record(
            "consumer-bravo",
            "bw-1",
            ConsumptionRecordStatus::Accepted,
            Some(9),
        ));
        st.put_consumption_record(sample_record(
            "consumer-charlie",
            "bw-2",
            ConsumptionRecordStatus::Challenged,
            None,
        ));

        let err = reject_if_primary_settlement_pending(&st, 42)
            .expect_err("challenged receipt must keep primary settlement pending");
        assert!(
            matches!(err, PouwError::State(msg) if msg.contains("1 unresolved consumption receipt"))
        );
    }

    #[test]
    fn reject_if_primary_settlement_pending_fails_closed_from_summary_without_records() {
        let mut st = StateStore::default();
        st.set_task_consumption_summary(TaskConsumptionSummary {
            task_id: 42,
            receipt_count: 2,
            accepted_receipt_count: 0,
            challenged_receipt_count: 0,
            total_consumed_tokens: 34,
            total_claimed_consumption_units: 34,
            total_credited_consumption_units: 0,
            last_settlement_height: None,
        });

        let err = reject_if_primary_settlement_pending(&st, 42)
            .expect_err("summary-only pending receipt metadata must fail closed");
        assert!(
            matches!(err, PouwError::State(msg) if msg.contains("2 unresolved consumption receipts"))
        );
    }

    #[test]
    fn primary_payout_work_units_fail_closed_for_summary_only_partial_credit_without_records() {
        let mut st = StateStore::default();
        let task = sample_task(TaskStatus::Completed);
        st.set_task_consumption_summary(TaskConsumptionSummary {
            task_id: task.task_id,
            receipt_count: 2,
            accepted_receipt_count: 1,
            challenged_receipt_count: 0,
            total_consumed_tokens: 34,
            total_claimed_consumption_units: 34,
            total_credited_consumption_units: 9,
            last_settlement_height: Some(77),
        });

        assert_eq!(
            preview_primary_payout_work_units(&st, &task, 50),
            PrimaryPayoutWorkUnitPreview::PocoPendingSettlement {
                unresolved_receipt_count: 1,
                metering_work_units: 50,
            }
        );
        assert_eq!(primary_payout_work_units(&st, &task, 50), 0);
    }

    #[test]
    fn reject_if_primary_settlement_pending_fails_closed_for_summary_only_partial_credit_without_records(
    ) {
        let mut st = StateStore::default();
        st.set_task_consumption_summary(TaskConsumptionSummary {
            task_id: 42,
            receipt_count: 2,
            accepted_receipt_count: 1,
            challenged_receipt_count: 0,
            total_consumed_tokens: 34,
            total_claimed_consumption_units: 34,
            total_credited_consumption_units: 9,
            last_settlement_height: Some(77),
        });

        let err = reject_if_primary_settlement_pending(&st, 42).expect_err(
            "summary-only partial PoCO credit must not prove terminal settlement completeness",
        );
        assert!(
            matches!(err, PouwError::State(msg) if msg.contains("1 unresolved consumption receipt"))
        );
    }

    #[test]
    fn primary_payout_work_units_fail_closed_for_summary_only_terminal_marker_without_receipts() {
        let mut st = StateStore::default();
        let task = sample_task(TaskStatus::Completed);
        st.set_task_consumption_summary(TaskConsumptionSummary {
            task_id: task.task_id,
            receipt_count: 0,
            accepted_receipt_count: 0,
            challenged_receipt_count: 0,
            total_consumed_tokens: 0,
            total_claimed_consumption_units: 0,
            total_credited_consumption_units: 0,
            last_settlement_height: Some(77),
        });

        assert_eq!(
            preview_primary_payout_work_units(&st, &task, 50),
            PrimaryPayoutWorkUnitPreview::PocoInconsistentSummary {
                reason: SUMMARY_SETTLEMENT_MARKER_WITHOUT_RECEIPTS,
                metering_work_units: 50,
            }
        );
        assert_eq!(primary_payout_work_units(&st, &task, 50), 0);
    }

    #[test]
    fn reject_if_primary_settlement_pending_fails_closed_for_summary_only_terminal_marker_without_receipts(
    ) {
        let mut st = StateStore::default();
        st.set_task_consumption_summary(TaskConsumptionSummary {
            task_id: 42,
            receipt_count: 0,
            accepted_receipt_count: 0,
            challenged_receipt_count: 0,
            total_consumed_tokens: 0,
            total_claimed_consumption_units: 0,
            total_credited_consumption_units: 0,
            last_settlement_height: Some(77),
        });

        let err = reject_if_primary_settlement_pending(&st, 42)
            .expect_err("summary-only settlement marker without receipts must fail closed");
        assert!(
            matches!(err, PouwError::State(msg) if msg.contains(SUMMARY_SETTLEMENT_MARKER_WITHOUT_RECEIPTS))
        );
    }

    #[test]
    fn timeout_revealed_summary_only_partial_credit_without_records_fail_closed() {
        let mut st = StateStore::default();
        let task_ref = st
            .put_task_new(sample_task(TaskStatus::Revealed))
            .expect("task");
        let task_id = task_ref.id;
        st.set_task_consumption_summary(TaskConsumptionSummary {
            task_id,
            receipt_count: 2,
            accepted_receipt_count: 1,
            challenged_receipt_count: 0,
            total_consumed_tokens: 34,
            total_claimed_consumption_units: 34,
            total_credited_consumption_units: 9,
            last_settlement_height: Some(77),
        });

        let err = apply_timeout(&mut st, task_ref, 101)
            .expect_err("summary-only partial PoCO credit must block timeout finalization");

        assert!(
            matches!(err, PouwError::State(msg) if msg.contains("poco primary settlement pending"))
        );
        assert_eq!(
            st.get_task(task_id).expect("task").status,
            TaskStatus::Revealed
        );
    }

    #[test]
    fn submit_consumption_receipt_rejects_closed_window_for_completed_task() {
        let mut st = StateStore::default();
        st.put_task_new(sample_task(TaskStatus::Completed))
            .expect("task");

        let err = submit_consumption_receipt_at_height(
            &mut st,
            sample_receipt(),
            "consumer-bravo".to_string(),
            101,
        )
        .expect_err("closed settlement window must reject late receipt submission");

        assert!(matches!(err, PouwError::DeadlineExceeded));
    }

    #[test]
    fn challenge_consumption_receipt_rejects_closed_window_for_completed_task() {
        let mut st = StateStore::default();
        st.put_task_new(sample_task(TaskStatus::Completed))
            .expect("task");
        let receipt = sample_receipt();
        let key = receipt.replay_key();
        submit_consumption_receipt_at_height(&mut st, receipt, "consumer-bravo".to_string(), 99)
            .expect("submit receipt within settlement window");

        let err = challenge_consumption_receipt_at_height(
            &mut st,
            key,
            "auditor-1".to_string(),
            "auditor-1".to_string(),
            101,
        )
        .expect_err("closed settlement window must reject late receipt challenge");

        assert!(matches!(err, PouwError::DeadlineExceeded));
    }

    #[test]
    fn resolve_consumption_receipt_rejects_closed_window_for_completed_task() {
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
        submit_consumption_receipt_at_height(&mut st, receipt, "consumer-bravo".to_string(), 99)
            .expect("submit receipt within settlement window");

        let err = resolve_consumption_receipt_at_height(
            &mut st,
            key,
            ConsumptionResolveDecision::Accept,
            None,
            None,
            "resolver-1".to_string(),
            "resolver-1".to_string(),
            101,
        )
        .expect_err("closed settlement window must reject late receipt resolution");

        assert!(matches!(err, PouwError::DeadlineExceeded));
    }

    #[test]
    fn challenge_consumption_receipt_rejects_closed_window_for_challenged_task() {
        let mut st = StateStore::default();
        let task_ref = st
            .put_task_new(sample_task(TaskStatus::Revealed))
            .expect("task");
        let receipt = sample_receipt();
        let key = receipt.replay_key();
        submit_consumption_receipt_at_height(&mut st, receipt, "consumer-bravo".to_string(), 99)
            .expect("submit receipt within settlement window");

        let mut challenged = st.get_task(42).expect("task");
        mark_task_challenged(&mut challenged);
        st.update_task(task_ref, challenged).expect("update task");

        let err = challenge_consumption_receipt_at_height(
            &mut st,
            key,
            "auditor-1".to_string(),
            "auditor-1".to_string(),
            111,
        )
        .expect_err("closed challenged resolve window must reject late receipt challenge");

        assert!(matches!(err, PouwError::DeadlineExceeded));
    }

    #[test]
    fn resolve_consumption_receipt_rejects_closed_window_for_challenged_task() {
        let mut st = StateStore::default();
        let _ = st.set_gov_param_bootstrap_unchecked(
            9_503,
            "resolve_authority".into(),
            "resolver-1,resolver-2".into(),
        );
        let task_ref = st
            .put_task_new(sample_task(TaskStatus::Revealed))
            .expect("task");
        let receipt = sample_receipt();
        let key = receipt.replay_key();
        submit_consumption_receipt_at_height(&mut st, receipt, "consumer-bravo".to_string(), 99)
            .expect("submit receipt within settlement window");

        let mut challenged = st.get_task(42).expect("task");
        mark_task_challenged(&mut challenged);
        st.update_task(task_ref, challenged).expect("update task");

        let err = resolve_consumption_receipt_at_height(
            &mut st,
            key,
            ConsumptionResolveDecision::Accept,
            None,
            None,
            "resolver-1".to_string(),
            "resolver-1".to_string(),
            111,
        )
        .expect_err("closed challenged resolve window must reject late receipt resolution");

        assert!(matches!(err, PouwError::DeadlineExceeded));
    }

    #[test]
    fn submit_consumption_receipt_rejects_missing_settlement_deadline_metadata() {
        let mut st = StateStore::default();
        let mut task = sample_task(TaskStatus::Completed);
        task.challenge_deadline_height = None;
        st.put_task_new(task).expect("task");

        let err = submit_consumption_receipt_at_height(
            &mut st,
            sample_receipt(),
            "consumer-bravo".to_string(),
            99,
        )
        .expect_err("missing settlement deadline must fail closed");

        assert!(
            matches!(err, PouwError::State(msg) if msg.contains("poco settlement window requires challenge_deadline_height"))
        );
    }

    #[test]
    fn challenge_consumption_receipt_rejects_missing_settlement_deadline_metadata() {
        let mut st = StateStore::default();
        let task_ref = st
            .put_task_new(sample_task(TaskStatus::Completed))
            .expect("task");
        let receipt = sample_receipt();
        let key = receipt.replay_key();
        submit_consumption_receipt_at_height(&mut st, receipt, "consumer-bravo".to_string(), 99)
            .expect("submit receipt within settlement window");

        let mut malformed = st.get_task(42).expect("task");
        malformed.challenge_deadline_height = None;
        st.update_task(task_ref, malformed).expect("update task");

        let err = challenge_consumption_receipt_at_height(
            &mut st,
            key,
            "auditor-1".to_string(),
            "auditor-1".to_string(),
            99,
        )
        .expect_err("missing settlement deadline must fail closed");

        assert!(
            matches!(err, PouwError::State(msg) if msg.contains("poco settlement window requires challenge_deadline_height"))
        );
    }

    #[test]
    fn resolve_consumption_receipt_rejects_missing_settlement_deadline_metadata() {
        let mut st = StateStore::default();
        let _ = st.set_gov_param_bootstrap_unchecked(
            9_501,
            "resolve_authority".into(),
            "resolver-1,resolver-2".into(),
        );
        let task_ref = st
            .put_task_new(sample_task(TaskStatus::Completed))
            .expect("task");
        let receipt = sample_receipt();
        let key = receipt.replay_key();
        submit_consumption_receipt_at_height(&mut st, receipt, "consumer-bravo".to_string(), 99)
            .expect("submit receipt within settlement window");

        let mut malformed = st.get_task(42).expect("task");
        malformed.challenge_deadline_height = None;
        st.update_task(task_ref, malformed).expect("update task");

        let err = resolve_consumption_receipt_at_height(
            &mut st,
            key,
            ConsumptionResolveDecision::Accept,
            None,
            None,
            "resolver-1".to_string(),
            "resolver-1".to_string(),
            99,
        )
        .expect_err("missing settlement deadline must fail closed");

        assert!(
            matches!(err, PouwError::State(msg) if msg.contains("poco settlement window requires challenge_deadline_height"))
        );
    }

    #[test]
    fn challenge_consumption_receipt_rejects_missing_resolve_deadline_metadata() {
        let mut st = StateStore::default();
        let task_ref = st
            .put_task_new(sample_task(TaskStatus::Revealed))
            .expect("task");
        let receipt = sample_receipt();
        let key = receipt.replay_key();
        submit_consumption_receipt_at_height(&mut st, receipt, "consumer-bravo".to_string(), 99)
            .expect("submit receipt within settlement window");

        let mut challenged = st.get_task(42).expect("task");
        mark_task_challenged(&mut challenged);
        challenged.resolve_deadline_height = None;
        st.update_task(task_ref, challenged).expect("update task");

        let err = challenge_consumption_receipt_at_height(
            &mut st,
            key,
            "auditor-1".to_string(),
            "auditor-1".to_string(),
            109,
        )
        .expect_err("missing challenged resolve deadline must fail closed");

        assert!(
            matches!(err, PouwError::State(msg) if msg.contains("poco settlement window requires resolve_deadline_height"))
        );
    }

    #[test]
    fn resolve_consumption_receipt_rejects_missing_resolve_deadline_metadata() {
        let mut st = StateStore::default();
        let _ = st.set_gov_param_bootstrap_unchecked(
            9_504,
            "resolve_authority".into(),
            "resolver-1,resolver-2".into(),
        );
        let task_ref = st
            .put_task_new(sample_task(TaskStatus::Revealed))
            .expect("task");
        let receipt = sample_receipt();
        let key = receipt.replay_key();
        submit_consumption_receipt_at_height(&mut st, receipt, "consumer-bravo".to_string(), 99)
            .expect("submit receipt within settlement window");

        let mut challenged = st.get_task(42).expect("task");
        mark_task_challenged(&mut challenged);
        challenged.resolve_deadline_height = None;
        st.update_task(task_ref, challenged).expect("update task");

        let err = resolve_consumption_receipt_at_height(
            &mut st,
            key,
            ConsumptionResolveDecision::Accept,
            None,
            None,
            "resolver-1".to_string(),
            "resolver-1".to_string(),
            109,
        )
        .expect_err("missing challenged resolve deadline must fail closed");

        assert!(
            matches!(err, PouwError::State(msg) if msg.contains("poco settlement window requires resolve_deadline_height"))
        );
    }

    #[test]
    fn timeout_revealed_pending_poco_primary_settlement_fail_closed() {
        let mut st = StateStore::default();
        let task_ref = st
            .put_task_new(sample_task(TaskStatus::Revealed))
            .expect("task");
        let task_id = task_ref.id;
        submit_consumption_receipt_at_height(
            &mut st,
            sample_receipt(),
            "consumer-bravo".into(),
            99,
        )
        .expect("submit receipt within settlement window");

        let err = apply_timeout(&mut st, task_ref, 101)
            .expect_err("pending PoCO settlement must block revealed timeout finalization");

        assert!(
            matches!(err, PouwError::State(msg) if msg.contains("poco primary settlement pending"))
        );
        assert_eq!(
            st.get_task(task_id).expect("task").status,
            TaskStatus::Revealed
        );
    }

    #[test]
    fn timeout_challenged_pending_poco_primary_settlement_fail_closed() {
        let mut st = StateStore::default();
        let task_ref = st
            .put_task_new(sample_task(TaskStatus::Revealed))
            .expect("task");
        let task_id = task_ref.id;
        submit_consumption_receipt_at_height(
            &mut st,
            sample_receipt(),
            "consumer-bravo".into(),
            99,
        )
        .expect("submit receipt within settlement window");

        let mut challenged = st.get_task(task_id).expect("task");
        mark_task_challenged(&mut challenged);
        let challenged_ref = st.update_task(task_ref, challenged).expect("update task");

        let err = apply_timeout(&mut st, challenged_ref, 111)
            .expect_err("pending PoCO settlement must block challenged timeout finalization");

        assert!(
            matches!(err, PouwError::State(msg) if msg.contains("poco primary settlement pending"))
        );
        assert_eq!(
            st.get_task(task_id).expect("task").status,
            TaskStatus::Challenged
        );
    }

    #[test]
    fn resolve_pending_poco_primary_settlement_fail_closed() {
        let mut st = StateStore::default();
        let _ = st.set_gov_param_bootstrap_unchecked(
            9_502,
            "resolve_authority".into(),
            "resolver-1,resolver-2".into(),
        );
        let task_ref = st
            .put_task_new(sample_task(TaskStatus::Revealed))
            .expect("task");
        let task_id = task_ref.id;
        submit_consumption_receipt_at_height(
            &mut st,
            sample_receipt(),
            "consumer-bravo".into(),
            99,
        )
        .expect("submit receipt within settlement window");

        let mut challenged = st.get_task(task_id).expect("task");
        mark_task_challenged(&mut challenged);
        let challenged_ref = st.update_task(task_ref, challenged).expect("update task");

        let err = apply_resolve_at_height(
            &mut st,
            challenged_ref,
            false,
            "resolver-1".to_string(),
            "resolver-1".to_string(),
            101,
        )
        .expect_err("pending PoCO settlement must block challenged resolve finalization");

        assert!(
            matches!(err, PouwError::State(msg) if msg.contains("poco primary settlement pending"))
        );
        assert_eq!(
            st.get_task(task_id).expect("task").status,
            TaskStatus::Challenged
        );
    }
}
