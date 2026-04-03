pub mod reliability;

mod relay;
mod transfer;

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use trnm_oracle::{OracleValidationMetrics, OracleValidationObservation, OracleValidationReport};
use trnm_types::{
    GovProposalStatus, TaskMetadataCompatibility, TaskMetadataCompatibilityFinding, TaskStatus,
};

fn option_vec_is_none_or_empty<T>(value: &Option<Vec<T>>) -> bool {
    value.as_ref().is_none_or(Vec::is_empty)
}

pub use relay::*;
pub use transfer::{
    compute_tx_hash, get_tx, submit_tx, GetTxError, GetTxResponse, InMemoryTransferLedger,
    SendTxResponse, SubmitTransferRequest, SubmitTransferResponse, TransferApplyError,
    TxLifecycleRecord, TxStatus,
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TaskMeteringPolicyQueryResponse {
    pub snapshot_version: u8,
    pub min_accept_work_units: u128,
    pub challenge_success_bounty_base: u128,
    pub challenge_success_bounty_per_work_unit_num: u128,
    pub challenge_success_bounty_per_work_unit_den: u128,
    pub worker_completion_bonus_per_work_unit_num: u128,
    pub worker_completion_bonus_per_work_unit_den: u128,
    pub worker_slash_rebate_per_work_unit_num: u128,
    pub worker_slash_rebate_per_work_unit_den: u128,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TaskMeteringDerivedQueryResponse {
    pub path: String,
    pub accept_floor_pass: bool,
    pub challenge_metered_bonus: u128,
    pub challenge_bonus_total: u128,
    pub worker_completion_bonus: u128,
    pub worker_slash_rebate: u128,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TaskMeteringQueryResponse {
    pub workload_class: String,
    pub metering_schema: String,
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
    pub policy: TaskMeteringPolicyQueryResponse,
    pub derived: TaskMeteringDerivedQueryResponse,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskQueryResponse {
    pub task_id: u64,
    pub status: TaskStatus,
    pub worker: Option<String>,
    pub bounty: u128,
    pub result_hash_hex: Option<String>,
    pub version: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata_compatibility: Option<TaskMetadataCompatibility>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata_runtime_compatible: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata_requires_governance_upgrade: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata_primary_compatibility_finding: Option<TaskMetadataCompatibilityFinding>,
    #[serde(default, skip_serializing_if = "option_vec_is_none_or_empty")]
    pub metadata_compatibility_findings: Option<Vec<TaskMetadataCompatibilityFinding>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metering: Option<TaskMeteringQueryResponse>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovProposalQueryResponse {
    pub proposal_id: u64,
    pub title: String,
    pub proposer: String,
    pub status: GovProposalStatus,
    pub version: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PendingGovParamUpdateQueryResponse {
    pub key_id: u64,
    pub key: String,
    pub value: String,
    pub activate_at_height: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GovParamQueryResponse {
    pub key_id: u64,
    pub key: String,
    pub value: String,
    pub version: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_update: Option<PendingGovParamUpdateQueryResponse>,
}

/// RPC envelope for oracle admissibility checks.
///
/// This response mirrors oracle-layer confidence accounting for transport
/// purposes only. `ok=true` means the snapshot passed oracle policy checks; it
/// does not imply bridge settlement finality, nor does a structured reject here
/// authorize replay reinterpretation of an already-terminal bridge outcome.
///
/// Layering contract:
/// - oracle validation answers only whether a snapshot is admissible enough to
///   forward downstream;
/// - RPC preserves that confidence accounting and shape-checks the envelope,
///   but does not manufacture new settlement semantics from it;
/// - bridge settlement/finality and replay boundaries remain owned by the
///   bridge layer after heartbeat/finality checks have already passed.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OracleValidateSnapshotResponse {
    pub ok: bool,
    pub now_ts_ms: u64,
    pub observation: OracleValidationObservation,
    pub metrics: OracleValidationMetrics,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl OracleValidateSnapshotResponse {
    fn has_non_empty_error_label(&self) -> bool {
        self.error
            .as_deref()
            .map(str::trim)
            .is_some_and(|label| !label.is_empty())
    }

    fn is_stale_error_label(label: &str) -> bool {
        matches!(label, "stale")
            || label.starts_with("future snapshot:")
            || label.starts_with("stale snapshot:")
            || label.starts_with("snapshot future:")
            || label.starts_with("snapshot stale:")
            || label.starts_with("invalid window:")
            || label.starts_with("invalid window timestamp:")
    }

    fn is_quorum_error_label(label: &str) -> bool {
        matches!(label, "quorum")
            || label.starts_with("insufficient sources:")
            || label.starts_with("inconsistent sample count:")
            || label.starts_with("invalid sample count:")
            || label.starts_with("snapshot hash mismatch:")
            || label.starts_with("snapshot hash is empty")
            || label.starts_with("snapshot hash must be canonical lowercase+trim:")
            || label.starts_with("snapshot hash must be a 64-char lowercase hex digest:")
            || label.starts_with("duplicate source ids are not allowed")
            || label.starts_with("source ids must be sorted canonically:")
            || label.starts_with("feed_id must be canonical lowercase [a-z0-9._-]:")
            || label.starts_with("source_id must be canonical lowercase [a-z0-9._-]:")
            || label.starts_with("feed_id must not be empty")
            || label.starts_with("source_id must not be empty")
    }

    fn is_drift_error_label(label: &str) -> bool {
        matches!(label, "drift")
    }

    fn has_explicit_unclassified_error_label(&self) -> bool {
        self.error
            .as_deref()
            .map(str::trim)
            .is_some_and(|label| {
                !label.is_empty()
                    && !Self::is_stale_error_label(label)
                    && !Self::is_quorum_error_label(label)
                    && !Self::is_drift_error_label(label)
            })
    }

    pub fn classified_reject_total(&self) -> u32 {
        self.metrics.classified_reject_total()
    }

    pub fn classified_outcome_total(&self) -> u32 {
        self.metrics.classified_outcome_total()
    }

    pub fn classified_outcome_conserves_sample_count(&self) -> bool {
        self.metrics.classified_outcome_conserves_sample_count()
    }

    pub fn observation_classified_reject_total(&self) -> u32 {
        self.observation.classified_reject_total()
    }

    pub fn observation_classified_outcome_total(&self) -> u32 {
        self.observation.classified_outcome_total()
    }

    pub fn observation_classified_outcome_conserves_sample_count(&self) -> bool {
        self.observation
            .classified_outcome_conserves_sample_count(self.metrics.sample_count)
    }

    pub fn observation_matches_metrics(&self) -> bool {
        self.observation.stale_reject_total == self.metrics.oracle_stale_reject_total
            && self.observation.quorum_reject_total == self.metrics.oracle_quorum_reject_total
            && self.observation.drift_reject_total == self.metrics.oracle_drift_reject_total
            && self.observation.accepted_total == self.metrics.accepted_total
    }

    /// Some oracle failures are intentionally left unclassified by the oracle
    /// layer (for example malformed payloads or transport/rate failures). RPC
    /// may carry those through as explicit fail-closed errors, but they still
    /// remain *admissibility* failures rather than settlement/finality signals.
    fn has_explicit_unclassified_failure_accounting(&self) -> bool {
        !self.ok
            && self.has_explicit_unclassified_error_label()
            && self.metrics.accepted_total == 0
            && self.classified_reject_total() == 0
            && self.observation_classified_reject_total() == 0
            && self.metrics.sample_count > 0
    }

    fn error_label_matches_accounting(&self) -> bool {
        if self.ok {
            return self.error.is_none();
        }

        let Some(label) = self.error.as_deref().map(str::trim) else {
            return false;
        };

        if Self::is_stale_error_label(label) {
            self.observation.stale_reject_total > 0 && self.metrics.oracle_stale_reject_total > 0
        } else if Self::is_quorum_error_label(label) {
            self.observation.quorum_reject_total > 0
                && self.metrics.oracle_quorum_reject_total > 0
        } else if Self::is_drift_error_label(label) {
            self.observation.drift_reject_total > 0 && self.metrics.oracle_drift_reject_total > 0
        } else {
            self.has_explicit_unclassified_error_label()
                && self.classified_reject_total() == 0
                && self.observation_classified_reject_total() == 0
        }
    }

    /// Verifies that the RPC payload is internally coherent as an oracle
    /// validation envelope.
    ///
    /// This is intentionally narrower than any bridge-side decision: a payload
    /// can be contract-consistent here and still be insufficient for settlement
    /// finality, replay admission, or confirmation-window advancement.
    ///
    /// Layering boundary:
    /// - this helper only checks whether RPC preserved the oracle layer's
    ///   admissibility/confidence accounting without inventing new meaning.
    /// - `sample_count` here counts validation outcomes carried in the response,
    ///   not the number of raw oracle source observations inside a snapshot.
    ///   A single accepted snapshot can therefore legitimately expose
    ///   `oracle_source_cardinality > sample_count` when that snapshot was
    ///   assembled from multiple canonical sources.
    /// - callers must still apply bridge-side replay identity, source/target
    ///   confirmation thresholds, and terminal settlement guards before moving
    ///   any state machine forward.
    pub fn bridge_contract_consistent(&self) -> bool {
        let non_empty_sample = self.metrics.sample_count > 0;
        let result_label_consistent = if self.ok {
            self.error.is_none() && self.metrics.accepted_total == self.metrics.sample_count
        } else {
            self.has_non_empty_error_label() && self.metrics.accepted_total == 0
        };
        let source_cardinality_consistent = if self.metrics.accepted_total > 0 {
            self.metrics.oracle_source_cardinality > 0
        } else {
            true
        };
        let outcome_accounting_consistent = self.classified_outcome_conserves_sample_count()
            && self.observation_classified_outcome_conserves_sample_count();

        non_empty_sample
            && self.observation_matches_metrics()
            && result_label_consistent
            && self.error_label_matches_accounting()
            && source_cardinality_consistent
            && (outcome_accounting_consistent
                || self.has_explicit_unclassified_failure_accounting())
    }
}

impl From<OracleValidationReport> for OracleValidateSnapshotResponse {
    fn from(report: OracleValidationReport) -> Self {
        Self {
            ok: report.ok,
            now_ts_ms: report.now_ts_ms,
            observation: report.observation,
            metrics: report.metrics,
            error: report.error,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventQueryResponse {
    pub event_type: String,
    pub task_id: u64,
    pub from_status: String,
    pub to_status: String,
    pub actor: String,
    pub tx_id: u64,
    pub block_height: u64,
    pub state_root: String,
    pub ts_unix_ms: u128,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub challenger: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tx_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolution_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub treasury_delta: Option<i128>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub challenger_delta: Option<i128>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bond_disposition: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metering: Option<TaskMeteringQueryResponse>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MessageRequestQueryResponse {
    pub request_id: String,
    pub task_id: u64,
    pub channel: String,
    pub user_id: String,
    pub session_id: String,
    pub text: String,
    pub idempotency_key: String,
    pub status: String,
    pub created_at_unix_ms: u128,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestFullQueryResponse {
    pub request: MessageRequestQueryResponse,
    pub verifier_status: Option<String>,
    pub resolution_code: Option<String>,
    pub result_hash: Option<String>,
    pub commit_tx_hash: Option<String>,
    pub reveal_tx_hash: Option<String>,
    pub events: Vec<EventQueryResponse>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AccountState {
    pub address: String,
    pub balance: u128,
    pub nonce: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AccountBalanceQueryResponse {
    pub address: String,
    pub balance: u128,
    pub version: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AccountNonceQueryResponse {
    pub address: String,
    pub nonce: u64,
    pub version: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FaucetRequestResponse {
    pub ok: bool,
    pub code: String,
    pub message: String,
    pub address: String,
    pub requested_amount: u128,
    pub granted_amount: u128,
    pub balance: Option<u128>,
    pub nonce: Option<u64>,
    pub window_seconds: u64,
    pub next_allowed_unix_ms: u128,
    pub version: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RpcErrorResponse {
    pub code: &'static str,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccountQueryError {
    InvalidAddressFormat(String),
    AccountNotFound(String),
}

impl AccountQueryError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidAddressFormat(_) => "INVALID_ADDRESS",
            Self::AccountNotFound(_) => "ACCOUNT_NOT_FOUND",
        }
    }

    pub fn message(&self) -> String {
        match self {
            Self::InvalidAddressFormat(addr) => {
                format!("invalid address format: {}", addr)
            }
            Self::AccountNotFound(addr) => format!("account not found: {}", addr),
        }
    }

    pub fn to_rpc_error(&self) -> RpcErrorResponse {
        RpcErrorResponse {
            code: self.code(),
            message: self.message(),
        }
    }
}

impl std::fmt::Display for AccountQueryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code(), self.message())
    }
}

impl std::error::Error for AccountQueryError {}

pub fn validate_trnm_address(address: &str) -> Result<(), AccountQueryError> {
    let Some(hex_part) = address.strip_prefix("trnm1") else {
        return Err(AccountQueryError::InvalidAddressFormat(address.to_string()));
    };

    // Hot-path parser for RPC account queries: enforce fixed-length lowercase
    // hex suffix using byte checks to avoid UTF-8 char iteration overhead.
    const TRNM_SUFFIX_LEN: usize = 40;
    if hex_part.len() != TRNM_SUFFIX_LEN {
        return Err(AccountQueryError::InvalidAddressFormat(address.to_string()));
    }

    if !hex_part
        .as_bytes()
        .iter()
        .copied()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(AccountQueryError::InvalidAddressFormat(address.to_string()));
    }

    Ok(())
}

pub fn query_account_state(
    accounts: &BTreeMap<String, AccountState>,
    address: &str,
) -> Result<AccountState, AccountQueryError> {
    let normalized_address = address.trim();
    validate_trnm_address(normalized_address)?;
    accounts
        .get(normalized_address)
        .cloned()
        .ok_or_else(|| AccountQueryError::AccountNotFound(normalized_address.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::collections::BTreeMap;

    #[test]
    fn rpc_schema_smoke_task_fields_stable() {
        let task = TaskQueryResponse {
            task_id: 1,
            status: TaskStatus::Open,
            worker: None,
            bounty: 100,
            result_hash_hex: None,
            version: 1,
            metadata_compatibility: None,
            metadata_runtime_compatible: None,
            metadata_requires_governance_upgrade: None,
            metadata_primary_compatibility_finding: None,
            metadata_compatibility_findings: None,
            metering: None,
        };
        let v = serde_json::to_value(task).unwrap();
        let obj = v.as_object().unwrap();
        for k in [
            "task_id",
            "status",
            "worker",
            "bounty",
            "result_hash_hex",
            "version",
        ] {
            assert!(obj.contains_key(k), "missing key: {}", k);
        }
    }

    #[test]
    fn rpc_task_query_omits_metering_when_absent() {
        let task = TaskQueryResponse {
            task_id: 1,
            status: TaskStatus::Open,
            worker: None,
            bounty: 100,
            result_hash_hex: None,
            version: 1,
            metadata_compatibility: None,
            metadata_runtime_compatible: None,
            metadata_requires_governance_upgrade: None,
            metadata_primary_compatibility_finding: None,
            metadata_compatibility_findings: None,
            metering: None,
        };
        let v = serde_json::to_value(task).unwrap();
        assert!(v.get("metering").is_none());
    }

    #[test]
    fn rpc_task_query_rejects_unknown_fields_fail_closed() {
        let err = serde_json::from_value::<TaskQueryResponse>(json!({
            "task_id": 1,
            "status": "Open",
            "worker": null,
            "bounty": 100,
            "result_hash_hex": null,
            "version": 1,
            "unexpected": true
        }))
        .expect_err("task query schema should reject unknown fields");
        assert!(err.to_string().contains("unexpected"));
    }

    #[test]
    fn rpc_gov_param_query_omits_pending_update_when_absent() {
        let response = GovParamQueryResponse {
            key_id: 7,
            key: "emergency_pause".into(),
            value: "false".into(),
            version: 3,
            pending_update: None,
        };
        let v = serde_json::to_value(response).unwrap();
        assert!(v.get("pending_update").is_none());
    }

    #[test]
    fn rpc_gov_param_query_includes_pending_update_when_present() {
        let response = GovParamQueryResponse {
            key_id: 12,
            key: "runtime_metadata_schema".into(),
            value: "v2".into(),
            version: 8,
            pending_update: Some(PendingGovParamUpdateQueryResponse {
                key_id: 12,
                key: "runtime_metadata_schema".into(),
                value: "v3".into(),
                activate_at_height: 4_096,
            }),
        };
        let v = serde_json::to_value(response).unwrap();
        assert_eq!(v["pending_update"]["key_id"], json!(12));
        assert_eq!(v["pending_update"]["key"], json!("runtime_metadata_schema"));
        assert_eq!(v["pending_update"]["value"], json!("v3"));
        assert_eq!(v["pending_update"]["activate_at_height"], json!(4_096));
    }

    #[test]
    fn rpc_task_query_includes_metering_when_present() {
        let task = TaskQueryResponse {
            task_id: 1,
            status: TaskStatus::Revealed,
            worker: Some("worker-1".into()),
            bounty: 100,
            result_hash_hex: Some("abcd".into()),
            version: 3,
            metadata_compatibility: None,
            metadata_runtime_compatible: None,
            metadata_requires_governance_upgrade: None,
            metadata_primary_compatibility_finding: None,
            metadata_compatibility_findings: None,
            metering: Some(TaskMeteringQueryResponse {
                workload_class: "llm_inference".into(),
                metering_schema: "llm_token_meter_v1".into(),
                receipt_hash: "deadbeef".into(),
                prompt_tokens: 128,
                generated_tokens: 32,
                decode_steps: 32,
                kv_bytes_moved: 4096,
                normalized_work_units: 192,
                prompt_token_weight: 1,
                generated_token_weight: 1,
                decode_step_weight: 1,
                kv_byte_weight: 0,
                policy: TaskMeteringPolicyQueryResponse {
                    snapshot_version: 1,
                    min_accept_work_units: 0,
                    challenge_success_bounty_base: 1,
                    challenge_success_bounty_per_work_unit_num: 1,
                    challenge_success_bounty_per_work_unit_den: 192,
                    worker_completion_bonus_per_work_unit_num: 1,
                    worker_completion_bonus_per_work_unit_den: 192,
                    worker_slash_rebate_per_work_unit_num: 1,
                    worker_slash_rebate_per_work_unit_den: 192,
                },
                derived: TaskMeteringDerivedQueryResponse {
                    path: "Revealed".into(),
                    accept_floor_pass: true,
                    challenge_metered_bonus: 1,
                    challenge_bonus_total: 2,
                    worker_completion_bonus: 1,
                    worker_slash_rebate: 1,
                },
            }),
        };
        let v = serde_json::to_value(task).unwrap();
        assert_eq!(v["metering"]["normalized_work_units"], json!(192));
        assert_eq!(v["metering"]["policy"]["snapshot_version"], json!(1));
        assert_eq!(
            v["metering"]["policy"]["challenge_success_bounty_base"],
            json!(1)
        );
        assert_eq!(v["metering"]["derived"]["challenge_bonus_total"], json!(2));
        assert_eq!(v["metering"]["derived"]["accept_floor_pass"], json!(true));
    }

    #[test]
    fn rpc_event_query_omits_metering_when_absent() {
        let event = EventQueryResponse {
            event_type: "commit".into(),
            task_id: 1,
            from_status: "Accepted".into(),
            to_status: "Committed".into(),
            actor: "worker-a".into(),
            tx_id: 10,
            block_height: 3,
            state_root: "abc".into(),
            ts_unix_ms: 123,
            signer: None,
            challenger: None,
            tx_hash: None,
            resolution_code: None,
            treasury_delta: None,
            challenger_delta: None,
            bond_disposition: None,
            metering: None,
        };
        let v = serde_json::to_value(event).unwrap();
        assert!(v.get("metering").is_none());
    }

    #[test]
    fn rpc_event_query_rejects_unknown_fields_fail_closed() {
        let err = serde_json::from_value::<EventQueryResponse>(json!({
            "event_type": "commit",
            "task_id": 1,
            "from_status": "Assigned",
            "to_status": "Committed",
            "actor": "worker1",
            "tx_id": 7,
            "block_height": 2,
            "state_root": "abc",
            "ts_unix_ms": 1,
            "unexpected": true
        }))
        .expect_err("event query schema should reject unknown fields");
        assert!(err.to_string().contains("unexpected"));
    }

    #[test]
    fn oracle_validate_snapshot_response_schema_smoke_stable() {
        let out = OracleValidateSnapshotResponse {
            ok: true,
            now_ts_ms: 123,
            observation: OracleValidationObservation {
                stale_reject_total: 0,
                quorum_reject_total: 0,
                drift_reject_total: 0,
                accepted_total: 1,
            },
            metrics: OracleValidationMetrics {
                oracle_stale_reject_total: 0,
                oracle_quorum_reject_total: 0,
                oracle_drift_reject_total: 0,
                oracle_source_cardinality: 2,
                accepted_total: 1,
                sample_count: 1,
            },
            error: None,
        };
        let v = serde_json::to_value(out).unwrap();
        let obj = v.as_object().unwrap();
        for k in ["ok", "now_ts_ms", "observation", "metrics"] {
            assert!(obj.contains_key(k), "missing key: {}", k);
        }
        assert!(!obj.contains_key("error"));
    }

    #[test]
    fn oracle_validate_snapshot_response_nested_metric_keys_remain_stable() {
        let out = OracleValidateSnapshotResponse {
            ok: false,
            now_ts_ms: 456,
            observation: OracleValidationObservation {
                stale_reject_total: 1,
                quorum_reject_total: 0,
                drift_reject_total: 0,
                accepted_total: 0,
            },
            metrics: OracleValidationMetrics {
                oracle_stale_reject_total: 1,
                oracle_quorum_reject_total: 0,
                oracle_drift_reject_total: 0,
                oracle_source_cardinality: 2,
                accepted_total: 0,
                sample_count: 1,
            },
            error: Some("stale".into()),
        };

        let v = serde_json::to_value(out).unwrap();
        let observation = v["observation"].as_object().unwrap();
        let metrics = v["metrics"].as_object().unwrap();

        let mut observation_keys = observation.keys().map(String::as_str).collect::<Vec<_>>();
        observation_keys.sort_unstable();
        let mut metrics_keys = metrics.keys().map(String::as_str).collect::<Vec<_>>();
        metrics_keys.sort_unstable();

        assert_eq!(
            observation_keys,
            vec![
                "accepted_total",
                "drift_reject_total",
                "quorum_reject_total",
                "stale_reject_total",
            ]
        );
        assert_eq!(
            metrics_keys,
            vec![
                "accepted_total",
                "oracle_drift_reject_total",
                "oracle_quorum_reject_total",
                "oracle_source_cardinality",
                "oracle_stale_reject_total",
                "sample_count",
            ]
        );
    }

    #[test]
    fn oracle_validation_report_into_rpc_response_preserves_contract_shape() {
        let report = OracleValidationReport {
            ok: false,
            now_ts_ms: 456,
            observation: OracleValidationObservation {
                stale_reject_total: 1,
                quorum_reject_total: 0,
                drift_reject_total: 0,
                accepted_total: 0,
            },
            metrics: OracleValidationMetrics {
                oracle_stale_reject_total: 1,
                oracle_quorum_reject_total: 0,
                oracle_drift_reject_total: 0,
                oracle_source_cardinality: 2,
                accepted_total: 0,
                sample_count: 1,
            },
            error: Some("stale".into()),
        };

        let out: OracleValidateSnapshotResponse = report.clone().into();
        assert_eq!(out.ok, report.ok);
        assert_eq!(out.now_ts_ms, report.now_ts_ms);
        assert_eq!(out.observation, report.observation);
        assert_eq!(out.metrics, report.metrics);
        assert_eq!(out.error, report.error);

        let v = serde_json::to_value(out).unwrap();
        assert_eq!(v["error"], "stale");
        assert_eq!(v["metrics"]["sample_count"], 1);
        assert_eq!(v["metrics"]["oracle_stale_reject_total"], 1);
    }

    #[test]
    fn oracle_validation_report_into_rpc_response_omits_success_error_field() {
        let report = OracleValidationReport {
            ok: true,
            now_ts_ms: 457,
            observation: OracleValidationObservation {
                stale_reject_total: 0,
                quorum_reject_total: 0,
                drift_reject_total: 0,
                accepted_total: 1,
            },
            metrics: OracleValidationMetrics {
                oracle_stale_reject_total: 0,
                oracle_quorum_reject_total: 0,
                oracle_drift_reject_total: 0,
                oracle_source_cardinality: 2,
                accepted_total: 1,
                sample_count: 1,
            },
            error: None,
        };

        let out: OracleValidateSnapshotResponse = report.clone().into();
        assert_eq!(out.ok, report.ok);
        assert_eq!(out.now_ts_ms, report.now_ts_ms);
        assert_eq!(out.observation, report.observation);
        assert_eq!(out.metrics, report.metrics);
        assert_eq!(out.error, None);

        let v = serde_json::to_value(out).unwrap();
        let obj = v.as_object().unwrap();
        assert!(!obj.contains_key("error"));
        assert_eq!(v["observation"]["accepted_total"], 1);
        assert_eq!(v["metrics"]["accepted_total"], 1);
    }

    #[test]
    fn oracle_validation_report_into_rpc_response_preserves_future_snapshot_as_stale_only() {
        let report = OracleValidationReport {
            ok: false,
            now_ts_ms: 10_000,
            observation: OracleValidationObservation {
                stale_reject_total: 1,
                quorum_reject_total: 0,
                drift_reject_total: 0,
                accepted_total: 0,
            },
            metrics: OracleValidationMetrics {
                oracle_stale_reject_total: 1,
                oracle_quorum_reject_total: 0,
                oracle_drift_reject_total: 0,
                oracle_source_cardinality: 2,
                accepted_total: 0,
                sample_count: 1,
            },
            error: Some("future snapshot: ts=10001, now=10000".into()),
        };

        let out: OracleValidateSnapshotResponse = report.into();

        assert!(!out.ok);
        assert_eq!(out.now_ts_ms, 10_000);
        assert_eq!(out.observation.stale_reject_total, 1);
        assert_eq!(out.observation.quorum_reject_total, 0);
        assert_eq!(out.observation.drift_reject_total, 0);
        assert_eq!(out.observation.accepted_total, 0);
        assert_eq!(out.metrics.oracle_stale_reject_total, 1);
        assert_eq!(out.metrics.oracle_quorum_reject_total, 0);
        assert_eq!(out.metrics.oracle_drift_reject_total, 0);
        assert_eq!(out.metrics.oracle_source_cardinality, 2);
        assert_eq!(out.metrics.accepted_total, 0);
        assert_eq!(out.metrics.sample_count, 1);
        assert_eq!(
            out.error.as_deref(),
            Some("future snapshot: ts=10001, now=10000")
        );
        assert_eq!(out.classified_reject_total(), 1);
        assert_eq!(out.classified_outcome_total(), 1);
        assert!(out.classified_outcome_conserves_sample_count());
        assert!(out.observation_matches_metrics());
        assert!(out.bridge_contract_consistent());
    }

    #[test]
    fn oracle_validation_response_bridge_contract_consistent_accepts_snapshot_future_label_variant() {
        let out = OracleValidateSnapshotResponse {
            ok: false,
            now_ts_ms: 10_000,
            observation: OracleValidationObservation {
                stale_reject_total: 1,
                quorum_reject_total: 0,
                drift_reject_total: 0,
                accepted_total: 0,
            },
            metrics: OracleValidationMetrics {
                oracle_stale_reject_total: 1,
                oracle_quorum_reject_total: 0,
                oracle_drift_reject_total: 0,
                oracle_source_cardinality: 2,
                accepted_total: 0,
                sample_count: 1,
            },
            error: Some("snapshot future: observed_at_ms=10001 now_ts_ms=10000".into()),
        };

        assert_eq!(out.classified_reject_total(), 1);
        assert_eq!(out.classified_outcome_total(), 1);
        assert!(out.classified_outcome_conserves_sample_count());
        assert!(out.observation_matches_metrics());
        assert!(out.bridge_contract_consistent());
    }

    #[test]
    fn oracle_validation_response_bridge_contract_consistent_accepts_snapshot_stale_label_variant() {
        let out = OracleValidateSnapshotResponse {
            ok: false,
            now_ts_ms: 70_001,
            observation: OracleValidationObservation {
                stale_reject_total: 1,
                quorum_reject_total: 0,
                drift_reject_total: 0,
                accepted_total: 0,
            },
            metrics: OracleValidationMetrics {
                oracle_stale_reject_total: 1,
                oracle_quorum_reject_total: 0,
                oracle_drift_reject_total: 0,
                oracle_source_cardinality: 2,
                accepted_total: 0,
                sample_count: 1,
            },
            error: Some("snapshot stale: observed_at_ms=10000 max_staleness_ms=60000".into()),
        };

        assert_eq!(out.classified_reject_total(), 1);
        assert_eq!(out.classified_outcome_total(), 1);
        assert!(out.classified_outcome_conserves_sample_count());
        assert!(out.observation_matches_metrics());
        assert!(out.bridge_contract_consistent());
    }

    #[test]
    fn oracle_validation_report_into_rpc_response_preserves_quorum_and_drift_labels() {
        let quorum_report = OracleValidationReport {
            ok: false,
            now_ts_ms: 788,
            observation: OracleValidationObservation {
                stale_reject_total: 0,
                quorum_reject_total: 1,
                drift_reject_total: 0,
                accepted_total: 0,
            },
            metrics: OracleValidationMetrics {
                oracle_stale_reject_total: 0,
                oracle_quorum_reject_total: 1,
                oracle_drift_reject_total: 0,
                oracle_source_cardinality: 1,
                accepted_total: 0,
                sample_count: 1,
            },
            error: Some("quorum".into()),
        };
        let drift_report = OracleValidationReport {
            ok: false,
            now_ts_ms: 789,
            observation: OracleValidationObservation {
                stale_reject_total: 0,
                quorum_reject_total: 0,
                drift_reject_total: 1,
                accepted_total: 0,
            },
            metrics: OracleValidationMetrics {
                oracle_stale_reject_total: 0,
                oracle_quorum_reject_total: 0,
                oracle_drift_reject_total: 1,
                oracle_source_cardinality: 2,
                accepted_total: 0,
                sample_count: 1,
            },
            error: Some("drift".into()),
        };

        let quorum_out: OracleValidateSnapshotResponse = quorum_report.into();
        let drift_out: OracleValidateSnapshotResponse = drift_report.into();

        assert_eq!(quorum_out.classified_reject_total(), 1);
        assert_eq!(quorum_out.classified_outcome_total(), 1);
        assert!(quorum_out.classified_outcome_conserves_sample_count());
        let quorum_json = serde_json::to_value(quorum_out).unwrap();
        assert_eq!(quorum_json["error"], "quorum");
        assert_eq!(quorum_json["metrics"]["oracle_quorum_reject_total"], 1);
        assert_eq!(quorum_json["metrics"]["oracle_source_cardinality"], 1);

        assert_eq!(drift_out.classified_reject_total(), 1);
        assert_eq!(drift_out.classified_outcome_total(), 1);
        assert!(drift_out.classified_outcome_conserves_sample_count());
        let drift_json = serde_json::to_value(drift_out).unwrap();
        assert_eq!(drift_json["error"], "drift");
        assert_eq!(drift_json["metrics"]["oracle_drift_reject_total"], 1);
        assert_eq!(drift_json["metrics"]["oracle_source_cardinality"], 2);
    }

    #[test]
    fn oracle_validation_report_into_rpc_response_preserves_rate_error_label() {
        let report = OracleValidationReport {
            ok: false,
            now_ts_ms: 789,
            observation: OracleValidationObservation {
                stale_reject_total: 0,
                quorum_reject_total: 0,
                drift_reject_total: 0,
                accepted_total: 0,
            },
            metrics: OracleValidationMetrics {
                oracle_stale_reject_total: 0,
                oracle_quorum_reject_total: 0,
                oracle_drift_reject_total: 0,
                oracle_source_cardinality: 2,
                accepted_total: 0,
                sample_count: 1,
            },
            error: Some("rate".into()),
        };

        let out: OracleValidateSnapshotResponse = report.into();
        assert_eq!(out.classified_reject_total(), 0);
        assert_eq!(out.classified_outcome_total(), 0);
        assert!(!out.classified_outcome_conserves_sample_count());
        let v = serde_json::to_value(out).unwrap();
        assert_eq!(v["error"], "rate");
        assert_eq!(v["metrics"]["sample_count"], 1);
        assert_eq!(v["metrics"]["oracle_source_cardinality"], 2);
    }

    #[test]
    fn oracle_validation_report_into_rpc_response_preserves_unmapped_error_string() {
        let report = OracleValidationReport {
            ok: false,
            now_ts_ms: 790,
            observation: OracleValidationObservation {
                stale_reject_total: 0,
                quorum_reject_total: 0,
                drift_reject_total: 0,
                accepted_total: 0,
            },
            metrics: OracleValidationMetrics {
                oracle_stale_reject_total: 0,
                oracle_quorum_reject_total: 0,
                oracle_drift_reject_total: 0,
                oracle_source_cardinality: 2,
                accepted_total: 0,
                sample_count: 1,
            },
            error: Some("snapshot hash mismatch: expected=abc, actual=def".into()),
        };

        let out: OracleValidateSnapshotResponse = report.into();
        assert_eq!(out.classified_reject_total(), 0);
        assert_eq!(out.classified_outcome_total(), 0);
        assert!(!out.classified_outcome_conserves_sample_count());
        let v = serde_json::to_value(out).unwrap();
        assert_eq!(
            v["error"],
            "snapshot hash mismatch: expected=abc, actual=def"
        );
        assert_eq!(v["metrics"]["sample_count"], 1);
        assert_eq!(v["metrics"]["oracle_source_cardinality"], 2);
    }

    #[test]
    fn oracle_validation_report_into_rpc_response_keeps_single_snapshot_cardinality_on_unclassified_error(
    ) {
        let report = OracleValidationReport {
            ok: false,
            now_ts_ms: 791,
            observation: OracleValidationObservation {
                stale_reject_total: 0,
                quorum_reject_total: 0,
                drift_reject_total: 0,
                accepted_total: 0,
            },
            metrics: OracleValidationMetrics {
                oracle_stale_reject_total: 0,
                oracle_quorum_reject_total: 0,
                oracle_drift_reject_total: 0,
                oracle_source_cardinality: 3,
                accepted_total: 0,
                sample_count: 1,
            },
            error: Some("invalid policy: max_deviation_bps must be <= 10000".into()),
        };

        let out: OracleValidateSnapshotResponse = report.into();
        let v = serde_json::to_value(out).unwrap();
        assert_eq!(
            v["error"],
            "invalid policy: max_deviation_bps must be <= 10000"
        );
        assert_eq!(v["metrics"]["accepted_total"], 0);
        assert_eq!(v["metrics"]["oracle_source_cardinality"], 3);
        assert_eq!(v["metrics"]["sample_count"], 1);
    }

    #[test]
    fn oracle_validation_report_into_rpc_response_preserves_classified_sample_count_invariant() {
        let ok_report = OracleValidationReport {
            ok: true,
            now_ts_ms: 123,
            observation: OracleValidationObservation {
                stale_reject_total: 0,
                quorum_reject_total: 0,
                drift_reject_total: 0,
                accepted_total: 1,
            },
            metrics: OracleValidationMetrics {
                oracle_stale_reject_total: 0,
                oracle_quorum_reject_total: 0,
                oracle_drift_reject_total: 0,
                oracle_source_cardinality: 2,
                accepted_total: 1,
                sample_count: 1,
            },
            error: None,
        };
        let stale_report = OracleValidationReport {
            ok: false,
            now_ts_ms: 124,
            observation: OracleValidationObservation {
                stale_reject_total: 1,
                quorum_reject_total: 0,
                drift_reject_total: 0,
                accepted_total: 0,
            },
            metrics: OracleValidationMetrics {
                oracle_stale_reject_total: 1,
                oracle_quorum_reject_total: 0,
                oracle_drift_reject_total: 0,
                oracle_source_cardinality: 2,
                accepted_total: 0,
                sample_count: 1,
            },
            error: Some("stale".into()),
        };

        let ok_out: OracleValidateSnapshotResponse = ok_report.into();
        let stale_out: OracleValidateSnapshotResponse = stale_report.into();

        assert_eq!(ok_out.classified_reject_total(), 0);
        assert_eq!(ok_out.observation_classified_reject_total(), 0);
        assert_eq!(ok_out.classified_outcome_total(), 1);
        assert_eq!(ok_out.observation_classified_outcome_total(), 1);
        assert!(ok_out.classified_outcome_conserves_sample_count());
        assert!(ok_out.observation_classified_outcome_conserves_sample_count());

        assert_eq!(stale_out.classified_reject_total(), 1);
        assert_eq!(stale_out.observation_classified_reject_total(), 1);
        assert_eq!(stale_out.classified_outcome_total(), 1);
        assert_eq!(stale_out.observation_classified_outcome_total(), 1);
        assert!(stale_out.classified_outcome_conserves_sample_count());
        assert!(stale_out.observation_classified_outcome_conserves_sample_count());
    }

    #[test]
    fn rpc_schema_smoke_event_fields_stable() {
        let evt = EventQueryResponse {
            event_type: "commit".into(),
            task_id: 1,
            from_status: "Assigned".into(),
            to_status: "Committed".into(),
            actor: "worker1".into(),
            tx_id: 7,
            block_height: 2,
            state_root: "abc".into(),
            ts_unix_ms: 1,
            signer: None,
            challenger: None,
            tx_hash: None,
            resolution_code: None,
            treasury_delta: None,
            challenger_delta: None,
            bond_disposition: None,
            metering: None,
        };
        let v = serde_json::to_value(evt).unwrap();
        assert_eq!(
            v,
            json!({
                "event_type":"commit",
                "task_id":1,
                "from_status":"Assigned",
                "to_status":"Committed",
                "actor":"worker1",
                "tx_id":7,
                "block_height":2,
                "state_root":"abc",
                "ts_unix_ms":1
            })
        );
    }

    #[test]
    fn query_account_state_ok() {
        let address = format!("trnm1{}", "1".repeat(40));
        let mut accounts = BTreeMap::new();
        accounts.insert(
            address.clone(),
            AccountState {
                address: address.clone(),
                balance: 42,
                nonce: 7,
            },
        );

        let got = query_account_state(&accounts, &address).unwrap();
        assert_eq!(got.balance, 42);
        assert_eq!(got.nonce, 7);
    }

    #[test]
    fn query_account_state_address_not_found() {
        let accounts = BTreeMap::new();
        let addr = &format!("trnm1{}", "2".repeat(40));
        let err = query_account_state(&accounts, addr).unwrap_err();
        assert_eq!(err.code(), "ACCOUNT_NOT_FOUND");
    }

    #[test]
    fn query_account_state_invalid_input() {
        let accounts = BTreeMap::new();
        let err = query_account_state(&accounts, "not-an-address").unwrap_err();
        assert_eq!(err.code(), "INVALID_ADDRESS");
    }

    #[test]
    fn query_account_state_accepts_whitespace_drift() {
        let address = format!("trnm1{}", "1".repeat(40));
        let mut accounts = BTreeMap::new();
        accounts.insert(
            address.clone(),
            AccountState {
                address: address.clone(),
                balance: 42,
                nonce: 7,
            },
        );

        let got = query_account_state(&accounts, &format!("  {}\n", address)).unwrap();
        assert_eq!(got.balance, 42);
        assert_eq!(got.nonce, 7);
    }

    #[test]
    fn query_account_state_accepts_unicode_whitespace_drift() {
        let address = format!("trnm1{}", "1".repeat(40));
        let mut accounts = BTreeMap::new();
        accounts.insert(
            address.clone(),
            AccountState {
                address: address.clone(),
                balance: 42,
                nonce: 7,
            },
        );

        let got = query_account_state(&accounts, &format!("\u{2003}{}\u{00a0}", address)).unwrap();
        assert_eq!(got.balance, 42);
        assert_eq!(got.nonce, 7);
    }

    #[test]
    fn query_account_state_rejects_non_hex_suffix() {
        let accounts = BTreeMap::new();
        let bad = format!("trnm1{}", "z".repeat(40));
        let err = query_account_state(&accounts, &bad).unwrap_err();
        assert_eq!(err.code(), "INVALID_ADDRESS");
    }

    #[test]
    fn query_account_state_rejects_uppercase_hex_suffix() {
        let accounts = BTreeMap::new();
        let bad = format!("trnm1{}", "A".repeat(40));
        let err = query_account_state(&accounts, &bad).unwrap_err();
        assert_eq!(err.code(), "INVALID_ADDRESS");
    }

    #[test]
    fn query_account_state_rejects_punctuation_wrapped_address() {
        let accounts = BTreeMap::new();
        let wrapped = format!("[trnm1{}]", "1".repeat(40));
        let err = query_account_state(&accounts, &wrapped).unwrap_err();
        assert_eq!(err.code(), "INVALID_ADDRESS");
    }

    #[test]
    fn query_account_state_rejects_wrong_suffix_length() {
        let accounts = BTreeMap::new();

        let short = format!("trnm1{}", "1".repeat(39));
        assert_eq!(
            query_account_state(&accounts, &short).unwrap_err().code(),
            "INVALID_ADDRESS"
        );

        let long = format!("trnm1{}", "1".repeat(41));
        assert_eq!(
            query_account_state(&accounts, &long).unwrap_err().code(),
            "INVALID_ADDRESS"
        );
    }

    #[test]
    fn oracle_validation_response_preserves_canonical_source_cardinality_value() {
        let report = OracleValidationReport {
            ok: false,
            now_ts_ms: 791,
            observation: OracleValidationObservation {
                stale_reject_total: 0,
                quorum_reject_total: 1,
                drift_reject_total: 0,
                accepted_total: 0,
            },
            metrics: OracleValidationMetrics {
                oracle_stale_reject_total: 0,
                oracle_quorum_reject_total: 1,
                oracle_drift_reject_total: 0,
                oracle_source_cardinality: 2,
                accepted_total: 0,
                sample_count: 1,
            },
            error: Some("quorum".into()),
        };

        let out: OracleValidateSnapshotResponse = report.into();
        assert_eq!(out.metrics.oracle_source_cardinality, 2);
        let v = serde_json::to_value(out).unwrap();
        assert_eq!(v["metrics"]["oracle_source_cardinality"], 2);
    }

    #[test]
    fn oracle_validation_response_observation_helpers_keep_unclassified_errors_out_of_classified_totals(
    ) {
        let report = OracleValidationReport {
            ok: false,
            now_ts_ms: 792,
            observation: OracleValidationObservation {
                stale_reject_total: 0,
                quorum_reject_total: 0,
                drift_reject_total: 0,
                accepted_total: 0,
            },
            metrics: OracleValidationMetrics {
                oracle_stale_reject_total: 0,
                oracle_quorum_reject_total: 0,
                oracle_drift_reject_total: 0,
                oracle_source_cardinality: 3,
                accepted_total: 0,
                sample_count: 1,
            },
            error: Some("rate".into()),
        };

        let out: OracleValidateSnapshotResponse = report.into();
        assert_eq!(out.classified_reject_total(), 0);
        assert_eq!(out.observation_classified_reject_total(), 0);
        assert_eq!(out.classified_outcome_total(), 0);
        assert_eq!(out.observation_classified_outcome_total(), 0);
        assert!(!out.classified_outcome_conserves_sample_count());
        assert!(!out.observation_classified_outcome_conserves_sample_count());
    }

    #[test]
    fn oracle_validation_response_bridge_contract_consistent_allows_explicit_unclassified_failures()
    {
        let report = OracleValidationReport {
            ok: false,
            now_ts_ms: 793,
            observation: OracleValidationObservation {
                stale_reject_total: 0,
                quorum_reject_total: 0,
                drift_reject_total: 0,
                accepted_total: 0,
            },
            metrics: OracleValidationMetrics {
                oracle_stale_reject_total: 0,
                oracle_quorum_reject_total: 0,
                oracle_drift_reject_total: 0,
                oracle_source_cardinality: 1,
                accepted_total: 0,
                sample_count: 1,
            },
            error: Some("rate".into()),
        };

        let out: OracleValidateSnapshotResponse = report.into();

        assert!(out.observation_matches_metrics());
        assert_eq!(out.classified_outcome_total(), 0);
        assert_eq!(out.observation_classified_outcome_total(), 0);
        assert!(!out.classified_outcome_conserves_sample_count());
        assert!(!out.observation_classified_outcome_conserves_sample_count());
        assert!(out.bridge_contract_consistent());
    }

    #[test]
    fn oracle_validation_response_bridge_contract_consistent_allows_unclassified_failures_with_repeated_observations()
    {
        let report = OracleValidationReport {
            ok: false,
            now_ts_ms: 794,
            observation: OracleValidationObservation {
                stale_reject_total: 0,
                quorum_reject_total: 0,
                drift_reject_total: 0,
                accepted_total: 0,
            },
            metrics: OracleValidationMetrics {
                oracle_stale_reject_total: 0,
                oracle_quorum_reject_total: 0,
                oracle_drift_reject_total: 0,
                oracle_source_cardinality: 2,
                accepted_total: 0,
                sample_count: 3,
            },
            error: Some("transport timeout".into()),
        };

        let out: OracleValidateSnapshotResponse = report.into();

        assert!(out.observation_matches_metrics());
        assert_eq!(out.metrics.oracle_source_cardinality, 2);
        assert_eq!(out.metrics.sample_count, 3);
        assert_eq!(out.classified_outcome_total(), 0);
        assert_eq!(out.observation_classified_outcome_total(), 0);
        assert!(!out.classified_outcome_conserves_sample_count());
        assert!(!out.observation_classified_outcome_conserves_sample_count());
        assert!(out.bridge_contract_consistent());
    }

    #[test]
    fn oracle_validation_response_preserves_rate_label_and_raw_sample_count() {
        let out: OracleValidateSnapshotResponse = OracleValidationReport {
            ok: false,
            now_ts_ms: 794,
            observation: OracleValidationObservation {
                stale_reject_total: 0,
                quorum_reject_total: 0,
                drift_reject_total: 0,
                accepted_total: 0,
            },
            metrics: OracleValidationMetrics {
                oracle_stale_reject_total: 0,
                oracle_quorum_reject_total: 0,
                oracle_drift_reject_total: 0,
                oracle_source_cardinality: 2,
                accepted_total: 0,
                sample_count: 3,
            },
            error: Some("rate".into()),
        }
        .into();

        let v = serde_json::to_value(&out).expect("serialize rate response");

        assert_eq!(v["error"], "rate");
        assert_eq!(v["metrics"]["sample_count"], 3);
        assert_eq!(v["metrics"]["accepted_total"], 0);
        assert_eq!(v["metrics"]["oracle_source_cardinality"], 2);
        assert_eq!(v["observation"]["accepted_total"], 0);
        assert_eq!(out.metrics.sample_count, 3);
        assert_eq!(out.classified_outcome_total(), 0);
        assert!(!out.classified_outcome_conserves_sample_count());
        assert!(out.bridge_contract_consistent());
    }

    #[test]
    fn oracle_validation_response_bridge_contract_consistent_for_classified_outcomes() {
        let reports = [
            OracleValidationReport {
                ok: true,
                now_ts_ms: 790,
                observation: OracleValidationObservation {
                    stale_reject_total: 0,
                    quorum_reject_total: 0,
                    drift_reject_total: 0,
                    accepted_total: 1,
                },
                metrics: OracleValidationMetrics {
                    oracle_stale_reject_total: 0,
                    oracle_quorum_reject_total: 0,
                    oracle_drift_reject_total: 0,
                    oracle_source_cardinality: 1,
                    accepted_total: 1,
                    sample_count: 1,
                },
                error: None,
            },
            OracleValidationReport {
                ok: false,
                now_ts_ms: 791,
                observation: OracleValidationObservation {
                    stale_reject_total: 1,
                    quorum_reject_total: 0,
                    drift_reject_total: 0,
                    accepted_total: 0,
                },
                metrics: OracleValidationMetrics {
                    oracle_stale_reject_total: 1,
                    oracle_quorum_reject_total: 0,
                    oracle_drift_reject_total: 0,
                    oracle_source_cardinality: 1,
                    accepted_total: 0,
                    sample_count: 1,
                },
                error: Some("stale".into()),
            },
            OracleValidationReport {
                ok: false,
                now_ts_ms: 792,
                observation: OracleValidationObservation {
                    stale_reject_total: 0,
                    quorum_reject_total: 1,
                    drift_reject_total: 0,
                    accepted_total: 0,
                },
                metrics: OracleValidationMetrics {
                    oracle_stale_reject_total: 0,
                    oracle_quorum_reject_total: 1,
                    oracle_drift_reject_total: 0,
                    oracle_source_cardinality: 1,
                    accepted_total: 0,
                    sample_count: 1,
                },
                error: Some("quorum".into()),
            },
            OracleValidationReport {
                ok: false,
                now_ts_ms: 793,
                observation: OracleValidationObservation {
                    stale_reject_total: 0,
                    quorum_reject_total: 0,
                    drift_reject_total: 1,
                    accepted_total: 0,
                },
                metrics: OracleValidationMetrics {
                    oracle_stale_reject_total: 0,
                    oracle_quorum_reject_total: 0,
                    oracle_drift_reject_total: 1,
                    oracle_source_cardinality: 1,
                    accepted_total: 0,
                    sample_count: 1,
                },
                error: Some("drift".into()),
            },
            OracleValidationReport {
                ok: false,
                now_ts_ms: 794,
                observation: OracleValidationObservation {
                    stale_reject_total: 0,
                    quorum_reject_total: 1,
                    drift_reject_total: 0,
                    accepted_total: 0,
                },
                metrics: OracleValidationMetrics {
                    oracle_stale_reject_total: 0,
                    oracle_quorum_reject_total: 1,
                    oracle_drift_reject_total: 0,
                    oracle_source_cardinality: 2,
                    accepted_total: 0,
                    sample_count: 1,
                },
                error: Some("snapshot hash mismatch: expected=abc, actual=def".into()),
            },
            OracleValidationReport {
                ok: false,
                now_ts_ms: 794,
                observation: OracleValidationObservation {
                    stale_reject_total: 0,
                    quorum_reject_total: 1,
                    drift_reject_total: 0,
                    accepted_total: 0,
                },
                metrics: OracleValidationMetrics {
                    oracle_stale_reject_total: 0,
                    oracle_quorum_reject_total: 1,
                    oracle_drift_reject_total: 0,
                    oracle_source_cardinality: 1,
                    accepted_total: 0,
                    sample_count: 1,
                },
                error: Some("insufficient sources: min=2, sources=1, sample_count=1".into()),
            },
            OracleValidationReport {
                ok: false,
                now_ts_ms: 795,
                observation: OracleValidationObservation {
                    stale_reject_total: 1,
                    quorum_reject_total: 0,
                    drift_reject_total: 0,
                    accepted_total: 0,
                },
                metrics: OracleValidationMetrics {
                    oracle_stale_reject_total: 1,
                    oracle_quorum_reject_total: 0,
                    oracle_drift_reject_total: 0,
                    oracle_source_cardinality: 2,
                    accepted_total: 0,
                    sample_count: 1,
                },
                error: Some("invalid window timestamp: observed=170, window_start=200".into()),
            },
        ];

        for report in reports {
            let out: OracleValidateSnapshotResponse = report.into();
            assert!(out.observation_matches_metrics());
            assert!(out.bridge_contract_consistent());
        }
    }

    #[test]
    fn oracle_validation_response_bridge_contract_consistent_rejects_counter_mismatch() {
        let report = OracleValidationReport {
            ok: false,
            now_ts_ms: 794,
            observation: OracleValidationObservation {
                stale_reject_total: 1,
                quorum_reject_total: 0,
                drift_reject_total: 0,
                accepted_total: 0,
            },
            metrics: OracleValidationMetrics {
                oracle_stale_reject_total: 0,
                oracle_quorum_reject_total: 1,
                oracle_drift_reject_total: 0,
                oracle_source_cardinality: 2,
                accepted_total: 0,
                sample_count: 1,
            },
            error: Some("stale".into()),
        };

        let out: OracleValidateSnapshotResponse = report.into();

        assert!(!out.observation_matches_metrics());
        assert_eq!(out.classified_outcome_total(), 1);
        assert_eq!(out.observation_classified_outcome_total(), 1);
        assert!(out.classified_outcome_conserves_sample_count());
        assert!(out.observation_classified_outcome_conserves_sample_count());
        assert!(!out.bridge_contract_consistent());
    }

    #[test]
    fn oracle_validation_response_bridge_contract_consistent_rejects_accepted_total_mismatch() {
        let report = OracleValidationReport {
            ok: true,
            now_ts_ms: 795,
            observation: OracleValidationObservation {
                stale_reject_total: 0,
                quorum_reject_total: 0,
                drift_reject_total: 0,
                accepted_total: 1,
            },
            metrics: OracleValidationMetrics {
                oracle_stale_reject_total: 0,
                oracle_quorum_reject_total: 0,
                oracle_drift_reject_total: 0,
                oracle_source_cardinality: 3,
                accepted_total: 0,
                sample_count: 0,
            },
            error: None,
        };

        let out: OracleValidateSnapshotResponse = report.into();

        assert!(!out.observation_matches_metrics());
        assert_eq!(out.classified_outcome_total(), 0);
        assert_eq!(out.observation_classified_outcome_total(), 1);
        assert!(out.classified_outcome_conserves_sample_count());
        assert!(!out.observation_classified_outcome_conserves_sample_count());
        assert!(!out.bridge_contract_consistent());
    }

    #[test]
    fn oracle_validation_response_bridge_contract_consistent_rejects_zero_sample_positive_source_cardinality(
    ) {
        let out: OracleValidateSnapshotResponse = OracleValidationReport {
            ok: true,
            now_ts_ms: 795,
            observation: OracleValidationObservation {
                stale_reject_total: 0,
                quorum_reject_total: 0,
                drift_reject_total: 0,
                accepted_total: 0,
            },
            metrics: OracleValidationMetrics {
                oracle_stale_reject_total: 0,
                oracle_quorum_reject_total: 0,
                oracle_drift_reject_total: 0,
                oracle_source_cardinality: 1,
                accepted_total: 0,
                sample_count: 0,
            },
            error: None,
        }
        .into();

        assert!(out.observation_matches_metrics());
        assert!(out.classified_outcome_conserves_sample_count());
        assert!(out.observation_classified_outcome_conserves_sample_count());
        assert!(!out.bridge_contract_consistent());
    }

    #[test]
    fn oracle_validation_response_bridge_contract_consistent_rejects_accepted_snapshot_without_canonical_sources(
    ) {
        let out: OracleValidateSnapshotResponse = OracleValidationReport {
            ok: true,
            now_ts_ms: 795,
            observation: OracleValidationObservation {
                stale_reject_total: 0,
                quorum_reject_total: 0,
                drift_reject_total: 0,
                accepted_total: 1,
            },
            metrics: OracleValidationMetrics {
                oracle_stale_reject_total: 0,
                oracle_quorum_reject_total: 0,
                oracle_drift_reject_total: 0,
                oracle_source_cardinality: 0,
                accepted_total: 1,
                sample_count: 1,
            },
            error: None,
        }
        .into();

        assert!(out.observation_matches_metrics());
        assert!(out.classified_outcome_conserves_sample_count());
        assert!(out.observation_classified_outcome_conserves_sample_count());
        assert!(!out.bridge_contract_consistent());
    }

    #[test]
    fn oracle_validation_response_bridge_contract_consistent_rejects_ok_error_label_mismatch() {
        let ok_with_error: OracleValidateSnapshotResponse = OracleValidationReport {
            ok: true,
            now_ts_ms: 796,
            observation: OracleValidationObservation {
                stale_reject_total: 0,
                quorum_reject_total: 0,
                drift_reject_total: 0,
                accepted_total: 1,
            },
            metrics: OracleValidationMetrics {
                oracle_stale_reject_total: 0,
                oracle_quorum_reject_total: 0,
                oracle_drift_reject_total: 0,
                oracle_source_cardinality: 2,
                accepted_total: 1,
                sample_count: 1,
            },
            error: Some("quorum".into()),
        }
        .into();
        assert!(!ok_with_error.bridge_contract_consistent());

        let err_without_label: OracleValidateSnapshotResponse = OracleValidationReport {
            ok: false,
            now_ts_ms: 797,
            observation: OracleValidationObservation {
                stale_reject_total: 1,
                quorum_reject_total: 0,
                drift_reject_total: 0,
                accepted_total: 0,
            },
            metrics: OracleValidationMetrics {
                oracle_stale_reject_total: 1,
                oracle_quorum_reject_total: 0,
                oracle_drift_reject_total: 0,
                oracle_source_cardinality: 2,
                accepted_total: 0,
                sample_count: 1,
            },
            error: None,
        }
        .into();
        assert!(!err_without_label.bridge_contract_consistent());

        let err_with_whitespace_label: OracleValidateSnapshotResponse = OracleValidationReport {
            ok: false,
            now_ts_ms: 798,
            observation: OracleValidationObservation {
                stale_reject_total: 0,
                quorum_reject_total: 1,
                drift_reject_total: 0,
                accepted_total: 0,
            },
            metrics: OracleValidationMetrics {
                oracle_stale_reject_total: 0,
                oracle_quorum_reject_total: 1,
                oracle_drift_reject_total: 0,
                oracle_source_cardinality: 1,
                accepted_total: 0,
                sample_count: 1,
            },
            error: Some(" \t\n ".into()),
        }
        .into();
        assert!(!err_with_whitespace_label.bridge_contract_consistent());
    }

    #[test]
    fn oracle_validation_response_bridge_contract_consistent_rejects_classified_error_label_counter_mismatch(
    ) {
        let out: OracleValidateSnapshotResponse = OracleValidationReport {
            ok: false,
            now_ts_ms: 798,
            observation: OracleValidationObservation {
                stale_reject_total: 0,
                quorum_reject_total: 1,
                drift_reject_total: 0,
                accepted_total: 0,
            },
            metrics: OracleValidationMetrics {
                oracle_stale_reject_total: 0,
                oracle_quorum_reject_total: 1,
                oracle_drift_reject_total: 0,
                oracle_source_cardinality: 2,
                accepted_total: 0,
                sample_count: 1,
            },
            error: Some("stale".into()),
        }
        .into();

        assert!(out.observation_matches_metrics());
        assert!(out.classified_outcome_conserves_sample_count());
        assert!(out.observation_classified_outcome_conserves_sample_count());
        assert!(!out.bridge_contract_consistent());
    }

    #[test]
    fn oracle_validate_snapshot_response_deserializes_canonical_bridge_payload_without_error_field()
    {
        let payload = json!({
            "ok": true,
            "now_ts_ms": 1_710_000_000_123u64,
            "observation": {
                "stale_reject_total": 0,
                "quorum_reject_total": 0,
                "drift_reject_total": 0,
                "accepted_total": 1
            },
            "metrics": {
                "oracle_stale_reject_total": 0,
                "oracle_quorum_reject_total": 0,
                "oracle_drift_reject_total": 0,
                "oracle_source_cardinality": 3,
                "accepted_total": 1,
                "sample_count": 1
            }
        });

        let out: OracleValidateSnapshotResponse = serde_json::from_value(payload).unwrap();

        assert!(out.ok);
        assert_eq!(out.now_ts_ms, 1_710_000_000_123u64);
        assert_eq!(out.error, None);
        assert_eq!(out.observation.accepted_total, 1);
        assert_eq!(out.metrics.oracle_source_cardinality, 3);
        assert_eq!(out.metrics.sample_count, 1);
        assert_eq!(out.classified_reject_total(), 0);
        assert_eq!(out.observation_classified_reject_total(), 0);
        assert!(out.classified_outcome_conserves_sample_count());
        assert!(out.observation_classified_outcome_conserves_sample_count());
    }

    #[test]
    fn oracle_validate_snapshot_response_rejects_unknown_top_level_fields() {
        let payload = json!({
            "ok": true,
            "now_ts_ms": 1_710_000_000_123u64,
            "observation": {
                "stale_reject_total": 0,
                "quorum_reject_total": 0,
                "drift_reject_total": 0,
                "accepted_total": 1
            },
            "metrics": {
                "oracle_stale_reject_total": 0,
                "oracle_quorum_reject_total": 0,
                "oracle_drift_reject_total": 0,
                "oracle_source_cardinality": 1,
                "accepted_total": 1,
                "sample_count": 1
            },
            "bridge_status": "finalized"
        });

        let err = serde_json::from_value::<OracleValidateSnapshotResponse>(payload)
            .expect_err("oracle read schema should reject unknown top-level fields");
        assert!(err.to_string().contains("bridge_status"));
    }

    #[test]
    fn oracle_validation_response_bridge_contract_consistent_accepts_repeated_observations_above_source_cardinality() {
        let out: OracleValidateSnapshotResponse = OracleValidationReport {
            ok: true,
            now_ts_ms: 794,
            observation: OracleValidationObservation {
                stale_reject_total: 0,
                quorum_reject_total: 0,
                drift_reject_total: 0,
                accepted_total: 3,
            },
            metrics: OracleValidationMetrics {
                oracle_stale_reject_total: 0,
                oracle_quorum_reject_total: 0,
                oracle_drift_reject_total: 0,
                oracle_source_cardinality: 2,
                accepted_total: 3,
                sample_count: 3,
            },
            error: None,
        }
        .into();

        assert!(out.observation_matches_metrics());
        assert_eq!(out.classified_reject_total(), 0);
        assert_eq!(out.observation_classified_reject_total(), 0);
        assert_eq!(out.classified_outcome_total(), 3);
        assert_eq!(out.observation_classified_outcome_total(), 3);
        assert!(out.classified_outcome_conserves_sample_count());
        assert!(out.observation_classified_outcome_conserves_sample_count());
        assert!(out.bridge_contract_consistent());
    }

    #[test]
    fn oracle_validation_response_bridge_contract_consistent_rejects_zero_source_cardinality() {
        let out: OracleValidateSnapshotResponse = OracleValidationReport {
            ok: true,
            now_ts_ms: 794,
            observation: OracleValidationObservation {
                stale_reject_total: 0,
                quorum_reject_total: 0,
                drift_reject_total: 0,
                accepted_total: 1,
            },
            metrics: OracleValidationMetrics {
                oracle_stale_reject_total: 0,
                oracle_quorum_reject_total: 0,
                oracle_drift_reject_total: 0,
                oracle_source_cardinality: 0,
                accepted_total: 1,
                sample_count: 1,
            },
            error: None,
        }
        .into();

        assert!(out.observation_matches_metrics());
        assert!(out.classified_outcome_conserves_sample_count());
        assert!(out.observation_classified_outcome_conserves_sample_count());
        assert!(!out.bridge_contract_consistent());
    }

    #[test]
    fn oracle_validation_response_bridge_contract_consistent_accepts_source_cardinality_exactly_at_sample_count(
    ) {
        let out: OracleValidateSnapshotResponse = OracleValidationReport {
            ok: true,
            now_ts_ms: 799,
            observation: OracleValidationObservation {
                stale_reject_total: 0,
                quorum_reject_total: 0,
                drift_reject_total: 0,
                accepted_total: 2,
            },
            metrics: OracleValidationMetrics {
                oracle_stale_reject_total: 0,
                oracle_quorum_reject_total: 0,
                oracle_drift_reject_total: 0,
                oracle_source_cardinality: 2,
                accepted_total: 2,
                sample_count: 2,
            },
            error: None,
        }
        .into();

        assert!(out.observation_matches_metrics());
        assert_eq!(out.classified_reject_total(), 0);
        assert_eq!(out.observation_classified_reject_total(), 0);
        assert_eq!(out.classified_outcome_total(), 2);
        assert_eq!(out.observation_classified_outcome_total(), 2);
        assert!(out.classified_outcome_conserves_sample_count());
        assert!(out.observation_classified_outcome_conserves_sample_count());
        assert!(out.bridge_contract_consistent());
    }

    #[test]
    fn oracle_validation_response_bridge_contract_consistent_accepts_multi_source_single_snapshot_success(
    ) {
        let out: OracleValidateSnapshotResponse = OracleValidationReport {
            ok: true,
            now_ts_ms: 799,
            observation: OracleValidationObservation {
                stale_reject_total: 0,
                quorum_reject_total: 0,
                drift_reject_total: 0,
                accepted_total: 1,
            },
            metrics: OracleValidationMetrics {
                oracle_stale_reject_total: 0,
                oracle_quorum_reject_total: 0,
                oracle_drift_reject_total: 0,
                oracle_source_cardinality: 2,
                accepted_total: 1,
                sample_count: 1,
            },
            error: None,
        }
        .into();

        assert!(out.observation_matches_metrics());
        assert!(out.classified_outcome_conserves_sample_count());
        assert!(out.observation_classified_outcome_conserves_sample_count());
        assert!(out.bridge_contract_consistent());
    }

    #[test]
    fn oracle_validation_response_bridge_contract_consistent_allows_unclassified_failure_without_source_cardinality(
    ) {
        let out: OracleValidateSnapshotResponse = OracleValidationReport {
            ok: false,
            now_ts_ms: 800,
            observation: OracleValidationObservation {
                stale_reject_total: 0,
                quorum_reject_total: 0,
                drift_reject_total: 0,
                accepted_total: 0,
            },
            metrics: OracleValidationMetrics {
                oracle_stale_reject_total: 0,
                oracle_quorum_reject_total: 0,
                oracle_drift_reject_total: 0,
                oracle_source_cardinality: 0,
                accepted_total: 0,
                sample_count: 1,
            },
            error: Some("rate".into()),
        }
        .into();

        assert!(out.observation_matches_metrics());
        assert_eq!(out.classified_outcome_total(), 0);
        assert_eq!(out.observation_classified_outcome_total(), 0);
        assert!(!out.classified_outcome_conserves_sample_count());
        assert!(!out.observation_classified_outcome_conserves_sample_count());
        assert!(out.bridge_contract_consistent());
    }

    #[test]
    fn oracle_validation_response_bridge_contract_consistent_rejects_unclassified_failure_with_nonzero_accepts(
    ) {
        let out: OracleValidateSnapshotResponse = OracleValidationReport {
            ok: false,
            now_ts_ms: 801,
            observation: OracleValidationObservation {
                stale_reject_total: 0,
                quorum_reject_total: 0,
                drift_reject_total: 0,
                accepted_total: 1,
            },
            metrics: OracleValidationMetrics {
                oracle_stale_reject_total: 0,
                oracle_quorum_reject_total: 0,
                oracle_drift_reject_total: 0,
                oracle_source_cardinality: 1,
                accepted_total: 1,
                sample_count: 1,
            },
            error: Some("rate".into()),
        }
        .into();

        assert!(out.observation_matches_metrics());
        assert_eq!(out.classified_outcome_total(), 1);
        assert_eq!(out.observation_classified_outcome_total(), 1);
        assert!(out.classified_outcome_conserves_sample_count());
        assert!(out.observation_classified_outcome_conserves_sample_count());
        assert!(!out.bridge_contract_consistent());
    }

    #[test]
    fn oracle_validation_response_bridge_contract_consistent_accepts_unclassified_multi_source_single_snapshot_failure(
    ) {
        let out: OracleValidateSnapshotResponse = OracleValidationReport {
            ok: false,
            now_ts_ms: 802,
            observation: OracleValidationObservation {
                stale_reject_total: 0,
                quorum_reject_total: 0,
                drift_reject_total: 0,
                accepted_total: 0,
            },
            metrics: OracleValidationMetrics {
                oracle_stale_reject_total: 0,
                oracle_quorum_reject_total: 0,
                oracle_drift_reject_total: 0,
                oracle_source_cardinality: 2,
                accepted_total: 0,
                sample_count: 1,
            },
            error: Some("rate".into()),
        }
        .into();

        assert!(out.observation_matches_metrics());
        assert_eq!(out.classified_outcome_total(), 0);
        assert_eq!(out.observation_classified_outcome_total(), 0);
        assert!(!out.classified_outcome_conserves_sample_count());
        assert!(!out.observation_classified_outcome_conserves_sample_count());
        assert!(out.bridge_contract_consistent());
    }

    #[test]
    fn oracle_validation_response_bridge_contract_consistent_rejects_unclassified_failure_with_zero_samples(
    ) {
        let out: OracleValidateSnapshotResponse = OracleValidationReport {
            ok: false,
            now_ts_ms: 802,
            observation: OracleValidationObservation {
                stale_reject_total: 0,
                quorum_reject_total: 0,
                drift_reject_total: 0,
                accepted_total: 0,
            },
            metrics: OracleValidationMetrics {
                oracle_stale_reject_total: 0,
                oracle_quorum_reject_total: 0,
                oracle_drift_reject_total: 0,
                oracle_source_cardinality: 0,
                accepted_total: 0,
                sample_count: 0,
            },
            error: Some("rate".into()),
        }
        .into();

        assert!(out.observation_matches_metrics());
        assert_eq!(out.classified_outcome_total(), 0);
        assert_eq!(out.observation_classified_outcome_total(), 0);
        assert!(out.classified_outcome_conserves_sample_count());
        assert!(out.observation_classified_outcome_conserves_sample_count());
        assert!(!out.bridge_contract_consistent());
    }
}
