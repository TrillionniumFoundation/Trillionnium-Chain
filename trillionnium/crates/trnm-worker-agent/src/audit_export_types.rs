use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct EnterpriseAuditExportRecord {
    pub(crate) request_id: String,
    pub(crate) task_id: u64,
    pub(crate) status: String,
    pub(crate) provider_request_id: Option<String>,
    pub(crate) provenance_schema_version: Option<String>,
    pub(crate) provenance_fingerprint: Option<String>,
    pub(crate) provider: Option<String>,
    pub(crate) model: Option<String>,
    pub(crate) adapter: Option<String>,
    pub(crate) agent_protocol: Option<String>,
    pub(crate) compliance_profile: Option<String>,
    #[serde(default)]
    pub(crate) reputation_label: Option<String>,
    #[serde(default)]
    pub(crate) reputation_delta: Option<i32>,
    #[serde(default)]
    pub(crate) reputation_tier: Option<u8>,
    #[serde(default)]
    pub(crate) reputation_weight_bps: Option<u16>,
    #[serde(default)]
    pub(crate) reputation_score_bps: Option<i32>,
    #[serde(default)]
    pub(crate) reputation_rank_ordinal: Option<u8>,
    #[serde(default)]
    pub(crate) reputation_gap_bps_from_best: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct AuditExportIndex {
    pub(crate) version: u8,
    pub(crate) total_records: usize,
    pub(crate) by_task_id: BTreeMap<String, Vec<usize>>,
    pub(crate) by_status: BTreeMap<String, Vec<usize>>,
    pub(crate) by_status_phase: BTreeMap<String, Vec<usize>>,
    pub(crate) by_provider: BTreeMap<String, Vec<usize>>,
    pub(crate) by_model: BTreeMap<String, Vec<usize>>,
    pub(crate) by_agent_protocol: BTreeMap<String, Vec<usize>>,
    pub(crate) by_compliance_profile: BTreeMap<String, Vec<usize>>,
    pub(crate) by_provenance_fingerprint: BTreeMap<String, Vec<usize>>,
}
