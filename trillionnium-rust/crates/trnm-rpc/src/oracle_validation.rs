use serde::{Deserialize, Serialize};
use trnm_oracle::{OracleValidationMetrics, OracleValidationObservation, OracleValidationReport};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OracleValidateSnapshotResponse {
    pub ok: bool,
    pub now_ts_ms: u64,
    pub observation: OracleValidationObservation,
    pub metrics: OracleValidationMetrics,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl OracleValidateSnapshotResponse {
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

    pub fn bridge_contract_consistent(&self) -> bool {
        self.observation_matches_metrics()
            && self.classified_outcome_conserves_sample_count()
            && self.observation_classified_outcome_conserves_sample_count()
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
