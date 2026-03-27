use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

use crate::{OracleError, OracleSnapshot};

use super::OraclePolicy;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OracleValidationObservation {
    pub stale_reject_total: u32,
    pub quorum_reject_total: u32,
    pub drift_reject_total: u32,
    pub accepted_total: u32,
}

impl OracleValidationObservation {
    pub fn classified_reject_total(&self) -> u32 {
        self.stale_reject_total + self.quorum_reject_total + self.drift_reject_total
    }

    pub fn classified_outcome_total(&self) -> u32 {
        self.accepted_total + self.classified_reject_total()
    }

    pub fn classified_outcome_conserves_sample_count(&self, sample_count: u32) -> bool {
        self.classified_outcome_total() == sample_count
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OracleValidationMetrics {
    pub oracle_stale_reject_total: u32,
    pub oracle_quorum_reject_total: u32,
    pub oracle_drift_reject_total: u32,
    pub oracle_source_cardinality: u32,
    pub accepted_total: u32,
    pub sample_count: u32,
}

impl OracleValidationMetrics {
    pub fn classified_reject_total(&self) -> u32 {
        self.oracle_stale_reject_total
            + self.oracle_quorum_reject_total
            + self.oracle_drift_reject_total
    }

    pub fn classified_outcome_total(&self) -> u32 {
        self.accepted_total + self.classified_reject_total()
    }

    pub fn classified_outcome_conserves_sample_count(&self) -> bool {
        self.classified_outcome_total() == self.sample_count
    }
}

fn canonical_source_cardinality(snapshot: &OracleSnapshot) -> u32 {
    snapshot
        .sources
        .iter()
        .map(|source| source.as_str())
        .collect::<BTreeSet<_>>()
        .len() as u32
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OracleValidationReport {
    pub ok: bool,
    pub now_ts_ms: u64,
    pub observation: OracleValidationObservation,
    pub metrics: OracleValidationMetrics,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl OracleValidationReport {
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

    fn has_explicit_unclassified_failure_accounting(&self) -> bool {
        !self.ok
            && self.error.is_some()
            && self.metrics.accepted_total == 0
            && self.classified_reject_total() == 0
            && self.observation_classified_reject_total() == 0
            && self.metrics.sample_count > 0
    }

    pub fn bridge_contract_consistent(&self) -> bool {
        let non_empty_sample = self.metrics.sample_count > 0;
        let result_label_consistent = if self.ok {
            self.error.is_none() && self.metrics.accepted_total == self.metrics.sample_count
        } else {
            self.error.is_some() && self.metrics.accepted_total == 0
        };
        let outcome_accounting_consistent = self.classified_outcome_conserves_sample_count()
            && self.observation_classified_outcome_conserves_sample_count();

        non_empty_sample
            && self.observation_matches_metrics()
            && result_label_consistent
            && (outcome_accounting_consistent
                || self.has_explicit_unclassified_failure_accounting())
    }
}

pub fn validate_snapshot_observed(
    policy: &OraclePolicy,
    snapshot: &OracleSnapshot,
    now_ts_ms: u64,
) -> OracleValidationReport {
    let mut observation = OracleValidationObservation {
        stale_reject_total: 0,
        quorum_reject_total: 0,
        drift_reject_total: 0,
        accepted_total: 0,
    };

    let result = policy.validate_snapshot(snapshot, now_ts_ms);
    let error = match &result {
        Ok(()) => {
            observation.accepted_total = 1;
            None
        }
        Err(OracleError::StaleSnapshot { .. }) => {
            observation.stale_reject_total = 1;
            Some("stale".to_string())
        }
        Err(OracleError::InsufficientSources { .. }) => {
            observation.quorum_reject_total = 1;
            Some("quorum".to_string())
        }
        Err(OracleError::DeviationExceeded { .. }) => {
            observation.drift_reject_total = 1;
            Some("drift".to_string())
        }
        Err(OracleError::UpdateRateExceeded { .. }) => Some("rate".to_string()),
        Err(err) => Some(err.to_string()),
    };

    OracleValidationReport {
        ok: result.is_ok(),
        now_ts_ms,
        metrics: OracleValidationMetrics {
            oracle_stale_reject_total: observation.stale_reject_total,
            oracle_quorum_reject_total: observation.quorum_reject_total,
            oracle_drift_reject_total: observation.drift_reject_total,
            oracle_source_cardinality: canonical_source_cardinality(snapshot),
            accepted_total: observation.accepted_total,
            sample_count: 1,
        },
        observation,
        error,
    }
}
