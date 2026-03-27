use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use thiserror::Error;

const MAX_DEVIATION_BPS_CAP: u32 = 10_000;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct OracleSourceId(String);

impl OracleSourceId {
    pub fn parse(raw: impl AsRef<str>) -> Result<Self, OracleError> {
        let raw = raw.as_ref();
        if raw.trim().is_empty() {
            return Err(OracleError::EmptySourceId);
        }
        let canonical = raw.trim().to_ascii_lowercase();
        if raw != canonical {
            return Err(OracleError::NonCanonicalSourceId {
                raw: raw.to_string(),
                canonical,
            });
        }
        Ok(Self(canonical))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OracleSnapshot {
    pub feed_id: String,
    pub value: i128,
    pub sources: Vec<OracleSourceId>,
    pub sample_count: u32,
    pub median: Option<i128>,
    pub mad: Option<u128>,
    pub window_start_ms: u64,
    pub window_end_ms: u64,
    pub snapshot_ts_ms: u64,
    pub snapshot_hash: String,
}

impl OracleSnapshot {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        feed_id: impl Into<String>,
        value: i128,
        mut sources: Vec<OracleSourceId>,
        sample_count: u32,
        median: Option<i128>,
        mad: Option<u128>,
        window_start_ms: u64,
        window_end_ms: u64,
        snapshot_ts_ms: u64,
    ) -> Result<Self, OracleError> {
        let raw_feed_id = feed_id.into();
        let feed_id = raw_feed_id.trim().to_ascii_lowercase();
        if feed_id.is_empty() {
            return Err(OracleError::EmptyFeedId);
        }
        if raw_feed_id != feed_id {
            return Err(OracleError::NonCanonicalFeedId {
                raw: raw_feed_id,
                canonical: feed_id,
            });
        }
        if window_end_ms < window_start_ms {
            return Err(OracleError::InvalidWindow {
                start_ms: window_start_ms,
                end_ms: window_end_ms,
            });
        }
        if snapshot_ts_ms < window_end_ms {
            return Err(OracleError::InvalidWindowTimestamp {
                window_end_ms,
                snapshot_ts_ms,
            });
        }

        sources.sort();
        if sources.windows(2).any(|w| w[0] == w[1]) {
            return Err(OracleError::DuplicateSources);
        }
        if sample_count == 0 {
            return Err(OracleError::InvalidPolicy("sample_count must be > 0"));
        }
        if sample_count < sources.len() as u32 {
            return Err(OracleError::InconsistentSampleCount {
                sample_count,
                actual_sources: sources.len() as u32,
            });
        }

        let mut snapshot = Self {
            feed_id,
            value,
            sources,
            sample_count,
            median,
            mad,
            window_start_ms,
            window_end_ms,
            snapshot_ts_ms,
            snapshot_hash: String::new(),
        };
        snapshot.snapshot_hash = snapshot.compute_hash();
        Ok(snapshot)
    }

    pub fn compute_hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.feed_id.as_bytes());
        hasher.update([0xff]);
        hasher.update(self.value.to_le_bytes());
        hasher.update([0xff]);
        hasher.update((self.sources.len() as u32).to_le_bytes());
        for source in &self.sources {
            hasher.update(source.as_str().as_bytes());
            hasher.update([0xff]);
        }
        hasher.update(self.sample_count.to_le_bytes());
        hasher.update([0xff]);

        match self.median {
            Some(v) => {
                hasher.update([1]);
                hasher.update(v.to_le_bytes());
            }
            None => hasher.update([0]),
        }

        match self.mad {
            Some(v) => {
                hasher.update([1]);
                hasher.update(v.to_le_bytes());
            }
            None => hasher.update([0]),
        }

        hasher.update(self.window_start_ms.to_le_bytes());
        hasher.update(self.window_end_ms.to_le_bytes());
        hasher.update(self.snapshot_ts_ms.to_le_bytes());

        hex::encode(hasher.finalize())
    }

    pub fn validate_hash(&self) -> Result<(), OracleError> {
        let expected = self.compute_hash();
        if self.snapshot_hash != expected {
            return Err(OracleError::SnapshotHashMismatch {
                expected,
                actual: self.snapshot_hash.clone(),
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OraclePolicy {
    pub min_sources: u32,
    pub max_staleness_ms: u64,
    pub max_deviation_bps: u32,
    pub max_update_rate_per_window: u32,
}

impl OraclePolicy {
    pub fn validate(&self) -> Result<(), OracleError> {
        if self.min_sources == 0 {
            return Err(OracleError::InvalidPolicy("min_sources must be > 0"));
        }
        if self.max_staleness_ms == 0 {
            return Err(OracleError::InvalidPolicy("max_staleness_ms must be > 0"));
        }
        if self.max_deviation_bps > MAX_DEVIATION_BPS_CAP {
            return Err(OracleError::InvalidPolicy(
                "max_deviation_bps must be <= 10000",
            ));
        }
        if self.max_update_rate_per_window == 0 {
            return Err(OracleError::InvalidPolicy(
                "max_update_rate_per_window must be > 0",
            ));
        }
        Ok(())
    }

    /// Validates that a snapshot is canonical, fresh, and policy-compliant
    /// enough to be consumed by higher layers.
    ///
    /// Layering contract:
    /// - the oracle crate only decides whether snapshot data is admissible;
    ///   it does not finalize bridge settlement or interpret replay/finality
    ///   outcomes.
    /// - a successful validation result means “this evidence may be considered”,
    ///   not “settlement is final”; downstream layers still own confirmation and
    ///   replay boundaries.
    /// - median/MAD and source-count checks are confidence/admissibility guards,
    ///   not settlement authority. They can reject low-confidence evidence, but
    ///   they can never upgrade a bridge observation into final settlement on
    ///   their own.
    /// - downstream bridge/RPC code should treat a validation failure here as a
    ///   fail-closed signal and avoid manufacturing fallback settlement meaning
    ///   from malformed oracle payloads.
    /// - replay identity and source-chain finality thresholds stay downstream:
    ///   bridge/RPC layers must dedupe repeated oracle payloads and enforce the
    ///   source/target confirmation boundary before any settlement transition.
    /// - `sample_count` may exceed the number of unique canonical sources when a
    ///   report aggregates repeated observations inside one window; the opposite
    ///   direction remains invalid and is rejected below.
    pub fn validate_snapshot(
        &self,
        snapshot: &OracleSnapshot,
        now_ts_ms: u64,
    ) -> Result<(), OracleError> {
        self.validate()?;

        let canonical_feed_id = snapshot.feed_id.trim().to_ascii_lowercase();
        if canonical_feed_id.is_empty() {
            return Err(OracleError::EmptyFeedId);
        }
        if snapshot.feed_id != canonical_feed_id {
            return Err(OracleError::NonCanonicalFeedId {
                raw: snapshot.feed_id.clone(),
                canonical: canonical_feed_id,
            });
        }
        if snapshot.window_end_ms < snapshot.window_start_ms {
            return Err(OracleError::InvalidWindow {
                start_ms: snapshot.window_start_ms,
                end_ms: snapshot.window_end_ms,
            });
        }
        if snapshot.snapshot_ts_ms < snapshot.window_end_ms {
            return Err(OracleError::InvalidWindowTimestamp {
                window_end_ms: snapshot.window_end_ms,
                snapshot_ts_ms: snapshot.snapshot_ts_ms,
            });
        }

        validate_snapshot_sources(snapshot)?;

        snapshot.validate_hash()?;

        if snapshot.snapshot_ts_ms > now_ts_ms {
            return Err(OracleError::FutureSnapshot {
                snapshot_ts_ms: snapshot.snapshot_ts_ms,
                now_ts_ms,
            });
        }

        if now_ts_ms - snapshot.snapshot_ts_ms > self.max_staleness_ms {
            return Err(OracleError::StaleSnapshot {
                snapshot_ts_ms: snapshot.snapshot_ts_ms,
                now_ts_ms,
                max_staleness_ms: self.max_staleness_ms,
            });
        }

        if snapshot.sample_count == 0 {
            return Err(OracleError::InvalidPolicy("sample_count must be > 0"));
        }

        if snapshot.sources.len() < self.min_sources as usize
            || snapshot.sample_count < self.min_sources
        {
            return Err(OracleError::InsufficientSources {
                min_sources: self.min_sources,
                actual_sources: snapshot.sources.len() as u32,
                sample_count: snapshot.sample_count,
            });
        }

        if snapshot.sample_count < snapshot.sources.len() as u32 {
            return Err(OracleError::InconsistentSampleCount {
                actual_sources: snapshot.sources.len() as u32,
                sample_count: snapshot.sample_count,
            });
        }

        if snapshot.sample_count > self.max_update_rate_per_window {
            return Err(OracleError::UpdateRateExceeded {
                sample_count: snapshot.sample_count,
                max_update_rate_per_window: self.max_update_rate_per_window,
            });
        }

        if let Some(median) = snapshot.median {
            let deviation = deviation_bps(snapshot.value, median);
            if deviation_reaches_boundary(deviation, self.max_deviation_bps) {
                return Err(OracleError::DeviationExceeded {
                    deviation_bps: deviation,
                    max_deviation_bps: self.max_deviation_bps,
                });
            }
        }

        Ok(())
    }
}

fn deviation_reaches_boundary(deviation_bps: u32, max_deviation_bps: u32) -> bool {
    deviation_bps > max_deviation_bps
        || (max_deviation_bps != 0 && deviation_bps == max_deviation_bps)
}

fn deviation_bps(value: i128, baseline: i128) -> u32 {
    if baseline == value {
        return 0;
    }
    if baseline == 0 {
        return MAX_DEVIATION_BPS_CAP;
    }

    let numerator = value
        .abs_diff(baseline)
        .saturating_mul(MAX_DEVIATION_BPS_CAP as u128);
    let denominator = baseline.unsigned_abs();
    let scaled = numerator / denominator;
    scaled.min(MAX_DEVIATION_BPS_CAP as u128) as u32
}

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
        .filter_map(|source| {
            let canonical = source.as_str().trim().to_ascii_lowercase();
            (!canonical.is_empty()).then_some(canonical)
        })
        .collect::<BTreeSet<_>>()
        .len() as u32
}

fn validate_snapshot_sources(snapshot: &OracleSnapshot) -> Result<(), OracleError> {
    let mut canonical_sequence = Vec::with_capacity(snapshot.sources.len());
    let mut canonical_sources = BTreeSet::new();

    for source in &snapshot.sources {
        let raw = source.as_str();
        if raw.trim().is_empty() {
            return Err(OracleError::EmptySourceId);
        }
        let canonical = raw.trim().to_ascii_lowercase();
        if raw != canonical {
            return Err(OracleError::NonCanonicalSourceId {
                raw: raw.to_string(),
                canonical,
            });
        }
        if !canonical_sources.insert(canonical.clone()) {
            return Err(OracleError::DuplicateSources);
        }
        canonical_sequence.push(canonical);
    }

    for window in canonical_sequence.windows(2) {
        let previous = &window[0];
        let current = &window[1];
        if current < previous {
            return Err(OracleError::NonCanonicalSourceOrdering {
                previous: previous.clone(),
                current: current.clone(),
            });
        }
    }

    Ok(())
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

    fn has_non_empty_error_label(&self) -> bool {
        self.error
            .as_deref()
            .map(str::trim)
            .is_some_and(|label| !label.is_empty())
    }

    fn has_explicit_unclassified_failure_accounting(&self) -> bool {
        !self.ok
            && self.has_non_empty_error_label()
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
            self.has_non_empty_error_label() && self.metrics.accepted_total == 0
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
        Err(OracleError::InsufficientSources { .. })
        | Err(OracleError::InconsistentSampleCount { .. }) => {
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

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum OracleError {
    #[error("source id is empty")]
    EmptySourceId,
    #[error("source id must be canonical lowercase+trim: raw={raw}, canonical={canonical}")]
    NonCanonicalSourceId { raw: String, canonical: String },
    #[error("feed id is empty")]
    EmptyFeedId,
    #[error("feed id must be canonical lowercase+trim: raw={raw}, canonical={canonical}")]
    NonCanonicalFeedId { raw: String, canonical: String },
    #[error("invalid window: start={start_ms}, end={end_ms}")]
    InvalidWindow { start_ms: u64, end_ms: u64 },
    #[error("invalid window timestamp: window_end={window_end_ms}, snapshot_ts={snapshot_ts_ms}")]
    InvalidWindowTimestamp {
        window_end_ms: u64,
        snapshot_ts_ms: u64,
    },
    #[error("duplicate source ids are not allowed")]
    DuplicateSources,
    #[error("source ids must be sorted canonically: previous={previous}, current={current}")]
    NonCanonicalSourceOrdering { previous: String, current: String },
    #[error("snapshot hash mismatch: expected={expected}, actual={actual}")]
    SnapshotHashMismatch { expected: String, actual: String },
    #[error("invalid policy: {0}")]
    InvalidPolicy(&'static str),
    #[error("future snapshot: ts={snapshot_ts_ms}, now={now_ts_ms}")]
    FutureSnapshot { snapshot_ts_ms: u64, now_ts_ms: u64 },
    #[error(
        "stale snapshot: ts={snapshot_ts_ms}, now={now_ts_ms}, max_staleness={max_staleness_ms}"
    )]
    StaleSnapshot {
        snapshot_ts_ms: u64,
        now_ts_ms: u64,
        max_staleness_ms: u64,
    },
    #[error(
        "insufficient sources: min={min_sources}, sources={actual_sources}, sample_count={sample_count}"
    )]
    InsufficientSources {
        min_sources: u32,
        actual_sources: u32,
        sample_count: u32,
    },
    #[error("deviation exceeded: deviation_bps={deviation_bps}, max={max_deviation_bps}")]
    DeviationExceeded {
        deviation_bps: u32,
        max_deviation_bps: u32,
    },
    #[error("inconsistent sample count: sources={actual_sources}, sample_count={sample_count}")]
    InconsistentSampleCount {
        actual_sources: u32,
        sample_count: u32,
    },
    #[error(
        "update rate exceeded: sample_count={sample_count}, max_update_rate_per_window={max_update_rate_per_window}"
    )]
    UpdateRateExceeded {
        sample_count: u32,
        max_update_rate_per_window: u32,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source(id: &str) -> OracleSourceId {
        OracleSourceId::parse(id).expect("valid source id")
    }

    fn policy() -> OraclePolicy {
        OraclePolicy {
            min_sources: 2,
            max_staleness_ms: 5_000,
            max_deviation_bps: 500,
            max_update_rate_per_window: 60,
        }
    }

    fn snapshot_with(value: i128, median: Option<i128>, snapshot_ts_ms: u64) -> OracleSnapshot {
        OracleSnapshot::new(
            "btc/usd",
            value,
            vec![source("coingecko"), source("chainlink")],
            2,
            median,
            Some(120),
            1_000,
            2_000,
            snapshot_ts_ms,
        )
        .expect("snapshot should be valid")
    }

    #[test]
    fn rejects_non_canonical_feed_id_when_building_snapshot() {
        let err = OracleSnapshot::new(
            " BTC/USD ",
            100_000,
            vec![source("coingecko"), source("chainlink")],
            2,
            Some(100_000),
            Some(120),
            1_000,
            2_000,
            10_000,
        )
        .expect_err("snapshot build should reject non-canonical feed id");

        assert_eq!(
            err,
            OracleError::NonCanonicalFeedId {
                raw: " BTC/USD ".to_string(),
                canonical: "btc/usd".to_string(),
            }
        );
    }

    #[test]
    fn rejects_empty_feed_id_when_building_snapshot() {
        let err = OracleSnapshot::new(
            "   ",
            100_000,
            vec![source("coingecko"), source("chainlink")],
            2,
            Some(100_000),
            Some(120),
            1_000,
            2_000,
            10_000,
        )
        .expect_err("snapshot build should reject blank feed id");

        assert_eq!(err, OracleError::EmptyFeedId);
    }

    #[test]
    fn rejects_snapshot_timestamp_before_window_end_when_building_snapshot() {
        let err = OracleSnapshot::new(
            "btc/usd",
            100_000,
            vec![source("coingecko"), source("chainlink")],
            2,
            Some(100_000),
            Some(120),
            1_000,
            2_000,
            1_999,
        )
        .expect_err("snapshot build should reject timestamps that predate the window end");

        assert_eq!(
            err,
            OracleError::InvalidWindowTimestamp {
                window_end_ms: 2_000,
                snapshot_ts_ms: 1_999,
            }
        );
    }

    #[test]
    fn accepts_snapshot_timestamp_exactly_at_window_end_boundary() {
        let snap = OracleSnapshot::new(
            "btc/usd",
            100_000,
            vec![source("coingecko"), source("chainlink")],
            2,
            Some(100_000),
            Some(120),
            1_000,
            2_000,
            2_000,
        )
        .expect("snapshot timestamp exactly at window end should remain canonical");

        policy()
            .validate_snapshot(&snap, 2_000)
            .expect("boundary-equal window end timestamp should validate");
    }

    #[test]
    fn rejects_stale_snapshot() {
        let p = policy();
        let snap = snapshot_with(100_000, Some(100_100), 10_000);

        let err = p
            .validate_snapshot(&snap, 16_000)
            .expect_err("snapshot should be stale");
        assert!(matches!(err, OracleError::StaleSnapshot { .. }));
    }

    #[test]
    fn rejects_deserialized_snapshot_timestamp_before_window_end() {
        let p = policy();
        let mut snap = snapshot_with(100_000, Some(100_100), 10_000);
        snap.snapshot_ts_ms = 1_999;
        snap.window_end_ms = 2_000;
        snap.snapshot_hash = snap.compute_hash();

        let err = p
            .validate_snapshot(&snap, 10_000)
            .expect_err("snapshot timestamp before window end should fail closed");
        assert_eq!(
            err,
            OracleError::InvalidWindowTimestamp {
                window_end_ms: 2_000,
                snapshot_ts_ms: 1_999,
            }
        );
    }

    #[test]
    fn rejects_deserialized_invalid_window_even_with_matching_hash() {
        let p = policy();
        let mut snap = snapshot_with(100_000, Some(100_100), 10_000);
        snap.window_start_ms = 2_001;
        snap.window_end_ms = 2_000;
        snap.snapshot_hash = snap.compute_hash();

        let err = p
            .validate_snapshot(&snap, 10_000)
            .expect_err("deserialized invalid window should fail closed even with matching hash");
        assert_eq!(
            err,
            OracleError::InvalidWindow {
                start_ms: 2_001,
                end_ms: 2_000,
            }
        );
    }

    #[test]
    fn rejects_insufficient_sources() {
        let p = policy();
        let snap = OracleSnapshot::new(
            "btc/usd",
            100_000,
            vec![source("coingecko")],
            1,
            Some(100_000),
            None,
            1_000,
            2_000,
            10_000,
        )
        .expect("snapshot build");

        let err = p
            .validate_snapshot(&snap, 10_100)
            .expect_err("snapshot should fail quorum");
        assert!(matches!(err, OracleError::InsufficientSources { .. }));
    }

    #[test]
    fn rejects_zero_sample_count_as_invalid_accounting() {
        let err = OracleSnapshot::new(
            "btc/usd",
            100_000,
            vec![source("coingecko")],
            0,
            Some(100_000),
            Some(120),
            1_000,
            2_000,
            10_000,
        )
        .expect_err("snapshot should reject zero sample accounting");

        assert!(matches!(
            err,
            OracleError::InvalidPolicy("sample_count must be > 0")
        ));
    }

    #[test]
    fn rejects_sample_count_below_distinct_source_count() {
        let err = OracleSnapshot::new(
            "btc/usd",
            100_000,
            vec![source("coingecko"), source("chainlink")],
            1,
            Some(100_000),
            Some(120),
            1_000,
            2_000,
            10_000,
        )
        .expect_err("snapshot should reject undercounted sample accounting");

        assert!(matches!(
            err,
            OracleError::InconsistentSampleCount {
                sample_count: 1,
                actual_sources: 2
            }
        ));
    }

    #[test]
    fn rejects_sample_count_above_update_rate_cap() {
        let p = policy();
        let snap = OracleSnapshot::new(
            "btc/usd",
            100_000,
            vec![source("coingecko"), source("chainlink")],
            61,
            Some(100_000),
            Some(120),
            1_000,
            2_000,
            10_000,
        )
        .expect("snapshot build");

        let err = p
            .validate_snapshot(&snap, 10_100)
            .expect_err("snapshot should fail update-rate cap");
        assert!(matches!(err, OracleError::UpdateRateExceeded { .. }));
    }

    #[test]
    fn accepts_sample_count_exactly_at_update_rate_cap() {
        let p = policy();
        let snap = OracleSnapshot::new(
            "btc/usd",
            100_000,
            vec![source("coingecko"), source("chainlink")],
            60,
            Some(100_000),
            Some(120),
            1_000,
            2_000,
            10_000,
        )
        .expect("snapshot build");

        p.validate_snapshot(&snap, 10_100)
            .expect("sample_count exactly at the configured cap should remain valid");
    }

    #[test]
    fn accepts_repeated_observations_when_sample_count_exceeds_unique_sources() {
        let p = policy();
        let snap = OracleSnapshot::new(
            "btc/usd",
            100_000,
            vec![source("coingecko"), source("chainlink")],
            3,
            Some(100_000),
            Some(120),
            1_000,
            2_000,
            10_000,
        )
        .expect("snapshot build");

        p.validate_snapshot(&snap, 10_100)
            .expect("repeated observations within one window should stay admissible");
    }

    #[test]
    fn rejects_sample_count_below_source_cardinality() {
        let err = OracleSnapshot::new(
            "btc/usd",
            100_000,
            vec![source("coingecko"), source("chainlink"), source("pyth")],
            2,
            Some(100_000),
            None,
            1_000,
            2_000,
            10_000,
        )
        .expect_err("snapshot should fail inconsistent accounting guardrail");

        assert!(matches!(
            err,
            OracleError::InconsistentSampleCount {
                actual_sources: 3,
                sample_count: 2,
            }
        ));
    }

    #[test]
    fn rejects_deviation_exceeded() {
        let p = policy();
        let snap = snapshot_with(120_000, Some(100_000), 10_000); // 2000 bps

        let err = p
            .validate_snapshot(&snap, 10_100)
            .expect_err("snapshot should fail drift check");
        assert!(matches!(err, OracleError::DeviationExceeded { .. }));
    }

    #[test]
    fn rejects_deviation_exactly_at_threshold() {
        let p = policy();
        let snap = snapshot_with(105_000, Some(100_000), 10_000); // 500 bps

        let err = p
            .validate_snapshot(&snap, 10_100)
            .expect_err("snapshot at drift threshold should fail");
        assert!(matches!(err, OracleError::DeviationExceeded { .. }));
    }

    #[test]
    fn zero_deviation_policy_accepts_only_exact_median_matches() {
        let p = OraclePolicy {
            min_sources: 2,
            max_staleness_ms: 5_000,
            max_deviation_bps: 0,
            max_update_rate_per_window: 60,
        };
        let exact = snapshot_with(100_000, Some(100_000), 10_000);
        let drifted = snapshot_with(100_100, Some(100_000), 10_000);

        p.validate_snapshot(&exact, 10_100)
            .expect("zero-deviation policy should accept exact median match");
        let err = p
            .validate_snapshot(&drifted, 10_100)
            .expect_err("zero-deviation policy should reject any non-zero drift");
        assert!(matches!(err, OracleError::DeviationExceeded { .. }));
    }

    #[test]
    fn deviation_bps_saturates_at_cap_for_extreme_values() {
        assert_eq!(deviation_bps(i128::MAX, 1), MAX_DEVIATION_BPS_CAP);
        assert_eq!(deviation_bps(i128::MIN, -1), MAX_DEVIATION_BPS_CAP);
    }

    #[test]
    fn observed_report_preserves_zero_deviation_boundary_as_drift_label() {
        let p = OraclePolicy {
            min_sources: 2,
            max_staleness_ms: 5_000,
            max_deviation_bps: 0,
            max_update_rate_per_window: 60,
        };
        let snap = snapshot_with(100_100, Some(100_000), 10_000);

        let report = validate_snapshot_observed(&p, &snap, 10_100);
        assert!(!report.ok);
        assert_eq!(report.error.as_deref(), Some("drift"));
        assert_eq!(report.observation.drift_reject_total, 1);
        assert_eq!(report.metrics.oracle_drift_reject_total, 1);
        assert_eq!(report.metrics.accepted_total, 0);
        assert_eq!(report.metrics.sample_count, 1);
        assert!(report.classified_outcome_conserves_sample_count());
    }

    #[test]
    fn zero_baseline_cap_boundary_is_treated_as_drift_guardrail() {
        let p = OraclePolicy {
            min_sources: 2,
            max_staleness_ms: 5_000,
            max_deviation_bps: MAX_DEVIATION_BPS_CAP,
            max_update_rate_per_window: 60,
        };
        let snap = snapshot_with(100_000, Some(0), 10_000);

        let err = p
            .validate_snapshot(&snap, 10_100)
            .expect_err("zero-baseline cap boundary should fail closed");
        assert!(matches!(
            err,
            OracleError::DeviationExceeded {
                deviation_bps: MAX_DEVIATION_BPS_CAP,
                max_deviation_bps: MAX_DEVIATION_BPS_CAP,
            }
        ));

        let report = validate_snapshot_observed(&p, &snap, 10_100);
        assert!(!report.ok);
        assert_eq!(report.error.as_deref(), Some("drift"));
        assert_eq!(report.observation.drift_reject_total, 1);
        assert_eq!(report.metrics.oracle_drift_reject_total, 1);
    }

    #[test]
    fn snapshot_hash_is_reproducible() {
        let s1 = OracleSnapshot::new(
            "btc/usd",
            100_000,
            vec![source("chainlink"), source("coingecko")],
            2,
            Some(99_900),
            Some(10),
            1_000,
            2_000,
            10_000,
        )
        .expect("snapshot 1");

        let s2 = OracleSnapshot::new(
            "btc/usd",
            100_000,
            vec![source("coingecko"), source("chainlink")],
            2,
            Some(99_900),
            Some(10),
            1_000,
            2_000,
            10_000,
        )
        .expect("snapshot 2");

        assert_eq!(s1.snapshot_hash, s2.snapshot_hash);
        assert!(s1.validate_hash().is_ok());
    }

    #[test]
    fn validate_hash_rejects_uppercase_snapshot_digest_surface() {
        let mut snapshot = OracleSnapshot::new(
            "btc/usd",
            100_000,
            vec![source("coingecko"), source("chainlink")],
            2,
            Some(99_900),
            Some(10),
            1_000,
            2_000,
            10_000,
        )
        .expect("snapshot");

        snapshot.snapshot_hash = snapshot.snapshot_hash.to_uppercase();

        let err = snapshot
            .validate_hash()
            .expect_err("uppercase digest surface must fail closed");
        assert!(matches!(err, OracleError::SnapshotHashMismatch { .. }));
    }

    #[test]
    fn rejects_future_snapshot_timestamp() {
        let p = policy();
        let snap = snapshot_with(100_000, Some(100_100), 10_001);

        let err = p
            .validate_snapshot(&snap, 10_000)
            .expect_err("future-dated snapshot should fail oracle guardrail");
        assert!(matches!(
            err,
            OracleError::FutureSnapshot {
                snapshot_ts_ms: 10_001,
                now_ts_ms: 10_000,
            }
        ));
    }

    #[test]
    fn policy_accepts_snapshot_exactly_at_staleness_boundary() {
        let p = policy();
        let snap = snapshot_with(100_000, Some(100_100), 10_000);

        p.validate_snapshot(&snap, 15_000)
            .expect("boundary staleness should remain valid");
    }

    #[test]
    fn observed_report_treats_exact_staleness_boundary_as_accepted_without_counter_drift() {
        let p = policy();
        let snap = snapshot_with(100_000, Some(100_100), 10_000);

        let report = validate_snapshot_observed(&p, &snap, 15_000);
        assert!(report.ok);
        assert_eq!(report.error, None);
        assert_eq!(report.observation.accepted_total, 1);
        assert_eq!(report.observation.stale_reject_total, 0);
        assert_eq!(report.metrics.oracle_stale_reject_total, 0);
        assert_eq!(report.metrics.accepted_total, 1);
        assert_eq!(report.metrics.sample_count, 1);
        assert!(report.classified_outcome_conserves_sample_count());
        assert!(report.bridge_contract_consistent());
    }

    #[test]
    fn observed_report_maps_success_to_stable_metrics_contract() {
        let p = policy();
        let snap = snapshot_with(100_000, Some(100_100), 10_000);

        let report = validate_snapshot_observed(&p, &snap, 10_100);
        assert!(report.ok);
        assert_eq!(report.error, None);
        assert_eq!(report.observation.accepted_total, 1);
        assert_eq!(report.metrics.oracle_stale_reject_total, 0);
        assert_eq!(report.metrics.oracle_quorum_reject_total, 0);
        assert_eq!(report.metrics.oracle_drift_reject_total, 0);
        assert_eq!(report.metrics.oracle_source_cardinality, 2);
        assert_eq!(report.metrics.accepted_total, 1);
        assert_eq!(report.metrics.sample_count, 1);
    }

    #[test]
    fn observed_report_keeps_source_cardinality_distinct_from_repeated_observation_count() {
        let p = policy();
        let snap = OracleSnapshot::new(
            "btc/usd",
            100_000,
            vec![source("coingecko"), source("chainlink")],
            3,
            Some(100_000),
            Some(120),
            1_000,
            2_000,
            10_000,
        )
        .expect("snapshot build");

        let report = validate_snapshot_observed(&p, &snap, 10_100);
        assert!(report.ok);
        assert_eq!(report.error, None);
        assert_eq!(report.metrics.oracle_source_cardinality, 2);
        assert_eq!(report.metrics.accepted_total, 1);
        assert_eq!(report.metrics.sample_count, 1);
        assert!(report.observation_matches_metrics());
        assert!(report.bridge_contract_consistent());
    }

    #[test]
    fn observed_report_maps_stale_rejection_to_stable_error_label() {
        let p = policy();
        let snap = snapshot_with(100_000, Some(100_100), 10_000);

        let report = validate_snapshot_observed(&p, &snap, 16_000);
        assert!(!report.ok);
        assert_eq!(report.error.as_deref(), Some("stale"));
        assert_eq!(report.observation.stale_reject_total, 1);
        assert_eq!(report.metrics.oracle_stale_reject_total, 1);
        assert_eq!(report.metrics.accepted_total, 0);
        assert_eq!(report.metrics.sample_count, 1);
    }

    #[test]
    fn observed_report_maps_quorum_rejection_to_stable_error_label() {
        let p = policy();
        let snap = OracleSnapshot::new(
            "btc/usd",
            100_000,
            vec![source("coingecko")],
            1,
            Some(100_000),
            Some(120),
            1_000,
            2_000,
            10_000,
        )
        .expect("snapshot build");

        let report = validate_snapshot_observed(&p, &snap, 10_100);
        assert!(!report.ok);
        assert_eq!(report.error.as_deref(), Some("quorum"));
        assert_eq!(report.observation.quorum_reject_total, 1);
        assert_eq!(report.metrics.oracle_quorum_reject_total, 1);
        assert_eq!(report.metrics.oracle_source_cardinality, 1);
        assert_eq!(report.metrics.accepted_total, 0);
        assert_eq!(report.metrics.sample_count, 1);
    }

    #[test]
    fn observed_report_maps_inconsistent_sample_count_to_quorum_error_label() {
        let p = policy();
        let mut snap = OracleSnapshot::new(
            "btc/usd",
            100_000,
            vec![source("coingecko"), source("chainlink"), source("pyth")],
            3,
            Some(100_000),
            Some(120),
            1_000,
            2_000,
            10_000,
        )
        .expect("snapshot build");
        snap.sample_count = 2;
        snap.snapshot_hash = snap.compute_hash();

        let report = validate_snapshot_observed(&p, &snap, 10_100);
        assert!(!report.ok);
        assert_eq!(report.error.as_deref(), Some("quorum"));
        assert_eq!(report.observation.quorum_reject_total, 1);
        assert_eq!(report.metrics.oracle_quorum_reject_total, 1);
        assert_eq!(report.metrics.oracle_source_cardinality, 3);
        assert_eq!(report.metrics.accepted_total, 0);
        assert_eq!(report.metrics.sample_count, 1);
        assert!(report.classified_outcome_conserves_sample_count());
        assert!(report.bridge_contract_consistent());
    }

    #[test]
    fn observed_report_maps_drift_rejection_to_stable_error_label() {
        let p = policy();
        let snap = snapshot_with(120_000, Some(100_000), 10_000);

        let report = validate_snapshot_observed(&p, &snap, 10_100);
        assert!(!report.ok);
        assert_eq!(report.error.as_deref(), Some("drift"));
        assert_eq!(report.observation.drift_reject_total, 1);
        assert_eq!(report.metrics.oracle_drift_reject_total, 1);
        assert_eq!(report.metrics.oracle_source_cardinality, 2);
        assert_eq!(report.metrics.accepted_total, 0);
        assert_eq!(report.metrics.sample_count, 1);
    }

    #[test]
    fn observed_report_preserves_exact_drift_boundary_as_drift_label() {
        let p = policy();
        let snap = snapshot_with(105_000, Some(100_000), 10_000); // 500 bps

        let report = validate_snapshot_observed(&p, &snap, 10_100);
        assert!(!report.ok);
        assert_eq!(report.error.as_deref(), Some("drift"));
        assert_eq!(report.observation.drift_reject_total, 1);
        assert_eq!(report.metrics.oracle_drift_reject_total, 1);
        assert_eq!(report.metrics.oracle_source_cardinality, 2);
        assert_eq!(report.metrics.accepted_total, 0);
        assert_eq!(report.metrics.sample_count, 1);
        assert!(report.classified_outcome_conserves_sample_count());
    }

    #[test]
    fn observed_report_caps_extreme_drift_boundary_to_guardrail_ceiling() {
        let p = OraclePolicy {
            min_sources: 2,
            max_staleness_ms: 5_000,
            max_deviation_bps: MAX_DEVIATION_BPS_CAP,
            max_update_rate_per_window: 60,
        };
        let snap = snapshot_with(i128::MAX, Some(1), 10_000);

        let err = p
            .validate_snapshot(&snap, 10_100)
            .expect_err("extreme drift should fail closed at the capped guardrail");
        assert!(matches!(
            err,
            OracleError::DeviationExceeded {
                deviation_bps: MAX_DEVIATION_BPS_CAP,
                max_deviation_bps: MAX_DEVIATION_BPS_CAP,
            }
        ));

        let report = validate_snapshot_observed(&p, &snap, 10_100);
        assert!(!report.ok);
        assert_eq!(report.error.as_deref(), Some("drift"));
        assert_eq!(report.observation.drift_reject_total, 1);
        assert_eq!(report.metrics.oracle_drift_reject_total, 1);
        assert!(report.classified_outcome_conserves_sample_count());
    }

    #[test]
    fn observed_report_maps_update_rate_rejection_to_stable_error_label() {
        let p = policy();
        let snap = OracleSnapshot::new(
            "btc/usd",
            100_000,
            vec![source("coingecko"), source("chainlink")],
            61,
            Some(100_000),
            Some(120),
            1_000,
            2_000,
            10_000,
        )
        .expect("snapshot build");

        let report = validate_snapshot_observed(&p, &snap, 10_100);
        assert!(!report.ok);
        assert_eq!(report.error.as_deref(), Some("rate"));
        assert_eq!(report.observation.stale_reject_total, 0);
        assert_eq!(report.observation.quorum_reject_total, 0);
        assert_eq!(report.observation.drift_reject_total, 0);
        assert_eq!(report.observation.accepted_total, 0);
        assert_eq!(report.metrics.oracle_stale_reject_total, 0);
        assert_eq!(report.metrics.oracle_quorum_reject_total, 0);
        assert_eq!(report.metrics.oracle_drift_reject_total, 0);
        assert_eq!(report.metrics.oracle_source_cardinality, 2);
        assert_eq!(report.metrics.accepted_total, 0);
        assert_eq!(report.metrics.sample_count, 1);
        assert!(report.bridge_contract_consistent());
    }

    #[test]
    fn observed_report_preserves_unmapped_bridge_error_string_without_counter_drift() {
        let p = policy();
        let mut snap = snapshot_with(100_000, Some(100_100), 10_000);
        snap.snapshot_hash.push('x');

        let report = validate_snapshot_observed(&p, &snap, 10_100);
        assert!(!report.ok);
        assert!(matches!(
            report.error.as_deref(),
            Some(err) if err.starts_with("snapshot hash mismatch:")
        ));
        assert_eq!(report.observation.stale_reject_total, 0);
        assert_eq!(report.observation.quorum_reject_total, 0);
        assert_eq!(report.observation.drift_reject_total, 0);
        assert_eq!(report.observation.accepted_total, 0);
        assert_eq!(report.metrics.oracle_stale_reject_total, 0);
        assert_eq!(report.metrics.oracle_quorum_reject_total, 0);
        assert_eq!(report.metrics.oracle_drift_reject_total, 0);
        assert_eq!(report.metrics.oracle_source_cardinality, 2);
        assert_eq!(report.metrics.accepted_total, 0);
        assert_eq!(report.metrics.sample_count, 1);
        assert!(report.bridge_contract_consistent());
    }

    #[test]
    fn observed_report_preserves_invalid_policy_error_without_counter_drift() {
        let p = OraclePolicy {
            min_sources: 2,
            max_staleness_ms: 5_000,
            max_deviation_bps: 10_001,
            max_update_rate_per_window: 60,
        };
        let snap = snapshot_with(100_000, Some(100_100), 10_000);

        let report = validate_snapshot_observed(&p, &snap, 10_100);
        assert!(!report.ok);
        assert_eq!(
            report.error.as_deref(),
            Some("invalid policy: max_deviation_bps must be <= 10000")
        );
        assert_eq!(report.observation.stale_reject_total, 0);
        assert_eq!(report.observation.quorum_reject_total, 0);
        assert_eq!(report.observation.drift_reject_total, 0);
        assert_eq!(report.observation.accepted_total, 0);
        assert_eq!(report.metrics.oracle_stale_reject_total, 0);
        assert_eq!(report.metrics.oracle_quorum_reject_total, 0);
        assert_eq!(report.metrics.oracle_drift_reject_total, 0);
        assert_eq!(report.metrics.oracle_source_cardinality, 2);
        assert_eq!(report.metrics.accepted_total, 0);
        assert_eq!(report.metrics.sample_count, 1);
    }

    #[test]
    fn observed_report_preserves_future_snapshot_error_without_counter_drift() {
        let snap = snapshot_with(100_000, Some(100_100), 10_001);

        let report = validate_snapshot_observed(&policy(), &snap, 10_000);
        assert!(!report.ok);
        assert_eq!(
            report.error.as_deref(),
            Some("future snapshot: ts=10001, now=10000")
        );
        assert_eq!(report.observation.stale_reject_total, 0);
        assert_eq!(report.observation.quorum_reject_total, 0);
        assert_eq!(report.observation.drift_reject_total, 0);
        assert_eq!(report.observation.accepted_total, 0);
        assert_eq!(report.metrics.oracle_stale_reject_total, 0);
        assert_eq!(report.metrics.oracle_quorum_reject_total, 0);
        assert_eq!(report.metrics.oracle_drift_reject_total, 0);
        assert_eq!(report.metrics.oracle_source_cardinality, 2);
        assert_eq!(report.metrics.accepted_total, 0);
        assert_eq!(report.metrics.sample_count, 1);
        assert!(report.observation_matches_metrics());
        assert!(report.bridge_contract_consistent());
    }

    #[test]
    fn observed_report_keeps_single_snapshot_source_cardinality_on_unclassified_error() {
        let p = OraclePolicy {
            min_sources: 2,
            max_staleness_ms: 5_000,
            max_deviation_bps: 10_001,
            max_update_rate_per_window: 60,
        };
        let snap = OracleSnapshot::new(
            "btc/usd",
            100_000,
            vec![source("coingecko"), source("binance"), source("chainlink")],
            3,
            Some(100_100),
            Some(120),
            1_000,
            2_000,
            10_000,
        )
        .expect("snapshot should be valid");

        let report = validate_snapshot_observed(&p, &snap, 10_100);
        assert!(!report.ok);
        assert_eq!(
            report.error.as_deref(),
            Some("invalid policy: max_deviation_bps must be <= 10000")
        );
        assert_eq!(report.metrics.oracle_source_cardinality, 3);
        assert_eq!(report.metrics.accepted_total, 0);
        assert_eq!(report.metrics.classified_reject_total(), 0);
        assert_eq!(report.metrics.sample_count, 1);
    }

    #[test]
    fn observed_report_preserves_single_snapshot_counter_conservation_for_classified_outcomes() {
        let reports = vec![
            validate_snapshot_observed(
                &policy(),
                &snapshot_with(100_000, Some(100_100), 10_000),
                10_100,
            ),
            validate_snapshot_observed(
                &policy(),
                &snapshot_with(100_000, Some(100_100), 10_000),
                16_000,
            ),
            validate_snapshot_observed(
                &policy(),
                &snapshot_with(120_000, Some(100_000), 10_000),
                10_100,
            ),
            validate_snapshot_observed(
                &policy(),
                &OracleSnapshot::new(
                    "btc/usd",
                    100_000,
                    vec![source("coingecko")],
                    1,
                    Some(100_000),
                    Some(120),
                    1_000,
                    2_000,
                    10_000,
                )
                .expect("snapshot build"),
                10_100,
            ),
        ];

        for report in reports {
            assert_eq!(report.metrics.sample_count, 1);
            assert!(report.classified_outcome_conserves_sample_count());
            assert_eq!(
                report.metrics.classified_outcome_total(),
                report.metrics.sample_count
            );
            assert_eq!(
                report.observation.accepted_total, report.metrics.accepted_total,
                "observation/metrics accepted_total drifted for error {:?}",
                report.error
            );
        }
    }

    #[test]
    fn observed_report_helpers_exclude_unclassified_errors_from_reject_total() {
        let report = validate_snapshot_observed(
            &policy(),
            &OracleSnapshot::new(
                "btc/usd",
                100_000,
                vec![source("coingecko"), source("chainlink")],
                61,
                Some(100_000),
                Some(120),
                1_000,
                2_000,
                10_000,
            )
            .expect("snapshot build"),
            10_100,
        );

        assert_eq!(report.error.as_deref(), Some("rate"));
        assert_eq!(report.metrics.classified_reject_total(), 0);
        assert_eq!(report.metrics.classified_outcome_total(), 0);
        assert!(!report.classified_outcome_conserves_sample_count());
        assert_eq!(report.metrics.sample_count, 1);
    }

    #[test]
    fn observed_report_uses_canonical_source_cardinality_for_deserialized_duplicates() {
        let snapshot: OracleSnapshot = serde_json::from_value(serde_json::json!({
            "feed_id": "btc/usd",
            "value": 100000,
            "sources": ["coingecko", "chainlink", "coingecko"],
            "sample_count": 3,
            "median": 100000,
            "mad": 120,
            "window_start_ms": 1000,
            "window_end_ms": 2000,
            "snapshot_ts_ms": 10000,
            "snapshot_hash": "broken"
        }))
        .expect("snapshot deserialize");

        let report = validate_snapshot_observed(&policy(), &snapshot, 10_100);

        assert!(!report.ok);
        assert_eq!(
            report.error.as_deref(),
            Some("duplicate source ids are not allowed")
        );
        assert_eq!(report.metrics.oracle_source_cardinality, 2);
    }

    #[test]
    fn observed_report_excludes_blank_source_ids_from_canonical_source_cardinality() {
        let snapshot: OracleSnapshot = serde_json::from_value(serde_json::json!({
            "feed_id": "btc/usd",
            "value": 100000,
            "sources": ["coingecko", "   "],
            "sample_count": 2,
            "median": 100000,
            "mad": 120,
            "window_start_ms": 1000,
            "window_end_ms": 2000,
            "snapshot_ts_ms": 10000,
            "snapshot_hash": "broken"
        }))
        .expect("snapshot deserialize");

        let report = validate_snapshot_observed(&policy(), &snapshot, 10_100);

        assert!(!report.ok);
        assert_eq!(report.error.as_deref(), Some("source id is empty"));
        assert_eq!(report.metrics.oracle_source_cardinality, 1);
    }

    #[test]
    fn observed_report_treats_deserialized_duplicate_sources_as_contract_consistent_unclassified_failure() {
        let snapshot: OracleSnapshot = serde_json::from_value(serde_json::json!({
            "feed_id": "btc/usd",
            "value": 100000,
            "sources": ["coingecko", "chainlink", "coingecko"],
            "sample_count": 3,
            "median": 100000,
            "mad": 120,
            "window_start_ms": 1000,
            "window_end_ms": 2000,
            "snapshot_ts_ms": 10000,
            "snapshot_hash": "broken"
        }))
        .expect("snapshot deserialize");

        let report = validate_snapshot_observed(&policy(), &snapshot, 10_100);

        assert!(!report.ok);
        assert_eq!(report.error.as_deref(), Some("duplicate source ids are not allowed"));
        assert_eq!(report.metrics.oracle_source_cardinality, 2);
        assert_eq!(report.metrics.accepted_total, 0);
        assert_eq!(report.classified_reject_total(), 0);
        assert_eq!(report.classified_outcome_total(), 0);
        assert!(!report.classified_outcome_conserves_sample_count());
        assert!(report.observation_matches_metrics());
        assert!(report.bridge_contract_consistent());
    }

    #[test]
    fn rejects_deserialized_duplicate_sources_even_with_matching_hash() {
        let mut snapshot: OracleSnapshot = serde_json::from_value(serde_json::json!({
            "feed_id": "btc/usd",
            "value": 100000,
            "sources": ["coingecko", "chainlink", "coingecko"],
            "sample_count": 3,
            "median": 100000,
            "mad": 120,
            "window_start_ms": 1000,
            "window_end_ms": 2000,
            "snapshot_ts_ms": 10000,
            "snapshot_hash": "broken"
        }))
        .expect("snapshot deserialize");
        snapshot.snapshot_hash = snapshot.compute_hash();

        let err = policy()
            .validate_snapshot(&snapshot, 10_100)
            .expect_err("deserialized duplicate sources must fail guardrail");
        assert_eq!(err, OracleError::DuplicateSources);
    }

    #[test]
    fn rejects_deserialized_non_canonical_feed_id_even_with_matching_hash() {
        let mut snapshot: OracleSnapshot = serde_json::from_value(serde_json::json!({
            "feed_id": " BTC/USD ",
            "value": 100000,
            "sources": ["coingecko", "chainlink"],
            "sample_count": 2,
            "median": 100000,
            "mad": 120,
            "window_start_ms": 1000,
            "window_end_ms": 2000,
            "snapshot_ts_ms": 10000,
            "snapshot_hash": "broken"
        }))
        .expect("snapshot deserialize");
        snapshot.snapshot_hash = snapshot.compute_hash();

        let err = policy()
            .validate_snapshot(&snapshot, 10_100)
            .expect_err("deserialized non-canonical feed id must fail guardrail");
        assert_eq!(
            err,
            OracleError::NonCanonicalFeedId {
                raw: " BTC/USD ".to_string(),
                canonical: "btc/usd".to_string(),
            }
        );
    }

    #[test]
    fn rejects_deserialized_empty_feed_id_even_with_matching_hash() {
        let mut snapshot: OracleSnapshot = serde_json::from_value(serde_json::json!({
            "feed_id": "   ",
            "value": 100000,
            "sources": ["coingecko", "chainlink"],
            "sample_count": 2,
            "median": 100000,
            "mad": 120,
            "window_start_ms": 1000,
            "window_end_ms": 2000,
            "snapshot_ts_ms": 10000,
            "snapshot_hash": "broken"
        }))
        .expect("snapshot deserialize");
        snapshot.snapshot_hash = snapshot.compute_hash();

        let err = policy()
            .validate_snapshot(&snapshot, 10_100)
            .expect_err("deserialized blank feed id must fail guardrail");
        assert_eq!(err, OracleError::EmptyFeedId);
    }

    #[test]
    fn rejects_deserialized_non_canonical_source_id_even_with_matching_hash() {
        let mut snapshot: OracleSnapshot = serde_json::from_value(serde_json::json!({
            "feed_id": "btc/usd",
            "value": 100000,
            "sources": ["coingecko", " Chainlink "],
            "sample_count": 2,
            "median": 100000,
            "mad": 120,
            "window_start_ms": 1000,
            "window_end_ms": 2000,
            "snapshot_ts_ms": 10000,
            "snapshot_hash": "broken"
        }))
        .expect("snapshot deserialize");
        snapshot.snapshot_hash = snapshot.compute_hash();

        let err = policy()
            .validate_snapshot(&snapshot, 10_100)
            .expect_err("deserialized non-canonical source id must fail guardrail");
        assert_eq!(
            err,
            OracleError::NonCanonicalSourceId {
                raw: " Chainlink ".to_string(),
                canonical: "chainlink".to_string(),
            }
        );
    }

    #[test]
    fn rejects_deserialized_empty_source_id_even_with_matching_hash() {
        let mut snapshot: OracleSnapshot = serde_json::from_value(serde_json::json!({
            "feed_id": "btc/usd",
            "value": 100000,
            "sources": ["coingecko", "   "],
            "sample_count": 2,
            "median": 100000,
            "mad": 120,
            "window_start_ms": 1000,
            "window_end_ms": 2000,
            "snapshot_ts_ms": 10000,
            "snapshot_hash": "broken"
        }))
        .expect("snapshot deserialize");
        snapshot.snapshot_hash = snapshot.compute_hash();

        let err = policy()
            .validate_snapshot(&snapshot, 10_100)
            .expect_err("deserialized blank source id must fail guardrail");
        assert_eq!(err, OracleError::EmptySourceId);
    }

    #[test]
    fn rejects_deserialized_zero_sample_count_even_with_matching_hash() {
        let mut snapshot: OracleSnapshot = serde_json::from_value(serde_json::json!({
            "feed_id": "btc/usd",
            "value": 100000,
            "sources": ["chainlink", "coingecko"],
            "sample_count": 0,
            "median": 100000,
            "mad": 120,
            "window_start_ms": 1000,
            "window_end_ms": 2000,
            "snapshot_ts_ms": 10000,
            "snapshot_hash": "broken"
        }))
        .expect("snapshot deserialize");
        snapshot.snapshot_hash = snapshot.compute_hash();

        let err = policy()
            .validate_snapshot(&snapshot, 10_100)
            .expect_err("deserialized zero sample count must fail guardrail");
        assert_eq!(err, OracleError::InvalidPolicy("sample_count must be > 0"));
    }

    #[test]
    fn rejects_deserialized_unsorted_sources_even_with_matching_hash() {
        let mut snapshot: OracleSnapshot = serde_json::from_value(serde_json::json!({
            "feed_id": "btc/usd",
            "value": 100000,
            "sources": ["pyth", "chainlink", "coingecko"],
            "sample_count": 3,
            "median": 100000,
            "mad": 120,
            "window_start_ms": 1000,
            "window_end_ms": 2000,
            "snapshot_ts_ms": 10000,
            "snapshot_hash": "broken"
        }))
        .expect("snapshot deserialize");
        snapshot.snapshot_hash = snapshot.compute_hash();

        let err = policy()
            .validate_snapshot(&snapshot, 10_100)
            .expect_err("deserialized source ordering must stay canonical");
        assert_eq!(
            err,
            OracleError::NonCanonicalSourceOrdering {
                previous: "pyth".to_string(),
                current: "chainlink".to_string(),
            }
        );
    }

    #[test]
    fn observed_report_preserves_unsorted_source_error_without_counter_drift() {
        let mut snapshot: OracleSnapshot = serde_json::from_value(serde_json::json!({
            "feed_id": "btc/usd",
            "value": 100000,
            "sources": ["pyth", "chainlink", "coingecko"],
            "sample_count": 3,
            "median": 100000,
            "mad": 120,
            "window_start_ms": 1000,
            "window_end_ms": 2000,
            "snapshot_ts_ms": 10000,
            "snapshot_hash": "broken"
        }))
        .expect("snapshot deserialize");
        snapshot.snapshot_hash = snapshot.compute_hash();

        let report = validate_snapshot_observed(&policy(), &snapshot, 10_100);
        assert!(!report.ok);
        assert_eq!(
            report.error.as_deref(),
            Some("source ids must be sorted canonically: previous=pyth, current=chainlink")
        );
        assert_eq!(report.observation.stale_reject_total, 0);
        assert_eq!(report.observation.quorum_reject_total, 0);
        assert_eq!(report.observation.drift_reject_total, 0);
        assert_eq!(report.observation.accepted_total, 0);
        assert_eq!(report.metrics.oracle_stale_reject_total, 0);
        assert_eq!(report.metrics.oracle_quorum_reject_total, 0);
        assert_eq!(report.metrics.oracle_drift_reject_total, 0);
        assert_eq!(report.metrics.oracle_source_cardinality, 3);
        assert_eq!(report.metrics.accepted_total, 0);
        assert_eq!(report.metrics.sample_count, 1);
    }

    #[test]
    fn observation_helpers_match_metrics_helpers_for_classified_outcomes() {
        let reports = vec![
            validate_snapshot_observed(
                &policy(),
                &snapshot_with(100_000, Some(100_100), 10_000),
                10_100,
            ),
            validate_snapshot_observed(
                &policy(),
                &snapshot_with(100_000, Some(100_100), 10_000),
                16_000,
            ),
            validate_snapshot_observed(
                &policy(),
                &OracleSnapshot::new(
                    "btc/usd",
                    100_000,
                    vec![source("coingecko")],
                    1,
                    Some(100_000),
                    Some(120),
                    1_000,
                    2_000,
                    10_000,
                )
                .expect("quorum snapshot build"),
                10_100,
            ),
            validate_snapshot_observed(
                &policy(),
                &snapshot_with(120_000, Some(100_000), 10_000),
                10_100,
            ),
        ];

        for report in reports {
            assert_eq!(
                report.observation_classified_reject_total(),
                report.classified_reject_total(),
                "classified reject totals drifted for error {:?}",
                report.error
            );
            assert_eq!(
                report.observation_classified_outcome_total(),
                report.classified_outcome_total(),
                "classified outcome totals drifted for error {:?}",
                report.error
            );
            assert_eq!(
                report.observation.classified_reject_total(),
                report.observation_classified_reject_total(),
                "observation helper drifted for error {:?}",
                report.error
            );
            assert_eq!(
                report.metrics.classified_reject_total(),
                report.classified_reject_total(),
                "metrics helper drifted for error {:?}",
                report.error
            );
            assert_eq!(
                report.observation.classified_outcome_total(),
                report.observation_classified_outcome_total(),
                "observation outcome helper drifted for error {:?}",
                report.error
            );
            assert_eq!(
                report.metrics.classified_outcome_total(),
                report.classified_outcome_total(),
                "metrics outcome helper drifted for error {:?}",
                report.error
            );
            assert_eq!(
                report
                    .observation
                    .classified_outcome_conserves_sample_count(report.metrics.sample_count),
                report.classified_outcome_conserves_sample_count(),
                "classified sample-count conservation drifted for error {:?}",
                report.error
            );
            assert!(
                report.observation_matches_metrics(),
                "observation/metrics bridge mapping drifted for error {:?}",
                report.error
            );
            assert!(
                report.bridge_contract_consistent(),
                "bridge contract drifted for error {:?}",
                report.error
            );
        }
    }

    #[test]
    fn observation_helpers_keep_unclassified_errors_out_of_classified_totals() {
        let report = validate_snapshot_observed(
            &policy(),
            &OracleSnapshot::new(
                "btc/usd",
                100_000,
                vec![source("coingecko"), source("chainlink")],
                61,
                Some(100_000),
                Some(120),
                1_000,
                2_000,
                10_000,
            )
            .expect("snapshot build"),
            10_100,
        );

        assert_eq!(report.error.as_deref(), Some("rate"));
        assert_eq!(report.observation.classified_reject_total(), 0);
        assert_eq!(report.observation.classified_outcome_total(), 0);
        assert!(!report
            .observation
            .classified_outcome_conserves_sample_count(report.metrics.sample_count));
        assert_eq!(
            report.observation.classified_reject_total(),
            report.metrics.classified_reject_total()
        );
        assert_eq!(
            report.observation.classified_outcome_total(),
            report.metrics.classified_outcome_total()
        );
    }

    #[test]
    fn bridge_contract_consistent_rejects_metrics_sample_count_mismatch() {
        let mut report = validate_snapshot_observed(
            &policy(),
            &snapshot_with(100_000, Some(100_100), 10_000),
            10_100,
        );

        assert!(report.bridge_contract_consistent());
        report.metrics.sample_count = 0;

        assert!(!report.classified_outcome_conserves_sample_count());
        assert!(report.observation_matches_metrics());
        assert!(!report.observation_classified_outcome_conserves_sample_count());
        assert!(!report.bridge_contract_consistent());
    }

    #[test]
    fn bridge_contract_consistent_rejects_empty_bridge_sample_even_when_counters_align() {
        let mut report = validate_snapshot_observed(
            &policy(),
            &snapshot_with(100_000, Some(100_100), 10_000),
            10_100,
        );

        assert!(report.bridge_contract_consistent());
        report.ok = false;
        report.error = Some("stale".to_string());
        report.observation.accepted_total = 0;
        report.observation.stale_reject_total = 0;
        report.metrics.accepted_total = 0;
        report.metrics.oracle_stale_reject_total = 0;
        report.metrics.sample_count = 0;

        assert!(report.observation_matches_metrics());
        assert!(report.classified_outcome_conserves_sample_count());
        assert!(report.observation_classified_outcome_conserves_sample_count());
        assert!(!report.bridge_contract_consistent());
    }

    #[test]
    fn bridge_contract_consistent_rejects_ok_error_coherence_drift() {
        let mut success = validate_snapshot_observed(
            &policy(),
            &snapshot_with(100_000, Some(100_100), 10_000),
            10_100,
        );
        assert!(success.bridge_contract_consistent());
        success.error = Some("stale".to_string());
        assert!(!success.bridge_contract_consistent());

        let mut failure = validate_snapshot_observed(
            &policy(),
            &snapshot_with(100_000, Some(100_100), 10_000),
            16_000,
        );
        assert!(failure.bridge_contract_consistent());
        failure.error = None;
        assert!(!failure.bridge_contract_consistent());
    }

    #[test]
    fn bridge_contract_consistent_rejects_blank_unclassified_error_label() {
        let mut report = validate_snapshot_observed(
            &policy(),
            &OracleSnapshot::new(
                "btc/usd",
                100_000,
                vec![source("coingecko"), source("chainlink")],
                61,
                Some(100_000),
                Some(120),
                1_000,
                2_000,
                10_000,
            )
            .expect("snapshot build"),
            10_100,
        );

        assert!(report.error.is_some());
        report.error = Some(" \n\t ".to_string());

        assert!(!report.bridge_contract_consistent());
    }
}
