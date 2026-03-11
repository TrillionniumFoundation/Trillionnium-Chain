use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
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
        let feed_id = feed_id.into().trim().to_ascii_lowercase();
        if feed_id.is_empty() {
            return Err(OracleError::EmptyFeedId);
        }
        if window_end_ms < window_start_ms {
            return Err(OracleError::InvalidWindow {
                start_ms: window_start_ms,
                end_ms: window_end_ms,
            });
        }

        sources.sort();
        if sources.windows(2).any(|w| w[0] == w[1]) {
            return Err(OracleError::DuplicateSources);
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

    pub fn validate_snapshot(
        &self,
        snapshot: &OracleSnapshot,
        now_ts_ms: u64,
    ) -> Result<(), OracleError> {
        self.validate()?;
        snapshot.validate_hash()?;

        if now_ts_ms.saturating_sub(snapshot.snapshot_ts_ms) > self.max_staleness_ms {
            return Err(OracleError::StaleSnapshot {
                snapshot_ts_ms: snapshot.snapshot_ts_ms,
                now_ts_ms,
                max_staleness_ms: self.max_staleness_ms,
            });
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

        if let Some(median) = snapshot.median {
            let deviation = deviation_bps(snapshot.value, median);
            if deviation > self.max_deviation_bps {
                return Err(OracleError::DeviationExceeded {
                    deviation_bps: deviation,
                    max_deviation_bps: self.max_deviation_bps,
                });
            }
        }

        Ok(())
    }
}

fn deviation_bps(value: i128, baseline: i128) -> u32 {
    if baseline == value {
        return 0;
    }
    if baseline == 0 {
        return MAX_DEVIATION_BPS_CAP;
    }

    let numerator = value.abs_diff(baseline) as u128 * 10_000;
    let denominator = baseline.unsigned_abs();
    (numerator / denominator) as u32
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum OracleError {
    #[error("source id is empty")]
    EmptySourceId,
    #[error("source id must be canonical lowercase+trim: raw={raw}, canonical={canonical}")]
    NonCanonicalSourceId { raw: String, canonical: String },
    #[error("feed id is empty")]
    EmptyFeedId,
    #[error("invalid window: start={start_ms}, end={end_ms}")]
    InvalidWindow { start_ms: u64, end_ms: u64 },
    #[error("duplicate source ids are not allowed")]
    DuplicateSources,
    #[error("snapshot hash mismatch: expected={expected}, actual={actual}")]
    SnapshotHashMismatch { expected: String, actual: String },
    #[error("invalid policy: {0}")]
    InvalidPolicy(&'static str),
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
    fn rejects_stale_snapshot() {
        let p = policy();
        let snap = snapshot_with(100_000, Some(100_100), 10_000);

        let err = p
            .validate_snapshot(&snap, 16_000)
            .expect_err("snapshot should be stale");
        assert!(matches!(err, OracleError::StaleSnapshot { .. }));
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
    fn rejects_deviation_exceeded() {
        let p = policy();
        let snap = snapshot_with(120_000, Some(100_000), 10_000); // 2000 bps

        let err = p
            .validate_snapshot(&snap, 10_100)
            .expect_err("snapshot should fail drift check");
        assert!(matches!(err, OracleError::DeviationExceeded { .. }));
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
            "BTC/USD",
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
    fn policy_accepts_snapshot_exactly_at_staleness_boundary() {
        let p = policy();
        let snap = snapshot_with(100_000, Some(100_100), 10_000);

        p.validate_snapshot(&snap, 15_000)
            .expect("boundary staleness should remain valid");
    }
}
