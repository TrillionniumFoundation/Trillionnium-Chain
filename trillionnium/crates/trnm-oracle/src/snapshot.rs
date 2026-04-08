use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::OracleError;

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
