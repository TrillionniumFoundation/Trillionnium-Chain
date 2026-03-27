use crate::{OracleError, OracleSnapshot, MAX_DEVIATION_BPS_CAP};
use serde::{Deserialize, Serialize};

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

        if snapshot.snapshot_ts_ms > now_ts_ms {
            return Err(OracleError::FutureSnapshot {
                snapshot_ts_ms: snapshot.snapshot_ts_ms,
                now_ts_ms,
            });
        }

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
            let exceeds_deviation_boundary = deviation > self.max_deviation_bps
                || (self.max_deviation_bps != 0 && deviation == self.max_deviation_bps);
            if exceeds_deviation_boundary {
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

    let numerator = value
        .abs_diff(baseline)
        .saturating_mul(MAX_DEVIATION_BPS_CAP as u128);
    let denominator = baseline.unsigned_abs();
    let scaled = numerator / denominator;
    scaled.min(MAX_DEVIATION_BPS_CAP as u128) as u32
}
