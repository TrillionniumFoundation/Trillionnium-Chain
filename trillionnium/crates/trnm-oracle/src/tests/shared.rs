use super::*;

pub fn source(id: &str) -> OracleSourceId {
    OracleSourceId::parse(id).expect("valid source id")
}

pub fn policy() -> OraclePolicy {
    OraclePolicy {
        min_sources: 2,
        max_staleness_ms: 5_000,
        max_deviation_bps: 500,
        max_update_rate_per_window: 60,
    }
}

pub fn snapshot_with(value: i128, median: Option<i128>, snapshot_ts_ms: u64) -> OracleSnapshot {
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
