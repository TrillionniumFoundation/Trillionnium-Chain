use super::shared::{policy, snapshot_with, source};
use super::*;

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
