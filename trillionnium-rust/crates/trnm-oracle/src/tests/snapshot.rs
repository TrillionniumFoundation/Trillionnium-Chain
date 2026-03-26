use super::shared::{snapshot_with, source};
use super::*;

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
fn snapshot_hash_binds_checkpoint_window_and_timestamp_surface() {
    let baseline = OracleSnapshot::new(
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
    .expect("baseline snapshot");

    let shifted_start = OracleSnapshot::new(
        "btc/usd",
        100_000,
        vec![source("coingecko"), source("chainlink")],
        2,
        Some(99_900),
        Some(10),
        1_001,
        2_000,
        10_000,
    )
    .expect("shifted start snapshot");

    let shifted_end = OracleSnapshot::new(
        "btc/usd",
        100_000,
        vec![source("coingecko"), source("chainlink")],
        2,
        Some(99_900),
        Some(10),
        1_000,
        2_001,
        10_000,
    )
    .expect("shifted end snapshot");

    let shifted_ts = OracleSnapshot::new(
        "btc/usd",
        100_000,
        vec![source("coingecko"), source("chainlink")],
        2,
        Some(99_900),
        Some(10),
        1_000,
        2_000,
        10_001,
    )
    .expect("shifted timestamp snapshot");

    assert_ne!(
        baseline.snapshot_hash, shifted_start.snapshot_hash,
        "snapshot hash must bind window_start_ms so adjacent checkpoint windows cannot share a proof surface"
    );
    assert_ne!(
        baseline.snapshot_hash, shifted_end.snapshot_hash,
        "snapshot hash must bind window_end_ms so adjacent checkpoint windows cannot share a proof surface"
    );
    assert_ne!(
        baseline.snapshot_hash, shifted_ts.snapshot_hash,
        "snapshot hash must bind snapshot_ts_ms so identical windows published at different proof times cannot hash identically"
    );
}

#[test]
fn policy_accepts_snapshot_exactly_at_staleness_boundary() {
    let p = super::shared::policy();
    let snap = snapshot_with(100_000, Some(100_100), 10_000);

    p.validate_snapshot(&snap, 15_000)
        .expect("boundary staleness should remain valid");
}
