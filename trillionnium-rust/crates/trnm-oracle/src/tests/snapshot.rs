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
fn policy_accepts_snapshot_exactly_at_staleness_boundary() {
    let p = super::shared::policy();
    let snap = snapshot_with(100_000, Some(100_100), 10_000);

    p.validate_snapshot(&snap, 15_000)
        .expect("boundary staleness should remain valid");
}

#[test]
fn snapshot_new_rejects_duplicate_sources_after_canonical_sort() {
    let err = OracleSnapshot::new(
        "btc/usd",
        100_000,
        vec![source("chainlink"), source("coingecko"), source("chainlink")],
        3,
        Some(99_900),
        Some(10),
        1_000,
        2_000,
        10_000,
    )
    .expect_err("duplicate oracle sources must fail closed before settlement layering");

    assert_eq!(err, OracleError::DuplicateSources);
}
