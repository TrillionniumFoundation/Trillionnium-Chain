use super::*;

#[test]
fn governance_param_whitelist_enforced() {
    let mut st = StateStore::new();
    let ok = st
        .set_gov_param_unchecked(7001, "max_block_ms".into(), "10".into())
        .unwrap();
    assert_eq!(ok.version, 1);

    let cur = st.get_param(7001).unwrap();
    assert_eq!(cur.key, "max_block_ms");
    assert_eq!(cur.value, "10");

    let bounty_ok = st
        .set_gov_param_unchecked(7003, "challenge_success_bounty".into(), "5".into())
        .unwrap();
    assert_eq!(bounty_ok.version, 1);

    let err = st
        .set_gov_param_unchecked(7002, "forbidden_key".into(), "1".into())
        .unwrap_err();
    assert!(err.contains("not allowed"));
}
#[test]
fn governance_param_schema_rejects_invalid_u64_values() {
    let mut st = StateStore::new();

    let err = st
        .set_gov_param_unchecked(7101, "max_block_ms".into(), "abc".into())
        .unwrap_err();
    assert!(err.contains("expected u64"));

    let err = st
        .set_gov_param_unchecked(7101, "max_parallel_workers".into(), "0".into())
        .unwrap_err();
    assert!(err.contains("out of range"));

    let ok = st
        .set_gov_param_unchecked(7101, "max_parallel_workers".into(), "32".into())
        .unwrap();
    assert_eq!(ok.version, 1);

    let err = st
        .set_gov_param_unchecked(7102, "challenge_window_blocks".into(), "99".into())
        .unwrap_err();
    assert!(err.contains("out of range"));

    let err = st
        .set_gov_param_unchecked(7103, "min_worker_stake".into(), "0".into())
        .unwrap_err();
    assert!(err.contains("out of range"));

    let err = st
        .set_gov_param_unchecked(7104, "challenge_min_bond".into(), "0".into())
        .unwrap_err();
    assert!(err.contains("out of range"));

    let err = st
        .set_gov_param_unchecked(7105, "challenge_success_bounty".into(), "-1".into())
        .unwrap_err();
    assert!(err.contains("expected u64"));

    let err = st
        .set_gov_param_unchecked(
            7105,
            "challenge_min_bond_bounty_bps".into(),
            "100001".into(),
        )
        .unwrap_err();
    assert!(err.contains("out of range"));

    let ok = st
        .set_gov_param_unchecked(
            7106,
            "challenge_min_bond_worker_stake_bps".into(),
            "0".into(),
        )
        .unwrap();
    assert_eq!(ok.version, 1);
}
