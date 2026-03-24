use super::*;

#[test]
fn auto_adaptive_sampling_includes_batch_tail_for_hotspot_estimate() {
    let _env = env_lock();
    let _streak = EnvGuard::set("TRNM_AUTO_HOT_STREAK_RATIO", "0.0");
    let _margin = EnvGuard::set("TRNM_AUTO_REORDER_MIN_MARGIN", "0.0");
    let _share = EnvGuard::set("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE", "0.0007");
    let _gain = EnvGuard::set("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE", "0.0");

    // sample_len clamps to 2048. Duplicate key appears only at the first and
    // final tx. Endpoint-inclusive sampling must capture both to avoid
    // underestimating tail hotspots.
    let mut txs = Vec::with_capacity(3000);
    txs.push(tx(1, vec![], vec![o(777)]));
    for i in 1..2999u64 {
        txs.push(tx(10_000 + i, vec![], vec![o(20_000 + i)]));
    }
    txs.push(tx(9_999, vec![], vec![o(777)]));

    let d = auto_adaptive_decision(&txs);
    assert!(d.use_hot_bucket, "tail hotspot should be counted in sample");
    assert_eq!(d.reason, "hotspot_detected");
}

#[test]
fn auto_adaptive_sampling_includes_batch_tail_for_read_only_hotspot_estimate() {
    let _env = env_lock();
    let _streak = EnvGuard::set("TRNM_AUTO_HOT_STREAK_RATIO", "0.0");
    let _margin = EnvGuard::set("TRNM_AUTO_REORDER_MIN_MARGIN", "0.0");
    let _share = EnvGuard::set("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE", "0.0007");
    let _gain = EnvGuard::set("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE", "0.0");

    // Keep the read-only counterpart to the endpoint-inclusive sampling
    // regression so adaptive tuning does not lose tail visibility when the
    // detector falls back from write_set to read_set keys.
    let mut txs = Vec::with_capacity(3000);
    txs.push(tx(1, vec![o(777)], vec![]));
    for i in 1..2999u64 {
        txs.push(tx(10_000 + i, vec![o(20_000 + i)], vec![]));
    }
    txs.push(tx(9_999, vec![o(777)], vec![]));

    let d = auto_adaptive_decision(&txs);
    assert!(
        d.use_hot_bucket,
        "read-only tail hotspot should be counted in sample"
    );
    assert_eq!(d.reason, "hotspot_detected");
}

#[test]
fn auto_adaptive_expected_gain_gate_blocks_low_value_hotspot_switches() {
    let _env = env_lock();
    let _streak = EnvGuard::set("TRNM_AUTO_HOT_STREAK_RATIO", "0.0");
    let _margin = EnvGuard::set("TRNM_AUTO_REORDER_MIN_MARGIN", "0.0");
    let _share = EnvGuard::set("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE", "0.0007");
    let _gain = EnvGuard::set("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE", "0.001");

    // Same endpoint-visible hotspot shape as the tail-sampling regression,
    // but with a gain threshold slightly above the observed streak*share.
    // Adaptive mode should fail closed instead of switching strategies on a
    // low-value hotspot signal.
    let mut txs = Vec::with_capacity(3000);
    txs.push(tx(1, vec![], vec![o(777)]));
    for i in 1..2999u64 {
        txs.push(tx(10_000 + i, vec![], vec![o(20_000 + i)]));
    }
    txs.push(tx(9_999, vec![], vec![o(777)]));

    let d = auto_adaptive_decision(&txs);
    assert!(d.expected_gain_score < d.min_expected_gain_score);
    assert!(
        !d.use_hot_bucket,
        "low-value hotspot signal should not switch adaptive strategy"
    );
    assert_eq!(d.reason, "low_expected_gain");
}

#[test]
fn auto_adaptive_read_only_expected_gain_gate_blocks_low_value_hotspot_switches() {
    let _env = env_lock();
    let _streak = EnvGuard::set("TRNM_AUTO_HOT_STREAK_RATIO", "0.0");
    let _margin = EnvGuard::set("TRNM_AUTO_REORDER_MIN_MARGIN", "0.0");
    let _share = EnvGuard::set("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE", "0.0007");
    let _gain = EnvGuard::set("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE", "0.001");

    // Mirror the low-value endpoint-hotspot regression for read-only
    // batches, where adaptive detection falls back to read_set keys.
    // Endpoint-visible sampling should stay fail-closed instead of
    // switching strategies on a trivial read-domain signal.
    let mut txs = Vec::with_capacity(3000);
    txs.push(tx(1, vec![o(777)], vec![]));
    for i in 1..2999u64 {
        txs.push(tx(10_000 + i, vec![o(20_000 + i)], vec![]));
    }
    txs.push(tx(9_999, vec![o(777)], vec![]));

    let d = auto_adaptive_decision(&txs);
    assert!(d.expected_gain_score < d.min_expected_gain_score);
    assert!(
        !d.use_hot_bucket,
        "low-value read-only hotspot signal should not switch adaptive strategy"
    );
    assert_eq!(d.reason, "low_expected_gain");
}

#[test]
fn auto_adaptive_expected_gain_gate_accepts_percent_form_env_values() {
    let _env = env_lock();
    let _min_batch = EnvGuard::set("TRNM_AUTO_MIN_BATCH_LEN", "64");
    let _sample_len = EnvGuard::set("TRNM_AUTO_SAMPLE_LEN", "64");
    let _streak = EnvGuard::set("TRNM_AUTO_HOT_STREAK_RATIO", "25%");
    let _margin = EnvGuard::set("TRNM_AUTO_REORDER_MIN_MARGIN", "0.0");
    let _share = EnvGuard::set("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE", "25%");
    let _gain = EnvGuard::set("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE", "25.5%");

    // Experimental lanes tune the expected-gain guard via env knobs. Keep
    // percent-form values wired through the parser so operators can raise
    // the gain floor without accidentally enabling adaptive mode.
    let mut txs = Vec::with_capacity(64);
    for i in 0..16u64 {
        txs.push(tx(120_000 + i * 4, vec![], vec![o(42)]));
        txs.push(tx(120_001 + i * 4, vec![], vec![o(42)]));
        txs.push(tx(120_002 + i * 4, vec![], vec![o(1_000 + i)]));
        txs.push(tx(120_003 + i * 4, vec![], vec![o(2_000 + i)]));
    }

    let d = auto_adaptive_decision(&txs);
    assert_eq!(d.sample_len, 64);
    assert!((d.streak_ratio - (16.0 / 63.0)).abs() < f64::EPSILON);
    assert!((d.hot_key_share - 0.5).abs() < f64::EPSILON);
    assert!((d.expected_gain_score - ((16.0 / 63.0) * 0.5)).abs() < f64::EPSILON);
    assert!((d.min_expected_gain_score - 0.255).abs() < f64::EPSILON);
    assert!(d.expected_gain_score < d.min_expected_gain_score);
    assert!(!d.use_hot_bucket);
    assert_eq!(d.reason, "low_expected_gain");
}

#[test]
fn auto_adaptive_expected_gain_boundary_is_inclusive() {
    let _env = env_lock();
    let _min_batch = EnvGuard::set("TRNM_AUTO_MIN_BATCH_LEN", "64");
    let _sample_len = EnvGuard::set("TRNM_AUTO_SAMPLE_LEN", "64");
    let _baseline_streak = EnvGuard::set("TRNM_AUTO_HOT_STREAK_RATIO", "0.0");
    let _baseline_margin = EnvGuard::set("TRNM_AUTO_REORDER_MIN_MARGIN", "0.0");
    let _baseline_share = EnvGuard::set("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE", "0.0");
    let _baseline_gain = EnvGuard::set("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE", "0.0");

    // Keep the expected-gain gate inclusive (`>=`) at exact equality so
    // experimental adaptive tuning can set a precise floor without a
    // float-boundary off-by-one silently suppressing the hotspot switch.
    let mut txs = Vec::with_capacity(64);
    for i in 0..16u64 {
        txs.push(tx(130_000 + i * 4, vec![], vec![o(77)]));
        txs.push(tx(130_001 + i * 4, vec![], vec![o(77)]));
        txs.push(tx(130_002 + i * 4, vec![], vec![o(3_000 + i)]));
        txs.push(tx(130_003 + i * 4, vec![], vec![o(4_000 + i)]));
    }

    let baseline = auto_adaptive_decision(&txs);
    assert!(
        baseline.use_hot_bucket,
        "baseline hotspot should clear permissive adaptive gates"
    );

    let gain = baseline.expected_gain_score.to_string();
    let hot_key_share = baseline.hot_key_share.to_string();
    let streak = baseline.streak_ratio.to_string();

    let _streak = EnvGuard::set("TRNM_AUTO_HOT_STREAK_RATIO", &streak);
    let _share = EnvGuard::set("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE", &hot_key_share);
    let _gain = EnvGuard::set("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE", &gain);

    let d = auto_adaptive_decision(&txs);
    assert!(
        d.use_hot_bucket,
        "expected-gain threshold should stay inclusive at exact equality"
    );
    assert_eq!(d.reason, "hotspot_detected");
    assert!(d.expected_gain_score >= d.min_expected_gain_score);
    assert!(d.hot_key_share >= d.min_hot_key_share);
    assert!(d.streak_ratio >= d.streak_threshold + d.min_margin);
}

#[test]
fn auto_adaptive_sampling_with_sparse_window_keeps_duplicate_indices_fail_closed() {
    let _env = env_lock();
    let _sample_len = EnvGuard::set("TRNM_AUTO_SAMPLE_LEN", "2048");
    let _streak = EnvGuard::set("TRNM_AUTO_HOT_STREAK_RATIO", "0.25");
    let _margin = EnvGuard::set("TRNM_AUTO_REORDER_MIN_MARGIN", "0.0");
    let _share = EnvGuard::set("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE", "0.10");
    let _gain = EnvGuard::set("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE", "0.03");

    // Keep a regression with a just-over-half window to exercise sparse
    // integer-step sampling, where nearby sample points can collapse onto
    // the same tx index. The decision should remain fail-closed for a broad
    // unique-key batch instead of overestimating hotspot streaks.
    let mut txs = Vec::with_capacity(3000);
    for i in 0..3000u64 {
        txs.push(tx(50_000 + i, vec![], vec![o(100_000 + i)]));
    }

    let d = auto_adaptive_decision(&txs);
    assert_eq!(d.sample_len, 2048);
    assert_eq!(d.reason, "low_hot_key_share");
    assert!(!d.use_hot_bucket);
    assert!(
        d.hot_key_share <= (1.0 / d.sample_len as f64),
        "duplicate sparse-sample indices must not inflate hot-key share"
    );
    assert_eq!(
        d.streak_ratio, 0.0,
        "duplicate sparse-sample indices must not manufacture streak runs"
    );
}

#[test]
fn auto_adaptive_read_only_sparse_sampling_keeps_duplicate_indices_fail_closed() {
    let _env = env_lock();
    let _sample_len = EnvGuard::set("TRNM_AUTO_SAMPLE_LEN", "2048");
    let _streak = EnvGuard::set("TRNM_AUTO_HOT_STREAK_RATIO", "0.25");
    let _margin = EnvGuard::set("TRNM_AUTO_REORDER_MIN_MARGIN", "0.0");
    let _share = EnvGuard::set("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE", "0.10");
    let _gain = EnvGuard::set("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE", "0.03");

    // Mirror the sparse-window duplicate-index regression for read-only
    // batches, where adaptive detection falls back to read_set keys.
    // Duplicate sample indices must stay fail-closed instead of creating
    // artificial hotspot share or streaks under broad unique-key traffic.
    let mut txs = Vec::with_capacity(3000);
    for i in 0..3000u64 {
        txs.push(tx(80_000 + i, vec![o(130_000 + i)], vec![]));
    }

    let d = auto_adaptive_decision(&txs);
    assert_eq!(d.sample_len, 2048);
    assert_eq!(d.reason, "low_hot_key_share");
    assert!(!d.use_hot_bucket);
    assert!(
        d.hot_key_share <= (1.0 / d.sample_len as f64),
        "duplicate sparse-sample indices must not inflate read-only hot-key share"
    );
    assert_eq!(
        d.streak_ratio, 0.0,
        "duplicate sparse-sample indices must not manufacture read-only streak runs"
    );
}
