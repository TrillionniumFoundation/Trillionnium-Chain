use super::*;

#[test]
fn auto_adaptive_small_batch_threshold_accepts_quoted_grouped_env_values() {
    let _env = env_lock();
    let _min_batch = EnvGuard::set("TRNM_AUTO_MIN_BATCH_LEN", " '6_4' ");
    let _streak = EnvGuard::set("TRNM_AUTO_HOT_STREAK_RATIO", "0%");
    let _margin = EnvGuard::set("TRNM_AUTO_REORDER_MIN_MARGIN", "0.0");
    let _share = EnvGuard::set("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE", "20%");
    let _gain = EnvGuard::set("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE", "0%");

    let mut txs = Vec::with_capacity(64);
    for i in 0..64u64 {
        txs.push(tx(i, vec![], vec![o(42)]));
    }

    let d = auto_adaptive_decision(&txs);
    assert_eq!(d.sample_len, 64);
    assert!(
        d.use_hot_bucket,
        "quoted/grouped env values should preserve small-batch hotspot detection"
    );
    assert_eq!(d.reason, "hotspot_detected");
}

#[test]
fn auto_adaptive_small_batch_threshold_is_env_tunable() {
    let _env = env_lock();
    let _min_batch = EnvGuard::set("TRNM_AUTO_MIN_BATCH_LEN", "64");
    let _streak = EnvGuard::set("TRNM_AUTO_HOT_STREAK_RATIO", "0.0");
    let _margin = EnvGuard::set("TRNM_AUTO_REORDER_MIN_MARGIN", "0.0");
    let _share = EnvGuard::set("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE", "0.2");
    let _gain = EnvGuard::set("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE", "0.0");

    let mut txs = Vec::with_capacity(64);
    for i in 0..64u64 {
        txs.push(tx(i, vec![], vec![o(42)]));
    }

    let d = auto_adaptive_decision(&txs);
    assert_eq!(d.sample_len, 64);
    assert!(
        d.use_hot_bucket,
        "env-tuned min batch should allow small-batch hotspot detection"
    );
    assert_eq!(d.reason, "hotspot_detected");
}

#[test]
fn auto_adaptive_small_batch_threshold_accepts_comma_grouped_env_values() {
    let _env = env_lock();
    let _min_batch = EnvGuard::set("TRNM_AUTO_MIN_BATCH_LEN", "1,024");
    let _streak = EnvGuard::set("TRNM_AUTO_HOT_STREAK_RATIO", "0.0");
    let _margin = EnvGuard::set("TRNM_AUTO_REORDER_MIN_MARGIN", "0.0");
    let _share = EnvGuard::set("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE", "0.0");
    let _gain = EnvGuard::set("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE", "0.0");

    // Experimental lanes tune adaptive entry thresholds via env knobs.
    // Comma-grouped numeric values should parse for min-batch gating so a
    // medium hotspot batch still stays fail-closed below the configured
    // threshold instead of switching strategies early.
    let mut txs = Vec::with_capacity(600);
    for i in 0..600u64 {
        txs.push(tx(i, vec![], vec![o(42)]));
    }

    let d = auto_adaptive_decision(&txs);
    assert_eq!(d.sample_len, txs.len());
    assert!(!d.use_hot_bucket);
    assert_eq!(d.reason, "small_batch");
    assert_eq!(d.streak_ratio, 0.0);
    assert_eq!(d.hot_key_share, 0.0);
    assert_eq!(d.expected_gain_score, 0.0);
}

#[test]
fn auto_adaptive_threshold_boundaries_are_inclusive() {
    let _env = env_lock();
    let _min_batch = EnvGuard::set("TRNM_AUTO_MIN_BATCH_LEN", "64");
    let _sample = EnvGuard::set("TRNM_AUTO_SAMPLE_LEN", "64");

    // Keep a precise boundary regression for the experimental adaptive lane:
    // when observed streak/share/gain land exactly on the configured
    // thresholds, the selector should stay inclusive (`>=`) instead of
    // fail-closing one notch below due to future comparator drift.
    let mut txs = Vec::with_capacity(64);
    for i in 0..16u64 {
        txs.push(tx(i, vec![], vec![o(7)]));
    }
    for i in 16..32u64 {
        txs.push(tx(i, vec![], vec![o(100 + i)]));
    }
    for i in 32..64u64 {
        txs.push(tx(i, vec![], vec![o(200 + i)]));
    }

    let _baseline_streak = EnvGuard::set("TRNM_AUTO_HOT_STREAK_RATIO", "0.0");
    let _baseline_margin = EnvGuard::set("TRNM_AUTO_REORDER_MIN_MARGIN", "0.0");
    let _baseline_share = EnvGuard::set("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE", "0.0");
    let _baseline_gain = EnvGuard::set("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE", "0.0");
    let baseline = auto_adaptive_decision(&txs);
    drop(_baseline_gain);
    drop(_baseline_share);
    drop(_baseline_margin);
    drop(_baseline_streak);

    let threshold = baseline.streak_ratio.to_string();
    let hot_key_share = baseline.hot_key_share.to_string();
    let gain = baseline.expected_gain_score.to_string();

    let _streak = EnvGuard::set("TRNM_AUTO_HOT_STREAK_RATIO", &threshold);
    let _margin = EnvGuard::set("TRNM_AUTO_REORDER_MIN_MARGIN", "0.0");
    let _share = EnvGuard::set("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE", &hot_key_share);
    let _gain = EnvGuard::set("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE", &gain);

    let d = auto_adaptive_decision(&txs);
    assert_eq!(d.sample_len, 64);
    assert!(
        d.use_hot_bucket,
        "exact boundary match should still enable hot-bucket strategy"
    );
    assert_eq!(d.reason, "hotspot_detected");
    assert!(d.streak_ratio >= d.streak_threshold + d.min_margin);
    assert!(d.hot_key_share >= d.min_hot_key_share);
    assert!(d.expected_gain_score >= d.min_expected_gain_score);
}

#[test]
fn auto_adaptive_default_min_batch_boundary_runs_hotspot_probe() {
    let _env = env_lock();
    let _sample = EnvGuard::set("TRNM_AUTO_SAMPLE_LEN", "2048");
    let _streak = EnvGuard::set("TRNM_AUTO_HOT_STREAK_RATIO", "0.20");
    let _margin = EnvGuard::set("TRNM_AUTO_REORDER_MIN_MARGIN", "0.0");
    let _share = EnvGuard::set("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE", "0.20");
    let _gain = EnvGuard::set("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE", "0.05");

    // The default adaptive entry gate is 512 txs. Keep an exact-boundary
    // regression so future tuning does not accidentally treat this as a
    // small batch and skip the hotspot probe on the first eligible batch.
    let mut txs = Vec::with_capacity(512);
    for i in 0..256u64 {
        txs.push(tx(i, vec![], vec![o(10_000 + i)]));
    }
    for i in 0..256u64 {
        txs.push(tx(1_000 + i, vec![], vec![o(42)]));
    }

    let d = auto_adaptive_decision(&txs);
    assert_eq!(d.sample_len, txs.len());
    assert!(
        d.use_hot_bucket,
        "default min-batch boundary should still run adaptive hotspot detection"
    );
    assert_eq!(d.reason, "hotspot_detected");
}

#[test]
fn auto_adaptive_sub_min_batch_hotspots_stay_fail_closed() {
    let _env = env_lock();
    let _min_batch = EnvGuard::set("TRNM_AUTO_MIN_BATCH_LEN", "64");
    let _sample = EnvGuard::set("TRNM_AUTO_SAMPLE_LEN", "2048");
    let _streak = EnvGuard::set("TRNM_AUTO_HOT_STREAK_RATIO", "0.0");
    let _margin = EnvGuard::set("TRNM_AUTO_REORDER_MIN_MARGIN", "0.0");
    let _share = EnvGuard::set("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE", "0.0");
    let _gain = EnvGuard::set("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE", "0.0");

    // Keep the just-below-threshold boundary fail-closed even when every
    // adaptive hotspot knob is permissive. Experimental sampling/window
    // tuning must not override the minimum batch gate.
    let mut txs = Vec::with_capacity(63);
    for i in 0..63u64 {
        txs.push(tx(i, vec![], vec![o(42)]));
    }

    let d = auto_adaptive_decision(&txs);
    assert_eq!(d.sample_len, 63);
    assert_eq!(d.reason, "small_batch");
    assert!(!d.use_hot_bucket);
    assert_eq!(d.hot_key_share, 0.0);
    assert_eq!(d.streak_ratio, 0.0);
    assert_eq!(d.expected_gain_score, 0.0);
}

#[test]
fn auto_adaptive_sampling_detects_late_batch_hotspots() {
    let _env = env_lock();
    let _streak = EnvGuard::set("TRNM_AUTO_HOT_STREAK_RATIO", "0.20");
    let _margin = EnvGuard::set("TRNM_AUTO_REORDER_MIN_MARGIN", "0.0");
    let _share = EnvGuard::set("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE", "0.10");
    let _gain = EnvGuard::set("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE", "0.01");

    let mut txs = Vec::with_capacity(4096);
    for i in 0..2048u64 {
        txs.push(tx(i, vec![], vec![o(10_000 + i)]));
    }
    for i in 0..2048u64 {
        txs.push(tx(3_000 + i, vec![], vec![o(42)]));
    }

    let d = auto_adaptive_decision(&txs);
    assert!(
        d.use_hot_bucket,
        "late hotspot should be visible in adaptive sample"
    );
    assert_eq!(d.reason, "hotspot_detected");
}

#[test]
fn auto_adaptive_min_clamped_sample_len_still_detects_tail_hotspots() {
    let _env = env_lock();
    let _sample = EnvGuard::set("TRNM_AUTO_SAMPLE_LEN", "8");
    let _streak = EnvGuard::set("TRNM_AUTO_HOT_STREAK_RATIO", "0.20");
    let _margin = EnvGuard::set("TRNM_AUTO_REORDER_MIN_MARGIN", "0.0");
    let _share = EnvGuard::set("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE", "0.10");
    let _gain = EnvGuard::set("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE", "0.01");

    // Experimental sample tuning clamps to a 64-item floor. Keep a tail-hotspot
    // regression here so overly small requested windows do not lose batch-tail
    // visibility while adaptive experimentation changes probe sizing.
    let mut txs = Vec::with_capacity(5000);
    for i in 0..2500u64 {
        txs.push(tx(i, vec![], vec![o(10_000 + i)]));
    }
    for i in 0..2500u64 {
        txs.push(tx(4_000 + i, vec![], vec![o(42)]));
    }

    let d = auto_adaptive_decision(&txs);
    assert_eq!(d.sample_len, 64);
    assert!(
        d.use_hot_bucket,
        "clamped minimum sample should still preserve tail hotspot visibility"
    );
    assert_eq!(d.reason, "hotspot_detected");
}

#[test]
fn auto_adaptive_min_clamped_sample_len_still_detects_tail_hotspots_for_read_only_batches() {
    let _env = env_lock();
    let _sample = EnvGuard::set("TRNM_AUTO_SAMPLE_LEN", "8");
    let _streak = EnvGuard::set("TRNM_AUTO_HOT_STREAK_RATIO", "0.20");
    let _margin = EnvGuard::set("TRNM_AUTO_REORDER_MIN_MARGIN", "0.0");
    let _share = EnvGuard::set("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE", "0.10");
    let _gain = EnvGuard::set("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE", "0.01");

    // Mirror the clamped-minimum tail-hotspot regression for read-only
    // batches. Experimental sample tuning still clamps to a 64-item floor,
    // and the detector must preserve late-batch visibility when it falls
    // back from write_set to read_set keys.
    let mut txs = Vec::with_capacity(5000);
    for i in 0..2500u64 {
        txs.push(tx(i, vec![o(10_000 + i)], vec![]));
    }
    for i in 0..2500u64 {
        txs.push(tx(4_000 + i, vec![o(42)], vec![]));
    }

    let d = auto_adaptive_decision(&txs);
    assert_eq!(d.sample_len, 64);
    assert!(
        d.use_hot_bucket,
        "clamped minimum sample should still preserve read-only tail hotspot visibility"
    );
    assert_eq!(d.reason, "hotspot_detected");
}

#[test]
fn auto_adaptive_direct_scan_detects_tail_hotspots_in_medium_batches() {
    let _env = env_lock();
    let _streak = EnvGuard::set("TRNM_AUTO_HOT_STREAK_RATIO", "0.20");
    let _margin = EnvGuard::set("TRNM_AUTO_REORDER_MIN_MARGIN", "0.0");
    let _share = EnvGuard::set("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE", "0.20");
    let _gain = EnvGuard::set("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE", "0.05");

    // Medium batches stay on the direct-scan fast path (sample_len == batch_len).
    // Keep a late-batch hotspot regression here so the optimized path does not
    // reintroduce first-window bias while adaptive tuning evolves.
    let mut txs = Vec::with_capacity(600);
    for i in 0..300u64 {
        txs.push(tx(i, vec![], vec![o(10_000 + i)]));
    }
    for i in 0..300u64 {
        txs.push(tx(1_000 + i, vec![], vec![o(42)]));
    }

    let d = auto_adaptive_decision(&txs);
    assert_eq!(d.sample_len, txs.len());
    assert!(
        d.use_hot_bucket,
        "direct-scan path should see tail hotspot runs"
    );
    assert_eq!(d.reason, "hotspot_detected");
}

#[test]
fn auto_adaptive_sampling_detects_late_batch_hotspots_for_read_only_batches() {
    let _env = env_lock();
    let _streak = EnvGuard::set("TRNM_AUTO_HOT_STREAK_RATIO", "0.20");
    let _margin = EnvGuard::set("TRNM_AUTO_REORDER_MIN_MARGIN", "0.0");
    let _share = EnvGuard::set("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE", "0.10");
    let _gain = EnvGuard::set("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE", "0.01");

    // Large adaptive batches use the bounded evenly-spaced sampling path.
    // Keep a read-only late-hotspot regression here so experiments around
    // sampling windows do not reintroduce first-window bias when write_set
    // is empty and the detector falls back to read_set keys.
    let mut txs = Vec::with_capacity(4096);
    for i in 0..2048u64 {
        txs.push(tx(i, vec![o(10_000 + i)], vec![]));
    }
    for i in 0..2048u64 {
        txs.push(tx(3_000 + i, vec![o(42)], vec![]));
    }

    let d = auto_adaptive_decision(&txs);
    assert!(
        d.use_hot_bucket,
        "late read-only hotspot should be visible in adaptive sample"
    );
    assert_eq!(d.reason, "hotspot_detected");
}

#[test]
fn auto_adaptive_default_sample_boundary_uses_direct_scan_for_tail_hotspots() {
    let _env = env_lock();
    let _streak = EnvGuard::set("TRNM_AUTO_HOT_STREAK_RATIO", "0.20");
    let _margin = EnvGuard::set("TRNM_AUTO_REORDER_MIN_MARGIN", "0.0");
    let _share = EnvGuard::set("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE", "0.20");
    let _gain = EnvGuard::set("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE", "0.05");

    // The default adaptive sample window tops out at 2048 txs. Keep the
    // exact boundary on the direct-scan fast path so future tuning does not
    // accidentally sample a partial prefix and miss a hotspot that appears
    // only in the batch tail.
    let mut txs = Vec::with_capacity(2048);
    for i in 0..1024u64 {
        txs.push(tx(i, vec![], vec![o(10_000 + i)]));
    }
    for i in 0..1024u64 {
        txs.push(tx(2_000 + i, vec![], vec![o(42)]));
    }

    let d = auto_adaptive_decision(&txs);
    assert_eq!(d.sample_len, txs.len());
    assert!(
        d.use_hot_bucket,
        "default sample boundary should stay on direct-scan and keep tail hotspots visible"
    );
    assert_eq!(d.reason, "hotspot_detected");
}

#[test]
fn auto_adaptive_default_sample_boundary_uses_direct_scan_for_read_only_tail_hotspots() {
    let _env = env_lock();
    let _streak = EnvGuard::set("TRNM_AUTO_HOT_STREAK_RATIO", "0.20");
    let _margin = EnvGuard::set("TRNM_AUTO_REORDER_MIN_MARGIN", "0.0");
    let _share = EnvGuard::set("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE", "0.20");
    let _gain = EnvGuard::set("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE", "0.05");

    // Mirror the exact 2048-tx default-sample boundary for read-only
    // batches. The adaptive fast path should stay on direct scan here so a
    // hotspot concentrated only in the batch tail cannot be lost when
    // experimental sample-window tuning evolves.
    let mut txs = Vec::with_capacity(2048);
    for i in 0..1024u64 {
        txs.push(tx(i, vec![o(10_000 + i)], vec![]));
    }
    for i in 0..1024u64 {
        txs.push(tx(2_000 + i, vec![o(42)], vec![]));
    }

    let d = auto_adaptive_decision(&txs);
    assert_eq!(d.sample_len, txs.len());
    assert!(
        d.use_hot_bucket,
        "default sample boundary should stay on direct-scan and keep read-only tail hotspots visible"
    );
    assert_eq!(d.reason, "hotspot_detected");
}

#[test]
fn auto_adaptive_first_sampled_batch_boundary_preserves_tail_hotspot_visibility() {
    let _env = env_lock();
    let _streak = EnvGuard::set("TRNM_AUTO_HOT_STREAK_RATIO", "0.20");
    let _margin = EnvGuard::set("TRNM_AUTO_REORDER_MIN_MARGIN", "0.0");
    let _share = EnvGuard::set("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE", "0.20");
    let _gain = EnvGuard::set("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE", "0.05");

    // 2049 txs is the first batch that exits the default direct-scan fast
    // path and enters bounded sampling. Keep a tight boundary regression so
    // experimental sampling changes do not lose a real tail hotspot on the
    // first sampled batch.
    let mut txs = Vec::with_capacity(2049);
    for i in 0..1024u64 {
        txs.push(tx(i, vec![], vec![o(10_000 + i)]));
    }
    for i in 0..1025u64 {
        txs.push(tx(2_000 + i, vec![], vec![o(42)]));
    }

    let d = auto_adaptive_decision(&txs);
    assert_eq!(d.sample_len, 2048);
    assert!(
        d.use_hot_bucket,
        "first sampled batch should preserve tail hotspot visibility"
    );
    assert_eq!(d.reason, "hotspot_detected");
}

#[test]
fn auto_adaptive_direct_scan_detects_tail_hotspots_for_read_only_batches() {
    let _env = env_lock();
    let _streak = EnvGuard::set("TRNM_AUTO_HOT_STREAK_RATIO", "0.20");
    let _margin = EnvGuard::set("TRNM_AUTO_REORDER_MIN_MARGIN", "0.0");
    let _share = EnvGuard::set("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE", "0.20");
    let _gain = EnvGuard::set("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE", "0.05");

    // Experimental adaptive detection falls back to read_set when write_set is
    // empty. Keep a read-only late-hotspot regression so future tuning of the
    // direct-scan path does not silently lose this signal.
    let mut txs = Vec::with_capacity(600);
    for i in 0..300u64 {
        txs.push(tx(i, vec![o(10_000 + i)], vec![]));
    }
    for i in 0..300u64 {
        txs.push(tx(1_000 + i, vec![o(42)], vec![]));
    }

    let d = auto_adaptive_decision(&txs);
    assert_eq!(d.sample_len, txs.len());
    assert!(
        d.use_hot_bucket,
        "direct-scan path should preserve read-only tail hotspot detection"
    );
    assert_eq!(d.reason, "hotspot_detected");
}
