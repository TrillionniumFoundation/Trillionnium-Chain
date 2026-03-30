use super::*;

#[test]
fn auto_adaptive_keyless_batches_fail_closed_as_insufficient_sample() {
    let _env = env_lock();
    let _min_batch = EnvGuard::set("TRNM_AUTO_MIN_BATCH_LEN", "64");
    let _streak = EnvGuard::set("TRNM_AUTO_HOT_STREAK_RATIO", "0.0");
    let _margin = EnvGuard::set("TRNM_AUTO_REORDER_MIN_MARGIN", "0.0");
    let _share = EnvGuard::set("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE", "0.0");
    let _gain = EnvGuard::set("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE", "0.0");

    // Experimental adaptive probes must stay fail-closed when a batch has
    // no observable read/write keys at all. Even with permissive thresholds,
    // keyless traffic should never manufacture a hotspot switch.
    let mut txs = Vec::with_capacity(600);
    for i in 0..600u64 {
        txs.push(tx(90_000 + i, vec![], vec![]));
    }

    let d = auto_adaptive_decision(&txs);
    assert_eq!(d.sample_len, txs.len());
    assert_eq!(d.reason, "insufficient_sample");
    assert!(!d.use_hot_bucket);
    assert_eq!(d.hot_key_share, 0.0);
    assert_eq!(d.streak_ratio, 0.0);
    assert_eq!(d.expected_gain_score, 0.0);
}

#[test]
fn auto_adaptive_empty_batches_fail_closed_even_with_permissive_env_knobs() {
    let _env = env_lock();
    let _min_batch = EnvGuard::set("TRNM_AUTO_MIN_BATCH_LEN", "64");
    let _streak = EnvGuard::set("TRNM_AUTO_HOT_STREAK_RATIO", "0.0");
    let _margin = EnvGuard::set("TRNM_AUTO_REORDER_MIN_MARGIN", "0.0");
    let _share = EnvGuard::set("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE", "0.0");
    let _gain = EnvGuard::set("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE", "0.0");

    // Empty batches must stay fail-closed in the experimental lane even if
    // every adaptive threshold is configured permissively.
    let txs: Vec<Tx> = Vec::new();

    let d = auto_adaptive_decision(&txs);
    assert_eq!(d.sample_len, 0);
    assert_eq!(d.reason, "small_batch");
    assert!(!d.use_hot_bucket);
    assert_eq!(d.hot_key_share, 0.0);
    assert_eq!(d.streak_ratio, 0.0);
    assert_eq!(d.expected_gain_score, 0.0);
}

#[test]
fn auto_adaptive_keyless_gaps_break_same_key_streaks_fail_closed() {
    let _env = env_lock();
    let _min_batch = EnvGuard::set("TRNM_AUTO_MIN_BATCH_LEN", "64");
    let _streak = EnvGuard::set("TRNM_AUTO_HOT_STREAK_RATIO", "0.5");
    let _margin = EnvGuard::set("TRNM_AUTO_REORDER_MIN_MARGIN", "0.0");
    let _share = EnvGuard::set("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE", "0.0");
    let _gain = EnvGuard::set("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE", "0.0");

    // Keyless txs should break streak continuity instead of letting the
    // detector count two same-key observations as adjacent when they are
    // separated by empty-access traffic.
    let mut txs = Vec::with_capacity(64);
    for i in 0..32u64 {
        txs.push(tx(100_000 + i * 2, vec![], vec![o(42)]));
        txs.push(tx(100_001 + i * 2, vec![], vec![]));
    }

    let d = auto_adaptive_decision(&txs);
    assert_eq!(d.sample_len, txs.len());
    assert_eq!(d.hot_key_share, 0.0);
    assert_eq!(d.streak_ratio, 0.0);
    assert!(!d.use_hot_bucket);
    assert_eq!(d.reason, "insufficient_sample");
    assert_eq!(d.expected_gain_score, 0.0);
}

#[test]
fn auto_adaptive_read_only_keyless_gaps_break_same_key_streaks_fail_closed() {
    let _env = env_lock();
    let _min_batch = EnvGuard::set("TRNM_AUTO_MIN_BATCH_LEN", "64");
    let _streak = EnvGuard::set("TRNM_AUTO_HOT_STREAK_RATIO", "0.5");
    let _margin = EnvGuard::set("TRNM_AUTO_REORDER_MIN_MARGIN", "0.0");
    let _share = EnvGuard::set("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE", "0.0");
    let _gain = EnvGuard::set("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE", "0.0");

    // Mirror the keyless-gap regression for read-only batches, where the
    // experimental detector falls back to read_set keys.
    let mut txs = Vec::with_capacity(64);
    for i in 0..32u64 {
        txs.push(tx(110_000 + i * 2, vec![o(42)], vec![]));
        txs.push(tx(110_001 + i * 2, vec![], vec![]));
    }

    let d = auto_adaptive_decision(&txs);
    assert_eq!(d.sample_len, txs.len());
    assert_eq!(d.hot_key_share, 0.0);
    assert_eq!(d.streak_ratio, 0.0);
    assert!(!d.use_hot_bucket);
    assert_eq!(d.reason, "insufficient_sample");
    assert_eq!(d.expected_gain_score, 0.0);
}

#[test]
fn auto_adaptive_large_sample_keyless_gaps_do_not_manufacture_false_hotspots() {
    let _env = env_lock();
    let _min_batch = EnvGuard::set("TRNM_AUTO_MIN_BATCH_LEN", "64");
    let _streak = EnvGuard::set("TRNM_AUTO_HOT_STREAK_RATIO", "0.5");
    let _margin = EnvGuard::set("TRNM_AUTO_REORDER_MIN_MARGIN", "0.0");
    let _share = EnvGuard::set("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE", "0.10");
    let _gain = EnvGuard::set("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE", "0.0");

    // Mirror the keyless-gap fail-closed guard on the large-batch sampled path.
    // Even when adaptive mode samples 2048 positions across a wide queue,
    // empty-access gaps must keep identical write keys from appearing adjacent
    // in the hotspot probe.
    let mut txs = Vec::with_capacity(3_000);
    for i in 0..1_500u64 {
        txs.push(tx(i * 2, vec![], vec![o(42)]));
        txs.push(tx(i * 2 + 1, vec![], vec![]));
    }

    let d = auto_adaptive_decision(&txs);
    assert_eq!(d.sample_len, 2048);
    assert_eq!(d.hot_key_share, 0.0);
    assert_eq!(d.streak_ratio, 0.0);
    assert!(!d.use_hot_bucket);
    assert_eq!(d.reason, "insufficient_sample");
    assert_eq!(d.expected_gain_score, 0.0);
}

#[test]
fn auto_adaptive_prefers_write_hotspot_signal_over_shared_read_domains() {
    let _env = env_lock();
    let _streak = EnvGuard::set("TRNM_AUTO_HOT_STREAK_RATIO", "0.20");
    let _margin = EnvGuard::set("TRNM_AUTO_REORDER_MIN_MARGIN", "0.0");
    let _share = EnvGuard::set("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE", "0.20");
    let _gain = EnvGuard::set("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE", "0.05");

    // Mixed read/write batches often share a broad read dependency (e.g. a
    // common config object) while writes stay unique. Adaptive detection
    // should prefer write_set keys when present so experiments do not switch
    // strategies based only on a shared read domain that does not imply a
    // write hotspot.
    let mut txs = Vec::with_capacity(600);
    for i in 0..600u64 {
        txs.push(tx(i, vec![o(42)], vec![o(10_000 + i)]));
    }

    let d = auto_adaptive_decision(&txs);
    assert_eq!(d.sample_len, txs.len());
    assert!(!d.use_hot_bucket);
    assert_eq!(d.reason, "low_hot_key_share");
    assert!(d.hot_key_share <= (1.0 / d.sample_len as f64));
    assert_eq!(d.streak_ratio, 0.0);
    assert_eq!(d.expected_gain_score, 0.0);
}

#[test]
fn auto_adaptive_large_sample_prefers_write_signal_over_shared_read_domains() {
    let _env = env_lock();
    let _min_batch = EnvGuard::set("TRNM_AUTO_MIN_BATCH_LEN", "64");
    let _streak = EnvGuard::set("TRNM_AUTO_HOT_STREAK_RATIO", "0.20");
    let _margin = EnvGuard::set("TRNM_AUTO_REORDER_MIN_MARGIN", "0.0");
    let _share = EnvGuard::set("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE", "0.20");
    let _gain = EnvGuard::set("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE", "0.05");

    // Mirror the shared-read-domain regression on the large-batch sampled
    // path. Even when adaptive mode samples a wide queue, unique writes
    // must prevent a false hotspot switch caused only by a common read key.
    let mut txs = Vec::with_capacity(3_000);
    for i in 0..3_000u64 {
        txs.push(tx(i, vec![o(42)], vec![o(10_000 + i)]));
    }

    let d = auto_adaptive_decision(&txs);
    assert_eq!(d.sample_len, 2048);
    assert!(!d.use_hot_bucket);
    assert_eq!(d.reason, "low_hot_key_share");
    assert!(d.hot_key_share <= (1.0 / d.sample_len as f64));
    assert_eq!(d.streak_ratio, 0.0);
    assert_eq!(d.expected_gain_score, 0.0);
}

#[test]
fn auto_adaptive_canonicalizes_duplicate_heavy_mixed_domains_before_hotspot_probe() {
    let _env = env_lock();
    let _min_batch = EnvGuard::set("TRNM_AUTO_MIN_BATCH_LEN", "64");
    let _sample = EnvGuard::set("TRNM_AUTO_SAMPLE_LEN", "64");
    let _streak = EnvGuard::set("TRNM_AUTO_HOT_STREAK_RATIO", "0.20");
    let _margin = EnvGuard::set("TRNM_AUTO_REORDER_MIN_MARGIN", "0.0");
    let _share = EnvGuard::set("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE", "0.20");
    let _gain = EnvGuard::set("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE", "0.05");

    let mut txs = Vec::with_capacity(64);
    for i in 0..64u64 {
        let tx_id = 140_000 + i;
        if i % 2 == 0 {
            txs.push(tx(tx_id, vec![o(41), o(13)], vec![o(13), o(29), o(29)]));
        } else {
            txs.push(tx(tx_id, vec![o(13), o(41), o(41)], vec![o(29), o(13), o(29)]));
        }
    }

    // Equivalent mixed domains with duplicate-heavy echoes should collapse to the
    // same canonical write-lane key before adaptive hotspot scoring. Otherwise
    // harmless ingress ordering differences fragment one executor lane into two
    // alternating pseudo-hot keys and suppress a real hotspot switch.
    let d = auto_adaptive_decision(&txs);
    assert_eq!(d.sample_len, 64);
    assert!(d.use_hot_bucket);
    assert_eq!(d.reason, "hotspot_detected");
    assert_eq!(d.hot_key_share, 1.0);
    assert_eq!(d.streak_ratio, 1.0);
    assert_eq!(d.expected_gain_score, 1.0);
}

#[test]
fn auto_adaptive_detects_write_hotspots_even_with_shared_read_domains() {
    let _env = env_lock();
    let _min_batch = EnvGuard::set("TRNM_AUTO_MIN_BATCH_LEN", "64");
    let _streak = EnvGuard::set("TRNM_AUTO_HOT_STREAK_RATIO", "0.20");
    let _margin = EnvGuard::set("TRNM_AUTO_REORDER_MIN_MARGIN", "0.0");
    let _share = EnvGuard::set("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE", "0.20");
    let _gain = EnvGuard::set("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE", "0.05");

    // Large mixed batches can share a broad read dependency while only a
    // late contiguous region develops a true write hotspot. Adaptive
    // experiments should still switch based on the write signal rather than
    // being diluted by the shared read domain.
    let mut txs = Vec::with_capacity(3_000);
    for i in 0..1_800u64 {
        txs.push(tx(i, vec![o(42)], vec![o(10_000 + i)]));
    }
    for i in 1_800..3_000u64 {
        txs.push(tx(i, vec![o(42)], vec![o(7)]));
    }

    let d = auto_adaptive_decision(&txs);
    assert_eq!(d.sample_len, 2048);
    assert!(d.use_hot_bucket);
    assert_eq!(d.reason, "hotspot_detected");
    assert!(d.hot_key_share >= 0.20);
    assert!(d.streak_ratio >= 0.20);
    assert!(d.expected_gain_score >= 0.05);
}

#[test]
fn auto_adaptive_detects_late_write_hotspots_after_keyless_prefixes() {
    let _env = env_lock();
    let _min_batch = EnvGuard::set("TRNM_AUTO_MIN_BATCH_LEN", "64");
    let _streak = EnvGuard::set("TRNM_AUTO_HOT_STREAK_RATIO", "0.20");
    let _margin = EnvGuard::set("TRNM_AUTO_REORDER_MIN_MARGIN", "0.0");
    let _share = EnvGuard::set("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE", "0.20");
    let _gain = EnvGuard::set("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE", "0.05");

    // Experimental adaptive sampling should stay fail-open for a real late
    // write hotspot even when much of the earlier sampled region is keyless
    // traffic. Keyless samples may break streak continuity locally, but they
    // must not suppress a dense tail hotspot that still clears the adaptive
    // switch thresholds.
    let mut txs = Vec::with_capacity(3_000);
    for i in 0..1_500u64 {
        txs.push(tx(i, vec![], vec![]));
    }
    for i in 1_500..1_800u64 {
        txs.push(tx(i, vec![], vec![o(10_000 + i)]));
    }
    for i in 1_800..3_000u64 {
        txs.push(tx(i, vec![], vec![o(7)]));
    }

    let d = auto_adaptive_decision(&txs);
    assert_eq!(d.sample_len, 2048);
    assert!(d.use_hot_bucket);
    assert_eq!(d.reason, "hotspot_detected");
    assert!(d.hot_key_share >= 0.20);
    assert!(d.streak_ratio >= 0.20);
    assert!(d.expected_gain_score >= 0.05);
}

#[test]
fn auto_adaptive_detects_late_read_only_hotspots_after_keyless_prefixes() {
    let _env = env_lock();
    let _min_batch = EnvGuard::set("TRNM_AUTO_MIN_BATCH_LEN", "64");
    let _streak = EnvGuard::set("TRNM_AUTO_HOT_STREAK_RATIO", "0.20");
    let _margin = EnvGuard::set("TRNM_AUTO_REORDER_MIN_MARGIN", "0.0");
    let _share = EnvGuard::set("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE", "0.20");
    let _gain = EnvGuard::set("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE", "0.05");

    // Read-only batches fall back to sampled read_set keys. Adaptive
    // experiments should still surface a real late tail hotspot even when
    // much of the earlier sampled region is keyless traffic.
    let mut txs = Vec::with_capacity(3_000);
    for i in 0..1_500u64 {
        txs.push(tx(i, vec![], vec![]));
    }
    for i in 1_500..1_800u64 {
        txs.push(tx(i, vec![o(10_000 + i)], vec![]));
    }
    for i in 1_800..3_000u64 {
        txs.push(tx(i, vec![o(7)], vec![]));
    }

    let d = auto_adaptive_decision(&txs);
    assert_eq!(d.sample_len, 2048);
    assert!(d.use_hot_bucket);
    assert_eq!(d.reason, "hotspot_detected");
    assert!(d.hot_key_share >= 0.20);
    assert!(d.streak_ratio >= 0.20);
    assert!(d.expected_gain_score >= 0.05);
}
