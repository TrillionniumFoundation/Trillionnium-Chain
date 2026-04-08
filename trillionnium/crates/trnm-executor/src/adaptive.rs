use std::collections::HashMap;

use trnm_types::Tx;

use crate::env_config::{
    auto_adaptive_min_batch_len, auto_adaptive_sample_len, auto_hot_streak_threshold,
    auto_min_expected_gain_score, auto_reorder_min_hot_key_share, auto_reorder_min_margin,
};
use crate::{primary_access_domain_key, AutoAdaptiveDecision};

pub(crate) fn auto_adaptive_decision(txs: &[Tx]) -> AutoAdaptiveDecision {
    let threshold = auto_hot_streak_threshold();
    let min_margin = auto_reorder_min_margin();
    let min_hot_key_share = auto_reorder_min_hot_key_share();
    let min_expected_gain_score = auto_min_expected_gain_score();
    let min_batch_len = auto_adaptive_min_batch_len();

    if txs.len() < min_batch_len {
        return AutoAdaptiveDecision {
            use_hot_bucket: false,
            reason: "small_batch",
            sample_len: txs.len(),
            streak_ratio: 0.0,
            streak_threshold: threshold,
            min_margin,
            hot_key_share: 0.0,
            min_hot_key_share,
            expected_gain_score: 0.0,
            min_expected_gain_score,
        };
    }

    // Sample a bounded, evenly-spaced window across the whole batch to avoid
    // first-window bias when hotspots arrive later in queue order. Keep the
    // sample window env-tunable for experimental adaptive lanes, but clamp it
    // fail-closed so misconfiguration cannot trigger unbounded scan work.
    let sample_len = auto_adaptive_sample_len(txs.len());
    let mut same_key_streak_hits = 0usize;
    let mut total_pairs = 0usize;
    let mut prev_key: Option<u64> = None;
    let mut key_hist: HashMap<u64, usize> = HashMap::new();
    let mut observed = 0usize;

    let batch_len = txs.len();
    let direct_scan = sample_len == batch_len;
    let mut prev_idx: Option<usize> = None;
    for i in 0..sample_len {
        // Keep endpoints visible in bounded sampling windows so late-batch
        // hotspots contribute to adaptive scheduler decisions.
        // When sample_len==batch_len (most medium batches), index directly to
        // avoid per-item division in this hot scheduler probe.
        let idx = if direct_scan {
            i
        } else if sample_len > 1 {
            i.saturating_mul(batch_len.saturating_sub(1)) / (sample_len - 1)
        } else {
            0
        };
        if prev_idx == Some(idx) {
            continue;
        }
        prev_idx = Some(idx);
        let tx = &txs[idx];
        let key = primary_access_domain_key(tx);
        if let Some(k) = key {
            observed += 1;
            *key_hist.entry(k).or_insert(0) += 1;
            if let Some(pk) = prev_key {
                total_pairs += 1;
                if pk == k {
                    same_key_streak_hits += 1;
                }
            }
            prev_key = Some(k);
        } else {
            // Keyless txs should break streak continuity instead of allowing
            // later keyed samples to look adjacent in the hotspot probe.
            prev_key = None;
        }
    }

    if total_pairs == 0 || observed == 0 {
        return AutoAdaptiveDecision {
            use_hot_bucket: false,
            reason: "insufficient_sample",
            sample_len,
            streak_ratio: 0.0,
            streak_threshold: threshold,
            min_margin,
            hot_key_share: 0.0,
            min_hot_key_share,
            expected_gain_score: 0.0,
            min_expected_gain_score,
        };
    }

    let streak_ratio = same_key_streak_hits as f64 / total_pairs as f64;
    let max_key_count = key_hist.values().copied().max().unwrap_or(0);
    let hot_key_share = max_key_count as f64 / observed as f64;

    let expected_gain_score = streak_ratio * hot_key_share;
    let use_hot_bucket = streak_ratio >= threshold + min_margin
        && hot_key_share >= min_hot_key_share
        && expected_gain_score >= min_expected_gain_score;
    let reason = if use_hot_bucket {
        "hotspot_detected"
    } else if hot_key_share < min_hot_key_share {
        "low_hot_key_share"
    } else if expected_gain_score < min_expected_gain_score {
        "low_expected_gain"
    } else {
        "below_streak_budget"
    };

    AutoAdaptiveDecision {
        use_hot_bucket,
        reason,
        sample_len,
        streak_ratio,
        streak_threshold: threshold,
        min_margin,
        hot_key_share,
        min_hot_key_share,
        expected_gain_score,
        min_expected_gain_score,
    }
}
