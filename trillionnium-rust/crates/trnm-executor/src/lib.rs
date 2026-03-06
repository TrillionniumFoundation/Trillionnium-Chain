use std::collections::{HashMap, HashSet};
use trnm_types::{ObjectRef, Tx};

#[derive(Debug, Clone, Copy)]
pub enum GroupingStrategy {
    Original,
    FootprintDesc,
    WriteFirst,
    WriteLast,
    HotBucketInterleave,
    AutoAdaptive,
    AggressiveGreedy,
}

#[derive(Debug, Clone)]
pub struct GroupingProfile {
    pub tx_count: usize,
    pub group_count: usize,
    pub grouped_count: usize,
    pub max_group_size: usize,
    pub min_group_size: usize,
    pub avg_group_size: f64,
    pub conflict_checks: usize,
    pub conflict_hits: usize,
    pub candidate_groups_scanned: usize,
    // Aggressive-only stage attribution counters.
    pub stage_ww_checks: usize,
    pub stage_ww_hits: usize,
    pub stage_wr_checks: usize,
    pub stage_wr_hits: usize,
    pub stage_rw_checks: usize,
    pub stage_rw_hits: usize,
}

#[derive(Debug, Clone)]
pub struct AutoAdaptiveDecision {
    pub use_hot_bucket: bool,
    pub reason: &'static str,
    pub sample_len: usize,
    pub streak_ratio: f64,
    pub streak_threshold: f64,
    pub min_margin: f64,
    pub hot_key_share: f64,
    pub min_hot_key_share: f64,
    pub expected_gain_score: f64,
    pub min_expected_gain_score: f64,
}

pub fn detect_conflict(a: &Tx, b: &Tx) -> bool {
    intersects(&a.write_set, &b.write_set)
        || intersects(&a.write_set, &b.read_set)
        || intersects(&a.read_set, &b.write_set)
}

#[inline]
fn access_key(obj: &ObjectRef) -> u64 {
    obj.id
}

#[inline]
fn dedup_access_keys(objs: &[ObjectRef]) -> Vec<u64> {
    // Small-set fast path avoids HashSet allocation for common tiny access lists.
    if objs.len() <= 8 {
        let mut out: Vec<u64> = Vec::with_capacity(objs.len());
        for obj in objs {
            let key = access_key(obj);
            if !out.contains(&key) {
                out.push(key);
            }
        }
        return out;
    }

    let mut seen: HashSet<u64> = HashSet::with_capacity(objs.len());
    let mut out: Vec<u64> = Vec::with_capacity(objs.len());
    for obj in objs {
        let key = access_key(obj);
        if seen.insert(key) {
            out.push(key);
        }
    }
    out
}

fn intersects(x: &[ObjectRef], y: &[ObjectRef]) -> bool {
    if x.is_empty() || y.is_empty() {
        return false;
    }

    // Singleton fast path: common for simple transfer-like txs; avoid HashSet and
    // reduce iterator overhead in hot conflict probes.
    if x.len() == 1 {
        let key = access_key(&x[0]);
        return y.iter().any(|obj| access_key(obj) == key);
    }
    if y.len() == 1 {
        let key = access_key(&y[0]);
        return x.iter().any(|obj| access_key(obj) == key);
    }

    // Tiny-set fast path: avoid HashSet allocation on common low-footprint txs.
    // Iterate the smaller side first to reduce pairwise comparisons under skewed
    // tiny footprints (e.g. 1x8), while preserving duplicate-tolerant semantics.
    if x.len() <= 8 && y.len() <= 8 {
        let (small, large) = if x.len() <= y.len() { (x, y) } else { (y, x) };
        for a in small {
            let akey = access_key(a);
            if large.iter().any(|b| access_key(b) == akey) {
                return true;
            }
        }
        return false;
    }

    // Build a set from the smaller side to reduce comparisons.
    let (small, large) = if x.len() <= y.len() { (x, y) } else { (y, x) };

    // Skewed low-footprint path: avoid HashSet allocation when one side has only a
    // handful of keys (common in transfer-like writes against large read domains).
    if small.len() <= 4 {
        for a in small {
            let akey = access_key(a);
            if large.iter().any(|b| access_key(b) == akey) {
                return true;
            }
        }
        return false;
    }

    let seen: HashSet<u64> = small.iter().map(access_key).collect();
    large.iter().any(|obj| seen.contains(&access_key(obj)))
}

#[inline]
fn vec_hashset_intersects(a: &[u64], b: &HashSet<u64>) -> bool {
    if a.is_empty() || b.is_empty() {
        return false;
    }

    // Singleton fast path shows up frequently in conflict-domain probes and
    // avoids iterator/closure overhead in the hottest branch.
    if a.len() == 1 {
        return b.contains(&a[0]);
    }

    // Symmetric singleton fast path: deep-scan stages can probe wide vectors
    // against one-key group domains; avoid walking the whole vector in that case.
    if b.len() == 1 {
        let only = *b.iter().next().expect("single-key set must contain one element");
        return a.contains(&only);
    }

    for k in a {
        if b.contains(k) {
            return true;
        }
    }
    false
}

/// Build parallel-safe groups:
/// - txs within the same group are pairwise non-conflicting (can run in parallel)
/// - groups themselves are applied in order
pub fn build_parallel_groups(txs: &[Tx]) -> Vec<Vec<Tx>> {
    build_parallel_groups_profile(txs).0
}

pub fn build_parallel_groups_profile(txs: &[Tx]) -> (Vec<Vec<Tx>>, GroupingProfile) {
    build_parallel_groups_profile_with_strategy(txs, GroupingStrategy::Original)
}

pub fn build_parallel_groups_profile_with_strategy(
    txs: &[Tx],
    strategy: GroupingStrategy,
) -> (Vec<Vec<Tx>>, GroupingProfile) {
    if txs.is_empty() {
        return (
            Vec::new(),
            GroupingProfile {
                tx_count: 0,
                group_count: 0,
                grouped_count: 0,
                max_group_size: 0,
                min_group_size: 0,
                avg_group_size: 0.0,
                conflict_checks: 0,
                conflict_hits: 0,
                candidate_groups_scanned: 0,
                stage_ww_checks: 0,
                stage_ww_hits: 0,
                stage_wr_checks: 0,
                stage_wr_hits: 0,
                stage_rw_checks: 0,
                stage_rw_hits: 0,
            },
        );
    }

    let mut selected = strategy;
    if matches!(selected, GroupingStrategy::AutoAdaptive) {
        let d = auto_adaptive_decision(txs);
        selected = if d.use_hot_bucket {
            GroupingStrategy::HotBucketInterleave
        } else {
            GroupingStrategy::Original
        };
    }

    let mut ordered: Vec<Tx> = txs.to_vec();
    reorder_for_strategy(&mut ordered, selected);

    if matches!(selected, GroupingStrategy::AggressiveGreedy) {
        return build_parallel_groups_aggressive_profile(txs, ordered);
    }

    let mut groups: Vec<Vec<Tx>> = Vec::new();

    // Pre-size maps from access-footprint hint to reduce rehashing on
    // wide-object workloads while keeping bounded overhead on tiny batches.
    let map_cap = access_map_capacity_hint(txs);
    // object(id) -> latest group that has a writer touching this object
    let mut latest_writer_group: HashMap<u64, usize> = HashMap::with_capacity(map_cap);
    // object(id) -> latest group that has a reader touching this object
    let mut latest_reader_group: HashMap<u64, usize> = HashMap::with_capacity(map_cap);

    // Profiling counters (lightweight approximation instead of pairwise O(n^2) scans)
    let mut conflict_checks = 0usize;
    let mut conflict_hits = 0usize;

    for tx in ordered {
        // minimal group index forced by previous conflicting accesses
        let mut required_group = 0usize;

        // Deduplicate per-tx access keys while avoiding HashSet allocation in hot path.
        let read_keys = dedup_access_keys(&tx.read_set);
        let write_keys = dedup_access_keys(&tx.write_set);

        // read conflicts with previous writers on the same object
        for key in &read_keys {
            conflict_checks += 1;
            if let Some(&g) = latest_writer_group.get(key) {
                conflict_hits += 1;
                required_group = required_group.max(g + 1);
            }
        }

        // write conflicts with previous writers and readers on the same object
        for key in &write_keys {
            conflict_checks += 1;
            if let Some(&g) = latest_writer_group.get(key) {
                conflict_hits += 1;
                required_group = required_group.max(g + 1);
            }
            conflict_checks += 1;
            if let Some(&g) = latest_reader_group.get(key) {
                conflict_hits += 1;
                required_group = required_group.max(g + 1);
            }
        }

        if groups.len() <= required_group {
            groups.resize_with(required_group + 1, Vec::new);
        }
        groups[required_group].push(tx);

        for key in read_keys {
            latest_reader_group.insert(key, required_group);
        }
        for key in write_keys {
            latest_writer_group.insert(key, required_group);
        }
    }

    let group_count = groups.len();
    let grouped_count: usize = groups.iter().map(|g| g.len()).sum();
    let max_group_size = groups.iter().map(|g| g.len()).max().unwrap_or(0);
    let min_group_size = groups.iter().map(|g| g.len()).min().unwrap_or(0);
    let avg_group_size = if group_count == 0 {
        0.0
    } else {
        grouped_count as f64 / group_count as f64
    };

    (
        groups,
        GroupingProfile {
            tx_count: txs.len(),
            group_count,
            grouped_count,
            max_group_size,
            min_group_size,
            avg_group_size,
            conflict_checks,
            conflict_hits,
            candidate_groups_scanned: 0,
            stage_ww_checks: 0,
            stage_ww_hits: 0,
            stage_wr_checks: 0,
            stage_wr_hits: 0,
            stage_rw_checks: 0,
            stage_rw_hits: 0,
        },
    )
}

fn build_parallel_groups_aggressive_profile(
    original_txs: &[Tx],
    ordered: Vec<Tx>,
) -> (Vec<Vec<Tx>>, GroupingProfile) {
    // Fast path (default): identical dependency-bound placement semantics as Original,
    // but keeps Aggressive strategy identity/flags and metrics interface stable.
    if !aggr_deep_scan_enabled() {
        let mut groups: Vec<Vec<Tx>> = Vec::new();
        let map_cap = access_map_capacity_hint(original_txs);
        let mut latest_writer_group: HashMap<u64, usize> = HashMap::with_capacity(map_cap);
        let mut latest_reader_group: HashMap<u64, usize> = HashMap::with_capacity(map_cap);

        let mut conflict_checks = 0usize;
        let mut conflict_hits = 0usize;

        for tx in ordered {
            let read_keys = dedup_access_keys(&tx.read_set);
            let write_keys = dedup_access_keys(&tx.write_set);

            let mut min_group = 0usize;
            for key in &read_keys {
                conflict_checks += 1;
                if let Some(&g) = latest_writer_group.get(key) {
                    conflict_hits += 1;
                    min_group = min_group.max(g + 1);
                }
            }
            for key in &write_keys {
                conflict_checks += 1;
                if let Some(&g) = latest_writer_group.get(key) {
                    conflict_hits += 1;
                    min_group = min_group.max(g + 1);
                }
                conflict_checks += 1;
                if let Some(&g) = latest_reader_group.get(key) {
                    conflict_hits += 1;
                    min_group = min_group.max(g + 1);
                }
            }

            if groups.len() <= min_group {
                groups.resize_with(min_group + 1, Vec::new);
            }
            groups[min_group].push(tx);

            for key in read_keys {
                latest_reader_group.insert(key, min_group);
            }
            for key in write_keys {
                latest_writer_group.insert(key, min_group);
            }
        }

        let group_count = groups.len();
        let grouped_count: usize = groups.iter().map(|g| g.len()).sum();
        let max_group_size = groups.iter().map(|g| g.len()).max().unwrap_or(0);
        let min_group_size = groups.iter().map(|g| g.len()).min().unwrap_or(0);
        let avg_group_size = if group_count == 0 {
            0.0
        } else {
            grouped_count as f64 / group_count as f64
        };

        return (
            groups,
            GroupingProfile {
                tx_count: original_txs.len(),
                group_count,
                grouped_count,
                max_group_size,
                min_group_size,
                avg_group_size,
                conflict_checks,
                conflict_hits,
                candidate_groups_scanned: 0,
                stage_ww_checks: 0,
                stage_ww_hits: 0,
                stage_wr_checks: 0,
                stage_wr_hits: 0,
                stage_rw_checks: 0,
                stage_rw_hits: 0,
            },
        );
    }

    // Deep scan path (experiment-only).
    let mut groups: Vec<Vec<Tx>> = Vec::new();
    let mut group_read_keys: Vec<HashSet<u64>> = Vec::new();
    let mut group_write_keys: Vec<HashSet<u64>> = Vec::new();

    let map_cap = access_map_capacity_hint(original_txs);
    let mut latest_writer_group: HashMap<u64, usize> = HashMap::with_capacity(map_cap);
    let mut latest_reader_group: HashMap<u64, usize> = HashMap::with_capacity(map_cap);

    let mut conflict_checks = 0usize;
    let mut conflict_hits = 0usize;
    let mut candidate_groups_scanned = 0usize;
    let mut stage_ww_checks = 0usize;
    let mut stage_ww_hits = 0usize;
    let mut stage_wr_checks = 0usize;
    let mut stage_wr_hits = 0usize;
    let mut stage_rw_checks = 0usize;
    let mut stage_rw_hits = 0usize;
    let scan_window = aggr_scan_window();
    let skip_empty_stage_checks = aggr_skip_empty_stage_checks();
    let rr_enabled = aggr_scan_round_robin_enabled();
    let mut rr_cursor = aggr_scan_round_robin_seed();

    for tx in ordered {
        let mut tx_slot = Some(tx);
        let read_keys = dedup_access_keys(&tx_slot.as_ref().expect("tx must exist").read_set);
        let write_keys = dedup_access_keys(&tx_slot.as_ref().expect("tx must exist").write_set);
        let read_empty = read_keys.is_empty();
        let write_empty = write_keys.is_empty();

        let mut min_group = 0usize;
        for key in &read_keys {
            if let Some(&g) = latest_writer_group.get(key) {
                min_group = min_group.max(g + 1);
            }
        }
        for key in &write_keys {
            if let Some(&g) = latest_writer_group.get(key) {
                min_group = min_group.max(g + 1);
            }
            if let Some(&g) = latest_reader_group.get(key) {
                min_group = min_group.max(g + 1);
            }
        }

        let mut placed = false;
        let mut scanned = 0usize;
        let candidate_span = groups.len().saturating_sub(min_group);
        let start_offset = if rr_enabled && candidate_span > 1 {
            rr_cursor % candidate_span
        } else {
            0
        };
        for step in 0..candidate_span {
            if scan_window > 0 && scanned >= scan_window {
                break;
            }
            let idx = min_group + ((start_offset + step) % candidate_span);
            scanned += 1;
            candidate_groups_scanned += 1;
            conflict_checks += 1;

            if !skip_empty_stage_checks || !write_empty {
                stage_ww_checks += 1;
                if vec_hashset_intersects(&write_keys, &group_write_keys[idx]) {
                    conflict_hits += 1;
                    stage_ww_hits += 1;
                    continue;
                }

                stage_wr_checks += 1;
                if vec_hashset_intersects(&write_keys, &group_read_keys[idx]) {
                    conflict_hits += 1;
                    stage_wr_hits += 1;
                    continue;
                }
            }

            if !skip_empty_stage_checks || !read_empty {
                stage_rw_checks += 1;
                if vec_hashset_intersects(&read_keys, &group_write_keys[idx]) {
                    conflict_hits += 1;
                    stage_rw_hits += 1;
                    continue;
                }
            }

            groups[idx].push(tx_slot.take().expect("tx already moved"));
            group_read_keys[idx].extend(read_keys.iter().copied());
            group_write_keys[idx].extend(write_keys.iter().copied());

            for key in &read_keys {
                latest_reader_group.insert(*key, idx);
            }
            for key in &write_keys {
                latest_writer_group.insert(*key, idx);
            }

            placed = true;
            break;
        }

        if !placed {
            let idx = groups.len();
            groups.push(vec![tx_slot.take().expect("tx already moved")]);
            group_read_keys.push(read_keys.iter().copied().collect());
            group_write_keys.push(write_keys.iter().copied().collect());

            for key in &group_read_keys[idx] {
                latest_reader_group.insert(*key, idx);
            }
            for key in &group_write_keys[idx] {
                latest_writer_group.insert(*key, idx);
            }
        }

        if rr_enabled && candidate_span > 1 {
            rr_cursor = rr_cursor.wrapping_add(1);
        }
    }

    let group_count = groups.len();
    let grouped_count: usize = groups.iter().map(|g| g.len()).sum();
    let max_group_size = groups.iter().map(|g| g.len()).max().unwrap_or(0);
    let min_group_size = groups.iter().map(|g| g.len()).min().unwrap_or(0);
    let avg_group_size = if group_count == 0 {
        0.0
    } else {
        grouped_count as f64 / group_count as f64
    };

    (
        groups,
        GroupingProfile {
            tx_count: original_txs.len(),
            group_count,
            grouped_count,
            max_group_size,
            min_group_size,
            avg_group_size,
            conflict_checks,
            conflict_hits,
            candidate_groups_scanned,
            stage_ww_checks,
            stage_ww_hits,
            stage_wr_checks,
            stage_wr_hits,
            stage_rw_checks,
            stage_rw_hits,
        },
    )
}

#[inline]
fn access_map_capacity_hint(txs: &[Tx]) -> usize {
    const MIN_CAP: usize = 64;
    const MAX_CAP: usize = 1 << 20;

    let mut footprint = 0usize;
    for tx in txs {
        footprint = footprint
            .saturating_add(tx.read_set.len())
            .saturating_add(tx.write_set.len());
    }

    // HashMap load-factor friendly sizing. Keep a floor for tiny batches and
    // cap for pathological bursts so this remains a low-risk sizing hint.
    let hinted = footprint.saturating_mul(4).saturating_div(3).saturating_add(1);
    hinted.clamp(MIN_CAP, MAX_CAP)
}

fn aggr_scan_window() -> usize {
    const MAX_SCAN_WINDOW: usize = 4096;

    std::env::var("TRNM_AGGR_SCAN_WINDOW")
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .map(|v| v.min(MAX_SCAN_WINDOW))
        .unwrap_or(0)
}

fn aggr_skip_empty_stage_checks() -> bool {
    std::env::var("TRNM_AGGR_SKIP_EMPTY_STAGE_CHECKS")
        .ok()
        .map(|v| {
            let s = v.trim().to_ascii_lowercase();
            !(s == "0" || s == "false" || s == "off" || s == "no")
        })
        .unwrap_or(true)
}

fn aggr_deep_scan_enabled() -> bool {
    std::env::var("TRNM_AGGR_DEEP_SCAN")
        .ok()
        .map(|v| {
            let s = v.trim().to_ascii_lowercase();
            !(s == "0" || s == "false" || s == "off" || s == "no")
        })
        .unwrap_or(false)
}

fn aggr_scan_round_robin_enabled() -> bool {
    std::env::var("TRNM_AGGR_SCAN_ROUND_ROBIN")
        .ok()
        .map(|v| {
            let s = v.trim().to_ascii_lowercase();
            !(s == "0" || s == "false" || s == "off" || s == "no")
        })
        .unwrap_or(true)
}

fn aggr_scan_round_robin_seed() -> usize {
    std::env::var("TRNM_AGGR_SCAN_RR_SEED")
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .unwrap_or(0)
}

fn auto_hot_streak_threshold() -> f64 {
    std::env::var("TRNM_AUTO_HOT_STREAK_RATIO")
        .ok()
        .and_then(|v| v.parse::<f64>().ok())
        .map(|v| v.clamp(0.0, 1.0))
        .unwrap_or(0.22)
}

fn auto_reorder_min_margin() -> f64 {
    std::env::var("TRNM_AUTO_REORDER_MIN_MARGIN")
        .ok()
        .and_then(|v| v.parse::<f64>().ok())
        .map(|v| v.clamp(0.0, 1.0))
        .unwrap_or(0.04)
}

fn auto_reorder_min_hot_key_share() -> f64 {
    std::env::var("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE")
        .ok()
        .and_then(|v| v.parse::<f64>().ok())
        .map(|v| v.clamp(0.0, 1.0))
        .unwrap_or(0.0075)
}

fn hot_bucket_count() -> usize {
    std::env::var("TRNM_HOT_BUCKETS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .map(|v| v.clamp(4, 64))
        .unwrap_or(8)
}

fn auto_min_expected_gain_score() -> f64 {
    std::env::var("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE")
        .ok()
        .and_then(|v| v.parse::<f64>().ok())
        .map(|v| v.clamp(0.0, 1.0))
        .unwrap_or(0.01)
}

pub fn auto_adaptive_decision(txs: &[Tx]) -> AutoAdaptiveDecision {
    let threshold = auto_hot_streak_threshold();
    let min_margin = auto_reorder_min_margin();
    let min_hot_key_share = auto_reorder_min_hot_key_share();
    let min_expected_gain_score = auto_min_expected_gain_score();

    if txs.len() < 512 {
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

    // Sample first window to estimate hot-key streak pressure.
    let sample_len = txs.len().min(2048);
    let mut same_key_streak_hits = 0usize;
    let mut total_pairs = 0usize;
    let mut prev_key: Option<u64> = None;
    let mut key_hist: HashMap<u64, usize> = HashMap::new();
    let mut observed = 0usize;

    for tx in txs.iter().take(sample_len) {
        let key = tx
            .write_set
            .first()
            .or_else(|| tx.read_set.first())
            .map(|o| o.id);
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

fn hot_bucket_hint(tx: &Tx, buckets_n: usize) -> usize {
    let key_a = tx
        .write_set
        .first()
        .or_else(|| tx.read_set.first())
        .map(|o| o.id as usize)
        .unwrap_or(0);
    let key_b = tx
        .write_set
        .get(1)
        .or_else(|| tx.read_set.get(1))
        .map(|o| o.id as usize)
        .unwrap_or(0);
    (key_a ^ key_b.rotate_left(7)) % buckets_n
}

fn reorder_for_strategy(txs: &mut [Tx], strategy: GroupingStrategy) {
    match strategy {
        GroupingStrategy::Original => {}
        GroupingStrategy::FootprintDesc => {
            txs.sort_by_key(|tx| {
                let footprint = tx.read_set.len() + tx.write_set.len();
                (std::cmp::Reverse(footprint), tx.id)
            });
        }
        GroupingStrategy::WriteFirst => {
            txs.sort_by_key(|tx| {
                (
                    std::cmp::Reverse(tx.write_set.len()),
                    std::cmp::Reverse(tx.read_set.len()),
                    tx.id,
                )
            });
        }
        GroupingStrategy::WriteLast => {
            txs.sort_by_key(|tx| {
                (
                    tx.write_set.len(),
                    std::cmp::Reverse(tx.read_set.len()),
                    tx.id,
                )
            });
        }
        GroupingStrategy::HotBucketInterleave => {
            // Heuristic reorder; see should_use_hot_bucket_interleave for adaptive trigger.
            // Heuristic: shard txs by a stable access-key hint, then round-robin buckets.
            // Goal is to avoid long same-key streaks in input order under hotspot workloads.
            if txs.len() <= 1 {
                return;
            }
            // Cap bucket fanout by input size: for tiny batches this avoids allocating
            // and probing empty buckets while preserving the same interleave semantics.
            let buckets_n = hot_bucket_count().min(txs.len());
            let mut buckets: Vec<Vec<Tx>> = vec![Vec::new(); buckets_n];

            for tx in txs.iter().cloned() {
                // Prefer write-set as stronger conflict signal; fold a second key when present
                // to reduce bucket skew for mixed workloads.
                let bucket = hot_bucket_hint(&tx, buckets_n);
                buckets[bucket].push(tx);
            }

            // Keep insertion order inside each bucket (already stable by input stream);
            // avoid extra O(n log n) sorting cost.

            // Stable round-robin with move semantics (avoid per-tx clone cost).
            let mut iters: Vec<std::vec::IntoIter<Tx>> =
                buckets.into_iter().map(|b| b.into_iter()).collect();
            let mut merged = Vec::with_capacity(txs.len());
            // Seed the initial bucket probe from the first tx hot-key hint so
            // repeated batches do not always favor bucket 0 at cycle start.
            let mut rr_start = txs
                .first()
                .map(|tx| hot_bucket_hint(tx, iters.len()))
                .unwrap_or(0);
            // Rotate the round-robin start bucket each pass to reduce consistent
            // first-bucket preference under uneven bucket depths.
            loop {
                let mut moved = false;
                let n = iters.len();
                for step in 0..n {
                    let idx = (rr_start + step) % n;
                    if let Some(tx) = iters[idx].next() {
                        merged.push(tx);
                        moved = true;
                    }
                }
                if !moved {
                    break;
                }
                rr_start = (rr_start + 1) % n;
            }

            for (dst, src) in txs.iter_mut().zip(merged.into_iter()) {
                *dst = src;
            }
        }
        GroupingStrategy::AutoAdaptive => {
            // Auto strategy is resolved before calling reorder_for_strategy.
        }
        GroupingStrategy::AggressiveGreedy => {
            // Keep original order by default; aggressive placement logic handles packing.
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, MutexGuard, OnceLock};

    fn o(id: u64) -> ObjectRef {
        ObjectRef { id, version: 1 }
    }
    fn tx(id: u64, r: Vec<ObjectRef>, w: Vec<ObjectRef>) -> Tx {
        Tx {
            id,
            read_set: r,
            write_set: w,
            payload: vec![],
        }
    }

    #[test]
    fn ww_conflict() {
        assert!(detect_conflict(
            &tx(1, vec![], vec![o(1)]),
            &tx(2, vec![], vec![o(1)])
        ));
    }

    #[test]
    fn rw_conflict() {
        assert!(detect_conflict(
            &tx(1, vec![o(2)], vec![]),
            &tx(2, vec![], vec![o(2)])
        ));
    }

    #[test]
    fn no_conflict() {
        assert!(!detect_conflict(
            &tx(1, vec![o(1)], vec![]),
            &tx(2, vec![o(2)], vec![])
        ));
    }

    #[test]
    fn tiny_footprint_conflict_check_handles_duplicates_without_false_positive() {
        let a = tx(1, vec![o(10), o(10), o(11)], vec![]);
        let b = tx(2, vec![o(12), o(12), o(13)], vec![]);
        let c = tx(3, vec![], vec![o(11)]);

        assert!(!detect_conflict(&a, &b));
        assert!(detect_conflict(&a, &c));
    }

    #[test]
    fn singleton_access_conflict_path_handles_skewed_footprints() {
        let singleton_write = tx(1, vec![], vec![o(42)]);
        let wide_read_hit = tx(2, vec![o(7), o(8), o(42), o(9), o(10)], vec![]);
        let wide_read_miss = tx(3, vec![o(7), o(8), o(9), o(10)], vec![]);

        assert!(detect_conflict(&singleton_write, &wide_read_hit));
        assert!(!detect_conflict(&singleton_write, &wide_read_miss));
    }

    #[test]
    fn vec_hashset_intersects_handles_singleton_hashset_domain() {
        let mut singleton = HashSet::new();
        singleton.insert(42u64);

        assert!(vec_hashset_intersects(&[7, 8, 42, 9], &singleton));
        assert!(!vec_hashset_intersects(&[7, 8, 9], &singleton));
    }

    #[test]
    fn skewed_small_vs_large_conflict_path_handles_large_domains() {
        let small_write = tx(1, vec![], vec![o(101), o(202), o(303), o(404)]);
        let mut wide_read_hit: Vec<ObjectRef> = (1..=64).map(o).collect();
        wide_read_hit.push(o(303));
        let wide_read_miss: Vec<ObjectRef> = (1..=64).map(|id| o(id + 10_000)).collect();

        assert!(detect_conflict(&small_write, &tx(2, wide_read_hit, vec![])));
        assert!(!detect_conflict(&small_write, &tx(3, wide_read_miss, vec![])));
    }

    #[test]
    fn grouping_parallel_safe() {
        let g = build_parallel_groups(&[
            tx(1, vec![], vec![o(1)]),
            tx(2, vec![], vec![o(2)]),
            tx(3, vec![o(1)], vec![]),
        ]);
        assert_eq!(g.len(), 2);
        assert_eq!(g.iter().map(|x| x.len()).sum::<usize>(), 3);
        // first group can contain tx1+tx2 (non-conflict), tx3 should be separate
        assert!(g
            .iter()
            .any(|grp| grp.iter().any(|t| t.id == 3) && grp.len() == 1));
    }

    #[test]
    fn strategy_preserves_tx_count() {
        let txs = vec![
            tx(1, vec![o(1)], vec![o(2)]),
            tx(2, vec![o(2)], vec![o(3)]),
            tx(3, vec![o(4)], vec![]),
        ];
        let (g1, _) = build_parallel_groups_profile_with_strategy(&txs, GroupingStrategy::Original);
        let (g2, _) =
            build_parallel_groups_profile_with_strategy(&txs, GroupingStrategy::FootprintDesc);
        let (g3, _) =
            build_parallel_groups_profile_with_strategy(&txs, GroupingStrategy::AutoAdaptive);
        let (g4, _) =
            build_parallel_groups_profile_with_strategy(&txs, GroupingStrategy::AggressiveGreedy);
        let c1: usize = g1.iter().map(|g| g.len()).sum();
        let c2: usize = g2.iter().map(|g| g.len()).sum();
        let c3: usize = g3.iter().map(|g| g.len()).sum();
        let c4: usize = g4.iter().map(|g| g.len()).sum();
        assert_eq!(c1, txs.len());
        assert_eq!(c2, txs.len());
        assert_eq!(c3, txs.len());
        assert_eq!(c4, txs.len());
    }

    #[test]
    fn aggressive_groups_are_pairwise_non_conflicting() {
        let txs = vec![
            tx(1, vec![o(1)], vec![o(2)]),
            tx(2, vec![o(3)], vec![o(4)]),
            tx(3, vec![o(2)], vec![]),
            tx(4, vec![o(5)], vec![o(1)]),
            tx(5, vec![o(9)], vec![o(10)]),
        ];
        let (groups, _) =
            build_parallel_groups_profile_with_strategy(&txs, GroupingStrategy::AggressiveGreedy);

        for grp in groups {
            for i in 0..grp.len() {
                for j in (i + 1)..grp.len() {
                    assert!(!detect_conflict(&grp[i], &grp[j]));
                }
            }
        }
    }

    fn env_lock() -> MutexGuard<'static, ()> {
        static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .expect("env test lock poisoned")
    }

    #[test]
    fn aggressive_round_robin_cursor_avoids_even_id_bias() {
        let _env = env_lock();
        let _deep = EnvGuard::set("TRNM_AGGR_DEEP_SCAN", "1");
        let _rr = EnvGuard::set("TRNM_AGGR_SCAN_ROUND_ROBIN", "1");
        let _window = EnvGuard::set("TRNM_AGGR_SCAN_WINDOW", "1");

        let txs = vec![
            tx(1, vec![], vec![o(7)]),   // group 0
            tx(3, vec![], vec![o(7)]),   // forced to group 1 (conflicts with tx1)
            tx(10, vec![o(101)], vec![]), // independent even ids that previously pinned to offset 0
            tx(12, vec![o(102)], vec![]),
            tx(14, vec![o(103)], vec![]),
            tx(16, vec![o(104)], vec![]),
        ];

        let (groups, _) =
            build_parallel_groups_profile_with_strategy(&txs, GroupingStrategy::AggressiveGreedy);

        assert!(groups.len() >= 2);
        assert!(groups[0].len() >= 2);
        assert!(groups[1].len() >= 2);
    }

    #[test]
    fn hot_bucket_interleave_seeds_initial_round_from_first_hot_key() {
        let mut txs = vec![
            tx(501, vec![], vec![o(5)]), // bucket 5 when TRNM_HOT_BUCKETS=8
            tx(101, vec![], vec![o(0)]), // bucket 0
            tx(102, vec![], vec![o(8)]), // bucket 0
            tx(103, vec![], vec![o(16)]), // bucket 0
        ];

        reorder_for_strategy(&mut txs, GroupingStrategy::HotBucketInterleave);
        assert_eq!(txs.first().map(|t| t.id), Some(501));
    }

    #[test]
    fn hot_bucket_interleave_empty_batch_is_noop() {
        let mut txs = Vec::<Tx>::new();
        reorder_for_strategy(&mut txs, GroupingStrategy::HotBucketInterleave);
        assert!(txs.is_empty());
    }

    #[test]
    fn aggressive_round_robin_seed_rotates_initial_probe_start() {
        let _env = env_lock();
        let _deep = EnvGuard::set("TRNM_AGGR_DEEP_SCAN", "1");
        let _rr = EnvGuard::set("TRNM_AGGR_SCAN_ROUND_ROBIN", "1");
        let _window = EnvGuard::set("TRNM_AGGR_SCAN_WINDOW", "1");
        let _seed = EnvGuard::set("TRNM_AGGR_SCAN_RR_SEED", "1");

        let txs = vec![
            tx(1, vec![], vec![o(7)]), // group 0
            tx(3, vec![], vec![o(7)]), // forced to group 1
            tx(10, vec![o(101)], vec![]), // first free candidate should honor seed offset
        ];

        let (groups, _) =
            build_parallel_groups_profile_with_strategy(&txs, GroupingStrategy::AggressiveGreedy);

        assert!(groups.len() >= 2);
        assert!(groups[1].iter().any(|t| t.id == 10));
    }

    #[test]
    fn aggressive_respects_skip_empty_stage_checks_toggle() {
        let _env = env_lock();
        let _deep = EnvGuard::set("TRNM_AGGR_DEEP_SCAN", "1");
        let _rr = EnvGuard::set("TRNM_AGGR_SCAN_ROUND_ROBIN", "0");
        let _window = EnvGuard::set("TRNM_AGGR_SCAN_WINDOW", "2");
        let _skip_empty = EnvGuard::set("TRNM_AGGR_SKIP_EMPTY_STAGE_CHECKS", "0");

        let txs = vec![
            tx(1, vec![], vec![o(7)]), // group 0
            tx(3, vec![], vec![o(7)]), // forced to group 1
            tx(10, vec![], vec![]),    // empty access set, scans existing groups first
        ];

        let (_groups, profile) =
            build_parallel_groups_profile_with_strategy(&txs, GroupingStrategy::AggressiveGreedy);

        assert!(
            profile.stage_ww_checks > 0,
            "disable-skip toggle must keep ww stage checks observable"
        );
        assert!(
            profile.stage_wr_checks > 0,
            "disable-skip toggle must keep wr stage checks observable"
        );
        assert!(
            profile.stage_rw_checks > 0,
            "disable-skip toggle must keep rw stage checks observable"
        );
    }

    #[test]
    fn aggressive_scan_window_caps_candidate_probe_cost() {
        let _env = env_lock();
        let _deep = EnvGuard::set("TRNM_AGGR_DEEP_SCAN", "1");
        let _rr = EnvGuard::set("TRNM_AGGR_SCAN_ROUND_ROBIN", "1");
        let _window = EnvGuard::set("TRNM_AGGR_SCAN_WINDOW", "1");

        // Force many independent txs to create an expanding candidate span.
        // With scan window=1, each tx can probe at most one candidate group,
        // bounding probe work to O(n) and preventing deep-scan blowups.
        let mut txs = Vec::new();
        txs.push(tx(1, vec![], vec![o(7)]));
        txs.push(tx(2, vec![], vec![o(7)]));
        for i in 0..32u64 {
            txs.push(tx(100 + i, vec![o(10_000 + i)], vec![]));
        }

        let (_groups, profile) =
            build_parallel_groups_profile_with_strategy(&txs, GroupingStrategy::AggressiveGreedy);

        assert!(
            profile.candidate_groups_scanned <= txs.len().saturating_sub(1),
            "scan window must cap candidate scans to ~1 probe per tx"
        );
    }

    #[test]
    fn aggressive_scan_window_is_clamped_to_prevent_misconfigured_probe_blowups() {
        let _env = env_lock();
        let _window = EnvGuard::set("TRNM_AGGR_SCAN_WINDOW", "999999");

        assert_eq!(aggr_scan_window(), 4096);
    }

    #[test]
    fn aggressive_scan_window_parses_trimmed_numeric_env_values() {
        let _env = env_lock();
        let _window = EnvGuard::set("TRNM_AGGR_SCAN_WINDOW", " 128 ");

        assert_eq!(aggr_scan_window(), 128);
    }

    #[test]
    fn aggressive_round_robin_seed_parses_trimmed_numeric_env_values() {
        let _env = env_lock();
        let _seed = EnvGuard::set("TRNM_AGGR_SCAN_RR_SEED", " 7 ");

        assert_eq!(aggr_scan_round_robin_seed(), 7);
    }

    #[test]
    fn empty_batch_fast_path_is_profile_stable_across_strategies() {
        let strategies = [
            GroupingStrategy::Original,
            GroupingStrategy::HotBucketInterleave,
            GroupingStrategy::AggressiveGreedy,
            GroupingStrategy::AutoAdaptive,
        ];

        for strategy in strategies {
            let (groups, profile) = build_parallel_groups_profile_with_strategy(&[], strategy);
            assert!(groups.is_empty());
            assert_eq!(profile.tx_count, 0);
            assert_eq!(profile.group_count, 0);
            assert_eq!(profile.grouped_count, 0);
            assert_eq!(profile.max_group_size, 0);
            assert_eq!(profile.min_group_size, 0);
            assert_eq!(profile.avg_group_size, 0.0);
            assert_eq!(profile.conflict_checks, 0);
            assert_eq!(profile.conflict_hits, 0);
            assert_eq!(profile.candidate_groups_scanned, 0);
            assert_eq!(profile.stage_ww_checks, 0);
            assert_eq!(profile.stage_ww_hits, 0);
            assert_eq!(profile.stage_wr_checks, 0);
            assert_eq!(profile.stage_wr_hits, 0);
            assert_eq!(profile.stage_rw_checks, 0);
            assert_eq!(profile.stage_rw_hits, 0);
        }
    }

    struct EnvGuard {
        key: &'static str,
        old: Option<String>,
    }

    impl EnvGuard {
        fn set(key: &'static str, value: &str) -> Self {
            let old = std::env::var(key).ok();
            unsafe {
                std::env::set_var(key, value);
            }
            Self { key, old }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            if let Some(v) = &self.old {
                unsafe {
                    std::env::set_var(self.key, v);
                }
            } else {
                unsafe {
                    std::env::remove_var(self.key);
                }
            }
        }
    }
}
