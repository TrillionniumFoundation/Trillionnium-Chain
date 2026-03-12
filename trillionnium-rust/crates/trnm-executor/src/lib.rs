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
    pub hot_object_share: f64,
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
    // Read-only pairs can never conflict; skip three intersection probes in
    // the common telemetry/transfer path where writes are absent.
    if a.write_set.is_empty() && b.write_set.is_empty() {
        return false;
    }

    // Asymmetric fast paths: when one side is read-only, only a single probe can
    // produce a write/read hazard. This trims two unnecessary intersections from
    // hot free-ingress scheduling probes under mixed read-only traffic.
    if a.write_set.is_empty() {
        return intersects(&a.read_set, &b.write_set);
    }
    if b.write_set.is_empty() {
        return intersects(&a.write_set, &b.read_set);
    }

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

        // Duplicate-heavy small footprints can otherwise rescan `large` for the same
        // key many times. Keep this tiny-path dedup allocation bounded by <=8 keys.
        let mut unique_small_keys: Vec<u64> = Vec::with_capacity(small.len());
        for a in small {
            let key = access_key(a);
            if !unique_small_keys.contains(&key) {
                unique_small_keys.push(key);
            }
        }

        for key in unique_small_keys {
            if large.iter().any(|b| access_key(b) == key) {
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
        // Duplicate-heavy small footprints can otherwise rescan the large side
        // multiple times for the same key under hot-key bursts.
        let mut keys: Vec<u64> = Vec::with_capacity(small.len());
        for a in small {
            let key = access_key(a);
            if !keys.contains(&key) {
                keys.push(key);
            }
        }
        for key in keys {
            if large.iter().any(|b| access_key(b) == key) {
                return true;
            }
        }
        return false;
    }

    // Medium-small skew path: for 5..=8 keys against a moderately larger domain,
    // avoid HashSet allocation and probe linearly. Once domains grow beyond this
    // range, fall back to the HashSet path below to avoid repeated full scans.
    if small.len() <= 8 && (16..=64).contains(&large.len()) {
        let mut keys: Vec<u64> = Vec::with_capacity(small.len());
        for a in small {
            let key = access_key(a);
            if !keys.contains(&key) {
                keys.push(key);
            }
        }
        for key in keys {
            if large.iter().any(|b| access_key(b) == key) {
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
        let only = *b
            .iter()
            .next()
            .expect("single-key set must contain one element");
        return a.contains(&only);
    }

    // Small/medium vector fast path: duplicate-heavy conflict domains can
    // repeatedly probe the same key in hot scheduling loops. Dedup the probe
    // side in-place to keep hash lookups bounded without paying HashSet
    // allocation cost.
    if a.len() <= 32 {
        let mut seen: Vec<u64> = Vec::with_capacity(a.len());
        for k in a {
            if !seen.contains(k) {
                if b.contains(k) {
                    return true;
                }
                seen.push(*k);
            }
        }
        return false;
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

fn hot_object_share(txs: &[Tx]) -> f64 {
    let mut counts: HashMap<u64, usize> = HashMap::new();
    let mut total = 0usize;

    for tx in txs {
        let mut keys = dedup_access_keys(&tx.read_set);
        for key in dedup_access_keys(&tx.write_set) {
            if !keys.contains(&key) {
                keys.push(key);
            }
        }
        total += keys.len();
        for key in keys {
            *counts.entry(key).or_insert(0) += 1;
        }
    }

    if total == 0 {
        return 0.0;
    }

    let hottest = counts.values().copied().max().unwrap_or(0);
    hottest as f64 / total as f64
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
                hot_object_share: 0.0,
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

    // Free-ingress fast path: when no tx carries read/write footprint, all txs are
    // conflict-independent and land in a single execution group. Skip per-key map
    // bookkeeping in this hot path to reduce scheduler overhead at high ingress.
    if ordered
        .iter()
        .all(|tx| tx.read_set.is_empty() && tx.write_set.is_empty())
    {
        let grouped_count = ordered.len();
        let avg_group_size = grouped_count as f64;
        return (
            vec![ordered],
            GroupingProfile {
                tx_count: txs.len(),
                group_count: 1,
                grouped_count,
                max_group_size: grouped_count,
                min_group_size: grouped_count,
                avg_group_size,
                hot_object_share: 0.0,
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
    let hot_object_share = hot_object_share(txs);

    (
        groups,
        GroupingProfile {
            tx_count: txs.len(),
            group_count,
            grouped_count,
            max_group_size,
            min_group_size,
            avg_group_size,
            hot_object_share,
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
        let hot_object_share = hot_object_share(original_txs);

        return (
            groups,
            GroupingProfile {
                tx_count: original_txs.len(),
                group_count,
                grouped_count,
                max_group_size,
                min_group_size,
                avg_group_size,
                hot_object_share,
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

            if !skip_empty_stage_checks || !write_empty {
                conflict_checks += 1;
                stage_ww_checks += 1;
                if vec_hashset_intersects(&write_keys, &group_write_keys[idx]) {
                    conflict_hits += 1;
                    stage_ww_hits += 1;
                    continue;
                }

                conflict_checks += 1;
                stage_wr_checks += 1;
                if vec_hashset_intersects(&write_keys, &group_read_keys[idx]) {
                    conflict_hits += 1;
                    stage_wr_hits += 1;
                    continue;
                }
            }

            if !skip_empty_stage_checks || !read_empty {
                conflict_checks += 1;
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
    let hot_object_share = hot_object_share(original_txs);

    (
        groups,
        GroupingProfile {
            tx_count: original_txs.len(),
            group_count,
            grouped_count,
            max_group_size,
            min_group_size,
            avg_group_size,
            hot_object_share,
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
    let hinted = footprint
        .saturating_mul(4)
        .saturating_div(3)
        .saturating_add(1);
    hinted.clamp(MIN_CAP, MAX_CAP)
}

#[inline]
fn parse_env_numeric(name: &str) -> Option<String> {
    std::env::var(name).ok().and_then(|v| {
        let trimmed = v.trim();
        if trimmed.is_empty() {
            return None;
        }

        let unquoted = trimmed
            .strip_prefix('"')
            .and_then(|inner| inner.strip_suffix('"'))
            .or_else(|| {
                trimmed
                    .strip_prefix('\'')
                    .and_then(|inner| inner.strip_suffix('\''))
            })
            .map(str::trim)
            .unwrap_or(trimmed);
        if unquoted.is_empty() {
            return None;
        }

        // Accept common human-friendly separators in ops configs.
        if unquoted.contains('_') || unquoted.contains(',') {
            let mut compact = String::with_capacity(unquoted.len());
            for ch in unquoted.chars() {
                if ch != '_' && ch != ',' {
                    compact.push(ch);
                }
            }
            if compact.is_empty() {
                None
            } else {
                Some(compact)
            }
        } else {
            Some(unquoted.to_owned())
        }
    })
}

#[inline]
fn parse_env_usize(name: &str) -> Option<usize> {
    parse_env_numeric(name).and_then(|v| v.parse::<usize>().ok())
}

#[inline]
fn parse_env_f64(name: &str) -> Option<f64> {
    parse_env_numeric(name).and_then(|v| {
        let percent = v.ends_with('%');
        let numeric = if percent { v.strip_suffix('%').unwrap_or(&v) } else { &v };
        let parsed = numeric.parse::<f64>().ok()?;
        if !parsed.is_finite() {
            return None;
        }
        let value = if percent { parsed / 100.0 } else { parsed };
        value.is_finite().then_some(value)
    })
}

fn aggr_scan_window() -> usize {
    const DEFAULT_SCAN_WINDOW: usize = 0;
    const MAX_SCAN_WINDOW: usize = 4096;

    parse_env_usize("TRNM_AGGR_SCAN_WINDOW")
        .map(|v| v.min(MAX_SCAN_WINDOW))
        .filter(|&v| v > 0)
        .unwrap_or_else(|| {
            if aggr_deep_scan_enabled() {
                DEFAULT_SCAN_WINDOW
            } else {
                0
            }
        })
}

fn env_toggle_enabled(name: &str, default: bool) -> bool {
    std::env::var(name)
        .ok()
        .map(|v| {
            let trimmed = v.trim();
            let unquoted = trimmed
                .strip_prefix('"')
                .and_then(|inner| inner.strip_suffix('"'))
                .or_else(|| {
                    trimmed
                        .strip_prefix('\'')
                        .and_then(|inner| inner.strip_suffix('\''))
                })
                .unwrap_or(trimmed);
            let s = unquoted.trim().to_ascii_lowercase();
            if s.is_empty() || s.chars().all(|ch| ch == '_' || ch == ',') {
                return default;
            }
            !(s == "0" || s == "false" || s == "off" || s == "no")
        })
        .unwrap_or(default)
}

fn aggr_skip_empty_stage_checks() -> bool {
    env_toggle_enabled("TRNM_AGGR_SKIP_EMPTY_STAGE_CHECKS", true)
}

fn aggr_deep_scan_enabled() -> bool {
    env_toggle_enabled("TRNM_AGGR_DEEP_SCAN", false)
}

fn aggr_scan_round_robin_enabled() -> bool {
    env_toggle_enabled("TRNM_AGGR_SCAN_ROUND_ROBIN", true)
}

fn aggr_scan_round_robin_seed() -> usize {
    parse_env_usize("TRNM_AGGR_SCAN_RR_SEED").unwrap_or(0)
}

fn auto_hot_streak_threshold() -> f64 {
    parse_env_f64("TRNM_AUTO_HOT_STREAK_RATIO")
        .map(|v| v.clamp(0.0, 1.0))
        .unwrap_or(0.22)
}

fn auto_reorder_min_margin() -> f64 {
    parse_env_f64("TRNM_AUTO_REORDER_MIN_MARGIN")
        .map(|v| v.clamp(0.0, 1.0))
        .unwrap_or(0.04)
}

fn auto_reorder_min_hot_key_share() -> f64 {
    parse_env_f64("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE")
        .map(|v| v.clamp(0.0, 1.0))
        .unwrap_or(0.0075)
}

fn hot_bucket_count() -> usize {
    parse_env_usize("TRNM_HOT_BUCKETS")
        .map(|v| v.clamp(4, 64))
        .unwrap_or(8)
}

fn auto_min_expected_gain_score() -> f64 {
    parse_env_f64("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE")
        .map(|v| v.clamp(0.0, 1.0))
        .unwrap_or(0.01)
}

fn auto_adaptive_min_batch_len() -> usize {
    const DEFAULT_MIN_BATCH_LEN: usize = 512;
    const MIN_BATCH_LEN_FLOOR: usize = 64;
    const MIN_BATCH_LEN_CEIL: usize = 4096;

    parse_env_usize("TRNM_AUTO_MIN_BATCH_LEN")
        .map(|v| v.clamp(MIN_BATCH_LEN_FLOOR, MIN_BATCH_LEN_CEIL))
        .unwrap_or(DEFAULT_MIN_BATCH_LEN)
}

fn auto_adaptive_sample_len(batch_len: usize) -> usize {
    const MAX_SAMPLE_LEN: usize = 2048;
    const MIN_SAMPLE_LEN_FLOOR: usize = 64;
    const MIN_SAMPLE_LEN_CEIL: usize = MAX_SAMPLE_LEN;

    let configured = parse_env_usize("TRNM_AUTO_SAMPLE_LEN")
        .map(|v| v.clamp(MIN_SAMPLE_LEN_FLOOR, MIN_SAMPLE_LEN_CEIL))
        .unwrap_or(MAX_SAMPLE_LEN);

    batch_len.min(configured)
}

pub fn auto_adaptive_decision(txs: &[Tx]) -> AutoAdaptiveDecision {
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
    // Defensive guard: keep helper total for misconfigured callers and tests.
    // Production reorder path always uses buckets_n>=1, but this preserves
    // fail-closed deterministic behavior if future call sites pass zero.
    if buckets_n == 0 {
        return 0;
    }

    // Keep hash mixing deterministic across targets (32/64-bit) by using a
    // fixed-width integer domain before reducing to bucket count.
    let key_a = tx
        .write_set
        .first()
        .or_else(|| tx.read_set.first())
        .map(|o| o.id)
        .unwrap_or(0);
    let key_b = tx
        .write_set
        .get(1)
        .or_else(|| tx.read_set.get(1))
        .map(|o| o.id)
        .unwrap_or(0);
    let mixed = key_a ^ key_b.rotate_left(7);
    if buckets_n.is_power_of_two() {
        // Fast-path hot scheduler probes: avoid division in the common power-of-two
        // bucket layout while keeping deterministic bucket mapping.
        (mixed as usize) & (buckets_n - 1)
    } else {
        // Reduce in u64-space first; casting mixed directly to usize would truncate
        // high bits on 32-bit targets and skew bucket selection under wide key domains.
        (mixed % buckets_n as u64) as usize
    }
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
            // Micro-batches (2-3 txs) do not benefit from bucket interleave and only pay
            // allocation/probing overhead. Keep original order for better free-ingress latency
            // at low concurrency while preserving deterministic behavior.
            if txs.len() < 4 {
                return;
            }
            // Free-ingress (empty read/write sets) has no conflict-domain signal to
            // interleave on. Skip bucket materialization/probing and preserve stable
            // order to reduce scheduler overhead on the no-access hot path.
            if txs
                .iter()
                .all(|tx| tx.read_set.is_empty() && tx.write_set.is_empty())
            {
                return;
            }
            // Cap bucket fanout by input size: for tiny batches this avoids allocating
            // and probing empty buckets while preserving the same interleave semantics.
            let buckets_n = hot_bucket_count().min(txs.len());
            // Misconfigured/trimmed bucket fanout can collapse to a single bucket,
            // where interleave degenerates to identity while still paying probe cost.
            if buckets_n <= 1 {
                return;
            }
            let mut bucket_depths = vec![0usize; buckets_n];
            let mut tx_bucket_hints = Vec::with_capacity(txs.len());
            let mut non_empty_buckets = 0usize;

            for tx in txs.iter() {
                // First pass: count occupancy only. This lets hotspot/singleton
                // short-circuits bail out before cloning tx payloads into buckets.
                let bucket = hot_bucket_hint(tx, buckets_n);
                tx_bucket_hints.push(bucket);
                if bucket_depths[bucket] == 0 {
                    non_empty_buckets += 1;
                }
                bucket_depths[bucket] += 1;
            }

            // Degenerate hotspot fast path: if all txs landed in the same bucket,
            // round-robin interleave would reproduce the original order while paying
            // n-bucket probing overhead. Keep stable input order for lower scheduler cost.
            if non_empty_buckets <= 1 {
                return;
            }
            // Free-ingress fast path: when every non-empty bucket is singleton,
            // interleave cannot reduce same-key streaks and only adds probe/rotation
            // overhead. Preserve stable input order to reduce micro-batch scheduler cost.
            // We already track how many buckets are non-empty; equality here means each
            // tx landed in its own bucket (all singleton), avoiding an extra max-depth scan.
            if non_empty_buckets == txs.len() {
                return;
            }

            // Reuse the precomputed first bucket hint instead of re-hashing the
            // first tx on the hot-path round-robin seed selection.
            let first_hint = tx_bucket_hints.first().copied().unwrap_or(0);

            // Stable round-robin with move semantics (avoid per-tx clone cost).
            let n = buckets_n;
            let mut merged = Vec::with_capacity(txs.len());
            // Under highly skewed hot-bucket loads, start from the sparsest non-empty
            // bucket so low-volume conflict domains are serviced promptly instead of
            // always waiting behind the dominant lane at cycle start.
            let sparse_start = {
                let mut min_non_zero = usize::MAX;
                let mut max_depth = 0usize;
                for &depth in &bucket_depths {
                    if depth == 0 {
                        continue;
                    }
                    max_depth = max_depth.max(depth);
                    min_non_zero = min_non_zero.min(depth);
                }

                if min_non_zero != usize::MAX && max_depth >= min_non_zero.saturating_mul(2) {
                    // When multiple equally sparse buckets exist, rotate the sparse
                    // anti-starvation seed around the first hot-key hint to avoid
                    // repeatedly preferring the lowest bucket index.
                    let mut best_idx = None;
                    let mut best_distance = usize::MAX;
                    let mut best_counter_clockwise = usize::MAX;
                    for (idx, &depth) in bucket_depths.iter().enumerate() {
                        if depth != min_non_zero {
                            continue;
                        }
                        let clockwise = (idx + n - first_hint) % n;
                        let counter_clockwise = (first_hint + n - idx) % n;
                        let distance = clockwise.min(counter_clockwise);
                        if distance < best_distance
                            || (distance == best_distance
                                && counter_clockwise < best_counter_clockwise)
                        {
                            best_distance = distance;
                            best_counter_clockwise = counter_clockwise;
                            best_idx = Some(idx);
                        }
                    }
                    best_idx
                } else {
                    None
                }
            };

            let mut buckets: Vec<Vec<Tx>> = bucket_depths
                .iter()
                .map(|depth| Vec::with_capacity(*depth))
                .collect();
            for (tx, bucket) in txs.iter().cloned().zip(tx_bucket_hints.into_iter()) {
                // Prefer write-set as stronger conflict signal; fold a second key when present
                // to reduce bucket skew for mixed workloads.
                buckets[bucket].push(tx);
            }

            // Keep insertion order inside each bucket (already stable by input stream);
            // avoid extra O(n log n) sorting cost.
            let mut iters: Vec<std::vec::IntoIter<Tx>> =
                buckets.into_iter().map(|b| b.into_iter()).collect();
            // Seed the initial bucket probe from either sparse anti-starvation hint
            // or first tx hot-key hint so repeated batches do not always favor bucket 0.
            let mut rr_start = sparse_start.unwrap_or(first_hint);
            // Rotate the round-robin start bucket each pass to reduce consistent
            // first-bucket preference under uneven bucket depths.
            loop {
                let mut moved = false;
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
    fn read_only_overlap_is_non_conflicting() {
        assert!(!detect_conflict(
            &tx(1, vec![o(7), o(8)], vec![]),
            &tx(2, vec![o(8), o(9)], vec![])
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
    fn vec_hashset_intersects_tiny_duplicate_probe_path_preserves_semantics() {
        let domain: HashSet<u64> = [11u64, 12u64].into_iter().collect();

        // Duplicate-heavy tiny probe vectors should behave identically to the
        // generic path while avoiding repeated hash probes for the same key.
        assert!(vec_hashset_intersects(&[9, 9, 9, 12, 12], &domain));
        assert!(!vec_hashset_intersects(&[9, 9, 10, 10], &domain));
    }

    #[test]
    fn vec_hashset_intersects_medium_duplicate_probe_path_preserves_semantics() {
        let domain: HashSet<u64> = [77u64, 88u64].into_iter().collect();

        // Medium duplicate-heavy probe vectors should still preserve hit/miss
        // correctness while capping repeated hash probes.
        let hit = [
            1, 1, 2, 2, 3, 3, 4, 4, 77, 77, 77, 5, 5, 6, 6, 7, 7, 8, 8, 9,
        ];
        let miss = [
            1, 1, 2, 2, 3, 3, 4, 4, 55, 55, 56, 56, 57, 57, 58, 58, 59, 59, 60, 60,
        ];

        assert!(vec_hashset_intersects(&hit, &domain));
        assert!(!vec_hashset_intersects(&miss, &domain));
    }

    #[test]
    fn skewed_small_vs_large_conflict_path_handles_large_domains() {
        let small_write = tx(1, vec![], vec![o(101), o(202), o(303), o(404)]);
        let mut wide_read_hit: Vec<ObjectRef> = (1..=64).map(o).collect();
        wide_read_hit.push(o(303));
        let wide_read_miss: Vec<ObjectRef> = (1..=64).map(|id| o(id + 10_000)).collect();

        assert!(detect_conflict(&small_write, &tx(2, wide_read_hit, vec![])));
        assert!(!detect_conflict(
            &small_write,
            &tx(3, wide_read_miss, vec![])
        ));
    }

    #[test]
    fn medium_small_vs_large_conflict_path_avoids_hashset_and_preserves_semantics() {
        let small_write = tx(
            1,
            vec![],
            vec![o(501), o(502), o(503), o(503), o(504), o(505)],
        );
        let mut wide_read_hit: Vec<ObjectRef> = (1..=64).map(|id| o(10_000 + id)).collect();
        wide_read_hit.push(o(504));
        let wide_read_miss: Vec<ObjectRef> = (1..=64).map(|id| o(20_000 + id)).collect();

        assert!(detect_conflict(&small_write, &tx(2, wide_read_hit, vec![])));
        assert!(!detect_conflict(
            &small_write,
            &tx(3, wide_read_miss, vec![])
        ));
    }

    #[test]
    fn medium_small_vs_very_large_conflict_path_preserves_semantics() {
        let small_write = tx(1, vec![], vec![o(901), o(902), o(903), o(904), o(905)]);
        let mut very_wide_read_hit: Vec<ObjectRef> = (1..=256).map(|id| o(30_000 + id)).collect();
        very_wide_read_hit.push(o(904));
        let very_wide_read_miss: Vec<ObjectRef> = (1..=256).map(|id| o(40_000 + id)).collect();

        assert!(detect_conflict(
            &small_write,
            &tx(2, very_wide_read_hit, vec![])
        ));
        assert!(!detect_conflict(
            &small_write,
            &tx(3, very_wide_read_miss, vec![])
        ));
    }

    #[test]
    fn dedup_access_keys_large_path_preserves_first_seen_order() {
        let keys = dedup_access_keys(&[
            o(100),
            o(200),
            o(100),
            o(300),
            o(400),
            o(300),
            o(500),
            o(600),
            o(700),
            o(600),
        ]);

        assert_eq!(keys, vec![100, 200, 300, 400, 500, 600, 700]);
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
            tx(1, vec![], vec![o(7)]),    // group 0
            tx(3, vec![], vec![o(7)]),    // forced to group 1 (conflicts with tx1)
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
            tx(501, vec![], vec![o(5)]),  // bucket 5 when TRNM_HOT_BUCKETS=8
            tx(101, vec![], vec![o(0)]),  // bucket 0
            tx(102, vec![], vec![o(8)]),  // bucket 0
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
    fn hot_bucket_interleave_prefers_sparse_non_empty_bucket_under_heavy_skew() {
        let mut txs = vec![
            tx(201, vec![], vec![o(0)]),  // hot bucket (depth 3)
            tx(202, vec![], vec![o(8)]),  // same hot bucket
            tx(203, vec![], vec![o(16)]), // same hot bucket
            tx(204, vec![], vec![o(3)]),  // sparse bucket (depth 1)
        ];

        reorder_for_strategy(&mut txs, GroupingStrategy::HotBucketInterleave);
        assert_eq!(txs.first().map(|t| t.id), Some(204));
    }

    #[test]
    fn hot_bucket_interleave_prefers_a_sparse_bucket_under_moderate_two_to_one_skew() {
        let mut txs = vec![
            tx(301, vec![], vec![o(0)]), // hot bucket (depth 2)
            tx(302, vec![], vec![o(8)]), // same hot bucket
            tx(303, vec![], vec![o(3)]), // sparse bucket A (depth 1)
            tx(304, vec![], vec![o(5)]), // sparse bucket B (depth 1); keeps len >= 4
        ];

        reorder_for_strategy(&mut txs, GroupingStrategy::HotBucketInterleave);
        assert!(matches!(txs.first().map(|t| t.id), Some(303 | 304)));
    }

    #[test]
    fn hot_bucket_interleave_keeps_first_hint_when_skew_is_below_two_to_one_threshold() {
        let mut txs = vec![
            tx(391, vec![], vec![o(0)]),  // first hot hint bucket 0
            tx(392, vec![], vec![o(8)]),  // same bucket (depth 3)
            tx(393, vec![], vec![o(16)]), // same bucket (depth 3)
            tx(394, vec![], vec![o(1)]),  // second bucket (depth 2)
            tx(395, vec![], vec![o(9)]),  // second bucket (depth 2)
        ];

        reorder_for_strategy(&mut txs, GroupingStrategy::HotBucketInterleave);
        // Sparse anti-starvation seeding should only engage at >=2x skew. For 3:2,
        // keep first-hot-hint ordering and deterministic pass rotation from bucket 0.
        assert_eq!(
            txs.iter().map(|t| t.id).collect::<Vec<_>>(),
            vec![391, 393, 392, 395, 394]
        );
    }

    #[test]
    fn hot_bucket_interleave_sparse_tie_rotates_from_first_hot_hint() {
        let mut txs = vec![
            tx(401, vec![], vec![o(5)]),  // first hot hint bucket 5
            tx(402, vec![], vec![o(13)]), // same hot bucket (depth 2)
            tx(403, vec![], vec![o(1)]),  // sparse bucket 1
            tx(404, vec![], vec![o(6)]),  // sparse bucket 6
        ];

        reorder_for_strategy(&mut txs, GroupingStrategy::HotBucketInterleave);
        // Both bucket 1 and 6 are equally sparse; prefer the one nearest the first
        // hot-key hint to avoid fixed low-index sparse bias across batches.
        assert_eq!(txs.first().map(|t| t.id), Some(404));
    }

    #[test]
    fn hot_bucket_interleave_sparse_tie_prefers_nearest_bucket_across_ring_wrap() {
        let mut txs = vec![
            tx(411, vec![], vec![o(0)]), // first hot hint bucket 0
            tx(412, vec![], vec![o(8)]), // same hot bucket (depth 2)
            tx(413, vec![], vec![o(1)]), // sparse bucket +1 clockwise
            tx(414, vec![], vec![o(7)]), // sparse bucket -1 counter-clockwise
        ];

        reorder_for_strategy(&mut txs, GroupingStrategy::HotBucketInterleave);
        // When sparse buckets straddle the ring boundary, prefer the truly nearest
        // bucket instead of always scanning clockwise from the first hint.
        assert_eq!(txs.first().map(|t| t.id), Some(414));
    }

    #[test]
    fn hot_bucket_interleave_keeps_first_hint_when_it_is_already_sparse_seed() {
        let mut txs = vec![
            tx(421, vec![], vec![o(5)]),  // first hot hint bucket 5 (also sparse)
            tx(422, vec![], vec![o(0)]),  // dominant bucket 0 depth 4
            tx(423, vec![], vec![o(8)]),  // dominant bucket 0 depth 4
            tx(424, vec![], vec![o(16)]), // dominant bucket 0 depth 4
            tx(425, vec![], vec![o(24)]), // dominant bucket 0 depth 4
            tx(426, vec![], vec![o(6)]),  // equally sparse bucket 6 depth 1
            tx(427, vec![], vec![o(1)]),  // sparse bucket 1 depth 1
            tx(428, vec![], vec![o(2)]),  // sparse bucket 2 depth 1
        ];

        reorder_for_strategy(&mut txs, GroupingStrategy::HotBucketInterleave);
        // Keep len >= default bucket fanout (8) so object ids map directly to buckets.
        // If the first-hot hint already points at one of the sparsest buckets,
        // keep that bucket as the anti-starvation seed (distance 0) instead of
        // rotating away to a neighboring sparse lane.
        assert_eq!(txs.first().map(|t| t.id), Some(421));
    }

    #[test]
    fn hot_bucket_interleave_skips_micro_batches_to_preserve_low_latency_order() {
        let mut txs = vec![
            tx(21, vec![], vec![o(8)]),
            tx(22, vec![], vec![o(1)]),
            tx(23, vec![], vec![o(16)]),
        ];

        reorder_for_strategy(&mut txs, GroupingStrategy::HotBucketInterleave);
        assert_eq!(
            txs.iter().map(|t| t.id).collect::<Vec<_>>(),
            vec![21, 22, 23]
        );
    }

    #[test]
    fn hot_bucket_interleave_short_circuits_empty_access_batches() {
        let mut txs = vec![
            tx(31, vec![], vec![]),
            tx(32, vec![], vec![]),
            tx(33, vec![], vec![]),
            tx(34, vec![], vec![]),
        ];

        reorder_for_strategy(&mut txs, GroupingStrategy::HotBucketInterleave);
        // Empty-access free-ingress has no conflict-domain signal; keep stable
        // order and avoid bucket allocation/probing overhead.
        assert_eq!(
            txs.iter().map(|t| t.id).collect::<Vec<_>>(),
            vec![31, 32, 33, 34]
        );
    }

    #[test]
    fn hot_bucket_interleave_short_circuits_single_bucket_hotspot() {
        let mut txs = vec![
            tx(61, vec![], vec![o(8)]),
            tx(62, vec![], vec![o(16)]),
            tx(63, vec![], vec![o(24)]),
            tx(64, vec![], vec![o(32)]),
        ];

        reorder_for_strategy(&mut txs, GroupingStrategy::HotBucketInterleave);
        // All keys map to bucket 0 under the default 8-bucket layout; interleave
        // is a no-op and should return early without extra round-robin passes.
        assert_eq!(
            txs.iter().map(|t| t.id).collect::<Vec<_>>(),
            vec![61, 62, 63, 64]
        );
    }

    #[test]
    fn hot_bucket_interleave_short_circuits_all_singleton_buckets() {
        let mut txs = vec![
            tx(71, vec![], vec![o(0)]),
            tx(72, vec![], vec![o(1)]),
            tx(73, vec![], vec![o(2)]),
            tx(74, vec![], vec![o(3)]),
        ];

        reorder_for_strategy(&mut txs, GroupingStrategy::HotBucketInterleave);
        // With singleton occupancy across non-empty buckets there are no same-key
        // streaks to break; keep ingress order and avoid extra round-robin probing.
        assert_eq!(
            txs.iter().map(|t| t.id).collect::<Vec<_>>(),
            vec![71, 72, 73, 74]
        );
    }

    #[test]
    fn hot_bucket_hint_uses_full_u64_keyspace_before_bucket_reduce() {
        let buckets_n = 97usize;
        let low = tx(1, vec![], vec![o(1)]);
        let high = tx(2, vec![], vec![o(1 + (1u64 << 40))]);

        let low_bucket = hot_bucket_hint(&low, buckets_n);
        let high_bucket = hot_bucket_hint(&high, buckets_n);

        // Distinct high bits must influence bucket selection; truncating to usize
        // before modulo would collapse these on 32-bit targets.
        assert_ne!(low_bucket, high_bucket);
        assert_eq!(
            high_bucket,
            ((1 + (1u64 << 40)) % buckets_n as u64) as usize
        );
    }

    #[test]
    fn hot_bucket_hint_power_of_two_fast_path_matches_modulo_mapping() {
        let txs = [
            tx(1, vec![], vec![o(1)]),
            tx(2, vec![], vec![o(1 + (1u64 << 40))]),
            tx(3, vec![o(7)], vec![]),
            tx(4, vec![o(11), o(13)], vec![]),
            tx(5, vec![], vec![o(23), o(29)]),
        ];
        let buckets_n = 8usize;

        for t in txs {
            let expected = ((t
                .write_set
                .first()
                .or_else(|| t.read_set.first())
                .map(|o| o.id)
                .unwrap_or(0)
                ^ t.write_set
                    .get(1)
                    .or_else(|| t.read_set.get(1))
                    .map(|o| o.id)
                    .unwrap_or(0)
                    .rotate_left(7))
                % buckets_n as u64) as usize;
            assert_eq!(hot_bucket_hint(&t, buckets_n), expected);
        }
    }

    #[test]
    fn hot_bucket_hint_zero_bucket_count_fails_closed_to_bucket_zero() {
        let t = tx(999, vec![], vec![o(42)]);
        assert_eq!(hot_bucket_hint(&t, 0), 0);
    }

    #[test]
    fn aggressive_round_robin_seed_rotates_initial_probe_start() {
        let _env = env_lock();
        let _deep = EnvGuard::set("TRNM_AGGR_DEEP_SCAN", "1");
        let _rr = EnvGuard::set("TRNM_AGGR_SCAN_ROUND_ROBIN", "1");
        let _window = EnvGuard::set("TRNM_AGGR_SCAN_WINDOW", "1");
        let _seed = EnvGuard::set("TRNM_AGGR_SCAN_RR_SEED", "1");

        let txs = vec![
            tx(1, vec![], vec![o(7)]),    // group 0
            tx(3, vec![], vec![o(7)]),    // forced to group 1
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
    fn aggressive_skip_empty_stage_checks_keeps_conflict_check_metric_at_zero_for_empty_access() {
        let _env = env_lock();
        let _deep = EnvGuard::set("TRNM_AGGR_DEEP_SCAN", "1");
        let _rr = EnvGuard::set("TRNM_AGGR_SCAN_ROUND_ROBIN", "0");
        let _window = EnvGuard::set("TRNM_AGGR_SCAN_WINDOW", "2");
        let _skip_empty = EnvGuard::set("TRNM_AGGR_SKIP_EMPTY_STAGE_CHECKS", "1");

        let txs = vec![
            tx(1, vec![], vec![o(7)]), // group 0
            tx(3, vec![], vec![o(7)]), // forced to group 1
            tx(10, vec![], vec![]),    // empty access set, should not execute stage probes
        ];

        let (_groups, profile) =
            build_parallel_groups_profile_with_strategy(&txs, GroupingStrategy::AggressiveGreedy);

        assert_eq!(profile.stage_ww_checks, 0);
        assert_eq!(profile.stage_wr_checks, 0);
        assert_eq!(profile.stage_rw_checks, 0);
        assert_eq!(profile.conflict_checks, 0);
        assert_eq!(profile.conflict_hits, 0);
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
    fn aggressive_scan_window_ignores_zero_and_separator_only_values() {
        let _env = env_lock();

        let _zero = EnvGuard::set("TRNM_AGGR_SCAN_WINDOW", "0");
        assert_eq!(aggr_scan_window(), 0);
        drop(_zero);

        let _underscores = EnvGuard::set("TRNM_AGGR_SCAN_WINDOW", "__,,__");
        assert_eq!(aggr_scan_window(), 0);
    }

    #[test]
    fn aggressive_round_robin_seed_parses_trimmed_numeric_env_values() {
        let _env = env_lock();
        let _seed = EnvGuard::set("TRNM_AGGR_SCAN_RR_SEED", " 7 ");

        assert_eq!(aggr_scan_round_robin_seed(), 7);
    }

    #[test]
    fn integer_env_parsers_accept_underscored_numeric_values() {
        let _env = env_lock();
        let _window = EnvGuard::set("TRNM_AGGR_SCAN_WINDOW", "1_024");
        let _seed = EnvGuard::set("TRNM_AGGR_SCAN_RR_SEED", "9_001");
        let _buckets = EnvGuard::set("TRNM_HOT_BUCKETS", "3_2");

        assert_eq!(aggr_scan_window(), 1024);
        assert_eq!(aggr_scan_round_robin_seed(), 9001);
        assert_eq!(hot_bucket_count(), 32);
    }

    #[test]
    fn aggressive_round_robin_toggle_parser_handles_trimmed_false_and_true_tokens() {
        let _env = env_lock();

        let _off = EnvGuard::set("TRNM_AGGR_SCAN_ROUND_ROBIN", " OFF ");
        assert!(!aggr_scan_round_robin_enabled());
        drop(_off);

        let _yes = EnvGuard::set("TRNM_AGGR_SCAN_ROUND_ROBIN", " yes ");
        assert!(aggr_scan_round_robin_enabled());
    }

    #[test]
    fn aggressive_round_robin_toggle_parser_accepts_quoted_tokens() {
        let _env = env_lock();

        let _off = EnvGuard::set("TRNM_AGGR_SCAN_ROUND_ROBIN", " \"off\" ");
        assert!(!aggr_scan_round_robin_enabled());
        drop(_off);

        let _on = EnvGuard::set("TRNM_AGGR_SCAN_ROUND_ROBIN", " \"on\" ");
        assert!(aggr_scan_round_robin_enabled());
    }

    #[test]
    fn aggressive_round_robin_toggle_parser_accepts_single_quoted_tokens() {
        let _env = env_lock();

        let _off = EnvGuard::set("TRNM_AGGR_SCAN_ROUND_ROBIN", " 'off' ");
        assert!(!aggr_scan_round_robin_enabled());
        drop(_off);

        let _on = EnvGuard::set("TRNM_AGGR_SCAN_ROUND_ROBIN", " 'on' ");
        assert!(aggr_scan_round_robin_enabled());
    }

    #[test]
    fn aggressive_toggle_parsers_accept_quoted_tokens_for_skip_empty_and_deep_scan() {
        let _env = env_lock();

        let _skip_off = EnvGuard::set("TRNM_AGGR_SKIP_EMPTY_STAGE_CHECKS", " \"off\" ");
        assert!(!aggr_skip_empty_stage_checks());
        drop(_skip_off);

        let _skip_on = EnvGuard::set("TRNM_AGGR_SKIP_EMPTY_STAGE_CHECKS", " 'on' ");
        assert!(aggr_skip_empty_stage_checks());
        drop(_skip_on);

        let _deep_off = EnvGuard::set("TRNM_AGGR_DEEP_SCAN", " 'off' ");
        assert!(!aggr_deep_scan_enabled());
        drop(_deep_off);

        let _deep_on = EnvGuard::set("TRNM_AGGR_DEEP_SCAN", " \"on\" ");
        assert!(aggr_deep_scan_enabled());
    }

    #[test]
    fn aggressive_toggle_parsers_fall_back_to_defaults_on_empty_or_separator_only_values() {
        let _env = env_lock();

        let _rr_empty = EnvGuard::set("TRNM_AGGR_SCAN_ROUND_ROBIN", "  ''  ");
        assert!(aggr_scan_round_robin_enabled());
        drop(_rr_empty);

        let _rr_separators = EnvGuard::set("TRNM_AGGR_SCAN_ROUND_ROBIN", " __,,__ ");
        assert!(aggr_scan_round_robin_enabled());
        drop(_rr_separators);

        let _deep_empty = EnvGuard::set("TRNM_AGGR_DEEP_SCAN", "  \"\"  ");
        assert!(!aggr_deep_scan_enabled());
        drop(_deep_empty);

        let _skip_separators = EnvGuard::set("TRNM_AGGR_SKIP_EMPTY_STAGE_CHECKS", " _,,_ ");
        assert!(aggr_skip_empty_stage_checks());
    }

    #[test]
    fn auto_threshold_env_parsers_accept_trimmed_numeric_values() {
        let _env = env_lock();
        let _streak = EnvGuard::set("TRNM_AUTO_HOT_STREAK_RATIO", " 0.35 ");
        let _margin = EnvGuard::set("TRNM_AUTO_REORDER_MIN_MARGIN", " 0.12 ");
        let _share = EnvGuard::set("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE", " 0.018 ");
        let _gain = EnvGuard::set("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE", " 0.03 ");

        assert!((auto_hot_streak_threshold() - 0.35).abs() < f64::EPSILON);
        assert!((auto_reorder_min_margin() - 0.12).abs() < f64::EPSILON);
        assert!((auto_reorder_min_hot_key_share() - 0.018).abs() < f64::EPSILON);
        assert!((auto_min_expected_gain_score() - 0.03).abs() < f64::EPSILON);
    }

    #[test]
    fn auto_threshold_env_parsers_accept_grouped_numeric_values() {
        let _env = env_lock();
        let _streak = EnvGuard::set("TRNM_AUTO_HOT_STREAK_RATIO", "0.2_5");
        let _margin = EnvGuard::set("TRNM_AUTO_REORDER_MIN_MARGIN", "0,1");
        let _share = EnvGuard::set("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE", "0.0_125");
        let _gain = EnvGuard::set("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE", "0,0_5");

        assert!((auto_hot_streak_threshold() - 0.25).abs() < f64::EPSILON);
        assert!((auto_reorder_min_margin() - 0.1).abs() < f64::EPSILON);
        assert!((auto_reorder_min_hot_key_share() - 0.0125).abs() < f64::EPSILON);
        assert!((auto_min_expected_gain_score() - 0.05).abs() < f64::EPSILON);
    }

    #[test]
    fn hot_bucket_count_parser_accepts_trimmed_numeric_values() {
        let _env = env_lock();
        let _buckets = EnvGuard::set("TRNM_HOT_BUCKETS", " 16 ");

        assert_eq!(hot_bucket_count(), 16);
    }

    #[test]
    fn hot_bucket_count_parser_accepts_grouped_numeric_values() {
        let _env = env_lock();
        let _underscored = EnvGuard::set("TRNM_HOT_BUCKETS", " 6_4 ");
        assert_eq!(hot_bucket_count(), 64);
        drop(_underscored);

        let _comma_grouped = EnvGuard::set("TRNM_HOT_BUCKETS", " 1,6 ");
        assert_eq!(hot_bucket_count(), 16);
    }

    #[test]
    fn hot_bucket_count_is_clamped_to_safe_bounds() {
        let _env = env_lock();

        let _low = EnvGuard::set("TRNM_HOT_BUCKETS", "0");
        assert_eq!(hot_bucket_count(), 4);
        drop(_low);

        let _high = EnvGuard::set("TRNM_HOT_BUCKETS", "999");
        assert_eq!(hot_bucket_count(), 64);
    }

    #[test]
    fn auto_adaptive_numeric_env_parser_accepts_quoted_values() {
        let _env = env_lock();

        let _window = EnvGuard::set("TRNM_AGGR_SCAN_WINDOW", "\"1_024\"");
        let _seed = EnvGuard::set("TRNM_AGGR_SCAN_RR_SEED", "'9_001'");
        let _streak = EnvGuard::set("TRNM_AUTO_HOT_STREAK_RATIO", "\"0.2_5\"");
        let _margin = EnvGuard::set("TRNM_AUTO_REORDER_MIN_MARGIN", "'0.1'");
        let _share = EnvGuard::set("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE", "\"0.0_125\"");
        let _gain = EnvGuard::set("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE", "'0.05'");
        let _buckets = EnvGuard::set("TRNM_HOT_BUCKETS", "\"1,6\"");
        let _min_batch = EnvGuard::set("TRNM_AUTO_MIN_BATCH_LEN", "'2_048'");
        let _sample_len = EnvGuard::set("TRNM_AUTO_SAMPLE_LEN", "\"1_024\"");

        assert_eq!(aggr_scan_window(), 1024);
        assert_eq!(aggr_scan_round_robin_seed(), 9001);
        assert_eq!(auto_hot_streak_threshold(), 0.25);
        assert_eq!(auto_reorder_min_margin(), 0.1);
        assert_eq!(auto_reorder_min_hot_key_share(), 0.0125);
        assert_eq!(auto_min_expected_gain_score(), 0.05);
        assert_eq!(hot_bucket_count(), 16);
        assert_eq!(auto_adaptive_min_batch_len(), 2048);
        assert_eq!(auto_adaptive_sample_len(5000), 1024);
    }

    #[test]
    fn auto_adaptive_numeric_env_parser_accepts_plus_prefixed_values() {
        let _env = env_lock();

        let _window = EnvGuard::set("TRNM_AGGR_SCAN_WINDOW", " +1_024 ");
        let _seed = EnvGuard::set("TRNM_AGGR_SCAN_RR_SEED", " '+9_001' ");
        let _streak = EnvGuard::set("TRNM_AUTO_HOT_STREAK_RATIO", " +0.2_5 ");
        let _margin = EnvGuard::set("TRNM_AUTO_REORDER_MIN_MARGIN", " '+0.1' ");
        let _share = EnvGuard::set("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE", " +0.0_125 ");
        let _gain = EnvGuard::set("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE", " '+0.05' ");
        let _buckets = EnvGuard::set("TRNM_HOT_BUCKETS", " '+1,6' ");
        let _min_batch = EnvGuard::set("TRNM_AUTO_MIN_BATCH_LEN", " '+1_024' ");
        let _sample_len = EnvGuard::set("TRNM_AUTO_SAMPLE_LEN", " '+0' ");

        assert_eq!(aggr_scan_window(), 1024);
        assert_eq!(aggr_scan_round_robin_seed(), 9001);
        assert_eq!(auto_hot_streak_threshold(), 0.25);
        assert_eq!(auto_reorder_min_margin(), 0.1);
        assert_eq!(auto_reorder_min_hot_key_share(), 0.0125);
        assert_eq!(auto_min_expected_gain_score(), 0.05);
        assert_eq!(hot_bucket_count(), 16);
        assert_eq!(auto_adaptive_min_batch_len(), 1024);
        assert_eq!(auto_adaptive_sample_len(5000), 64);
    }

    #[test]
    fn auto_adaptive_numeric_env_parser_accepts_percent_suffix_for_ratio_knobs() {
        let _env = env_lock();

        let _streak = EnvGuard::set("TRNM_AUTO_HOT_STREAK_RATIO", "25%");
        let _margin = EnvGuard::set("TRNM_AUTO_REORDER_MIN_MARGIN", " 10% ");
        let _share = EnvGuard::set("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE", "'1.25%' ");
        let _gain = EnvGuard::set("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE", " \"5%\" ");

        assert_eq!(auto_hot_streak_threshold(), 0.25);
        assert_eq!(auto_reorder_min_margin(), 0.1);
        assert_eq!(auto_reorder_min_hot_key_share(), 0.0125);
        assert_eq!(auto_min_expected_gain_score(), 0.05);
    }

    #[test]
    fn auto_adaptive_numeric_env_parser_falls_back_to_defaults_on_invalid_values() {
        let _env = env_lock();

        let _window = EnvGuard::set("TRNM_AGGR_SCAN_WINDOW", "not-a-number");
        let _seed = EnvGuard::set("TRNM_AGGR_SCAN_RR_SEED", "seed??");
        let _streak = EnvGuard::set("TRNM_AUTO_HOT_STREAK_RATIO", "NaN%");
        let _margin = EnvGuard::set("TRNM_AUTO_REORDER_MIN_MARGIN", "margin");
        let _share = EnvGuard::set("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE", "share");
        let _gain = EnvGuard::set("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE", "gain");
        let _buckets = EnvGuard::set("TRNM_HOT_BUCKETS", "bucket-count");
        let _min_batch = EnvGuard::set("TRNM_AUTO_MIN_BATCH_LEN", "batch??");

        assert_eq!(aggr_scan_window(), 0);
        assert_eq!(aggr_scan_round_robin_seed(), 0);
        assert_eq!(auto_hot_streak_threshold(), 0.22);
        assert_eq!(auto_reorder_min_margin(), 0.04);
        assert_eq!(auto_reorder_min_hot_key_share(), 0.0075);
        assert_eq!(auto_min_expected_gain_score(), 0.01);
        assert_eq!(hot_bucket_count(), 8);
        assert_eq!(auto_adaptive_min_batch_len(), 512);
    }

    #[test]
    fn auto_adaptive_numeric_env_parser_ignores_empty_or_separator_only_values() {
        let _env = env_lock();

        let _window = EnvGuard::set("TRNM_AGGR_SCAN_WINDOW", "   ");
        let _seed = EnvGuard::set("TRNM_AGGR_SCAN_RR_SEED", "__,,__");
        let _streak = EnvGuard::set("TRNM_AUTO_HOT_STREAK_RATIO", " '' ");
        let _margin = EnvGuard::set("TRNM_AUTO_REORDER_MIN_MARGIN", " \"\" ");
        let _share = EnvGuard::set("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE", " _,_ ");
        let _gain = EnvGuard::set("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE", " '__,,__' ");
        let _buckets = EnvGuard::set("TRNM_HOT_BUCKETS", " \"_,,\" ");
        let _min_batch = EnvGuard::set("TRNM_AUTO_MIN_BATCH_LEN", " '__,,__' ");

        assert_eq!(aggr_scan_window(), 0);
        assert_eq!(aggr_scan_round_robin_seed(), 0);
        assert_eq!(auto_hot_streak_threshold(), 0.22);
        assert_eq!(auto_reorder_min_margin(), 0.04);
        assert_eq!(auto_reorder_min_hot_key_share(), 0.0075);
        assert_eq!(auto_min_expected_gain_score(), 0.01);
        assert_eq!(hot_bucket_count(), 8);
        assert_eq!(auto_adaptive_min_batch_len(), 512);
    }

    #[test]
    fn auto_adaptive_min_batch_len_is_clamped_to_safe_bounds() {
        let _env = env_lock();

        let _low = EnvGuard::set("TRNM_AUTO_MIN_BATCH_LEN", "8");
        assert_eq!(auto_adaptive_min_batch_len(), 64);
        drop(_low);

        let _high = EnvGuard::set("TRNM_AUTO_MIN_BATCH_LEN", "99999");
        assert_eq!(auto_adaptive_min_batch_len(), 4096);
    }

    #[test]
    fn auto_adaptive_sample_len_is_env_tunable_and_clamped() {
        let _env = env_lock();

        let _default = EnvGuard::set("TRNM_AUTO_SAMPLE_LEN", "batch??");
        assert_eq!(auto_adaptive_sample_len(5000), 2048);
        drop(_default);

        let _zero = EnvGuard::set("TRNM_AUTO_SAMPLE_LEN", "0");
        assert_eq!(auto_adaptive_sample_len(5000), 64);
        drop(_zero);

        let _low = EnvGuard::set("TRNM_AUTO_SAMPLE_LEN", "8");
        assert_eq!(auto_adaptive_sample_len(5000), 64);
        drop(_low);

        let _high = EnvGuard::set("TRNM_AUTO_SAMPLE_LEN", "99999");
        assert_eq!(auto_adaptive_sample_len(5000), 2048);
        drop(_high);

        let _trimmed = EnvGuard::set("TRNM_AUTO_SAMPLE_LEN", " '1_024' ");
        assert_eq!(auto_adaptive_sample_len(5000), 1024);
        assert_eq!(auto_adaptive_sample_len(256), 256);
    }

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
        assert!(d.use_hot_bucket, "env-tuned min batch should allow small-batch hotspot detection");
        assert_eq!(d.reason, "hotspot_detected");
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
        assert!(d.use_hot_bucket, "direct-scan path should see tail hotspot runs");
        assert_eq!(d.reason, "hotspot_detected");
    }

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
    fn free_ingress_batches_short_circuit_to_single_group_after_strategy_reorder() {
        let txs = vec![
            tx(9, vec![], vec![]),
            tx(3, vec![], vec![]),
            tx(7, vec![], vec![]),
        ];

        let (groups, profile) =
            build_parallel_groups_profile_with_strategy(&txs, GroupingStrategy::WriteFirst);

        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].len(), txs.len());
        // WriteFirst tie-breaks by tx id; fast path must preserve strategy reorder.
        assert_eq!(
            groups[0].iter().map(|t| t.id).collect::<Vec<_>>(),
            vec![3, 7, 9]
        );
        assert_eq!(profile.conflict_checks, 0);
        assert_eq!(profile.conflict_hits, 0);
        assert_eq!(profile.group_count, 1);
        assert_eq!(profile.max_group_size, txs.len());
        assert_eq!(profile.min_group_size, txs.len());
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
