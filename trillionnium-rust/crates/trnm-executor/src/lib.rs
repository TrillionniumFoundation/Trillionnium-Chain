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
}

pub fn detect_conflict(a: &Tx, b: &Tx) -> bool {
    intersects(&a.write_set, &b.write_set)
        || intersects(&a.write_set, &b.read_set)
        || intersects(&a.read_set, &b.write_set)
}

#[inline]
fn access_key(obj: &ObjectRef) -> (u64, u64) {
    (obj.id, obj.version)
}

#[inline]
fn dedup_access_keys(objs: &[ObjectRef]) -> Vec<(u64, u64)> {
    // Small-set fast path avoids HashSet allocation for common tiny access lists.
    if objs.len() <= 8 {
        let mut out: Vec<(u64, u64)> = Vec::with_capacity(objs.len());
        for obj in objs {
            let key = access_key(obj);
            if !out.contains(&key) {
                out.push(key);
            }
        }
        return out;
    }

    let mut seen: HashSet<(u64, u64)> = HashSet::with_capacity(objs.len());
    let mut out: Vec<(u64, u64)> = Vec::with_capacity(objs.len());
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
    // Build a set from the smaller side to reduce comparisons.
    let (small, large) = if x.len() <= y.len() { (x, y) } else { (y, x) };
    let seen: HashSet<(u64, u64)> = small.iter().map(access_key).collect();
    large.iter().any(|obj| seen.contains(&access_key(obj)))
}

#[inline]
fn hashset_intersects(a: &HashSet<(u64, u64)>, b: &HashSet<(u64, u64)>) -> bool {
    if a.is_empty() || b.is_empty() {
        return false;
    }
    let (small, large) = if a.len() <= b.len() { (a, b) } else { (b, a) };
    small.iter().any(|k| large.contains(k))
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
    let mut selected = strategy;
    if matches!(selected, GroupingStrategy::AutoAdaptive) {
        selected = if should_use_hot_bucket_interleave(txs) {
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

    // Pre-size maps to reduce rehashing on large workloads.
    let map_cap = (txs.len() / 2).max(64);
    // object(id,version) -> latest group that has a writer touching this object
    let mut latest_writer_group: HashMap<(u64, u64), usize> = HashMap::with_capacity(map_cap);
    // object(id,version) -> latest group that has a reader touching this object
    let mut latest_reader_group: HashMap<(u64, u64), usize> = HashMap::with_capacity(map_cap);

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
        },
    )
}

fn build_parallel_groups_aggressive_profile(
    original_txs: &[Tx],
    ordered: Vec<Tx>,
) -> (Vec<Vec<Tx>>, GroupingProfile) {
    let mut groups: Vec<Vec<Tx>> = Vec::new();
    let mut group_read_keys: Vec<HashSet<(u64, u64)>> = Vec::new();
    let mut group_write_keys: Vec<HashSet<(u64, u64)>> = Vec::new();

    // Lower-bound index hints (same semantics as Original strategy):
    // a tx cannot be placed before the latest conflicting writer/reader + 1.
    let map_cap = (original_txs.len() / 2).max(64);
    let mut latest_writer_group: HashMap<(u64, u64), usize> = HashMap::with_capacity(map_cap);
    let mut latest_reader_group: HashMap<(u64, u64), usize> = HashMap::with_capacity(map_cap);

    let mut conflict_checks = 0usize;
    let mut conflict_hits = 0usize;

    for tx in ordered {
        let read_keys: HashSet<(u64, u64)> = tx.read_set.iter().map(access_key).collect();
        let write_keys: HashSet<(u64, u64)> = tx.write_set.iter().map(access_key).collect();

        // Compute a safe lower-bound to prune candidate groups.
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
        for idx in min_group..groups.len() {
            conflict_checks += 1;

            // Write-vs-write tends to be hottest; short-circuit early on conflict.
            if hashset_intersects(&write_keys, &group_write_keys[idx]) {
                conflict_hits += 1;
                continue;
            }
            // Then write-vs-read.
            if hashset_intersects(&write_keys, &group_read_keys[idx]) {
                conflict_hits += 1;
                continue;
            }
            // Finally read-vs-write.
            if hashset_intersects(&read_keys, &group_write_keys[idx]) {
                conflict_hits += 1;
                continue;
            }

            groups[idx].push(tx.clone());
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
            groups.push(vec![tx]);
            group_read_keys.push(read_keys.clone());
            group_write_keys.push(write_keys.clone());

            for key in &read_keys {
                latest_reader_group.insert(*key, idx);
            }
            for key in &write_keys {
                latest_writer_group.insert(*key, idx);
            }
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
        },
    )
}

fn should_use_hot_bucket_interleave(txs: &[Tx]) -> bool {
    if txs.len() < 512 {
        return false;
    }

    // Sample first window to estimate hot-key streak pressure.
    let sample_len = txs.len().min(2048);
    let mut same_key_streak_hits = 0usize;
    let mut total_pairs = 0usize;
    let mut prev_key: Option<u64> = None;

    for tx in txs.iter().take(sample_len) {
        let key = tx
            .write_set
            .first()
            .or_else(|| tx.read_set.first())
            .map(|o| o.id);
        if let Some(k) = key {
            if let Some(pk) = prev_key {
                total_pairs += 1;
                if pk == k {
                    same_key_streak_hits += 1;
                }
            }
            prev_key = Some(k);
        }
    }

    if total_pairs == 0 {
        return false;
    }

    let streak_ratio = same_key_streak_hits as f64 / total_pairs as f64;
    // Empirical heuristic: enable hot-bucket only when streak pressure is clearly present.
    streak_ratio >= 0.22
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
            txs.sort_by_key(|tx| (tx.write_set.len(), std::cmp::Reverse(tx.read_set.len()), tx.id));
        }
        GroupingStrategy::HotBucketInterleave => {
            // Heuristic reorder; see should_use_hot_bucket_interleave for adaptive trigger.
            // Heuristic: shard txs by a stable access-key hint, then round-robin buckets.
            // Goal is to avoid long same-key streaks in input order under hotspot workloads.
            const BUCKETS: usize = 16;
            let mut buckets: Vec<Vec<Tx>> = vec![Vec::new(); BUCKETS];

            for tx in txs.iter().cloned() {
                // Prefer write-set as stronger conflict signal; fold a second key when present
                // to reduce bucket skew for mixed workloads.
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
                let bucket = (key_a ^ key_b.rotate_left(7)) % BUCKETS;
                buckets[bucket].push(tx);
            }

            for b in &mut buckets {
                b.sort_by_key(|tx| tx.id);
            }

            // Stable round-robin with move semantics (avoid per-tx clone cost).
            let mut iters: Vec<std::vec::IntoIter<Tx>> =
                buckets.into_iter().map(|b| b.into_iter()).collect();
            let mut merged = Vec::with_capacity(txs.len());
            loop {
                let mut moved = false;
                for it in &mut iters {
                    if let Some(tx) = it.next() {
                        merged.push(tx);
                        moved = true;
                    }
                }
                if !moved {
                    break;
                }
            }

            txs.clone_from_slice(&merged);
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
    fn grouping_parallel_safe() {
        let g = build_parallel_groups(&[
            tx(1, vec![], vec![o(1)]),
            tx(2, vec![], vec![o(2)]),
            tx(3, vec![o(1)], vec![]),
        ]);
        assert_eq!(g.len(), 2);
        assert_eq!(g.iter().map(|x| x.len()).sum::<usize>(), 3);
        // first group can contain tx1+tx2 (non-conflict), tx3 should be separate
        assert!(g.iter().any(|grp| grp.iter().any(|t| t.id == 3) && grp.len() == 1));
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
}
