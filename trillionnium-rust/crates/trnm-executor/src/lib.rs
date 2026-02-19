use std::collections::HashMap;
use trnm_types::{ObjectRef, Tx};

#[derive(Debug, Clone, Copy)]
pub enum GroupingStrategy {
    Original,
    FootprintDesc,
    WriteFirst,
    WriteLast,
    HotBucketInterleave,
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

fn intersects(x: &[ObjectRef], y: &[ObjectRef]) -> bool {
    x.iter().any(|i| y.iter().any(|j| i == j))
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
    let mut ordered: Vec<Tx> = txs.to_vec();
    reorder_for_strategy(&mut ordered, strategy);

    let mut groups: Vec<Vec<Tx>> = Vec::new();

    // object -> latest group that has a writer touching this object
    let mut latest_writer_group: HashMap<ObjectRef, usize> = HashMap::new();
    // object -> latest group that has a reader touching this object
    let mut latest_reader_group: HashMap<ObjectRef, usize> = HashMap::new();

    // Profiling counters (lightweight approximation instead of pairwise O(n^2) scans)
    let mut conflict_checks = 0usize;
    let mut conflict_hits = 0usize;

    for tx in ordered.iter().cloned() {
        // minimal group index forced by previous conflicting accesses
        let mut required_group = 0usize;

        // read conflicts with previous writers on the same object
        for obj in &tx.read_set {
            conflict_checks += 1;
            if let Some(&g) = latest_writer_group.get(obj) {
                conflict_hits += 1;
                required_group = required_group.max(g + 1);
            }
        }

        // write conflicts with previous writers and readers on the same object
        for obj in &tx.write_set {
            conflict_checks += 1;
            if let Some(&g) = latest_writer_group.get(obj) {
                conflict_hits += 1;
                required_group = required_group.max(g + 1);
            }
            conflict_checks += 1;
            if let Some(&g) = latest_reader_group.get(obj) {
                conflict_hits += 1;
                required_group = required_group.max(g + 1);
            }
        }

        if groups.len() <= required_group {
            groups.resize_with(required_group + 1, Vec::new);
        }
        groups[required_group].push(tx.clone());

        for obj in &tx.read_set {
            latest_reader_group.insert(obj.clone(), required_group);
        }
        for obj in &tx.write_set {
            latest_writer_group.insert(obj.clone(), required_group);
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
            // Heuristic: shard txs by a stable "hot key" hint, then interleave buckets.
            // Goal is to avoid long same-key streaks in input order.
            const BUCKETS: usize = 16;
            let mut buckets: Vec<Vec<Tx>> = vec![Vec::new(); BUCKETS];
            for tx in txs.iter().cloned() {
                let key = tx
                    .write_set
                    .first()
                    .or_else(|| tx.read_set.first())
                    .map(|o| o.id as usize)
                    .unwrap_or(0);
                buckets[key % BUCKETS].push(tx);
            }
            for b in &mut buckets {
                b.sort_by_key(|tx| tx.id);
            }
            let mut merged = Vec::with_capacity(txs.len());
            loop {
                let mut moved = false;
                for b in &mut buckets {
                    if let Some(tx) = b.pop() {
                        merged.push(tx);
                        moved = true;
                    }
                }
                if !moved {
                    break;
                }
            }
            merged.reverse();
            txs.clone_from_slice(&merged);
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
        let c1: usize = g1.iter().map(|g| g.len()).sum();
        let c2: usize = g2.iter().map(|g| g.len()).sum();
        assert_eq!(c1, txs.len());
        assert_eq!(c2, txs.len());
    }
}
