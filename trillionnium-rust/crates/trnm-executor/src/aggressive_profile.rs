use std::collections::{HashMap, HashSet};

use trnm_types::Tx;

use crate::conflict::{
    access_map_capacity_hint, dedup_access_keys, hot_object_share, vec_hashset_intersects,
};
use crate::env_config::{
    aggr_deep_scan_enabled, aggr_scan_round_robin_enabled, aggr_scan_round_robin_seed,
    aggr_scan_window, aggr_skip_empty_stage_checks,
};
use crate::GroupingProfile;

pub(crate) fn build_parallel_groups_aggressive_profile(
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
                retry_fallback_new_groups: 0,
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
    let mut retry_fallback_new_groups = 0usize;
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
            if candidate_span > 0 {
                retry_fallback_new_groups += 1;
            }
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
            retry_fallback_new_groups,
            stage_ww_checks,
            stage_ww_hits,
            stage_wr_checks,
            stage_wr_hits,
            stage_rw_checks,
            stage_rw_hits,
        },
    )
}
