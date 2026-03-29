use super::*;

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
fn same_object_different_versions_land_in_separate_groups() {
    let txs = vec![
        Tx {
            id: 1,
            read_set: vec![ObjectRef { id: 55, version: 1 }],
            write_set: vec![],
            payload: vec![],
        },
        Tx {
            id: 2,
            read_set: vec![],
            write_set: vec![ObjectRef { id: 55, version: 2 }],
            payload: vec![],
        },
    ];

    let groups = build_parallel_groups(&txs);
    assert_eq!(groups.len(), 2);
    assert_eq!(groups[0][0].id, 1);
    assert_eq!(groups[1][0].id, 2);
}

#[test]
fn object_zero_different_versions_land_in_separate_groups() {
    let txs = vec![
        Tx {
            id: 10,
            read_set: vec![ObjectRef { id: 0, version: 1 }],
            write_set: vec![],
            payload: vec![],
        },
        Tx {
            id: 11,
            read_set: vec![],
            write_set: vec![ObjectRef { id: 0, version: 2 }],
            payload: vec![],
        },
    ];

    // Object id 0 is a real execution-domain key, not a sentinel. Mixed-domain
    // version skew on object 0 must still force separate groups.
    let groups = build_parallel_groups(&txs);
    assert_eq!(groups.len(), 2);
    assert_eq!(groups[0][0].id, 10);
    assert_eq!(groups[1][0].id, 11);
}

#[test]
fn read_only_same_object_different_versions_share_one_group() {
    let txs = vec![
        Tx {
            id: 1,
            read_set: vec![ObjectRef { id: 55, version: 1 }],
            write_set: vec![],
            payload: vec![],
        },
        Tx {
            id: 2,
            read_set: vec![ObjectRef { id: 55, version: 2 }],
            write_set: vec![],
            payload: vec![],
        },
    ];

    let groups = build_parallel_groups(&txs);
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].iter().map(|tx| tx.id).collect::<Vec<_>>(), vec![1, 2]);
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
    let (g3, _) = build_parallel_groups_profile_with_strategy(&txs, GroupingStrategy::AutoAdaptive);
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

#[test]
fn aggressive_fast_path_matches_original_when_deep_scan_is_disabled() {
    let _env = env_lock();
    let _deep = EnvGuard::set("TRNM_AGGR_DEEP_SCAN", "0");

    let txs = vec![
        tx(1, vec![], vec![o(10)]),
        tx(2, vec![o(10)], vec![]),
        tx(3, vec![o(30)], vec![o(40)]),
        tx(4, vec![o(40)], vec![]),
        tx(5, vec![], vec![]),
        tx(6, vec![o(90)], vec![o(91)]),
    ];

    let (original_groups, original_profile) =
        build_parallel_groups_profile_with_strategy(&txs, GroupingStrategy::Original);
    let (aggressive_groups, aggressive_profile) =
        build_parallel_groups_profile_with_strategy(&txs, GroupingStrategy::AggressiveGreedy);

    let original_ids: Vec<Vec<u64>> = original_groups
        .iter()
        .map(|group| group.iter().map(|tx| tx.id).collect())
        .collect();
    let aggressive_ids: Vec<Vec<u64>> = aggressive_groups
        .iter()
        .map(|group| group.iter().map(|tx| tx.id).collect())
        .collect();

    assert_eq!(aggressive_ids, original_ids);
    assert_eq!(aggressive_profile.group_count, original_profile.group_count);
    assert_eq!(
        aggressive_profile.grouped_count,
        original_profile.grouped_count
    );
    assert_eq!(
        aggressive_profile.max_group_size,
        original_profile.max_group_size
    );
    assert_eq!(
        aggressive_profile.min_group_size,
        original_profile.min_group_size
    );
    assert_eq!(
        aggressive_profile.conflict_checks,
        original_profile.conflict_checks
    );
    assert_eq!(
        aggressive_profile.conflict_hits,
        original_profile.conflict_hits
    );
    assert_eq!(aggressive_profile.candidate_groups_scanned, 0);
    assert_eq!(aggressive_profile.stage_ww_checks, 0);
    assert_eq!(aggressive_profile.stage_wr_checks, 0);
    assert_eq!(aggressive_profile.stage_rw_checks, 0);
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
#[should_panic(expected = "mixed access domain contains the same object id with multiple versions")]
fn write_first_grouping_rejects_mixed_domain_version_skew() {
    let txs = vec![tx(9, vec![ov(77, 1)], vec![ov(77, 2)])];
    let _ = build_parallel_groups_profile_with_strategy(&txs, GroupingStrategy::WriteFirst);
}

#[test]
#[should_panic(expected = "mixed access domain contains the same object id with multiple versions")]
fn write_last_grouping_rejects_mixed_domain_version_skew() {
    let txs = vec![tx(9, vec![ov(77, 1)], vec![ov(77, 2)])];
    let _ = build_parallel_groups_profile_with_strategy(&txs, GroupingStrategy::WriteLast);
}

#[test]
fn grouping_profile_retry_metrics_stay_zero_fail_closed_on_empty_denominators() {
    let profile = GroupingProfile {
        tx_count: 0,
        group_count: 0,
        grouped_count: 0,
        max_group_size: 0,
        min_group_size: 0,
        avg_group_size: 0.0,
        hot_object_share: 0.0,
        conflict_checks: 0,
        conflict_hits: 3,
        candidate_groups_scanned: 7,
        stage_ww_checks: 0,
        stage_ww_hits: 0,
        stage_wr_checks: 0,
        stage_wr_hits: 0,
        stage_rw_checks: 0,
        stage_rw_hits: 0,
    };

    assert_eq!(profile.conflict_checks_per_tx(), 0.0);
    assert_eq!(profile.conflict_hits_per_tx(), 0.0);
    assert_eq!(profile.candidate_groups_per_tx(), 0.0);
    assert_eq!(profile.retry_pressure(), 0.0);
    assert_eq!(profile.retry_fallback_share_of_new_groups(), 0.0);
    assert_eq!(profile.retry_fallback_scan_share(), 0.0);
    assert_eq!(profile.reused_group_placements(), 0);
    assert_eq!(profile.reused_group_share(), 0.0);
    assert_eq!(profile.new_group_share(), 0.0);
    assert_eq!(profile.candidate_groups_per_retry_hit(), 0.0);
    assert_eq!(profile.candidate_groups_per_reused_placement(), 0.0);
    assert_eq!(profile.retry_scan_hit_rate(), 0.0);
    assert_eq!(profile.retry_scan_misses(), 4);
    assert_eq!(profile.retry_scan_miss_rate(), 4.0 / 7.0);
    assert_eq!(profile.retry_scan_reuse_rate(), 0.0);
    assert_eq!(profile.retry_scan_misses_per_tx(), 0.0);
    assert_eq!(profile.retry_scan_misses_per_group(), 0.0);
    assert!((profile.retry_scan_overhang_per_hit() - (4.0 / 3.0)).abs() < f64::EPSILON);
    assert_eq!(profile.retry_scan_overhang_per_reused_placement(), 0.0);
    assert_eq!(profile.ww_retry_hit_rate(), 0.0);
    assert_eq!(profile.wr_retry_hit_rate(), 0.0);
    assert_eq!(profile.rw_retry_hit_rate(), 0.0);
    assert_eq!(profile.ww_retry_share(), 0.0);
    assert_eq!(profile.wr_retry_share(), 0.0);
    assert_eq!(profile.rw_retry_share(), 0.0);
    assert_eq!(profile.dominant_retry_stage(), "none");
    assert_eq!(profile.dominant_retry_share(), 0.0);
    assert_eq!(profile.dominant_attributed_retry_share(), 0.0);
    assert_eq!(profile.dominant_retry_lead_hits(), 0);
    assert_eq!(profile.dominant_retry_lead_share(), 0.0);
    assert_eq!(profile.attributed_retry_hits(), 0);
    assert_eq!(profile.unattributed_retry_hits(), 3);
    assert_eq!(profile.unattributed_retry_share(), 1.0);
    assert_eq!(profile.retry_attribution_coverage(), 0.0);
    assert_eq!(profile.retry_stage_overlap_hits(), 0);
    assert_eq!(profile.retry_stage_overlap_share(), 0.0);
    assert_eq!(profile.retry_stage_overlap_share_of_attributed(), 0.0);
    assert_eq!(profile.retry_stage_mix_entropy(), 0.0);
}

#[test]
fn grouping_profile_retry_metrics_prefer_heaviest_retry_stage() {
    let profile = GroupingProfile {
        tx_count: 8,
        group_count: 2,
        grouped_count: 8,
        max_group_size: 4,
        min_group_size: 4,
        avg_group_size: 4.0,
        hot_object_share: 0.5,
        conflict_checks: 12,
        conflict_hits: 6,
        candidate_groups_scanned: 10,
        stage_ww_checks: 3,
        stage_ww_hits: 1,
        stage_wr_checks: 5,
        stage_wr_hits: 4,
        stage_rw_checks: 4,
        stage_rw_hits: 2,
    };

    assert!((profile.conflict_checks_per_tx() - 1.5).abs() < f64::EPSILON);
    assert!((profile.conflict_hits_per_tx() - 0.75).abs() < f64::EPSILON);
    assert!((profile.candidate_groups_per_tx() - 1.25).abs() < f64::EPSILON);
    assert!((profile.retry_pressure() - 3.0).abs() < f64::EPSILON);
    assert_eq!(profile.retry_fallback_share_of_new_groups(), 0.0);
    assert_eq!(profile.retry_fallback_scan_share(), 0.0);
    assert_eq!(profile.reused_group_placements(), 6);
    assert!((profile.reused_group_share() - 0.75).abs() < f64::EPSILON);
    assert!((profile.new_group_share() - 0.25).abs() < f64::EPSILON);
    assert!((profile.candidate_groups_per_retry_hit() - (10.0 / 6.0)).abs() < f64::EPSILON);
    assert!((profile.candidate_groups_per_reused_placement() - (10.0 / 6.0)).abs() < f64::EPSILON);
    assert!((profile.retry_scan_hit_rate() - 0.6).abs() < f64::EPSILON);
    assert_eq!(profile.retry_scan_misses(), 4);
    assert!((profile.retry_scan_miss_rate() - 0.4).abs() < f64::EPSILON);
    assert!((profile.retry_scan_misses_per_tx() - 0.5).abs() < f64::EPSILON);
    assert!((profile.retry_scan_misses_per_group() - 2.0).abs() < f64::EPSILON);
    assert!((profile.retry_scan_overhang_per_hit() - (4.0 / 6.0)).abs() < f64::EPSILON);
    assert!((profile.retry_scan_overhang_per_reused_placement() - (4.0 / 6.0)).abs() < f64::EPSILON);
    assert!((profile.ww_retry_hit_rate() - (1.0 / 3.0)).abs() < f64::EPSILON);
    assert!((profile.wr_retry_hit_rate() - 0.8).abs() < f64::EPSILON);
    assert!((profile.rw_retry_hit_rate() - 0.5).abs() < f64::EPSILON);
    assert!((profile.ww_retry_share() - (1.0 / 6.0)).abs() < f64::EPSILON);
    assert!((profile.wr_retry_share() - (4.0 / 6.0)).abs() < f64::EPSILON);
    assert!((profile.rw_retry_share() - (2.0 / 6.0)).abs() < f64::EPSILON);
    assert_eq!(profile.dominant_retry_stage(), "wr");
    assert!((profile.dominant_retry_share() - (4.0 / 6.0)).abs() < f64::EPSILON);
    assert!((profile.dominant_attributed_retry_share() - (4.0 / 7.0)).abs() < f64::EPSILON);
    assert_eq!(profile.dominant_retry_lead_hits(), 2);
    assert!((profile.dominant_retry_lead_share() - (2.0 / 6.0)).abs() < f64::EPSILON);
    assert_eq!(profile.attributed_retry_hits(), 7);
    assert_eq!(profile.unattributed_retry_hits(), 0);
    assert_eq!(profile.unattributed_retry_share(), 0.0);
    assert_eq!(profile.retry_attribution_coverage(), 1.0);
    assert_eq!(profile.retry_stage_overlap_hits(), 1);
    assert!((profile.retry_stage_overlap_share() - (1.0 / 6.0)).abs() < f64::EPSILON);
    assert!((profile.retry_stage_overlap_share_of_attributed() - (1.0 / 7.0)).abs() < f64::EPSILON);
    assert!((profile.retry_stage_mix_entropy() - 0.8699155297736259).abs() < 1e-12);
}

#[test]
fn grouping_profile_retry_metrics_report_mixed_when_retry_stage_ties() {
    let profile = GroupingProfile {
        tx_count: 8,
        group_count: 2,
        grouped_count: 8,
        max_group_size: 4,
        min_group_size: 4,
        avg_group_size: 4.0,
        hot_object_share: 0.5,
        conflict_checks: 12,
        conflict_hits: 6,
        candidate_groups_scanned: 10,
        stage_ww_checks: 4,
        stage_ww_hits: 3,
        stage_wr_checks: 5,
        stage_wr_hits: 3,
        stage_rw_checks: 3,
        stage_rw_hits: 1,
    };

    assert!((profile.ww_retry_hit_rate() - 0.75).abs() < f64::EPSILON);
    assert!((profile.wr_retry_hit_rate() - 0.6).abs() < f64::EPSILON);
    assert!((profile.rw_retry_hit_rate() - (1.0 / 3.0)).abs() < f64::EPSILON);
    assert!((profile.ww_retry_share() - 0.5).abs() < f64::EPSILON);
    assert!((profile.wr_retry_share() - 0.5).abs() < f64::EPSILON);
    assert!((profile.rw_retry_share() - (1.0 / 6.0)).abs() < f64::EPSILON);
    assert_eq!(profile.dominant_retry_stage(), "mixed");
    assert!((profile.dominant_retry_share() - 0.5).abs() < f64::EPSILON);
    assert_eq!(profile.dominant_retry_lead_hits(), 0);
    assert_eq!(profile.dominant_retry_lead_share(), 0.0);
    assert_eq!(profile.unattributed_retry_hits(), 0);
    assert_eq!(profile.unattributed_retry_share(), 0.0);
    assert_eq!(profile.retry_attribution_coverage(), 1.0);
    assert!((profile.retry_stage_overlap_share() - (1.0 / 6.0)).abs() < f64::EPSILON);
    assert!((profile.retry_stage_overlap_share_of_attributed() - (1.0 / 7.0)).abs() < f64::EPSILON);
    assert!((profile.retry_stage_mix_entropy() - 0.914100892018565).abs() < 1e-12);
}

#[test]
fn candidate_groups_per_reused_placement_tracks_speculative_retry_cost() {
    let profile = GroupingProfile {
        tx_count: 8,
        group_count: 3,
        grouped_count: 8,
        max_group_size: 3,
        min_group_size: 2,
        avg_group_size: 8.0 / 3.0,
        hot_object_share: 0.5,
        conflict_checks: 10,
        conflict_hits: 2,
        candidate_groups_scanned: 10,
        retry_fallback_new_groups: 1,
        stage_ww_checks: 3,
        stage_ww_hits: 1,
        stage_wr_checks: 4,
        stage_wr_hits: 1,
        stage_rw_checks: 3,
        stage_rw_hits: 0,
    };

    assert_eq!(profile.reused_group_placements(), 5);
    assert!((profile.candidate_groups_per_retry_hit() - 5.0).abs() < f64::EPSILON);
    assert!((profile.candidate_groups_per_reused_placement() - 2.0).abs() < f64::EPSILON);
    assert!((profile.retry_fallback_scan_share() - 0.1).abs() < f64::EPSILON);
    assert!((profile.retry_scan_reuse_rate() - 0.5).abs() < f64::EPSILON);
    assert!((profile.retry_scan_overhang_per_reused_placement() - 1.6).abs() < f64::EPSILON);
    assert!((profile.retry_fallback_share_of_new_groups() - (1.0 / 3.0)).abs() < f64::EPSILON);
}

#[test]
fn retry_fallback_share_of_retry_misses_fails_closed_without_scan_misses() {
    let profile = GroupingProfile {
        tx_count: 6,
        group_count: 2,
        grouped_count: 6,
        max_group_size: 3,
        min_group_size: 3,
        avg_group_size: 3.0,
        hot_object_share: 0.5,
        conflict_checks: 4,
        conflict_hits: 4,
        candidate_groups_scanned: 4,
        retry_fallback_new_groups: 2,
        stage_ww_checks: 2,
        stage_ww_hits: 2,
        stage_wr_checks: 2,
        stage_wr_hits: 2,
        stage_rw_checks: 0,
        stage_rw_hits: 0,
    };

    assert_eq!(profile.retry_scan_misses(), 0);
    assert_eq!(profile.retry_scan_miss_rate(), 0.0);
    assert_eq!(profile.retry_fallback_share_of_retry_misses(), 0.0);
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
