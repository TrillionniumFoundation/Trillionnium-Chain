use super::*;

#[test]
fn round_change_guardrail_metrics_make_bft_jitter_visible() {
    let bft_round_change_total = 6u64;
    let bft_round_change_active_heights = 2u64;
    let bft_committed_heights = 4u64;
    let bft_round_change_backoff_total_ms = 18u64;
    let bft_round_change_backoff_max_ms = 8u64;

    assert_eq!(
        ratio_ppm_u64(bft_round_change_total, bft_committed_heights),
        1_500_000
    );
    assert_eq!(
        bft_round_change_backoff_total_ms / bft_round_change_total,
        3
    );
    assert_eq!(
        bft_round_change_backoff_total_ms / bft_round_change_active_heights,
        9
    );
    assert_eq!(
        ratio_milli_u64(
            bft_round_change_backoff_total_ms,
            bft_round_change_active_heights,
        ),
        9_000
    );
    assert_eq!(
        ratio_ppm_u64(bft_round_change_backoff_total_ms, bft_committed_heights),
        4_500_000
    );
    assert!(
        bft_round_change_backoff_max_ms
            > bft_round_change_backoff_total_ms / bft_round_change_total
    );
}

#[test]
fn consensus_summary_bursty_review_bundles_keep_active_height_counts_next_to_coverage_and_budget_views(
) {
    let review_bundles: &[&[&str]] = &[
        &[
            "critical_wait_active_heights",
            "critical_wait_active_height_rate_ppm",
            "critical_wait_active_observed_height_rate_ppm",
            "critical_wait_density_avg_milli",
            "critical_wait_active_height_share_ppm",
        ],
        &[
            "hot_object_active_heights",
            "hot_object_active_height_rate_ppm",
            "hot_object_active_observed_height_rate_ppm",
            "hot_object_active_top_label_share_avg_ppm",
            "hot_object_active_tail_share_avg_ppm",
            "hot_object_active_height_share_ppm",
        ],
        &[
            "rollback_active_heights",
            "rollback_active_height_rate_ppm",
            "rollback_active_observed_height_rate_ppm",
            "rollback_density_avg_milli",
            "rollback_active_height_share_ppm",
        ],
        &[
            "preexec_reject_active_heights",
            "preexec_reject_active_height_rate_ppm",
            "preexec_reject_active_observed_height_rate_ppm",
            "preexec_reject_density_avg_milli",
            "preexec_reject_active_height_share_ppm",
        ],
        &[
            "bft_round_change_active_heights",
            "bft_round_change_active_height_rate_ppm",
            "bft_round_change_active_observed_height_rate_ppm",
            "bft_round_change_density_avg_milli",
            "bft_round_change_active_height_share_ppm",
        ],
        &[
            "bft_round_change_backoff_active_heights",
            "bft_round_change_backoff_active_height_rate_ppm",
            "bft_round_change_backoff_active_observed_height_rate_ppm",
            "bft_round_change_backoff_density_avg_milli",
            "bft_round_change_backoff_active_height_share_ppm",
        ],
        &[
            "bft_leader_missed_active_heights",
            "bft_leader_missed_active_height_rate_ppm",
            "bft_leader_missed_active_observed_height_rate_ppm",
            "bft_leader_missed_density_avg_milli",
            "bft_leader_missed_active_height_share_ppm",
        ],
    ];

    for bundle in review_bundles {
        assert!(bundle[0].ends_with("_active_heights"));
        assert!(bundle[1].ends_with("_active_height_rate_ppm"));
        assert!(bundle[2].ends_with("_active_observed_height_rate_ppm"));
        assert_ne!(bundle[0], bundle[1]);
        assert_ne!(bundle[0], bundle[2]);
        assert_ne!(bundle[1], bundle[2]);
        assert!(
            bundle[3].ends_with("_avg_milli") || bundle[3].ends_with("_share_avg_ppm"),
            "expected density or active-share companion field, got {}",
            bundle[3]
        );
        assert!(bundle.last().unwrap().ends_with("_active_height_share_ppm"));
    }
}

#[test]
fn consensus_log_contract_keeps_round_change_density_milli_fields() {
    let field_name = "bft_round_change_density_avg_milli";
    let integer_avg_field_name = "bft_round_change_density_avg";
    let active_share_field_name = "bft_round_change_active_height_share_ppm";
    let backoff_field_name = "bft_round_change_backoff_density_avg_milli";
    let backoff_integer_avg_field_name = "bft_round_change_backoff_density_avg_ms";
    let backoff_active_share_field_name = "bft_round_change_backoff_active_height_share_ppm";

    assert!(field_name.ends_with("_avg_milli"));
    assert!(active_share_field_name.ends_with("_share_ppm"));
    assert!(backoff_field_name.ends_with("_avg_milli"));
    assert!(backoff_integer_avg_field_name.ends_with("_avg_ms"));
    assert!(backoff_active_share_field_name.ends_with("_share_ppm"));
    assert_ne!(field_name, integer_avg_field_name);
    assert_ne!(active_share_field_name, field_name);
    assert_ne!(backoff_field_name, backoff_integer_avg_field_name);
    assert_ne!(backoff_active_share_field_name, backoff_field_name);
}

#[test]
fn active_height_budget_share_metrics_can_exceed_one_million_when_jitter_or_fairness_dominates_finality(
) {
    let finality_avg = 2u128;
    let round_change_density_avg_milli = 3_000u64;
    let round_change_backoff_density_avg_milli = 4_500u64;
    let leader_missed_density_avg_milli = 2_500u64;

    let round_change_active_height_share_ppm =
        finality_budget_share_ppm(round_change_density_avg_milli, finality_avg);
    let round_change_backoff_active_height_share_ppm =
        finality_budget_share_ppm(round_change_backoff_density_avg_milli, finality_avg);
    let leader_missed_active_height_share_ppm =
        finality_budget_share_ppm(leader_missed_density_avg_milli, finality_avg);

    assert_eq!(round_change_active_height_share_ppm, 1_500_000);
    assert_eq!(round_change_backoff_active_height_share_ppm, 2_250_000);
    assert_eq!(leader_missed_active_height_share_ppm, 1_250_000);
    assert!(round_change_active_height_share_ppm > 1_000_000);
    assert!(round_change_backoff_active_height_share_ppm > 1_000_000);
    assert!(leader_missed_active_height_share_ppm > 1_000_000);
}
