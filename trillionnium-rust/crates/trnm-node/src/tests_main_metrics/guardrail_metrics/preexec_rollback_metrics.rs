use super::*;

#[test]
fn guardrail_review_bundles_keep_cause_fields_next_to_coverage_and_budget_pressure() {
    let review_bundles: &[&[&str]] = &[
        &[
            "preexec_reject_active_heights",
            "preexec_reject_active_height_rate_ppm",
            "preexec_reject_active_observed_height_rate_ppm",
            "bft_commit_observed_height_rate_ppm",
            "bft_skipped_height_total",
            "bft_skipped_observed_height_rate_ppm",
            "preexec_reject_density_avg_milli",
            "preexec_reject_active_height_share_ppm",
            "preexec_reject_share_bps",
            "preexec_conflict_miss_share_bps",
        ],
        &[
            "rollback_active_heights",
            "rollback_active_height_rate_ppm",
            "rollback_active_observed_height_rate_ppm",
            "bft_commit_observed_height_rate_ppm",
            "bft_skipped_height_total",
            "bft_skipped_observed_height_rate_ppm",
            "rollback_density_avg_milli",
            "rollback_active_height_share_ppm",
            "apply_error_rollback_share_bps",
        ],
    ];

    assert_eq!(review_bundles.len(), 2);
    for bundle in review_bundles {
        assert!(bundle[0].ends_with("_active_heights"));
        assert!(bundle[1].ends_with("_active_height_rate_ppm"));
        assert!(bundle[2].ends_with("_active_observed_height_rate_ppm"));
        assert_eq!(bundle[3], "bft_commit_observed_height_rate_ppm");
        assert_eq!(bundle[4], "bft_skipped_height_total");
        assert_eq!(bundle[5], "bft_skipped_observed_height_rate_ppm");
        assert!(bundle[6].ends_with("_avg_milli"));
        assert!(bundle[7].ends_with("_active_height_share_ppm"));
        assert!(bundle.last().unwrap().ends_with("_share_bps"));
    }
    assert_eq!(
        review_bundles[0].last().copied(),
        Some("preexec_conflict_miss_share_bps")
    );
    assert_eq!(
        review_bundles[1].last().copied(),
        Some("apply_error_rollback_share_bps")
    );
}

#[test]
fn fairness_and_guardrail_review_bundles_keep_skipped_width_adjacent_to_skip_rate() {
    let review_bundles: &[&[&str]] = &[
        &[
            "critical_wait_active_height_rate_ppm",
            "critical_wait_active_observed_height_rate_ppm",
            "bft_commit_observed_height_rate_ppm",
            "bft_skipped_height_total",
            "bft_skipped_observed_height_rate_ppm",
            "critical_wait_density_avg_milli",
            "critical_wait_active_height_share_ppm",
        ],
        &[
            "preexec_reject_active_height_rate_ppm",
            "preexec_reject_active_observed_height_rate_ppm",
            "bft_commit_observed_height_rate_ppm",
            "bft_skipped_height_total",
            "bft_skipped_observed_height_rate_ppm",
            "preexec_reject_density_avg_milli",
            "preexec_reject_active_height_share_ppm",
            "preexec_reject_share_bps",
            "preexec_conflict_miss_share_bps",
        ],
        &[
            "rollback_active_height_rate_ppm",
            "rollback_active_observed_height_rate_ppm",
            "bft_commit_observed_height_rate_ppm",
            "bft_skipped_height_total",
            "bft_skipped_observed_height_rate_ppm",
            "rollback_density_avg_milli",
            "rollback_active_height_share_ppm",
            "apply_error_rollback_share_bps",
        ],
        &[
            "bft_round_change_active_height_rate_ppm",
            "bft_round_change_active_observed_height_rate_ppm",
            "bft_commit_observed_height_rate_ppm",
            "bft_skipped_height_total",
            "bft_skipped_observed_height_rate_ppm",
            "bft_round_change_active_height_share_ppm",
        ],
        &[
            "bft_round_change_backoff_active_height_rate_ppm",
            "bft_round_change_backoff_active_observed_height_rate_ppm",
            "bft_commit_observed_height_rate_ppm",
            "bft_skipped_height_total",
            "bft_skipped_observed_height_rate_ppm",
            "bft_round_change_backoff_active_height_share_ppm",
        ],
        &[
            "bft_leader_missed_active_height_rate_ppm",
            "bft_leader_missed_active_observed_height_rate_ppm",
            "bft_commit_observed_height_rate_ppm",
            "bft_skipped_height_total",
            "bft_skipped_observed_height_rate_ppm",
            "bft_leader_missed_density_avg_milli",
            "bft_leader_missed_active_height_share_ppm",
        ],
    ];

    assert_eq!(review_bundles.len(), 6);
    for bundle in review_bundles {
        let skipped_total_idx = bundle
            .iter()
            .position(|field| *field == "bft_skipped_height_total")
            .expect("skipped total must stay present in review bundle");
        let skipped_rate_idx = bundle
            .iter()
            .position(|field| *field == "bft_skipped_observed_height_rate_ppm")
            .expect("skipped observed rate must stay present in review bundle");

        assert_eq!(skipped_rate_idx, skipped_total_idx + 1);
        assert_eq!(
            bundle[skipped_total_idx - 1],
            "bft_commit_observed_height_rate_ppm"
        );
        assert!(bundle[0].ends_with("_active_height_rate_ppm"));
        assert!(bundle[1].ends_with("_active_observed_height_rate_ppm"));
        assert_ne!(bundle[0], bundle[1]);
        assert_ne!(bundle[skipped_total_idx], bundle[skipped_rate_idx]);
    }
}
