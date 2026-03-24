use super::*;

#[test]
fn consensus_summary_guardrail_field_list_keeps_active_height_and_observed_coverage_views() {
    let observed_coverage_fields = [
        "critical_wait_active_observed_height_rate_ppm",
        "hot_object_active_observed_height_rate_ppm",
        "preexec_reject_active_observed_height_rate_ppm",
        "rollback_active_observed_height_rate_ppm",
        "bft_round_change_active_observed_height_rate_ppm",
        "bft_round_change_backoff_active_observed_height_rate_ppm",
        "bft_leader_missed_active_observed_height_rate_ppm",
    ];
    let active_budget_share_fields = [
        "critical_wait_active_height_share_ppm",
        "hot_object_active_height_share_ppm",
        "preexec_reject_active_height_share_ppm",
        "rollback_active_height_share_ppm",
        "bft_round_change_active_height_share_ppm",
        "bft_round_change_backoff_active_height_share_ppm",
        "bft_leader_missed_active_height_share_ppm",
    ];

    assert_eq!(observed_coverage_fields.len(), 7);
    assert_eq!(active_budget_share_fields.len(), 7);
    assert!(observed_coverage_fields
        .iter()
        .all(|field| field.ends_with("_rate_ppm")));
    assert!(active_budget_share_fields
        .iter()
        .all(|field| field.ends_with("_share_ppm")));
    for observed_field in observed_coverage_fields {
        assert!(
            !active_budget_share_fields.contains(&observed_field),
            "observed coverage field should stay distinct: {observed_field}"
        );
    }
}

#[test]
fn consensus_summary_backoff_field_list_keeps_wall_alias_separate_from_budget_share_fields() {
    let backoff_fields = [
        "bft_round_change_backoff_active_height_share_ppm",
        "bft_round_change_backoff_wall_share_ppm",
        "bft_round_change_backoff_share_ppm",
    ];

    assert_eq!(backoff_fields.len(), 3);
    assert!(backoff_fields
        .iter()
        .all(|field| field.ends_with("_share_ppm")));
    assert_ne!(backoff_fields[0], backoff_fields[1]);
    assert_ne!(backoff_fields[0], backoff_fields[2]);
    assert_ne!(backoff_fields[1], backoff_fields[2]);
}

#[test]
fn consensus_bursty_review_bundles_keep_commit_vs_observed_coverage_pair_near_active_height_rates()
{
    let review_bundles: &[&[&str]] = &[
        &[
            "hot_object_active_heights",
            "hot_object_active_height_rate_ppm",
            "hot_object_active_observed_height_rate_ppm",
            "bft_commit_observed_height_rate_ppm",
            "bft_skipped_observed_height_rate_ppm",
            "hot_object_active_height_share_ppm",
        ],
        &[
            "bft_round_change_active_heights",
            "bft_round_change_active_height_rate_ppm",
            "bft_round_change_active_observed_height_rate_ppm",
            "bft_commit_observed_height_rate_ppm",
            "bft_skipped_observed_height_rate_ppm",
            "bft_round_change_active_height_share_ppm",
        ],
        &[
            "bft_round_change_backoff_active_heights",
            "bft_round_change_backoff_active_height_rate_ppm",
            "bft_round_change_backoff_active_observed_height_rate_ppm",
            "bft_commit_observed_height_rate_ppm",
            "bft_skipped_observed_height_rate_ppm",
            "bft_round_change_backoff_active_height_share_ppm",
        ],
        &[
            "bft_leader_missed_active_heights",
            "bft_leader_missed_active_height_rate_ppm",
            "bft_leader_missed_active_observed_height_rate_ppm",
            "bft_commit_observed_height_rate_ppm",
            "bft_skipped_observed_height_rate_ppm",
            "bft_leader_missed_active_height_share_ppm",
        ],
    ];

    assert_eq!(review_bundles.len(), 4);
    for bundle in review_bundles {
        assert!(bundle[0].ends_with("_active_heights"));
        assert!(bundle[1].ends_with("_active_height_rate_ppm"));
        assert!(bundle[2].ends_with("_active_observed_height_rate_ppm"));
        assert_eq!(bundle[3], "bft_commit_observed_height_rate_ppm");
        assert_eq!(bundle[4], "bft_skipped_observed_height_rate_ppm");
        assert!(bundle[5].ends_with("_active_height_share_ppm"));
        assert_ne!(bundle[1], bundle[2]);
        assert_ne!(bundle[3], bundle[4]);
    }
}

#[test]
fn consensus_bursty_review_bundles_keep_absolute_skipped_height_width_next_to_observed_coverage_rates(
) {
    let review_bundles: &[&[&str]] = &[
        &[
            "critical_wait_active_height_rate_ppm",
            "critical_wait_active_observed_height_rate_ppm",
            "bft_commit_observed_height_rate_ppm",
            "bft_skipped_height_total",
            "bft_skipped_observed_height_rate_ppm",
        ],
        &[
            "hot_object_active_height_rate_ppm",
            "hot_object_active_observed_height_rate_ppm",
            "bft_commit_observed_height_rate_ppm",
            "bft_skipped_height_total",
            "bft_skipped_observed_height_rate_ppm",
        ],
        &[
            "preexec_reject_active_height_rate_ppm",
            "preexec_reject_active_observed_height_rate_ppm",
            "bft_commit_observed_height_rate_ppm",
            "bft_skipped_height_total",
            "bft_skipped_observed_height_rate_ppm",
        ],
        &[
            "rollback_active_height_rate_ppm",
            "rollback_active_observed_height_rate_ppm",
            "bft_commit_observed_height_rate_ppm",
            "bft_skipped_height_total",
            "bft_skipped_observed_height_rate_ppm",
        ],
        &[
            "bft_round_change_active_height_rate_ppm",
            "bft_round_change_active_observed_height_rate_ppm",
            "bft_commit_observed_height_rate_ppm",
            "bft_skipped_height_total",
            "bft_skipped_observed_height_rate_ppm",
        ],
        &[
            "bft_round_change_backoff_active_height_rate_ppm",
            "bft_round_change_backoff_active_observed_height_rate_ppm",
            "bft_commit_observed_height_rate_ppm",
            "bft_skipped_height_total",
            "bft_skipped_observed_height_rate_ppm",
        ],
        &[
            "bft_leader_missed_active_height_rate_ppm",
            "bft_leader_missed_active_observed_height_rate_ppm",
            "bft_commit_observed_height_rate_ppm",
            "bft_skipped_height_total",
            "bft_skipped_observed_height_rate_ppm",
        ],
    ];

    assert_eq!(review_bundles.len(), 7);
    for bundle in review_bundles {
        assert!(bundle[0].ends_with("_active_height_rate_ppm"));
        assert!(bundle[1].ends_with("_active_observed_height_rate_ppm"));
        assert_eq!(bundle[2], "bft_commit_observed_height_rate_ppm");
        assert_eq!(bundle[3], "bft_skipped_height_total");
        assert_eq!(bundle[4], "bft_skipped_observed_height_rate_ppm");
        assert_ne!(bundle[0], bundle[1]);
        assert_ne!(bundle[2], bundle[4]);
    }
}
