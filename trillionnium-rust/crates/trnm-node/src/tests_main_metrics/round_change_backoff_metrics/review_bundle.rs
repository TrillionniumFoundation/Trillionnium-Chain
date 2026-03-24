use super::super::*;

#[test]
fn round_change_backoff_review_bundle_keeps_coverage_wall_and_budget_views_together() {
    let jitter_review_fields = [
        "bft_round_change_backoff_active_heights",
        "bft_round_change_backoff_active_height_rate_ppm",
        "bft_round_change_backoff_active_observed_height_rate_ppm",
        "bft_round_change_backoff_density_avg_milli",
        "bft_round_change_backoff_active_height_share_ppm",
        "bft_round_change_backoff_wall_share_ppm",
        "bft_round_change_backoff_share_ppm",
    ];

    assert_eq!(jitter_review_fields.len(), 7);
    assert!(jitter_review_fields[0].ends_with("_heights"));
    assert!(jitter_review_fields[1].ends_with("_rate_ppm"));
    assert!(jitter_review_fields[2].ends_with("_rate_ppm"));
    assert!(jitter_review_fields[3].ends_with("_avg_milli"));
    assert!(jitter_review_fields[4].ends_with("_share_ppm"));
    assert!(jitter_review_fields[5].ends_with("_share_ppm"));
    assert!(jitter_review_fields[6].ends_with("_share_ppm"));
    assert_ne!(jitter_review_fields[1], jitter_review_fields[2]);
    assert_ne!(jitter_review_fields[4], jitter_review_fields[5]);
    assert_ne!(jitter_review_fields[4], jitter_review_fields[6]);
    assert_ne!(jitter_review_fields[5], jitter_review_fields[6]);
}

#[test]
fn round_change_backoff_review_bundle_keeps_skipped_width_next_to_coverage_and_share_context() {
    let jitter_review_fields = [
        "bft_round_change_backoff_active_heights",
        "bft_round_change_backoff_active_height_rate_ppm",
        "bft_round_change_backoff_active_observed_height_rate_ppm",
        "bft_commit_observed_height_rate_ppm",
        "bft_skipped_height_total",
        "bft_skipped_observed_height_rate_ppm",
        "bft_round_change_backoff_density_avg_milli",
        "bft_round_change_backoff_active_height_share_ppm",
        "bft_round_change_backoff_wall_share_ppm",
        "bft_round_change_backoff_share_ppm",
    ];

    assert_eq!(jitter_review_fields.len(), 10);
    assert!(jitter_review_fields[0].ends_with("_active_heights"));
    assert!(jitter_review_fields[1].ends_with("_active_height_rate_ppm"));
    assert!(jitter_review_fields[2].ends_with("_active_observed_height_rate_ppm"));
    assert_eq!(
        jitter_review_fields[3],
        "bft_commit_observed_height_rate_ppm"
    );
    assert_eq!(jitter_review_fields[4], "bft_skipped_height_total");
    assert_eq!(
        jitter_review_fields[5],
        "bft_skipped_observed_height_rate_ppm"
    );
    assert!(jitter_review_fields[6].ends_with("_avg_milli"));
    assert!(jitter_review_fields[7].ends_with("_share_ppm"));
    assert!(jitter_review_fields[8].ends_with("_share_ppm"));
    assert!(jitter_review_fields[9].ends_with("_share_ppm"));
    assert_ne!(jitter_review_fields[1], jitter_review_fields[2]);
    assert_ne!(jitter_review_fields[3], jitter_review_fields[5]);
    assert_ne!(jitter_review_fields[7], jitter_review_fields[8]);
    assert_ne!(jitter_review_fields[7], jitter_review_fields[9]);
    assert_ne!(jitter_review_fields[8], jitter_review_fields[9]);
}

#[test]
fn round_change_backoff_review_bundle_keeps_budget_share_ahead_of_wall_time_aliases() {
    let jitter_review_fields = [
        "bft_round_change_backoff_active_observed_height_rate_ppm",
        "bft_commit_observed_height_rate_ppm",
        "bft_skipped_height_total",
        "bft_skipped_observed_height_rate_ppm",
        "bft_round_change_backoff_density_avg_milli",
        "bft_round_change_backoff_active_height_share_ppm",
        "bft_round_change_backoff_wall_share_ppm",
        "bft_round_change_backoff_share_ppm",
    ];

    assert_eq!(jitter_review_fields.len(), 8);
    assert!(jitter_review_fields[0].ends_with("_active_observed_height_rate_ppm"));
    assert_eq!(
        jitter_review_fields[1],
        "bft_commit_observed_height_rate_ppm"
    );
    assert_eq!(jitter_review_fields[2], "bft_skipped_height_total");
    assert_eq!(
        jitter_review_fields[3],
        "bft_skipped_observed_height_rate_ppm"
    );
    assert!(jitter_review_fields[4].ends_with("_avg_milli"));
    assert_eq!(
        jitter_review_fields[5],
        "bft_round_change_backoff_active_height_share_ppm"
    );
    assert_eq!(
        jitter_review_fields[6],
        "bft_round_change_backoff_wall_share_ppm"
    );
    assert_eq!(
        jitter_review_fields[7],
        "bft_round_change_backoff_share_ppm"
    );
    assert_ne!(jitter_review_fields[5], jitter_review_fields[6]);
    assert_ne!(jitter_review_fields[5], jitter_review_fields[7]);
    assert_ne!(jitter_review_fields[6], jitter_review_fields[7]);
}
