use super::super::*;

#[test]
fn leader_missed_review_bundle_keeps_validator_spread_next_to_height_pressure_fields() {
    let fairness_review_fields = [
        "bft_leader_missed_top_share_ppm",
        "bft_leader_missed_active_validators",
        "bft_leader_missed_active_validator_share_ppm",
        "bft_leader_missed_active_heights",
        "bft_leader_missed_active_height_rate_ppm",
        "bft_leader_missed_active_observed_height_rate_ppm",
        "bft_leader_missed_density_avg_milli",
        "bft_leader_missed_active_height_share_ppm",
    ];

    assert_eq!(fairness_review_fields.len(), 8);
    assert!(fairness_review_fields[0].ends_with("_share_ppm"));
    assert!(fairness_review_fields[1].ends_with("_validators"));
    assert!(fairness_review_fields[2].ends_with("_share_ppm"));
    assert!(fairness_review_fields[3].ends_with("_active_heights"));
    assert!(fairness_review_fields[4].ends_with("_active_height_rate_ppm"));
    assert!(fairness_review_fields[5].ends_with("_active_observed_height_rate_ppm"));
    assert!(fairness_review_fields[6].ends_with("_avg_milli"));
    assert!(fairness_review_fields[7].ends_with("_active_height_share_ppm"));
    assert_ne!(fairness_review_fields[0], fairness_review_fields[2]);
    assert_ne!(fairness_review_fields[2], fairness_review_fields[7]);
    assert_ne!(fairness_review_fields[4], fairness_review_fields[5]);
}

#[test]
fn leader_missed_review_bundle_keeps_commit_vs_skipped_coverage_context_near_fairness_pressure() {
    let fairness_review_fields = [
        "bft_leader_missed_top_share_ppm",
        "bft_leader_missed_active_validators",
        "bft_leader_missed_active_validator_share_ppm",
        "bft_leader_missed_active_heights",
        "bft_leader_missed_active_height_rate_ppm",
        "bft_leader_missed_active_observed_height_rate_ppm",
        "bft_commit_observed_height_rate_ppm",
        "bft_skipped_observed_height_rate_ppm",
        "bft_leader_missed_density_avg_milli",
        "bft_leader_missed_active_height_share_ppm",
    ];

    assert_eq!(fairness_review_fields.len(), 10);
    assert!(fairness_review_fields[0].ends_with("_share_ppm"));
    assert!(fairness_review_fields[1].ends_with("_validators"));
    assert!(fairness_review_fields[2].ends_with("_share_ppm"));
    assert!(fairness_review_fields[3].ends_with("_active_heights"));
    assert!(fairness_review_fields[4].ends_with("_active_height_rate_ppm"));
    assert!(fairness_review_fields[5].ends_with("_active_observed_height_rate_ppm"));
    assert_eq!(
        fairness_review_fields[6],
        "bft_commit_observed_height_rate_ppm"
    );
    assert_eq!(
        fairness_review_fields[7],
        "bft_skipped_observed_height_rate_ppm"
    );
    assert!(fairness_review_fields[8].ends_with("_avg_milli"));
    assert!(fairness_review_fields[9].ends_with("_active_height_share_ppm"));
    assert_ne!(fairness_review_fields[4], fairness_review_fields[5]);
    assert_ne!(fairness_review_fields[6], fairness_review_fields[7]);
}

#[test]
fn leader_missed_review_bundle_keeps_absolute_skipped_width_next_to_fairness_spread_and_budget_pressure(
) {
    let fairness_review_fields = [
        "bft_leader_missed_top_share_ppm",
        "bft_leader_missed_active_validators",
        "bft_leader_missed_active_validator_share_ppm",
        "bft_leader_missed_active_heights",
        "bft_leader_missed_active_height_rate_ppm",
        "bft_leader_missed_active_observed_height_rate_ppm",
        "bft_commit_observed_height_rate_ppm",
        "bft_skipped_height_total",
        "bft_skipped_observed_height_rate_ppm",
        "bft_leader_missed_density_avg_milli",
        "bft_leader_missed_active_height_share_ppm",
    ];

    assert_eq!(fairness_review_fields.len(), 11);
    assert!(fairness_review_fields[0].ends_with("_share_ppm"));
    assert!(fairness_review_fields[1].ends_with("_validators"));
    assert!(fairness_review_fields[2].ends_with("_share_ppm"));
    assert!(fairness_review_fields[3].ends_with("_active_heights"));
    assert!(fairness_review_fields[4].ends_with("_active_height_rate_ppm"));
    assert!(fairness_review_fields[5].ends_with("_active_observed_height_rate_ppm"));
    assert_eq!(
        fairness_review_fields[6],
        "bft_commit_observed_height_rate_ppm"
    );
    assert_eq!(fairness_review_fields[7], "bft_skipped_height_total");
    assert_eq!(
        fairness_review_fields[8],
        "bft_skipped_observed_height_rate_ppm"
    );
    assert!(fairness_review_fields[9].ends_with("_avg_milli"));
    assert!(fairness_review_fields[10].ends_with("_active_height_share_ppm"));
    assert_ne!(fairness_review_fields[4], fairness_review_fields[5]);
    assert_ne!(fairness_review_fields[6], fairness_review_fields[8]);
    assert_ne!(fairness_review_fields[7], fairness_review_fields[8]);
}

#[test]
fn leader_missed_review_bundle_keeps_skipped_width_between_commit_coverage_and_skip_rate() {
    let fairness_review_fields = [
        "bft_leader_missed_top_share_ppm",
        "bft_leader_missed_active_validators",
        "bft_leader_missed_active_validator_share_ppm",
        "bft_leader_missed_active_heights",
        "bft_leader_missed_active_height_rate_ppm",
        "bft_leader_missed_active_observed_height_rate_ppm",
        "bft_commit_observed_height_rate_ppm",
        "bft_skipped_height_total",
        "bft_skipped_observed_height_rate_ppm",
        "bft_leader_missed_density_avg_milli",
        "bft_leader_missed_active_height_share_ppm",
    ];

    let commit_idx = fairness_review_fields
        .iter()
        .position(|field| *field == "bft_commit_observed_height_rate_ppm")
        .expect("commit coverage field present");
    let skipped_total_idx = fairness_review_fields
        .iter()
        .position(|field| *field == "bft_skipped_height_total")
        .expect("skipped width field present");
    let skipped_rate_idx = fairness_review_fields
        .iter()
        .position(|field| *field == "bft_skipped_observed_height_rate_ppm")
        .expect("skipped coverage field present");
    let density_idx = fairness_review_fields
        .iter()
        .position(|field| *field == "bft_leader_missed_density_avg_milli")
        .expect("density field present");
    let share_idx = fairness_review_fields
        .iter()
        .position(|field| *field == "bft_leader_missed_active_height_share_ppm")
        .expect("budget share field present");

    assert_eq!(skipped_total_idx, commit_idx + 1);
    assert_eq!(skipped_rate_idx, skipped_total_idx + 1);
    assert!(density_idx > skipped_rate_idx);
    assert!(share_idx > density_idx);
}

#[test]
fn leader_missed_review_bundle_keeps_validator_spread_coverage_and_budget_views_together() {
    let fairness_review_fields = [
        "bft_leader_missed_top_share_ppm",
        "bft_leader_missed_active_validators",
        "bft_leader_missed_active_validator_share_ppm",
        "bft_leader_missed_active_heights",
        "bft_leader_missed_active_height_rate_ppm",
        "bft_leader_missed_active_observed_height_rate_ppm",
        "bft_leader_missed_density_avg_milli",
        "bft_leader_missed_active_height_share_ppm",
    ];

    assert_eq!(fairness_review_fields.len(), 8);
    assert!(fairness_review_fields[0].ends_with("_share_ppm"));
    assert!(fairness_review_fields[1].ends_with("_validators"));
    assert!(fairness_review_fields[2].ends_with("_share_ppm"));
    assert!(fairness_review_fields[3].ends_with("_heights"));
    assert!(fairness_review_fields[4].ends_with("_rate_ppm"));
    assert!(fairness_review_fields[5].ends_with("_rate_ppm"));
    assert!(fairness_review_fields[6].ends_with("_avg_milli"));
    assert!(fairness_review_fields[7].ends_with("_share_ppm"));
    assert_ne!(fairness_review_fields[2], fairness_review_fields[7]);
    assert_ne!(fairness_review_fields[4], fairness_review_fields[5]);
}

#[test]
fn leader_missed_review_bundle_keeps_commit_skip_coverage_pair_near_fairness_hotspots() {
    let fairness_review_fields = [
        "bft_leader_missed_active_height_rate_ppm",
        "bft_leader_missed_active_observed_height_rate_ppm",
        "bft_commit_observed_height_rate_ppm",
        "bft_skipped_height_total",
        "bft_skipped_observed_height_rate_ppm",
        "bft_leader_missed_density_avg_milli",
        "bft_leader_missed_active_height_share_ppm",
    ];

    assert_eq!(fairness_review_fields.len(), 7);
    assert!(fairness_review_fields[0].ends_with("_rate_ppm"));
    assert!(fairness_review_fields[1].ends_with("_rate_ppm"));
    assert!(fairness_review_fields[2].ends_with("_rate_ppm"));
    assert!(fairness_review_fields[3].ends_with("_total"));
    assert!(fairness_review_fields[4].ends_with("_rate_ppm"));
    assert!(fairness_review_fields[5].ends_with("_avg_milli"));
    assert!(fairness_review_fields[6].ends_with("_share_ppm"));
    assert_ne!(fairness_review_fields[0], fairness_review_fields[1]);
    assert_ne!(fairness_review_fields[1], fairness_review_fields[2]);
    assert_ne!(fairness_review_fields[2], fairness_review_fields[4]);
    assert_ne!(fairness_review_fields[5], fairness_review_fields[6]);
}
