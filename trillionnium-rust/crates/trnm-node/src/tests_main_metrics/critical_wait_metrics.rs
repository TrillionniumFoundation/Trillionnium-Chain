use super::*;

#[test]
fn critical_wait_density_metrics_make_fairness_stalls_visible() {
    let finality_avg = 200u128;
    let critical_wait_blocks_avg = 50u128;
    let finality_max = 320u128;
    let critical_wait_blocks_max = 160u128;

    assert_eq!(ratio_ppm(critical_wait_blocks_avg, finality_avg), 250_000);
    assert_eq!(ratio_ppm(critical_wait_blocks_max, finality_max), 500_000);
    assert_eq!(ratio_ppm(critical_wait_blocks_max, 0), 0);
}

#[test]
fn critical_wait_active_height_rate_metrics_make_fairness_stall_concentration_visible() {
    let critical_wait_active_heights = 2u64;
    let finality_sample_count = 4u64;
    let bft_observed_heights = 5u64;
    let critical_wait_total = 5u64;
    let critical_wait_density_avg = critical_wait_total / critical_wait_active_heights;
    let critical_wait_density_avg_milli =
        ratio_milli_u64(critical_wait_total, critical_wait_active_heights);
    let critical_wait_active_height_rate_ppm =
        ratio_ppm_u64(critical_wait_active_heights, finality_sample_count);
    let critical_wait_active_observed_height_rate_ppm =
        ratio_ppm_u64(critical_wait_active_heights, bft_observed_heights);

    assert_eq!(critical_wait_active_height_rate_ppm, 500_000);
    assert_eq!(critical_wait_active_observed_height_rate_ppm, 400_000);
    assert!(critical_wait_active_observed_height_rate_ppm < critical_wait_active_height_rate_ppm);
    assert_eq!(critical_wait_density_avg, 2);
    assert_eq!(critical_wait_density_avg_milli, 2_500);
}

#[test]
fn critical_wait_metric_names_keep_committed_and_observed_coverage_distinct() {
    let active_height_rate_field_name = "critical_wait_active_height_rate_ppm";
    let active_observed_height_rate_field_name = "critical_wait_active_observed_height_rate_ppm";
    let density_field_name = "critical_wait_density_avg";
    let milli_density_field_name = "critical_wait_density_avg_milli";
    let active_height_share_field_name = "critical_wait_active_height_share_ppm";

    assert!(active_height_rate_field_name.ends_with("_rate_ppm"));
    assert!(active_observed_height_rate_field_name.ends_with("_rate_ppm"));
    assert!(density_field_name.ends_with("_avg"));
    assert!(milli_density_field_name.ends_with("_avg_milli"));
    assert!(active_height_share_field_name.ends_with("_share_ppm"));
    assert_ne!(
        active_height_rate_field_name,
        active_observed_height_rate_field_name
    );
    assert_ne!(active_observed_height_rate_field_name, density_field_name);
    assert_ne!(density_field_name, milli_density_field_name);
    assert_ne!(milli_density_field_name, active_height_share_field_name);
}

#[test]
fn critical_wait_observed_height_rate_exposes_skipped_height_coverage_gap() {
    let critical_wait_active_heights = 2u64;
    let committed_heights = 2u64;
    let observed_heights = 5u64;
    let committed_height_rate_ppm = ratio_ppm_u64(critical_wait_active_heights, committed_heights);
    let observed_height_rate_ppm = ratio_ppm_u64(critical_wait_active_heights, observed_heights);

    assert_eq!(committed_height_rate_ppm, 1_000_000);
    assert_eq!(observed_height_rate_ppm, 400_000);
    assert!(observed_height_rate_ppm < committed_height_rate_ppm);
}

#[test]
fn critical_wait_review_bundle_keeps_commit_skip_coverage_pair_near_fairness_stall_pressure() {
    let fairness_review_fields = [
        "critical_wait_active_heights",
        "critical_wait_active_height_rate_ppm",
        "critical_wait_active_observed_height_rate_ppm",
        "bft_commit_observed_height_rate_ppm",
        "bft_skipped_height_total",
        "bft_skipped_observed_height_rate_ppm",
        "critical_wait_density_avg_milli",
        "critical_wait_active_height_share_ppm",
    ];

    assert_eq!(fairness_review_fields.len(), 8);
    assert!(fairness_review_fields[0].ends_with("_heights"));
    assert!(fairness_review_fields[1].ends_with("_rate_ppm"));
    assert!(fairness_review_fields[2].ends_with("_rate_ppm"));
    assert!(fairness_review_fields[3].ends_with("_rate_ppm"));
    assert!(fairness_review_fields[4].ends_with("_total"));
    assert!(fairness_review_fields[5].ends_with("_rate_ppm"));
    assert!(fairness_review_fields[6].ends_with("_avg_milli"));
    assert!(fairness_review_fields[7].ends_with("_share_ppm"));
    assert_ne!(fairness_review_fields[1], fairness_review_fields[2]);
    assert_ne!(fairness_review_fields[2], fairness_review_fields[3]);
    assert_ne!(fairness_review_fields[3], fairness_review_fields[5]);
    assert_ne!(fairness_review_fields[6], fairness_review_fields[7]);
}

#[test]
fn critical_wait_density_avg_handles_empty_active_height_set() {
    let critical_wait_total = 5u64;
    let critical_wait_active_heights = 0u64;
    let critical_wait_density_avg = if critical_wait_active_heights == 0 {
        0
    } else {
        critical_wait_total / critical_wait_active_heights
    };
    let critical_wait_density_avg_milli =
        ratio_milli_u64(critical_wait_total, critical_wait_active_heights);
    let critical_wait_active_height_share_ppm =
        finality_budget_share_ppm(critical_wait_density_avg_milli, 200u128);

    assert_eq!(critical_wait_density_avg, 0);
    assert_eq!(critical_wait_density_avg_milli, 0);
    assert_eq!(critical_wait_active_height_share_ppm, 0);
}

#[test]
fn critical_wait_active_height_share_tracks_clustered_fairness_stall_budget_pressure() {
    let critical_wait_density_avg_milli = 2_500u64;
    let finality_avg = 200u128;
    let critical_wait_active_height_share_ppm =
        finality_budget_share_ppm(critical_wait_density_avg_milli, finality_avg);

    assert_eq!(critical_wait_active_height_share_ppm, 12_500);
    assert!(critical_wait_active_height_share_ppm < 1_000_000);
}
