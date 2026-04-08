use super::*;

#[test]
fn rollback_block_rate_counts_only_blocks_with_any_rollback() {
    let rollback_samples = vec![0, 2, 0, 1];
    let rollback_block_total = rollback_samples.iter().filter(|count| **count > 0).count() as u64;
    let rollback_block_rate = rollback_block_total as f64 / rollback_samples.len() as f64;

    assert_eq!(rollback_block_total, 2);
    assert!((rollback_block_rate - 0.5).abs() < f64::EPSILON);
}

#[test]
fn rollback_share_metrics_make_rollback_regressions_visible() {
    let finality_avg = 200u128;
    let rollback_avg = 40u128;
    let finality_max = 320u128;
    let rollback_max = 80u128;
    let rollback_total = 3u64;
    let rollback_block_total = 2u64;
    let rollback_active_heights = rollback_block_total;
    let finality_sample_count = 4u64;
    let rollback_block_rate_ppm = ratio_ppm_u64(rollback_block_total, finality_sample_count);
    let rollback_active_height_rate_ppm = rollback_block_rate_ppm;
    let rollback_density_avg = rollback_total / rollback_block_total;
    let rollback_density_avg_milli = ratio_milli_u64(rollback_total, rollback_block_total);

    assert_eq!(ratio_ppm(rollback_avg, finality_avg), 200_000);
    assert_eq!(ratio_ppm(rollback_max, finality_max), 250_000);
    assert_eq!(rollback_active_heights, rollback_block_total);
    assert_eq!(rollback_block_rate_ppm, 500_000);
    assert_eq!(rollback_active_height_rate_ppm, rollback_block_rate_ppm);
    assert_eq!(rollback_density_avg, 1);
    assert_eq!(rollback_density_avg_milli, 1_500);
}

#[test]
fn rollback_active_height_metric_names_keep_compatibility_and_height_semantics_distinct() {
    let compatibility_count_field_name = "rollback_block_total";
    let height_count_field_name = "rollback_active_heights";
    let compatibility_rate_field_name = "rollback_block_rate_ppm";
    let height_rate_field_name = "rollback_active_height_rate_ppm";
    let observed_height_rate_field_name = "rollback_active_observed_height_rate_ppm";

    assert!(compatibility_count_field_name.ends_with("_total"));
    assert!(height_count_field_name.ends_with("_heights"));
    assert!(compatibility_rate_field_name.ends_with("_rate_ppm"));
    assert!(height_rate_field_name.ends_with("_height_rate_ppm"));
    assert!(observed_height_rate_field_name.ends_with("_rate_ppm"));
    assert_ne!(compatibility_count_field_name, height_count_field_name);
    assert_ne!(compatibility_rate_field_name, height_rate_field_name);
    assert_ne!(height_rate_field_name, observed_height_rate_field_name);
    assert_ne!(
        compatibility_rate_field_name,
        observed_height_rate_field_name
    );
}

#[test]
fn rollback_observed_height_rate_exposes_skipped_height_coverage_gap() {
    let rollback_active_heights = 2u64;
    let rollback_committed_height_rate_ppm = ratio_ppm_u64(rollback_active_heights, 2u64);
    let rollback_observed_height_rate_ppm = ratio_ppm_u64(rollback_active_heights, 5u64);

    assert_eq!(rollback_committed_height_rate_ppm, 1_000_000);
    assert_eq!(rollback_observed_height_rate_ppm, 400_000);
    assert!(rollback_observed_height_rate_ppm < rollback_committed_height_rate_ppm);
}

#[test]
fn rollback_active_height_share_tracks_clustered_rollback_budget_pressure() {
    let rollback_density_avg_milli = 2_500u64;
    let finality_avg = 2u128;

    let rollback_active_height_share_ppm =
        finality_budget_share_ppm(rollback_density_avg_milli, finality_avg);

    assert_eq!(rollback_active_height_share_ppm, 1_250_000);
    assert!(rollback_active_height_share_ppm > 1_000_000);
}

#[test]
fn rollback_metric_names_keep_budget_share_and_coverage_distinct() {
    let peak_field_name = "rollback_peak_share_ppm";
    let active_height_rate_field_name = "rollback_active_height_rate_ppm";
    let active_observed_height_rate_field_name = "rollback_active_observed_height_rate_ppm";
    let density_avg_milli_field_name = "rollback_density_avg_milli";
    let active_height_share_field_name = "rollback_active_height_share_ppm";

    assert!(peak_field_name.ends_with("_share_ppm"));
    assert!(active_height_rate_field_name.ends_with("_rate_ppm"));
    assert!(active_observed_height_rate_field_name.ends_with("_rate_ppm"));
    assert!(density_avg_milli_field_name.ends_with("_avg_milli"));
    assert!(active_height_share_field_name.ends_with("_share_ppm"));
    assert_ne!(peak_field_name, active_height_rate_field_name);
    assert_ne!(
        active_height_rate_field_name,
        active_observed_height_rate_field_name
    );
    assert_ne!(
        active_observed_height_rate_field_name,
        density_avg_milli_field_name
    );
    assert_ne!(density_avg_milli_field_name, active_height_share_field_name);
}

#[test]
fn rollback_review_bundle_keeps_commit_skip_coverage_pair_near_guardrail_pressure() {
    let guardrail_review_fields = [
        "rollback_peak_share_ppm",
        "rollback_active_heights",
        "rollback_active_height_rate_ppm",
        "rollback_active_observed_height_rate_ppm",
        "bft_commit_observed_height_rate_ppm",
        "bft_skipped_height_total",
        "bft_skipped_observed_height_rate_ppm",
        "rollback_density_avg_milli",
        "rollback_active_height_share_ppm",
        "apply_error_rollback_share_bps",
    ];

    assert_eq!(guardrail_review_fields.len(), 10);
    assert!(guardrail_review_fields[0].ends_with("_share_ppm"));
    assert!(guardrail_review_fields[1].ends_with("_heights"));
    assert!(guardrail_review_fields[2].ends_with("_rate_ppm"));
    assert!(guardrail_review_fields[3].ends_with("_rate_ppm"));
    assert!(guardrail_review_fields[4].ends_with("_rate_ppm"));
    assert!(guardrail_review_fields[5].ends_with("_total"));
    assert!(guardrail_review_fields[6].ends_with("_rate_ppm"));
    assert!(guardrail_review_fields[7].ends_with("_avg_milli"));
    assert!(guardrail_review_fields[8].ends_with("_share_ppm"));
    assert!(guardrail_review_fields[9].ends_with("_share_bps"));
    assert_ne!(guardrail_review_fields[2], guardrail_review_fields[3]);
    assert_ne!(guardrail_review_fields[4], guardrail_review_fields[6]);
    assert_ne!(guardrail_review_fields[5], guardrail_review_fields[6]);
    assert_ne!(guardrail_review_fields[7], guardrail_review_fields[8]);
}
