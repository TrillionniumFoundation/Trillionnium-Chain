use super::*;

#[test]
fn round_change_active_height_rate_metrics_make_jitter_concentration_visible() {
    let bft_round_change_total = 6u64;
    let bft_round_change_active_heights = 2u64;
    let bft_committed_heights = 4u64;
    let bft_observed_heights = 5u64;

    assert_eq!(
        ratio_ppm_u64(bft_round_change_active_heights, bft_committed_heights),
        500_000
    );
    assert_eq!(
        ratio_ppm_u64(bft_round_change_active_heights, bft_observed_heights),
        400_000
    );
    assert_eq!(bft_round_change_total / bft_round_change_active_heights, 3);
    assert_eq!(
        ratio_ppm_u64(bft_round_change_total, bft_round_change_active_heights),
        3_000_000
    );
}

#[test]
fn round_change_metric_names_keep_committed_budget_and_observed_coverage_distinct() {
    let active_height_rate_field_name = "bft_round_change_active_height_rate_ppm";
    let active_observed_height_rate_field_name = "bft_round_change_active_observed_height_rate_ppm";
    let active_height_share_field_name = "bft_round_change_active_height_share_ppm";
    let density_avg_milli_field_name = "bft_round_change_density_avg_milli";

    assert!(active_height_rate_field_name.ends_with("_rate_ppm"));
    assert!(active_observed_height_rate_field_name.ends_with("_rate_ppm"));
    assert!(active_height_share_field_name.ends_with("_share_ppm"));
    assert!(density_avg_milli_field_name.ends_with("_avg_milli"));
    assert_ne!(
        active_height_rate_field_name,
        active_observed_height_rate_field_name
    );
    assert_ne!(
        active_height_rate_field_name,
        active_height_share_field_name
    );
    assert_ne!(
        active_observed_height_rate_field_name,
        active_height_share_field_name
    );
    assert_ne!(density_avg_milli_field_name, active_height_share_field_name);
}

#[test]
fn round_change_observed_height_rate_exposes_skipped_height_coverage_gap() {
    let bft_round_change_active_heights = 2u64;
    let bft_committed_heights = 2u64;
    let bft_observed_heights = 5u64;
    let committed_height_rate_ppm =
        ratio_ppm_u64(bft_round_change_active_heights, bft_committed_heights);
    let observed_height_rate_ppm =
        ratio_ppm_u64(bft_round_change_active_heights, bft_observed_heights);

    assert_eq!(committed_height_rate_ppm, 1_000_000);
    assert_eq!(observed_height_rate_ppm, 400_000);
    assert!(observed_height_rate_ppm < committed_height_rate_ppm);
}

#[test]
fn round_change_coverage_pair_with_commit_and_skip_rates_exposes_denominator_shift() {
    let bft_round_change_active_heights = 2u64;
    let bft_committed_heights = 2u64;
    let bft_observed_heights = 5u64;
    let bft_skipped_height_total = bft_observed_heights - bft_committed_heights;

    let bft_round_change_active_height_rate_ppm =
        ratio_ppm_u64(bft_round_change_active_heights, bft_committed_heights);
    let bft_round_change_active_observed_height_rate_ppm =
        ratio_ppm_u64(bft_round_change_active_heights, bft_observed_heights);
    let bft_commit_observed_height_rate_ppm =
        ratio_ppm_u64(bft_committed_heights, bft_observed_heights);
    let bft_skipped_observed_height_rate_ppm =
        ratio_ppm_u64(bft_skipped_height_total, bft_observed_heights);

    assert_eq!(bft_round_change_active_height_rate_ppm, 1_000_000);
    assert_eq!(bft_round_change_active_observed_height_rate_ppm, 400_000);
    assert_eq!(bft_commit_observed_height_rate_ppm, 400_000);
    assert_eq!(bft_skipped_observed_height_rate_ppm, 600_000);
    assert_eq!(
        bft_commit_observed_height_rate_ppm + bft_skipped_observed_height_rate_ppm,
        1_000_000
    );
    assert!(
        bft_round_change_active_observed_height_rate_ppm < bft_round_change_active_height_rate_ppm
    );
    assert_eq!(
        bft_round_change_active_observed_height_rate_ppm,
        bft_commit_observed_height_rate_ppm
    );
    assert!(bft_skipped_observed_height_rate_ppm > bft_commit_observed_height_rate_ppm);
}

#[test]
fn round_change_review_bundle_keeps_commit_skip_and_coverage_denominator_views_together() {
    let jitter_review_fields = [
        "bft_round_change_active_heights",
        "bft_round_change_active_height_rate_ppm",
        "bft_round_change_active_observed_height_rate_ppm",
        "bft_commit_observed_height_rate_ppm",
        "bft_skipped_height_total",
        "bft_skipped_observed_height_rate_ppm",
        "bft_round_change_density_avg_milli",
        "bft_round_change_active_height_share_ppm",
    ];

    assert_eq!(jitter_review_fields.len(), 8);
    assert!(jitter_review_fields[0].ends_with("_heights"));
    assert!(jitter_review_fields[1].ends_with("_rate_ppm"));
    assert!(jitter_review_fields[2].ends_with("_rate_ppm"));
    assert!(jitter_review_fields[3].ends_with("_rate_ppm"));
    assert!(jitter_review_fields[4].ends_with("_total"));
    assert!(jitter_review_fields[5].ends_with("_rate_ppm"));
    assert!(jitter_review_fields[6].ends_with("_avg_milli"));
    assert!(jitter_review_fields[7].ends_with("_share_ppm"));
    assert_ne!(jitter_review_fields[1], jitter_review_fields[2]);
    assert_ne!(jitter_review_fields[2], jitter_review_fields[3]);
    assert_ne!(jitter_review_fields[3], jitter_review_fields[5]);
    assert_ne!(jitter_review_fields[6], jitter_review_fields[7]);
}

#[test]
fn round_change_density_avg_milli_preserves_sub_integer_jitter_signal() {
    let bft_round_change_total = 5u64;
    let bft_round_change_active_heights = 2u64;
    let bft_round_change_density_avg = bft_round_change_total / bft_round_change_active_heights;
    let bft_round_change_density_avg_milli =
        ratio_milli_u64(bft_round_change_total, bft_round_change_active_heights);

    assert_eq!(bft_round_change_density_avg, 2);
    assert_eq!(bft_round_change_density_avg_milli, 2_500);
}

#[test]
fn round_change_density_milli_fields_preserve_sub_integer_signal_vs_integer_averages() {
    let bft_round_change_total = 5u64;
    let bft_round_change_backoff_total_ms = 5u64;
    let bft_round_change_active_heights = 2u64;
    let bft_round_change_backoff_active_heights = 2u64;
    let finality_avg = 10u128;

    let density_avg = bft_round_change_total / bft_round_change_active_heights;
    let density_avg_milli =
        ratio_milli_u64(bft_round_change_total, bft_round_change_active_heights);
    let active_height_share_ppm = ratio_ppm_u64(density_avg_milli, (finality_avg as u64) * 1_000);
    let backoff_density_avg_ms =
        bft_round_change_backoff_total_ms / bft_round_change_backoff_active_heights;
    let backoff_density_avg_milli = ratio_milli_u64(
        bft_round_change_backoff_total_ms,
        bft_round_change_backoff_active_heights,
    );
    let backoff_active_height_share_ppm =
        ratio_ppm_u64(backoff_density_avg_milli, (finality_avg as u64) * 1_000);

    assert_eq!(density_avg, 2);
    assert_eq!(density_avg_milli, 2_500);
    assert!(density_avg_milli > density_avg * 1_000);
    assert_eq!(active_height_share_ppm, 250_000);
    assert_eq!(backoff_density_avg_ms, 2);
    assert_eq!(backoff_density_avg_milli, 2_500);
    assert!(backoff_density_avg_milli > backoff_density_avg_ms * 1_000);
    assert_eq!(backoff_active_height_share_ppm, 250_000);
}

#[test]
fn round_change_density_avg_handles_empty_active_height_set() {
    let bft_round_change_total = 6u64;
    let bft_round_change_active_heights = 0u64;
    let bft_round_change_density_avg = if bft_round_change_active_heights == 0 {
        0
    } else {
        bft_round_change_total / bft_round_change_active_heights
    };

    assert_eq!(bft_round_change_density_avg, 0);
}

#[test]
fn round_change_active_height_share_handles_zero_finality_budget() {
    let bft_round_change_density_avg_milli = 2_500u64;
    let finality_avg = 0u128;

    assert_eq!(
        finality_budget_share_ppm(bft_round_change_density_avg_milli, finality_avg),
        0
    );
}

#[test]
fn round_change_active_height_share_can_exceed_budget_when_jitter_dominates() {
    let bft_round_change_density_avg_milli = 6_000u64;
    let finality_avg = 4u128;

    assert_eq!(
        finality_budget_share_ppm(bft_round_change_density_avg_milli, finality_avg),
        1_500_000
    );
}
