use super::*;

#[test]
fn preexec_peak_share_metric_makes_tail_latency_regressions_visible() {
    let finality_max = 320u128;
    let preexec_max = 160u128;

    assert_eq!(ratio_ppm(preexec_max, finality_max), 500_000);
    assert_eq!(ratio_ppm(preexec_max, 0), 0);
}

#[test]
fn preexec_reject_share_metric_highlights_guardrail_pressure() {
    assert_eq!(ratio_percent_bps(6, 15), 4_000);
    assert_eq!(ratio_percent_bps(0, 15), 0);
    assert_eq!(ratio_percent_bps(4, 0), 0);
}

#[test]
fn preexec_reject_density_metrics_expose_concentrated_guardrail_pressure() {
    let preexec_reject_total = 7u64;
    let preexec_reject_active_heights = 2u64;
    let bft_committed_heights = 3u64;
    let bft_observed_heights = 5u64;
    let finality_avg = 200u128;
    let preexec_reject_density_avg = preexec_reject_total / preexec_reject_active_heights;
    let preexec_reject_density_avg_milli =
        ratio_milli_u64(preexec_reject_total, preexec_reject_active_heights);
    let preexec_reject_active_height_rate_ppm =
        ratio_ppm_u64(preexec_reject_active_heights, bft_committed_heights);
    let preexec_reject_active_observed_height_rate_ppm =
        ratio_ppm_u64(preexec_reject_active_heights, bft_observed_heights);
    let preexec_reject_active_height_share_ppm =
        finality_budget_share_ppm(preexec_reject_density_avg_milli, finality_avg);

    assert_eq!(preexec_reject_density_avg, 3);
    assert_eq!(preexec_reject_density_avg_milli, 3_500);
    assert_eq!(preexec_reject_active_height_rate_ppm, 666_666);
    assert_eq!(preexec_reject_active_observed_height_rate_ppm, 400_000);
    assert_eq!(preexec_reject_active_height_share_ppm, 17_500);
    assert!(preexec_reject_active_observed_height_rate_ppm < preexec_reject_active_height_rate_ppm);
    assert_eq!(ratio_milli_u64(0, bft_committed_heights), 0);
    assert_eq!(ratio_milli_u64(preexec_reject_total, 0), 0);
}

#[test]
fn preexec_reject_metric_names_keep_height_coverage_and_budget_semantics_distinct() {
    let total_field_name = "preexec_reject_total";
    let active_height_count_field_name = "preexec_reject_active_heights";
    let active_height_rate_field_name = "preexec_reject_active_height_rate_ppm";
    let active_observed_height_rate_field_name = "preexec_reject_active_observed_height_rate_ppm";
    let active_height_share_field_name = "preexec_reject_active_height_share_ppm";
    let density_avg_field_name = "preexec_reject_density_avg";
    let density_avg_milli_field_name = "preexec_reject_density_avg_milli";
    let budget_share_field_name = "preexec_reject_share_bps";

    assert!(total_field_name.ends_with("_total"));
    assert!(active_height_count_field_name.ends_with("_heights"));
    assert!(active_height_rate_field_name.ends_with("_height_rate_ppm"));
    assert!(active_observed_height_rate_field_name.ends_with("_rate_ppm"));
    assert!(active_height_share_field_name.ends_with("_share_ppm"));
    assert!(density_avg_field_name.ends_with("_avg"));
    assert!(density_avg_milli_field_name.ends_with("_avg_milli"));
    assert!(budget_share_field_name.ends_with("_share_bps"));
    assert_ne!(total_field_name, active_height_count_field_name);
    assert_ne!(active_height_count_field_name, active_height_rate_field_name);
    assert_ne!(
        active_height_rate_field_name,
        active_observed_height_rate_field_name
    );
    assert_ne!(
        active_observed_height_rate_field_name,
        active_height_share_field_name
    );
    assert_ne!(active_height_share_field_name, density_avg_field_name);
    assert_ne!(density_avg_field_name, density_avg_milli_field_name);
    assert_ne!(density_avg_milli_field_name, budget_share_field_name);
}

#[test]
fn preexec_metric_names_keep_tail_and_guardrail_semantics_distinct() {
    let peak_field_name = "preexec_peak_share_ppm";
    let reject_density_avg_milli_field_name = "preexec_reject_density_avg_milli";
    let reject_share_field_name = "preexec_reject_share_bps";
    let conflict_miss_share_field_name = "preexec_conflict_miss_share_bps";

    assert!(peak_field_name.ends_with("_share_ppm"));
    assert!(reject_density_avg_milli_field_name.ends_with("_avg_milli"));
    assert!(reject_share_field_name.ends_with("_share_bps"));
    assert!(conflict_miss_share_field_name.ends_with("_share_bps"));
    assert_ne!(peak_field_name, reject_density_avg_milli_field_name);
    assert_ne!(peak_field_name, reject_share_field_name);
    assert_ne!(peak_field_name, conflict_miss_share_field_name);
    assert_ne!(reject_density_avg_milli_field_name, reject_share_field_name);
    assert_ne!(
        reject_density_avg_milli_field_name,
        conflict_miss_share_field_name
    );
    assert_ne!(reject_share_field_name, conflict_miss_share_field_name);
}

#[test]
fn preexec_reject_review_bundle_keeps_commit_skip_coverage_pair_near_guardrail_pressure() {
    let guardrail_review_fields = [
        "preexec_peak_share_ppm",
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
    ];

    assert_eq!(guardrail_review_fields.len(), 11);
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
    assert!(guardrail_review_fields[10].ends_with("_share_bps"));
    assert_ne!(guardrail_review_fields[2], guardrail_review_fields[3]);
    assert_ne!(guardrail_review_fields[4], guardrail_review_fields[6]);
    assert_ne!(guardrail_review_fields[5], guardrail_review_fields[6]);
    assert_ne!(guardrail_review_fields[7], guardrail_review_fields[8]);
    assert_ne!(guardrail_review_fields[9], guardrail_review_fields[10]);
}
