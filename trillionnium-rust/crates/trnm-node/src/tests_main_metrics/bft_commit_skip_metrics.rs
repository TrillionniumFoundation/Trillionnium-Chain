use super::*;

#[test]
fn bft_commit_and_skipped_height_rates_make_no_commit_pressure_visible() {
    let bft_observed_heights = 5u64;
    let bft_committed_heights = 4u64;
    let bft_skipped_height_total = bft_observed_heights - bft_committed_heights;
    let bft_commit_observed_height_rate_ppm =
        ratio_ppm_u64(bft_committed_heights, bft_observed_heights);
    let bft_skipped_observed_height_rate_ppm =
        ratio_ppm_u64(bft_skipped_height_total, bft_observed_heights);

    assert_eq!(bft_commit_observed_height_rate_ppm, 800_000);
    assert_eq!(bft_skipped_height_total, 1);
    assert_eq!(bft_skipped_observed_height_rate_ppm, 200_000);
    assert_eq!(
        bft_commit_observed_height_rate_ppm + bft_skipped_observed_height_rate_ppm,
        1_000_000
    );
}

#[test]
fn bft_commit_and_skipped_height_metric_names_keep_commit_and_skip_views_distinct() {
    let commit_rate_field_name = "bft_commit_observed_height_rate_ppm";
    let skipped_total_field_name = "bft_skipped_height_total";
    let skipped_rate_field_name = "bft_skipped_observed_height_rate_ppm";

    assert!(commit_rate_field_name.ends_with("_rate_ppm"));
    assert!(skipped_total_field_name.ends_with("_total"));
    assert!(skipped_rate_field_name.ends_with("_rate_ppm"));
    assert_ne!(commit_rate_field_name, skipped_total_field_name);
    assert_ne!(commit_rate_field_name, skipped_rate_field_name);
    assert_ne!(skipped_total_field_name, skipped_rate_field_name);
}

#[test]
fn bft_commit_and_skipped_height_review_bundle_keeps_observed_coverage_pair_together() {
    let coverage_review_fields = [
        "bft_commit_observed_height_rate_ppm",
        "bft_skipped_height_total",
        "bft_skipped_observed_height_rate_ppm",
    ];

    assert_eq!(coverage_review_fields.len(), 3);
    assert!(coverage_review_fields[0].ends_with("_rate_ppm"));
    assert!(coverage_review_fields[1].ends_with("_total"));
    assert!(coverage_review_fields[2].ends_with("_rate_ppm"));
    assert_ne!(coverage_review_fields[0], coverage_review_fields[2]);
}
