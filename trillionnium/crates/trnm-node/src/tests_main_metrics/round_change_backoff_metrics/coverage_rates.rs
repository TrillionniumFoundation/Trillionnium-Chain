use super::super::*;

#[test]
fn round_change_backoff_active_height_rate_exposes_zero_backoff_round_change_gap() {
    let bft_round_change_active_heights = 3u64;
    let bft_round_change_backoff_active_heights = 2u64;
    let bft_committed_heights = 4u64;
    let bft_observed_heights = 5u64;

    let committed_height_rate_ppm = ratio_ppm_u64(
        bft_round_change_backoff_active_heights,
        bft_committed_heights,
    );
    let observed_height_rate_ppm = ratio_ppm_u64(
        bft_round_change_backoff_active_heights,
        bft_observed_heights,
    );

    assert_eq!(committed_height_rate_ppm, 500_000);
    assert_eq!(observed_height_rate_ppm, 400_000);
    assert!(bft_round_change_backoff_active_heights < bft_round_change_active_heights);
    assert!(observed_height_rate_ppm < committed_height_rate_ppm);
}

#[test]
fn round_change_backoff_observed_coverage_stays_distinct_from_wall_share_alias() {
    let bft_round_change_backoff_total_ms = 12u64;
    let bft_round_change_backoff_active_heights = 2u64;
    let bft_committed_heights = 3u64;
    let bft_observed_heights = 5u64;
    let finality_avg = 8u128;

    let wall_share_ppm = ratio_ppm_u64(bft_round_change_backoff_total_ms, bft_committed_heights);
    let compatibility_alias_ppm = wall_share_ppm;
    let active_observed_height_rate_ppm = ratio_ppm_u64(
        bft_round_change_backoff_active_heights,
        bft_observed_heights,
    );
    let active_height_share_ppm = finality_budget_share_ppm(
        ratio_milli_u64(
            bft_round_change_backoff_total_ms,
            bft_round_change_backoff_active_heights,
        ),
        finality_avg,
    );

    assert_eq!(wall_share_ppm, 4_000_000);
    assert_eq!(compatibility_alias_ppm, wall_share_ppm);
    assert_eq!(active_observed_height_rate_ppm, 400_000);
    assert_eq!(active_height_share_ppm, 750_000);
    assert_ne!(active_observed_height_rate_ppm, compatibility_alias_ppm);
    assert_ne!(active_height_share_ppm, compatibility_alias_ppm);
    assert!(active_observed_height_rate_ppm < active_height_share_ppm);
}

#[test]
fn round_change_backoff_coverage_pair_with_commit_and_skip_rates_exposes_denominator_shift() {
    let bft_round_change_backoff_active_heights = 2u64;
    let bft_committed_heights = 2u64;
    let bft_observed_heights = 5u64;
    let bft_skipped_height_total = bft_observed_heights - bft_committed_heights;

    let bft_round_change_backoff_active_height_rate_ppm = ratio_ppm_u64(
        bft_round_change_backoff_active_heights,
        bft_committed_heights,
    );
    let bft_round_change_backoff_active_observed_height_rate_ppm = ratio_ppm_u64(
        bft_round_change_backoff_active_heights,
        bft_observed_heights,
    );
    let bft_commit_observed_height_rate_ppm =
        ratio_ppm_u64(bft_committed_heights, bft_observed_heights);
    let bft_skipped_observed_height_rate_ppm =
        ratio_ppm_u64(bft_skipped_height_total, bft_observed_heights);

    assert_eq!(bft_round_change_backoff_active_height_rate_ppm, 1_000_000);
    assert_eq!(
        bft_round_change_backoff_active_observed_height_rate_ppm,
        400_000
    );
    assert_eq!(bft_commit_observed_height_rate_ppm, 400_000);
    assert_eq!(bft_skipped_observed_height_rate_ppm, 600_000);
    assert_eq!(
        bft_commit_observed_height_rate_ppm + bft_skipped_observed_height_rate_ppm,
        1_000_000
    );
    assert!(
        bft_round_change_backoff_active_observed_height_rate_ppm
            < bft_round_change_backoff_active_height_rate_ppm
    );
    assert_eq!(
        bft_round_change_backoff_active_observed_height_rate_ppm,
        bft_commit_observed_height_rate_ppm
    );
    assert!(bft_skipped_observed_height_rate_ppm > bft_commit_observed_height_rate_ppm);
}

#[test]
fn round_change_backoff_share_metric_handles_empty_consensus_samples() {
    assert_eq!(ratio_ppm_u64(18, 0), 0);
    assert_eq!(ratio_ppm_u64(0, 0), 0);
}
