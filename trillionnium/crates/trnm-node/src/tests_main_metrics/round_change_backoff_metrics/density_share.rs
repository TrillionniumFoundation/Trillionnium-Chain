use super::super::*;

#[test]
fn round_change_backoff_wall_share_metric_normalizes_per_committed_height_budget() {
    let bft_round_change_backoff_total_ms = 18u64;
    let bft_committed_heights = 4u64;
    let finality_avg_ms = 20u128;
    let wall_share_ppm = wall_time_share_ppm(
        bft_round_change_backoff_total_ms,
        bft_committed_heights,
        finality_avg_ms,
    );
    let active_height_share_ppm = finality_budget_share_ppm(
        ratio_milli_u64(bft_round_change_backoff_total_ms, bft_committed_heights),
        finality_avg_ms,
    );

    assert_eq!(wall_share_ppm, 225_000);
    assert_eq!(active_height_share_ppm, 225_000);
}

#[test]
fn round_change_backoff_compatibility_alias_matches_wall_share_metric() {
    let bft_round_change_backoff_total_ms = 18u64;
    let bft_committed_heights = 4u64;
    let finality_avg_ms = 20u128;
    let wall_share_ppm = wall_time_share_ppm(
        bft_round_change_backoff_total_ms,
        bft_committed_heights,
        finality_avg_ms,
    );
    let compatibility_alias_ppm = wall_share_ppm;

    assert_eq!(wall_share_ppm, 225_000);
    assert_eq!(compatibility_alias_ppm, wall_share_ppm);
}

#[test]
fn round_change_backoff_wall_share_metric_can_exceed_one_million_when_backoff_dominates() {
    let bft_round_change_backoff_total_ms = 12u64;
    let bft_committed_heights = 3u64;
    let finality_avg_ms = 2u128;
    let wall_share_ppm = wall_time_share_ppm(
        bft_round_change_backoff_total_ms,
        bft_committed_heights,
        finality_avg_ms,
    );

    assert_eq!(wall_share_ppm, 2_000_000);
    assert!(wall_share_ppm > 1_000_000);
}

#[test]
fn round_change_backoff_density_avg_milli_preserves_clustered_jitter_signal() {
    let bft_round_change_backoff_total_ms = 5u64;
    let bft_round_change_backoff_active_heights = 2u64;
    let bft_round_change_backoff_density_avg_ms =
        bft_round_change_backoff_total_ms / bft_round_change_backoff_active_heights;
    let bft_round_change_backoff_density_avg_milli = ratio_milli_u64(
        bft_round_change_backoff_total_ms,
        bft_round_change_backoff_active_heights,
    );

    assert_eq!(bft_round_change_backoff_density_avg_ms, 2);
    assert_eq!(bft_round_change_backoff_density_avg_milli, 2_500);
}

#[test]
fn round_change_backoff_density_uses_backoff_active_heights_not_round_change_coverage() {
    let bft_round_change_backoff_total_ms = 5u64;
    let bft_round_change_active_heights = 4u64;
    let bft_round_change_backoff_active_heights = 2u64;
    let finality_avg = 10u128;

    let diluted_density_avg_milli = ratio_milli_u64(
        bft_round_change_backoff_total_ms,
        bft_round_change_active_heights,
    );
    let backoff_density_avg_milli = ratio_milli_u64(
        bft_round_change_backoff_total_ms,
        bft_round_change_backoff_active_heights,
    );
    let backoff_active_height_share_ppm =
        finality_budget_share_ppm(backoff_density_avg_milli, finality_avg);

    assert_eq!(diluted_density_avg_milli, 1_250);
    assert_eq!(backoff_density_avg_milli, 2_500);
    assert!(backoff_density_avg_milli > diluted_density_avg_milli);
    assert_eq!(backoff_active_height_share_ppm, 250_000);
}

#[test]
fn round_change_backoff_budget_share_metric_stays_distinct_from_wall_share_signal() {
    let bft_round_change_backoff_total_ms = 18u64;
    let bft_round_change_active_heights = 2u64;
    let bft_committed_heights = 4u64;
    let finality_avg = 36u128;

    let backoff_active_height_share_ppm = finality_budget_share_ppm(
        ratio_milli_u64(
            bft_round_change_backoff_total_ms,
            bft_round_change_active_heights,
        ),
        finality_avg,
    );
    let backoff_wall_share_ppm =
        ratio_ppm_u64(bft_round_change_backoff_total_ms, bft_committed_heights);

    assert_eq!(backoff_active_height_share_ppm, 250_000);
    assert_eq!(backoff_wall_share_ppm, 4_500_000);
    assert_ne!(backoff_active_height_share_ppm, backoff_wall_share_ppm);
}

#[test]
fn round_change_backoff_active_height_share_handles_zero_finality_budget() {
    let bft_round_change_backoff_density_avg_milli = 2_500u64;
    let finality_avg = 0u128;
    let backoff_active_height_share_ppm =
        finality_budget_share_ppm(bft_round_change_backoff_density_avg_milli, finality_avg);

    assert_eq!(backoff_active_height_share_ppm, 0);
}

#[test]
fn round_change_backoff_active_height_share_can_exceed_budget_when_jitter_dominates() {
    let bft_round_change_backoff_density_avg_milli = 6_000u64;
    let finality_avg = 4u128;
    let backoff_active_height_share_ppm =
        finality_budget_share_ppm(bft_round_change_backoff_density_avg_milli, finality_avg);

    assert_eq!(backoff_active_height_share_ppm, 1_500_000);
    assert!(backoff_active_height_share_ppm > 1_000_000);
}
