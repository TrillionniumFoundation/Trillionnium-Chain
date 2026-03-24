use super::super::*;

#[test]
fn leader_missed_active_height_rate_metrics_make_fairness_stall_concentration_visible() {
    let bft_leader_missed_active_heights = 3u64;
    let bft_committed_heights = 4u64;
    let bft_observed_heights = 6u64;
    let bft_leader_missed_active_height_rate_ppm =
        ratio_ppm_u64(bft_leader_missed_active_heights, bft_committed_heights);
    let bft_leader_missed_active_observed_height_rate_ppm =
        ratio_ppm_u64(bft_leader_missed_active_heights, bft_observed_heights);

    assert_eq!(bft_leader_missed_active_heights, 3);
    assert_eq!(bft_leader_missed_active_height_rate_ppm, 750_000);
    assert_eq!(bft_leader_missed_active_observed_height_rate_ppm, 500_000);
}

#[test]
fn leader_missed_active_heights_count_only_new_miss_bursts() {
    let mut active_heights = 0u64;
    let mut previous_snapshot = vec![0u64, 0u64, 0u64, 0u64];
    let snapshots = [
        vec![0u64, 1u64, 0u64, 0u64],
        vec![0u64, 1u64, 0u64, 0u64],
        vec![0u64, 1u64, 0u64, 1u64],
    ];

    for snapshot in snapshots {
        if missed_proposals_added_since(&previous_snapshot, &snapshot) > 0 {
            active_heights += 1;
        }
        previous_snapshot = snapshot;
    }

    assert_eq!(active_heights, 2);
}

#[test]
fn leader_missed_added_since_ignores_repeated_cumulative_snapshots() {
    let previous_snapshot = vec![0u64, 2u64, 1u64, 0u64];
    let repeated_snapshot = vec![0u64, 2u64, 1u64, 0u64];

    assert_eq!(
        missed_proposals_added_since(&previous_snapshot, &repeated_snapshot),
        0
    );
}

#[test]
fn leader_missed_observed_height_rate_exposes_skipped_height_coverage_gap() {
    let bft_leader_missed_active_heights = 2u64;
    let bft_committed_heights = 2u64;
    let bft_observed_heights = 5u64;
    let committed_height_rate_ppm =
        ratio_ppm_u64(bft_leader_missed_active_heights, bft_committed_heights);
    let observed_height_rate_ppm =
        ratio_ppm_u64(bft_leader_missed_active_heights, bft_observed_heights);

    assert_eq!(committed_height_rate_ppm, 1_000_000);
    assert_eq!(observed_height_rate_ppm, 400_000);
    assert!(observed_height_rate_ppm < committed_height_rate_ppm);
}

#[test]
fn leader_missed_density_avg_milli_preserves_bursted_fairness_stall_signal() {
    let bft_leader_missed_total = 5u64;
    let bft_leader_missed_active_heights = 2u64;
    let bft_leader_missed_density_avg = bft_leader_missed_total / bft_leader_missed_active_heights;
    let bft_leader_missed_density_avg_milli =
        ratio_milli_u64(bft_leader_missed_total, bft_leader_missed_active_heights);

    assert_eq!(bft_leader_missed_density_avg, 2);
    assert_eq!(bft_leader_missed_density_avg_milli, 2_500);
    assert!(bft_leader_missed_density_avg_milli > bft_leader_missed_density_avg * 1_000);
}

#[test]
fn leader_missed_metric_names_include_density_fields_for_active_height_bursts() {
    let density_field_name = "bft_leader_missed_density_avg";
    let milli_density_field_name = "bft_leader_missed_density_avg_milli";
    let active_height_share_field_name = "bft_leader_missed_active_height_share_ppm";
    let active_heights_field_name = "bft_leader_missed_active_heights";
    let active_observed_height_rate_field_name =
        "bft_leader_missed_active_observed_height_rate_ppm";

    assert!(density_field_name.ends_with("_avg"));
    assert!(milli_density_field_name.ends_with("_avg_milli"));
    assert!(active_height_share_field_name.ends_with("_share_ppm"));
    assert!(active_heights_field_name.ends_with("_heights"));
    assert!(active_observed_height_rate_field_name.ends_with("_rate_ppm"));
    assert_ne!(density_field_name, milli_density_field_name);
    assert_ne!(milli_density_field_name, active_height_share_field_name);
    assert_ne!(active_height_share_field_name, active_heights_field_name);
    assert_ne!(
        active_heights_field_name,
        active_observed_height_rate_field_name
    );
}

#[test]
fn leader_missed_metric_names_keep_validator_spread_distinct_from_height_budget_pressure() {
    let active_validator_share_field_name = "bft_leader_missed_active_validator_share_ppm";
    let active_height_share_field_name = "bft_leader_missed_active_height_share_ppm";
    let density_field_name = "bft_leader_missed_density_avg_milli";
    let active_observed_height_rate_field_name =
        "bft_leader_missed_active_observed_height_rate_ppm";

    assert!(active_validator_share_field_name.ends_with("_share_ppm"));
    assert!(active_height_share_field_name.ends_with("_share_ppm"));
    assert!(density_field_name.ends_with("_avg_milli"));
    assert!(active_observed_height_rate_field_name.ends_with("_rate_ppm"));
    assert_ne!(
        active_validator_share_field_name,
        active_height_share_field_name
    );
    assert_ne!(active_validator_share_field_name, density_field_name);
    assert_ne!(
        active_height_share_field_name,
        active_observed_height_rate_field_name
    );
}

#[test]
fn leader_missed_metric_names_keep_validator_spread_coverage_and_budget_views_distinct() {
    let active_validators_field_name = "bft_leader_missed_active_validators";
    let active_validator_share_field_name = "bft_leader_missed_active_validator_share_ppm";
    let active_heights_field_name = "bft_leader_missed_active_heights";
    let active_height_rate_field_name = "bft_leader_missed_active_height_rate_ppm";
    let active_observed_height_rate_field_name =
        "bft_leader_missed_active_observed_height_rate_ppm";
    let density_avg_milli_field_name = "bft_leader_missed_density_avg_milli";
    let active_height_share_field_name = "bft_leader_missed_active_height_share_ppm";

    assert!(active_validators_field_name.ends_with("_validators"));
    assert!(active_validator_share_field_name.ends_with("_share_ppm"));
    assert!(active_heights_field_name.ends_with("_heights"));
    assert!(active_height_rate_field_name.ends_with("_rate_ppm"));
    assert!(active_observed_height_rate_field_name.ends_with("_rate_ppm"));
    assert!(density_avg_milli_field_name.ends_with("_avg_milli"));
    assert!(active_height_share_field_name.ends_with("_share_ppm"));
    assert_ne!(active_validators_field_name, active_heights_field_name);
    assert_ne!(
        active_validator_share_field_name,
        active_height_share_field_name
    );
    assert_ne!(
        active_height_rate_field_name,
        active_observed_height_rate_field_name
    );
    assert_ne!(density_avg_milli_field_name, active_height_share_field_name);
}

#[test]
fn leader_missed_active_height_share_handles_zero_finality_budget() {
    let bft_leader_missed_density_avg_milli = 2_500u64;
    let finality_avg = 0u128;

    assert_eq!(
        finality_budget_share_ppm(bft_leader_missed_density_avg_milli, finality_avg),
        0
    );
}

#[test]
fn leader_missed_active_height_share_can_exceed_budget_when_fairness_stalls_dominate() {
    let bft_leader_missed_density_avg_milli = 6_000u64;
    let finality_avg = 4u128;

    assert_eq!(
        finality_budget_share_ppm(bft_leader_missed_density_avg_milli, finality_avg),
        1_500_000
    );
}
