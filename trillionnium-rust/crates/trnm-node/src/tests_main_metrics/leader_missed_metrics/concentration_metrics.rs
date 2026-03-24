use super::super::*;

#[test]
fn leader_missed_concentration_metrics_make_single_proposer_hotspots_visible() {
    let leader_missed_final = vec![4u64, 1u64, 1u64, 0u64];
    let bft_leader_missed_total: u64 = leader_missed_final.iter().copied().sum();
    let bft_leader_missed_max = leader_missed_final.iter().copied().max().unwrap_or(0);
    let bft_leader_missed_top_share_ppm =
        ratio_ppm_u64(bft_leader_missed_max, bft_leader_missed_total);
    let bft_leader_missed_active_validators = leader_missed_final
        .iter()
        .filter(|missed| **missed > 0)
        .count() as u64;
    let bft_leader_missed_active_validator_share_ppm = ratio_ppm_u64(
        bft_leader_missed_active_validators,
        leader_missed_final.len() as u64,
    );

    assert_eq!(bft_leader_missed_total, 6);
    assert_eq!(bft_leader_missed_max, 4);
    assert_eq!(bft_leader_missed_top_share_ppm, 666_666);
    assert_eq!(bft_leader_missed_active_validators, 3);
    assert_eq!(bft_leader_missed_active_validator_share_ppm, 750_000);
}

#[test]
fn leader_missed_concentration_metrics_are_zero_without_any_misses() {
    let leader_missed_final = vec![0u64, 0u64, 0u64, 0u64];
    let bft_leader_missed_total: u64 = leader_missed_final.iter().copied().sum();
    let bft_leader_missed_max = leader_missed_final.iter().copied().max().unwrap_or(0);
    let bft_leader_missed_top_share_ppm =
        ratio_ppm_u64(bft_leader_missed_max, bft_leader_missed_total);
    let bft_leader_missed_active_validators = leader_missed_final
        .iter()
        .filter(|missed| **missed > 0)
        .count() as u64;
    let bft_leader_missed_active_validator_share_ppm = ratio_ppm_u64(
        bft_leader_missed_active_validators,
        leader_missed_final.len() as u64,
    );

    assert_eq!(bft_leader_missed_total, 0);
    assert_eq!(bft_leader_missed_max, 0);
    assert_eq!(bft_leader_missed_top_share_ppm, 0);
    assert_eq!(bft_leader_missed_active_validators, 0);
    assert_eq!(bft_leader_missed_active_validator_share_ppm, 0);
}

#[test]
fn leader_missed_metric_names_keep_hotspot_and_distribution_semantics_distinct() {
    let total_field_name = "bft_leader_missed_total";
    let max_field_name = "bft_leader_missed_max";
    let top_share_field_name = "bft_leader_missed_top_share_ppm";
    let active_validators_field_name = "bft_leader_missed_active_validators";
    let active_validator_share_field_name = "bft_leader_missed_active_validator_share_ppm";
    let active_heights_field_name = "bft_leader_missed_active_heights";
    let active_height_rate_field_name = "bft_leader_missed_active_height_rate_ppm";
    let active_observed_height_rate_field_name =
        "bft_leader_missed_active_observed_height_rate_ppm";
    let distribution_field_name = "bft_leader_missed_proposals";

    assert!(total_field_name.ends_with("_total"));
    assert!(max_field_name.ends_with("_max"));
    assert!(top_share_field_name.ends_with("_share_ppm"));
    assert!(active_validators_field_name.ends_with("_validators"));
    assert!(active_validator_share_field_name.ends_with("_share_ppm"));
    assert!(active_heights_field_name.ends_with("_heights"));
    assert!(
        active_height_rate_field_name.ends_with("_share_ppm")
            || active_height_rate_field_name.ends_with("_rate_ppm")
    );
    assert!(active_observed_height_rate_field_name.ends_with("_rate_ppm"));
    assert!(distribution_field_name.ends_with("_proposals"));
    assert_ne!(total_field_name, max_field_name);
    assert_ne!(max_field_name, top_share_field_name);
    assert_ne!(top_share_field_name, active_validators_field_name);
    assert_ne!(
        active_validators_field_name,
        active_validator_share_field_name
    );
    assert_ne!(active_validator_share_field_name, active_heights_field_name);
    assert_ne!(active_heights_field_name, active_height_rate_field_name);
    assert_ne!(
        active_height_rate_field_name,
        active_observed_height_rate_field_name
    );
    assert_ne!(
        active_observed_height_rate_field_name,
        distribution_field_name
    );
}

#[test]
fn leader_missed_hotspot_metrics_stay_visible_when_distribution_looks_benign() {
    let leader_missed_final = vec![2u64, 2u64, 1u64, 1u64];
    let bft_leader_missed_total: u64 = leader_missed_final.iter().copied().sum();
    let bft_leader_missed_max = leader_missed_final.iter().copied().max().unwrap_or(0);
    let bft_leader_missed_top_share_ppm =
        ratio_ppm_u64(bft_leader_missed_max, bft_leader_missed_total);
    let bft_leader_missed_active_validators = leader_missed_final
        .iter()
        .filter(|missed| **missed > 0)
        .count() as u64;
    let bft_leader_missed_active_validator_share_ppm = ratio_ppm_u64(
        bft_leader_missed_active_validators,
        leader_missed_final.len() as u64,
    );
    let bft_leader_missed_active_heights = 2u64;
    let bft_committed_heights = 6u64;
    let bft_observed_heights = 8u64;
    let finality_avg = 2u128;
    let bft_leader_missed_density_avg_milli =
        ratio_milli_u64(bft_leader_missed_total, bft_leader_missed_active_heights);
    let bft_leader_missed_active_height_rate_ppm =
        ratio_ppm_u64(bft_leader_missed_active_heights, bft_committed_heights);
    let bft_leader_missed_active_observed_height_rate_ppm =
        ratio_ppm_u64(bft_leader_missed_active_heights, bft_observed_heights);
    let bft_leader_missed_active_height_share_ppm =
        finality_budget_share_ppm(bft_leader_missed_density_avg_milli, finality_avg);

    assert_eq!(bft_leader_missed_total, 6);
    assert_eq!(bft_leader_missed_top_share_ppm, 333_333);
    assert_eq!(bft_leader_missed_active_validator_share_ppm, 1_000_000);
    assert_eq!(bft_leader_missed_active_height_rate_ppm, 333_333);
    assert_eq!(bft_leader_missed_active_observed_height_rate_ppm, 250_000);
    assert_eq!(bft_leader_missed_density_avg_milli, 3_000);
    assert_eq!(bft_leader_missed_active_height_share_ppm, 1_500_000);
    assert!(bft_leader_missed_active_height_share_ppm > 1_000_000);
    assert!(
        bft_leader_missed_top_share_ppm < 500_000
            && bft_leader_missed_active_validator_share_ppm == 1_000_000
    );
}

#[test]
fn leader_missed_active_height_share_stays_distinct_from_validator_distribution_share() {
    let bft_leader_missed_total = 6u64;
    let bft_leader_missed_active_heights = 2u64;
    let bft_observed_heights = 8u64;
    let leader_missed_final = vec![2u64, 2u64, 1u64, 1u64];
    let finality_avg = 2u128;

    let bft_leader_missed_active_validator_share_ppm = ratio_ppm_u64(
        leader_missed_final
            .iter()
            .filter(|missed| **missed > 0)
            .count() as u64,
        leader_missed_final.len() as u64,
    );
    let bft_leader_missed_active_observed_height_rate_ppm =
        ratio_ppm_u64(bft_leader_missed_active_heights, bft_observed_heights);
    let bft_leader_missed_active_height_share_ppm = finality_budget_share_ppm(
        ratio_milli_u64(bft_leader_missed_total, bft_leader_missed_active_heights),
        finality_avg,
    );

    assert_eq!(bft_leader_missed_active_validator_share_ppm, 1_000_000);
    assert_eq!(bft_leader_missed_active_observed_height_rate_ppm, 250_000);
    assert_eq!(bft_leader_missed_active_height_share_ppm, 1_500_000);
    assert_ne!(
        bft_leader_missed_active_height_share_ppm,
        bft_leader_missed_active_validator_share_ppm
    );
    assert!(
        bft_leader_missed_active_height_share_ppm > bft_leader_missed_active_validator_share_ppm
    );
}
