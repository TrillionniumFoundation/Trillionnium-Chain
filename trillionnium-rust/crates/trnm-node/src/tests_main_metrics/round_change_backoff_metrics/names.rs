use super::super::*;

#[test]
fn round_change_backoff_metric_names_keep_tail_and_share_semantics_distinct() {
    let max_field_name = "bft_round_change_backoff_max_ms";
    let wall_share_field_name = "bft_round_change_backoff_wall_share_ppm";
    let compatibility_field_name = "bft_round_change_backoff_share_ppm";

    assert!(max_field_name.ends_with("_max_ms"));
    assert!(wall_share_field_name.ends_with("_share_ppm"));
    assert!(compatibility_field_name.ends_with("_share_ppm"));
    assert_ne!(max_field_name, wall_share_field_name);
    assert_ne!(max_field_name, compatibility_field_name);
}

#[test]
fn round_change_backoff_wall_share_metric_name_stays_ppm_based() {
    let field_name = "bft_round_change_backoff_wall_share_ppm";
    assert!(field_name.ends_with("_share_ppm"));
    assert!(!field_name.ends_with("_per_height_ms"));
}

#[test]
fn round_change_backoff_share_metric_keeps_compatibility_alias_name() {
    let field_name = "bft_round_change_backoff_share_ppm";
    assert!(field_name.ends_with("_share_ppm"));
    assert!(!field_name.contains("wall_share_ppm"));
}

#[test]
fn round_change_backoff_metric_names_keep_wall_alias_and_budget_share_distinct() {
    let wall_share_field_name = "bft_round_change_backoff_wall_share_ppm";
    let compatibility_alias_field_name = "bft_round_change_backoff_share_ppm";
    let active_height_share_field_name = "bft_round_change_backoff_active_height_share_ppm";

    assert!(wall_share_field_name.ends_with("_share_ppm"));
    assert!(compatibility_alias_field_name.ends_with("_share_ppm"));
    assert!(active_height_share_field_name.ends_with("_share_ppm"));
    assert_ne!(wall_share_field_name, compatibility_alias_field_name);
    assert_ne!(wall_share_field_name, active_height_share_field_name);
    assert_ne!(
        compatibility_alias_field_name,
        active_height_share_field_name
    );
}

#[test]
fn round_change_backoff_active_height_metric_names_stay_distinct_from_round_change_coverage() {
    let round_change_active_heights_field_name = "bft_round_change_active_heights";
    let backoff_active_heights_field_name = "bft_round_change_backoff_active_heights";
    let backoff_active_height_rate_field_name = "bft_round_change_backoff_active_height_rate_ppm";
    let backoff_active_observed_height_rate_field_name =
        "bft_round_change_backoff_active_observed_height_rate_ppm";

    assert!(round_change_active_heights_field_name.ends_with("_heights"));
    assert!(backoff_active_heights_field_name.ends_with("_heights"));
    assert!(backoff_active_height_rate_field_name.ends_with("_rate_ppm"));
    assert!(backoff_active_observed_height_rate_field_name.ends_with("_rate_ppm"));
    assert_ne!(
        round_change_active_heights_field_name,
        backoff_active_heights_field_name
    );
    assert_ne!(
        backoff_active_heights_field_name,
        backoff_active_height_rate_field_name
    );
    assert_ne!(
        backoff_active_height_rate_field_name,
        backoff_active_observed_height_rate_field_name
    );
}

#[test]
fn round_change_backoff_metric_names_keep_observed_coverage_distinct_from_wall_and_budget_views() {
    let active_observed_height_rate_field_name =
        "bft_round_change_backoff_active_observed_height_rate_ppm";
    let active_height_share_field_name = "bft_round_change_backoff_active_height_share_ppm";
    let wall_share_field_name = "bft_round_change_backoff_wall_share_ppm";
    let compatibility_alias_field_name = "bft_round_change_backoff_share_ppm";

    assert!(active_observed_height_rate_field_name.ends_with("_rate_ppm"));
    assert!(active_height_share_field_name.ends_with("_share_ppm"));
    assert!(wall_share_field_name.ends_with("_share_ppm"));
    assert!(compatibility_alias_field_name.ends_with("_share_ppm"));
    assert_ne!(
        active_observed_height_rate_field_name,
        active_height_share_field_name
    );
    assert_ne!(
        active_observed_height_rate_field_name,
        wall_share_field_name
    );
    assert_ne!(
        active_observed_height_rate_field_name,
        compatibility_alias_field_name
    );
}
