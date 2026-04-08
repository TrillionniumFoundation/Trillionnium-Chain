use super::*;

#[test]
fn consensus_share_ppm_is_zero_when_finality_avg_is_zero() {
    assert_eq!(ratio_ppm(10, 0), 0);
}

#[test]
fn consensus_share_ppm_makes_component_regressions_visible() {
    let finality_avg = 200u128;
    let scheduler_avg = 50u128;
    let preexec_avg = 120u128;
    let commit_avg = 20u128;
    let state_root_total_avg = 10u128;

    assert_eq!(ratio_ppm(scheduler_avg, finality_avg), 250_000);
    assert_eq!(ratio_ppm(preexec_avg, finality_avg), 600_000);
    assert_eq!(ratio_ppm(commit_avg, finality_avg), 100_000);
    assert_eq!(ratio_ppm(state_root_total_avg, finality_avg), 50_000);
}

#[test]
fn scheduler_peak_share_metric_makes_tail_latency_regressions_visible() {
    let finality_max = 320u128;
    let scheduler_max = 96u128;

    assert_eq!(ratio_ppm(scheduler_max, finality_max), 300_000);
    assert_eq!(ratio_ppm(scheduler_max, 0), 0);
}

#[test]
fn commit_and_state_root_peak_share_metrics_make_tail_latency_regressions_visible() {
    let finality_max = 320u128;
    let commit_max = 96u128;
    let state_root_total_max = 144u128;

    assert_eq!(ratio_ppm(commit_max, finality_max), 300_000);
    assert_eq!(ratio_ppm(state_root_total_max, finality_max), 450_000);
    assert_eq!(ratio_ppm(commit_max, 0), 0);
    assert_eq!(ratio_ppm(state_root_total_max, 0), 0);
}

#[test]
fn percentage_bps_guardrails_make_preexec_and_rollback_regressions_visible() {
    assert_eq!(ratio_percent_bps(3, 12), 2_500);
    assert_eq!(ratio_percent_bps(2, 5), 4_000);
    assert_eq!(ratio_percent_bps(1, 0), 0);
}

#[test]
fn unprofiled_finality_gap_metric_captures_hidden_block_time() {
    assert_eq!(gap_percent_bps(200, 80, 40), 4_000);
    assert_eq!(gap_percent_bps(200, 150, 80), 0);
    assert_eq!(gap_percent_bps(0, 10, 5), 0);
}

#[test]
fn scheduler_peak_share_metric_name_stays_distinct_from_average_share_field() {
    let avg_field_name = "scheduler_share_avg_ppm";
    let peak_field_name = "scheduler_peak_share_ppm";

    assert!(avg_field_name.ends_with("_avg_ppm"));
    assert!(peak_field_name.ends_with("_share_ppm"));
    assert!(!peak_field_name.contains("avg"));
    assert_ne!(avg_field_name, peak_field_name);
}
