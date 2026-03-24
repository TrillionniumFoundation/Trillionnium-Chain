use super::*;

#[test]
fn finality_budget_share_helper_matches_round_change_density_semantics() {
    let bft_round_change_density_avg_milli = 2_500u64;
    let finality_avg = 10u128;

    assert_eq!(
        finality_budget_share_ppm(bft_round_change_density_avg_milli, finality_avg),
        250_000
    );
}

#[test]
fn finality_budget_share_helper_saturates_huge_finality_budgets_without_overflow() {
    let bft_round_change_density_avg_milli = 2_500u64;
    let finality_avg = (u64::MAX as u128) + 1;

    assert_eq!(
        finality_budget_share_ppm(bft_round_change_density_avg_milli, finality_avg),
        0
    );
}

#[test]
fn ratio_helpers_saturate_huge_metric_inputs_without_overflow() {
    assert_eq!(ratio_ppm_u64(u64::MAX, 1), u64::MAX);
    assert_eq!(ratio_milli_u64(u64::MAX, 1), u64::MAX);
    assert_eq!(ratio_percent_bps(u128::MAX, 1), u128::MAX);
    assert_eq!(ratio_ppm(u128::MAX, 1), u128::MAX);
}
