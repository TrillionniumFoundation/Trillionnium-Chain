use super::*;

#[test]
fn market_score_config_output_reports_symmetric_fail_closed_reputation_bounds() {
    with_market_score_env(
        &[
            (MARKET_PRICE_WEIGHT_ENV, "7"),
            (MARKET_REPUTATION_WEIGHT_ENV, "11"),
            (MARKET_REPUTATION_CLAMP_ENV, " '0' "),
        ],
        || {
            let cfg = market_score_config();
            let output = MarketScoreConfigOutput::from(cfg);

            assert_eq!(output.reputation_clamp, MARKET_REPUTATION_CLAMP_MIN);
            assert_eq!(output.max_effective_reputation, output.reputation_clamp);
            assert_eq!(output.min_effective_reputation, -output.reputation_clamp);
            assert_eq!(
                clamp_reputation_for_market(i64::MAX, cfg),
                output.max_effective_reputation
            );
            assert_eq!(
                clamp_reputation_for_market(i64::MIN, cfg),
                output.min_effective_reputation
            );
        },
    );
}

#[test]
fn market_score_surface_keeps_zero_effective_reputation_delta_neutral() {
    with_market_score_env(
        &[
            (MARKET_PRICE_WEIGHT_ENV, "13"),
            (MARKET_REPUTATION_WEIGHT_ENV, "17"),
            (MARKET_REPUTATION_CLAMP_ENV, "29"),
        ],
        || {
            let cfg = market_score_config();
            let output = MarketScoreConfigOutput::from(cfg);
            let breakdown = market_score_breakdown(41, 0, cfg);

            assert_eq!(breakdown.effective_reputation, 0);
            assert_eq!(breakdown.base_score, 533);
            assert_eq!(breakdown.reputation_reward, 0);
            assert_eq!(breakdown.penalty, 0);
            assert_eq!(breakdown.effective_score, breakdown.base_score);
            assert_eq!(market_reputation_score_delta(&breakdown), 0);
            assert!(!breakdown.score_floor_applied);

            assert!(0 <= output.max_effective_reputation);
            assert!(0 >= output.min_effective_reputation);
            assert_eq!(output.max_reputation_score_delta, 29 * 17);
            assert_eq!(output.min_reputation_score_delta, -((29_i128) * 17));
        },
    );
}
