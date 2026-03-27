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
