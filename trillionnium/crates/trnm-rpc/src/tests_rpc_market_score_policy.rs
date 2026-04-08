use super::*;

#[test]
fn market_score_config_uses_defaults_for_empty_wrapped_env_values() {
    with_market_score_env(
        &[
            (MARKET_PRICE_WEIGHT_ENV, " '' "),
            (MARKET_REPUTATION_WEIGHT_ENV, " \"\" "),
            (MARKET_REPUTATION_CLAMP_ENV, " ` ` "),
        ],
        || {
            assert_eq!(market_effective_score(10, 5), 9_500);
        },
    );
}

#[test]
fn market_m2_policy_gate_guards_default_drift_to_min_boundaries() {
    with_market_score_env(
        &[
            (MARKET_PRICE_WEIGHT_ENV, "''"),
            (MARKET_REPUTATION_WEIGHT_ENV, "0"),
            (MARKET_REPUTATION_CLAMP_ENV, "0"),
        ],
        || {
            let cfg = market_score_config();
            assert_eq!(cfg.price_weight, MARKET_PRICE_WEIGHT_DEFAULT);
            assert_eq!(cfg.reputation_weight, MARKET_WEIGHT_MIN);
            assert_eq!(cfg.reputation_clamp, MARKET_REPUTATION_CLAMP_MIN);
        },
    );
}

#[test]
fn market_score_config_output_normalizes_clamp_before_reporting_max_delta() {
    with_market_score_env(
        &[
            (MARKET_PRICE_WEIGHT_ENV, "7"),
            (MARKET_REPUTATION_WEIGHT_ENV, "11"),
            (MARKET_REPUTATION_CLAMP_ENV, "0"),
        ],
        || {
            let output = MarketScoreConfigOutput::from(market_score_config());
            assert_eq!(output.price_weight, 7);
            assert_eq!(output.reputation_weight, 11);
            assert_eq!(output.reputation_clamp, MARKET_REPUTATION_CLAMP_MIN);
            assert_eq!(
                output.max_reputation_score_delta,
                (MARKET_REPUTATION_CLAMP_MIN as u128) * 11
            );
            assert_eq!(
                output.min_reputation_score_delta,
                -(((MARKET_REPUTATION_CLAMP_MIN as u128) * 11) as i128)
            );
        },
    );
}

#[test]
fn market_score_config_parses_nested_wrapped_weight_envs_and_fail_closed_clamp_floor() {
    with_market_score_env(
        &[
            (MARKET_PRICE_WEIGHT_ENV, " '7' "),
            (MARKET_REPUTATION_WEIGHT_ENV, " \"11\" "),
            (MARKET_REPUTATION_CLAMP_ENV, " ' \"-2\" ' "),
        ],
        || {
            let cfg = market_score_config();
            assert_eq!(cfg.price_weight, 7);
            assert_eq!(cfg.reputation_weight, 11);
            assert_eq!(cfg.reputation_clamp, MARKET_REPUTATION_CLAMP_MIN);

            let output = MarketScoreConfigOutput::from(cfg);
            assert_eq!(output.reputation_clamp, MARKET_REPUTATION_CLAMP_MIN);
            assert_eq!(output.max_reputation_score_delta, 11);
            assert_eq!(output.min_reputation_score_delta, -11);
        },
    );
}

#[test]
fn market_score_config_output_fail_closed_clamps_manual_reputation_ceiling() {
    let output = MarketScoreConfigOutput::from(MarketScoreConfig {
        price_weight: 7,
        reputation_weight: 11,
        reputation_clamp: MARKET_REPUTATION_CLAMP_MAX + 123,
    });

    assert_eq!(output.price_weight, 7);
    assert_eq!(output.reputation_weight, 11);
    assert_eq!(output.reputation_clamp, MARKET_REPUTATION_CLAMP_MAX);
    assert_eq!(output.max_effective_reputation, MARKET_REPUTATION_CLAMP_MAX);
    assert_eq!(output.min_effective_reputation, -MARKET_REPUTATION_CLAMP_MAX);
    assert_eq!(
        output.max_reputation_score_delta,
        (MARKET_REPUTATION_CLAMP_MAX as u128) * 11
    );
    assert_eq!(
        output.min_reputation_score_delta,
        -(((MARKET_REPUTATION_CLAMP_MAX as u128) * 11) as i128)
    );
}
