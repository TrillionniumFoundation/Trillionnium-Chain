pub(crate) use super::*;

#[test]
fn market_worker_tie_break_key_normalizes_case_and_whitespace() {
    assert_eq!(market_worker_tie_break_key(" Worker-A "), "worker-a");
    assert_eq!(market_worker_tie_break_key("worker-Z"), "worker-z");
}

#[test]
fn market_effective_score_rewards_higher_reputation() {
    let low_rep = market_effective_score(100, 0);
    let high_rep = market_effective_score(100, 80);
    assert!(high_rep < low_rep);
}

#[test]
fn market_effective_score_penalizes_negative_reputation() {
    let neutral = market_effective_score(100, 0);
    let penalized = market_effective_score(100, -50);
    assert!(penalized > neutral);
}

#[test]
fn market_effective_score_applies_configured_reputation_weight() {
    with_market_score_env(
        &[
            (MARKET_PRICE_WEIGHT_ENV, "1000"),
            (MARKET_REPUTATION_WEIGHT_ENV, "10"),
            (MARKET_REPUTATION_CLAMP_ENV, "1000"),
        ],
        || {
            assert_eq!(market_effective_score(101, 20), 100_800);
        },
    );
}

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
fn market_effective_score_clamps_reputation_clamp_config_to_min_boundary() {
    with_market_score_env(
        &[
            (MARKET_PRICE_WEIGHT_ENV, "1000"),
            (MARKET_REPUTATION_WEIGHT_ENV, "100"),
            (MARKET_REPUTATION_CLAMP_ENV, "0"),
        ],
        || {
            assert_eq!(market_effective_score(101, 100_000), 100_900);
        },
    );
}

#[test]
fn market_effective_score_clamps_reputation_clamp_config_to_max_boundary() {
    with_market_score_env(
        &[
            (MARKET_PRICE_WEIGHT_ENV, "1000"),
            (MARKET_REPUTATION_WEIGHT_ENV, "1"),
            (MARKET_REPUTATION_CLAMP_ENV, "9999999"),
        ],
        || {
            assert_eq!(market_effective_score(101, 2_000_000), 0);
        },
    );
}

#[test]
fn market_effective_score_clamps_price_weight_config_to_min_boundary() {
    with_market_score_env(
        &[
            (MARKET_PRICE_WEIGHT_ENV, "0"),
            (MARKET_REPUTATION_WEIGHT_ENV, "1"),
            (MARKET_REPUTATION_CLAMP_ENV, "1000"),
        ],
        || {
            assert_eq!(market_effective_score(2, 0), 2);
        },
    );
}

#[test]
fn market_effective_score_clamps_reputation_weight_config_to_min_boundary() {
    with_market_score_env(
        &[
            (MARKET_PRICE_WEIGHT_ENV, "1000"),
            (MARKET_REPUTATION_WEIGHT_ENV, "0"),
            (MARKET_REPUTATION_CLAMP_ENV, "1000"),
        ],
        || {
            assert_eq!(market_effective_score(2, 5), 1995);
        },
    );
}

#[test]
fn market_effective_score_clamps_reputation_weight_config_to_max_boundary() {
    with_market_score_env(
        &[
            (MARKET_PRICE_WEIGHT_ENV, "1"),
            (MARKET_REPUTATION_WEIGHT_ENV, "999999999"),
            (MARKET_REPUTATION_CLAMP_ENV, "1000"),
        ],
        || {
            assert_eq!(market_effective_score(1, -2000), 1_000_000_001);
        },
    );
}

#[test]
fn market_effective_score_clamps_price_weight_config_to_max_boundary() {
    with_market_score_env(
        &[
            (MARKET_PRICE_WEIGHT_ENV, "999999999"),
            (MARKET_REPUTATION_WEIGHT_ENV, "1"),
            (MARKET_REPUTATION_CLAMP_ENV, "1000"),
        ],
        || {
            assert_eq!(market_effective_score(2, 0), 2_000_000);
        },
    );
}

#[test]
fn market_score_breakdown_marks_floor_when_reward_exactly_matches_base_score() {
    with_market_score_env(
        &[
            (MARKET_PRICE_WEIGHT_ENV, "1"),
            (MARKET_REPUTATION_WEIGHT_ENV, "5"),
            (MARKET_REPUTATION_CLAMP_ENV, "1000"),
        ],
        || {
            let breakdown = market_score_breakdown(5, 1, market_score_config());
            assert_eq!(breakdown.base_score, 5);
            assert_eq!(breakdown.reputation_reward, 5);
            assert_eq!(breakdown.effective_score, 0);
            assert!(breakdown.score_floor_applied);
        },
    );
}

#[test]
fn market_score_breakdown_saturates_penalty_path_at_u128_max() {
    let breakdown = market_score_breakdown(
        u128::MAX,
        -1,
        MarketScoreConfig {
            price_weight: 2,
            reputation_weight: u128::MAX,
            reputation_clamp: 1,
        },
    );

    assert_eq!(breakdown.effective_reputation, -1);
    assert_eq!(breakdown.base_score, u128::MAX);
    assert_eq!(breakdown.penalty, u128::MAX);
    assert_eq!(breakdown.effective_score, u128::MAX);
    assert_eq!(breakdown.reputation_reward, 0);
    assert!(!breakdown.score_floor_applied);
}

#[test]
fn market_score_breakdown_saturates_reward_path_at_zero_and_marks_floor() {
    let breakdown = market_score_breakdown(
        1,
        2,
        MarketScoreConfig {
            price_weight: 1,
            reputation_weight: u128::MAX,
            reputation_clamp: 2,
        },
    );

    assert_eq!(breakdown.effective_reputation, 2);
    assert_eq!(breakdown.base_score, 1);
    assert_eq!(breakdown.reputation_reward, u128::MAX);
    assert_eq!(breakdown.penalty, 0);
    assert_eq!(breakdown.effective_score, 0);
    assert!(breakdown.score_floor_applied);
}

#[test]
fn clamp_reputation_for_market_normalizes_negative_manual_clamp_to_fail_closed_minimum() {
    let cfg = MarketScoreConfig {
        price_weight: 3,
        reputation_weight: 7,
        reputation_clamp: -10,
    };

    assert_eq!(clamp_reputation_for_market(250, cfg), 1);
    assert_eq!(clamp_reputation_for_market(-250, cfg), -1);
}

#[test]
fn market_score_breakdown_normalizes_negative_manual_clamp_without_panic() {
    let breakdown = market_score_breakdown(
        50,
        250,
        MarketScoreConfig {
            price_weight: 3,
            reputation_weight: 7,
            reputation_clamp: -10,
        },
    );

    assert_eq!(breakdown.effective_reputation, 1);
    assert_eq!(breakdown.base_score, 150);
    assert_eq!(breakdown.reputation_reward, 7);
    assert_eq!(breakdown.effective_score, 143);
    assert_eq!(breakdown.penalty, 0);
    assert!(!breakdown.score_floor_applied);
}

#[test]
fn market_score_config_output_normalizes_negative_manual_clamp_to_fail_closed_minimum() {
    let output = MarketScoreConfigOutput::from(MarketScoreConfig {
        price_weight: 3,
        reputation_weight: 7,
        reputation_clamp: -10,
    });

    assert_eq!(output.price_weight, 3);
    assert_eq!(output.reputation_weight, 7);
    assert_eq!(output.reputation_clamp, 1);
    assert_eq!(output.max_reputation_score_delta, 7);
    assert_eq!(output.min_reputation_score_delta, -7);
}

#[test]
fn market_score_config_output_normalizes_zero_manual_clamp_to_symmetric_fail_closed_bounds() {
    let output = MarketScoreConfigOutput::from(MarketScoreConfig {
        price_weight: 5,
        reputation_weight: 11,
        reputation_clamp: 0,
    });

    assert_eq!(output.price_weight, 5);
    assert_eq!(output.reputation_weight, 11);
    assert_eq!(output.reputation_clamp, MARKET_REPUTATION_CLAMP_MIN);
    assert_eq!(output.max_effective_reputation, MARKET_REPUTATION_CLAMP_MIN);
    assert_eq!(output.min_effective_reputation, -MARKET_REPUTATION_CLAMP_MIN);
    assert_eq!(output.max_reputation_score_delta, 11);
    assert_eq!(output.min_reputation_score_delta, -11);
}

#[test]
fn market_score_config_output_saturates_max_reputation_score_delta_without_wrapping() {
    let output = MarketScoreConfigOutput::from(MarketScoreConfig {
        price_weight: 1,
        reputation_weight: u128::MAX,
        reputation_clamp: i64::MAX,
    });

    assert_eq!(output.price_weight, 1);
    assert_eq!(output.reputation_weight, u128::MAX);
    assert_eq!(output.reputation_clamp, i64::MAX);
    assert_eq!(output.max_reputation_score_delta, u128::MAX);
    assert_eq!(output.min_reputation_score_delta, i128::MIN);
}

#[test]
fn market_reputation_score_delta_saturates_positive_reward_at_i128_min() {
    let breakdown = MarketScoreBreakdown {
        effective_reputation: 1,
        base_score: 1,
        reputation_reward: u128::MAX,
        penalty: 0,
        effective_score: 0,
        score_floor_applied: true,
    };

    assert_eq!(market_reputation_score_delta(&breakdown), i128::MIN);
}

#[test]
fn market_reputation_score_delta_saturates_negative_penalty_at_i128_max() {
    let breakdown = MarketScoreBreakdown {
        effective_reputation: -1,
        base_score: 1,
        reputation_reward: 0,
        penalty: u128::MAX,
        effective_score: u128::MAX,
        score_floor_applied: false,
    };

    assert_eq!(market_reputation_score_delta(&breakdown), i128::MAX);
}

#[test]
fn market_reputation_score_delta_uses_breakdown_effective_reputation_sign_fail_closed() {
    let reward_breakdown = MarketScoreBreakdown {
        effective_reputation: 3,
        base_score: 100,
        reputation_reward: 21,
        penalty: 999,
        effective_score: 79,
        score_floor_applied: false,
    };
    assert_eq!(market_reputation_score_delta(&reward_breakdown), -21);

    let penalty_breakdown = MarketScoreBreakdown {
        effective_reputation: -3,
        base_score: 100,
        reputation_reward: 999,
        penalty: 21,
        effective_score: 121,
        score_floor_applied: false,
    };
    assert_eq!(market_reputation_score_delta(&penalty_breakdown), 21);
}

#[test]
fn market_reputation_score_delta_treats_zero_effective_reputation_as_neutral() {
    let neutral_breakdown = MarketScoreBreakdown {
        effective_reputation: 0,
        base_score: 100,
        reputation_reward: 21,
        penalty: 21,
        effective_score: 100,
        score_floor_applied: false,
    };

    assert_eq!(market_reputation_score_delta(&neutral_breakdown), 0);
}

#[test]
fn market_score_breakdown_treats_zero_effective_reputation_as_neutral() {
    let breakdown = market_score_breakdown(
        50,
        0,
        MarketScoreConfig {
            price_weight: 3,
            reputation_weight: 7,
            reputation_clamp: 10,
        },
    );

    assert_eq!(breakdown.effective_reputation, 0);
    assert_eq!(breakdown.base_score, 150);
    assert_eq!(breakdown.reputation_reward, 0);
    assert_eq!(breakdown.penalty, 0);
    assert_eq!(breakdown.effective_score, 150);
    assert!(!breakdown.score_floor_applied);
}

#[test]
fn market_score_breakdown_uses_clamped_negative_reputation_for_penalty() {
    let breakdown = market_score_breakdown(
        50,
        -250,
        MarketScoreConfig {
            price_weight: 3,
            reputation_weight: 7,
            reputation_clamp: 10,
        },
    );

    assert_eq!(breakdown.effective_reputation, -10);
    assert_eq!(breakdown.base_score, 150);
    assert_eq!(breakdown.penalty, 70);
    assert_eq!(breakdown.effective_score, 220);
    assert_eq!(breakdown.reputation_reward, 0);
    assert!(!breakdown.score_floor_applied);
}

#[test]
fn market_score_breakdown_uses_clamped_positive_reputation_for_reward() {
    let breakdown = market_score_breakdown(
        50,
        250,
        MarketScoreConfig {
            price_weight: 3,
            reputation_weight: 7,
            reputation_clamp: 10,
        },
    );

    assert_eq!(breakdown.effective_reputation, 10);
    assert_eq!(breakdown.base_score, 150);
    assert_eq!(breakdown.reputation_reward, 70);
    assert_eq!(breakdown.effective_score, 80);
    assert_eq!(breakdown.penalty, 0);
    assert!(!breakdown.score_floor_applied);
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
