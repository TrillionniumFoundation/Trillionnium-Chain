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
fn market_score_breakdown_does_not_mark_floor_when_reward_exactly_matches_base_score() {
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
            assert!(!breakdown.score_floor_applied);
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
