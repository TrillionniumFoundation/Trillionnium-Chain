use super::*;

#[test]
fn market_effective_score_rewards_higher_reputation() {
    with_market_score_env(
        &[
            (MARKET_PRICE_WEIGHT_ENV, "1000"),
            (MARKET_REPUTATION_WEIGHT_ENV, "100"),
            (MARKET_REPUTATION_CLAMP_ENV, "1000"),
        ],
        || {
            let low_rep = market_effective_score(100, 0);
            let high_rep = market_effective_score(100, 80);
            assert!(high_rep < low_rep);
        },
    );
}

#[test]
fn market_effective_score_penalizes_negative_reputation() {
    with_market_score_env(
        &[
            (MARKET_PRICE_WEIGHT_ENV, "1000"),
            (MARKET_REPUTATION_WEIGHT_ENV, "100"),
            (MARKET_REPUTATION_CLAMP_ENV, "1000"),
        ],
        || {
            let neutral = market_effective_score(100, 0);
            let penalized = market_effective_score(100, -50);
            assert!(penalized > neutral);
        },
    );
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
fn market_score_breakdown_marks_when_positive_reputation_floors_effective_score() {
    with_market_score_env(
        &[
            (MARKET_PRICE_WEIGHT_ENV, "1"),
            (MARKET_REPUTATION_WEIGHT_ENV, "10"),
            (MARKET_REPUTATION_CLAMP_ENV, "1000"),
        ],
        || {
            let breakdown = market_score_breakdown(5, 1, market_score_config());
            assert_eq!(breakdown.base_score, 5);
            assert_eq!(breakdown.reputation_reward, 10);
            assert_eq!(breakdown.effective_score, 0);
            assert!(breakdown.score_floor_applied);
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
