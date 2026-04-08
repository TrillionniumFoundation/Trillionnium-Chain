pub(crate) use super::*;

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
