pub(crate) use super::*;

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
