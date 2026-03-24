pub(crate) use super::*;

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
