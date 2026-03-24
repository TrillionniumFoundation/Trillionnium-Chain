use serde::Serialize;

use super::{
    env_i64_clamped, env_u128_clamped, MARKET_PRICE_WEIGHT_DEFAULT, MARKET_PRICE_WEIGHT_ENV,
    MARKET_REPUTATION_CLAMP_DEFAULT, MARKET_REPUTATION_CLAMP_ENV, MARKET_REPUTATION_CLAMP_MAX,
    MARKET_REPUTATION_CLAMP_MIN, MARKET_REPUTATION_WEIGHT_DEFAULT, MARKET_REPUTATION_WEIGHT_ENV,
    MARKET_WEIGHT_MAX, MARKET_WEIGHT_MIN,
};

#[derive(Debug, Clone, Copy)]
pub(crate) struct MarketScoreConfig {
    pub(crate) price_weight: u128,
    pub(crate) reputation_weight: u128,
    pub(crate) reputation_clamp: i64,
}

#[derive(Debug, Serialize)]
pub(crate) struct MarketScoreConfigOutput {
    pub(crate) price_weight: u128,
    pub(crate) reputation_weight: u128,
    pub(crate) reputation_clamp: i64,
}

impl From<MarketScoreConfig> for MarketScoreConfigOutput {
    fn from(value: MarketScoreConfig) -> Self {
        Self {
            price_weight: value.price_weight,
            reputation_weight: value.reputation_weight,
            reputation_clamp: value.reputation_clamp,
        }
    }
}

pub(crate) fn market_score_config() -> MarketScoreConfig {
    MarketScoreConfig {
        price_weight: env_u128_clamped(
            MARKET_PRICE_WEIGHT_ENV,
            MARKET_PRICE_WEIGHT_DEFAULT,
            MARKET_WEIGHT_MIN,
            MARKET_WEIGHT_MAX,
        ),
        reputation_weight: env_u128_clamped(
            MARKET_REPUTATION_WEIGHT_ENV,
            MARKET_REPUTATION_WEIGHT_DEFAULT,
            MARKET_WEIGHT_MIN,
            MARKET_WEIGHT_MAX,
        ),
        reputation_clamp: env_i64_clamped(
            MARKET_REPUTATION_CLAMP_ENV,
            MARKET_REPUTATION_CLAMP_DEFAULT,
            MARKET_REPUTATION_CLAMP_MIN,
            MARKET_REPUTATION_CLAMP_MAX,
        ),
    }
}

pub(crate) fn clamp_reputation_for_market(reputation: i64, cfg: MarketScoreConfig) -> i64 {
    reputation.clamp(-cfg.reputation_clamp, cfg.reputation_clamp)
}

pub(crate) fn market_effective_score_with_config(
    price: u128,
    reputation: i64,
    cfg: MarketScoreConfig,
) -> u128 {
    let rep = clamp_reputation_for_market(reputation, cfg);
    let base = price.saturating_mul(cfg.price_weight);
    if rep >= 0 {
        base.saturating_sub((rep as u128).saturating_mul(cfg.reputation_weight))
    } else {
        base.saturating_add((rep.unsigned_abs() as u128).saturating_mul(cfg.reputation_weight))
    }
}

#[cfg(test)]
pub(crate) fn market_effective_score(price: u128, reputation: i64) -> u128 {
    market_effective_score_with_config(price, reputation, market_score_config())
}
