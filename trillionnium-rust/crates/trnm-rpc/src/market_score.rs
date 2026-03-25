use serde::Serialize;

use crate::envpaths::{env_i64_clamped, env_u128_clamped};
use crate::{
    MARKET_PRICE_WEIGHT_DEFAULT, MARKET_PRICE_WEIGHT_ENV, MARKET_REPUTATION_CLAMP_DEFAULT,
    MARKET_REPUTATION_CLAMP_ENV, MARKET_REPUTATION_CLAMP_MAX, MARKET_REPUTATION_CLAMP_MIN,
    MARKET_REPUTATION_WEIGHT_DEFAULT, MARKET_REPUTATION_WEIGHT_ENV, MARKET_WEIGHT_MAX,
    MARKET_WEIGHT_MIN,
};

#[derive(Debug, Clone, Copy)]
pub(crate) struct MarketScoreConfig {
    pub(crate) price_weight: u128,
    pub(crate) reputation_weight: u128,
    pub(crate) reputation_clamp: i64,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct MarketScoreConfigOutput {
    pub(crate) price_weight: u128,
    pub(crate) reputation_weight: u128,
    pub(crate) reputation_clamp: i64,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct MarketScoreBreakdown {
    pub(crate) effective_reputation: i64,
    pub(crate) base_score: u128,
    pub(crate) reputation_reward: u128,
    pub(crate) penalty: u128,
    pub(crate) effective_score: u128,
    pub(crate) score_floor_applied: bool,
}

impl From<MarketScoreConfig> for MarketScoreConfigOutput {
    fn from(value: MarketScoreConfig) -> Self {
        Self {
            price_weight: value.price_weight,
            reputation_weight: value.reputation_weight,
            reputation_clamp: normalized_reputation_clamp(value.reputation_clamp),
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

fn normalized_reputation_clamp(clamp: i64) -> i64 {
    clamp.max(MARKET_REPUTATION_CLAMP_MIN)
}

pub(crate) fn clamp_reputation_for_market(reputation: i64, cfg: MarketScoreConfig) -> i64 {
    let clamp = normalized_reputation_clamp(cfg.reputation_clamp);
    reputation.clamp(-clamp, clamp)
}

pub(crate) fn market_score_breakdown(
    price: u128,
    reputation: i64,
    cfg: MarketScoreConfig,
) -> MarketScoreBreakdown {
    let effective_reputation = clamp_reputation_for_market(reputation, cfg);
    let base_score = price.saturating_mul(cfg.price_weight);
    if effective_reputation >= 0 {
        let reputation_reward = (effective_reputation as u128).saturating_mul(cfg.reputation_weight);
        let score_floor_applied = reputation_reward > base_score;
        MarketScoreBreakdown {
            effective_reputation,
            base_score,
            reputation_reward,
            penalty: 0,
            effective_score: base_score.saturating_sub(reputation_reward),
            score_floor_applied,
        }
    } else {
        let penalty = (effective_reputation.unsigned_abs() as u128)
            .saturating_mul(cfg.reputation_weight);
        MarketScoreBreakdown {
            effective_reputation,
            base_score,
            reputation_reward: 0,
            penalty,
            effective_score: base_score.saturating_add(penalty),
            score_floor_applied: false,
        }
    }
}

pub(crate) fn market_effective_score_with_config(
    price: u128,
    reputation: i64,
    cfg: MarketScoreConfig,
) -> u128 {
    market_score_breakdown(price, reputation, cfg).effective_score
}

#[cfg(test)]
pub(crate) fn market_effective_score(price: u128, reputation: i64) -> u128 {
    market_effective_score_with_config(price, reputation, market_score_config())
}
