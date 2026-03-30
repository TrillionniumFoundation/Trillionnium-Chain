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

#[derive(Debug, Clone, Serialize)]
pub(crate) struct MarketScoreConfigOutput {
    pub(crate) price_weight: u128,
    pub(crate) reputation_weight: u128,
    pub(crate) reputation_clamp: i64,
    pub(crate) max_effective_reputation: i64,
    pub(crate) min_effective_reputation: i64,
    pub(crate) max_reputation_score_delta: u128,
    pub(crate) min_reputation_score_delta: i128,
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

fn saturated_negative_i128(value: u128) -> i128 {
    if value >= (i128::MAX as u128) + 1 {
        i128::MIN
    } else {
        -(value as i128)
    }
}

impl From<MarketScoreConfig> for MarketScoreConfigOutput {
    fn from(value: MarketScoreConfig) -> Self {
        let reputation_clamp = normalized_reputation_clamp(value.reputation_clamp);
        let max_reputation_score_delta = (reputation_clamp as u128)
            .saturating_mul(value.reputation_weight);
        Self {
            price_weight: value.price_weight,
            reputation_weight: value.reputation_weight,
            reputation_clamp,
            max_effective_reputation: reputation_clamp,
            min_effective_reputation: -reputation_clamp,
            max_reputation_score_delta,
            min_reputation_score_delta: saturated_negative_i128(max_reputation_score_delta),
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
    clamp.clamp(MARKET_REPUTATION_CLAMP_MIN, MARKET_REPUTATION_CLAMP_MAX)
}

pub(crate) fn clamp_reputation_for_market(reputation: i64, cfg: MarketScoreConfig) -> i64 {
    let clamp = normalized_reputation_clamp(cfg.reputation_clamp);
    reputation.clamp(-clamp, clamp)
}

pub(crate) fn market_reputation_score_delta(breakdown: &MarketScoreBreakdown) -> i128 {
    if breakdown.effective_reputation > 0 {
        saturated_negative_i128(breakdown.reputation_reward)
    } else if breakdown.effective_reputation < 0 {
        breakdown.penalty.min(i128::MAX as u128) as i128
    } else {
        0
    }
}

pub(crate) fn market_reputation_component_applied(breakdown: &MarketScoreBreakdown) -> u128 {
    if breakdown.effective_reputation < 0 {
        breakdown.penalty
    } else if breakdown.effective_reputation > 0 {
        breakdown.reputation_reward
    } else {
        0
    }
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
        let score_floor_applied = effective_reputation > 0 && reputation_reward >= base_score;
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

#[cfg(test)]
mod tests {
    use super::*;

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
    fn market_score_breakdown_keeps_zero_reputation_delta_neutral_runtime_surface() {
        let breakdown = market_score_breakdown(
            42,
            0,
            MarketScoreConfig {
                price_weight: 10,
                reputation_weight: 100,
                reputation_clamp: 25,
            },
        );

        assert_eq!(breakdown.effective_reputation, 0);
        assert_eq!(breakdown.base_score, 420);
        assert_eq!(breakdown.reputation_reward, 0);
        assert_eq!(breakdown.penalty, 0);
        assert_eq!(breakdown.effective_score, 420);
        assert_eq!(market_reputation_score_delta(&breakdown), 0);
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
        assert_eq!(output.reputation_clamp, MARKET_REPUTATION_CLAMP_MIN);
        assert_eq!(output.max_effective_reputation, MARKET_REPUTATION_CLAMP_MIN);
        assert_eq!(output.min_effective_reputation, -MARKET_REPUTATION_CLAMP_MIN);
        assert_eq!(output.max_reputation_score_delta, 7);
        assert_eq!(output.min_reputation_score_delta, -7);
    }

    #[test]
    fn market_score_config_output_reports_symmetric_fail_closed_reputation_bounds() {
        let output = MarketScoreConfigOutput::from(MarketScoreConfig {
            price_weight: 1,
            reputation_weight: 7,
            reputation_clamp: 13,
        });

        assert_eq!(output.max_effective_reputation, 13);
        assert_eq!(output.min_effective_reputation, -13);
        assert_eq!(output.max_reputation_score_delta, 91);
        assert_eq!(output.min_reputation_score_delta, -91);
    }

    #[test]
    fn market_score_config_output_saturates_min_reputation_delta_at_i128_min() {
        let output = MarketScoreConfigOutput::from(MarketScoreConfig {
            price_weight: 1,
            reputation_weight: (i128::MAX as u128) + 1,
            reputation_clamp: 1,
        });

        assert_eq!(output.max_effective_reputation, 1);
        assert_eq!(output.min_effective_reputation, -1);
        assert_eq!(output.max_reputation_score_delta, (i128::MAX as u128) + 1);
        assert_eq!(output.min_reputation_score_delta, i128::MIN);
    }

    #[test]
    fn market_score_config_output_clamps_oversized_manual_clamp_to_fail_closed_maximum() {
        let output = MarketScoreConfigOutput::from(MarketScoreConfig {
            price_weight: 2,
            reputation_weight: 3,
            reputation_clamp: MARKET_REPUTATION_CLAMP_MAX + 99,
        });

        assert_eq!(output.price_weight, 2);
        assert_eq!(output.reputation_weight, 3);
        assert_eq!(output.reputation_clamp, MARKET_REPUTATION_CLAMP_MAX);
        assert_eq!(output.max_effective_reputation, MARKET_REPUTATION_CLAMP_MAX);
        assert_eq!(output.min_effective_reputation, -MARKET_REPUTATION_CLAMP_MAX);
        assert_eq!(
            output.max_reputation_score_delta,
            (MARKET_REPUTATION_CLAMP_MAX as u128) * 3
        );
        assert_eq!(
            output.min_reputation_score_delta,
            -((MARKET_REPUTATION_CLAMP_MAX as i128) * 3)
        );
    }

    #[test]
    fn market_score_config_output_saturates_max_reputation_score_delta_without_wrapping() {
        let output = MarketScoreConfigOutput::from(MarketScoreConfig {
            price_weight: 1,
            reputation_weight: u128::MAX,
            reputation_clamp: MARKET_REPUTATION_CLAMP_MAX,
        });

        assert_eq!(output.max_effective_reputation, MARKET_REPUTATION_CLAMP_MAX);
        assert_eq!(output.min_effective_reputation, -MARKET_REPUTATION_CLAMP_MAX);
        assert_eq!(output.max_reputation_score_delta, u128::MAX);
        assert_eq!(output.min_reputation_score_delta, i128::MIN);
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
    fn market_reputation_score_delta_keeps_zero_effective_reputation_neutral() {
        let delta = market_reputation_score_delta(&MarketScoreBreakdown {
            effective_reputation: 0,
            base_score: 500,
            reputation_reward: 77,
            penalty: 88,
            effective_score: 500,
            score_floor_applied: false,
        });

        assert_eq!(delta, 0);
    }

    #[test]
    fn market_score_breakdown_keeps_zero_reputation_delta_neutral() {
        let breakdown = market_score_breakdown(
            42,
            0,
            MarketScoreConfig {
                price_weight: 10,
                reputation_weight: 100,
                reputation_clamp: 25,
            },
        );

        assert_eq!(breakdown.effective_reputation, 0);
        assert_eq!(breakdown.base_score, 420);
        assert_eq!(breakdown.reputation_reward, 0);
        assert_eq!(breakdown.penalty, 0);
        assert_eq!(breakdown.effective_score, 420);
        assert_eq!(market_reputation_score_delta(&breakdown), 0);
        assert!(!breakdown.score_floor_applied);
    }

    #[test]
    fn market_score_breakdown_keeps_zero_reputation_zero_price_neutral() {
        let breakdown = market_score_breakdown(
            0,
            0,
            MarketScoreConfig {
                price_weight: 7,
                reputation_weight: 11,
                reputation_clamp: 10,
            },
        );

        assert_eq!(breakdown.effective_reputation, 0);
        assert_eq!(breakdown.base_score, 0);
        assert_eq!(breakdown.reputation_reward, 0);
        assert_eq!(breakdown.penalty, 0);
        assert_eq!(breakdown.effective_score, 0);
        assert!(!breakdown.score_floor_applied);
        assert_eq!(market_reputation_score_delta(&breakdown), 0);
    }

    #[test]
    fn market_score_breakdown_keeps_zero_reputation_neutral_when_manual_clamp_is_invalid() {
        let breakdown = market_score_breakdown(
            9,
            0,
            MarketScoreConfig {
                price_weight: 13,
                reputation_weight: 17,
                reputation_clamp: -99,
            },
        );

        assert_eq!(breakdown.effective_reputation, 0);
        assert_eq!(breakdown.base_score, 117);
        assert_eq!(breakdown.reputation_reward, 0);
        assert_eq!(breakdown.penalty, 0);
        assert_eq!(breakdown.effective_score, 117);
        assert!(!breakdown.score_floor_applied);
        assert_eq!(market_reputation_score_delta(&breakdown), 0);
    }

    #[test]
    fn market_reputation_score_delta_saturates_positive_reward_at_i128_min() {
        let delta = market_reputation_score_delta(&MarketScoreBreakdown {
            effective_reputation: 1,
            base_score: 0,
            reputation_reward: (i128::MAX as u128) + 1,
            penalty: 0,
            effective_score: 0,
            score_floor_applied: true,
        });

        assert_eq!(delta, i128::MIN);
    }

    #[test]
    fn market_reputation_score_delta_uses_effective_reputation_sign_fail_closed() {
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
    fn market_reputation_score_delta_saturates_negative_penalty_at_i128_max() {
        let delta = market_reputation_score_delta(&MarketScoreBreakdown {
            effective_reputation: -1,
            base_score: 0,
            reputation_reward: 0,
            penalty: (i128::MAX as u128) + 1,
            effective_score: u128::MAX,
            score_floor_applied: false,
        });

        assert_eq!(delta, i128::MAX);
    }

    #[test]
    fn market_reputation_component_applied_tracks_active_adjustment_path() {
        let reward = MarketScoreBreakdown {
            effective_reputation: 4,
            base_score: 100,
            reputation_reward: 17,
            penalty: 99,
            effective_score: 83,
            score_floor_applied: false,
        };
        assert_eq!(market_reputation_component_applied(&reward), 17);

        let penalty = MarketScoreBreakdown {
            effective_reputation: -4,
            base_score: 100,
            reputation_reward: 17,
            penalty: 23,
            effective_score: 123,
            score_floor_applied: false,
        };
        assert_eq!(market_reputation_component_applied(&penalty), 23);

        let neutral = MarketScoreBreakdown {
            effective_reputation: 0,
            base_score: 100,
            reputation_reward: 17,
            penalty: 23,
            effective_score: 100,
            score_floor_applied: false,
        };
        assert_eq!(market_reputation_component_applied(&neutral), 0);
    }

    #[test]
    fn market_score_breakdown_marks_exact_floor_match_as_floor_applied() {
        let breakdown = market_score_breakdown(
            7,
            3,
            MarketScoreConfig {
                price_weight: 3,
                reputation_weight: 7,
                reputation_clamp: 10,
            },
        );

        assert_eq!(breakdown.base_score, 21);
        assert_eq!(breakdown.reputation_reward, 21);
        assert_eq!(breakdown.penalty, 0);
        assert_eq!(breakdown.effective_score, 0);
        assert!(breakdown.score_floor_applied);
        assert_eq!(market_reputation_score_delta(&breakdown), -21);
    }

    #[test]
    fn market_score_breakdown_exact_floor_match_keeps_reputation_adjustment_explainable() {
        let breakdown = market_score_breakdown(
            7,
            3,
            MarketScoreConfig {
                price_weight: 3,
                reputation_weight: 7,
                reputation_clamp: 10,
            },
        );

        assert_eq!(breakdown.base_score, 21);
        assert_eq!(breakdown.reputation_reward, 21);
        assert_eq!(breakdown.penalty, 0);
        assert_eq!(breakdown.effective_score, 0);
        assert!(breakdown.score_floor_applied);
        assert_eq!(market_reputation_score_delta(&breakdown), -21);
        assert_eq!(market_reputation_component_applied(&breakdown), 21);
    }

    #[test]
    fn market_score_breakdown_marks_zero_price_positive_reputation_as_floor_applied() {
        let breakdown = market_score_breakdown(
            0,
            5,
            MarketScoreConfig {
                price_weight: 11,
                reputation_weight: 13,
                reputation_clamp: 10,
            },
        );

        assert_eq!(breakdown.effective_reputation, 5);
        assert_eq!(breakdown.base_score, 0);
        assert_eq!(breakdown.reputation_reward, 65);
        assert_eq!(breakdown.penalty, 0);
        assert_eq!(breakdown.effective_score, 0);
        assert!(breakdown.score_floor_applied);
        assert_eq!(market_reputation_score_delta(&breakdown), -65);
    }

    #[test]
    fn market_score_breakdown_clamps_out_of_range_reputation_symmetrically() {
        let cfg = MarketScoreConfig {
            price_weight: 10,
            reputation_weight: 3,
            reputation_clamp: 5,
        };

        let reward = market_score_breakdown(20, 999, cfg);
        assert_eq!(reward.effective_reputation, 5);
        assert_eq!(reward.reputation_reward, 15);
        assert_eq!(reward.penalty, 0);
        assert_eq!(reward.effective_score, 185);
        assert_eq!(market_reputation_score_delta(&reward), -15);

        let penalty = market_score_breakdown(20, -999, cfg);
        assert_eq!(penalty.effective_reputation, -5);
        assert_eq!(penalty.reputation_reward, 0);
        assert_eq!(penalty.penalty, 15);
        assert_eq!(penalty.effective_score, 215);
        assert_eq!(market_reputation_score_delta(&penalty), 15);
    }
}
