use serde::{Deserialize, Serialize};

/// Minimal M2 reputation + penalty model (basis points).
///
/// Goal: provide a deterministic, auditable score contract that can be reused
/// by matching/routing logic without coupling to chain state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MarketReputationInput {
    /// Successful task completion rate in bps [0, 10000].
    pub success_rate_bps: u16,
    /// Timeout rate in bps [0, 10000].
    pub timeout_rate_bps: u16,
    /// Dispute rate in bps [0, 10000].
    pub dispute_rate_bps: u16,
    /// Count of recent penalty/slash events in the scoring window.
    pub penalty_events: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReputationTier {
    Trusted,
    Watch,
    Restricted,
}

/// Compute an auditable reputation score in bps [0, 10000].
///
/// Penalty policy (M2 MVP):
/// - timeout weight = 1x
/// - dispute weight = 2x
/// - each penalty event = 200 bps deduction
pub fn compute_reputation_score_bps(input: MarketReputationInput) -> u16 {
    let success = input.success_rate_bps.min(10_000) as i32;
    let timeout = input.timeout_rate_bps.min(10_000) as i32;
    let dispute = input.dispute_rate_bps.min(10_000) as i32;
    let penalties = (input.penalty_events as i32) * 200;

    let score = success - timeout - (2 * dispute) - penalties;
    score.clamp(0, 10_000) as u16
}

/// Tiering contract for M2 routing/policy.
pub fn classify_reputation_tier(score_bps: u16) -> ReputationTier {
    match score_bps {
        8_000..=10_000 => ReputationTier::Trusted,
        5_000..=7_999 => ReputationTier::Watch,
        _ => ReputationTier::Restricted,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reputation_score_is_clamped_to_zero() {
        let score = compute_reputation_score_bps(MarketReputationInput {
            success_rate_bps: 500,
            timeout_rate_bps: 9_000,
            dispute_rate_bps: 5_000,
            penalty_events: 10,
        });
        assert_eq!(score, 0);
    }

    #[test]
    fn reputation_score_penalty_events_reduce_score_monotonically() {
        let base = compute_reputation_score_bps(MarketReputationInput {
            success_rate_bps: 9_500,
            timeout_rate_bps: 200,
            dispute_rate_bps: 100,
            penalty_events: 0,
        });
        let penalized = compute_reputation_score_bps(MarketReputationInput {
            success_rate_bps: 9_500,
            timeout_rate_bps: 200,
            dispute_rate_bps: 100,
            penalty_events: 3,
        });
        assert!(penalized < base);
    }

    #[test]
    fn reputation_tier_thresholds_are_stable() {
        assert_eq!(classify_reputation_tier(8_000), ReputationTier::Trusted);
        assert_eq!(classify_reputation_tier(7_999), ReputationTier::Watch);
        assert_eq!(classify_reputation_tier(5_000), ReputationTier::Watch);
        assert_eq!(classify_reputation_tier(4_999), ReputationTier::Restricted);
    }

    #[test]
    fn reputation_score_clamps_input_rates_above_bps_ceiling() {
        let score = compute_reputation_score_bps(MarketReputationInput {
            success_rate_bps: u16::MAX,
            timeout_rate_bps: u16::MAX,
            dispute_rate_bps: u16::MAX,
            penalty_events: 0,
        });

        // 10_000 - 10_000 - 2*10_000 would be negative before clamping.
        assert_eq!(score, 0);
    }

    #[test]
    fn reputation_score_never_exceeds_bps_ceiling() {
        let score = compute_reputation_score_bps(MarketReputationInput {
            success_rate_bps: u16::MAX,
            timeout_rate_bps: 0,
            dispute_rate_bps: 0,
            penalty_events: 0,
        });

        assert_eq!(score, 10_000);
        assert_eq!(classify_reputation_tier(score), ReputationTier::Trusted);
    }
}
