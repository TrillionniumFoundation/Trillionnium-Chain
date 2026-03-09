use trnm_types::{
    classify_reputation_tier, compute_reputation_score_bps, MarketReputationInput, ReputationTier,
};

#[test]
fn m2_reputation_score_clamps_to_upper_bound_and_stays_trusted() {
    let score = compute_reputation_score_bps(MarketReputationInput {
        success_rate_bps: u16::MAX,
        timeout_rate_bps: 0,
        dispute_rate_bps: 0,
        penalty_events: 0,
    });

    assert_eq!(score, 10_000, "score must clamp to 10000 bps ceiling");
    assert_eq!(
        classify_reputation_tier(score),
        ReputationTier::Trusted,
        "ceiling score must remain in trusted routing tier"
    );
}
