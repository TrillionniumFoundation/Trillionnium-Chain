use super::*;

#[test]
fn proposer_selection_skips_penalized_or_missed_leader() {
    let control = BftJitterControl {
        missed_threshold: 2,
        penalty_rounds: 2,
        round_change_backoff_ms: 5,
        round_change_backoff_cap_ms: 40,
        leader_health: vec![
            LeaderHealth {
                missed_proposals: 3,
                penalty_until_round: 5,
            },
            LeaderHealth::default(),
            LeaderHealth::default(),
            LeaderHealth::default(),
        ],
    };

    let (idx, shifted) = select_proposer(1, 1, &control, 4); // base proposer is v3(index=2)
    assert_eq!(idx, 2);
    assert!(!shifted);

    let (idx2, shifted2) = select_proposer(4, 0, &control, 4); // base proposer is v1(index=0), should be skipped
    assert_eq!(idx2, 1);
    assert!(shifted2);
}
