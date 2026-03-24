use super::*;

#[test]
fn aggregate_votes_dedups_validator_duplicates_per_hash() {
    let votes = vec![
        BftVote {
            validator: "v1".into(),
            vote_type: VoteType::Prevote,
            block_hash: "h1".into(),
            byzantine: false,
            height: 7,
            round: 0,
        },
        // Same validator + same hash duplicate must not increase tally.
        BftVote {
            validator: "v1".into(),
            vote_type: VoteType::Prevote,
            block_hash: "h1".into(),
            byzantine: false,
            height: 7,
            round: 0,
        },
        BftVote {
            validator: "v2".into(),
            vote_type: VoteType::Prevote,
            block_hash: "h1".into(),
            byzantine: false,
            height: 7,
            round: 0,
        },
    ];

    let tally = aggregate_votes(&votes, VoteType::Prevote);
    assert_eq!(tally.get("h1"), Some(&2));
}
