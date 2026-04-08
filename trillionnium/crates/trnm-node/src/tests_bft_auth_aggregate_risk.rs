use super::*;

#[test]
fn auth_rejects_same_nonce_equivocation_as_nonce_equivocation_not_replay() {
    let mut last_nonce = HashMap::new();
    let mut accepted = Vec::new();
    let mut reject_stats = AuthRejectStats::default();

    let vote1 = BftVote {
        validator: "v1".into(),
        vote_type: VoteType::Prevote,
        block_hash: "h10-r0-a".into(),
        byzantine: false,
        height: 10,
        round: 0,
    };
    let nonce = 77;
    accept_signed_vote(
        SignedVote {
            vote: vote1.clone(),
            nonce,
            signature: vote_signature(&vote1, nonce),
        },
        &mut last_nonce,
        &mut accepted,
        &mut reject_stats,
    );

    let vote2 = BftVote {
        validator: "v1".into(),
        vote_type: VoteType::Prevote,
        block_hash: "h10-r0-b".into(),
        byzantine: false,
        height: 10,
        round: 0,
    };
    accept_signed_vote(
        SignedVote {
            vote: vote2.clone(),
            nonce,
            signature: vote_signature(&vote2, nonce),
        },
        &mut last_nonce,
        &mut accepted,
        &mut reject_stats,
    );

    assert_eq!(accepted.len(), 1);
    assert_eq!(reject_stats.bad_sig, 1);
    assert_eq!(reject_stats.replay, 0);
    assert_eq!(reject_stats.stale_nonce, 0);
    let key = ("v1".to_string(), 10, 0, VoteType::Prevote);
    assert_eq!(last_nonce.get(&key), Some(&nonce));
}
