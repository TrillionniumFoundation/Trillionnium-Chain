use super::*;

#[test]
fn auth_rejects_zero_height_before_nonce_and_signature_checks() {
    let vote = BftVote {
        validator: "v1".into(),
        vote_type: VoteType::Prevote,
        block_hash: "h1".into(),
        byzantine: false,
        height: 0,
        round: 0,
    };

    let mut last_nonce = HashMap::new();
    let mut accepted = Vec::new();
    let mut reject_stats = AuthRejectStats::default();

    accept_signed_vote(
        SignedVote {
            vote: vote.clone(),
            nonce: 1,
            signature: vote_signature(&vote, 1),
        },
        &mut last_nonce,
        &mut accepted,
        &mut reject_stats,
    );

    assert!(accepted.is_empty());
    assert_eq!(reject_stats.bad_sig, 1);
    assert_eq!(reject_stats.replay, 0);
    assert_eq!(reject_stats.stale_nonce, 0);
    assert!(last_nonce.is_empty());
}
