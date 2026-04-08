use super::*;

#[test]
fn auth_nonce_tracking_is_scoped_per_height() {
    let mut last_nonce = HashMap::new();
    let mut accepted = Vec::new();
    let mut reject_stats = AuthRejectStats::default();

    let vote_h10 = BftVote {
        validator: "v1".into(),
        vote_type: VoteType::Prevote,
        block_hash: "h10".into(),
        byzantine: false,
        height: 10,
        round: 0,
    };
    accept_signed_vote(
        SignedVote {
            vote: vote_h10.clone(),
            nonce: 9_999,
            signature: vote_signature(&vote_h10, 9_999),
        },
        &mut last_nonce,
        &mut accepted,
        &mut reject_stats,
    );

    let vote_h11 = BftVote {
        validator: "v1".into(),
        vote_type: VoteType::Prevote,
        block_hash: "h11".into(),
        byzantine: false,
        height: 11,
        round: 0,
    };
    accept_signed_vote(
        SignedVote {
            vote: vote_h11.clone(),
            nonce: 1,
            signature: vote_signature(&vote_h11, 1),
        },
        &mut last_nonce,
        &mut accepted,
        &mut reject_stats,
    );

    assert_eq!(accepted.len(), 2);
    assert_eq!(reject_stats.bad_sig, 0);
    assert_eq!(reject_stats.replay, 0);
    assert_eq!(reject_stats.stale_nonce, 0);
}

#[test]
fn auth_nonce_tracking_is_scoped_per_round() {
    let mut last_nonce = HashMap::new();
    let mut accepted = Vec::new();
    let mut reject_stats = AuthRejectStats::default();

    let vote_r0 = BftVote {
        validator: "v1".into(),
        vote_type: VoteType::Prevote,
        block_hash: "h10-r0".into(),
        byzantine: false,
        height: 10,
        round: 0,
    };
    accept_signed_vote(
        SignedVote {
            vote: vote_r0.clone(),
            nonce: 9_999,
            signature: vote_signature(&vote_r0, 9_999),
        },
        &mut last_nonce,
        &mut accepted,
        &mut reject_stats,
    );

    let vote_r1 = BftVote {
        validator: "v1".into(),
        vote_type: VoteType::Prevote,
        block_hash: "h10-r1".into(),
        byzantine: false,
        height: 10,
        round: 1,
    };
    accept_signed_vote(
        SignedVote {
            vote: vote_r1.clone(),
            nonce: 1,
            signature: vote_signature(&vote_r1, 1),
        },
        &mut last_nonce,
        &mut accepted,
        &mut reject_stats,
    );

    assert_eq!(accepted.len(), 2);
    assert_eq!(reject_stats.bad_sig, 0);
    assert_eq!(reject_stats.replay, 0);
    assert_eq!(reject_stats.stale_nonce, 0);
}

#[test]
fn auth_nonce_tracking_is_scoped_per_vote_type() {
    let mut last_nonce = HashMap::new();
    let mut accepted = Vec::new();
    let mut reject_stats = AuthRejectStats::default();

    let prevote = BftVote {
        validator: "v1".into(),
        vote_type: VoteType::Prevote,
        block_hash: "h10-r0".into(),
        byzantine: false,
        height: 10,
        round: 0,
    };
    accept_signed_vote(
        SignedVote {
            vote: prevote.clone(),
            nonce: 10,
            signature: vote_signature(&prevote, 10),
        },
        &mut last_nonce,
        &mut accepted,
        &mut reject_stats,
    );

    let precommit = BftVote {
        validator: "v1".into(),
        vote_type: VoteType::Precommit,
        block_hash: "h10-r0".into(),
        byzantine: false,
        height: 10,
        round: 0,
    };
    // Reusing a lower nonce across vote types must be accepted: replay domain is
    // (validator, height, round, vote_type), not a cross-type global counter.
    accept_signed_vote(
        SignedVote {
            vote: precommit.clone(),
            nonce: 1,
            signature: vote_signature(&precommit, 1),
        },
        &mut last_nonce,
        &mut accepted,
        &mut reject_stats,
    );

    assert_eq!(accepted.len(), 2);
    assert_eq!(reject_stats.bad_sig, 0);
    assert_eq!(reject_stats.replay, 0);
    assert_eq!(reject_stats.stale_nonce, 0);
}
