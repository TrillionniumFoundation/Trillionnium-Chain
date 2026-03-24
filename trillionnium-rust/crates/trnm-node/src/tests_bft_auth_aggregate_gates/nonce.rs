use super::*;

#[test]
fn auth_rejects_zero_nonce_vote_before_signature_check() {
    let vote = BftVote {
        validator: "v1".into(),
        vote_type: VoteType::Prevote,
        block_hash: "h1".into(),
        byzantine: false,
        height: 1,
        round: 0,
    };

    let mut last_nonce = HashMap::new();
    let mut accepted = Vec::new();
    let mut reject_stats = AuthRejectStats::default();

    accept_signed_vote(
        SignedVote {
            vote: vote.clone(),
            nonce: 0,
            // even with a syntactically valid signature for nonce=0, ingress must reject
            signature: vote_signature(&vote, 0),
        },
        &mut last_nonce,
        &mut accepted,
        &mut reject_stats,
    );

    assert!(accepted.is_empty());
    assert_eq!(reject_stats.bad_sig, 0);
    assert_eq!(reject_stats.replay, 0);
    assert_eq!(reject_stats.stale_nonce, 1);
    assert!(last_nonce.is_empty());
}

#[test]
fn auth_rejects_excessive_forward_nonce_jump_within_same_round_domain() {
    let mut last_nonce = HashMap::new();
    let mut accepted = Vec::new();
    let mut reject_stats = AuthRejectStats::default();

    let vote1 = BftVote {
        validator: "v1".into(),
        vote_type: VoteType::Prevote,
        block_hash: "h10-r0".into(),
        byzantine: false,
        height: 10,
        round: 0,
    };
    accept_signed_vote(
        SignedVote {
            vote: vote1.clone(),
            nonce: 10,
            signature: vote_signature(&vote1, 10),
        },
        &mut last_nonce,
        &mut accepted,
        &mut reject_stats,
    );

    let vote2 = BftVote {
        validator: "v1".into(),
        vote_type: VoteType::Prevote,
        block_hash: "h10-r0-alt".into(),
        byzantine: false,
        height: 10,
        round: 0,
    };
    let jumped_nonce = 10 + MAX_BFT_NONCE_FORWARD_JUMP + 1;
    accept_signed_vote(
        SignedVote {
            vote: vote2.clone(),
            nonce: jumped_nonce,
            signature: vote_signature(&vote2, jumped_nonce),
        },
        &mut last_nonce,
        &mut accepted,
        &mut reject_stats,
    );

    assert_eq!(accepted.len(), 1);
    assert_eq!(reject_stats.bad_sig, 0);
    assert_eq!(reject_stats.replay, 0);
    assert_eq!(reject_stats.stale_nonce, 1);

    let key = ("v1".to_string(), 10, 0, VoteType::Prevote);
    assert_eq!(last_nonce.get(&key), Some(&10));
}

#[test]
fn auth_accepts_forward_nonce_jump_at_boundary_within_same_round_domain() {
    let mut last_nonce = HashMap::new();
    let mut accepted = Vec::new();
    let mut reject_stats = AuthRejectStats::default();

    let vote1 = BftVote {
        validator: "v1".into(),
        vote_type: VoteType::Prevote,
        block_hash: "h10-r0".into(),
        byzantine: false,
        height: 10,
        round: 0,
    };
    accept_signed_vote(
        SignedVote {
            vote: vote1.clone(),
            nonce: 10,
            signature: vote_signature(&vote1, 10),
        },
        &mut last_nonce,
        &mut accepted,
        &mut reject_stats,
    );

    let vote2 = BftVote {
        validator: "v1".into(),
        vote_type: VoteType::Prevote,
        block_hash: "h10-r0-alt".into(),
        byzantine: false,
        height: 10,
        round: 0,
    };
    let boundary_nonce = 10 + MAX_BFT_NONCE_FORWARD_JUMP;
    accept_signed_vote(
        SignedVote {
            vote: vote2.clone(),
            nonce: boundary_nonce,
            signature: vote_signature(&vote2, boundary_nonce),
        },
        &mut last_nonce,
        &mut accepted,
        &mut reject_stats,
    );

    assert_eq!(accepted.len(), 2);
    assert_eq!(reject_stats.bad_sig, 0);
    assert_eq!(reject_stats.replay, 0);
    assert_eq!(reject_stats.stale_nonce, 0);

    let key = ("v1".to_string(), 10, 0, VoteType::Prevote);
    assert_eq!(last_nonce.get(&key), Some(&boundary_nonce));
}

#[test]
fn auth_rejects_first_nonce_bootstrap_jump_without_prior_domain_nonce() {
    let mut last_nonce = HashMap::new();
    let mut accepted = Vec::new();
    let mut reject_stats = AuthRejectStats::default();

    let vote = BftVote {
        validator: "v1".into(),
        vote_type: VoteType::Prevote,
        block_hash: "h11-r0".into(),
        byzantine: false,
        height: 11,
        round: 0,
    };
    let jumped_nonce = MAX_BFT_NONCE_FORWARD_JUMP + 1;
    accept_signed_vote(
        SignedVote {
            vote: vote.clone(),
            nonce: jumped_nonce,
            signature: vote_signature(&vote, jumped_nonce),
        },
        &mut last_nonce,
        &mut accepted,
        &mut reject_stats,
    );

    assert_eq!(accepted.len(), 0);
    assert_eq!(reject_stats.bad_sig, 0);
    assert_eq!(reject_stats.replay, 0);
    assert_eq!(reject_stats.stale_nonce, 1);

    let key = ("v1".to_string(), 11, 0, VoteType::Prevote);
    assert_eq!(last_nonce.get(&key), None);
}
