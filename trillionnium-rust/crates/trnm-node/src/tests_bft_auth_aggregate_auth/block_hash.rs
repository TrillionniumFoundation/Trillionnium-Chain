use super::*;

#[test]
fn auth_rejects_hyphen_only_block_hash_before_nonce_and_signature_checks() {
    let vote = BftVote {
        validator: "v1".into(),
        vote_type: VoteType::Prevote,
        block_hash: "---".into(),
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

#[test]
fn auth_rejects_edge_hyphen_block_hash_before_nonce_and_signature_checks() {
    for block_hash in ["-h1", "h1-"] {
        let vote = BftVote {
            validator: "v1".into(),
            vote_type: VoteType::Prevote,
            block_hash: block_hash.into(),
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
}

#[test]
fn auth_rejects_consecutive_hyphen_block_hash_before_nonce_and_signature_checks() {
    let vote = BftVote {
        validator: "v1".into(),
        vote_type: VoteType::Prevote,
        block_hash: "h1--fork".into(),
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

#[test]
fn auth_rejects_overlong_block_hash_before_nonce_and_signature_checks() {
    let vote = BftVote {
        validator: "v1".into(),
        vote_type: VoteType::Prevote,
        block_hash: "h".repeat(MAX_BFT_TOKEN_LEN + 1),
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

#[test]
fn auth_rejects_noncanonical_block_hash_before_nonce_and_signature_checks() {
    let vote = BftVote {
        validator: "v1".into(),
        vote_type: VoteType::Prevote,
        block_hash: " h1 ".into(),
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
            // even with nonce=0 and matching signature, ingress must reject non-canonical hash first
            signature: vote_signature(&vote, 0),
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

#[test]
fn auth_rejects_uppercase_block_hash_before_nonce_and_signature_checks() {
    let vote = BftVote {
        validator: "v1".into(),
        vote_type: VoteType::Prevote,
        block_hash: "A1b2".into(),
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
            nonce: 1,
            // even with nonce>0 and matching signature, ingress must reject non-canonical hash first
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
