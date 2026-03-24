use super::*;

#[test]
fn auth_rejects_empty_validator_before_nonce_and_signature_checks() {
    let vote = BftVote {
        validator: "   ".into(),
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
            // even with nonce=0 and matching signature, ingress must reject empty validator first
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
fn auth_rejects_noncanonical_validator_before_nonce_and_signature_checks() {
    let vote = BftVote {
        validator: " v1 ".into(),
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
fn auth_rejects_uppercase_validator_before_nonce_and_signature_checks() {
    let vote = BftVote {
        validator: "V1".into(),
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
fn auth_rejects_hyphen_only_validator_before_nonce_and_signature_checks() {
    let vote = BftVote {
        validator: "---".into(),
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
fn auth_rejects_edge_hyphen_validator_before_nonce_and_signature_checks() {
    for validator in ["-v1", "v1-"] {
        let vote = BftVote {
            validator: validator.into(),
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
fn auth_rejects_consecutive_hyphen_validator_before_nonce_and_signature_checks() {
    let vote = BftVote {
        validator: "v1--worker".into(),
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
fn auth_rejects_overlong_validator_before_nonce_and_signature_checks() {
    let vote = BftVote {
        validator: "v".repeat(MAX_BFT_TOKEN_LEN + 1),
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
