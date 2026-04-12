use super::*;

pub(crate) fn simulate_bft_round(
    height: u64,
    round: u64,
    proposal_hash: &str,
    locked_hash: Option<&str>,
    validators: usize,
    byzantine: usize,
    force_no_quorum: bool,
    proposer_idx: usize,
    proposer_shifted: bool,
) -> (bool, usize, usize, Option<String>, usize, AuthRejectStats) {
    let n = validators.max(1);
    let b = byzantine.min(n.saturating_sub(1));
    let q = quorum_threshold(n);
    let proposer_id = format!("v{}", proposer_idx + 1);
    let round_hash = locked_hash.unwrap_or(proposal_hash).to_string();

    println!("[bft] height={} round={} step={:?} proposer={} shifted={} validators={} byzantine={} quorum={} locked={}", height, round, RoundStep::Propose, proposer_id, proposer_shifted, n, b, q, locked_hash.is_some());

    let mut votes = Vec::new();
    let mut auth_nonce: HashMap<(String, u64, u64, VoteType), u64> = HashMap::new();
    let mut reject_stats = AuthRejectStats::default();
    let bad_hash = hash32_hex(&[b"byzantine", round_hash.as_bytes()].concat());
    for i in 0..n {
        let vid = format!("v{}", i + 1);
        let is_bad = i < b;
        let nonce = height * 10_000 + round * 100 + i as u64;
        let canonical_hash = round_hash.clone();
        let bad_vote_hash = bad_hash.clone();

        let good_vote = BftVote {
            validator: vid.clone(),
            vote_type: VoteType::Prevote,
            block_hash: if force_no_quorum {
                bad_vote_hash.clone()
            } else {
                canonical_hash.clone()
            },
            byzantine: is_bad,
            height,
            round,
        };
        let good_sig = vote_signature(&good_vote, nonce);
        accept_signed_vote(
            SignedVote {
                vote: good_vote,
                nonce,
                signature: good_sig,
            },
            &mut auth_nonce,
            &mut votes,
            &mut reject_stats,
        );

        if is_bad {
            let bad_sig_vote = BftVote {
                validator: vid.clone(),
                vote_type: VoteType::Prevote,
                block_hash: bad_vote_hash.clone(),
                byzantine: true,
                height,
                round,
            };
            accept_signed_vote(
                SignedVote {
                    vote: bad_sig_vote,
                    nonce: nonce + 1,
                    signature: "bad_signature".to_string(),
                },
                &mut auth_nonce,
                &mut votes,
                &mut reject_stats,
            );

            let replay_vote = BftVote {
                validator: vid.clone(),
                vote_type: VoteType::Prevote,
                block_hash: canonical_hash.clone(),
                byzantine: true,
                height,
                round,
            };
            let replay_sig = vote_signature(&replay_vote, nonce);
            accept_signed_vote(
                SignedVote {
                    vote: replay_vote,
                    nonce,
                    signature: replay_sig,
                },
                &mut auth_nonce,
                &mut votes,
                &mut reject_stats,
            );

            let eq_vote = BftVote {
                validator: vid.clone(),
                vote_type: VoteType::Prevote,
                block_hash: bad_vote_hash,
                byzantine: true,
                height,
                round,
            };
            let eq_nonce = nonce + 2;
            let eq_sig = vote_signature(&eq_vote, eq_nonce);
            accept_signed_vote(
                SignedVote {
                    vote: eq_vote,
                    nonce: eq_nonce,
                    signature: eq_sig,
                },
                &mut auth_nonce,
                &mut votes,
                &mut reject_stats,
            );

            let stale_vote = BftVote {
                validator: vid,
                vote_type: VoteType::Prevote,
                block_hash: canonical_hash,
                byzantine: true,
                height,
                round,
            };
            let stale_nonce = nonce + 1;
            let stale_sig = vote_signature(&stale_vote, stale_nonce);
            accept_signed_vote(
                SignedVote {
                    vote: stale_vote,
                    nonce: stale_nonce,
                    signature: stale_sig,
                },
                &mut auth_nonce,
                &mut votes,
                &mut reject_stats,
            );
        }
    }
    println!(
        "[bft] height={} round={} step={:?}",
        height,
        round,
        RoundStep::Prevote
    );

    let prevote_tally = aggregate_votes(&votes, VoteType::Prevote);
    let prevote_count = *prevote_tally.get(&round_hash).unwrap_or(&0);
    let new_lock = if prevote_count >= q {
        Some(round_hash.clone())
    } else {
        None
    };

    for i in 0..n {
        let vid = format!("v{}", i + 1);
        let is_bad = i < b;
        let nonce = height * 10_000 + round * 100 + i as u64 + 50;
        let canonical_hash = round_hash.clone();
        let bad_vote_hash = bad_hash.clone();
        let vote_hash = if prevote_count >= q && !is_bad {
            canonical_hash.clone()
        } else {
            bad_vote_hash.clone()
        };

        let good_vote = BftVote {
            validator: vid.clone(),
            vote_type: VoteType::Precommit,
            block_hash: vote_hash,
            byzantine: is_bad,
            height,
            round,
        };
        let good_sig = vote_signature(&good_vote, nonce);
        accept_signed_vote(
            SignedVote {
                vote: good_vote,
                nonce,
                signature: good_sig,
            },
            &mut auth_nonce,
            &mut votes,
            &mut reject_stats,
        );

        if is_bad {
            let bad_sig_vote = BftVote {
                validator: vid.clone(),
                vote_type: VoteType::Precommit,
                block_hash: bad_vote_hash.clone(),
                byzantine: true,
                height,
                round,
            };
            accept_signed_vote(
                SignedVote {
                    vote: bad_sig_vote,
                    nonce: nonce + 1,
                    signature: "bad_signature".to_string(),
                },
                &mut auth_nonce,
                &mut votes,
                &mut reject_stats,
            );

            let replay_vote = BftVote {
                validator: vid.clone(),
                vote_type: VoteType::Precommit,
                block_hash: canonical_hash.clone(),
                byzantine: true,
                height,
                round,
            };
            let replay_sig = vote_signature(&replay_vote, nonce);
            accept_signed_vote(
                SignedVote {
                    vote: replay_vote,
                    nonce,
                    signature: replay_sig,
                },
                &mut auth_nonce,
                &mut votes,
                &mut reject_stats,
            );

            let eq_vote = BftVote {
                validator: vid.clone(),
                vote_type: VoteType::Precommit,
                block_hash: canonical_hash.clone(),
                byzantine: true,
                height,
                round,
            };
            let eq_nonce = nonce + 2;
            let eq_sig = vote_signature(&eq_vote, eq_nonce);
            accept_signed_vote(
                SignedVote {
                    vote: eq_vote,
                    nonce: eq_nonce,
                    signature: eq_sig,
                },
                &mut auth_nonce,
                &mut votes,
                &mut reject_stats,
            );

            let stale_vote = BftVote {
                validator: vid,
                vote_type: VoteType::Precommit,
                block_hash: canonical_hash,
                byzantine: true,
                height,
                round,
            };
            let stale_nonce = nonce + 1;
            let stale_sig = vote_signature(&stale_vote, stale_nonce);
            accept_signed_vote(
                SignedVote {
                    vote: stale_vote,
                    nonce: stale_nonce,
                    signature: stale_sig,
                },
                &mut auth_nonce,
                &mut votes,
                &mut reject_stats,
            );
        }
    }
    println!(
        "[bft] height={} round={} step={:?}",
        height,
        round,
        RoundStep::Precommit
    );

    let precommit_tally = aggregate_votes(&votes, VoteType::Precommit);
    let precommit_count = *precommit_tally.get(&round_hash).unwrap_or(&0);
    let unique_voters: HashSet<String> = votes.iter().map(|v| v.validator.clone()).collect();
    let byzantine_votes = votes.iter().filter(|v| v.byzantine).count();
    let double_vote_events = detect_double_votes(&votes, VoteType::Prevote)
        + detect_double_votes(&votes, VoteType::Precommit);
    let committed = precommit_count >= q;
    if committed {
        println!("[bft] height={} round={} step={:?} block_hash={} precommit={}/{} unique_voters={} byzantine_votes={} double_vote_events={} auth_reject_bad_sig={} auth_reject_replay={} auth_reject_stale={} auth_reject_stale_nonce={}", height, round, RoundStep::Commit, round_hash, precommit_count, n, unique_voters.len(), byzantine_votes, double_vote_events, reject_stats.bad_sig, reject_stats.replay, reject_stats.stale, reject_stats.stale_nonce);
    } else {
        println!("[bft] height={} round={} step=RoundChange reason=no_quorum precommit={}/{} unique_voters={} byzantine_votes={} double_vote_events={} auth_reject_bad_sig={} auth_reject_replay={} auth_reject_stale={} auth_reject_stale_nonce={}", height, round, precommit_count, n, unique_voters.len(), byzantine_votes, double_vote_events, reject_stats.bad_sig, reject_stats.replay, reject_stats.stale, reject_stats.stale_nonce);
    }

    (
        committed,
        prevote_count,
        precommit_count,
        new_lock,
        double_vote_events,
        reject_stats,
    )
}
