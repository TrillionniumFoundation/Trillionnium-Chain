use super::*;

pub(crate) const MAX_BFT_TOKEN_LEN: usize = 128;
pub(crate) const MAX_BFT_NONCE_FORWARD_JUMP: u64 = 1_000_000;

pub(crate) fn is_canonical_validator_token(v: &str) -> bool {
    !v.is_empty()
        && v.len() <= MAX_BFT_TOKEN_LEN
        && v.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && v.bytes()
            .any(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        && v.as_bytes()
            .first()
            .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        && v.as_bytes()
            .last()
            .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        && !v.contains("--")
}

pub(crate) fn is_canonical_block_hash_token(v: &str) -> bool {
    !v.is_empty()
        && v.len() <= MAX_BFT_TOKEN_LEN
        && v.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && v.bytes()
            .any(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        && v.as_bytes()
            .first()
            .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        && v.as_bytes()
            .last()
            .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        && !v.contains("--")
}

pub(crate) fn accept_signed_vote(
    msg: SignedVote,
    last_nonce: &mut HashMap<(String, u64, u64, VoteType), u64>,
    accepted: &mut Vec<BftVote>,
    reject_stats: &mut AuthRejectStats,
) {
    let validator_trimmed = msg.vote.validator.trim();
    if validator_trimmed.is_empty() {
        reject_stats.bad_sig += 1;
        println!(
            "[bft-net] reject reason=empty_validator height={} round={} vote_type={} nonce={}",
            msg.vote.height,
            msg.vote.round,
            vote_type_name(msg.vote.vote_type),
            msg.nonce
        );
        return;
    }
    if validator_trimmed != msg.vote.validator || !is_canonical_validator_token(&msg.vote.validator)
    {
        reject_stats.bad_sig += 1;
        println!(
            "[bft-net] reject reason=noncanonical_validator validator={} height={} round={} vote_type={} nonce={}",
            msg.vote.validator,
            msg.vote.height,
            msg.vote.round,
            vote_type_name(msg.vote.vote_type),
            msg.nonce
        );
        return;
    }

    let block_hash_trimmed = msg.vote.block_hash.trim();
    if block_hash_trimmed.is_empty() {
        reject_stats.bad_sig += 1;
        println!(
            "[bft-net] reject reason=empty_block_hash validator={} height={} round={} vote_type={} nonce={}",
            msg.vote.validator,
            msg.vote.height,
            msg.vote.round,
            vote_type_name(msg.vote.vote_type),
            msg.nonce
        );
        return;
    }
    if block_hash_trimmed != msg.vote.block_hash
        || !is_canonical_block_hash_token(&msg.vote.block_hash)
    {
        reject_stats.bad_sig += 1;
        println!(
            "[bft-net] reject reason=noncanonical_block_hash validator={} height={} round={} vote_type={} nonce={}",
            msg.vote.validator,
            msg.vote.height,
            msg.vote.round,
            vote_type_name(msg.vote.vote_type),
            msg.nonce
        );
        return;
    }

    if msg.vote.height == 0 {
        reject_stats.bad_sig += 1;
        println!(
            "[bft-net] reject reason=invalid_height validator={} height={} round={} vote_type={} nonce={}",
            msg.vote.validator,
            msg.vote.height,
            msg.vote.round,
            vote_type_name(msg.vote.vote_type),
            msg.nonce
        );
        return;
    }

    if msg.nonce == 0 {
        reject_stats.stale_nonce += 1;
        println!(
            "[bft-net] reject reason=zero_nonce validator={} height={} round={} vote_type={} nonce={}",
            msg.vote.validator,
            msg.vote.height,
            msg.vote.round,
            vote_type_name(msg.vote.vote_type),
            msg.nonce
        );
        return;
    }

    let expected = vote_signature(&msg.vote, msg.nonce);
    if msg.signature != expected {
        reject_stats.bad_sig += 1;
        println!(
            "[bft-net] reject reason=bad_sig validator={} height={} round={} vote_type={} nonce={}",
            msg.vote.validator,
            msg.vote.height,
            msg.vote.round,
            vote_type_name(msg.vote.vote_type),
            msg.nonce
        );
        return;
    }

    let key = (
        msg.vote.validator.clone(),
        msg.vote.height,
        msg.vote.round,
        msg.vote.vote_type,
    );
    if !last_nonce.contains_key(&key) && msg.nonce > MAX_BFT_NONCE_FORWARD_JUMP {
        reject_stats.stale_nonce += 1;
        println!(
            "[bft-net] reject reason=nonce_bootstrap_jump validator={} height={} round={} vote_type={} nonce={} max_initial_nonce={}",
            msg.vote.validator,
            msg.vote.height,
            msg.vote.round,
            vote_type_name(msg.vote.vote_type),
            msg.nonce,
            MAX_BFT_NONCE_FORWARD_JUMP
        );
        return;
    }
    if let Some(prev) = last_nonce.get(&key) {
        if msg.nonce == *prev {
            let maybe_prev_vote = accepted.iter().rev().find(|v| {
                v.validator == msg.vote.validator
                    && v.height == msg.vote.height
                    && v.round == msg.vote.round
                    && v.vote_type == msg.vote.vote_type
            });
            if let Some(prev_vote) = maybe_prev_vote {
                if prev_vote.block_hash != msg.vote.block_hash {
                    reject_stats.bad_sig += 1;
                    println!(
                        "[bft-net] reject reason=nonce_equivocation validator={} height={} round={} vote_type={} nonce={} prev_hash={} new_hash={}",
                        msg.vote.validator,
                        msg.vote.height,
                        msg.vote.round,
                        vote_type_name(msg.vote.vote_type),
                        msg.nonce,
                        prev_vote.block_hash,
                        msg.vote.block_hash
                    );
                    return;
                }
            }
            reject_stats.replay += 1;
            println!(
                "[bft-net] reject reason=replay validator={} height={} round={} vote_type={} nonce={}",
                msg.vote.validator,
                msg.vote.height,
                msg.vote.round,
                vote_type_name(msg.vote.vote_type),
                msg.nonce
            );
            return;
        }
        if msg.nonce < *prev {
            reject_stats.stale_nonce += 1;
            println!(
                "[bft-net] reject reason=stale_nonce validator={} height={} round={} vote_type={} nonce={} last_nonce={}",
                msg.vote.validator,
                msg.vote.height,
                msg.vote.round,
                vote_type_name(msg.vote.vote_type),
                msg.nonce,
                prev
            );
            return;
        }
        if msg.nonce > prev.saturating_add(MAX_BFT_NONCE_FORWARD_JUMP) {
            reject_stats.stale_nonce += 1;
            println!(
                "[bft-net] reject reason=nonce_jump validator={} height={} round={} vote_type={} nonce={} last_nonce={} max_jump={}",
                msg.vote.validator,
                msg.vote.height,
                msg.vote.round,
                vote_type_name(msg.vote.vote_type),
                msg.nonce,
                prev,
                MAX_BFT_NONCE_FORWARD_JUMP
            );
            return;
        }
    }

    last_nonce.insert(key, msg.nonce);
    accepted.push(msg.vote);
}
