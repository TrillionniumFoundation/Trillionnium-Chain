use std::collections::{HashMap, HashSet};

use crate::bft::model::{AuthRejectStats, BftJitterControl, BftVote, SignedVote, VoteType};
use crate::hash::hash32_hex;

pub(crate) fn quorum_threshold(n: usize) -> usize {
    // 2f+1 where f = floor((n-1)/3)
    let f = n.saturating_sub(1) / 3;
    2 * f + 1
}

fn proposer(height: u64, round: u64, n: usize) -> usize {
    ((height + round) as usize) % n.max(1)
}

pub(crate) fn select_proposer(
    height: u64,
    round: u64,
    control: &BftJitterControl,
    n: usize,
) -> (usize, bool) {
    let n = n.max(1);
    let base = proposer(height, round, n);
    if control.missed_threshold == 0 {
        return (base, false);
    }
    for offset in 0..n {
        let idx = (base + offset) % n;
        let health = control.leader_health.get(idx).cloned().unwrap_or_default();
        let penalized = round < health.penalty_until_round;
        let too_many_misses = health.missed_proposals >= control.missed_threshold;
        if !penalized && !too_many_misses {
            return (idx, offset > 0);
        }
    }
    (base, false)
}

pub(crate) fn round_change_backoff_ms(round_changes: u64, base_ms: u64, cap_ms: u64) -> u64 {
    if round_changes == 0 || base_ms == 0 {
        return 0;
    }
    let shift = (round_changes - 1).min(20);
    let factor = 1u64 << shift;
    base_ms.saturating_mul(factor).min(cap_ms)
}

pub(crate) fn aggregate_votes(votes: &[BftVote], vote_type: VoteType) -> HashMap<String, usize> {
    let mut voters_per_hash: HashMap<String, HashSet<String>> = HashMap::new();
    for v in votes.iter().filter(|v| v.vote_type == vote_type) {
        // Consensus safety: count each validator once per hash so
        // nonce-bumped duplicates cannot inflate quorum tallies.
        voters_per_hash
            .entry(v.block_hash.clone())
            .or_default()
            .insert(v.validator.clone());
    }

    voters_per_hash
        .into_iter()
        .map(|(hash, voters)| (hash, voters.len()))
        .collect()
}

pub(crate) fn vote_type_name(v: VoteType) -> &'static str {
    match v {
        VoteType::Prevote => "prevote",
        VoteType::Precommit => "precommit",
    }
}

pub(crate) fn vote_signature(vote: &BftVote, nonce: u64) -> String {
    hash32_hex(
        format!(
            "sig|{}|{}|{}|{}|{}|{}",
            vote.validator,
            vote.height,
            vote.round,
            vote_type_name(vote.vote_type),
            vote.block_hash,
            nonce
        )
        .as_bytes(),
    )
}

pub(crate) const MAX_BFT_TOKEN_LEN: usize = 128;
// Fail-closed nonce boundary to prevent namespace pinning via unbounded nonce jumps.
pub(crate) const MAX_BFT_NONCE_FORWARD_JUMP: u64 = 1_000_000;

fn is_canonical_validator_token(v: &str) -> bool {
    !v.is_empty()
        && v.len() <= MAX_BFT_TOKEN_LEN
        && v
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        // Gate hardening: separators-only ids (e.g. "---") are ambiguous and
        // can create replay/auth namespace confusion in logs and tooling.
        && v.bytes().any(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        // Avoid edge separators that can collapse in parsers/log processors.
        && v
            .as_bytes()
            .first()
            .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        && v
            .as_bytes()
            .last()
            .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        // Disallow repeated separators to avoid parser normalization ambiguity.
        && !v.contains("--")
}

fn is_canonical_block_hash_token(v: &str) -> bool {
    !v.is_empty()
        && v.len() <= MAX_BFT_TOKEN_LEN
        && v
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        // Replay namespace hardening: require at least one alnum so hyphen-only
        // placeholders cannot masquerade as canonical block hash identifiers.
        && v.bytes().any(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        // Avoid edge separators that can collapse in parsers/log processors.
        && v
            .as_bytes()
            .first()
            .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        && v
            .as_bytes()
            .last()
            .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        // Disallow repeated separators to avoid parser normalization ambiguity.
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

    // Scope nonce monotonicity to (validator, height, round, vote_type) so
    // replay/stale tracking cannot leak across rounds and suppress valid
    // round-change votes that restart nonce sequencing.
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

pub(crate) fn detect_double_votes(votes: &[BftVote], vote_type: VoteType) -> usize {
    let mut seen: HashMap<(String, u64, u64, VoteType), String> = HashMap::new();
    let mut events = 0usize;
    for v in votes.iter().filter(|v| v.vote_type == vote_type) {
        let k = (v.validator.clone(), v.height, v.round, v.vote_type);
        if let Some(prev_hash) = seen.get(&k) {
            if prev_hash != &v.block_hash {
                events += 1;
                println!(
                    "[bft-slash] event=double_vote validator={} height={} round={} vote_type={:?} first_hash={} second_hash={}",
                    v.validator, v.height, v.round, v.vote_type, prev_hash, v.block_hash
                );
            }
        } else {
            seen.insert(k, v.block_hash.clone());
        }
    }
    events
}
