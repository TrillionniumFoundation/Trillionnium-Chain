use super::*;

pub(crate) fn quorum_threshold(n: usize) -> usize {
    let f = n.saturating_sub(1) / 3;
    2 * f + 1
}

pub(crate) fn proposer(height: u64, round: u64, n: usize) -> usize {
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

pub(crate) fn ratio_ppm_u64(numerator: u64, denominator: u64) -> u64 {
    if denominator == 0 {
        return 0;
    }
    numerator.saturating_mul(1_000_000) / denominator
}

pub(crate) fn aggregate_votes(votes: &[BftVote], vote_type: VoteType) -> HashMap<String, usize> {
    let mut voters_per_hash: HashMap<String, HashSet<String>> = HashMap::new();
    for v in votes.iter().filter(|v| v.vote_type == vote_type) {
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
