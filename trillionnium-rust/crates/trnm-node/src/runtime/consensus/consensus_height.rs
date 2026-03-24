use super::*;

pub(crate) fn simulate_bft_height(
    height: u64,
    proposal_hash: &str,
    validators: usize,
    byzantine: usize,
    max_rounds: u64,
    fault_rounds: u64,
    initial_lock: Option<String>,
    control: &mut BftJitterControl,
) -> BftHeightResult {
    let mut locked: Option<String> = initial_lock;
    let mut round_changes = 0u64;
    let mut last_prevote = 0usize;
    let mut last_precommit = 0usize;
    let mut total_double_vote_events = 0usize;
    let mut total_auth_reject_bad_sig = 0usize;
    let mut total_auth_reject_replay = 0usize;
    let mut total_auth_reject_stale_nonce = 0usize;
    let mut round_change_backoff_total_ms = 0u64;
    let mut round_change_backoff_max_ms = 0u64;
    let n = validators.max(1);
    if control.leader_health.len() != n {
        control.leader_health = vec![LeaderHealth::default(); n];
    }

    for round in 0..max_rounds.max(1) {
        let force_no_quorum = round < fault_rounds;
        let effective_byz = if force_no_quorum { 0 } else { byzantine };
        let (proposer_idx, proposer_shifted) = select_proposer(height, round, control, n);
        let (committed, pv, pc, new_lock, dv, auth) = simulate_bft_round(
            height,
            round,
            proposal_hash,
            locked.as_deref(),
            validators,
            effective_byz,
            force_no_quorum,
            proposer_idx,
            proposer_shifted,
        );
        last_prevote = pv;
        last_precommit = pc;
        total_double_vote_events += dv;
        total_auth_reject_bad_sig += auth.bad_sig;
        total_auth_reject_replay += auth.replay;
        total_auth_reject_stale_nonce += auth.stale_nonce;
        if new_lock.is_some() {
            locked = new_lock;
        }
        if committed {
            control.leader_health[proposer_idx].missed_proposals = 0;
            return BftHeightResult {
                committed: true,
                committed_round: round,
                round_changes,
                prevote_count: pv,
                precommit_count: pc,
                double_vote_events: total_double_vote_events,
                auth_reject_bad_sig: total_auth_reject_bad_sig,
                auth_reject_replay: total_auth_reject_replay,
                auth_reject_stale_nonce: total_auth_reject_stale_nonce,
                round_change_backoff_total_ms,
                round_change_backoff_max_ms,
                leader_missed_snapshot: control
                    .leader_health
                    .iter()
                    .map(|h| h.missed_proposals)
                    .collect(),
            };
        }
        round_changes += 1;
        let health = &mut control.leader_health[proposer_idx];
        health.missed_proposals = health.missed_proposals.saturating_add(1);
        if control.missed_threshold > 0 && health.missed_proposals >= control.missed_threshold {
            health.penalty_until_round = round.saturating_add(1 + control.penalty_rounds);
        }
        let backoff_ms = round_change_backoff_ms(
            round_changes,
            control.round_change_backoff_ms,
            control.round_change_backoff_cap_ms,
        );
        round_change_backoff_total_ms = round_change_backoff_total_ms.saturating_add(backoff_ms);
        round_change_backoff_max_ms = round_change_backoff_max_ms.max(backoff_ms);
        println!(
            "[bft] height={} round={} step=RoundBackoff delay_ms={} cap_ms={} proposer=v{} missed_proposals={} penalty_until_round={}",
            height,
            round,
            backoff_ms,
            control.round_change_backoff_cap_ms,
            proposer_idx + 1,
            health.missed_proposals,
            health.penalty_until_round
        );
    }

    BftHeightResult {
        committed: false,
        committed_round: max_rounds.saturating_sub(1),
        round_changes,
        prevote_count: last_prevote,
        precommit_count: last_precommit,
        double_vote_events: total_double_vote_events,
        auth_reject_bad_sig: total_auth_reject_bad_sig,
        auth_reject_replay: total_auth_reject_replay,
        auth_reject_stale_nonce: total_auth_reject_stale_nonce,
        round_change_backoff_total_ms,
        round_change_backoff_max_ms,
        leader_missed_snapshot: control
            .leader_health
            .iter()
            .map(|h| h.missed_proposals)
            .collect(),
    }
}
