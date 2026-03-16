use crate::bft::core::{round_change_backoff_ms, select_proposer};
use crate::bft::model::{BftHeightResult, BftJitterControl};
use crate::bft::round::simulate_bft_round;

fn update_leader_health(
    control: &mut BftJitterControl,
    proposer_idx: usize,
    committed: bool,
    round: u64,
) {
    if control.missed_threshold == 0 || proposer_idx >= control.leader_health.len() {
        return;
    }
    if committed {
        control.leader_health[proposer_idx].missed_proposals = 0;
        return;
    }
    let leader = &mut control.leader_health[proposer_idx];
    leader.missed_proposals = leader.missed_proposals.saturating_add(1);
    if leader.missed_proposals >= control.missed_threshold {
        leader.penalty_until_round = round.saturating_add(control.penalty_rounds.max(1));
    }
}

pub(crate) fn simulate_bft_height(
    height: u64,
    proposal_hash: &str,
    validators: usize,
    byzantine: usize,
    max_rounds: u64,
    fault_rounds: u64,
    restored_lock: Option<String>,
    control: &mut BftJitterControl,
) -> BftHeightResult {
    let mut round = 0u64;
    let mut locked: Option<String> = restored_lock;
    let mut round_changes = 0u64;
    let mut total_backoff_ms = 0u64;
    let mut max_backoff_ms = 0u64;
    let mut leader_missed_snapshot = vec![0u64; validators.max(1)];
    loop {
        let force_no_quorum = round < fault_rounds;
        let (proposer_idx, proposer_shifted) = select_proposer(height, round, control, validators);
        let (committed, prevote_count, precommit_count, new_lock, dv_events, auth_rejects) =
            simulate_bft_round(
                height,
                round,
                proposal_hash,
                locked.as_deref(),
                validators,
                byzantine,
                force_no_quorum,
                proposer_idx,
                proposer_shifted,
            );
        update_leader_health(control, proposer_idx, committed, round);
        leader_missed_snapshot = control
            .leader_health
            .iter()
            .map(|h| h.missed_proposals)
            .collect();
        if committed {
            return BftHeightResult {
                committed: true,
                committed_round: round,
                round_changes,
                prevote_count,
                precommit_count,
                double_vote_events: dv_events,
                auth_reject_bad_sig: auth_rejects.bad_sig,
                auth_reject_replay: auth_rejects.replay,
                auth_reject_stale_nonce: auth_rejects.stale_nonce,
                round_change_backoff_total_ms: total_backoff_ms,
                round_change_backoff_max_ms: max_backoff_ms,
                leader_missed_snapshot,
            };
        }
        round_changes += 1;
        if let Some(lock_hash) = new_lock {
            locked = Some(lock_hash);
        }
        let backoff = round_change_backoff_ms(
            round_changes,
            control.round_change_backoff_ms,
            control.round_change_backoff_cap_ms,
        );
        total_backoff_ms = total_backoff_ms.saturating_add(backoff);
        max_backoff_ms = max_backoff_ms.max(backoff);
        round += 1;
        if round >= max_rounds {
            return BftHeightResult {
                committed: false,
                committed_round: round - 1,
                round_changes,
                prevote_count,
                precommit_count,
                double_vote_events: dv_events,
                auth_reject_bad_sig: auth_rejects.bad_sig,
                auth_reject_replay: auth_rejects.replay,
                auth_reject_stale_nonce: auth_rejects.stale_nonce,
                round_change_backoff_total_ms: total_backoff_ms,
                round_change_backoff_max_ms: max_backoff_ms,
                leader_missed_snapshot,
            };
        }
    }
}
