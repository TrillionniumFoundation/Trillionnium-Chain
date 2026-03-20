use std::collections::HashSet;

use trnm_pouw::apply_timeout;
use trnm_state::StateStore;
use trnm_types::TaskStatus;

use crate::accounting::balance_deltas_for_transition;
use crate::events::{emit_timeout_event, status_name};

fn is_timeout_eligible_status(status: &TaskStatus) -> bool {
    matches!(
        status,
        TaskStatus::Assigned | TaskStatus::Committed | TaskStatus::Revealed | TaskStatus::Challenged
    )
}

fn should_scan_timeout(status: &TaskStatus, emergency_paused: bool) -> bool {
    is_timeout_eligible_status(status)
        && !(emergency_paused && matches!(status, TaskStatus::Challenged))
}

pub(crate) fn sorted_timeout_candidate_ids(known_task_ids: &HashSet<u64>) -> Vec<u64> {
    let mut task_ids: Vec<u64> = known_task_ids.iter().copied().collect();
    task_ids.sort_unstable();
    task_ids
}

fn timeout_bond_disposition(
    was_challenged: bool,
    challenge_bond_forfeited: Option<bool>,
) -> Option<&'static str> {
    if !was_challenged {
        return None;
    }
    challenge_bond_forfeited.map(|forfeited| if forfeited { "forfeited" } else { "refunded" })
}

pub(crate) fn scan_and_apply_timeouts(
    st: &mut StateStore,
    known_task_ids: &HashSet<u64>,
    current_height: u64,
    tx_id_seed: u64,
) -> u64 {
    let mut migrated = 0u64;
    for task_id in sorted_timeout_candidate_ids(known_task_ids) {
        let Some(task) = st.get_task(task_id) else {
            continue;
        };
        if !should_scan_timeout(&task.status, st.is_emergency_paused()) {
            // Governance boundary hardening: the node-level timeout scanner must not even
            // enter challenged settlement while emergency pause is active. The lower-level
            // timeout path is already fail-closed, but skipping here keeps pause semantics
            // explicit and preserves staged resolve approvals/escrow without touching the
            // challenged settlement path at all.
            continue;
        }
        let from_status = format!("{:?}", task.status);
        let was_challenged = matches!(task.status, TaskStatus::Challenged);
        let challenger = task.challenger.clone();
        let Some(task_ref) = st.get_ref(task_id) else {
            continue;
        };
        let before = st.clone();
        if apply_timeout(st, task_ref, current_height).is_ok() {
            migrated += 1;
            let to_status = status_name(st, task_id);
            let root = hex::encode(st.state_root());
            let (treasury_delta, challenger_delta) =
                balance_deltas_for_transition(&before, st, task_id, challenger.as_deref());
            let bond_disposition = timeout_bond_disposition(
                was_challenged,
                st.get_task(task_id)
                    .and_then(|t| t.challenge_bond_forfeited),
            );
            emit_timeout_event(
                st,
                task_id,
                tx_id_seed.saturating_add(migrated),
                current_height,
                &from_status,
                &to_status,
                &root,
                &treasury_delta,
                challenger_delta.as_ref(),
                challenger.as_deref(),
                bond_disposition,
            );
            println!(
                "[timeout] height={} task_id={} from_status={} to_status={} source=auto_scan",
                current_height, task_id, from_status, to_status
            );
        }
    }
    migrated
}

#[cfg(test)]
mod tests {
    use super::{should_scan_timeout, timeout_bond_disposition};
    use trnm_types::TaskStatus;

    #[test]
    fn timeout_scan_status_gate_keeps_timeout_surface_explicit() {
        assert!(should_scan_timeout(&TaskStatus::Assigned, false));
        assert!(should_scan_timeout(&TaskStatus::Committed, false));
        assert!(should_scan_timeout(&TaskStatus::Revealed, false));
        assert!(should_scan_timeout(&TaskStatus::Challenged, false));

        assert!(!should_scan_timeout(&TaskStatus::Created, false));
        assert!(!should_scan_timeout(&TaskStatus::Completed, false));
        assert!(!should_scan_timeout(&TaskStatus::Resolved, false));
        assert!(!should_scan_timeout(&TaskStatus::Slashed, false));
    }

    #[test]
    fn timeout_scan_pause_gate_only_suppresses_challenged_recovery_edge() {
        assert!(should_scan_timeout(&TaskStatus::Assigned, true));
        assert!(should_scan_timeout(&TaskStatus::Committed, true));
        assert!(should_scan_timeout(&TaskStatus::Revealed, true));
        assert!(!should_scan_timeout(&TaskStatus::Challenged, true));
    }

    #[test]
    fn timeout_bond_disposition_only_surfaces_challenged_settlement_outcomes() {
        assert_eq!(timeout_bond_disposition(false, Some(true)), None);
        assert_eq!(timeout_bond_disposition(true, Some(false)), Some("refunded"));
        assert_eq!(timeout_bond_disposition(true, Some(true)), Some("forfeited"));
        assert_eq!(timeout_bond_disposition(true, None), None);
    }
}
