use std::collections::HashSet;

use trnm_pouw::apply_timeout;
use trnm_state::StateStore;
use trnm_types::TaskStatus;

use crate::accounting::balance_deltas_for_transition;
use crate::events::{emit_timeout_event, status_name};

pub(crate) fn scan_and_apply_timeouts(
    st: &mut StateStore,
    known_task_ids: &HashSet<u64>,
    current_height: u64,
    tx_id_seed: u64,
) -> u64 {
    let mut migrated = 0u64;
    for task_id in known_task_ids.iter().copied() {
        let Some(task) = st.get_task(task_id) else {
            continue;
        };
        if !matches!(
            task.status,
            TaskStatus::Assigned
                | TaskStatus::Committed
                | TaskStatus::Revealed
                | TaskStatus::Challenged
        ) {
            continue;
        }
        if st.is_emergency_paused() && matches!(task.status, TaskStatus::Challenged) {
            // Governance boundary hardening: the node-level timeout scanner must not even
            // enter challenged settlement while emergency pause is active. The lower-level
            // timeout path is already fail-closed, but skipping here keeps pause semantics
            // explicit and preserves staged resolve approvals/escrow without touching the
            // challenged settlement path at all.
            continue;
        }
        let from_status = format!("{:?}", task.status);
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
            let bond_disposition = if from_status == "Challenged" {
                st.get_task(task_id).and_then(|t| {
                    t.challenge_bond_forfeited
                        .map(|forfeited| if forfeited { "forfeited" } else { "refunded" })
                })
            } else {
                None
            };
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
