use std::collections::HashSet;

use trnm_pouw::apply_timeout;
use trnm_state::StateStore;
use trnm_types::TaskStatus;

use crate::accounting::balance_deltas_for_transition;
use crate::events::{emit_timeout_event, status_name};

pub(crate) const TIMEOUT_SCAN_MAX_TASK_ID: u64 = 9_000_000;

fn is_timeout_eligible_status(status: &TaskStatus) -> bool {
    matches!(
        status,
        TaskStatus::Assigned | TaskStatus::Committed | TaskStatus::Revealed | TaskStatus::Challenged
    )
}

fn timeout_skip_reason(status: &TaskStatus, emergency_paused: bool) -> Option<&'static str> {
    if !is_timeout_eligible_status(status) {
        return Some("status_not_timeout_eligible");
    }
    if emergency_paused && matches!(status, TaskStatus::Challenged) {
        return Some("emergency_pause_challenged");
    }
    None
}

fn should_scan_timeout(status: &TaskStatus, emergency_paused: bool) -> bool {
    timeout_skip_reason(status, emergency_paused).is_none()
}

pub(crate) fn sorted_timeout_candidate_ids(known_task_ids: &HashSet<u64>) -> Vec<u64> {
    let mut task_ids: Vec<u64> = known_task_ids
        .iter()
        .copied()
        .filter(|task_id| *task_id <= TIMEOUT_SCAN_MAX_TASK_ID)
        .collect();
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
    Some(match challenge_bond_forfeited {
        Some(true) => "forfeited",
        Some(false) => "refunded",
        None => "unknown",
    })
}

fn timeout_event_surface_metadata(tx_id_seed: u64, migrated_before_emit: u64) -> (u64, u64, bool, bool) {
    let tx_ordinal_overflowed = migrated_before_emit == u64::MAX;
    let tx_ordinal = migrated_before_emit.saturating_add(1);
    let (tx_id, tx_id_overflowed) = match tx_id_seed.checked_add(tx_ordinal) {
        Some(tx_id) => (tx_id, tx_ordinal_overflowed),
        None => (u64::MAX, true),
    };
    (tx_id, tx_ordinal, tx_id_overflowed, tx_ordinal_overflowed)
}

fn timeout_event_tx_metadata(tx_id_seed: u64, migrated_before_emit: u64) -> (u64, bool) {
    let (tx_id, _, tx_id_overflowed, tx_ordinal_overflowed) =
        timeout_event_surface_metadata(tx_id_seed, migrated_before_emit);
    (tx_id, tx_id_overflowed || tx_ordinal_overflowed)
}

fn timeout_event_tx_id(tx_id_seed: u64, migrated_before_emit: u64) -> u64 {
    timeout_event_surface_metadata(tx_id_seed, migrated_before_emit).0
}

fn timeout_event_tx_overflowed(tx_id_seed: u64, migrated_before_emit: u64) -> bool {
    timeout_event_tx_metadata(tx_id_seed, migrated_before_emit).1
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
        if let Some(reason) = timeout_skip_reason(&task.status, st.is_emergency_paused()) {
            // Governance boundary hardening: the node-level timeout scanner must not even
            // enter challenged settlement while emergency pause is active. The lower-level
            // timeout path is already fail-closed, but skipping here keeps pause semantics
            // explicit and preserves staged resolve approvals/escrow without touching the
            // challenged settlement path at all.
            if reason == "emergency_pause_challenged" {
                println!(
                    "[timeout-skip] height={} task_id={} status={:?} reason={}",
                    current_height, task_id, task.status, reason
                );
            }
            continue;
        }
        let from_status = format!("{:?}", task.status);
        let was_challenged = matches!(task.status, TaskStatus::Challenged);
        let challenger = task.challenger.clone();
        let Some(task_ref) = st.get_ref(task_id) else {
            println!(
                "[timeout-skip] height={} task_id={} status={:?} reason=missing_task_ref",
                current_height, task_id, task.status
            );
            continue;
        };
        let before = st.clone();
        match apply_timeout(st, task_ref, current_height) {
            Ok(()) => {
                let (
                    event_tx_id,
                    event_tx_ordinal,
                    event_tx_overflowed,
                    event_tx_ordinal_overflowed,
                ) = timeout_event_surface_metadata(tx_id_seed, migrated);
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
                    event_tx_id,
                    event_tx_ordinal,
                    event_tx_overflowed,
                    event_tx_ordinal_overflowed,
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
                    "[timeout] height={} task_id={} tx_id={} tx_ordinal={} tx_id_overflow={} tx_ordinal_overflow={} from_status={} to_status={} source=auto_scan",
                    current_height,
                    task_id,
                    event_tx_id,
                    event_tx_ordinal,
                    event_tx_overflowed,
                    event_tx_ordinal_overflowed,
                    from_status,
                    to_status
                );
            }
            Err(err) => {
                println!(
                    "[timeout-skip] height={} task_id={} status={:?} reason=apply_timeout_failed error={}",
                    current_height, task_id, task.status, err
                );
            }
        }
    }
    migrated
}

#[cfg(test)]
mod tests {
    use super::{
        should_scan_timeout, sorted_timeout_candidate_ids, timeout_bond_disposition,
        timeout_event_surface_metadata, timeout_event_tx_id, timeout_event_tx_metadata,
        timeout_event_tx_overflowed, timeout_skip_reason, TIMEOUT_SCAN_MAX_TASK_ID,
    };
    use std::collections::HashSet;
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
    fn timeout_skip_reason_surfaces_pause_visibility_without_blurring_other_edges() {
        assert_eq!(
            timeout_skip_reason(&TaskStatus::Challenged, true),
            Some("emergency_pause_challenged")
        );
        assert_eq!(
            timeout_skip_reason(&TaskStatus::Assigned, true),
            None,
            "pause should not hide normal assignment timeout edges"
        );
        assert_eq!(
            timeout_skip_reason(&TaskStatus::Created, false),
            Some("status_not_timeout_eligible")
        );
    }

    #[test]
    fn timeout_skip_reason_keeps_non_eligible_status_precedence_even_while_paused() {
        assert_eq!(
            timeout_skip_reason(&TaskStatus::Created, true),
            Some("status_not_timeout_eligible"),
            "pause must not relabel non-timeout states as challenged settlement skips"
        );
        assert_eq!(
            timeout_skip_reason(&TaskStatus::Completed, true),
            Some("status_not_timeout_eligible"),
            "completed tasks must stay outside the timeout scanner even during emergency pause"
        );
    }

    #[test]
    fn timeout_skip_reason_and_scan_gate_stay_exact_complements_across_status_matrix() {
        let cases = [
            (TaskStatus::Created, false, Some("status_not_timeout_eligible")),
            (TaskStatus::Created, true, Some("status_not_timeout_eligible")),
            (TaskStatus::Assigned, false, None),
            (TaskStatus::Assigned, true, None),
            (TaskStatus::Committed, false, None),
            (TaskStatus::Committed, true, None),
            (TaskStatus::Revealed, false, None),
            (TaskStatus::Revealed, true, None),
            (TaskStatus::Challenged, false, None),
            (
                TaskStatus::Challenged,
                true,
                Some("emergency_pause_challenged"),
            ),
            (TaskStatus::Completed, false, Some("status_not_timeout_eligible")),
            (TaskStatus::Completed, true, Some("status_not_timeout_eligible")),
            (TaskStatus::Resolved, false, Some("status_not_timeout_eligible")),
            (TaskStatus::Resolved, true, Some("status_not_timeout_eligible")),
            (TaskStatus::Slashed, false, Some("status_not_timeout_eligible")),
            (TaskStatus::Slashed, true, Some("status_not_timeout_eligible")),
        ];

        for (status, paused, expected_reason) in cases {
            assert_eq!(
                timeout_skip_reason(&status, paused),
                expected_reason,
                "skip reason drifted for status={status:?} paused={paused}"
            );
            assert_eq!(
                should_scan_timeout(&status, paused),
                expected_reason.is_none(),
                "scan gate must remain the exact complement of skip reasons for status={status:?} paused={paused}"
            );
        }
    }

    #[test]
    fn timeout_bond_disposition_only_surfaces_challenged_settlement_outcomes() {
        assert_eq!(timeout_bond_disposition(false, Some(true)), None);
        assert_eq!(timeout_bond_disposition(true, Some(false)), Some("refunded"));
        assert_eq!(timeout_bond_disposition(true, Some(true)), Some("forfeited"));
        assert_eq!(timeout_bond_disposition(true, None), Some("unknown"));
    }

    #[test]
    fn timeout_event_tx_id_starts_after_seed_and_preserves_scan_order_visibility() {
        assert_eq!(timeout_event_tx_id(9_000_000, 0), 9_000_001);
        assert_eq!(timeout_event_tx_id(9_000_000, 1), 9_000_002);
        assert_eq!(timeout_event_tx_id(u64::MAX, 0), u64::MAX);
        assert_eq!(timeout_event_tx_id(9_000_000, u64::MAX), u64::MAX);
    }

    #[test]
    fn timeout_event_tx_overflowed_only_marks_saturated_visibility_edges() {
        assert!(!timeout_event_tx_overflowed(9_000_000, 0));
        assert!(!timeout_event_tx_overflowed(9_000_000, 1));
        assert!(timeout_event_tx_overflowed(u64::MAX, 0));
        assert!(timeout_event_tx_overflowed(9_000_000, u64::MAX));
        assert!(timeout_event_tx_overflowed(u64::MAX - 1, 1));
    }

    #[test]
    fn timeout_event_tx_metadata_keeps_tx_id_and_overflow_flag_consistent_at_boundary() {
        assert_eq!(timeout_event_tx_metadata(9_000_000, 0), (9_000_001, false));
        assert_eq!(timeout_event_tx_metadata(u64::MAX - 1, 0), (u64::MAX, false));
        assert_eq!(timeout_event_tx_metadata(u64::MAX - 1, 1), (u64::MAX, true));
        assert_eq!(timeout_event_tx_metadata(u64::MAX, 0), (u64::MAX, true));
    }

    #[test]
    fn timeout_event_tx_metadata_marks_seed_saturation_without_hiding_first_ordinal() {
        assert_eq!(timeout_event_surface_metadata(u64::MAX, 0), (u64::MAX, 1, true, false));
        assert_eq!(timeout_event_tx_metadata(u64::MAX, 0), (u64::MAX, true));
    }

    #[test]
    fn timeout_event_tx_metadata_marks_saturated_ordinal_as_overflow_for_visibility() {
        assert_eq!(timeout_event_tx_metadata(0, u64::MAX), (u64::MAX, true));
    }

    #[test]
    fn timeout_event_surface_metadata_keeps_tx_id_and_ordinal_overflow_flags_distinct() {
        assert_eq!(
            timeout_event_surface_metadata(0, u64::MAX),
            (u64::MAX, u64::MAX, false, true)
        );
        assert_eq!(
            timeout_event_surface_metadata(u64::MAX, 0),
            (u64::MAX, 1, true, false)
        );
    }

    #[test]
    fn timeout_event_surface_metadata_keeps_tx_id_ordinal_and_overflow_in_lockstep() {
        assert_eq!(
            timeout_event_surface_metadata(9_000_000, 0),
            (9_000_001, 1, false, false)
        );
        assert_eq!(
            timeout_event_surface_metadata(u64::MAX - 1, 0),
            (u64::MAX, 1, false, false)
        );
        assert_eq!(
            timeout_event_surface_metadata(u64::MAX - 1, 1),
            (u64::MAX, 2, true, false)
        );
        assert_eq!(
            timeout_event_surface_metadata(0, u64::MAX),
            (u64::MAX, u64::MAX, true, true)
        );
        assert_eq!(
            timeout_event_surface_metadata(u64::MAX, u64::MAX),
            (u64::MAX, u64::MAX, true, true)
        );
    }

    #[test]
    fn timeout_event_surface_metadata_marks_ordinal_saturation_separately_from_tx_id_overflow() {
        assert_eq!(
            timeout_event_surface_metadata(u64::MAX - 1, 1),
            (u64::MAX, 2, true, false),
            "seed+ordinal overflow should not pretend the ordinal itself saturated"
        );
        assert_eq!(
            timeout_event_surface_metadata(9_000_000, u64::MAX),
            (u64::MAX, u64::MAX, true, true),
            "saturated ordinal should stay explicitly visible even when tx_id also sticks"
        );
    }

    #[test]
    fn timeout_event_surface_metadata_preserves_ordinal_visibility_when_seed_is_already_saturated() {
        assert_eq!(
            timeout_event_surface_metadata(u64::MAX, 1),
            (u64::MAX, 2, true, false),
            "a saturated tx_id seed must not collapse the independently visible ordinal"
        );
    }

    #[test]
    fn timeout_event_surface_metadata_keeps_exact_u64_max_boundary_visible_without_fake_overflow() {
        assert_eq!(
            timeout_event_surface_metadata(0, u64::MAX - 1),
            (u64::MAX, u64::MAX, false, false),
            "landing exactly on u64::MAX should stay visible without reporting saturation"
        );
        assert!(!timeout_event_tx_overflowed(0, u64::MAX - 1));
    }

    #[test]
    fn sorted_timeout_candidate_ids_keeps_exact_scan_cap_visible_in_order() {
        let known: HashSet<u64> = [TIMEOUT_SCAN_MAX_TASK_ID, 7_002u64, 7_001u64]
            .into_iter()
            .collect();

        assert_eq!(
            sorted_timeout_candidate_ids(&known),
            vec![7_001, 7_002, TIMEOUT_SCAN_MAX_TASK_ID]
        );
    }

    #[test]
    fn sorted_timeout_candidate_ids_filters_synthetic_ids_above_scan_cap() {
        let known: HashSet<u64> = [7_003u64, TIMEOUT_SCAN_MAX_TASK_ID + 1, 7_001, 7_002]
            .into_iter()
            .collect();

        assert_eq!(sorted_timeout_candidate_ids(&known), vec![7_001, 7_002, 7_003]);
    }
}
