use trnm_state::{PendingResolveApprovalSnapshot, StateStore};

use crate::accounting::{event_delta_from_balances, EventDelta};
use crate::txmeta::task_id_of;
use crate::types::MockTx;

#[derive(Debug, Clone)]
pub(crate) struct TxRollbackSnapshot {
    pub(crate) task_id: u64,
    pub(crate) task: Option<trnm_types::TaskObject>,
    pub(crate) balances: Vec<(String, Option<u128>)>,
    pub(crate) pending_resolve_approval: Option<PendingResolveApprovalSnapshot>,
}

fn balance_snapshot(st: &StateStore, address: &str) -> Option<u128> {
    let balance = st.balance_of(address);
    if balance == 0 {
        None
    } else {
        Some(balance)
    }
}

pub(crate) fn capture_rollback_snapshot(st: &StateStore, tx: &MockTx) -> TxRollbackSnapshot {
    let task_id = task_id_of(tx);
    let task = st.get_task(task_id);
    let pending_resolve_approval = st.pending_resolve_approval_snapshot(task_id);
    let mut balances: Vec<(String, Option<u128>)> = Vec::new();
    let mut push_balance = |address: &str| {
        if balances.iter().any(|(existing, _)| existing == address) {
            return;
        }
        balances.push((address.to_string(), balance_snapshot(st, address)));
    };

    match tx {
        MockTx::CreateTask { creator, .. } => {
            push_balance(creator);
        }
        MockTx::Challenge { challenger, .. } => {
            push_balance(challenger);
            push_balance("treasury.challenge_escrow");
        }
        MockTx::Resolve { .. } => {
            push_balance("treasury.challenge_escrow");
            push_balance("treasury.challenge_forfeits");
            push_balance("treasury.worker_slashes");
            if let Some(task) = task.as_ref() {
                if let Some(worker) = task.worker.as_deref() {
                    push_balance(worker);
                }
                if let Some(challenger) = task.challenger.as_deref() {
                    push_balance(challenger);
                }
            }
        }
        MockTx::AcceptTask { .. } | MockTx::Commit { .. } | MockTx::Reveal { .. } => {}
    }

    TxRollbackSnapshot {
        task_id,
        task,
        balances,
        pending_resolve_approval,
    }
}

pub(crate) fn canonicalize_resolve_authority_snapshot(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed != raw {
        return None;
    }

    let has_forbidden_separator = |token: &str| {
        token.contains(';')
            || token.contains('|')
            || token.contains('；')
            || token.contains('，')
            || token.contains('、')
    };

    let mut seen = std::collections::BTreeSet::new();
    let mut canonical_members = Vec::new();
    for member in trimmed.split(',') {
        let member_trimmed = member.trim();
        if member_trimmed.is_empty()
            || member_trimmed != member
            || member_trimmed.chars().any(|c| c.is_whitespace())
            || has_forbidden_separator(member_trimmed)
            || !member_trimmed.is_ascii()
            || member_trimmed.chars().any(|c| c.is_ascii_control())
            || member_trimmed.eq_ignore_ascii_case("governance.resolve_authority")
            || member_trimmed.eq_ignore_ascii_case("governance.emergency_pause")
            || member_trimmed.eq_ignore_ascii_case("system")
            || member_trimmed.eq_ignore_ascii_case("treasury.challenge_escrow")
            || member_trimmed.eq_ignore_ascii_case("treasury.challenge_forfeits")
            || member_trimmed.eq_ignore_ascii_case("treasury.worker_slashes")
        {
            return None;
        }
        let lowered = member_trimmed.to_ascii_lowercase();
        if !seen.insert(lowered.clone()) {
            return None;
        }
        canonical_members.push(lowered);
    }

    if canonical_members.len() < 2 {
        return None;
    }
    canonical_members.sort();
    Some(canonical_members.join(","))
}

pub(crate) fn is_canonical_resolve_approver_snapshot(raw: &str) -> bool {
    let trimmed = raw.trim();
    !trimmed.is_empty()
        && trimmed == raw
        && !trimmed.chars().any(|c| c.is_whitespace())
        && !trimmed.contains(',')
        && !trimmed.contains(';')
        && !trimmed.contains('|')
        && trimmed.is_ascii()
        && !trimmed.chars().any(|c| c.is_ascii_control())
        && !trimmed.eq_ignore_ascii_case("governance.resolve_authority")
        && !trimmed.eq_ignore_ascii_case("governance.emergency_pause")
        && !trimmed.eq_ignore_ascii_case("system")
        && !trimmed.eq_ignore_ascii_case("treasury.challenge_escrow")
        && !trimmed.eq_ignore_ascii_case("treasury.challenge_forfeits")
        && !trimmed.eq_ignore_ascii_case("treasury.worker_slashes")
}

pub(crate) fn restore_pending_resolve_approval_from_snapshot(
    st: &mut StateStore,
    task_id: u64,
    snapshot: Option<PendingResolveApprovalSnapshot>,
) {
    st.clear_pending_resolve_approval(task_id);

    let Some(snapshot) = snapshot else {
        return;
    };

    let Some(task) = st.get_task(task_id) else {
        return;
    };
    if snapshot.task_version != task.version {
        return;
    }
    if snapshot.confirmations != 1 {
        return;
    }
    if !is_canonical_resolve_approver_snapshot(&snapshot.first_approver) {
        return;
    }
    let snapshot_first_approver = snapshot.first_approver.to_ascii_lowercase();

    let Some(snapshot_authority_set) =
        canonicalize_resolve_authority_snapshot(&snapshot.authority_set)
    else {
        return;
    };
    let expected_authority_set = st
        .pending_gov_update("resolve_authority")
        .map(|pending| pending.value)
        .or_else(|| st.gov_param_string("resolve_authority"));
    let Some(expected_authority_set) = expected_authority_set
        .as_deref()
        .and_then(canonicalize_resolve_authority_snapshot)
    else {
        return;
    };
    if snapshot_authority_set != expected_authority_set {
        return;
    }

    st.restore_pending_resolve_approval_from_rollback(
        task_id,
        Some(PendingResolveApprovalSnapshot {
            first_approver: snapshot_first_approver,
            authority_set: snapshot_authority_set,
            ..snapshot
        }),
    );
}

pub(crate) fn rollback_tx_snapshot(st: &mut StateStore, snapshot: TxRollbackSnapshot) {
    st.restore_task(snapshot.task_id, snapshot.task);
    for (address, balance) in snapshot.balances {
        st.restore_balance(&address, balance);
    }
    restore_pending_resolve_approval_from_snapshot(
        st,
        snapshot.task_id,
        snapshot.pending_resolve_approval,
    );
}

pub(crate) fn balance_deltas_from_snapshot(
    before: &TxRollbackSnapshot,
    after: &StateStore,
    challenger: Option<&str>,
) -> (EventDelta, Option<EventDelta>) {
    let treasury_before: u128 = before
        .balances
        .iter()
        .filter(|(address, _)| address.starts_with("treasury."))
        .map(|(_, balance)| balance.unwrap_or(0))
        .sum();
    let treasury_after: u128 = before
        .balances
        .iter()
        .filter(|(address, _)| address.starts_with("treasury."))
        .map(|(address, _)| after.balance_of(address))
        .sum();
    let treasury_delta = event_delta_from_balances(treasury_after, treasury_before);
    let challenger_delta = challenger.and_then(|acct| {
        before
            .balances
            .iter()
            .find(|(address, _)| address == acct)
            .map(|(_, balance)| {
                event_delta_from_balances(after.balance_of(acct), balance.unwrap_or(0))
            })
    });
    (treasury_delta, challenger_delta)
}
