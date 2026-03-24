use super::*;

pub(crate) fn requeue_uncommitted_txs(mempool: &mut VecDeque<MockTx>, picked: Vec<MockTx>) {
    if picked.is_empty() {
        return;
    }
    mempool.extend(picked);
}

pub(crate) fn event_type_of(tx: &MockTx) -> &'static str {
    match tx {
        MockTx::CreateTask { .. } => "create",
        MockTx::AcceptTask { .. } => "accept",
        MockTx::Commit { .. } => "commit",
        MockTx::Reveal { .. } => "reveal",
        MockTx::Challenge { .. } => "challenge",
        MockTx::Resolve { .. } => "resolve",
    }
}

pub(crate) fn event_type_for_apply_outcome(tx: &MockTx, err_kind: Option<&str>) -> &'static str {
    if matches!(tx, MockTx::Resolve { .. }) && err_kind == Some("resolve_approval_staged") {
        "resolve_approval_staged"
    } else {
        event_type_of(tx)
    }
}

pub(crate) fn is_critical_tx(tx: &MockTx) -> bool {
    matches!(tx, MockTx::Challenge { .. } | MockTx::Resolve { .. })
}

pub(crate) fn pick_txs_with_critical_guard(
    mempool: &mut VecDeque<MockTx>,
    txs_per_block: usize,
) -> Vec<MockTx> {
    if txs_per_block == 0 || mempool.is_empty() {
        return Vec::new();
    }

    if txs_per_block >= mempool.len() {
        return mempool.drain(..).collect();
    }

    if !mempool.iter().any(is_critical_tx) {
        let mut picked = Vec::with_capacity(txs_per_block);
        for _ in 0..txs_per_block {
            let Some(tx) = mempool.pop_front() else {
                break;
            };
            picked.push(tx);
        }
        return picked;
    }

    let mut lane = LaneAdmissionGate::new(mempool.len(), 1);
    let mempool_len = mempool.len();
    for (idx, tx) in mempool.iter().enumerate() {
        let class = if is_critical_tx(tx) {
            IngressClass::Critical
        } else {
            IngressClass::Normal
        };
        let _ = lane.admit(idx as u64, class);
    }

    let mut selected = Vec::with_capacity(txs_per_block);
    while selected.len() < txs_per_block {
        let Some(id) = lane.pop_ready() else {
            break;
        };
        let idx = id as usize;
        if idx < mempool_len {
            selected.push((idx, selected.len()));
        }
    }

    let mut picked_slots: Vec<Option<MockTx>> = (0..selected.len()).map(|_| None).collect();
    selected.sort_unstable_by(|(lhs, _), (rhs, _)| rhs.cmp(lhs));

    for (idx, pos) in selected {
        let tx = mempool
            .remove(idx)
            .expect("selected tx index must still exist during descending extraction");
        picked_slots[pos] = Some(tx);
    }

    picked_slots.into_iter().flatten().collect()
}

pub(crate) fn tx_hash_of(tx_id: u64) -> String {
    format!("0xmock{:016x}", tx_id)
}

pub(crate) fn status_name(st: &StateStore, task_id: u64) -> String {
    st.get_task(task_id)
        .map(|t| format!("{:?}", t.status))
        .unwrap_or_else(|| "NONE".to_string())
}

pub(crate) fn is_high_risk_tx(tx: &MockTx) -> bool {
    match tx {
        MockTx::CreateTask { .. }
        | MockTx::AcceptTask { .. }
        | MockTx::Commit { .. }
        | MockTx::Reveal { .. }
        | MockTx::Challenge { .. }
        | MockTx::Resolve { .. } => true,
    }
}

pub(crate) fn is_rejected_by_emergency_pause(is_paused: bool, tx: &MockTx) -> bool {
    is_paused && is_high_risk_tx(tx)
}
