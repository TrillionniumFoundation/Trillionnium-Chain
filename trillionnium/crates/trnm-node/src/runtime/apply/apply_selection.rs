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
        let Some(tx) = mempool.remove(idx) else {
            // Fail closed on any stale/duplicated admission output instead of
            // panicking the node hot path. Deterministic callers still produce
            // the same picked set on the happy path.
            continue;
        };
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

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_commitment(task_id: u64, worker: &str) -> [u8; 32] {
        compute_commitment(task_id, &[7u8; 32], &[9u8; 32], worker)
    }

    fn sample_txs() -> [MockTx; 6] {
        [
            MockTx::CreateTask {
                task_id: 1,
                creator: "alice".into(),
                bounty: 100,
            },
            MockTx::AcceptTask {
                task_id: 1,
                worker: "worker".into(),
            },
            MockTx::Commit {
                task_id: 1,
                worker: "worker".into(),
                committed_hash: sample_commitment(1, "worker"),
            },
            MockTx::Reveal {
                task_id: 1,
                result_hash: [7u8; 32],
                reveal_salt: [9u8; 32],
            },
            MockTx::Challenge {
                task_id: 1,
                challenger: "challenger".into(),
                bond: 10,
            },
            MockTx::Resolve {
                task_id: 1,
                slash_worker: false,
                resolver: "governance.resolve_authority".into(),
            },
        ]
    }

    #[test]
    fn emergency_pause_gates_every_runtime_tx_variant() {
        for tx in sample_txs() {
            assert!(
                is_high_risk_tx(&tx),
                "runtime pause classifier drifted for tx variant: {:?}",
                tx
            );
            assert!(
                is_rejected_by_emergency_pause(true, &tx),
                "paused runtime must reject high-risk tx variant: {:?}",
                tx
            );
            assert!(
                !is_rejected_by_emergency_pause(false, &tx),
                "unpaused runtime must not reject tx variant: {:?}",
                tx
            );
        }
    }

    #[test]
    fn resolve_approval_staged_maps_to_dedicated_event_type_only_for_resolve() {
        let resolve = MockTx::Resolve {
            task_id: 9,
            slash_worker: true,
            resolver: "authority-a".into(),
        };
        let create = MockTx::CreateTask {
            task_id: 9,
            creator: "alice".into(),
            bounty: 50,
        };

        assert_eq!(
            event_type_for_apply_outcome(&resolve, Some("resolve_approval_staged")),
            "resolve_approval_staged"
        );
        assert_eq!(event_type_for_apply_outcome(&resolve, None), "resolve");
        assert_eq!(
            event_type_for_apply_outcome(&create, Some("resolve_approval_staged")),
            "create",
            "non-resolve tx must not reuse resolve_approval_staged event alias"
        );
    }
}
