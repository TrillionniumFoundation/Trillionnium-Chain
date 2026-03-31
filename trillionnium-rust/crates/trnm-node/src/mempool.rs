use std::collections::VecDeque;

use trnm_mempool::{IngressClass, LaneAdmissionGate};

use crate::types::MockTx;

fn is_critical_tx(tx: &MockTx) -> bool {
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
        // Free-ingress fast path: when block capacity can absorb the whole queue,
        // keep FIFO dequeue semantics while avoiding lane-gate bookkeeping.
        return mempool.drain(..).collect();
    }

    if !mempool.iter().any(is_critical_tx) || mempool.iter().all(is_critical_tx) {
        // Homogeneous backlog has no cross-class anti-starvation requirement.
        // Keep FIFO prefix drain and skip lane gate bookkeeping to reduce
        // free-ingress selection overhead on the hot path.
        let mut picked = Vec::with_capacity(txs_per_block);
        for _ in 0..txs_per_block {
            let Some(tx) = mempool.pop_front() else {
                break;
            };
            picked.push(tx);
        }
        return picked;
    }

    // Selection fairness should consider the full queued backlog, not only the
    // first block-sized prefix. Otherwise a critical tx that arrives behind a
    // long normal queue can never enter the fairness gate and is effectively
    // starved until the prefix drains.
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

pub(crate) fn requeue_uncommitted_txs(mempool: &mut VecDeque<MockTx>, picked: Vec<MockTx>) {
    if picked.is_empty() {
        return;
    }
    mempool.extend(picked);
}
