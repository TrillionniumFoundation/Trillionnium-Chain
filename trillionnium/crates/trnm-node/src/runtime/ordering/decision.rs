use super::*;

pub(crate) fn decide_order_for_commit(
    state: &StateStore,
    picked: &[MockTx],
    workers: usize,
    enable_da_ordering_decouple: bool,
    candidate_height: u64,
) -> OrderingDecision {
    if !enable_da_ordering_decouple {
        return decide_legacy_order_for_commit(state, picked, workers, candidate_height);
    }

    let da = LegacyMempoolDaProvider;
    let ordering = PreexecOrderingEngine;
    let da_batch = da.batch_from_picked(picked);
    ordering.decide(state, picked, &da_batch, workers, candidate_height)
}

fn decide_legacy_order_for_commit(
    state: &StateStore,
    picked: &[MockTx],
    workers: usize,
    candidate_height: u64,
) -> OrderingDecision {
    let plan: Vec<Tx> = picked
        .iter()
        .enumerate()
        .map(|(i, tx)| read_write_decl(state, tx, (i as u64) + 1))
        .collect();
    let groups = build_parallel_groups(&plan);
    let group_count = groups.len();
    let critical_wait_blocks = group_count.saturating_sub(1) as u64;
    let mut ordered = Vec::new();
    let mut rejected = 0u64;
    let pool = PreExecPool::new(
        Arc::new(state.clone()),
        Arc::new(picked.to_vec()),
        workers,
        candidate_height,
    );
    let preexec_started = Instant::now();
    for g in groups {
        let group_ids: Vec<u64> = g.iter().map(|t| t.id).collect();
        let (ids, rej) = pre_execute_group_parallel(&pool, group_ids);
        ordered.extend(ids);
        rejected += rej;
    }
    OrderingDecision {
        ordered_ids: ordered,
        rejected,
        preexec_elapsed_ms: preexec_started.elapsed().as_millis(),
        group_count,
        critical_wait_blocks,
    }
}
