use std::{
    collections::{HashSet, VecDeque},
    sync::{mpsc, Arc, Condvar, Mutex},
    thread,
    time::Instant,
};

use trnm_executor::build_parallel_groups;
use trnm_state::StateStore;
use trnm_types::Tx;

use crate::apply::apply_one;
use crate::rwset::read_write_decl;
use crate::types::{DaBatch, MockTx, OrderingDecision};

trait DaProvider {
    fn batch_from_picked(&self, picked: &[MockTx]) -> DaBatch;
}

struct LegacyMempoolDaProvider;

impl DaProvider for LegacyMempoolDaProvider {
    fn batch_from_picked(&self, picked: &[MockTx]) -> DaBatch {
        DaBatch {
            tx_ids: (1..=(picked.len() as u64)).collect(),
        }
    }
}

trait OrderingEngine {
    fn decide(
        &self,
        snapshot: &StateStore,
        picked: &[MockTx],
        da_batch: &DaBatch,
        workers: usize,
        candidate_height: u64,
    ) -> OrderingDecision;
}

struct PreexecOrderingEngine;

impl OrderingEngine for PreexecOrderingEngine {
    fn decide(
        &self,
        snapshot: &StateStore,
        picked: &[MockTx],
        da_batch: &DaBatch,
        workers: usize,
        candidate_height: u64,
    ) -> OrderingDecision {
        let plan: Vec<Tx> = picked
            .iter()
            .enumerate()
            .map(|(i, tx)| read_write_decl(snapshot, tx, (i as u64) + 1))
            .collect();
        let da_ids: HashSet<u64> = da_batch.tx_ids.iter().copied().collect();
        let ordered_groups: Vec<Vec<u64>> = build_parallel_groups(&plan)
            .into_iter()
            .map(|group| {
                group
                    .into_iter()
                    .map(|tx| tx.id)
                    .filter(|id| da_ids.contains(id))
                    .collect::<Vec<_>>()
            })
            .filter(|group_ids| !group_ids.is_empty())
            .collect();
        let group_count = ordered_groups.len();
        let critical_wait_blocks = group_count.saturating_sub(1) as u64;

        let pool = PreExecPool::new(
            Arc::new(snapshot.clone()),
            Arc::new(picked.to_vec()),
            workers,
            candidate_height,
        );
        let preexec_started = Instant::now();
        let mut ordered_ids = Vec::new();
        let mut rejected = 0u64;
        for group_ids in ordered_groups {
            let (accepted_ids, group_rejected) = pre_execute_group_parallel(&pool, group_ids);
            ordered_ids.extend(accepted_ids);
            rejected = rejected.saturating_add(group_rejected);
        }
        OrderingDecision {
            ordered_ids,
            rejected,
            preexec_elapsed_ms: preexec_started.elapsed().as_millis(),
            group_count,
            critical_wait_blocks,
        }
    }
}

#[derive(Clone)]
struct PreExecJob {
    ids: Vec<u64>,
    result_tx: mpsc::Sender<(u64, bool, String)>,
}

enum PreExecQueueEntry {
    Run(PreExecJob),
    Shutdown,
}

struct PreExecPoolState {
    queue: Mutex<VecDeque<PreExecQueueEntry>>,
    cv: Condvar,
}

pub(crate) struct PreExecPool {
    state: Arc<PreExecPoolState>,
    handles: Vec<thread::JoinHandle<()>>,
    width: usize,
}

impl PreExecPool {
    pub(crate) fn new(
        snapshot: Arc<StateStore>,
        picked: Arc<Vec<MockTx>>,
        workers: usize,
        candidate_height: u64,
    ) -> Self {
        let width = workers.max(1);
        let state = Arc::new(PreExecPoolState {
            queue: Mutex::new(VecDeque::new()),
            cv: Condvar::new(),
        });
        let mut handles = Vec::with_capacity(width);
        for _ in 0..width {
            let state_cloned = Arc::clone(&state);
            let snapshot_cloned = Arc::clone(&snapshot);
            let picked_cloned = Arc::clone(&picked);
            handles.push(thread::spawn(move || loop {
                let entry = {
                    let mut guard = state_cloned.queue.lock().expect("preexec queue poisoned");
                    loop {
                        if let Some(entry) = guard.pop_front() {
                            break entry;
                        }
                        guard = state_cloned
                            .cv
                            .wait(guard)
                            .expect("preexec queue poisoned while waiting");
                    }
                };
                match entry {
                    PreExecQueueEntry::Run(job) => {
                        for id in job.ids {
                            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                let idx = id
                                    .checked_sub(1)
                                    .map(|raw| raw as usize)
                                    .ok_or_else(|| invalid_preexec_tx_id(id, candidate_height))?;
                                let tx = picked_cloned
                                    .get(idx)
                                    .cloned()
                                    .ok_or_else(|| invalid_preexec_tx_id(id, candidate_height))?;
                                let mut local_state = snapshot_cloned.as_ref().clone();
                                apply_one(&mut local_state, tx, candidate_height)
                                    .map(|_| ())
                                    .map_err(|e| e.to_string())
                            }));
                            match result {
                                Ok(Ok(())) => {
                                    let _ = job.result_tx.send((id, true, String::new()));
                                }
                                Ok(Err(err)) => {
                                    let _ = job.result_tx.send((id, false, err));
                                }
                                Err(_) => {
                                    let _ = job
                                        .result_tx
                                        .send((id, false, preexec_worker_panic(id, candidate_height)));
                                }
                            }
                        }
                    }
                    PreExecQueueEntry::Shutdown => break,
                }
            }));
        }

        Self {
            state,
            handles,
            width,
        }
    }

    fn execute_group(&self, group_ids: Vec<u64>) -> (Vec<u64>, u64) {
        if group_ids.is_empty() {
            return (vec![], 0);
        }

        let (unique_group_ids, replayed_ids) = normalize_group_ids_for_preexec(&group_ids);
        if replayed_ids > 0 {
            println!(
                "[preexec] deduped_replayed_group_ids={} unique_group_ids={} replay_sample={}",
                replayed_ids,
                unique_group_ids.len(),
                format_replayed_group_id_sample(&group_ids, 4)
            );
        }

        let workers = self.width.min(unique_group_ids.len());
        if workers == 0 {
            return (vec![], 0);
        }
        let (tx, rx) = mpsc::channel::<(u64, bool, String)>();
        {
            let mut queue = self.state.queue.lock().expect("preexec queue poisoned");
            for w in 0..workers {
                let ids: Vec<u64> = unique_group_ids
                    .iter()
                    .copied()
                    .enumerate()
                    .filter_map(|(i, id)| if i % workers == w { Some(id) } else { None })
                    .collect();
                if ids.is_empty() {
                    continue;
                }
                queue.push_back(PreExecQueueEntry::Run(PreExecJob {
                    ids,
                    result_tx: tx.clone(),
                }));
            }
        }
        self.state.cv.notify_all();
        drop(tx);

        let mut ok_ids = HashSet::with_capacity(unique_group_ids.len());
        let mut rejected = 0u64;
        for (id, ok, err) in rx {
            if ok {
                ok_ids.insert(id);
            } else {
                rejected += 1;
                println!("[preexec] tx_id={} rejected err={}", id, err);
            }
        }

        let ordered_ok_ids = unique_group_ids
            .into_iter()
            .filter(|id| ok_ids.contains(id))
            .collect();
        (ordered_ok_ids, rejected)
    }
}

fn format_replayed_group_id_sample(group_ids: &[u64], limit: usize) -> String {
    if limit == 0 || group_ids.len() <= 1 {
        return "[]".to_string();
    }

    let mut seen_ids = HashSet::with_capacity(group_ids.len());
    let mut replay_sample = Vec::with_capacity(limit.min(group_ids.len()));
    let mut replayed_unique_total = 0usize;
    for &id in group_ids {
        if !seen_ids.insert(id) {
            replayed_unique_total += 1;
            if replay_sample.len() < limit {
                replay_sample.push(id);
            }
        }
    }

    if replay_sample.is_empty() {
        return "[]".to_string();
    }

    let omitted = replayed_unique_total.saturating_sub(replay_sample.len());
    if omitted == 0 {
        format!("{:?}", replay_sample)
    } else {
        format!("{:?}+{}more", replay_sample, omitted)
    }
}

fn normalize_group_ids_for_preexec(group_ids: &[u64]) -> (Vec<u64>, usize) {
    let input_len = group_ids.len();
    if input_len <= 1 {
        return (group_ids.to_vec(), 0);
    }

    // Replay fanout is typically tiny (single group, a duplicate echo, or a
    // short handoff list). Keep the common path allocation-light before falling
    // back to HashSet for broader batches.
    if input_len <= 8 {
        let mut unique_group_ids = Vec::with_capacity(input_len);
        for &id in group_ids {
            if !unique_group_ids.contains(&id) {
                unique_group_ids.push(id);
            }
        }
        let replayed_ids = input_len.saturating_sub(unique_group_ids.len());
        return (unique_group_ids, replayed_ids);
    }

    let mut unique_group_ids = Vec::with_capacity(input_len);
    let mut seen_ids = HashSet::with_capacity(input_len);
    for &id in group_ids {
        if seen_ids.insert(id) {
            unique_group_ids.push(id);
        }
    }
    let replayed_ids = input_len.saturating_sub(unique_group_ids.len());
    (unique_group_ids, replayed_ids)
}

impl Drop for PreExecPool {
    fn drop(&mut self) {
        {
            let mut queue = self.state.queue.lock().expect("preexec queue poisoned");
            for _ in 0..self.handles.len() {
                queue.push_back(PreExecQueueEntry::Shutdown);
            }
        }
        self.state.cv.notify_all();
        while let Some(handle) = self.handles.pop() {
            let _ = handle.join();
        }
    }
}

pub(crate) fn invalid_preexec_tx_id(id: u64, candidate_height: u64) -> String {
    format!(
        "preexec invalid tx id {} at candidate_height={} (tx ids are 1-based)",
        id, candidate_height
    )
}

pub(crate) fn preexec_worker_panic(id: u64, candidate_height: u64) -> String {
    format!(
        "preexec worker panic while evaluating tx_id={} at candidate_height={}",
        id, candidate_height
    )
}

pub(crate) fn pre_execute_group_parallel(
    pool: &PreExecPool,
    group_ids: Vec<u64>,
) -> (Vec<u64>, u64) {
    pool.execute_group(group_ids)
}

pub(crate) fn decide_order_for_commit(
    state: &StateStore,
    picked: &[MockTx],
    workers: usize,
    enable_da_ordering_decouple: bool,
    candidate_height: u64,
) -> OrderingDecision {
    if !enable_da_ordering_decouple {
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
        return OrderingDecision {
            ordered_ids: ordered,
            rejected,
            preexec_elapsed_ms: preexec_started.elapsed().as_millis(),
            group_count,
            critical_wait_blocks,
        };
    }

    let da = LegacyMempoolDaProvider;
    let ordering = PreexecOrderingEngine;
    let da_batch = da.batch_from_picked(picked);
    ordering.decide(state, picked, &da_batch, workers, candidate_height)
}
