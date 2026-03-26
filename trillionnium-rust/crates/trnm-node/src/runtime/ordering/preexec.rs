use super::*;

#[derive(Clone)]
pub(crate) struct PreExecJob {
    pub(crate) ids: Vec<u64>,
    pub(crate) result_tx: mpsc::Sender<(u64, bool, String)>,
}

pub(crate) enum PreExecQueueEntry {
    Run(PreExecJob),
    Shutdown,
}

pub(crate) struct PreExecPoolState {
    pub(crate) queue: Mutex<VecDeque<PreExecQueueEntry>>,
    pub(crate) cv: Condvar,
}

pub(crate) struct PreExecPool {
    pub(crate) state: Arc<PreExecPoolState>,
    pub(crate) handles: Vec<thread::JoinHandle<()>>,
    pub(crate) width: usize,
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
                        run_job(&job, &picked_cloned, &snapshot_cloned, candidate_height)
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
                "[preexec] candidate_height={} deduped_replayed_group_ids={} unique_group_ids={}",
                candidate_height,
                replayed_ids,
                unique_group_ids.len()
            );
        }

        let workers = self.width.min(unique_group_ids.len());
        let (tx, rx) = mpsc::channel::<(u64, bool, String)>();
        {
            let mut queue = self.state.queue.lock().expect("preexec queue poisoned");
            for ids in shard_group_ids(&unique_group_ids, workers) {
                queue.push_back(PreExecQueueEntry::Run(PreExecJob {
                    ids,
                    result_tx: tx.clone(),
                }));
            }
        }
        self.state.cv.notify_all();
        drop(tx);
        collect_group_results(rx, unique_group_ids)
    }
}

fn run_job(
    job: &PreExecJob,
    picked: &Arc<Vec<MockTx>>,
    snapshot: &Arc<StateStore>,
    candidate_height: u64,
) {
    for id in &job.ids {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let idx = id
                .checked_sub(1)
                .map(|raw| raw as usize)
                .ok_or_else(|| invalid_preexec_tx_id(*id, candidate_height))?;
            let tx = picked
                .get(idx)
                .cloned()
                .ok_or_else(|| invalid_preexec_tx_id(*id, candidate_height))?;
            let mut local_state = snapshot.as_ref().clone();
            apply_one(&mut local_state, tx, candidate_height)
                .map(|_| ())
                .map_err(|e| e.to_string())
        }));
        match result {
            Ok(Ok(())) => {
                let _ = job.result_tx.send((*id, true, String::new()));
            }
            Ok(Err(err)) => {
                let _ = job.result_tx.send((*id, false, err));
            }
            Err(_) => {
                let _ = job
                    .result_tx
                    .send((*id, false, preexec_worker_panic(*id, candidate_height)));
            }
        }
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

fn shard_group_ids(group_ids: &[u64], workers: usize) -> Vec<Vec<u64>> {
    let mut shards = Vec::with_capacity(workers);
    for w in 0..workers {
        let ids: Vec<u64> = group_ids
            .iter()
            .copied()
            .enumerate()
            .filter_map(|(i, id)| if i % workers == w { Some(id) } else { None })
            .collect();
        if !ids.is_empty() {
            shards.push(ids);
        }
    }
    shards
}

fn collect_group_results(
    rx: mpsc::Receiver<(u64, bool, String)>,
    ordered_group_ids: Vec<u64>,
) -> (Vec<u64>, u64) {
    let mut ok_ids = HashSet::with_capacity(ordered_group_ids.len());
    let mut rejected = 0u64;
    for (id, ok, err) in rx {
        if ok {
            ok_ids.insert(id);
        } else {
            rejected += 1;
            println!("[preexec] tx_id={} rejected err={}", id, err);
        }
    }

    let ordered_ok_ids = ordered_group_ids
        .into_iter()
        .filter(|id| ok_ids.contains(id))
        .collect();
    (ordered_ok_ids, rejected)
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

pub(crate) fn pre_execute_group_parallel(
    pool: &PreExecPool,
    group_ids: Vec<u64>,
) -> (Vec<u64>, u64) {
    pool.execute_group(group_ids)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_group_ids_preserves_first_seen_order_for_short_replay_lists() {
        let (normalized, replayed) = normalize_group_ids_for_preexec(&[4, 2, 4, 3, 2, 4]);

        assert_eq!(normalized, vec![4, 2, 3]);
        assert_eq!(replayed, 3);
    }

    #[test]
    fn normalize_group_ids_preserves_first_seen_order_for_long_replay_lists() {
        let (normalized, replayed) =
            normalize_group_ids_for_preexec(&[7, 3, 7, 5, 3, 9, 7, 11, 5, 13, 9, 15]);

        assert_eq!(normalized, vec![7, 3, 5, 9, 11, 13, 15]);
        assert_eq!(replayed, 5);
    }
}
