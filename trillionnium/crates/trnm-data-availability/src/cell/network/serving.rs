//! Explicit configured-peer serving; no discovery, retention or use authority.
use super::*;

#[derive(Clone, Copy, Debug)]
pub struct CellServeLimitsV1 {
    pub request_timeout: Duration,
    pub overall_timeout: Duration,
    pub max_workers: usize,
    /// Accepted sockets, including overload refusals. No application queue.
    pub max_connections: u64,
    /// Actual application bytes written, including partial failed responses.
    pub max_response_bytes: u64,
}

impl CellServeLimitsV1 {
    fn validate(self) -> CellResultV1<()> {
        CellPeerLimitsV1 {
            request_timeout: self.request_timeout,
            overall_timeout: self.overall_timeout,
            max_cell_bytes: MAX_CELL_BYTES,
            parallelism: self.max_workers,
            max_connections: self.max_connections,
            max_response_bytes: self.max_response_bytes,
        }
        .validate()
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CellServeReportV1 {
    pub accepted_connections: u64,
    pub overloaded_connections: u64,
    pub completed_requests: u64,
    pub peak_active_workers: usize,
    pub sent_response_bytes: u64,
}

type CellServeWorker<'scope> = thread::ScopedJoinHandle<'scope, (CellStoreV1, bool)>;

fn join_worker(
    worker: CellServeWorker<'_>,
    report: &mut CellServeReportV1,
    failure: &mut Option<CellErrorV1>,
) -> Option<CellStoreV1> {
    match worker.join() {
        Ok((store, complete)) => {
            report.completed_requests += u64::from(complete);
            Some(store)
        }
        Err(_) => {
            failure.get_or_insert(CellErrorV1::Invalid("cell serving worker panicked"));
            None
        }
    }
}

fn reap_finished_workers(
    active: &mut [Option<CellServeWorker<'_>>],
    readers: &mut [Option<CellStoreV1>],
    report: &mut CellServeReportV1,
    failure: &mut Option<CellErrorV1>,
) {
    for (slot, reader) in active.iter_mut().zip(readers) {
        if slot.as_ref().is_some_and(|worker| worker.is_finished()) {
            *reader = join_worker(slot.take().unwrap(), report, failure);
        }
    }
}

/// Each active request owns a validated read-only cache connection. Completed
/// workers return their reader for reuse; no SQLite lock spans socket I/O.
/// Socket timeouts and all writes use the original absolute service deadline.
/// Shutdown stops intake and joins admitted work within its existing deadline;
/// filesystem/SQLite/hash calls remain cooperative, not preemptible. This pilot
/// does not promise fair service against an attacker occupying every slot.
pub fn serve_cells_bounded(
    listener: &TcpListener,
    cache: &Path,
    shutdown: &AtomicBool,
    limits: CellServeLimitsV1,
) -> CellResultV1<CellServeReportV1> {
    serve_cells_inner(listener, cache, shutdown, limits, &|_| ())
}

fn serve_cells_inner(
    listener: &TcpListener,
    cache: &Path,
    shutdown: &AtomicBool,
    limits: CellServeLimitsV1,
    observed: &(impl Fn(&CellServeReportV1) + Sync),
) -> CellResultV1<CellServeReportV1> {
    limits.validate()?;
    let deadline = Instant::now() + limits.overall_timeout;
    let mut readers = (0..limits.max_workers)
        .map(|_| CellStoreV1::open_read_only(cache).map(Some))
        .collect::<CellResultV1<Vec<_>>>()?;
    listener.set_nonblocking(true)?;
    let responses = ResponseBudget::new(limits.max_response_bytes);
    let mut report = CellServeReportV1::default();
    thread::scope(|scope| -> CellResultV1<()> {
        let mut active: Vec<Option<CellServeWorker<'_>>> =
            (0..limits.max_workers).map(|_| None).collect();
        let mut failure = None;
        while !shutdown.load(Ordering::Relaxed)
            && report.accepted_connections < limits.max_connections
            && Instant::now() < deadline
        {
            reap_finished_workers(&mut active, &mut readers, &mut report, &mut failure);
            if failure.is_some() {
                // Explicitly join every remaining worker before returning an error.
                break;
            }
            #[cfg(test)]
            tests::observe_reap_accept_window(&active);
            match listener.accept() {
                Ok((mut stream, _)) => {
                    report.accepted_connections += 1;
                    if readers.iter().all(Option::is_none) {
                        // A worker may finish after the loop's reap and before
                        // accept. Reuse finished slots before deciding overload;
                        // never wait or queue for a worker that is still active.
                        reap_finished_workers(&mut active, &mut readers, &mut report, &mut failure);
                        if failure.is_some() {
                            break;
                        }
                    }
                    let Some(index) = readers.iter().position(Option::is_some) else {
                        report.overloaded_connections += 1;
                        drop(stream);
                        observed(&report);
                        continue;
                    };
                    let store = readers[index].take().unwrap();
                    let request_deadline = deadline.min(Instant::now() + limits.request_timeout);
                    let budget = &responses;
                    match thread::Builder::new()
                        .name("cell-serve".into())
                        .spawn_scoped(scope, move || {
                            let complete = serve_one_budgeted(
                                &mut stream,
                                &store,
                                request_deadline,
                                Some(budget),
                            )
                            .is_ok();
                            (store, complete)
                        }) {
                        Ok(worker) => active[index] = Some(worker),
                        Err(error) => {
                            failure = Some(error.into());
                            break;
                        }
                    }
                    report.peak_active_workers = report
                        .peak_active_workers
                        .max(active.iter().filter(|worker| worker.is_some()).count());
                    observed(&report);
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5))
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => (),
                Err(error) => {
                    failure = Some(error.into());
                    break;
                }
            }
        }
        for worker in active.into_iter().flatten() {
            drop(join_worker(worker, &mut report, &mut failure));
        }
        if let Some(error) = failure {
            return Err(error);
        }
        Ok(())
    })?;
    report.sent_response_bytes = responses.received()?;
    Ok(report)
}

#[cfg(test)]
mod tests;
