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
    pub(super) fn validate(self) -> CellResultV1<()> {
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

#[cfg(unix)]
fn listener_wait_timeout(deadline: Instant, now: Instant) -> Duration {
    Duration::from_millis(5).min(deadline.saturating_duration_since(now))
}

/// Readiness is only a hint. The caller rechecks shutdown, intake limits and
/// the original service deadline before retrying the nonblocking accept.
/// Interrupted polls return to that same outer loop without a timeout reset.
#[cfg(unix)]
pub(super) fn wait_for_listener(listener: &TcpListener, deadline: Instant) -> io::Result<bool> {
    use rustix::event::{poll, PollFd, PollFlags, Timespec};

    let wait = listener_wait_timeout(deadline, Instant::now());
    if wait.is_zero() {
        return Ok(false);
    }
    // At most 5 ms: both timespec fields fit on every supported Unix target.
    // The kernel's timer granularity does not move the service's deadline.
    let timeout = Timespec {
        tv_sec: 0,
        tv_nsec: wait.subsec_nanos() as _,
    };
    let mut descriptors = [PollFd::new(listener, PollFlags::IN)];
    poll(&mut descriptors, Some(&timeout))?;
    let events = descriptors[0].revents();
    if events.intersects(PollFlags::ERR | PollFlags::HUP | PollFlags::NVAL) {
        // Do not spin on a broken listener or bypass the ordinary join-all
        // failure exit. A borrowed descriptor remains owned by the caller.
        return Err(io::Error::other("cell serving listener readiness failure"));
    }
    Ok(events.contains(PollFlags::IN))
}

#[cfg(not(unix))]
pub(super) fn wait_for_listener(_listener: &TcpListener, _deadline: Instant) -> io::Result<bool> {
    // Preserve the existing portable path where Unix polling is unavailable.
    thread::sleep(Duration::from_millis(5));
    Ok(false)
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

/// Explicitly admit the separate TCI1/TIS1 bounded inventory profile on this
/// same server. Existing TCQ1/TCS1 byte requests retain their original meaning.
/// Inventory is a transient length/presence hint, never proof of possession.
pub fn serve_cells_bounded_with_availability(
    listener: &TcpListener,
    cache: &Path,
    shutdown: &AtomicBool,
    limits: CellServeLimitsV1,
) -> CellResultV1<CellServeReportV1> {
    serve_cells_profile(listener, cache, shutdown, limits, &|_| (), true, None)
}

/// Announce the completed reader setup without opening a probe connection.
/// The callback runs after every cache reader has passed its ordinary checks
/// and the listener is nonblocking, inside the original service deadline.
/// It is a local startup observation, not availability or custody authority.
pub fn serve_cells_bounded_with_ready(
    listener: &TcpListener,
    cache: &Path,
    shutdown: &AtomicBool,
    limits: CellServeLimitsV1,
    ready: &dyn Fn() -> CellResultV1<()>,
) -> CellResultV1<CellServeReportV1> {
    serve_cells_profile(
        listener,
        cache,
        shutdown,
        limits,
        &|_| (),
        false,
        Some(ready),
    )
}

/// The same startup observation for the explicit bounded inventory profile.
pub fn serve_cells_bounded_with_availability_and_ready(
    listener: &TcpListener,
    cache: &Path,
    shutdown: &AtomicBool,
    limits: CellServeLimitsV1,
    ready: &dyn Fn() -> CellResultV1<()>,
) -> CellResultV1<CellServeReportV1> {
    serve_cells_profile(
        listener,
        cache,
        shutdown,
        limits,
        &|_| (),
        true,
        Some(ready),
    )
}

pub(super) fn announce_service_ready(
    ready: Option<&dyn Fn() -> CellResultV1<()>>,
    shutdown: &AtomicBool,
    deadline: Instant,
    response_bytes: u64,
) -> CellResultV1<()> {
    if let Some(ready) = ready {
        let available = || {
            require(
                !shutdown.load(Ordering::Acquire)
                    && Instant::now() < deadline
                    && response_bytes > 0,
                "cell service not ready within original budget",
            )
        };
        available()?;
        ready()?;
        // Publishing or flushing the observation cannot renew the service.
        available()?;
    }
    Ok(())
}

fn serve_cells_inner(
    listener: &TcpListener,
    cache: &Path,
    shutdown: &AtomicBool,
    limits: CellServeLimitsV1,
    observed: &(impl Fn(&CellServeReportV1) + Sync),
) -> CellResultV1<CellServeReportV1> {
    serve_cells_profile(listener, cache, shutdown, limits, observed, false, None)
}

fn serve_cells_profile(
    listener: &TcpListener,
    cache: &Path,
    shutdown: &AtomicBool,
    limits: CellServeLimitsV1,
    observed: &(impl Fn(&CellServeReportV1) + Sync),
    allow_availability: bool,
    ready: Option<&dyn Fn() -> CellResultV1<()>>,
) -> CellResultV1<CellServeReportV1> {
    limits.validate()?;
    let deadline = Instant::now() + limits.overall_timeout;
    let mut readers = (0..limits.max_workers)
        .map(|_| CellStoreV1::open_read_only(cache).map(Some))
        .collect::<CellResultV1<Vec<_>>>()?;
    listener.set_nonblocking(true)?;
    announce_service_ready(ready, shutdown, deadline, limits.max_response_bytes)?;
    let responses = ResponseBudget::new(limits.max_response_bytes);
    let mut report = CellServeReportV1::default();
    thread::scope(|scope| -> CellResultV1<()> {
        let mut active: Vec<Option<CellServeWorker<'_>>> =
            (0..limits.max_workers).map(|_| None).collect();
        let mut failure = None;
        while !shutdown.load(Ordering::Relaxed)
            && report.accepted_connections < limits.max_connections
            && responses.received()? < limits.max_response_bytes
            && Instant::now() < deadline
        {
            reap_finished_workers(&mut active, &mut readers, &mut report, &mut failure);
            if failure.is_some() {
                // Explicitly join every remaining worker before returning an error.
                break;
            }
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
                            let complete = serve_one_profile(
                                &mut stream,
                                &store,
                                request_deadline,
                                Some(budget),
                                allow_availability,
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
                    match wait_for_listener(listener, deadline) {
                        Ok(_) => (),
                        Err(error) if error.kind() == io::ErrorKind::Interrupted => (),
                        Err(error) => {
                            failure = Some(error.into());
                            break;
                        }
                    }
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
