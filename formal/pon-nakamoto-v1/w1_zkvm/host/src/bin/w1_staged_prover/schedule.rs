//! Scheduling rules only. No value produced here is a cryptographic receipt.
use anyhow::{ensure, Context, Result};
use std::{
    panic::{catch_unwind, AssertUnwindSafe},
    sync::atomic::{AtomicBool, Ordering},
    thread,
};

pub(super) const MAX_ITEMS: usize = 4096;
pub(super) const MAX_WORKERS: usize = 4;
const MAX_RAYON_THREADS: usize = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Resources {
    pub(super) workers: usize,
    pub(super) rayon_threads: usize,
}

impl Resources {
    pub(super) fn new(workers: usize, rayon_threads: usize) -> Result<Self> {
        ensure!(
            (1..=MAX_WORKERS).contains(&workers),
            "backend workers must be 1..4"
        );
        ensure!(
            rayon_threads > 0,
            "each backend worker needs explicit Rayon threads"
        );
        let requested = workers
            .checked_mul(rayon_threads)
            .context("backend thread budget overflow")?;
        ensure!(
            requested <= MAX_RAYON_THREADS,
            "backend workers times Rayon threads exceeds the eight-thread experiment bound"
        );
        Ok(Self {
            workers,
            rayon_threads,
        })
    }

    pub(super) fn checkpoint_namespace(self) -> String {
        format!(
            "balanced-v2-w{:02}-t{:02}",
            self.workers, self.rayon_threads
        )
    }

    pub(super) fn segment_candidate_namespace(self) -> String {
        format!(
            "segment-parallel-v1-w{:02}-t{:02}",
            self.workers, self.rayon_threads
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Range {
    pub(super) start: usize,
    pub(super) end: usize,
}

#[derive(Debug)]
pub(super) struct Pair {
    pub(super) left: usize,
    pub(super) right: usize,
    pub(super) range: Range,
}

#[derive(Debug)]
pub(super) struct Round {
    pub(super) pairs: Vec<Pair>,
    pub(super) carry: Option<usize>,
}

pub(super) fn validate_partition(ranges: &[Range], total: usize) -> Result<()> {
    ensure!(
        (1..=MAX_ITEMS).contains(&total),
        "complete segment count bound"
    );
    ensure!(!ranges.is_empty(), "empty recursive partition");
    let mut expected = 0;
    for range in ranges {
        ensure!(
            range.start == expected && range.start < range.end && range.end <= total,
            "recursive ranges must cover the original ordered session exactly once"
        );
        expected = range.end;
    }
    ensure!(
        expected == total,
        "recursive partition omits the session suffix"
    );
    Ok(())
}

pub(super) fn plan_round(ranges: &[Range], total: usize) -> Result<Round> {
    validate_partition(ranges, total)?;
    ensure!(
        ranges.len() > 1,
        "a complete recursive root needs no further round"
    );
    let pairs = (0..ranges.len() / 2)
        .map(|index| {
            let left = index * 2;
            let right = left + 1;
            Pair {
                left,
                right,
                range: Range {
                    start: ranges[left].start,
                    end: ranges[right].end,
                },
            }
        })
        .collect();
    let carry = (ranges.len() % 2 == 1).then_some(ranges.len() - 1);
    Ok(Round { pairs, carry })
}

// Set stop while an error or panic leaves the individual call, before dropping
// its enclosing client context. Waiting until the parent joins this worker can
// otherwise let other workers dispatch an entire stride after a panic.
struct StopOnError<'a> {
    stop: &'a AtomicBool,
    armed: bool,
}

impl Drop for StopOnError<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.stop.store(true, Ordering::SeqCst);
        }
    }
}

fn stop_on_error<T>(stop: &AtomicBool, call: impl FnOnce() -> Result<T>) -> Result<T> {
    let mut guard = StopOnError { stop, armed: true };
    let result = call();
    if result.is_ok() {
        guard.armed = false;
    }
    result
}

/// Drain every started Rust worker, including on client-init errors, operation
/// errors, panics and OS thread-spawn errors. A call admitted before stop may
/// finish; this is not cancellation or proof of reaping an SDK's child process.
pub(super) fn scoped_items<T: Send, C>(
    count: usize,
    workers: usize,
    initialize: impl Fn(usize) -> Result<C> + Sync,
    perform: impl Fn(&C, usize, usize) -> Result<T> + Sync,
) -> Result<Vec<T>> {
    ensure!(
        (1..=MAX_ITEMS).contains(&count),
        "bounded nonempty work required"
    );
    ensure!((1..=MAX_WORKERS).contains(&workers), "worker count bound");
    let workers = workers.min(count);
    let stop = AtomicBool::new(false);
    thread::scope(|scope| {
        let mut handles = Vec::with_capacity(workers);
        let mut errors = Vec::new();
        for worker in 0..workers {
            if stop.load(Ordering::SeqCst) {
                break;
            }
            let stop = &stop;
            let initialize = &initialize;
            let perform = &perform;
            let spawned = thread::Builder::new()
                .name(format!("w1-backend-{worker}"))
                .spawn_scoped(scope, move || {
                    let mut completed = Vec::new();
                    let result = catch_unwind(AssertUnwindSafe(|| -> Result<()> {
                        if stop.load(Ordering::SeqCst) {
                            return Ok(());
                        }
                        let client = stop_on_error(stop, || initialize(worker))
                            .with_context(|| format!("worker {worker} client initialization"))?;
                        for index in (worker..count).step_by(workers) {
                            if stop.load(Ordering::SeqCst) {
                                break;
                            }
                            let value = stop_on_error(stop, || perform(&client, worker, index))
                                .with_context(|| format!("worker {worker} item {index}"))?;
                            completed.push((index, value));
                        }
                        Ok(())
                    }));
                    let error = match result {
                        Ok(Ok(())) => None,
                        Ok(Err(error)) => Some(format!("{error:#}")),
                        Err(payload) => {
                            stop.store(true, Ordering::SeqCst);
                            let reason = payload
                                .downcast_ref::<&str>()
                                .map(|value| (*value).to_owned())
                                .or_else(|| payload.downcast_ref::<String>().cloned())
                                .unwrap_or_else(|| "non-string panic payload".into());
                            Some(format!("worker {worker} panicked: {reason}"))
                        }
                    };
                    (completed, error)
                });
            match spawned {
                Ok(handle) => handles.push((worker, handle)),
                Err(error) => {
                    stop.store(true, Ordering::SeqCst);
                    errors.push(format!("worker {worker} thread spawn failed: {error}"));
                    break;
                }
            }
        }
        let mut rows = Vec::with_capacity(count);
        for (worker, handle) in handles {
            match handle.join() {
                Ok((mut completed, error)) => {
                    rows.append(&mut completed);
                    if let Some(error) = error {
                        errors.push(error);
                    }
                }
                Err(_) => {
                    stop.store(true, Ordering::SeqCst);
                    errors.push(format!(
                        "worker {worker} panicked outside its operation guard"
                    ));
                }
            }
        }
        ensure!(
            errors.is_empty(),
            "parallel backend failed: {}",
            errors.join("; ")
        );
        ensure!(rows.len() == count, "parallel backend omitted work");
        rows.sort_by_key(|(index, _)| *index);
        ensure!(
            rows.iter()
                .enumerate()
                .all(|(expected, (actual, _))| expected == *actual),
            "parallel backend result order changed"
        );
        Ok(rows.into_iter().map(|(_, value)| value).collect())
    })
}

#[cfg(test)]
#[path = "schedule_tests.rs"]
mod tests;
