use super::*;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    mpsc, Mutex,
};
use std::time::Duration;

#[test]
fn bounded_queue_computes_every_index_once_and_preserves_result_order() {
    for count in [1, 2, 7, 8, 9, 17, 31, MAX_BATCH_V0] {
        for workers in [1, 2, 4, 8, 64] {
            let calls: Vec<_> = (0..count).map(|_| AtomicUsize::new(0)).collect();
            let result = run_indexed_jobs_v0(count, workers, |index| {
                assert_eq!(calls[index].fetch_add(1, Ordering::Relaxed), 0);
                Some(index * 3)
            });
            assert_eq!(result, (0..count).map(|i| Some(i * 3)).collect::<Vec<_>>());
            assert!(calls.iter().all(|n| n.load(Ordering::Relaxed) == 1));
        }
    }
}

#[test]
fn idle_workers_drain_remaining_jobs_while_first_job_is_blocked() {
    let count = 24;
    let (finished, ready) = mpsc::channel();
    let ready = Mutex::new(ready);
    let completed = AtomicUsize::new(0);
    let result = run_indexed_jobs_v0(count, 4, |index| {
        if index == 0 {
            // A static chunk scheduler cannot finish every other job while
            // this worker is blocked. Timeout bounds a failing regression.
            ready
                .lock()
                .unwrap()
                .recv_timeout(Duration::from_secs(5))
                .unwrap();
        } else if completed.fetch_add(1, Ordering::AcqRel) == count - 2 {
            finished.send(()).unwrap();
        }
        Some(index)
    });
    assert_eq!(completed.load(Ordering::Acquire), count - 1);
    assert_eq!(result, (0..count).map(Some).collect::<Vec<_>>());
}

#[test]
fn worker_panic_discards_its_results_and_joins_other_workers() {
    let finished = AtomicUsize::new(0);
    let result = run_indexed_jobs_v0(16, 4, |index| {
        assert_ne!(index, 0, "injected disposable worker panic");
        finished.fetch_add(1, Ordering::Relaxed);
        Some(index)
    });
    assert_eq!(result[0], None);
    assert_eq!(finished.load(Ordering::Relaxed), 15);
    assert_eq!(result[1..], (1..16).map(Some).collect::<Vec<_>>());
}

#[test]
fn scheduling_bounds_do_not_invoke_runtime_or_invent_results() {
    for (count, workers) in [(0, 8), (8, 0), (MAX_BATCH_V0 + 1, 8)] {
        let result: Vec<Option<usize>> = run_indexed_jobs_v0(count, workers, |_| {
            panic!("out-of-profile speculation must not run")
        });
        assert_eq!(result.len(), count);
        assert!(result.iter().all(Option::is_none));
    }
    assert_eq!(run_indexed_jobs_v0::<usize>(8, 4, |_| None).len(), 8);
}
