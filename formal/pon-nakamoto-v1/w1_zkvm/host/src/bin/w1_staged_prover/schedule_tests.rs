//! Finite scheduler tests. These never construct or certify a zkVM proof.
use super::*;
use std::sync::{
    atomic::AtomicUsize,
    mpsc::{channel, Sender},
    Mutex,
};
use std::time::Duration;

const WAIT: Duration = Duration::from_secs(5);

#[derive(Default)]
struct Counters {
    initialized: AtomicUsize,
    dropped: AtomicUsize,
    live: AtomicUsize,
    peak: AtomicUsize,
    calls: AtomicUsize,
}

struct Client<'a> {
    worker: usize,
    counters: &'a Counters,
    dropped_signal: Option<&'a Sender<usize>>,
}

impl<'a> Client<'a> {
    fn new(worker: usize, counters: &'a Counters) -> Self {
        counters.initialized.fetch_add(1, Ordering::SeqCst);
        let live = counters.live.fetch_add(1, Ordering::SeqCst) + 1;
        counters.peak.fetch_max(live, Ordering::SeqCst);
        Self {
            worker,
            counters,
            dropped_signal: None,
        }
    }
}

impl Drop for Client<'_> {
    fn drop(&mut self) {
        self.counters.live.fetch_sub(1, Ordering::SeqCst);
        self.counters.dropped.fetch_add(1, Ordering::SeqCst);
        if let Some(signal) = self.dropped_signal {
            let _ = signal.send(self.worker);
        }
    }
}

#[test]
fn forty_three_leaves_keep_every_interval_once_without_padding() {
    let mut ranges: Vec<_> = (0..43)
        .map(|start| Range {
            start,
            end: start + 1,
        })
        .collect();
    let mut leaves: Vec<_> = (0..43).map(|index| vec![index]).collect();
    let mut joins = 0;
    let mut round_sizes = Vec::new();
    let mut carries = Vec::new();
    while ranges.len() > 1 {
        let round = plan_round(&ranges, 43).unwrap();
        let mut next_ranges = Vec::new();
        let mut next_leaves = Vec::new();
        let mut consumed = vec![false; ranges.len()];
        for pair in &round.pairs {
            assert!(!consumed[pair.left] && !consumed[pair.right]);
            consumed[pair.left] = true;
            consumed[pair.right] = true;
            assert_eq!(ranges[pair.left].end, ranges[pair.right].start);
            assert_eq!(
                pair.range,
                Range {
                    start: ranges[pair.left].start,
                    end: ranges[pair.right].end,
                }
            );
            let mut items = leaves[pair.left].clone();
            items.extend_from_slice(&leaves[pair.right]);
            next_ranges.push(pair.range);
            next_leaves.push(items);
        }
        if let Some(index) = round.carry {
            assert!(!consumed[index]);
            consumed[index] = true;
            next_ranges.push(ranges[index]);
            next_leaves.push(leaves[index].clone());
        }
        assert!(consumed.into_iter().all(|value| value));
        validate_partition(&next_ranges, 43).unwrap();
        joins += round.pairs.len();
        carries.push(round.carry);
        round_sizes.push(next_ranges.len());
        ranges = next_ranges;
        leaves = next_leaves;
    }
    assert_eq!(round_sizes, vec![22, 11, 6, 3, 2, 1]);
    assert_eq!(carries, vec![Some(42), None, Some(10), None, Some(2), None]);
    assert_eq!(joins, 42);
    assert_eq!(ranges, vec![Range { start: 0, end: 43 }]);
    assert_eq!(leaves, vec![(0..43).collect::<Vec<_>>()]);
}

#[test]
fn partition_rejects_gaps_duplicates_overlap_and_missing_suffix() {
    for ranges in [
        vec![],
        vec![Range { start: 1, end: 3 }],
        vec![Range { start: 0, end: 2 }],
        vec![Range { start: 0, end: 4 }],
        vec![Range { start: 0, end: 0 }, Range { start: 0, end: 3 }],
        vec![Range { start: 0, end: 1 }, Range { start: 2, end: 3 }],
        vec![Range { start: 0, end: 2 }, Range { start: 1, end: 3 }],
        vec![Range { start: 0, end: 1 }, Range { start: 0, end: 3 }],
    ] {
        assert!(validate_partition(&ranges, 3).is_err());
        assert!(plan_round(&ranges, 3).is_err());
    }
    assert!(validate_partition(&[], 0).is_err());
    assert!(validate_partition(
        &[Range {
            start: 0,
            end: MAX_ITEMS + 1
        }],
        MAX_ITEMS + 1
    )
    .is_err());
    validate_partition(&[Range { start: 0, end: 1 }], 1).unwrap();
    assert!(plan_round(&[Range { start: 0, end: 1 }], 1).is_err());
}

#[test]
fn resource_plans_bound_total_rayon_requests_and_separate_caches() {
    let plans = [
        Resources::new(1, 8).unwrap(),
        Resources::new(2, 4).unwrap(),
        Resources::new(4, 2).unwrap(),
    ];
    for (index, plan) in plans.iter().enumerate() {
        for other in &plans[index + 1..] {
            assert_ne!(plan.checkpoint_namespace(), other.checkpoint_namespace());
        }
    }
    for (workers, threads) in [(0, 8), (5, 1), (2, 8), (1, 0), (4, usize::MAX)] {
        assert!(Resources::new(workers, threads).is_err());
    }
}

#[test]
fn scoped_workers_bound_live_contexts_restore_order_and_drop_every_context() {
    let counters = Counters::default();
    let values = scoped_items(
        43,
        2,
        |worker| Ok(Client::new(worker, &counters)),
        |client, worker, index| {
            assert_eq!(client.worker, worker);
            counters.calls.fetch_add(1, Ordering::SeqCst);
            if index % 2 == 0 {
                thread::yield_now();
            }
            Ok(index * index)
        },
    )
    .unwrap();
    assert_eq!(
        values,
        (0..43).map(|value| value * value).collect::<Vec<_>>()
    );
    assert_eq!(counters.calls.load(Ordering::SeqCst), 43);
    assert_eq!(counters.initialized.load(Ordering::SeqCst), 2);
    assert_eq!(counters.dropped.load(Ordering::SeqCst), 2);
    assert_eq!(counters.live.load(Ordering::SeqCst), 0);
    assert!(counters.peak.load(Ordering::SeqCst) <= 2);
}

#[test]
fn every_in_flight_error_survives_worker_collection() {
    let counters = Counters::default();
    let (first_ready, first_wait) = channel();
    let (second_ready, second_wait) = channel();
    let first_wait = Mutex::new(first_wait);
    let second_wait = Mutex::new(second_wait);
    let error = scoped_items::<usize, _>(
        43,
        2,
        |worker| Ok(Client::new(worker, &counters)),
        |_client, worker, _index| {
            counters.calls.fetch_add(1, Ordering::SeqCst);
            if worker == 0 {
                first_ready.send(())?;
                second_wait.lock().unwrap().recv_timeout(WAIT)?;
            } else {
                second_ready.send(())?;
                first_wait.lock().unwrap().recv_timeout(WAIT)?;
            }
            anyhow::bail!("observed failure from worker {worker}");
        },
    )
    .unwrap_err();
    let error = format!("{error:#}");
    assert!(error.contains("observed failure from worker 0"));
    assert!(error.contains("observed failure from worker 1"));
    assert_eq!(counters.calls.load(Ordering::SeqCst), 2);
    assert_eq!(counters.dropped.load(Ordering::SeqCst), 2);
    assert_eq!(counters.live.load(Ordering::SeqCst), 0);
}

#[test]
fn panic_stops_further_admission_before_the_panicking_client_is_dropped() {
    let counters = Counters::default();
    let (first_ready, first_wait) = channel();
    let (second_ready, second_wait) = channel();
    let (dropped, dropped_wait) = channel();
    let first_wait = Mutex::new(first_wait);
    let second_wait = Mutex::new(second_wait);
    let dropped_wait = Mutex::new(dropped_wait);
    let error = scoped_items::<usize, _>(
        43,
        2,
        |worker| {
            let mut client = Client::new(worker, &counters);
            if worker == 0 {
                client.dropped_signal = Some(&dropped);
            }
            Ok(client)
        },
        |_client, worker, index| {
            counters.calls.fetch_add(1, Ordering::SeqCst);
            if worker == 0 {
                first_ready.send(())?;
                second_wait.lock().unwrap().recv_timeout(WAIT)?;
                panic!("intentional scheduler-only panic");
            }
            second_ready.send(())?;
            first_wait.lock().unwrap().recv_timeout(WAIT)?;
            assert_eq!(dropped_wait.lock().unwrap().recv_timeout(WAIT)?, 0);
            Ok(index)
        },
    )
    .unwrap_err();
    assert!(format!("{error:#}").contains("intentional scheduler-only panic"));
    assert_eq!(counters.calls.load(Ordering::SeqCst), 2);
    assert_eq!(counters.dropped.load(Ordering::SeqCst), 2);
    assert_eq!(counters.live.load(Ordering::SeqCst), 0);
}

#[test]
fn initialization_error_joins_an_already_initialized_other_worker() {
    let counters = Counters::default();
    let (initialized, initialized_wait) = channel();
    let initialized_wait = Mutex::new(initialized_wait);
    let error = scoped_items(
        43,
        2,
        |worker| {
            if worker == 0 {
                initialized_wait.lock().unwrap().recv_timeout(WAIT)?;
                anyhow::bail!("client construction failed");
            }
            let client = Client::new(worker, &counters);
            initialized.send(())?;
            Ok(client)
        },
        |_client, _worker, index| Ok(index),
    )
    .unwrap_err();
    assert!(format!("{error:#}").contains("worker 0 client initialization"));
    assert_eq!(counters.initialized.load(Ordering::SeqCst), 1);
    assert_eq!(counters.dropped.load(Ordering::SeqCst), 1);
    assert_eq!(counters.live.load(Ordering::SeqCst), 0);
}

#[test]
fn invalid_work_never_initializes_a_client() {
    let calls = AtomicUsize::new(0);
    for (count, workers) in [(0, 1), (MAX_ITEMS + 1, 1), (1, 0), (1, MAX_WORKERS + 1)] {
        assert!(scoped_items(
            count,
            workers,
            |_| {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
            |_, _, index| Ok(index),
        )
        .is_err());
    }
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}
