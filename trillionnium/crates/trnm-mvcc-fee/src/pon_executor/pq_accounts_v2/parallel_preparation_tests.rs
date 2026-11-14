//! Real NPQ6 signatures on the existing bounded executor. These controls observe
//! actual worker lifetimes and canonical patches; configured worker counts alone
//! are not evidence that more than one preparation ran.
use super::{fixture_v5 as fixture, *};
use crate::pon_executor::{self as exec, ExecutionProgress};
use std::{
    collections::HashSet,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Condvar, Mutex,
    },
    thread::ThreadId,
    time::Duration,
};

#[derive(Default)]
struct Workers {
    spawned: AtomicUsize,
    active: AtomicUsize,
    started: Mutex<Vec<ThreadId>>,
    finished: Mutex<Vec<ThreadId>>,
    refuse: Option<usize>,
}
struct Interval<'a> {
    workers: &'a Workers,
    thread: ThreadId,
}
impl exec::ExecutionWorkerInterval for Interval<'_> {}
impl Drop for Interval<'_> {
    fn drop(&mut self) {
        assert_eq!(std::thread::current().id(), self.thread);
        self.workers.finished.lock().unwrap().push(self.thread);
        self.workers.active.fetch_sub(1, Ordering::SeqCst);
    }
}
impl exec::ExecutionWorkerAccounting for Workers {
    fn worker_started(&self) -> Option<Box<dyn exec::ExecutionWorkerInterval + '_>> {
        let thread = std::thread::current().id();
        self.started.lock().unwrap().push(thread);
        self.active.fetch_add(1, Ordering::SeqCst);
        Some(Box::new(Interval {
            workers: self,
            thread,
        }))
    }
    fn worker_spawn_succeeded(&self) {
        self.spawned.fetch_add(1, Ordering::SeqCst);
    }
    fn test_spawn_allowed(&self, index: usize) -> bool {
        self.refuse != Some(index)
    }
}
impl Workers {
    fn joined(&self, expected: usize, owner: ThreadId) {
        assert_eq!(self.spawned.load(Ordering::SeqCst), expected);
        assert_eq!(self.active.load(Ordering::SeqCst), 0);
        let started = self.started.lock().unwrap();
        let finished = self.finished.lock().unwrap();
        assert_eq!(started.len(), expected);
        assert_eq!(finished.len(), expected);
        let identities: HashSet<_> = started.iter().copied().collect();
        assert_eq!(identities.len(), expected);
        assert!(!identities.contains(&owner));
        assert_eq!(identities, finished.iter().copied().collect());
    }
}

struct Harness {
    cfg: Config,
    state: State,
    genesis: Hash,
    keys: [fixture::Key; 3],
}
impl Harness {
    fn new() -> Self {
        let keys = [
            fixture::Key::public_test_seed(231),
            fixture::Key::public_test_seed(232),
            fixture::Key::public_test_seed(233),
        ];
        let accounts = keys
            .iter()
            .enumerate()
            .map(|(index, key)| GenesisAccount {
                spki: key.spki.clone(),
                balance: if index == 0 { 100_000_000 } else { 0 },
            })
            .collect::<Vec<_>>();
        let (cfg, state, genesis) = application_v6::genesis(
            &accounts,
            1000,
            &application_v6::ApplicationPolicy {
                evaluators: BTreeSet::from([keys[0].id, keys[1].id]),
                evaluation_profile: crate::public_evaluation::PROFILE.into(),
                model_profile: "linear-expert-dev-v1".into(),
            },
        )
        .unwrap();
        Self {
            cfg,
            state,
            genesis,
            keys,
        }
    }
    fn transfer(&self, sender: usize, nonce: u64, amount: u64) -> Vec<u8> {
        let payload = [
            self.keys[1 - sender].id.as_slice(),
            &amount.to_le_bytes(),
            &0_u16.to_be_bytes(),
        ]
        .concat();
        fixture::signed_for_profile(
            wire::AccountProfile::ApplicationV6,
            &fixture::common(context(&self.cfg).unwrap(), self.keys[sender].id, nonce, 1),
            1,
            &payload,
            &[fixture::primary(&self.keys[sender], 1)],
            None,
        )
    }
    fn batch(&self, count: usize, dependent: bool) -> Vec<Vec<u8>> {
        (0..count)
            .map(|index| {
                if dependent {
                    self.transfer(
                        index % 2,
                        (index / 2 + 1) as u64,
                        if index.is_multiple_of(2) {
                            1_000_000
                        } else {
                            100_000
                        },
                    )
                } else {
                    self.transfer(0, (index + 1) as u64, 1000)
                }
            })
            .collect()
    }
    fn run(
        &self,
        transactions: &[Vec<u8>],
        workers: usize,
        control: &exec::ExecutionControl<'_, &'static str>,
        observer: Option<&dyn exec::CanonicalTransitionObserver>,
    ) -> exec::ControlledResult<exec::Output, &'static str> {
        exec::execute_with_state_inputs(
            &self.state,
            exec::BlockExecution {
                timestamp: Some(1001),
                transactions,
                height: 1,
                miner: self.keys[2].id,
                parent_id: self.genesis,
                workers,
            },
            &self.cfg,
            |_, next| exec::root_for_config(next, &self.cfg),
            control,
            exec::StateInputs {
                observer,
                ..exec::StateInputs::default()
            },
        )
    }
}

// Only the first job of each existing worker waits. Reversing all transaction
// indices would deadlock the executor's fixed strided schedule at workers < 8.
struct ReverseFirst {
    count: usize,
    next: Mutex<usize>,
    wake: Condvar,
    completed: Mutex<Vec<usize>>,
}
impl ReverseFirst {
    fn new(count: usize) -> Self {
        Self {
            count,
            next: Mutex::new(count),
            wake: Condvar::new(),
            completed: Mutex::new(Vec::new()),
        }
    }
    fn after(&self, index: usize) {
        if index >= self.count {
            return;
        }
        let mut next = self.next.lock().unwrap();
        while *next != index + 1 {
            let waited = self
                .wake
                .wait_timeout(next, Duration::from_secs(10))
                .unwrap();
            next = waited.0;
            assert!(!waited.1.timed_out(), "real PQ worker rendezvous expired");
        }
        self.completed.lock().unwrap().push(index);
        *next -= 1;
        self.wake.notify_all();
    }
    fn assert_reversed(&self) {
        assert_eq!(
            *self.completed.lock().unwrap(),
            (0..self.count).rev().collect::<Vec<_>>()
        );
    }
}

struct CanonicalOwner<'a> {
    thread: ThreadId,
    transactions: &'a [Vec<u8>],
    applied: Mutex<Vec<usize>>,
}
impl exec::CanonicalTransitionObserver for CanonicalOwner<'_> {
    fn mandatory(&self, _: &State, _: &State, _: &[Vec<u8>]) -> Result<()> {
        assert_eq!(std::thread::current().id(), self.thread);
        Ok(())
    }
    fn native_pq_transaction(
        &self,
        index: usize,
        command: &PreparedCommand,
        before: &State,
        writes: &State,
        _: u64,
        _: &[u8],
    ) -> Result<()> {
        assert_eq!(std::thread::current().id(), self.thread);
        assert_eq!(command.raw(), self.transactions[index].as_slice());
        let sender = format!("account:{}", hex::encode(command.sender()));
        assert_eq!(field(&before[&sender], "nonce")? + 1, command.nonce());
        assert_eq!(field(&writes[&sender], "nonce")?, command.nonce());
        self.applied.lock().unwrap().push(index);
        Ok(())
    }
}

#[test]
fn pq_parallel_preparation_uses_real_workers_and_canonical_dependencies() {
    let h = Harness::new();
    let parent = h.state.clone();
    let owner = std::thread::current().id();
    for dependent in [false, true] {
        let transactions = h.batch(8, dependent);
        if dependent {
            // The second payer starts with zero funds. Its valid signature alone
            // cannot apply before the first canonical transfer credits it.
            assert_eq!(
                h.run(
                    &transactions[1..2],
                    1,
                    &exec::ExecutionControl::new(&|_| Ok(()), &()),
                    None,
                )
                .unwrap_err(),
                exec::ExecutionError::Relation("FUNDS")
            );
        }
        let mut reference = None;
        for count in [1, 2, 4, 8] {
            let workers = Workers::default();
            let reverse = ReverseFirst::new(count);
            let observation = CanonicalOwner {
                thread: owner,
                transactions: &transactions,
                applied: Mutex::new(Vec::new()),
            };
            let progress = |point| {
                match point {
                    ExecutionProgress::BeforePrepare { .. }
                    | ExecutionProgress::AfterPrepare { .. } => {
                        assert_eq!(std::thread::current().id() == owner, count == 1);
                        if let ExecutionProgress::AfterPrepare { index } = point {
                            reverse.after(index);
                        }
                    }
                    _ => assert_eq!(std::thread::current().id(), owner),
                }
                Ok(())
            };
            let output = h
                .run(
                    &transactions,
                    count,
                    &exec::ExecutionControl::new(&progress, &workers),
                    Some(&observation),
                )
                .unwrap();
            workers.joined(if count == 1 { 0 } else { count }, owner);
            reverse.assert_reversed();
            assert_eq!(output.metrics.signature_verifications, 8);
            assert_eq!(output.metrics.speculative, 0);
            assert_eq!(
                *observation.applied.lock().unwrap(),
                (0..8).collect::<Vec<_>>()
            );
            let actual = (output.state, output.receipts, output.root);
            if let Some(expected) = &reference {
                assert_eq!(&actual, expected);
            }
            reference = Some(actual);
            assert_eq!(h.state, parent);
        }
    }
}

#[test]
fn pq_parallel_preparation_keeps_early_state_error_before_late_bad_signature() {
    let h = Harness::new();
    let parent = h.state.clone();
    let owner = std::thread::current().id();
    for expected in ["NONCE", "FUNDS"] {
        let mut transactions = h.batch(8, false);
        transactions[0] = h.transfer(
            0,
            if expected == "NONCE" { 2 } else { 1 },
            if expected == "FUNDS" {
                200_000_000
            } else {
                1000
            },
        );
        *transactions[7].last_mut().unwrap() ^= 1;
        for count in [1, 2, 4, 8] {
            let workers = Workers::default();
            let late = (Mutex::new(false), Condvar::new());
            let order = Mutex::new(Vec::new());
            let progress = |point| {
                if count > 1 && point == (ExecutionProgress::BeforePrepare { index: 0 }) {
                    let ready = late.0.lock().unwrap();
                    let (ready, timed) = late
                        .1
                        .wait_timeout_while(ready, Duration::from_secs(10), |ready| !*ready)
                        .unwrap();
                    assert!(
                        *ready && !timed.timed_out(),
                        "late real signature never completed"
                    );
                }
                if let ExecutionProgress::AfterPrepare { index } = point {
                    order.lock().unwrap().push(index);
                    if index == 7 {
                        *late.0.lock().unwrap() = true;
                        late.1.notify_all();
                    }
                }
                if matches!(point, ExecutionProgress::BeforeApply { .. }) {
                    assert_eq!(std::thread::current().id(), owner);
                }
                Ok(())
            };
            assert_eq!(
                h.run(
                    &transactions,
                    count,
                    &exec::ExecutionControl::new(&progress, &workers),
                    None,
                )
                .unwrap_err(),
                exec::ExecutionError::Relation(expected)
            );
            workers.joined(if count == 1 { 0 } else { count }, owner);
            let completed = order.into_inner().unwrap();
            assert_eq!(completed.len(), 8);
            if count > 1 {
                assert!(
                    completed.iter().position(|i| *i == 7).unwrap()
                        < completed.iter().position(|i| *i == 0).unwrap()
                );
            }
            assert_eq!(h.state, parent);
        }
        // Establish that the same late bytes really fail ML-DSA, independently
        // of the deliberately earlier canonical state error.
        let attempts = AtomicUsize::new(0);
        assert_eq!(
            prepare_signature_metered(&h.state, &transactions[7], 1001, &h.cfg, &attempts).err(),
            Some("PQ2_SIGNATURE")
        );
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn pq_parallel_preparation_joins_cancelled_panicked_and_partial_workers_and_keeps_budget() {
    let h = Harness::new();
    let parent = h.state.clone();
    let transactions = h.batch(8, false);
    let owner = std::thread::current().id();
    for count in [2, 4, 8] {
        for panic_worker in [false, true] {
            let workers = Workers::default();
            let reverse = ReverseFirst::new(count);
            let progress = |point| {
                if let ExecutionProgress::AfterPrepare { index } = point {
                    reverse.after(index);
                    if index == 0 {
                        if panic_worker {
                            panic!("real PQ worker unwind after signature preparation");
                        }
                        return Err("TEST_ORIGINAL_PQ_CANCEL");
                    }
                }
                Ok(())
            };
            let failure = h
                .run(
                    &transactions,
                    count,
                    &exec::ExecutionControl::new(&progress, &workers),
                    None,
                )
                .unwrap_err();
            assert_eq!(
                failure,
                if panic_worker {
                    exec::ExecutionError::Relation("WORKER_PANIC")
                } else {
                    exec::ExecutionError::Cancelled("TEST_ORIGINAL_PQ_CANCEL")
                }
            );
            reverse.assert_reversed();
            workers.joined(count, owner);
            assert_eq!(h.state, parent);
        }
    }
    let partial = Workers {
        refuse: Some(2),
        ..Workers::default()
    };
    let prepared = AtomicUsize::new(0);
    assert_eq!(
        h.run(
            &transactions,
            4,
            &exec::ExecutionControl::new(
                &|point| {
                    if matches!(point, ExecutionProgress::AfterPrepare { .. }) {
                        prepared.fetch_add(1, Ordering::SeqCst);
                    }
                    Ok(())
                },
                &partial,
            ),
            None,
        )
        .unwrap_err(),
        exec::ExecutionError::Relation("WORKER_START")
    );
    partial.joined(2, owner);
    assert_eq!(prepared.load(Ordering::SeqCst), 4);
    assert_eq!(h.state, parent);

    // Retry a complete, real 64-signature block after the failures above. The
    // original NPQ6 transaction/signature limits are unchanged by worker count.
    let at_limit = h.batch(wire::APPLICATION_MAX_VERIFICATIONS, false);
    assert_eq!(at_limit.len(), 64);
    let mut expected = None;
    for count in [1, 2, 4, 8] {
        let workers = Workers::default();
        let output = h
            .run(
                &at_limit,
                count,
                &exec::ExecutionControl::new(&|_| Ok(()), &workers),
                None,
            )
            .unwrap();
        workers.joined(if count == 1 { 0 } else { count }, owner);
        assert_eq!(output.metrics.signature_verifications, 64);
        let actual = (output.state, output.receipts, output.root);
        if let Some(prior) = &expected {
            assert_eq!(&actual, prior);
        }
        expected = Some(actual);
        let mut over_limit = at_limit.clone();
        over_limit.push(h.transfer(0, 65, 1000));
        let denied = Workers::default();
        let preparation_calls = AtomicUsize::new(0);
        assert_eq!(
            h.run(
                &over_limit,
                count,
                &exec::ExecutionControl::new(
                    &|point| {
                        if matches!(point, ExecutionProgress::BeforePrepare { .. }) {
                            preparation_calls.fetch_add(1, Ordering::SeqCst);
                        }
                        Ok(())
                    },
                    &denied,
                ),
                None,
            )
            .unwrap_err(),
            exec::ExecutionError::Relation("PQ2_TRANSACTION_LIMIT")
        );
        denied.joined(0, owner);
        assert_eq!(preparation_calls.load(Ordering::SeqCst), 0);
    }
    let mut bad = transactions[0].clone();
    *bad.last_mut().unwrap() ^= 1;
    let attempts = AtomicUsize::new(0);
    for _ in 0..63 {
        prepare_signature_metered(&h.state, &transactions[0], 1001, &h.cfg, &attempts).unwrap();
    }
    assert_eq!(attempts.load(Ordering::SeqCst), 63);
    assert_eq!(
        prepare_signature_metered(&h.state, &bad, 1001, &h.cfg, &attempts).err(),
        Some("PQ2_SIGNATURE")
    );
    assert_eq!(attempts.load(Ordering::SeqCst), 64);
    assert_eq!(
        prepare_signature_metered(&h.state, &transactions[0], 1001, &h.cfg, &attempts).err(),
        Some("PQ_VERIFY_BUDGET")
    );
    assert_eq!(attempts.load(Ordering::SeqCst), 64);
    assert_eq!(h.state, parent);
}
