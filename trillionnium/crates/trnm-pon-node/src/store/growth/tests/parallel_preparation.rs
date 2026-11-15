//! Exercise the actual Growth admission owner, proof view and scoped worker
//! accounting. Parallel preparation must preserve canonical effects and replay.
use super::*;
use pon_executor::{ExecutionProgress, ExecutionWorkerAccounting, ExecutionWorkerInterval};

#[derive(Default)]
struct JoinedWorkers {
    spawned: AtomicUsize,
    started: AtomicUsize,
    finished: AtomicUsize,
    active: AtomicUsize,
}

struct WorkerInterval<'a>(&'a JoinedWorkers);
impl ExecutionWorkerInterval for WorkerInterval<'_> {}
impl Drop for WorkerInterval<'_> {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::SeqCst);
        self.0.finished.fetch_add(1, Ordering::SeqCst);
    }
}
impl ExecutionWorkerAccounting for JoinedWorkers {
    fn worker_started(&self) -> Option<Box<dyn ExecutionWorkerInterval + '_>> {
        self.started.fetch_add(1, Ordering::SeqCst);
        self.active.fetch_add(1, Ordering::SeqCst);
        Some(Box::new(WorkerInterval(self)))
    }
    fn worker_spawn_succeeded(&self) {
        self.spawned.fetch_add(1, Ordering::SeqCst);
    }
}
impl JoinedWorkers {
    fn assert_joined(&self, workers: usize) {
        let expected = if workers == 1 { 0 } else { workers };
        assert_eq!(self.spawned.load(Ordering::SeqCst), expected);
        assert_eq!(self.started.load(Ordering::SeqCst), expected);
        assert_eq!(self.finished.load(Ordering::SeqCst), expected);
        assert_eq!(self.active.load(Ordering::SeqCst), 0);
    }
}

fn signed_batch(settings: &Settings, hot: bool) -> Vec<Vec<u8>> {
    (0..8)
        .map(|index| {
            transfer(
                settings,
                if hot { 0 } else { index % 4 },
                if hot { index + 1 } else { index / 4 + 1 },
                public(if hot { 100 } else { 100 + index }),
                1000,
            )
        })
        .collect()
}

fn checked(packet: &GrowthPacket) -> GrowthWorkCheckedPacket {
    GrowthWorkCheckedPacket::verify_with_progress(packet.clone(), &|_| Ok(())).unwrap()
}

#[test]
fn growth_parallel_preparation_preserves_signed_effects_nonce_roots_and_cold_replay() {
    for hot in [false, true] {
        let settings = settings();
        let source_dir = tempfile::tempdir().unwrap();
        let source =
            Node::open_with_permanent_account_growth_v2(source_dir.path(), settings.clone())
                .unwrap();
        let packet = make(&source, settings.genesis(), signed_batch(&settings, hot));
        let expected = reference(&settings, &settings.initial, &packet);
        let mut prior_rows = None;
        for workers in [1, 2, 4, 8] {
            let dir = tempfile::tempdir().unwrap();
            let mut node = Node::open_with_permanent_account_growth_v2_and_workers(
                dir.path(),
                settings.clone(),
                workers,
            )
            .unwrap();
            let accounting = JoinedWorkers::default();
            let caller = std::thread::current().id();
            let id = node
                .admit_growth_work_checked_with_worker_accounting(
                    checked(&packet),
                    100_000,
                    &|point| {
                        if !matches!(
                            point,
                            GrowthProgress::Execution(
                                ExecutionProgress::BeforePrepare { .. }
                                    | ExecutionProgress::AfterPrepare { .. }
                            )
                        ) {
                            assert_eq!(
                                std::thread::current().id(),
                                caller,
                                "state/proof/commit left owner"
                            );
                        }
                        Ok(())
                    },
                    &accounting,
                )
                .unwrap();
            accounting.assert_joined(workers);
            assert_eq!(node.active().unwrap(), (settings.genesis(), 0));
            assert_eq!(node.activate(id).unwrap(), id);
            assert_reference(&node, id, &expected);
            let actual = rows(&node.db);
            if let Some(prior) = &prior_rows {
                assert_eq!(&actual, prior);
            }
            prior_rows = Some(actual.clone());
            let active = node.active().unwrap();
            drop(node);
            // Cold audit uses its original independent serial execution path.
            let reopened =
                Node::open_with_permanent_account_growth_v2(dir.path(), settings.clone()).unwrap();
            assert_eq!(reopened.active().unwrap(), active);
            assert_eq!(rows(&reopened.db), actual);
            assert_reference(&reopened, id, &expected);
        }
    }
}

#[test]
fn growth_parallel_preparation_has_only_canonical_witness_access() {
    let settings = settings();
    let dir = tempfile::tempdir().unwrap();
    let node = Node::open_with_permanent_account_growth_v2(dir.path(), settings.clone()).unwrap();
    let packet = make(&node, settings.genesis(), signed_batch(&settings, false));
    let parent = node.growth_parent(settings.genesis()).unwrap();
    let proof = CheckedMultiproof::verify(context(&settings), &parent.checkpoint, &packet.accounts)
        .unwrap();
    let mut view = parent.source.stored.working.clone();
    for (owner, value) in proof.values() {
        if let Some(value) = value {
            view.insert(
                format!("account:{}", hex::encode(owner)),
                json!({"balance":value.balance,"nonce":value.nonce}),
            );
        }
    }
    let partition = limits::AccountPartition {
        parent_count: parent.verified.permanent_account_count,
        parent_balance: parent.verified.permanent_account_balance,
    };
    let mut reference_accesses = None;
    for workers in [1, 2, 4, 8] {
        let caller = std::thread::current().id();
        let accesses = Mutex::new(Vec::new());
        let access = |who: &str| {
            assert_eq!(
                std::thread::current().id(),
                caller,
                "speculative witness access"
            );
            let owner = crate::digest(who).map_err(|_| "GROWTH_ACCOUNT_KEY")?;
            proof
                .account(owner)
                .map_err(|_| "GROWTH_MISSING_ACCOUNT_WITNESS")?;
            accesses.lock().unwrap().push(who.to_owned());
            Ok(())
        };
        let accounting = JoinedWorkers::default();
        let h = &packet.header.ledger;
        let output = limits::execute_with_commitment_observed_control(
            &view,
            pon_executor::BlockExecution {
                timestamp: Some(h.timestamp),
                transactions: &packet.transactions,
                height: h.height,
                miner: h.miner,
                parent_id: h.parent,
                workers,
            },
            &settings.app,
            limits::GrowthExecutionInputs {
                partition: &partition,
                account_access: &access,
                observer: None,
            },
            |_, next| {
                native_growth::successor_with_progress(&parent.verified, &proof, next, &|_| Ok(()))
                    .map(|s| s.id)
                    .map_err(|_| "TEST_COMMITMENT")
            },
            &pon_executor::ExecutionControl::new(&|_| Ok::<_, Error>(()), &accounting),
        )
        .unwrap();
        accounting.assert_joined(workers);
        assert_eq!(output.root, h.state);
        assert_eq!(sequence_root("receipts", &output.receipts), h.receipts);
        assert_eq!(output.metrics.signature_verifications, 8);
        let actual = accesses.into_inner().unwrap();
        assert!(!actual.is_empty());
        if let Some(prior) = &reference_accesses {
            assert_eq!(&actual, prior);
        }
        reference_accesses = Some(actual);
    }
}

#[test]
fn growth_parallel_preparation_joins_cancelled_workers_and_rolls_back_then_retries() {
    let settings = settings();
    let source_dir = tempfile::tempdir().unwrap();
    let source =
        Node::open_with_permanent_account_growth_v2(source_dir.path(), settings.clone()).unwrap();
    let packet = make(&source, settings.genesis(), signed_batch(&settings, false));
    for workers in [1, 2, 4, 8] {
        for after_write in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let mut node = Node::open_with_permanent_account_growth_v2_and_workers(
                dir.path(),
                settings.clone(),
                workers,
            )
            .unwrap();
            let before = rows(&node.db);
            let accounting = JoinedWorkers::default();
            let error = node
                .admit_growth_work_checked_with_worker_accounting(
                    checked(&packet),
                    100_000,
                    &|point| {
                        let cancel = if after_write {
                            point == GrowthProgress::BeforeCommit
                        } else {
                            point
                                == GrowthProgress::Execution(ExecutionProgress::AfterPrepare {
                                    index: 0,
                                })
                        };
                        if cancel {
                            Err("TEST_ORIGINAL_CANCEL".into())
                        } else {
                            Ok(())
                        }
                    },
                    &accounting,
                )
                .unwrap_err();
            assert_eq!(error.to_string(), "TEST_ORIGINAL_CANCEL");
            accounting.assert_joined(workers);
            assert_eq!(rows(&node.db), before);
            assert_eq!(node.active().unwrap(), (settings.genesis(), 0));
            let id = node.admit_growth(&packet, 100_000).unwrap();
            assert_eq!(id, packet.id().unwrap());
        }
    }
}

#[test]
fn growth_parallel_preparation_preserves_signature_rejection_and_worker_limit() {
    let settings = settings();
    let source_dir = tempfile::tempdir().unwrap();
    let source =
        Node::open_with_permanent_account_growth_v2(source_dir.path(), settings.clone()).unwrap();
    let mut packet = make(&source, settings.genesis(), signed_batch(&settings, false));
    *packet.transactions[3].last_mut().unwrap() ^= 1;
    packet.header.ledger.transactions = sequence_root("transactions", &packet.transactions);
    reseal(&mut packet);
    let mut reference_error = None;
    for workers in [1, 2, 4, 8] {
        let dir = tempfile::tempdir().unwrap();
        let mut node = Node::open_with_permanent_account_growth_v2_and_workers(
            dir.path(),
            settings.clone(),
            workers,
        )
        .unwrap();
        let before = rows(&node.db);
        let accounting = JoinedWorkers::default();
        let error = node
            .admit_growth_work_checked_with_worker_accounting(
                checked(&packet),
                100_000,
                &|_| Ok(()),
                &accounting,
            )
            .unwrap_err()
            .to_string();
        assert!(error.contains("SIGNATURE"), "{error}");
        accounting.assert_joined(workers);
        assert_eq!(rows(&node.db), before);
        if let Some(prior) = &reference_error {
            assert_eq!(&error, prior);
        }
        reference_error = Some(error);
    }
    for workers in [0, 3, 9, usize::MAX] {
        let dir = tempfile::tempdir().unwrap();
        let store = dir.path().join("must-not-be-created");
        assert_eq!(
            Node::open_with_permanent_account_growth_v2_and_workers(
                &store,
                settings.clone(),
                workers
            )
            .err()
            .unwrap()
            .to_string(),
            "GROWTH_WORKERS"
        );
        assert!(!store.exists());
    }
}

#[test]
fn growth_parallel_preparation_keeps_early_state_error_before_late_bad_signature() {
    let settings = settings();
    let source_dir = tempfile::tempdir().unwrap();
    let source =
        Node::open_with_permanent_account_growth_v2(source_dir.path(), settings.clone()).unwrap();
    let original = make(&source, settings.genesis(), signed_batch(&settings, false));
    for expected in ["NONCE", "FUNDS"] {
        let mut packet = original.clone();
        packet.transactions[0] = transfer(
            &settings,
            0,
            if expected == "NONCE" { 2 } else { 1 },
            public(100),
            if expected == "FUNDS" { u64::MAX } else { 1_000 },
        );
        // The early error has a valid signature. Recompute the transaction
        // commitment and full W1 after corrupting a later signature, so header
        // filtering cannot stand in for canonical transaction error order.
        *packet.transactions[7].last_mut().unwrap() ^= 1;
        packet.header.ledger.transactions = sequence_root("transactions", &packet.transactions);
        reseal(&mut packet);
        for workers in [1, 2, 4, 8] {
            let dir = tempfile::tempdir().unwrap();
            let mut node = Node::open_with_permanent_account_growth_v2_and_workers(
                dir.path(),
                settings.clone(),
                workers,
            )
            .unwrap();
            let before = rows(&node.db);
            let accounting = JoinedWorkers::default();
            let after_apply = AtomicUsize::new(0);
            let error = node
                .admit_growth_work_checked_with_worker_accounting(
                    checked(&packet),
                    100_000,
                    &|point| {
                        if matches!(
                            point,
                            GrowthProgress::Execution(ExecutionProgress::AfterApply { .. })
                        ) {
                            after_apply.fetch_add(1, Ordering::Relaxed);
                        }
                        Ok(())
                    },
                    &accounting,
                )
                .unwrap_err();
            assert_eq!(error.to_string(), expected, "workers={workers}");
            accounting.assert_joined(workers);
            assert_eq!(after_apply.load(Ordering::Relaxed), 0);
            assert!(node.db.is_autocommit());
            assert_eq!(rows(&node.db), before);
            assert_eq!(node.active().unwrap(), (settings.genesis(), 0));
            assert_eq!(
                node.admit_growth(&original, 100_000).unwrap(),
                original.id().unwrap()
            );
        }
    }
}

#[cfg(panic = "unwind")]
#[test]
fn growth_parallel_preparation_joins_panicked_workers_and_owner_can_retry() {
    let settings = settings();
    let source_dir = tempfile::tempdir().unwrap();
    let source =
        Node::open_with_permanent_account_growth_v2(source_dir.path(), settings.clone()).unwrap();
    let packet = make(&source, settings.genesis(), signed_batch(&settings, false));
    for workers in [2, 4, 8] {
        let dir = tempfile::tempdir().unwrap();
        let mut node = Node::open_with_permanent_account_growth_v2_and_workers(
            dir.path(),
            settings.clone(),
            workers,
        )
        .unwrap();
        let before = rows(&node.db);
        let accounting = JoinedWorkers::default();
        let error = node
            .admit_growth_work_checked_with_worker_accounting(
                checked(&packet),
                100_000,
                &|point| {
                    assert_ne!(
                        point,
                        GrowthProgress::Execution(ExecutionProgress::BeforePrepare { index: 0 }),
                        "controlled preparation-worker panic"
                    );
                    Ok(())
                },
                &accounting,
            )
            .unwrap_err();
        assert_eq!(error.to_string(), "WORKER_PANIC");
        accounting.assert_joined(workers);
        assert!(node.db.is_autocommit());
        assert_eq!(rows(&node.db), before);
        assert_eq!(node.active().unwrap(), (settings.genesis(), 0));
        let retry_accounting = JoinedWorkers::default();
        let id = node
            .admit_growth_work_checked_with_worker_accounting(
                checked(&packet),
                100_000,
                &|_| Ok(()),
                &retry_accounting,
            )
            .unwrap();
        retry_accounting.assert_joined(workers);
        assert_eq!(id, packet.id().unwrap());
    }
}

#[test]
fn growth_parallel_preparation_keeps_dependent_task_settlement_spends_and_reward_canonical() {
    let settings = settings();
    let source_dir = tempfile::tempdir().unwrap();
    let source =
        Node::open_with_permanent_account_growth_v2(source_dir.path(), settings.clone()).unwrap();
    let mut transactions = Vec::new();
    let mut tasks = Vec::new();
    let mut spent = 0;
    for (provider, reserve_nonce, budget) in [(1_u64, 1_u64, 12_345_u64), (2, 3, 23_456)] {
        let deadline = 6_u64;
        let task = hash(
            b"task-instance-v3",
            &[
                &settings.network(),
                &settings.parameters(),
                &public(0),
                &reserve_nonce.to_le_bytes(),
                &public(provider),
                &budget.to_le_bytes(),
                &deadline.to_le_bytes(),
            ],
        );
        let mut reserve = task.to_vec();
        reserve.extend(public(provider));
        reserve.extend(budget.to_le_bytes());
        reserve.extend(deadline.to_le_bytes());
        let mut receipt = task.to_vec();
        receipt.extend([71_u8; 32]);
        transactions.push(signed(&settings, 0, reserve_nonce, 2, reserve));
        transactions.push(signed(&settings, provider, 1, 4, receipt.clone()));
        transactions.push(signed(&settings, 0, reserve_nonce + 1, 5, receipt));
        let balance = settings.initial[&format!("account:{}", hex::encode(public(provider)))]
            ["balance"]
            .as_u64()
            .unwrap();
        // Paying both fees and spending the entire genesis balance requires
        // this provider's earlier settlement credit in the same block.
        transactions.push(transfer(&settings, provider, 2, public(100), balance));
        spent += balance;
        tasks.push(task);
    }
    let packet = make(&source, settings.genesis(), transactions);
    let expected = reference(&settings, &settings.initial, &packet);
    assert_eq!(
        expected[&format!("account:{}", hex::encode(public(0)))]["nonce"],
        4
    );
    assert_eq!(
        expected[&format!("account:{}", hex::encode(public(100)))]["balance"],
        spent
    );
    for task in tasks {
        let row = &expected[&format!("task:{}", hex::encode(task))];
        assert_eq!(row["status"], "settled");
        assert_eq!(row["remaining"], 0);
    }
    assert_eq!(
        expected
            .keys()
            .filter(|key| key.starts_with("reward:"))
            .count(),
        1
    );

    // All envelopes, the transaction commitment and complete W1 are valid.
    // Settlement before the provider's receipt is a canonical state error.
    let mut wrong_order = packet.clone();
    wrong_order.transactions.swap(1, 2);
    wrong_order.header.ledger.transactions =
        sequence_root("transactions", &wrong_order.transactions);
    reseal(&mut wrong_order);

    let mut prior_rows = None;
    for workers in [1, 2, 4, 8] {
        let dir = tempfile::tempdir().unwrap();
        let mut node = Node::open_with_permanent_account_growth_v2_and_workers(
            dir.path(),
            settings.clone(),
            workers,
        )
        .unwrap();
        let before = rows(&node.db);
        let caller = std::thread::current().id();
        for (candidate, succeeds) in [(&wrong_order, false), (&packet, true)] {
            let accounting = JoinedWorkers::default();
            let first_wave = Mutex::new(Vec::new());
            let ready = std::sync::Condvar::new();
            let applied = Mutex::new(Vec::new());
            let rewards = AtomicUsize::new(0);
            let commits = AtomicUsize::new(0);
            let result = node.admit_growth_work_checked_with_worker_accounting(
                checked(candidate),
                100_000,
                &|point| {
                    if let GrowthProgress::Execution(ExecutionProgress::AfterPrepare { index }) =
                        point
                    {
                        if index < workers {
                            // Every worker owns one first-wave transaction. A
                            // condition variable forces their preparation
                            // callbacks to complete in reverse canonical order;
                            // the timeout only bounds a broken scheduling test.
                            let (mut order, timeout) = ready
                                .wait_timeout_while(
                                    first_wave.lock().unwrap(),
                                    std::time::Duration::from_secs(30),
                                    |order| order.len() != workers - index - 1,
                                )
                                .unwrap();
                            assert!(
                                !timeout.timed_out(),
                                "reverse preparation stalled: workers={workers} index={index}"
                            );
                            order.push(index);
                            ready.notify_all();
                        }
                    }
                    if !matches!(
                        point,
                        GrowthProgress::Execution(
                            ExecutionProgress::BeforePrepare { .. }
                                | ExecutionProgress::AfterPrepare { .. }
                        )
                    ) {
                        assert_eq!(
                            std::thread::current().id(),
                            caller,
                            "state/proof/commit left owner"
                        );
                    }
                    match point {
                        GrowthProgress::Execution(ExecutionProgress::BeforeApply { .. }) => {
                            assert_eq!(
                                accounting.active.load(Ordering::SeqCst),
                                0,
                                "commit raced preparation"
                            );
                        }
                        GrowthProgress::Execution(ExecutionProgress::AfterApply { index }) => {
                            applied.lock().unwrap().push(index);
                        }
                        GrowthProgress::Execution(ExecutionProgress::BeforeReward) => {
                            rewards.fetch_add(1, Ordering::SeqCst);
                        }
                        GrowthProgress::BeforeCommit => {
                            commits.fetch_add(1, Ordering::SeqCst);
                        }
                        _ => {}
                    }
                    Ok(())
                },
                &accounting,
            );
            accounting.assert_joined(workers);
            assert_eq!(
                *first_wave.lock().unwrap(),
                (0..workers).rev().collect::<Vec<_>>()
            );
            assert_eq!(node.active().unwrap(), (settings.genesis(), 0));
            assert!(node.db.is_autocommit());
            if succeeds {
                assert_eq!(result.unwrap(), packet.id().unwrap());
                assert_eq!(*applied.lock().unwrap(), (0..8).collect::<Vec<_>>());
                assert_eq!(rewards.load(Ordering::SeqCst), 1);
                assert_eq!(commits.load(Ordering::SeqCst), 1);
            } else {
                assert_eq!(
                    result.unwrap_err().to_string(),
                    "STATE",
                    "workers={workers}"
                );
                assert_eq!(*applied.lock().unwrap(), vec![0]);
                assert_eq!(rewards.load(Ordering::SeqCst), 0);
                assert_eq!(commits.load(Ordering::SeqCst), 0);
                assert_eq!(rows(&node.db), before);
            }
        }
        let id = packet.id().unwrap();
        assert_eq!(node.activate(id).unwrap(), id);
        assert_reference(&node, id, &expected);
        assert_eq!(
            node.growth_observe(id).unwrap().commitment.escrow_balance,
            0
        );
        let actual = rows(&node.db);
        if let Some(prior) = &prior_rows {
            assert_eq!(&actual, prior);
        }
        prior_rows = Some(actual.clone());
        let active = node.active().unwrap();
        drop(node);
        let reopened =
            Node::open_with_permanent_account_growth_v2(dir.path(), settings.clone()).unwrap();
        assert_eq!(reopened.active().unwrap(), active);
        assert_eq!(rows(&reopened.db), actual);
        assert_reference(&reopened, id, &expected);
    }
}
