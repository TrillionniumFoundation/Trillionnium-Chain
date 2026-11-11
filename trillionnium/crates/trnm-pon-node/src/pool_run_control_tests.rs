//! Same real pool runner and signed transactions on both sides of the control.
//! The hooks below only observe existing boundaries and change the caller's
//! original stop bit, or wait for its actual absolute end. They create no error,
//! CPU credit, clock, candidate, admission or execution result. The identical
//! hooks and this file can be added to the old production source as a control.
use super::*;
use crate::{development_public, PoolLimits, PoolState, Settings};
use std::{cell::RefCell, path::Path, sync::mpsc};
use trnm_crypto_primitives::{sign_hex, signing_key_from_hex};
use trnm_protocol::pon_wire::Envelope;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Trigger {
    StopAtRows,
    DeadlineAtRows,
    BeforePoolExecution,
    AfterStage,
}
struct Observation {
    target: &'static str,
    trigger: Trigger,
    stop: Arc<AtomicBool>,
    current: Option<&'static str>,
    end: Option<Instant>,
    fired: bool,
    max_rows_after_signal: usize,
    completed_pool_executions_after_signal: usize,
    concurrent: Option<(mpsc::SyncSender<()>, mpsc::Receiver<()>)>,
}
thread_local! {
    static OBSERVATION: RefCell<Option<Observation>> = const { RefCell::new(None) };
}
struct Observer;
impl Observer {
    fn install(target: &'static str, trigger: Trigger, stop: Arc<AtomicBool>) -> Self {
        OBSERVATION.with(|slot| {
            let mut slot = slot.borrow_mut();
            assert!(slot.is_none());
            *slot = Some(Observation {
                target,
                trigger,
                stop,
                current: None,
                end: None,
                fired: false,
                max_rows_after_signal: 0,
                completed_pool_executions_after_signal: 0,
                concurrent: None,
            });
        });
        Self
    }
    fn finish(self) -> Observation {
        OBSERVATION.with(|slot| slot.borrow_mut().take().unwrap())
    }
}
impl Drop for Observer {
    fn drop(&mut self) {
        let _ = OBSERVATION.with(|slot| slot.borrow_mut().take());
    }
}

pub(crate) fn enter_stage(stage: &'static str, end: Instant) {
    OBSERVATION.with(|slot| {
        if let Some(observation) = slot.borrow_mut().as_mut() {
            observation.current = Some(stage);
            observation.end = Some(end);
        }
    });
}

pub(crate) fn state_rows(rows: usize) {
    OBSERVATION.with(|slot| {
        let mut slot = slot.borrow_mut();
        let Some(observation) = slot.as_mut() else {
            return;
        };
        if observation.current != Some(observation.target)
            || !matches!(
                observation.trigger,
                Trigger::StopAtRows | Trigger::DeadlineAtRows
            )
        {
            return;
        }
        if rows == 256 && !observation.fired {
            let end = observation.end.unwrap();
            assert!(
                Instant::now() < end,
                "POOL_RUN_FIXTURE_EXPIRED_BEFORE_SIGNAL"
            );
            observation.fired = true;
            if observation.trigger == Trigger::StopAtRows {
                observation.stop.store(true, Ordering::Release);
            } else {
                // No virtual clock or new stage deadline. This is exactly the
                // end computed by this call to run_pool_mining before any work.
                while Instant::now() < end {
                    thread::sleep(end.saturating_duration_since(Instant::now()));
                }
            }
        }
        if observation.fired {
            observation.max_rows_after_signal = observation.max_rows_after_signal.max(rows);
        }
    });
}

pub(crate) fn before_pool_execution() {
    OBSERVATION.with(|slot| {
        if let Some(observation) = slot.borrow_mut().as_mut() {
            if observation.current == Some(observation.target)
                && observation.trigger == Trigger::BeforePoolExecution
                && !observation.fired
            {
                assert!(Instant::now() < observation.end.unwrap());
                observation.fired = true;
                observation.stop.store(true, Ordering::Release);
            }
        }
    });
}

pub(crate) fn after_pool_execution() {
    OBSERVATION.with(|slot| {
        if let Some(observation) = slot.borrow_mut().as_mut() {
            if observation.current == Some(observation.target)
                && observation.trigger == Trigger::BeforePoolExecution
                && observation.fired
            {
                observation.completed_pool_executions_after_signal += 1;
            }
        }
    });
}

pub(crate) fn after_stage(stage: &'static str) {
    OBSERVATION.with(|slot| {
        if let Some(observation) = slot.borrow_mut().as_mut() {
            if stage == observation.target
                && observation.trigger == Trigger::AfterStage
                && !observation.fired
            {
                // A different thread sets the actual stop bit after native/SQL
                // has returned, but before the runner classifies that result.
                let (start, done) = observation.concurrent.as_ref().unwrap();
                start.send(()).unwrap();
                done.recv_timeout(Duration::from_secs(10)).unwrap();
                observation.fired = true;
                assert!(observation.stop.load(Ordering::Acquire));
            }
        }
    });
}

fn signed_transfer(settings: &Settings) -> Vec<u8> {
    let mut payload = development_public(1).unwrap().to_vec();
    payload.extend(1_u64.to_le_bytes());
    let mut transaction = Envelope {
        network: settings.network(),
        sender: development_public(0).unwrap(),
        nonce: 1,
        expiry: 2000,
        fee_limit: 1_000_000,
        tag: 1,
        payload,
        signature: [0; 64],
    };
    let key =
        signing_key_from_hex(&hex::encode(hash(b"DEV-ONLY-KEY", &[&0_u64.to_le_bytes()]))).unwrap();
    transaction.signature = hex::decode(sign_hex(&key, &transaction.signing_digest().unwrap()))
        .unwrap()
        .try_into()
        .unwrap();
    transaction.encode().unwrap()
}

fn setup(
    path: &Path,
    registered: bool,
    authenticated: bool,
    large: bool,
) -> (Node, Settings, MiningConfig, Vec<u8>) {
    let profile = if registered {
        continuity_v1::PROFILE
    } else {
        "legacy-task-v1"
    };
    let mut settings = Settings::development_with_profiles(
        Some(ingress::now().unwrap() - 100),
        "native-public-evaluation-dev-v1",
        profile,
    )
    .unwrap();
    if large {
        for index in 0_u64..1024 {
            settings.initial.insert(
                format!(
                    "account:{}",
                    hex::encode(hash(b"pool-run-stop-dormant", &[&index.to_le_bytes()]))
                ),
                serde_json::json!({"balance":0,"nonce":7}),
            );
        }
        continuity_v1::check_state(&settings.initial, 0, &settings.app).unwrap();
        settings.genesis = hash(
            b"genesis",
            &[
                &settings.network(),
                &settings.parameters(),
                &settings.state_root(&settings.initial).unwrap(),
                &settings.genesis_time().to_le_bytes(),
            ],
        );
    }
    let mut node = if authenticated {
        Node::open_with_authenticated_state(path, settings.clone(), 2).unwrap()
    } else {
        Node::open(path, settings.clone(), 2).unwrap()
    };
    let miner = development_public(3).unwrap();
    node.enable_local_mempool(PoolLimits {
        max_records: 32,
        max_bytes: 65536,
        max_group_members: 16,
        critical_reserve: 0,
        max_removals: 32,
        preview_miner: miner,
    })
    .unwrap();
    let material = if registered {
        let (model, input, _, _) = settings.consensus_maintenance_material().unwrap();
        MiningMaterial::Registered { model, input }
    } else {
        MiningMaterial::LegacyDevelopment
    };
    let config = MiningConfig {
        miner,
        material,
        max_transactions: 256,
        max_transaction_bytes: 524288,
        search_attempts: 4096,
        pace: Duration::from_secs(1),
        runtime: Duration::from_secs(30),
        max_blocks: 1,
    };
    let raw = signed_transfer(&settings);
    node.pool_submit(raw.clone()).unwrap();
    (node, settings, config, raw)
}

fn cancelled_run(stage: &'static str, trigger: Trigger, registered: bool, authenticated: bool) {
    let directory = tempfile::tempdir().unwrap();
    let (node, settings, mut config, _) = setup(directory.path(), registered, authenticated, true);
    if trigger == Trigger::DeadlineAtRows {
        config.runtime = Duration::from_secs(5);
    }
    let before = node.read_active().unwrap();
    let owner = Arc::new(Mutex::new(node));
    let stop = Arc::new(AtomicBool::new(false));
    let hook = Observer::install(stage, trigger, stop.clone());
    let mut events = Vec::new();
    let result = run_pool_mining(owner.clone(), config, stop, |event| {
        assert!(
            owner.try_lock().is_ok(),
            "observation retained the Node mutex"
        );
        events.push(serde_json::to_value(event)?);
        Ok(())
    });
    let observed = hook.finish();
    assert!(
        observed.fired,
        "POOL_RUN_FIXTURE_DID_NOT_REACH_SIGNAL: {stage}"
    );
    let report = result.expect("cooperative run cancellation became an operational failure");
    if trigger == Trigger::BeforePoolExecution {
        assert_eq!(
            observed.completed_pool_executions_after_signal, 0,
            "POOL_RUN_PREVIEW_IGNORED_STOP"
        );
    } else {
        assert_eq!(
            observed.max_rows_after_signal, 256,
            "POOL_RUN_PARENT_SCAN_IGNORED_STOP: {stage}"
        );
    }
    assert_eq!(
        report.stop_reason,
        if trigger == Trigger::DeadlineAtRows {
            "runtime"
        } else {
            "stop-request"
        }
    );
    assert_eq!(report.activated_blocks, 0);
    assert_eq!(report.included_transactions, 0);
    assert!(!report.stage_preemption);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["failure_stage"], stage);
    assert_eq!(
        events[0]["kind"],
        if stage == "batch-revalidation" {
            "stopped-before-admission"
        } else {
            "stopped-before-search"
        }
    );
    assert!(events[0]["failure"].is_null());
    assert_eq!(events[0]["admit_ns"], 0);
    assert_eq!(events[0]["admitted"], false);
    assert_eq!(events[0]["activated"], false);
    assert_eq!(
        report.attempted_searches,
        u64::from(stage == "batch-revalidation")
    );
    let node = owner.lock().unwrap();
    assert_eq!(node.read_active().unwrap(), before);
    let snapshot = node.pool_status_snapshot().unwrap();
    assert_eq!(snapshot.retained_records, 1);
    assert_eq!(snapshot.groups[0].state, PoolState::Queued);
    assert_eq!(node.next_nonce(development_public(0).unwrap()).unwrap(), 1);
    drop(node);
    drop(owner);
    let reopened = if authenticated {
        Node::open_with_authenticated_state(directory.path(), settings, 2).unwrap()
    } else {
        Node::open(directory.path(), settings, 2).unwrap()
    };
    assert_eq!(reopened.read_active().unwrap(), before);
    assert_eq!(
        reopened.pool_status_snapshot().unwrap().groups[0].state,
        PoolState::Queued
    );
}

#[test]
fn pool_run_stop_interrupts_batch_parent_scan() {
    for authenticated in [false, true] {
        cancelled_run("pool-batch", Trigger::StopAtRows, true, authenticated);
    }
}

#[test]
fn pool_run_stop_interrupts_registered_and_legacy_prepare() {
    for registered in [true, false] {
        for authenticated in [false, true] {
            cancelled_run("prepare", Trigger::StopAtRows, registered, authenticated);
        }
    }
}

#[test]
fn pool_run_stop_interrupts_post_search_revalidation() {
    for authenticated in [false, true] {
        cancelled_run(
            "batch-revalidation",
            Trigger::StopAtRows,
            true,
            authenticated,
        );
    }
}

#[test]
fn pool_run_original_deadline_interrupts_parent_scan() {
    for stage in ["pool-batch", "prepare", "batch-revalidation"] {
        cancelled_run(stage, Trigger::DeadlineAtRows, true, false);
    }
}

#[test]
fn pool_run_cancelled_preview_keeps_queue_without_completed_m06() {
    cancelled_run("pool-batch", Trigger::BeforePoolExecution, true, false);
}

#[test]
fn pool_run_native_and_sql_failures_survive_concurrent_stop() {
    assert!(crate::Error::from("MINING_RUN_STOPPED").code().is_none());
    for sql in [true, false] {
        let directory = tempfile::tempdir().unwrap();
        let (node, _, mut config, _) = setup(directory.path(), true, false, false);
        let before = node.read_active().unwrap();
        let connection =
            rusqlite::Connection::open(directory.path().join("native.sqlite")).unwrap();
        let stage = if sql {
            connection.execute_batch("CREATE TRIGGER pool_control_cut BEFORE UPDATE ON local_pool_groups BEGIN SELECT RAISE(ABORT,'MINING_RUN_STOPPED'); END;").unwrap();
            "pool-batch"
        } else {
            config.material = MiningMaterial::Registered {
                model: vec![255; 16384],
                input: vec![255; 16384],
            };
            "prepare"
        };
        let owner = Arc::new(Mutex::new(node));
        let stop = Arc::new(AtomicBool::new(false));
        let hook = Observer::install(stage, Trigger::AfterStage, stop.clone());
        let (start_tx, start_rx) = mpsc::sync_channel(0);
        let (done_tx, done_rx) = mpsc::sync_channel(0);
        OBSERVATION.with(|slot| {
            slot.borrow_mut().as_mut().unwrap().concurrent = Some((start_tx, done_rx))
        });
        let worker_stop = stop.clone();
        let stopper = thread::spawn(move || {
            start_rx.recv_timeout(Duration::from_secs(10)).unwrap();
            worker_stop.store(true, Ordering::Release);
            done_tx.send(()).unwrap();
        });
        let mut events = Vec::new();
        let result = run_pool_mining(owner.clone(), config, stop, |event| {
            assert!(owner.try_lock().is_ok());
            events.push(serde_json::to_value(event)?);
            Ok(())
        });
        let observation = hook.finish();
        stopper.join().unwrap();
        assert!(observation.fired);
        let error = result.expect_err("concurrent stop hid a real native/SQL failure");
        assert!(error.to_string().contains(if sql {
            "MINING_RUN_STOPPED"
        } else {
            "TASK_MATERIAL:Numeric"
        }));
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["kind"], "failed");
        assert_eq!(events[0]["failure_stage"], stage);
        assert_eq!(events[0]["admitted"], false);
        assert_eq!(owner.lock().unwrap().read_active().unwrap(), before);
        assert_eq!(
            owner.lock().unwrap().pool_status_snapshot().unwrap().groups[0].state,
            PoolState::Queued
        );
    }
}

#[test]
fn pool_run_completed_packet_and_reconcile_failure_remain_durable() {
    for registered in [false, true] {
        for fail_reconcile in [false, true] {
            let directory = tempfile::tempdir().unwrap();
            let (node, settings, config, raw) = setup(directory.path(), registered, false, false);
            let connection =
                rusqlite::Connection::open(directory.path().join("native.sqlite")).unwrap();
            if fail_reconcile {
                connection.execute_batch("CREATE TABLE pool_control_count(n INTEGER NOT NULL); INSERT INTO pool_control_count VALUES(0); CREATE TRIGGER pool_control_after_activation BEFORE UPDATE ON local_pool_groups BEGIN UPDATE pool_control_count SET n=n+1; SELECT CASE WHEN (SELECT n FROM pool_control_count)>=3 THEN RAISE(ABORT,'pool-control-after-activation') END; END;").unwrap();
            }
            let owner = Arc::new(Mutex::new(node));
            let mut events = Vec::new();
            let result = run_pool_mining(
                owner.clone(),
                config.clone(),
                Arc::new(AtomicBool::new(false)),
                |event| {
                    assert!(owner.try_lock().is_ok());
                    events.push(serde_json::to_value(event)?);
                    Ok(())
                },
            );
            assert_eq!(events.len(), 1);
            if fail_reconcile {
                assert!(result
                    .unwrap_err()
                    .to_string()
                    .contains("pool-control-after-activation"));
                assert_eq!(events[0]["kind"], "failed");
                assert_eq!(events[0]["failure_stage"], "pool-reconciliation");
                connection
                    .execute_batch("DROP TRIGGER pool_control_after_activation")
                    .unwrap();
            } else {
                let report = result.unwrap();
                assert_eq!(report.stop_reason, "block-limit");
                assert_eq!(report.activated_blocks, 1);
                assert_eq!(report.included_transactions, 1);
                assert!(!report.stage_preemption);
            }
            assert_eq!(events[0]["admitted"], true);
            assert_eq!(events[0]["activated"], true);
            let node = owner.lock().unwrap();
            let state = node.read_active().unwrap();
            let packet = node.packet(state.0).unwrap();
            assert_eq!(packet.transactions, vec![raw.clone()]);
            assert_eq!(node.next_nonce(development_public(0).unwrap()).unwrap(), 2);
            let expected = match &config.material {
                MiningMaterial::LegacyDevelopment => node
                    .make(
                        settings.genesis(),
                        vec![raw],
                        config.miner,
                        packet.header.timestamp,
                        config.search_attempts,
                    )
                    .unwrap(),
                MiningMaterial::Registered { model, input } => node
                    .make_with_registered_material(
                        settings.genesis(),
                        vec![raw],
                        config.miner,
                        packet.header.timestamp,
                        config.search_attempts,
                        model,
                        input,
                    )
                    .unwrap(),
            };
            assert_eq!(packet.encode().unwrap(), expected.encode().unwrap());
            drop(node);
            drop(owner);
            let mut reopened = Node::open(directory.path(), settings, 2).unwrap();
            assert_eq!(reopened.read_active().unwrap(), state);
            assert_eq!(
                reopened.packet(state.0).unwrap().encode().unwrap(),
                packet.encode().unwrap()
            );
            // A failed final cache update cannot undo the native block. The next
            // ordinary pool reconciliation uses the actual durable generation.
            assert_eq!(
                reopened.pool_status().unwrap().groups[0].state,
                PoolState::SequenceConsumed
            );
        }
    }
}
