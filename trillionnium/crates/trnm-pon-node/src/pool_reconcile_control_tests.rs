//! Original-run controls inside actual retained-pool decoding. The hooks only
//! observe completed native boundaries and set the existing caller stop flag or
//! wait for its existing absolute end. They create no error or native result.
//! Kept separate from the earlier source-bound pool control experiment.
use super::*;
use crate::{development_public, PoolLimits, Settings};
use std::cell::RefCell;
use trnm_crypto_primitives::{sign_hex, signing_key_from_hex};
use trnm_protocol::pon_wire::Envelope;

struct Observation {
    target: &'static str,
    expire: bool,
    stop: Arc<AtomicBool>,
    current: Option<&'static str>,
    end: Option<Instant>,
    fired: bool,
    max_rows_after_signal: usize,
    completed_executions_after_signal: usize,
}
thread_local! {
    static OBSERVATION: RefCell<Option<Observation>> = const { RefCell::new(None) };
}
struct Observer;
impl Observer {
    fn install(target: &'static str, expire: bool, stop: Arc<AtomicBool>) -> Self {
        OBSERVATION.with(|slot| {
            let mut slot = slot.borrow_mut();
            assert!(slot.is_none());
            *slot = Some(Observation {
                target,
                expire,
                stop,
                current: None,
                end: None,
                fired: false,
                max_rows_after_signal: 0,
                completed_executions_after_signal: 0,
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

pub(crate) fn pool_rows(rows: usize) {
    OBSERVATION.with(|slot| {
        let mut slot = slot.borrow_mut();
        let Some(observation) = slot.as_mut() else {
            return;
        };
        if observation.current != Some(observation.target) {
            return;
        }
        if rows == 2 && !observation.fired {
            let end = observation.end.unwrap();
            assert!(
                Instant::now() < end,
                "POOL_RUN_RETAINED_FIXTURE_EXPIRED_BEFORE_SIGNAL"
            );
            observation.fired = true;
            if observation.expire {
                // This is the exact end computed by run_pool_mining before any
                // work. No replacement clock or stage deadline is introduced.
                while Instant::now() < end {
                    thread::sleep(end.saturating_duration_since(Instant::now()));
                }
            } else {
                observation.stop.store(true, Ordering::Release);
            }
        }
        if observation.fired {
            observation.max_rows_after_signal = observation.max_rows_after_signal.max(rows);
        }
    });
}

pub(crate) fn after_pool_execution() {
    OBSERVATION.with(|slot| {
        if let Some(observation) = slot.borrow_mut().as_mut() {
            if observation.current == Some(observation.target) && observation.fired {
                observation.completed_executions_after_signal += 1;
            }
        }
    });
}

fn signed_transfer(settings: &Settings, nonce: u64) -> Vec<u8> {
    let mut payload = development_public(1).unwrap().to_vec();
    payload.extend(1_u64.to_le_bytes());
    let mut transaction = Envelope {
        network: settings.network(),
        sender: development_public(0).unwrap(),
        nonce,
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

fn cancelled_retained_pool_scan(stage: &'static str, expire: bool, authenticated: bool) {
    let directory = tempfile::tempdir().unwrap();
    let settings = Settings::development_with_profiles(
        Some(ingress::now().unwrap() - 100),
        "native-public-evaluation-dev-v1",
        continuity_v1::PROFILE,
    )
    .unwrap();
    let mut node = if authenticated {
        Node::open_with_authenticated_state(directory.path(), settings.clone(), 2).unwrap()
    } else {
        Node::open(directory.path(), settings.clone(), 2).unwrap()
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
    for nonce in 1..=6 {
        node.pool_submit(signed_transfer(&settings, nonce)).unwrap();
    }
    let (model, input, _, _) = settings.consensus_maintenance_material().unwrap();
    let config = MiningConfig {
        miner,
        material: MiningMaterial::Registered { model, input },
        max_transactions: 256,
        max_transaction_bytes: 524288,
        search_attempts: 4096,
        pace: Duration::from_secs(1),
        runtime: Duration::from_secs(if expire { 5 } else { 30 }),
        max_blocks: 1,
    };
    let original = node.read_active().unwrap();
    let before = serde_json::to_value(node.pool_status_snapshot().unwrap()).unwrap();
    assert_eq!(before["retained_records"], 6);
    let owner = Arc::new(Mutex::new(node));
    let stop = Arc::new(AtomicBool::new(false));
    let hook = Observer::install(stage, expire, stop.clone());
    let mut events = Vec::new();
    let result = run_pool_mining(owner.clone(), config, stop, |event| {
        assert!(owner.try_lock().is_ok());
        events.push(serde_json::to_value(event)?);
        Ok(())
    });
    let observation = hook.finish();
    assert!(
        observation.fired,
        "POOL_RUN_RETAINED_FIXTURE_DID_NOT_REACH_SIGNAL: {stage}"
    );
    let report = result.expect("retained-row cancellation became an operational failure");
    assert_eq!(
        observation.max_rows_after_signal, 2,
        "POOL_RUN_RECONCILIATION_ROWS_IGNORED_ORIGINAL_CONTROL: {stage}"
    );
    assert_eq!(observation.completed_executions_after_signal, 0);
    assert_eq!(
        report.stop_reason,
        if expire { "runtime" } else { "stop-request" }
    );
    assert_eq!(report.activated_blocks, 0);
    assert_eq!(report.included_transactions, 0);
    assert_eq!(
        report.attempted_searches,
        u64::from(stage == "batch-revalidation")
    );
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
    let node = owner.lock().unwrap();
    assert_eq!(node.read_active().unwrap(), original);
    assert_eq!(
        serde_json::to_value(node.pool_status_snapshot().unwrap()).unwrap(),
        before
    );
    assert_eq!(node.next_nonce(development_public(0).unwrap()).unwrap(), 1);
    drop(node);
    drop(owner);
    let reopened = if authenticated {
        Node::open_with_authenticated_state(directory.path(), settings, 2).unwrap()
    } else {
        Node::open(directory.path(), settings, 2).unwrap()
    };
    assert_eq!(reopened.read_active().unwrap(), original);
    assert_eq!(
        serde_json::to_value(reopened.pool_status_snapshot().unwrap()).unwrap(),
        before
    );
}

#[test]
fn pool_run_stop_interrupts_reconciliation_pool_rows() {
    for stage in ["pool-batch", "batch-revalidation"] {
        for authenticated in [false, true] {
            cancelled_retained_pool_scan(stage, false, authenticated);
        }
    }
}

#[test]
fn pool_run_deadline_interrupts_reconciliation_pool_rows() {
    for stage in ["pool-batch", "batch-revalidation"] {
        for authenticated in [false, true] {
            cancelled_retained_pool_scan(stage, true, authenticated);
        }
    }
}
