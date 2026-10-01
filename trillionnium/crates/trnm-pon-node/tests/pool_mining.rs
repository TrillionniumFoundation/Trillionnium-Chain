//! Actual wall-clock owner, signed queued transactions and native proof execution.
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};
use trnm_crypto_primitives::{sign_hex, signing_key_from_hex};
use trnm_pon_node::{
    development_public, ingress,
    mining::{run_pool_mining, MiningConfig, MiningMaterial},
    Node, PoolLimits, PoolState, Settings,
};
use trnm_protocol::{
    pon_wire::{hash, Envelope},
    qualified_work_task::lifecycle_v3::{AtomicRenewTaskV3, PROFILE},
};

fn signature(who: u64, message: &[u8]) -> [u8; 64] {
    let key =
        signing_key_from_hex(&hex::encode(hash(b"DEV-ONLY-KEY", &[&who.to_le_bytes()]))).unwrap();
    hex::decode(sign_hex(&key, message))
        .unwrap()
        .try_into()
        .unwrap()
}
fn transaction(settings: &Settings, who: u64, nonce: u64, tag: u8, payload: Vec<u8>) -> Vec<u8> {
    let mut tx = Envelope {
        network: settings.network(),
        sender: development_public(who).unwrap(),
        nonce,
        expiry: 2000,
        fee_limit: 1_000_000,
        tag,
        payload,
        signature: [0; 64],
    };
    tx.signature = signature(who, &tx.signing_digest().unwrap());
    tx.encode().unwrap()
}
fn transfer(settings: &Settings, who: u64, nonce: u64, receiver: u64, amount: u64) -> Vec<u8> {
    let mut payload = development_public(receiver).unwrap().to_vec();
    payload.extend(amount.to_le_bytes());
    transaction(settings, who, nonce, 1, payload)
}
fn setup(path: &std::path::Path) -> (Node, Settings, MiningConfig, PoolLimits) {
    setup_profile(path, PROFILE)
}
fn setup_profile(
    path: &std::path::Path,
    profile: &str,
) -> (Node, Settings, MiningConfig, PoolLimits) {
    let settings = Settings::development_with_profiles(
        Some(ingress::now().unwrap() - 100),
        "native-public-evaluation-dev-v1",
        profile,
    )
    .unwrap();
    let mut node = Node::open(path, settings.clone(), 2).unwrap();
    let miner = development_public(3).unwrap();
    let limits = PoolLimits {
        max_records: 32,
        max_bytes: 65536,
        max_group_members: 16,
        critical_reserve: 0,
        max_removals: 32,
        preview_miner: miner,
    };
    node.enable_local_mempool(limits.clone()).unwrap();
    let (model, input, _, _) = settings.bootstrap_task_material().unwrap();
    let config = MiningConfig {
        miner,
        material: MiningMaterial::Registered { model, input },
        max_transactions: 256,
        max_transaction_bytes: 524288,
        search_attempts: 4096,
        pace: Duration::from_secs(1),
        runtime: Duration::from_secs(10),
        max_blocks: 2,
    };
    (node, settings, config, limits)
}

#[test]
fn wall_clock_loop_executes_funding_dependencies_then_reopens_exact_queue_and_chain() {
    let dir = tempfile::tempdir().unwrap();
    let (mut node, settings, config, limits) = setup(dir.path());
    let funding = transfer(&settings, 0, 1, 4, 1000);
    let spend = transfer(&settings, 4, 1, 2, 100);
    assert!(node.pool_submit(spend.clone()).is_err());
    node.pool_submit_bundle(vec![funding.clone(), spend.clone()])
        .unwrap();
    let owner = Arc::new(Mutex::new(node));
    let mut events = Vec::new();
    let report = run_pool_mining(
        owner.clone(),
        config,
        Arc::new(AtomicBool::new(false)),
        |event| {
            events.push(serde_json::to_value(event)?);
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(report.activated_blocks, 2);
    assert_eq!(report.included_transactions, 2);
    assert_eq!(report.stop_reason, "block-limit");
    assert!(!report.stage_preemption);
    assert!(report.actual_elapsed_ns >= 1_000_000_000);
    assert_eq!(events.len(), 2);
    for field in [
        "initial_owner_wait_ns",
        "pool_batch_ns",
        "pre_search_batch_validation_ns",
        "prepare_ns",
        "search_ns",
        "post_search_owner_wait_ns",
        "post_search_batch_validation_ns",
        "make_ns",
        "admit_ns",
        "activate_ns",
        "reconcile_ns",
    ] {
        let actual: u64 = events
            .iter()
            .map(|event| event[field].as_u64().unwrap())
            .sum();
        assert_eq!(
            serde_json::to_value(&report).unwrap()[field]
                .as_u64()
                .unwrap(),
            actual
        );
    }
    for event in &events {
        for field in [
            "pool_batch_ns",
            "pre_search_batch_validation_ns",
            "prepare_ns",
            "search_ns",
            "post_search_batch_validation_ns",
            "admit_ns",
            "activate_ns",
            "reconcile_ns",
        ] {
            assert!(event[field].as_u64().unwrap() > 0);
        }
        assert!(
            event["make_ns"].as_u64().unwrap()
                >= event["prepare_ns"].as_u64().unwrap() + event["search_ns"].as_u64().unwrap()
        );
    }
    let measured = report.initial_owner_wait_ns
        + report.pool_batch_ns
        + report.pre_search_batch_validation_ns
        + report.make_ns
        + report.post_search_owner_wait_ns
        + report.post_search_batch_validation_ns
        + report.admit_ns
        + report.activate_ns
        + report.reconcile_ns;
    assert!(report.actual_elapsed_ns >= measured);
    assert!(
        events[1]["observed_wall_seconds"].as_u64().unwrap()
            > events[0]["observed_wall_seconds"].as_u64().unwrap()
    );
    let node = owner.lock().unwrap();
    let tip = node.active().unwrap();
    let last = node.packet(tip.0).unwrap();
    assert!(last.transactions.is_empty());
    assert_eq!(
        node.packet(last.header.parent).unwrap().transactions,
        vec![funding.clone(), spend.clone()]
    );
    assert_eq!(node.next_nonce(development_public(4).unwrap()).unwrap(), 2);
    let final_root = node.stats().unwrap()["state_root"].clone();
    drop(node);
    drop(owner);
    let mut reopened = Node::open(dir.path(), settings, 1).unwrap();
    reopened.enable_local_mempool(limits).unwrap();
    assert_eq!(reopened.active().unwrap(), tip);
    assert_eq!(reopened.stats().unwrap()["state_root"], final_root);
    assert!(reopened
        .pool_status()
        .unwrap()
        .groups
        .iter()
        .all(|g| g.state == PoolState::SequenceConsumed));
    assert_eq!(
        reopened
            .pool_submit_bundle(vec![funding, spend])
            .unwrap()
            .state,
        PoolState::SequenceConsumed
    );
}

#[test]
fn reconciliation_failure_reports_the_already_activated_durable_block() {
    let dir = tempfile::tempdir().unwrap();
    let (mut node, settings, mut config, limits) = setup(dir.path());
    let raw = transfer(&settings, 0, 1, 2, 5);
    node.pool_submit(raw.clone()).unwrap();
    config.max_blocks = 1;
    let fixture = rusqlite::Connection::open(dir.path().join("native.sqlite")).unwrap();
    fixture.execute_batch("CREATE TRIGGER pool_after_activation_cut BEFORE UPDATE ON local_pool_groups WHEN (SELECT generation FROM active WHERE singleton=1)>0 BEGIN SELECT RAISE(ABORT,'owned-postactivation-cache-cut'); END;").unwrap();
    let owner = Arc::new(Mutex::new(node));
    let mut events = Vec::new();
    let error = run_pool_mining(
        owner.clone(),
        config,
        Arc::new(AtomicBool::new(false)),
        |event| {
            events.push(serde_json::to_value(event)?);
            Ok(())
        },
    )
    .unwrap_err();
    assert!(error.to_string().contains("owned-postactivation-cache-cut"));
    assert_eq!(events.len(), 1);
    let event = &events[0];
    assert_eq!(event["kind"], "failed");
    assert_eq!(event["failure_stage"], "pool-reconciliation");
    assert!(event["reconcile_ns"].as_u64().unwrap() > 0);
    assert!(event["post_search_batch_validation_ns"].as_u64().unwrap() > 0);
    assert_eq!(event["admitted"], true);
    assert_eq!(event["activated"], true);
    let node = owner.lock().unwrap();
    let active = node.active().unwrap();
    assert_eq!(event["block"], hex::encode(active.0));
    assert_eq!(node.parent_height(active.0).unwrap(), 1);
    assert_eq!(node.packet(active.0).unwrap().transactions, vec![raw]);
    assert_eq!(node.next_nonce(development_public(0).unwrap()).unwrap(), 2);
    assert!(!node.pool_status_snapshot().unwrap().classification_current);
    drop(node);
    fixture
        .execute_batch("DROP TRIGGER pool_after_activation_cut;")
        .unwrap();
    drop(fixture);
    drop(owner);
    let mut reopened = Node::open(dir.path(), settings, 1).unwrap();
    reopened.enable_local_mempool(limits).unwrap();
    assert_eq!(reopened.active().unwrap(), active);
    assert_eq!(
        reopened.pool_status().unwrap().groups[0].state,
        PoolState::SequenceConsumed
    );
}

#[test]
fn next_block_uses_current_authenticated_statement_after_atomic_renewal() {
    for profile in [
        PROFILE,
        trnm_protocol::qualified_work_task::lifecycle_v4::PROFILE,
    ] {
        let dir = tempfile::tempdir().unwrap();
        let (mut node, settings, config, _) = setup_profile(dir.path(), profile);
        let boot = settings.bootstrap_lifecycle_task().unwrap();
        let mut lease = boot.lease.clone();
        lease.revision += 1;
        lease.not_before = 1;
        lease.expires = 1001;
        lease.available_until = 1101;
        let mut signed = boot.signed.clone();
        signed.lease_id = lease.id().unwrap();
        signed.manifest.source_record = lease.bound_source_record().unwrap();
        signed.manifest.withdrawal_head = lease.withdrawal_frontier().unwrap();
        signed.manifest.not_before = lease.not_before;
        signed.manifest.expires = lease.expires;
        signed.manifest.available_until = lease.available_until;
        signed.manifest.demand_nonce = 2;
        signed.signature = signature(0, &signed.signing_message().unwrap());
        let raw = transaction(
            &settings,
            1,
            1,
            22,
            AtomicRenewTaskV3 {
                lease,
                signed: signed.clone(),
            }
            .encode()
            .unwrap(),
        );
        node.pool_submit(raw.clone()).unwrap();
        let owner = Arc::new(Mutex::new(node));
        let report = run_pool_mining(
            owner.clone(),
            config,
            Arc::new(AtomicBool::new(false)),
            |_| Ok(()),
        )
        .unwrap();
        assert_eq!(report.activated_blocks, 2);
        assert_eq!(report.included_transactions, 1);
        let node = owner.lock().unwrap();
        let second = node.packet(node.active().unwrap().0).unwrap();
        assert_eq!(
            node.packet(second.header.parent).unwrap().transactions,
            vec![raw]
        );
        let state = node.state_at(second.header.parent).unwrap();
        let slot = &state[&trnm_mvcc_fee::qualified_task_lifecycle::slot_key(0).unwrap()];
        assert_eq!(slot["statement"], hex::encode(signed.encode().unwrap()));
        assert_ne!(
            slot["statement"],
            hex::encode(boot.signed.encode().unwrap())
        );
        assert_eq!(slot["source_sequence"], 2);
        assert_eq!(slot["output_count"], 0);
        assert_eq!(node.next_nonce(development_public(0).unwrap()).unwrap(), 1);
    }
}

#[test]
fn bounded_stop_runtime_and_invalid_material_do_not_mine_or_consume_pending_transactions() {
    let dir = tempfile::tempdir().unwrap();
    let (mut node, settings, config, _) = setup(dir.path());
    node.pool_submit(transfer(&settings, 0, 1, 2, 5)).unwrap();
    let before = node.active().unwrap();
    let owner = Arc::new(Mutex::new(node));
    let stop = Arc::new(AtomicBool::new(true));
    let report = run_pool_mining(owner.clone(), config.clone(), stop.clone(), |_| {
        panic!("stopped")
    })
    .unwrap();
    assert_eq!(report.stop_reason, "stop-request");
    assert_eq!(report.activated_blocks, 0);
    stop.store(false, Ordering::Release);
    let guard = owner.lock().unwrap();
    let mut locked = config.clone();
    locked.runtime = Duration::from_millis(150);
    let start = Instant::now();
    let report =
        run_pool_mining(owner.clone(), locked, stop.clone(), |_| panic!("locked")).unwrap();
    assert_eq!(report.activated_blocks, 0);
    assert_eq!(report.stop_reason, "runtime");
    assert!(start.elapsed() < Duration::from_secs(2));
    assert!(report.initial_owner_wait_ns >= 100_000_000);
    assert_eq!(report.pool_batch_ns, 0);
    assert_eq!(report.post_search_owner_wait_ns, 0);
    drop(guard);
    let mut wrong_miner = config.clone();
    wrong_miner.miner = development_public(4).unwrap();
    let mut miner_failures = 0;
    let error = run_pool_mining(owner.clone(), wrong_miner, stop.clone(), |event| {
        assert_eq!(event.kind, "failed");
        assert_eq!(event.failure_stage, Some("pre-search-batch-validation"));
        assert_eq!(event.failure.as_deref(), Some("POOL_MINER"));
        assert!(event.pool_batch_ns > 0);
        assert_eq!(event.prepare_ns, 0);
        assert_eq!(event.work_trials, 0);
        miner_failures += 1;
        Ok(())
    })
    .unwrap_err();
    assert_eq!(error.to_string(), "POOL_MINER");
    assert_eq!(miner_failures, 1);
    let mut wrong = config;
    wrong.material = MiningMaterial::Registered {
        model: vec![0; 16384],
        input: vec![0; 16384],
    };
    let mut failures = 0;
    assert!(run_pool_mining(owner.clone(), wrong, stop, |e| {
        assert_eq!(e.kind, "failed");
        failures += 1;
        Ok(())
    })
    .is_err());
    assert_eq!(failures, 1);
    let mut node = owner.lock().unwrap();
    assert_eq!(node.active().unwrap(), before);
    assert_eq!(node.pool_status().unwrap().retained_records, 1);
    assert_eq!(
        node.pool_status().unwrap().groups[0].state,
        PoolState::Queued
    );
}

#[test]
fn completed_sqlite_blocked_batch_observes_stop_before_revalidation_or_preparation() {
    // A real second SQLite writer holds the reconciliation transaction. Neither
    // the batch nor its SQLite work is made preemptible by the cooperative fence.
    for requested_stop in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let (mut node, settings, mut config, _) = setup(dir.path());
        let raw = transfer(&settings, 0, 1, 2, 5);
        node.pool_submit(raw.clone()).unwrap();
        let before = node.active().unwrap();
        let state = node.state_at(before.0).unwrap();
        config.runtime = if requested_stop {
            Duration::from_secs(10)
        } else {
            Duration::from_millis(150)
        };
        let fixture = rusqlite::Connection::open(dir.path().join("native.sqlite")).unwrap();
        fixture.execute_batch("BEGIN IMMEDIATE").unwrap();
        let owner = Arc::new(Mutex::new(node));
        let worker_owner = owner.clone();
        let observer_owner = owner.clone();
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = stop.clone();
        let worker = std::thread::spawn(move || {
            let mut events = Vec::new();
            let result = run_pool_mining(worker_owner, config, worker_stop, |event| {
                // Diagnostics must run after releasing the exclusive owner.
                assert!(observer_owner.try_lock().is_ok());
                events.push(serde_json::to_value(event)?);
                Ok(())
            });
            (result, events)
        });
        let acquisition_deadline = Instant::now() + Duration::from_secs(3);
        loop {
            match owner.try_lock() {
                Err(std::sync::TryLockError::WouldBlock) => break,
                Err(std::sync::TryLockError::Poisoned(_)) => panic!("mining owner poisoned"),
                Ok(guard) => drop(guard),
            }
            assert!(
                Instant::now() < acquisition_deadline,
                "mining did not acquire owner"
            );
            std::thread::yield_now();
        }
        std::thread::sleep(Duration::from_millis(250));
        assert!(matches!(
            owner.try_lock(),
            Err(std::sync::TryLockError::WouldBlock)
        ));
        if requested_stop {
            stop.store(true, Ordering::Release);
        }
        fixture.execute_batch("ROLLBACK").unwrap();
        let (result, events) = worker.join().unwrap();
        let report = result.unwrap();
        assert_eq!(
            report.stop_reason,
            if requested_stop {
                "stop-request"
            } else {
                "runtime"
            }
        );
        assert_eq!(report.attempted_searches, 0);
        assert_eq!(report.activated_blocks, 0);
        assert_eq!(report.observed_work_trials, 0);
        assert!(!report.stage_preemption);
        assert_eq!(events.len(), 1);
        let event = &events[0];
        assert_eq!(event["kind"], "stopped-before-search");
        assert_eq!(event["failure_stage"], "pool-batch");
        assert_eq!(event["transactions"], 1);
        assert!(event["pool_batch_ns"].as_u64().unwrap() >= 250_000_000);
        for field in [
            "pre_search_batch_validation_ns",
            "prepare_ns",
            "search_ns",
            "make_ns",
            "post_search_owner_wait_ns",
            "post_search_batch_validation_ns",
            "admit_ns",
            "activate_ns",
            "reconcile_ns",
        ] {
            assert_eq!(event[field], 0);
            assert_eq!(serde_json::to_value(&report).unwrap()[field], 0);
        }
        assert_eq!(event["admitted"], false);
        assert_eq!(event["activated"], false);
        let mut node = owner.lock().unwrap();
        assert_eq!(node.active().unwrap(), before);
        assert_eq!(node.state_at(before.0).unwrap(), state);
        assert_eq!(node.next_nonce(development_public(0).unwrap()).unwrap(), 1);
        let status = node.pool_status().unwrap();
        assert_eq!(status.retained_records, 1);
        assert_eq!(status.groups[0].state, PoolState::Queued);
        assert_eq!(
            node.pool_mining_batch(before.0, before.1, 256, 524288)
                .unwrap()
                .transactions,
            vec![raw]
        );
    }
}

#[test]
fn actual_cli_retains_signed_group_then_mines_with_wall_clock_and_refuses_logical_clock() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("store");
    let (node, settings, _, limits) = setup(&store);
    drop(node);
    let policy = dir.path().join("policy.json");
    std::fs::write(&policy, serde_json::to_vec(&limits).unwrap()).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&policy, std::fs::Permissions::from_mode(0o600)).unwrap();
    let transactions = dir.path().join("transactions.json");
    let raw = transfer(&settings, 0, 1, 2, 17);
    std::fs::write(
        &transactions,
        serde_json::to_vec(&vec![hex::encode(&raw)]).unwrap(),
    )
    .unwrap();
    let invoke = |command: &str, extra: &[&str]| {
        std::process::Command::new(env!("CARGO_BIN_EXE_trnm-pon-node"))
            .arg(command)
            .args([
                "--development",
                "--store",
                store.to_str().unwrap(),
                "--genesis-time",
                &settings.genesis_time().to_string(),
                "--evaluation-policy",
                "native-public-evaluation-dev-v1",
                "--task-profile",
                PROFILE,
            ])
            .args(extra)
            .output()
            .unwrap()
    };
    let submitted = invoke(
        "pool-submit",
        &[
            "--pool-policy",
            policy.to_str().unwrap(),
            "--transactions",
            transactions.to_str().unwrap(),
        ],
    );
    assert!(
        submitted.status.success(),
        "{}",
        String::from_utf8_lossy(&submitted.stderr)
    );
    let receipt: serde_json::Value = serde_json::from_slice(&submitted.stdout).unwrap();
    assert_eq!(receipt["result"]["state"], "Queued");
    let refused = invoke(
        "mine-loop",
        &[
            "--pool-policy",
            policy.to_str().unwrap(),
            "--task-bootstrap",
            "--logical-now",
            "1800010000",
        ],
    );
    assert!(!refused.status.success());
    assert!(String::from_utf8_lossy(&refused.stderr).contains("NETWORK_USES_LOCAL_WALL_CLOCK"));
    let mined = invoke(
        "mine-loop",
        &[
            "--pool-policy",
            policy.to_str().unwrap(),
            "--task-bootstrap",
            "--seconds",
            "10",
            "--blocks",
            "2",
            "--pace-ms",
            "1000",
        ],
    );
    assert!(
        mined.status.success(),
        "{}",
        String::from_utf8_lossy(&mined.stderr)
    );
    let text = String::from_utf8(mined.stdout).unwrap();
    let rows: Vec<serde_json::Value> = text
        .lines()
        .map(|s| serde_json::from_str(s).unwrap())
        .collect();
    assert_eq!(rows.len(), 3);
    assert_eq!(rows[2]["result"]["activated_blocks"], 2);
    assert_eq!(rows[2]["result"]["included_transactions"], 1);
    assert_eq!(rows[2]["clock_scope"], "local-wall");
    let reopened = Node::open(&store, settings, 1).unwrap();
    let packet = reopened.packet(reopened.active().unwrap().0).unwrap();
    assert_eq!(
        reopened.packet(packet.header.parent).unwrap().transactions,
        vec![raw]
    );
    assert_eq!(
        reopened.next_nonce(development_public(0).unwrap()).unwrap(),
        2
    );
}

#[test]
fn failed_pool_batch_retains_elapsed_before_any_search_or_admission() {
    let dir = tempfile::tempdir().unwrap();
    let (mut node, settings, mut config, _) = setup(dir.path());
    node.pool_submit(transfer(&settings, 0, 1, 2, 5)).unwrap();
    config.max_blocks = 1;
    let before = node.active().unwrap();
    let fixture = rusqlite::Connection::open(dir.path().join("native.sqlite")).unwrap();
    fixture.execute_batch("CREATE TRIGGER pool_before_search_cut BEFORE UPDATE ON local_pool_groups BEGIN SELECT RAISE(ABORT,'owned-presearch-cache-cut'); END;").unwrap();
    let owner = Arc::new(Mutex::new(node));
    let mut events = Vec::new();
    let error = run_pool_mining(
        owner.clone(),
        config,
        Arc::new(AtomicBool::new(false)),
        |event| {
            events.push(serde_json::to_value(event)?);
            Ok(())
        },
    )
    .unwrap_err();
    assert!(error.to_string().contains("owned-presearch-cache-cut"));
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["failure_stage"], "pool-batch");
    assert!(events[0]["pool_batch_ns"].as_u64().unwrap() > 0);
    assert_eq!(events[0]["make_ns"], 0);
    assert_eq!(events[0]["admit_ns"], 0);
    assert_eq!(events[0]["activated"], false);
    assert_eq!(owner.lock().unwrap().active().unwrap(), before);
}

#[test]
fn failed_post_search_revalidation_retains_elapsed_without_admission() {
    // There is one complete selection preview under the initial owner guard.
    // The second reconciliation follows search and must still fail closed.
    {
        let dir = tempfile::tempdir().unwrap();
        let (mut node, settings, mut config, _) = setup(dir.path());
        node.pool_submit(transfer(&settings, 0, 1, 2, 5)).unwrap();
        config.max_blocks = 1;
        let before = node.active().unwrap();
        let fixture = rusqlite::Connection::open(dir.path().join("native.sqlite")).unwrap();
        fixture.execute_batch("CREATE TABLE fixture_rechecks(n INTEGER NOT NULL); INSERT INTO fixture_rechecks VALUES(0); CREATE TRIGGER revalidation_cut BEFORE UPDATE ON local_pool_groups BEGIN UPDATE fixture_rechecks SET n=n+1; SELECT CASE WHEN (SELECT n FROM fixture_rechecks)>=2 THEN RAISE(ABORT,'owned-revalidation-cut') END; END;").unwrap();
        let owner = Arc::new(Mutex::new(node));
        let mut events = Vec::new();
        let error = run_pool_mining(
            owner.clone(),
            config,
            Arc::new(AtomicBool::new(false)),
            |event| {
                events.push(serde_json::to_value(event)?);
                Ok(())
            },
        )
        .unwrap_err();
        assert!(error.to_string().contains("owned-revalidation-cut"));
        assert_eq!(events.len(), 1);
        let event = &events[0];
        assert!(event["pool_batch_ns"].as_u64().unwrap() > 0);
        assert!(event["pre_search_batch_validation_ns"].as_u64().unwrap() > 0);
        assert_eq!(event["failure_stage"], "batch-revalidation");
        assert!(event["make_ns"].as_u64().unwrap() > 0);
        assert!(event["post_search_batch_validation_ns"].as_u64().unwrap() > 0);
        assert_eq!(event["admit_ns"], 0);
        assert_eq!(event["admitted"], false);
        assert_eq!(event["activated"], false);
        assert_eq!(owner.lock().unwrap().active().unwrap(), before);
    }
}
