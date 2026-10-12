//! Actual paid V3 TCP + separate persisted native owner. This local test is not
//! a multi-host/WAN campaign or permissionless peer discovery/eclipsing proof.
use std::{
    net::TcpListener,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread,
    time::Duration,
};
use trnm_crypto_primitives::qualified_work_task::{
    lifecycle_v2::verify_lifecycle_admission, TaskMaterial,
};
use trnm_pon_node::{
    development_public,
    ingress::{
        self,
        public_v3::{self, PublicPolicy, PublicServer},
        DevelopmentIdentity,
    },
    peer_polling::{run_pinned_peer_polling, PeerPollingConfig, PinnedPeer, PEER_POLLING_SCHEMA},
    Node, PoolLimits, Settings,
};
fn identity(n: u8) -> DevelopmentIdentity {
    DevelopmentIdentity::from_secret_hex(&hex::encode([n; 32])).unwrap()
}
#[test]
fn actual_paid_pinned_v3_follows_qualified_native_chain_and_reuses_only_durable_admission() {
    let clock = ingress::now().unwrap();
    let settings = Settings::development_with_profiles(
        Some(clock - 100),
        "native-public-evaluation-dev-v1",
        "signed-task-lifecycle-dev-v3",
    )
    .unwrap();
    let remote_dir = tempfile::tempdir().unwrap();
    let local_dir = tempfile::tempdir().unwrap();
    let mut remote = Node::open(remote_dir.path(), settings.clone(), 2).unwrap();
    remote
        .enable_local_mempool(PoolLimits {
            max_records: 16,
            max_bytes: 32768,
            max_group_members: 16,
            critical_reserve: 0,
            max_removals: 64,
            preview_miner: development_public(0).unwrap(),
        })
        .unwrap();
    let bootstrap = settings.bootstrap_lifecycle_task().unwrap();
    let (model, input, a, b) = settings.bootstrap_task_material().unwrap();
    let make = |remote: &mut Node, parent, height: u64, offset: u64| {
        let material = || TaskMaterial {
            model: &model,
            input: &input,
            a: &a,
            b: &b,
        };
        let admission = verify_lifecycle_admission(
            &bootstrap.signed.encode().unwrap(),
            material(),
            &bootstrap.lease,
            height,
        )
        .unwrap();
        let p = remote
            .make_with_task(
                parent,
                vec![],
                development_public(3 + offset).unwrap(),
                clock - 100 + height * 10 + offset,
                4096,
                &admission,
                material(),
            )
            .unwrap();
        let id = remote.admit(&p, clock).unwrap();
        remote.activate_observed(id, clock).unwrap();
        p
    };
    let mut packets = vec![];
    for height in 1..=3 {
        let parent = remote.active().unwrap().0;
        packets.push(make(&mut remote, parent, height, 0));
    }
    let a_tip = remote.active().unwrap().0;
    let local = Arc::new(Mutex::new(
        Node::open(local_dir.path(), settings.clone(), 2).unwrap(),
    ));
    let remote = Arc::new(Mutex::new(remote));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let policy = PublicPolicy::new(8, Duration::from_secs(2)).unwrap();
    let service_stop = Arc::new(AtomicBool::new(false));
    let signal = service_stop.clone();
    let server = remote.clone();
    let worker = thread::spawn(move || {
        public_v3::serve_public_protected_v3(
            listener,
            server,
            Duration::from_secs(60),
            signal,
            PublicServer::new(identity(71), policy).unwrap(),
        )
        .unwrap()
    });
    let cfg = PeerPollingConfig {
        schema: PEER_POLLING_SCHEMA.into(),
        network: hex::encode(settings.network()),
        parameters: hex::encode(settings.parameters()),
        genesis: hex::encode(settings.genesis()),
        transport_profile: hex::encode(policy.id()),
        bits: 8,
        lifetime_ms: 2000,
        peers: vec![PinnedPeer {
            address,
            server_public: identity(71).public_key().into(),
        }],
        poll_interval_ms: 10,
        runtime_ms: 30_000,
        max_calls: 10,
        max_pages_per_cycle: 1,
    };
    let peer_stop = Arc::new(AtomicBool::new(false));
    let mut events = vec![];
    let mut added_fork = false;
    let report = run_pinned_peer_polling(
        local.clone(),
        cfg.clone(),
        identity(72),
        peer_stop.clone(),
        |e| {
            events.push(serde_json::to_value(e).unwrap());
            // After the first actual native completion, publish a heavier fork on
            // the real server. Its History implementation must refuse the old
            // completed anchor with the actual signed CURSOR response.
            if e.kind == "fixed_target_native_complete"
                && e.active_tip == Some(hex::encode(a_tip))
                && !added_fork
            {
                let mut owner = remote.lock().unwrap();
                let mut parent = packets[0].id().unwrap();
                for height in 2..=4 {
                    let p = make(&mut owner, parent, height, 1);
                    parent = p.id().unwrap();
                    packets.push(p);
                }
                added_fork = true;
            }
            Ok(())
        },
    )
    .unwrap();
    let expected = remote.lock().unwrap().read_active().unwrap();
    let expected_tip = expected.0;
    assert!(added_fork);
    assert_ne!(a_tip, expected_tip);
    assert_eq!(report.rpc_attempts, 10);
    assert_eq!(report.ok_replies, 9);
    assert_eq!(report.rejected_replies, 1);
    assert_eq!(report.history_pages, 7);
    assert_eq!(report.verified_new_packets, 6);
    assert_eq!(report.peers[0].initial_anchor_fallbacks, 1);
    assert_eq!(report.peers[0].failures, 1);
    assert_eq!(
        report.peers[0].last_error.as_ref().unwrap().message,
        "PEER_REFUSAL:CURSOR"
    );
    let refused = events
        .iter()
        .position(|e| e["error"]["message"] == "PEER_REFUSAL:CURSOR")
        .unwrap();
    assert_eq!(
        events[refused + 1]["kind"],
        "initial_anchor_refused_restart_same_target_at_genesis"
    );
    assert_eq!(events[refused + 1]["target"], hex::encode(expected_tip));
    assert_eq!(report.transport_errors, 0);
    assert_eq!(report.peers[0].completed_targets, 2);
    assert_eq!(
        report.peers[0].last_completed,
        Some(hex::encode(expected_tip))
    );
    assert_eq!(report.stop_reason, "call_budget");
    assert!(!peer_stop.load(Ordering::Acquire));
    let actual = local.lock().unwrap().read_active().unwrap();
    assert_eq!(actual.0, expected.0);
    assert_eq!(actual.2, expected.2);
    assert_eq!(
        local.lock().unwrap().stats().unwrap()["chainwork_hex"],
        remote.lock().unwrap().stats().unwrap()["chainwork_hex"]
    );
    for p in &packets {
        assert_eq!(
            local
                .lock()
                .unwrap()
                .packet(p.id().unwrap())
                .unwrap()
                .encode()
                .unwrap(),
            p.encode().unwrap()
        );
    }
    let costs = events
        .iter()
        .filter_map(|e| e.get("rpc_cost").filter(|v| !v.is_null()))
        .collect::<Vec<_>>();
    assert_eq!(costs.len(), 10);
    assert!(costs.iter().all(|e| e["solve_trials"].as_u64().unwrap() > 0
        && e["solve_elapsed_ns"].as_u64().unwrap() > 0
        && e["body_bytes_sent"].as_u64().unwrap() > 0));
    drop(local); // Actual same persisted owner reopen; replay memory is new.
    let local = Arc::new(Mutex::new(
        Node::open(local_dir.path(), settings.clone(), 2).unwrap(),
    ));
    let mut repeat = cfg;
    repeat.max_calls = 1;
    let report = run_pinned_peer_polling(
        local.clone(),
        repeat,
        identity(72),
        peer_stop.clone(),
        |_| Ok(()),
    )
    .unwrap();
    assert_eq!(report.history_pages, 0);
    assert_eq!(report.verified_new_packets, 0);
    assert_eq!(report.peers[0].completed_targets, 1);
    assert_eq!(local.lock().unwrap().active().unwrap().0, expected_tip);
    assert!(!peer_stop.load(Ordering::Acquire));
    service_stop.store(true, Ordering::Release);
    let metrics = worker.join().unwrap();
    assert_eq!(metrics.completed_read, 10); // eleven signed replies, one native CURSOR refusal
    assert_eq!(metrics.delivered_response_frames, 11);
    assert_eq!(metrics.unknown_caller_durable_rows, 0);
    assert_eq!(metrics.paid_body_reserved_bytes_after_shutdown, 0);
    assert_eq!(metrics.output_reserved_bytes_after_shutdown, 0);
    drop(local);
    drop(remote);
    for directory in [local_dir.path(), remote_dir.path()] {
        let db = rusqlite::Connection::open_with_flags(
            directory.join("native.sqlite"),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap();
        for table in ["peer_replay", "peer_outbox", "peer_request_audit"] {
            let count: u64 = db
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))
                .unwrap();
            assert_eq!(count, 0);
        }
    }
}
