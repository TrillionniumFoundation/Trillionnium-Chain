//! Observer lifetime and failed-call costs never alter the signed guest protocol.
use std::{
    net::TcpListener,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread,
    time::Duration,
};
use trnm_pon_node::{
    development_public,
    ingress::{
        self,
        public_v3::{self, PublicClientStage, PublicMetrics, PublicPolicy, PublicServer, Request},
        DevelopmentIdentity,
    },
    Node, PoolLimits, Settings,
};
fn identity(n: u8) -> DevelopmentIdentity {
    DevelopmentIdentity::from_secret_hex(&hex::encode([n; 32])).unwrap()
}
#[test]
fn external_read_only_observer_survives_shutdown_with_actual_paid_snapshot_counts() {
    let directory = tempfile::tempdir().unwrap();
    let settings = Settings::development(Some(ingress::now().unwrap() - 100)).unwrap();
    let mut node = Node::open(directory.path(), settings.clone(), 1).unwrap();
    node.enable_local_mempool(PoolLimits {
        max_records: 8,
        max_bytes: 32768,
        max_group_members: 4,
        critical_reserve: 0,
        max_removals: 16,
        preview_miner: development_public(3).unwrap(),
    })
    .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let observer = Arc::new(Mutex::new(PublicMetrics::default()));
    let policy = PublicPolicy::new(8, Duration::from_secs(2)).unwrap();
    let (signal, counters) = (stop.clone(), observer.clone());
    let worker = thread::spawn(move || {
        public_v3::serve_public_protected_v3_with_metrics(
            listener,
            Arc::new(Mutex::new(node)),
            Duration::from_secs(10),
            signal,
            PublicServer::new(identity(71), policy).unwrap(),
            counters,
        )
        .unwrap()
    });
    let (reply, cost) = public_v3::call_public_protected_v3_with_metrics(
        address,
        &Request::PoolStatus,
        &settings,
        identity(71).public_key(),
        &identity(72),
        policy,
    );
    assert!(reply.unwrap().ok);
    assert!(cost.solution_found);
    assert!(cost.solution_trials > 0);
    assert!(cost.construction_ns > 0);
    assert!(cost.challenge_ns > 0);
    assert!(cost.solution_body_response_ns > 0);
    assert!(cost.total_elapsed_ns >= cost.solution_search_ns);
    assert_eq!(cost.failed_stage, None);
    assert_eq!(observer.lock().unwrap().completed_pool_status, 1);
    assert_eq!(observer.lock().unwrap().pool_submit_started, 0);
    assert_eq!(observer.lock().unwrap().work_started, 0);
    stop.store(true, Ordering::Release);
    let final_metrics = worker.join().unwrap();
    assert_eq!(final_metrics.completed_pool_status, 1);
    assert_eq!(observer.lock().unwrap().completed_pool_status, 1);
    assert_eq!(final_metrics.unknown_caller_durable_rows, 0);
}
#[test]
fn refusal_retains_partial_challenge_cost_without_body_or_ticket_claim() {
    let settings = Settings::development(Some(1)).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let (reply, cost) = public_v3::call_public_protected_v3_with_metrics(
        address,
        &Request::PoolStatus,
        &settings,
        identity(71).public_key(),
        &identity(72),
        PublicPolicy::development(),
    );
    assert!(reply.is_err());
    assert_eq!(cost.failed_stage, Some(PublicClientStage::Challenge));
    assert_eq!(
        serde_json::to_value(&cost).unwrap()["failed_stage"],
        "challenge"
    );
    assert!(cost.construction_ns > 0);
    assert!(cost.challenge_ns > 0);
    assert!(cost.total_elapsed_ns >= cost.challenge_ns);
    assert_eq!(cost.solution_trials, 0);
    assert!(!cost.solution_found);
    assert_eq!(cost.solution_body_response_ns, 0);
}
