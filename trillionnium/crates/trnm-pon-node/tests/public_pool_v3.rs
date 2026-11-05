//! Real paid guest socket operations connect the exact shared Node persistent pool.
use std::{
    net::TcpListener,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use trnm_crypto_primitives::{sign_hex, signing_key_from_hex};
use trnm_pon_node::{
    development_public,
    ingress::{
        public_v2,
        public_v3::{self, PublicPolicy, PublicServer, Request},
        DevelopmentIdentity,
    },
    Node, PoolLimits, Settings,
};
use trnm_protocol::pon_wire::{hash, Envelope};
fn identity(n: u8) -> DevelopmentIdentity {
    DevelopmentIdentity::from_secret_hex(&hex::encode([n; 32])).unwrap()
}
fn limits() -> PoolLimits {
    PoolLimits {
        max_records: 16,
        max_bytes: 32768,
        max_group_members: 16,
        critical_reserve: 0,
        max_removals: 64,
        preview_miner: development_public(0).unwrap(),
    }
}
fn transfer(s: &Settings, who: u64, nonce: u64, to: u64, amount: u64) -> String {
    let mut payload = development_public(to).unwrap().to_vec();
    payload.extend(amount.to_le_bytes());
    let mut e = Envelope {
        network: s.network(),
        sender: development_public(who).unwrap(),
        nonce,
        expiry: 2000,
        fee_limit: 1_000_000,
        tag: 1,
        payload,
        signature: [0; 64],
    };
    let key =
        signing_key_from_hex(&hex::encode(hash(b"DEV-ONLY-KEY", &[&who.to_le_bytes()]))).unwrap();
    e.signature = hex::decode(sign_hex(&key, &e.signing_digest().unwrap()))
        .unwrap()
        .try_into()
        .unwrap();
    hex::encode(e.encode().unwrap())
}
#[test]
fn real_guest_bundle_exact_pool_duplicate_stale_snapshot_and_restart_no_authority() {
    let dir = tempfile::tempdir().unwrap();
    let clock = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let settings = Settings::development(Some(clock - 100)).unwrap();
    let mut owner = Node::open(dir.path(), settings.clone(), 2).unwrap();
    let context = hex::encode(owner.enable_local_mempool(limits()).unwrap());
    let shared = Arc::new(Mutex::new(owner));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let policy = PublicPolicy::new(8, Duration::from_secs(2)).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let node = shared.clone();
    let signal = stop.clone();
    let key = identity(71).public_key().to_owned();
    let worker = thread::spawn(move || {
        public_v3::serve_public_protected_v3(
            listener,
            node,
            Duration::from_secs(30),
            signal,
            PublicServer::new(identity(71), policy).unwrap(),
        )
        .unwrap()
    });
    let call = |request: &Request| {
        public_v3::call_public_protected_v3(
            address,
            request,
            &settings,
            &key,
            &identity(72),
            policy,
        )
        .unwrap()
    };
    let first = call(&Request::PoolStatus);
    assert!(first.ok);
    assert_eq!(first.value["context"], context);
    assert_eq!(first.value["retained_records"], 0);
    assert!(first.value["groups"].is_null());
    assert_eq!(first.value["snapshot_does_not_reconcile"], true);
    let transactions = vec![
        transfer(&settings, 0, 1, 4, 1000),
        transfer(&settings, 4, 1, 2, 100),
    ];
    let request = Request::PoolSubmitBundle {
        pool_context: context.clone(),
        transactions: transactions.clone(),
    };
    let before = shared.lock().unwrap().read_active().unwrap();
    let stats = shared.lock().unwrap().stats().unwrap();
    let receipt = call(&request);
    assert!(receipt.ok, "{}", receipt.value);
    assert_eq!(receipt.value["receipt"]["state"], "Queued");
    assert_eq!(receipt.value["receipt"]["typed_gate_admissions"], 2);
    assert_eq!(receipt.value["receipt"]["duplicate"], false);
    for field in [
        "exact_inclusion_proof",
        "adoption_authority",
        "reward_authority",
        "public_network_ready",
    ] {
        assert_eq!(receipt.value[field], false);
    }
    let duplicate = call(&request);
    assert!(duplicate.ok);
    assert_eq!(duplicate.value["receipt"]["duplicate"], true);
    let snapshot = call(&Request::PoolStatus);
    assert_eq!(snapshot.value["retained_records"], 2);
    assert_eq!(snapshot.value["queued_groups"], 1);
    assert_eq!(shared.lock().unwrap().read_active().unwrap(), before);
    assert_eq!(shared.lock().unwrap().stats().unwrap(), stats);
    assert_eq!(
        shared
            .lock()
            .unwrap()
            .next_nonce(development_public(0).unwrap())
            .unwrap(),
        1
    );
    let wrong = call(&Request::PoolSubmitBundle {
        pool_context: "ff".repeat(32),
        transactions: transactions.clone(),
    });
    assert!(!wrong.ok);
    let mut bad = transfer(&settings, 0, 2, 1, 20).into_bytes();
    let last = bad.len() - 1;
    bad[last] = if bad[last] == b'0' { b'1' } else { b'0' };
    let rejected = call(&Request::PoolSubmitBundle {
        pool_context: context.clone(),
        transactions: vec![String::from_utf8(bad).unwrap()],
    });
    assert!(!rejected.ok);
    assert_eq!(call(&Request::PoolStatus).value["retained_records"], 2);
    // The operator changes chain state outside the socket reactor. A guest read cannot reconcile it.
    let block = {
        let mut node = shared.lock().unwrap();
        let active = node.active().unwrap();
        let batch = node
            .pool_mining_batch(active.0, active.1, 16, 32768)
            .unwrap();
        assert_eq!(
            batch.transactions,
            transactions
                .iter()
                .map(|s| hex::decode(s).unwrap())
                .collect::<Vec<_>>()
        );
        node.pool_validate_batch(&batch).unwrap();
        let p = node
            .make(
                active.0,
                batch.transactions,
                development_public(0).unwrap(),
                clock - 90,
                4096,
            )
            .unwrap();
        let id = node.admit(&p, clock).unwrap();
        node.activate(id).unwrap();
        id
    };
    let stale = call(&Request::PoolStatus);
    assert!(stale.ok);
    assert_eq!(stale.value["parent"], hex::encode(block));
    assert_eq!(stale.value["classification_current"], false);
    assert_eq!(stale.value["checked_parent"], hex::encode(before.0));
    assert_eq!(stale.value["queued_groups"], 1); // Last checked classification, never claimed current.
    shared.lock().unwrap().pool_status().unwrap(); // Explicit operator action, not guest API.
    let checked = call(&Request::PoolStatus);
    assert_eq!(checked.value["classification_current"], true);
    assert_eq!(checked.value["sequence_consumed_groups"], 1);
    assert_eq!(checked.value["exact_inclusion_proof"], false);
    stop.store(true, Ordering::Release);
    let metrics = worker.join().unwrap();
    assert_eq!(metrics.completed_pool_submit, 2);
    assert_eq!(metrics.pool_submit_started, 3);
    assert_eq!(metrics.pool_submit_failed, 1);
    assert_eq!(metrics.work_started, 0);
    assert!(metrics.completed_pool_status >= 5);
    assert_eq!(metrics.unknown_caller_durable_rows, 0);
    assert_eq!(metrics.paid_body_reserved_bytes_after_shutdown, 0);
    assert_eq!(metrics.output_reserved_bytes_after_shutdown, 0);
    drop(shared);
    let reopened = Node::open(dir.path(), settings, 2).unwrap();
    assert_eq!(reopened.pool_status_snapshot().unwrap().retained_records, 2);
}
#[test]
fn both_actual_socket_cross_version_clients_reject_without_body_or_fallback() {
    let clock = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let settings = Settings::development(Some(clock - 100)).unwrap();
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let mut new = Node::open(a.path(), settings.clone(), 1).unwrap();
    new.enable_local_mempool(limits()).unwrap();
    let old = Node::open(b.path(), settings.clone(), 1).unwrap();
    let ln = TcpListener::bind("127.0.0.1:0").unwrap();
    let an = ln.local_addr().unwrap();
    let lo = TcpListener::bind("127.0.0.1:0").unwrap();
    let ao = lo.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let sn = stop.clone();
    let so = stop.clone();
    let np = PublicPolicy::new(8, Duration::from_secs(2)).unwrap();
    let op = public_v2::PublicPolicy::new(8, Duration::from_secs(2)).unwrap();
    let wn = thread::spawn(move || {
        public_v3::serve_public_protected_v3(
            ln,
            Arc::new(Mutex::new(new)),
            Duration::from_secs(10),
            sn,
            PublicServer::new(identity(71), np).unwrap(),
        )
        .unwrap()
    });
    let wo = thread::spawn(move || {
        public_v2::serve_public_protected_v2(
            lo,
            old,
            Duration::from_secs(10),
            so,
            public_v2::PublicServer::new(identity(71), op).unwrap(),
        )
        .unwrap()
    });
    let server = identity(71);
    let caller = identity(72);
    assert!(public_v3::call_public_protected_v3(
        ao,
        &Request::Head,
        &settings,
        server.public_key(),
        &caller,
        np
    )
    .is_err());
    assert!(public_v2::call_public_protected_v2(
        an,
        &trnm_pon_node::ingress::Request::Head,
        &settings,
        server.public_key(),
        &caller,
        op
    )
    .is_err());
    assert!(
        public_v3::call_public_protected_v3(
            an,
            &Request::Head,
            &settings,
            server.public_key(),
            &caller,
            np
        )
        .unwrap()
        .ok
    );
    assert!(
        public_v2::call_public_protected_v2(
            ao,
            &trnm_pon_node::ingress::Request::Head,
            &settings,
            server.public_key(),
            &caller,
            op
        )
        .unwrap()
        .ok
    );
    stop.store(true, Ordering::Release);
    let nm = wn.join().unwrap();
    let om = wo.join().unwrap();
    assert_eq!(nm.preface_refusals, 1);
    assert_eq!(om.preface_refusals, 1);
    assert_eq!(nm.completed_read, 1);
    assert_eq!(om.completed_read, 1);
    assert_eq!(nm.work_started, 0);
    assert_eq!(om.work_started, 0);
}
#[test]
fn serving_cannot_enable_pool_and_lifetime_has_explicit_72h_bound() {
    let dir = tempfile::tempdir().unwrap();
    let settings = Settings::development(Some(1)).unwrap();
    let node = Arc::new(Mutex::new(Node::open(dir.path(), settings, 1).unwrap()));
    let stop = Arc::new(AtomicBool::new(false));
    for life in [Duration::ZERO, Duration::from_secs(72 * 3600 + 1)] {
        let e = public_v3::serve_public_protected_v3(
            TcpListener::bind("127.0.0.1:0").unwrap(),
            node.clone(),
            life,
            stop.clone(),
            PublicServer::new(identity(71), PublicPolicy::development()).unwrap(),
        )
        .unwrap_err();
        assert_eq!(e.to_string(), "PUBLIC_LIFETIME");
    }
    assert!(public_v3::serve_public_protected_v3(
        TcpListener::bind("127.0.0.1:0").unwrap(),
        node.clone(),
        Duration::from_secs(1),
        stop,
        PublicServer::new(identity(71), PublicPolicy::development()).unwrap()
    )
    .unwrap_err()
    .to_string()
    .contains("POOL_NOT_ENABLED"));
    assert!(node.lock().unwrap().pool_status_snapshot().is_err());
}
