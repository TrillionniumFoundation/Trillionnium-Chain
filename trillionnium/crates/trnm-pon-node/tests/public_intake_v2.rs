//! Real unknown-caller transport; task and ledger authority remain native checks.
use std::{
    net::TcpListener,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::Duration,
};
use trnm_crypto_primitives::{
    pon_work,
    qualified_work_task::{verify_development_admission, TaskMaterial},
};
use trnm_pon_node::{
    development_public,
    ingress::{
        self,
        public_v2::{self, PublicPolicy, PublicServer},
        DevelopmentIdentity, Page, Request,
    },
    maintenance, Node, Packet, Settings,
};
use trnm_protocol::pon_wire::hash;
fn identity(n: u8) -> DevelopmentIdentity {
    DevelopmentIdentity::from_secret_hex(&hex::encode([n; 32])).unwrap()
}
fn request(packet: &Packet) -> Request {
    Request::Submit {
        packet: hex::encode(packet.encode().unwrap()),
    }
}
fn actual_work_with_false_state(packet: &Packet) -> Packet {
    let mut forged = packet.clone();
    forged.header.state = [0xf9; 32];
    let (a, b) = maintenance();
    let prepared = pon_work::PreparedTask::new(&a, &b).unwrap();
    for nonce in 0..4096 {
        forged.header.nonce = nonce;
        forged.proof = prepared.prove(forged.header.challenge()).unwrap();
        if hash(
            b"ticket",
            &[
                &forged.header.challenge(),
                &forged.proof[forged.proof.len() - 32..],
            ],
        ) <= forged.header.target
        {
            pon_work::verify(
                forged.header.challenge(),
                forged.header.work_task,
                forged.header.target,
                &forged.proof,
            )
            .unwrap();
            return forged;
        }
    }
    panic!("bounded actual work search");
}
#[test]
fn unknown_caller_cannot_override_ledger_and_full_sync_independently_verifies_actual_work() {
    let validator_dir = tempfile::tempdir().unwrap();
    let producer_dir = tempfile::tempdir().unwrap();
    let confirmer_dir = tempfile::tempdir().unwrap();
    let clock = ingress::now().unwrap();
    let settings = Settings::development_with_profiles(
        Some(clock - 100),
        "native-public-evaluation-dev-v1",
        "signed-task-dev-v1",
    )
    .unwrap();
    let producer = Node::open(producer_dir.path(), settings.clone(), 2).unwrap();
    let signed = settings.bootstrap_task_statement().unwrap();
    let (model, input, a, b) = settings.bootstrap_task_material().unwrap();
    let material = TaskMaterial {
        model: &model,
        input: &input,
        a: &a,
        b: &b,
    };
    let context = settings
        .qualified_task_context(signed.manifest.demand_id, 1)
        .unwrap();
    let admission =
        verify_development_admission(&signed.encode().unwrap(), material, &context).unwrap();
    let packet = producer
        .make_with_task(
            settings.genesis(),
            vec![],
            development_public(0).unwrap(),
            clock - 90,
            4096,
            &admission,
            TaskMaterial {
                model: &model,
                input: &input,
                a: &a,
                b: &b,
            },
        )
        .unwrap();
    let false_state = actual_work_with_false_state(&packet);
    let validator = Node::open(validator_dir.path(), settings.clone(), 2).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let signal = stop.clone();
    let server_key = identity(71).public_key().to_owned();
    let caller = identity(72);
    let policy = PublicPolicy::new(8, Duration::from_secs(2)).unwrap();
    let worker = thread::spawn(move || {
        public_v2::serve_public_protected_v2(
            listener,
            validator,
            Duration::from_secs(10),
            signal,
            PublicServer::new(identity(71), policy).unwrap(),
        )
        .unwrap()
    });
    let failed = public_v2::call_public_protected_v2(
        address,
        &request(&false_state),
        &settings,
        &server_key,
        &caller,
        policy,
    )
    .unwrap();
    assert!(!failed.ok);
    assert_eq!(failed.value["error"], "ROOT");
    assert!(!failed.identity_authority);
    let before = public_v2::call_public_protected_v2(
        address,
        &Request::Head,
        &settings,
        &server_key,
        &caller,
        policy,
    )
    .unwrap();
    assert!(before.ok);
    assert_eq!(before.value["height"], 0);
    let accepted = public_v2::call_public_protected_v2(
        address,
        &request(&packet),
        &settings,
        &server_key,
        &caller,
        policy,
    )
    .unwrap();
    assert!(accepted.ok);
    assert_eq!(accepted.value["block"], hex::encode(packet.id().unwrap()));
    let head = public_v2::call_public_protected_v2(
        address,
        &Request::Head,
        &settings,
        &server_key,
        &caller,
        policy,
    )
    .unwrap();
    assert!(head.ok);
    assert_eq!(head.value["height"], 1);
    assert_eq!(head.value["tip"], hex::encode(packet.id().unwrap()));
    assert!(head.value.get("state_keys").is_none());
    let reply = public_v2::call_public_protected_v2(
        address,
        &Request::History {
            tip: hex::encode(packet.id().unwrap()),
            after: hex::encode(settings.genesis()),
        },
        &settings,
        &server_key,
        &caller,
        policy,
    )
    .unwrap();
    assert!(reply.ok);
    let page: Page = serde_json::from_value(reply.value).unwrap();
    assert_eq!(page.packets.len(), 1);
    let mut confirmer = Node::open(confirmer_dir.path(), settings.clone(), 2).unwrap();
    let tip = ingress::receive_page(
        &mut confirmer,
        page,
        packet.id().unwrap(),
        settings.genesis(),
        clock,
    )
    .unwrap();
    assert_eq!(tip, packet.id().unwrap());
    assert_eq!(confirmer.active().unwrap().0, tip);
    assert_eq!(
        confirmer.packet(tip).unwrap().encode().unwrap(),
        packet.encode().unwrap()
    );
    assert_eq!(
        confirmer.stats().unwrap()["state_root"],
        head.value["state_root"]
    );
    let unsupported = public_v2::call_public_protected_v2(
        address,
        &Request::Confirm {
            transaction: hex::encode([0; 32]),
            block: hex::encode(tip),
        },
        &settings,
        &server_key,
        &caller,
        policy,
    )
    .unwrap_err();
    assert_eq!(unsupported.to_string(), "PUBLIC_OPERATION");
    stop.store(true, Ordering::Release);
    let metrics = worker.join().unwrap();
    assert_eq!(metrics.work_started, 2);
    assert_eq!(metrics.work_finished, 2);
    assert_eq!(metrics.work_failed, 0);
    assert_eq!(metrics.executor_refusals, 1);
    assert_eq!(metrics.completed_submit, 1);
    assert_eq!(metrics.completed_read, 3);
    assert_eq!(metrics.unknown_caller_durable_rows, 0);
    let reopened = Node::open(validator_dir.path(), settings, 2).unwrap();
    let stats = reopened.stats().unwrap();
    for field in [
        "authenticated_sessions",
        "authenticated_pending",
        "authenticated_audit_rows",
        "authenticated_outbox_sessions",
        "authenticated_outbox_pending",
    ] {
        assert_eq!(stats[field], 0, "{field}");
    }
    assert_eq!(reopened.active().unwrap().0, tip);
}

#[test]
fn one_packet_history_preserves_partial_progress_and_independent_validation() {
    let server_dir = tempfile::tempdir().unwrap();
    let confirmer_dir = tempfile::tempdir().unwrap();
    let clock = ingress::now().unwrap();
    let settings = Settings::development(Some(clock - 100)).unwrap();
    let mut server = Node::open(server_dir.path(), settings.clone(), 2).unwrap();
    let mut tip = settings.genesis();
    let mut ids = Vec::new();
    for height in 1..=3 {
        let packet = server
            .make(
                tip,
                vec![],
                development_public(0).unwrap(),
                clock - 100 + height * 10,
                4096,
            )
            .unwrap();
        tip = server.admit(&packet, clock).unwrap();
        server.activate(tip).unwrap();
        ids.push(tip);
    }
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let signal = stop.clone();
    let server_key = identity(71).public_key().to_owned();
    let policy = PublicPolicy::new(8, Duration::from_secs(2)).unwrap();
    let worker = thread::spawn(move || {
        public_v2::serve_public_protected_v2(
            listener,
            server,
            Duration::from_secs(10),
            signal,
            PublicServer::new(identity(71), policy).unwrap(),
        )
        .unwrap()
    });
    let mut confirmer = Node::open(confirmer_dir.path(), settings.clone(), 2).unwrap();
    let mut after = settings.genesis();
    for (index, id) in ids.iter().enumerate() {
        let reply = public_v2::call_public_protected_v2(
            address,
            &Request::History {
                tip: hex::encode(tip),
                after: hex::encode(after),
            },
            &settings,
            &server_key,
            &identity(72),
            policy,
        )
        .unwrap();
        assert!(reply.ok);
        let page: Page = serde_json::from_value(reply.value).unwrap();
        assert_eq!(page.packets.len(), 1);
        assert_eq!(page.complete, index == 2);
        assert_eq!(page.next, hex::encode(id));
        after = ingress::receive_page(&mut confirmer, page, tip, after, clock).unwrap();
        assert_eq!(after, *id);
        if index < 2 {
            assert_eq!(confirmer.active().unwrap().0, settings.genesis());
        }
    }
    assert_eq!(confirmer.active().unwrap().0, tip);
    let empty = public_v2::call_public_protected_v2(
        address,
        &Request::History {
            tip: hex::encode(tip),
            after: hex::encode(tip),
        },
        &settings,
        &server_key,
        &identity(72),
        policy,
    )
    .unwrap();
    assert!(empty.ok);
    assert_eq!(empty.value["packets"].as_array().unwrap().len(), 0);
    assert_eq!(empty.value["complete"], true);
    stop.store(true, Ordering::Release);
    let m = worker.join().unwrap();
    assert_eq!(m.completed_read, 4);
    assert_eq!(m.work_started, 0);
    assert_eq!(m.paid_body_reserved_bytes_after_shutdown, 0);
    assert_eq!(m.output_reserved_bytes_after_shutdown, 0);
}
