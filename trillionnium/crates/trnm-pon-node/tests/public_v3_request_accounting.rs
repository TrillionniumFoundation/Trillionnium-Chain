//! Actual optional measurements preserve full native acceptance/rejection and shutdown.
use std::{
    io::Write,
    net::{Shutdown, TcpListener, TcpStream},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};
use trnm_crypto_primitives::pon_work;
use trnm_pon_node::{
    development_public,
    ingress::{
        self,
        public_v3::{
            self, PublicMetrics, PublicPolicy, PublicRequestObserver, PublicServer, Request,
        },
        DevelopmentIdentity,
    },
    Node, PoolLimits, Settings,
};

fn identity(n: u8) -> DevelopmentIdentity {
    DevelopmentIdentity::from_secret_hex(&hex::encode([n; 32])).unwrap()
}
fn enable(node: &mut Node) {
    node.enable_local_mempool(PoolLimits {
        max_records: 8,
        max_bytes: 32768,
        max_group_members: 4,
        critical_reserve: 0,
        max_removals: 16,
        preview_miner: development_public(3).unwrap(),
    })
    .unwrap();
}
type RunningService = (
    std::net::SocketAddr,
    Arc<AtomicBool>,
    Arc<Mutex<PublicMetrics>>,
    thread::JoinHandle<PublicMetrics>,
);
fn service(node: Arc<Mutex<Node>>, observer: PublicRequestObserver) -> RunningService {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let metrics = Arc::new(Mutex::new(PublicMetrics::default()));
    let signal = stop.clone();
    let counters = metrics.clone();
    let worker = thread::spawn(move || {
        public_v3::serve_public_protected_v3_with_request_observer(
            listener,
            node,
            Duration::from_secs(15),
            signal,
            PublicServer::new(
                identity(71),
                PublicPolicy::new(8, Duration::from_secs(2)).unwrap(),
            )
            .unwrap(),
            counters,
            observer,
        )
        .unwrap()
    });
    (address, stop, metrics, worker)
}

#[test]
fn actual_paid_native_work_rejection_read_frames_and_partial_eof_are_attributed() {
    let now = ingress::now().unwrap();
    let settings = Settings::development(Some(now - 100)).unwrap();
    let oracle_dir = tempfile::tempdir().unwrap();
    let mut oracle = Node::open(oracle_dir.path(), settings.clone(), 1).unwrap();
    let packet = oracle
        .make(
            settings.genesis(),
            vec![],
            development_public(3).unwrap(),
            now - 90,
            4096,
        )
        .unwrap();
    let mut bad = packet.clone();
    let offset = 4 + 8 * pon_work::CELLS;
    let value = u32::from_le_bytes(bad.proof[offset..offset + 4].try_into().unwrap());
    bad.proof[offset..offset + 4]
        .copy_from_slice(&((u128::from(value) + 1) % pon_work::Q).to_le_bytes()[..4]);
    assert_eq!(
        pon_work::verify(
            bad.header.challenge(),
            bad.header.work_task,
            bad.header.target,
            &bad.proof
        )
        .unwrap_err(),
        pon_work::WorkError::Product
    );
    let native_dir = tempfile::tempdir().unwrap();
    let mut node = Node::open(native_dir.path(), settings.clone(), 1).unwrap();
    enable(&mut node);
    let node = Arc::new(Mutex::new(node));
    let observer = PublicRequestObserver::new(5).unwrap();
    let (address, stop, metrics, worker) = service(node.clone(), observer.clone());
    let mut partial = TcpStream::connect(address).unwrap();
    partial.write_all(b"PPI3\x01").unwrap();
    partial.shutdown(Shutdown::Write).unwrap();
    drop(partial);
    let end = Instant::now() + Duration::from_secs(2);
    while metrics.lock().unwrap().preface_refusals == 0 {
        assert!(Instant::now() < end);
        thread::sleep(Duration::from_millis(2));
    }
    let policy = PublicPolicy::new(8, Duration::from_secs(2)).unwrap();
    let requests = [
        Request::Submit {
            packet: hex::encode(bad.encode().unwrap()),
        },
        Request::Submit {
            packet: hex::encode(packet.encode().unwrap()),
        },
        Request::Head,
        Request::History {
            tip: hex::encode(packet.id().unwrap()),
            after: hex::encode(settings.genesis()),
        },
    ];
    let mut expected_body = Vec::new();
    for (i, request) in requests.iter().enumerate() {
        let (result, cost) = public_v3::call_public_protected_v3_with_metrics(
            address,
            request,
            &settings,
            identity(71).public_key(),
            &identity(80 + i as u8),
            policy,
        );
        let reply = result.unwrap();
        assert_eq!(reply.ok, i != 0, "{}", reply.value);
        if i == 0 {
            assert!(reply.value.to_string().contains("Product"));
        }
        assert!(cost.solution_found);
        expected_body.push(reply.body_bytes_sent);
    }
    stop.store(true, Ordering::Release);
    let metrics = worker.join().unwrap();
    let snapshot = observer.snapshot();
    assert_eq!(snapshot.accepted_connections_seen, 5);
    assert_eq!(snapshot.records.len(), 5);
    assert_eq!(snapshot.records_not_retained, 0);
    assert_eq!(snapshot.measurement_failures, 0);
    assert!(!snapshot.counter_overflow);
    assert_eq!(metrics.work_started, 2);
    assert_eq!(metrics.work_finished, 2);
    assert_eq!(metrics.work_failed, 1);
    let partial = &snapshot.records[0];
    assert!(partial.complete && partial.connection_closed && !partial.task_created);
    assert_eq!(partial.application_bytes_read, Some(5));
    assert_eq!(partial.application_bytes_written, Some(0));
    assert!(!partial.frames[0].complete);
    assert_eq!(partial.dispatch_thread_cpu_ns, None);
    assert_eq!(partial.full_work_thread_cpu_ns, None);
    for (i, row) in snapshot.records[1..].iter().enumerate() {
        assert!(row.complete && row.task_created && row.task_closed && row.response_frame_complete);
        assert!(row.frames.iter().all(|f| f.complete));
        assert_eq!(row.frames[0].bytes_read, 108);
        assert_eq!(row.frames[2].bytes_read, 108);
        assert_eq!(row.frames[4].bytes_read, expected_body[i] as u64);
        assert_eq!(
            row.application_bytes_read,
            Some(216 + expected_body[i] as u64)
        );
        assert_eq!(
            row.application_bytes_written,
            Some(row.frames.iter().map(|f| f.bytes_written).sum())
        );
        assert!(
            row.frames[1].bytes_written > 4
                && row.frames[3].bytes_written > 4
                && row.frames[5].bytes_written > 4
        );
        assert_eq!(row.physical_network_bytes, None);
        assert!(row.dispatch_started);
        assert_eq!(row.dispatch_accepted, Some(i != 0));
        assert_eq!(row.full_work_started, i < 2);
        if i < 2 {
            assert_eq!(row.full_work_accepted, Some(i == 1));
            if cfg!(target_os = "linux") {
                assert!(
                    row.dispatch_thread_cpu_ns.unwrap() >= row.full_work_thread_cpu_ns.unwrap()
                );
                assert!(row.full_work_thread_cpu_ns.unwrap() > 0);
            }
        } else {
            assert_eq!(row.full_work_thread_cpu_ns, None);
            assert_eq!(row.full_work_accepted, None);
        }
    }
    let id = oracle.admit(&packet, now).unwrap();
    oracle.activate_observed(id, now).unwrap();
    assert_eq!(
        node.lock().unwrap().read_active().unwrap(),
        oracle.read_active().unwrap()
    );
    assert_eq!(
        node.lock().unwrap().packet(id).unwrap().encode().unwrap(),
        packet.encode().unwrap()
    );
    assert_eq!(metrics.unknown_caller_durable_rows, 0);
    assert_eq!(metrics.paid_body_reserved_bytes_after_shutdown, 0);
    assert_eq!(metrics.output_reserved_bytes_after_shutdown, 0);
    println!("{}", serde_json::to_string(&snapshot).unwrap());
}

#[test]
fn real_observer_capacity_overflow_does_not_refuse_concurrent_honest_reads() {
    let directory = tempfile::tempdir().unwrap();
    let settings = Settings::development(Some(ingress::now().unwrap() - 100)).unwrap();
    let mut node = Node::open(directory.path(), settings.clone(), 1).unwrap();
    enable(&mut node);
    let before = node.read_active().unwrap();
    let node = Arc::new(Mutex::new(node));
    let observer = PublicRequestObserver::new(1).unwrap();
    let (address, stop, _, worker) = service(node.clone(), observer.clone());
    thread::scope(|scope| {
        let mut clients = Vec::new();
        for i in 0..4 {
            let settings = &settings;
            clients.push(scope.spawn(move || {
                public_v3::call_public_protected_v3(
                    address,
                    &Request::Head,
                    settings,
                    identity(71).public_key(),
                    &identity(80 + i),
                    PublicPolicy::new(8, Duration::from_secs(2)).unwrap(),
                )
                .unwrap()
            }));
        }
        for client in clients {
            assert!(client.join().unwrap().ok);
        }
    });
    stop.store(true, Ordering::Release);
    let metrics = worker.join().unwrap();
    let snapshot = observer.snapshot();
    assert_eq!(metrics.completed_read, 4);
    assert_eq!(snapshot.accepted_connections_seen, 4);
    assert_eq!(snapshot.records_not_retained, 3);
    assert_eq!(snapshot.records.len(), 1);
    assert!(snapshot.records[0].complete);
    assert_eq!(snapshot.records[0].full_work_thread_cpu_ns, None);
    assert_eq!(node.lock().unwrap().read_active().unwrap(), before);
}
