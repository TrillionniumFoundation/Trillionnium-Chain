//! Observe real PQ admission workers, then independently exercise the existing
//! PNQ2 socket owner and cold replay. No public PQ Submit or CPU qualification
//! is inferred from this loopback fixture, and ACK is not a confirmation count.
use super::canonical_tests::{key, setup, signed_command};
use super::*;
use rusqlite::{types::Value as SqlValue, Connection, OpenFlags};
use std::{collections::HashSet, path::Path, sync::atomic::AtomicUsize, thread::ThreadId};
use trnm_mvcc_fee::pon_executor::{
    ExecutionControl, ExecutionProgress, ExecutionWorkerAccounting, ExecutionWorkerInterval,
};

#[derive(Default)]
struct Workers {
    spawned: AtomicUsize,
    started: Mutex<Vec<ThreadId>>,
    finished: Mutex<Vec<ThreadId>>,
    active: AtomicUsize,
}
struct Interval<'a> {
    workers: &'a Workers,
    thread: ThreadId,
}
impl ExecutionWorkerInterval for Interval<'_> {}
impl Drop for Interval<'_> {
    fn drop(&mut self) {
        assert_eq!(std::thread::current().id(), self.thread);
        self.workers.finished.lock().unwrap().push(self.thread);
        self.workers.active.fetch_sub(1, Ordering::SeqCst);
    }
}
impl ExecutionWorkerAccounting for Workers {
    fn worker_started(&self) -> Option<Box<dyn ExecutionWorkerInterval + '_>> {
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

type Rows = Vec<(&'static str, Vec<Vec<SqlValue>>)>;

// Diagnostic comparison only, on an independent read-only SQLite connection.
// These are the actual durable chain tables, not replay-authorizing snapshots.
fn chain_rows(path: &Path) -> Rows {
    let db =
        Connection::open_with_flags(path.join("native.sqlite"), OpenFlags::SQLITE_OPEN_READ_ONLY)
            .unwrap();
    [
        ("blocks", "SELECT * FROM blocks ORDER BY id"),
        ("deltas", "SELECT * FROM deltas ORDER BY block,key"),
        ("snapshots", "SELECT * FROM snapshots ORDER BY block"),
        ("kv", "SELECT * FROM kv ORDER BY slot,key"),
        ("active", "SELECT * FROM active ORDER BY singleton"),
        ("events", "SELECT * FROM events ORDER BY generation,ordinal"),
        (
            "ancestry_jump",
            "SELECT * FROM ancestry_jump ORDER BY block,level",
        ),
    ]
    .into_iter()
    .map(|(name, sql)| {
        let mut statement = db.prepare(sql).unwrap();
        let columns = statement.column_count();
        let rows = statement
            .query_map([], |row| {
                (0..columns)
                    .map(|index| row.get::<_, SqlValue>(index))
                    .collect::<rusqlite::Result<Vec<_>>>()
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        (name, rows)
    })
    .collect()
}

struct StopOnDrop(Arc<AtomicBool>);
impl Drop for StopOnDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

#[test]
fn pq_parallel_admission_matches_serial_rows_and_cold_socket_replay() {
    let (settings, policy) = setup();
    let transactions = (1..=8)
        .map(|nonce| {
            let payload = [
                key(2).public_key_id().as_slice(),
                &42_u64.to_le_bytes(),
                &0_u16.to_be_bytes(),
            ]
            .concat();
            signed_command(&settings, 1, nonce, 1, &payload)
        })
        .collect();
    let source_dir = tempfile::tempdir().unwrap();
    let source =
        Node::open_with_pq_network(source_dir.path(), settings.clone(), 1, &policy).unwrap();
    let packet = source
        .make_consensus_maintenance(
            settings.genesis(),
            transactions,
            key(3).public_key_id(),
            settings.genesis_time() + 10,
            4096,
        )
        .unwrap();
    drop(source);
    let id = packet.id().unwrap();
    let wire = packet.encode_for_settings(&settings).unwrap();
    assert_eq!(packet.transactions.len(), 8);
    assert!(wire.starts_with(b"PQP6\x06\0\0\0"));
    let mut serial = None;
    for count in [1, 2, 4, 8] {
        // This existing admission API carries the real accounting observer.
        // The separate socket path below intentionally keeps its original &().
        let directory = tempfile::tempdir().unwrap();
        let mut node =
            Node::open_with_pq_network(directory.path(), settings.clone(), count, &policy).unwrap();
        let workers = Workers::default();
        let owner = std::thread::current().id();
        let prepared = Mutex::new(Vec::new());
        let applied = Mutex::new(Vec::new());
        let progress = |point| {
            match point {
                ExecutionProgress::BeforePrepare { .. }
                | ExecutionProgress::AfterPrepare { .. } => {
                    assert_eq!(std::thread::current().id() == owner, count == 1);
                    if let ExecutionProgress::AfterPrepare { index } = point {
                        prepared.lock().unwrap().push(index);
                    }
                }
                _ => {
                    assert_eq!(std::thread::current().id(), owner);
                    if let ExecutionProgress::AfterApply { index } = point {
                        applied.lock().unwrap().push(index);
                    }
                }
            }
            Ok(())
        };
        assert_eq!(
            node.admit_work_checked_with_control(
                WorkCheckedPacket::verify(packet.clone()).unwrap(),
                super::super::now().unwrap(),
                &ExecutionControl::new(&progress, &workers),
            )
            .unwrap(),
            id
        );
        workers.joined(if count == 1 { 0 } else { count }, owner);
        let mut prepared = prepared.into_inner().unwrap();
        prepared.sort_unstable();
        assert_eq!(prepared, (0..8).collect::<Vec<_>>());
        assert_eq!(applied.into_inner().unwrap(), (0..8).collect::<Vec<_>>());
        assert_eq!(node.activate(id).unwrap(), id);
        let expected_state = node.state_at(id).unwrap();
        assert_eq!(
            expected_state[&format!("account:{}", hex::encode(key(1).public_key_id()))]["nonce"],
            8
        );
        assert_eq!(
            expected_state[&format!("account:{}", hex::encode(key(2).public_key_id()))]["balance"],
            1_000_000_336_u64
        );
        assert_eq!(
            node.packet(id)
                .unwrap()
                .encode_for_settings(&settings)
                .unwrap(),
            wire
        );
        let actual = (
            node.active().unwrap(),
            expected_state,
            chain_rows(directory.path()),
        );
        if let Some(reference) = &serial {
            assert_eq!(&actual, reference);
        }
        serial = Some(actual.clone());
        drop(node);
        let cold =
            Node::open_with_pq_network(directory.path(), settings.clone(), 1, &policy).unwrap();
        assert_eq!(cold.active().unwrap(), actual.0);
        assert_eq!(cold.state_at(id).unwrap(), actual.1);
        assert_eq!(chain_rows(directory.path()), actual.2);
        drop(cold);

        // A fresh real PNQ2 service executes this packet, then returns the exact
        // retained response for the same authenticated operation. Its native
        // state is compared with the instrumented original admission above.
        let socket_directory = tempfile::tempdir().unwrap();
        let socket_node =
            Node::open_with_pq_network(socket_directory.path(), settings.clone(), count, &policy)
                .unwrap();
        assert!(socket_node.packet(id).is_err());
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = stop.clone();
        let server = PqServer::new(policy.clone(), key(71)).unwrap();
        let client = PqClient::new(policy.clone(), key(72)).unwrap();
        let request = client
            .prepare(
                1,
                super::super::now().unwrap() + 60,
                Request::Submit {
                    packet: hex::encode(&wire),
                },
            )
            .unwrap();
        std::thread::scope(|scope| {
            let worker = scope.spawn(move || {
                serve_pq_authenticated(
                    listener,
                    socket_node,
                    Duration::from_secs(30),
                    worker_stop,
                    server,
                )
            });
            let stop_on_drop = StopOnDrop(stop);
            let response = client
                .send(address, &request, Duration::from_secs(10))
                .unwrap();
            assert!(response.ok, "{:?}", response.value);
            assert_eq!(response.value["block"], hex::encode(id));
            assert_eq!(response.value["physical_execution"], false);
            let replay = client
                .send(address, &request, Duration::from_secs(10))
                .unwrap();
            assert_eq!(replay, response);
            drop(stop_on_drop);
            let metrics = worker.join().unwrap().unwrap();
            assert_eq!(metrics.accepted, 2);
            assert_eq!(metrics.refused, 0);
        });
        let cold =
            Node::open_with_pq_network(socket_directory.path(), settings.clone(), 1, &policy)
                .unwrap();
        assert_eq!(cold.active().unwrap(), actual.0);
        assert_eq!(cold.state_at(id).unwrap(), actual.1);
        assert_eq!(chain_rows(socket_directory.path()), actual.2);
        let status = cold.pq_network_status(&policy).unwrap();
        assert_eq!(status["records"], 1);
        assert_eq!(status["inbound_signature_attempts"], 2);
        assert_eq!(status["ingress_connections"], 2);
        assert_eq!(status["inbound_signature_attempt_limit"], 64);
        assert_eq!(status["production_activation"], false);
    }
}
