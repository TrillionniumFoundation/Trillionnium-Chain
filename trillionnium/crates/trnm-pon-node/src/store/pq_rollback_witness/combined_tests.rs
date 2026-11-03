//! One configuration combines native PQ accounts, real PNQ2 TCP, and the
//! separately running durable witness. Child libtest output is captured.
use super::*;
use crate::{
    ingress::{
        self,
        pq_network::{
            canonical_tests::{key, transfer},
            serve_pq_authenticated, PqClient, PqServer,
        },
        Request,
    },
    pq_rollback_witness::{test_observation, ConnectedWitnessTransport, DurableWitness},
    Settings,
};
use std::{
    collections::BTreeSet,
    fs,
    io::{Read, Write},
    net::{Shutdown, TcpListener, TcpStream},
    os::unix::net::{UnixListener, UnixStream},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::Duration,
};
use trnm_mvcc_fee::pon_executor::pq_accounts_v2::{self as accounts, application_v6};

const FIXTURE_ENV: &str = "TRNM_PQ_WITNESS_PROCESS_FIXTURE";
const TIME_ENV: &str = "TRNM_PQ_WITNESS_PROCESS_GENESIS";

fn settings_and_policy(genesis: u64) -> (Settings, Arc<PqNetworkPolicy>) {
    let seeded: Vec<_> = [1, 2, 3]
        .into_iter()
        .map(|seed| accounts::GenesisAccount {
            spki: key(seed).public_spki().to_vec(),
            balance: 1_000_000_000,
        })
        .collect();
    let settings = Settings::native_pq_application_v6(
        &seeded,
        genesis,
        &application_v6::ApplicationPolicy {
            evaluators: BTreeSet::from([key(2).public_key_id(), key(3).public_key_id()]),
            evaluation_profile: trnm_mvcc_fee::public_evaluation::PROFILE.into(),
            model_profile: "linear-expert-dev-v1".into(),
        },
    )
    .unwrap();
    let policy = Arc::new(
        PqNetworkPolicy::new(
            &settings,
            key(71).public_spki(),
            1,
            [key(72).public_spki().to_vec()],
        )
        .unwrap(),
    );
    (settings, policy)
}
fn binding(policy: &PqNetworkPolicy) -> WitnessBinding {
    WitnessBinding::new(policy, 1, key(91).public_spki(), key(92).public_spki()).unwrap()
}
fn client(directory: &Path, policy: &PqNetworkPolicy) -> WitnessClient {
    WitnessClient::new(
        binding(policy),
        key(92),
        Box::new(ConnectedWitnessTransport::new(
            UnixStream::connect(directory.join("witness.sock")).unwrap(),
        )),
    )
    .unwrap()
}

struct Process {
    child: Option<Child>,
    directory: PathBuf,
}
impl Process {
    fn start(directory: &Path, genesis: u64) -> Self {
        for name in [
            "witness.sock",
            "ready",
            "ready.pending",
            "stop",
            "receipt",
            test_observation::CHILD_FILE,
            test_observation::CHILD_PENDING,
        ] {
            match fs::remove_file(directory.join(name)) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => panic!("fixture cleanup: {error}"),
            }
        }
        let child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "store::pq_rollback_witness::combined_tests::independent_witness_process_child",
                "--nocapture",
            ])
            .env(FIXTURE_ENV, directory)
            .env(TIME_ENV, genesis.to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut process = Self {
            child: Some(child),
            directory: directory.to_path_buf(),
        };
        let until = Instant::now() + Duration::from_secs(10);
        while !directory.join("ready").exists() {
            assert!(
                Instant::now() < until,
                "independent witness startup deadline"
            );
            if let Some(status) = process.child.as_mut().unwrap().try_wait().unwrap() {
                let output = process.child.take().unwrap().wait_with_output().unwrap();
                test_observation::forward_child(directory);
                // Preserve the child's actual failure without printing its
                // nested libtest summary into the parent's exact-test receipt.
                panic!(
                    "independent witness exited before ready ({status}): {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            thread::sleep(Duration::from_millis(5));
        }
        let recorded: u32 = fs::read_to_string(directory.join("ready"))
            .unwrap()
            .parse()
            .unwrap();
        assert_eq!(recorded, process.child.as_ref().unwrap().id());
        assert_ne!(recorded, std::process::id());
        process
    }
    fn stop(&mut self) {
        fs::write(self.directory.join("stop"), b"stop fixture").unwrap();
        let until = Instant::now() + Duration::from_secs(10);
        while self.child.as_mut().unwrap().try_wait().unwrap().is_none() {
            assert!(Instant::now() < until, "independent witness stop deadline");
            thread::sleep(Duration::from_millis(5));
        }
        let child = self.child.take().unwrap();
        let pid = child.id();
        let output = child.wait_with_output().unwrap();
        test_observation::forward_child(&self.directory);
        assert!(
            output.status.success(),
            "independent witness child failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        // Do not emit the child's nested libtest summary into an exact-selector
        // receipt. Both stdout and stderr remain captured in this process.
        let receipt = fs::read_to_string(self.directory.join("receipt")).unwrap();
        let (observed_pid, operations) = receipt.split_once(' ').unwrap();
        assert_eq!(observed_pid.parse::<u32>().unwrap(), pid);
        assert!(operations.parse::<u64>().unwrap() > 0);
    }
}
impl Drop for Process {
    fn drop(&mut self) {
        if let Some(child) = self.child.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
            test_observation::forward_child(&self.directory);
        }
    }
}

/// Subprocess harness, deliberately excluded from the meaningful-control count.
#[test]
fn independent_witness_process_child() {
    let Some(directory) = std::env::var_os(FIXTURE_ENV) else {
        return;
    };
    let directory = PathBuf::from(directory);
    let _diagnostics = test_observation::Scope::child(&directory);
    let genesis = std::env::var(TIME_ENV).unwrap().parse().unwrap();
    let (_, policy) = settings_and_policy(genesis);
    // The service process only opens existing state; no enrollment fallback.
    let mut owner =
        DurableWitness::open_existing(&directory.join("witness.sqlite"), binding(&policy), key(91))
            .unwrap();
    let listener = UnixListener::bind(directory.join("witness.sock")).unwrap();
    listener.set_nonblocking(true).unwrap();
    fs::write(
        directory.join("ready.pending"),
        std::process::id().to_string(),
    )
    .unwrap();
    fs::rename(directory.join("ready.pending"), directory.join("ready")).unwrap();
    let end = Instant::now() + Duration::from_secs(60);
    let mut operations = 0_u64;
    while !directory.join("stop").exists() {
        assert!(Instant::now() < end, "independent witness fixture lifetime");
        match listener.accept() {
            Ok((mut stream, _)) => {
                let mut failed_request = None;
                while !directory.join("stop").exists() && Instant::now() < end {
                    if let Err(error) = owner.serve_one(
                        &mut stream,
                        end.min(Instant::now() + Duration::from_secs(10)),
                    ) {
                        failed_request = Some(error);
                        break;
                    }
                    operations += 1;
                }
                // Preserve the old connection close before any diagnostic I/O.
                // At most one completed-failure checkpoint and one final scope
                // snapshot use the same bounded file; neither renews a budget.
                drop(stream);
                if let Some(error) = failed_request {
                    _diagnostics.save_child_failure(&error);
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(2))
            }
            Err(error) => panic!("independent witness accept: {error}"),
        }
    }
    fs::write(
        directory.join("receipt"),
        format!("{} {operations}", std::process::id()),
    )
    .unwrap();
}

struct StopOnDrop(Arc<AtomicBool>);
impl Drop for StopOnDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

#[test]
fn guarded_npq6_submit_recovers_after_invalid_signature_and_independent_process_restart() {
    let diagnostics = test_observation::Scope::new();
    let directory = tempfile::tempdir().unwrap();
    let genesis = ingress::now().unwrap() - 100;
    let (settings, policy) = settings_and_policy(genesis);
    let binding = binding(&policy);
    let initial = initial_checkpoint(&policy, &binding).unwrap();
    drop(
        DurableWitness::register_new(
            &directory.path().join("witness.sqlite"),
            binding,
            initial,
            key(91),
        )
        .unwrap(),
    );
    let mut external = Process::start(directory.path(), genesis);
    let node_path = directory.path().join("node");
    let node = Node::create_with_pq_witness(
        &node_path,
        settings.clone(),
        1,
        &policy,
        client(directory.path(), &policy),
    )
    .unwrap();
    let packet = node
        .make_consensus_maintenance(
            settings.genesis(),
            vec![transfer(&settings)],
            key(1).public_key_id(),
            settings.genesis_time() + 10,
            4096,
        )
        .unwrap();
    let raw = packet.encode_for_settings(&settings).unwrap();
    assert!(raw.starts_with(b"PQP6\x06\0\0\0"));
    assert!(crate::Packet::decode(&raw).is_err());
    let id = packet.id().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let _stop_on_drop = StopOnDrop(stop.clone());
    let stopped = stop.clone();
    let server = PqServer::new(policy.clone(), key(71)).unwrap();
    let worker_observations = diagnostics.recorder();
    let worker = thread::spawn(move || {
        let _observations = test_observation::Scope::attach(worker_observations);
        serve_pq_authenticated(listener, node, Duration::from_secs(30), stopped, server).unwrap()
    });
    let sender = PqClient::new(policy.clone(), key(72)).unwrap();
    let prepared = sender
        .prepare(
            1,
            ingress::now().unwrap() + 60,
            Request::Submit {
                packet: hex::encode(raw),
            },
        )
        .unwrap();
    let mut bad = prepared.wire().to_vec();
    bad[8 + trnm_protocol::pq_frame::TPQ1_UNSIGNED_BYTES + 2] ^= 1;
    let mut rejected = TcpStream::connect(address).unwrap();
    rejected
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    rejected
        .set_write_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    rejected
        .write_all(&(bad.len() as u32).to_be_bytes())
        .unwrap();
    rejected.write_all(&bad).unwrap();
    rejected.shutdown(Shutdown::Write).unwrap();
    let mut byte = [0; 1];
    match rejected.read(&mut byte) {
        Ok(0) => {}
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::UnexpectedEof
            ) => {}
        other => panic!("invalid signature was not refused by closing TCP: {other:?}"),
    }
    drop(rejected);
    let first = sender
        .send(address, &prepared, Duration::from_secs(10))
        .unwrap();
    assert!(first.ok, "{:?}", first.value);
    assert_eq!(first.value["block"], hex::encode(id));
    let replay = sender
        .send(address, &prepared, Duration::from_secs(10))
        .unwrap();
    assert_eq!(first, replay);
    stop.store(true, Ordering::Release);
    let metrics = worker.join().unwrap();
    assert_eq!(metrics.accepted, 2);
    assert_eq!(metrics.refused, 1);
    // The TCP worker dropped its actual Node and Unix stream. Cold-restart the
    // independent process; it opens the retained external database, never seeds.
    external.stop();
    let mut restarted = Process::start(directory.path(), genesis);
    let reopened = Node::open_with_pq_witness(
        &node_path,
        settings,
        1,
        &policy,
        client(directory.path(), &policy),
    )
    .unwrap();
    assert_eq!(reopened.active().unwrap().0, id);
    let state = reopened.state_at(id).unwrap();
    assert_eq!(
        state[&format!("account:{}", hex::encode(key(2).public_key_id()))]["balance"],
        1_000_000_042_u64
    );
    let status = reopened.pq_network_status(&policy).unwrap();
    assert_eq!(status["records"], 1);
    assert_eq!(status["inbound_signature_attempts"], 3);
    assert_eq!(status["ingress_connections"], 3);
    assert_eq!(status["transport_confidentiality"], false);
    assert!(checkpoint(&reopened.db).unwrap().sequence > initial.sequence);
    drop(reopened);
    restarted.stop();
}
