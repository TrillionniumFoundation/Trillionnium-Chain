//! One configuration combines native PQ accounts, real PNQ2 TCP, and the
//! separately running durable witness. Child libtest output is captured.
use super::*;
use crate::{
    ingress::{
        self,
        pq_network::{
            canonical_tests::{key, transfer},
            serve_pq_authenticated, PqClient, PqNetworkMetrics, PqServer,
        },
        Request,
    },
    pq_rollback_witness::{test_observation, ConnectedWitnessTransport, DurableWitness},
    Settings,
};
use std::{
    collections::BTreeSet,
    fs,
    io::{Read, Seek, SeekFrom, Write},
    net::{Shutdown, TcpListener, TcpStream},
    os::unix::net::{UnixListener, UnixStream},
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc,
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

type ProcessOutcome = std::io::Result<(ExitStatus, std::io::Result<Vec<u8>>)>;

struct Process {
    abort: mpsc::Sender<()>,
    outcome: mpsc::Receiver<ProcessOutcome>,
    status: Option<ExitStatus>,
    successful_stop: bool,
    pid: u32,
    directory: Arc<tempfile::TempDir>,
}

fn captured_file(file: &mut fs::File) -> std::io::Result<Vec<u8>> {
    const LIMIT: u64 = 64 * 1024;
    file.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::new();
    file.take(LIMIT + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > LIMIT {
        return Err(std::io::Error::other("owned witness output limit"));
    }
    Ok(bytes)
}

impl Process {
    fn start(directory: &Arc<tempfile::TempDir>, genesis: u64) -> Self {
        let path = directory.path();
        for name in [
            "witness.sock",
            "ready",
            "ready.pending",
            "stop",
            "receipt",
            test_observation::CHILD_FILE,
            test_observation::CHILD_PENDING,
        ] {
            match fs::remove_file(path.join(name)) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => panic!("fixture cleanup: {error}"),
            }
        }
        // Regular private files cannot leave a post-exit pipe reader waiting
        // for EOF. Neither child output nor a nested libtest summary is emitted.
        let mut stdout = tempfile::tempfile_in(path).unwrap();
        let mut stderr = tempfile::tempfile_in(path).unwrap();
        let child_stdout = stdout.try_clone().unwrap();
        let child_stderr = stderr.try_clone().unwrap();
        let (handoff, owned_child) = mpsc::channel::<Child>();
        let (abort, aborts) = mpsc::channel();
        let (completed, outcome) = mpsc::channel();
        let retained_directory = directory.clone();
        // This owner exists before its single child. All signalling and reaping
        // stay with that exact Child; no PID-only action can race PID reuse.
        // A caller timeout leaves the private directory with the actual owner.
        thread::spawn(move || {
            let _directory = retained_directory;
            let Ok(mut child) = owned_child.recv() else {
                return;
            };
            let mut killed = false;
            let mut reported_error = false;
            loop {
                match child.try_wait() {
                    Ok(Some(status)) => {
                        let captured =
                            captured_file(&mut stdout).and_then(|_| captured_file(&mut stderr));
                        let _ = completed.send(Ok((status, captured)));
                        return;
                    }
                    Ok(None) => {}
                    Err(error) => {
                        if !killed {
                            let _ = child.kill();
                            killed = true;
                        }
                        if !reported_error {
                            let _ = completed.send(Err(error));
                            reported_error = true;
                        }
                        // An observation error is not reaping. Keep ownership
                        // and the directory until try_wait actually sees exit.
                    }
                }
                if !killed
                    && matches!(
                        aborts.try_recv(),
                        Ok(()) | Err(mpsc::TryRecvError::Disconnected)
                    )
                {
                    let _ = child.kill();
                    killed = true;
                }
                thread::sleep(Duration::from_millis(5));
            }
        });
        let child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "store::pq_rollback_witness::combined_tests::independent_witness_process_child",
                "--nocapture",
            ])
            .env(FIXTURE_ENV, path)
            .env(TIME_ENV, genesis.to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::from(child_stdout))
            .stderr(Stdio::from(child_stderr))
            .spawn()
            .unwrap();
        let pid = child.id();
        handoff.send(child).unwrap();
        let mut process = Self {
            abort,
            outcome,
            status: None,
            successful_stop: false,
            pid,
            directory: directory.clone(),
        };
        let until = Instant::now() + Duration::from_secs(10);
        while !path.join("ready").exists() {
            assert!(
                Instant::now() < until,
                "independent witness startup deadline"
            );
            match process.outcome.try_recv() {
                Ok(output) => {
                    test_observation::forward_child(path);
                    let (status, stderr) = output.unwrap();
                    process.status = Some(status);
                    panic!(
                        "independent witness exited before ready ({status}): {}",
                        String::from_utf8_lossy(&stderr.unwrap())
                    );
                }
                Err(mpsc::TryRecvError::Empty) => {}
                Err(mpsc::TryRecvError::Disconnected) => {
                    panic!("independent witness process owner unavailable")
                }
            }
            thread::sleep(Duration::from_millis(5));
        }
        let recorded: u32 = fs::read_to_string(path.join("ready"))
            .unwrap()
            .parse()
            .unwrap();
        assert_eq!(recorded, process.pid);
        assert_ne!(recorded, std::process::id());
        process
    }
    fn stop(&mut self) {
        self.stop_until(Instant::now() + Duration::from_secs(10))
            .unwrap();
    }
    fn stop_until(&mut self, until: Instant) -> Result<()> {
        if self.status.is_some() {
            ensure(
                self.successful_stop,
                "owned witness cleanup previously failed",
            )?;
            return ensure(Instant::now() < until, "owned witness cleanup deadline");
        }
        fs::write(self.directory.path().join("stop"), b"stop fixture")?;
        let received = self
            .outcome
            .recv_timeout(until.saturating_duration_since(Instant::now()));
        let (status, stderr) = match received {
            Ok(output) => output?,
            Err(error) => {
                let _ = self.abort.send(());
                test_observation::forward_child(self.directory.path());
                return Err(format!("owned witness cleanup incomplete: {error}").into());
            }
        };
        self.status = Some(status);
        test_observation::forward_child(self.directory.path());
        let stderr = stderr?;
        ensure(
            status.success(),
            &format!(
                "independent witness child failed: {}",
                String::from_utf8_lossy(&stderr)
                    .chars()
                    .take(4096)
                    .collect::<String>()
            ),
        )?;
        // Do not emit the child's nested libtest summary into an exact-selector
        // receipt. Both stdout and stderr remain captured in this process.
        let receipt = fs::read_to_string(self.directory.path().join("receipt"))?;
        let (observed_pid, operations) = receipt
            .split_once(' ')
            .ok_or("owned witness receipt shape")?;
        ensure(
            observed_pid
                .parse::<u32>()
                .map_err(|_| "owned witness receipt pid")?
                == self.pid,
            "owned witness receipt pid",
        )?;
        ensure(
            operations
                .parse::<u64>()
                .map_err(|_| "owned witness receipt count")?
                > 0,
            "owned witness receipt count",
        )?;
        self.successful_stop = true;
        ensure(Instant::now() < until, "owned witness cleanup deadline")
    }
}
impl Drop for Process {
    fn drop(&mut self) {
        if self.status.is_none() {
            // The owner retains Child and directory until actual reaping. An
            // abort request is not an observed exit or completed cleanup.
            let _ = self.abort.send(());
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

struct Worker {
    stop: Arc<AtomicBool>,
    outcome: mpsc::Receiver<Result<PqNetworkMetrics>>,
    joined: bool,
    metrics: Option<PqNetworkMetrics>,
}
impl Worker {
    fn new(
        worker: thread::JoinHandle<PqNetworkMetrics>,
        stop: Arc<AtomicBool>,
        directory: Arc<tempfile::TempDir>,
    ) -> Self {
        let (completed, outcome) = mpsc::channel();
        thread::spawn(move || {
            let _directory = directory;
            // Only a returned join proves worker termination, including TLS
            // destructors. The caller observes this through a bounded receive.
            let joined = worker
                .join()
                .map_err(|_| crate::Error::from("owned node worker panicked"));
            let _ = completed.send(joined);
        });
        Self {
            stop,
            outcome,
            joined: false,
            metrics: None,
        }
    }
    fn stop_until(&mut self, until: Instant) -> Result<()> {
        self.stop.store(true, Ordering::Release);
        if self.joined {
            ensure(self.metrics.is_some(), "owned node worker panicked")?;
            return ensure(Instant::now() < until, "owned node cleanup deadline");
        }
        let joined = self
            .outcome
            .recv_timeout(until.saturating_duration_since(Instant::now()))
            .map_err(|error| {
                crate::Error::from(format!("owned node cleanup incomplete: {error}"))
            })?;
        self.joined = true;
        self.metrics = Some(joined?);
        ensure(Instant::now() < until, "owned node cleanup deadline")
    }
}
impl Drop for Worker {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
    }
}

fn cleanup(worker: &mut Worker, external: &mut Process) -> (Result<()>, Result<()>) {
    // One cleanup interval; no substep renews it. Business/transport deadlines
    // are already over and are never extended by collecting these observations.
    let until = Instant::now() + Duration::from_secs(10);
    let joined = worker.stop_until(until);
    let stopped = external.stop_until(until);
    (joined, stopped)
}

fn preserve_send_error<T>(
    result: Result<T>,
    worker: &mut Worker,
    external: &mut Process,
) -> Result<T> {
    if result.is_err() {
        let (joined, stopped) = cleanup(worker, external);
        eprintln!(
            "TRNM_PQ_FIXTURE_CLEANUP {}",
            serde_json::json!({
                "primary_error_preserved":true,
                "worker_join_observed":worker.joined,
                "child_exit_observed":external.status.is_some(),
                "child_exit_success":external.status.map(|status|status.success()),
                "cleanup_complete":joined.is_ok() && stopped.is_ok(),
                "worker_cleanup_error":joined.err().map(|error|error.to_string()),
                "child_cleanup_error":stopped.err().map(|error|error.to_string()),
            })
        );
    }
    result
}

#[derive(Clone, Copy)]
enum SubmitControl {
    AfterRejectedSignature,
    ValidOnly,
    ValidThenCleanupError,
}

#[test]
fn guarded_npq6_submit_recovers_after_invalid_signature_and_independent_process_restart() {
    submit_replay_restart(SubmitControl::AfterRejectedSignature);
}

#[test]
fn guarded_npq6_valid_submit_exact_replay_and_independent_process_restart() {
    submit_replay_restart(SubmitControl::ValidOnly);
}

#[test]
fn guarded_npq6_valid_submit_cleanup_preserves_primary_error_and_child_diagnostics() {
    submit_replay_restart(SubmitControl::ValidThenCleanupError);
}

fn submit_replay_restart(control: SubmitControl) {
    let diagnostics = test_observation::Scope::new();
    let directory = Arc::new(tempfile::tempdir().unwrap());
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
    let mut external = Process::start(&directory, genesis);
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
    if matches!(control, SubmitControl::AfterRejectedSignature) {
        assert!(crate::Packet::decode(&raw).is_err());
    }
    let id = packet.id().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let _stop_on_drop = StopOnDrop(stop.clone());
    let stopped = stop.clone();
    let server = PqServer::new(policy.clone(), key(71)).unwrap();
    let worker_observations = diagnostics.recorder();
    let worker_directory = directory.clone();
    let worker = thread::spawn(move || {
        let _directory = worker_directory;
        let _observations = test_observation::Scope::attach(worker_observations);
        serve_pq_authenticated(listener, node, Duration::from_secs(30), stopped, server).unwrap()
    });
    let mut worker = Worker::new(worker, stop.clone(), directory.clone());
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
    if matches!(control, SubmitControl::AfterRejectedSignature) {
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
    }
    let first = preserve_send_error(
        sender.send(address, &prepared, Duration::from_secs(10)),
        &mut worker,
        &mut external,
    )
    .unwrap();
    assert!(first.ok, "{:?}", first.value);
    assert_eq!(first.value["block"], hex::encode(id));
    if matches!(control, SubmitControl::ValidThenCleanupError) {
        // The legitimate Submit has completed. This local sentinel enters no
        // transport and triggers no further witness request or request retry.
        let primary = crate::Error::from("VALID_FIXTURE_CLEANUP_SENTINEL");
        let expected = format!("{primary:?}");
        let result: Result<()> = preserve_send_error(Err(primary), &mut worker, &mut external);
        let error = result.unwrap_err();
        assert_eq!(format!("{error:?}"), expected);
        assert_eq!(error.to_string(), "VALID_FIXTURE_CLEANUP_SENTINEL");
        assert!(worker.joined);
        assert_eq!(worker.metrics.as_ref().unwrap().accepted, 1);
        assert_eq!(worker.metrics.as_ref().unwrap().refused, 0);
        assert!(external.status.unwrap().success());
        assert!(external.successful_stop);
        let mut bytes = Vec::new();
        fs::File::open(directory.path().join(test_observation::CHILD_FILE))
            .unwrap()
            .take(32 * 1024 + 1)
            .read_to_end(&mut bytes)
            .unwrap();
        assert!(bytes.len() <= 32 * 1024);
        let text = std::str::from_utf8(&bytes).unwrap();
        let snapshot: serde_json::Value =
            serde_json::from_str(text.strip_prefix(test_observation::PREFIX).unwrap()).unwrap();
        assert_eq!(snapshot["schema"], "pon-pq-test-phase-observation-v1");
        assert_eq!(snapshot["scope_snapshot_is_final"], true);
        assert_eq!(snapshot["has_open_operations"], false);
        assert!(snapshot["records_started"].as_u64().unwrap() > 0);
        // An already queued/observed terminal fact cannot promote cleanup to
        // timely completion after its original observation interval has ended.
        assert_eq!(
            worker.stop_until(Instant::now()).unwrap_err().to_string(),
            "owned node cleanup deadline"
        );
        assert_eq!(
            external.stop_until(Instant::now()).unwrap_err().to_string(),
            "owned witness cleanup deadline"
        );
        assert!(worker.joined);
        assert!(external.status.unwrap().success());
        assert!(external.successful_stop);
        return;
    }
    let replay = preserve_send_error(
        sender.send(address, &prepared, Duration::from_secs(10)),
        &mut worker,
        &mut external,
    )
    .unwrap();
    assert_eq!(first, replay);
    let (joined, stopped) = cleanup(&mut worker, &mut external);
    joined.unwrap();
    let metrics = worker.metrics.as_ref().unwrap();
    assert_eq!(metrics.accepted, 2);
    if matches!(control, SubmitControl::AfterRejectedSignature) {
        assert_eq!(metrics.refused, 1);
    } else {
        assert_eq!(metrics.refused, 0);
    }
    // The TCP worker dropped its actual Node and Unix stream. Cold-restart the
    // independent process; it opens the retained external database, never seeds.
    stopped.unwrap();
    let mut restarted = Process::start(&directory, genesis);
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
    if matches!(control, SubmitControl::AfterRejectedSignature) {
        assert_eq!(status["inbound_signature_attempts"], 3);
        assert_eq!(status["ingress_connections"], 3);
    } else {
        assert_eq!(status["inbound_signature_attempts"], 2);
        assert_eq!(status["ingress_connections"], 2);
    }
    assert_eq!(status["transport_confidentiality"], false);
    assert!(checkpoint(&reopened.db).unwrap().sequence > initial.sequence);
    drop(reopened);
    restarted.stop();
}
