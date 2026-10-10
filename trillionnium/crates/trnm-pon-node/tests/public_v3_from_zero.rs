//! Finite local from-zero W1 traffic on the existing public service CPU domain.
//! No WAN, cheapest-producer, saturation, energy or production qualification.
//! CPU intervals are actual calling-thread measurements, never wall estimates.
//! The new source must be compiled and executed; retained binaries do not test it.
use serde_json::{json, Value};
use std::{
    fs,
    net::{SocketAddr, TcpListener},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Barrier, Mutex,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use trnm_crypto_primitives::pon_work;
use trnm_pon_node::{
    development_public,
    ingress::{
        self,
        public_v3::{self, PublicPolicy, PublicServer, Request},
        DevelopmentIdentity,
    },
    maintenance, sequence_root, Node, Packet, PoolLimits, Settings,
};
use trnm_protocol::pon_wire::{hash, Hash, Header};

const SEARCH_BUDGET: u64 = 4096;
const ATTACKS: usize = 8;
const PROBES: usize = 8;
const CALL_MS: u64 = 2000;

fn identity(n: u8) -> DevelopmentIdentity {
    DevelopmentIdentity::from_secret_hex(&hex::encode([n; 32])).unwrap()
}
fn ns(start: Instant) -> u64 {
    start.elapsed().as_nanos().try_into().unwrap()
}
// Match the existing receiver's checked Linux clock semantics without making a
// private receiver type public or adding a dependency. Missing clocks stay None.
struct ThreadCpuStamp {
    owner: thread::ThreadId,
    value: u64,
}
impl ThreadCpuStamp {
    fn start() -> Option<Self> {
        Some(Self {
            owner: thread::current().id(),
            value: thread_cpu_ns()?,
        })
    }
    fn finish(self) -> Option<u64> {
        if self.owner != thread::current().id() {
            return None;
        }
        thread_cpu_ns()?.checked_sub(self.value)
    }
}
fn cpu_elapsed(stamp: Option<ThreadCpuStamp>) -> Option<u64> {
    stamp.and_then(ThreadCpuStamp::finish)
}
fn checked_cpu_ns(seconds: i64, nanoseconds: i64) -> Option<u64> {
    let seconds = u64::try_from(seconds).ok()?;
    let nanoseconds = u64::try_from(nanoseconds).ok()?;
    if nanoseconds >= 1_000_000_000 {
        return None;
    }
    seconds.checked_mul(1_000_000_000)?.checked_add(nanoseconds)
}
#[cfg(target_os = "linux")]
fn thread_cpu_ns() -> Option<u64> {
    use rustix::time::{clock_gettime_dynamic, ClockId, DynamicClockId};
    let value = clock_gettime_dynamic(DynamicClockId::Known(ClockId::ThreadCPUTime)).ok()?;
    checked_cpu_ns(value.tv_sec, value.tv_nsec)
}
#[cfg(not(target_os = "linux"))]
fn thread_cpu_ns() -> Option<u64> {
    None
}
fn policy() -> PublicPolicy {
    PublicPolicy::new(8, Duration::from_secs(2)).unwrap()
}

struct Search {
    packet: Option<Packet>,
    observation: Value,
}

// Inputs are public context and task material, never a valid packet, product,
// producer, cached trace or verifier result. Even the claimed C is merely zero
// bytes. Every hash trial (including misses) remains in the returned observation.
fn search_from_zero(header: Header, a: &[u32], b: &[u32], budget: u64) -> Search {
    assert!(budget <= SEARCH_BUDGET);
    let total = Instant::now();
    let total_cpu = ThreadCpuStamp::start();
    let setup = Instant::now();
    let setup_cpu = ThreadCpuStamp::start();
    assert_eq!(pon_work::task_id(a, b).unwrap(), header.work_task);
    let mut proof = Vec::with_capacity(pon_work::PROOF_BYTES);
    proof.extend_from_slice(b"PNW1");
    for matrix in [a, b] {
        for value in matrix {
            proof.extend_from_slice(&value.to_le_bytes());
        }
    }
    proof.resize(pon_work::PROOF_BYTES, 0);
    let challenge = header.challenge();
    let setup_cpu_ns = cpu_elapsed(setup_cpu);
    let setup_ns = ns(setup);
    let mut attempts = Vec::new();
    let mut winner = None;
    let search = Instant::now();
    let search_cpu = ThreadCpuStamp::start();
    for nonce in 0..budget {
        let trace = hash(
            b"public-v3-from-zero-v1",
            &[&challenge, &nonce.to_le_bytes()],
        );
        let ticket = hash(b"ticket", &[&challenge, &trace]);
        let hit = header.target != [0; 32] && ticket <= header.target;
        attempts.push(json!({
            "nonce": nonce, "trace": hex::encode(trace),
            "ticket": hex::encode(ticket), "target_hit": hit,
        }));
        if hit {
            proof[pon_work::PROOF_BYTES - 32..].copy_from_slice(&trace);
            winner = Some(nonce);
            break;
        }
    }
    let search_cpu_ns = cpu_elapsed(search_cpu);
    let search_ns = ns(search);
    let header_hex = hex::encode(header.encode());
    let packet = winner.map(|_| Packet {
        header,
        transactions: vec![],
        proof,
    });
    let encoding = Instant::now();
    let encoding_cpu = ThreadCpuStamp::start();
    let packet_hex = packet.as_ref().map(|p| hex::encode(p.encode().unwrap()));
    let packet_encoding_cpu_ns = cpu_elapsed(encoding_cpu);
    let encoding_ns = ns(encoding);
    let attacker_cpu_ns = cpu_elapsed(total_cpu);
    let elapsed_ns = ns(total);
    let observation = json!({
        "header": header_hex, "challenge": hex::encode(challenge),
        "attempt_budget": budget, "attempts": attempts,
        "winner_nonce": winner, "packet": packet_hex,
        "status": if packet.is_some() { "target_hit_unverified" } else { "exhausted" },
        "setup_calls": 1, "setup_ns": setup_ns, "search_ns": search_ns,
        "packet_encoding_ns": encoding_ns, "total_wall_ns": elapsed_ns,
        "attacker_cpu_ns": attacker_cpu_ns,
        "setup_cpu_ns": setup_cpu_ns, "search_cpu_ns": search_cpu_ns,
        "packet_encoding_cpu_ns": packet_encoding_cpu_ns,
        "cpu_clock": "calling-thread CPU; missing or reversed intervals remain null",
        "phase_intervals_nested_in_total": true,
        "scope": "task validation, proof allocation, every trial with its record, header/packet encoding; excludes final observation object and report file serialization; no matrix evaluation or valid proof acquisition",
    });
    Search {
        packet,
        observation,
    }
}

fn genesis_header(settings: &Settings, target: Hash, nonce: u64, task: Hash) -> Header {
    Header {
        network: settings.network(),
        parameters: settings.parameters(),
        parent: settings.genesis(),
        height: 1,
        timestamp: settings.genesis_time() + 1,
        target,
        miner: development_public(0).unwrap(),
        transactions: sequence_root("transactions", &[]),
        // Deliberately untrusted commitments. These must not shortcut the W1
        // replay; the unchanged native admission checks execution after W1.
        state: [0; 32],
        receipts: [0; 32],
        work_task: task,
        nonce,
    }
}

#[derive(Clone)]
struct Client {
    address: SocketAddr,
    settings: Settings,
    epoch: Instant,
}
fn call_deadline(start: Instant, outer: Option<Instant>) -> Instant {
    let local = start + Duration::from_millis(CALL_MS);
    outer.map(|deadline| deadline.min(local)).unwrap_or(local)
}
impl Client {
    fn call(&self, lane: &str, who: u8, request: Request) -> Value {
        self.call_before(lane, who, request, None)
    }
    fn call_before(&self, lane: &str, who: u8, request: Request, outer: Option<Instant>) -> Value {
        let start = Instant::now();
        let deadline = call_deadline(start, outer);
        let client_cpu = ThreadCpuStamp::start();
        let started_ns: u64 = start
            .duration_since(self.epoch)
            .as_nanos()
            .try_into()
            .unwrap();
        let (reply, metrics) = public_v3::call_public_protected_v3_with_deadline(
            self.address,
            &request,
            &self.settings,
            identity(71).public_key(),
            &identity(who),
            policy(),
            Some(deadline),
        );
        let client_thread_cpu_ns = cpu_elapsed(client_cpu);
        let end = Instant::now();
        let ended_ns: u64 = end
            .duration_since(self.epoch)
            .as_nanos()
            .try_into()
            .unwrap();
        let elapsed_ns: u64 = end.duration_since(start).as_nanos().try_into().unwrap();
        let deadline_at_ns: u64 = deadline
            .duration_since(self.epoch)
            .as_nanos()
            .try_into()
            .unwrap();
        let outer_at_ns =
            outer.map(|value| u64::try_from(value.duration_since(self.epoch).as_nanos()).unwrap());
        let late = end > deadline;
        let (status, response, error) = match reply {
            Ok(reply) => (
                if reply.ok { "ok" } else { "refused" },
                Some(serde_json::to_value(reply).unwrap()),
                None,
            ),
            Err(error) => ("error", None, Some(error.to_string())),
        };
        json!({
            "lane": lane, "caller_fixture": who, "request": request,
            "started_ns": started_ns, "ended_ns": ended_ns,
            "elapsed_wall_ns": elapsed_ns, "deadline_ms": CALL_MS,
            "effective_deadline_at_ns": deadline_at_ns, "outer_deadline_at_ns": outer_at_ns,
            "client_thread_cpu_ns": client_thread_cpu_ns,
            "client_cpu_scope": "identity creation, negotiation, ticket search, request encoding, I/O and reply validation on this calling thread; excludes receiver and final diagnostic JSON",
            "returned_after_deadline": late,
            "status": status, "response": response, "error": error,
            // Retain the real transport challenge/search and failure metrics.
            "metrics": metrics,
        })
    }
}

// Local test ownership only. Assertions/unwind cannot leave the listener alive.
struct RunningService {
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<Value>>,
}
impl RunningService {
    fn finish(mut self) -> Value {
        self.stop.store(true, Ordering::Release);
        self.worker.take().unwrap().join().unwrap()
    }
}
impl Drop for RunningService {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn phase(
    number: u64,
    node: Node,
    producer: &mut Node,
    server: PublicServer,
    target: Hash,
    epoch: Instant,
) -> (Node, Value) {
    let complete_phase_start = Instant::now();
    let settings = node.settings().clone();
    let build_start = Instant::now();
    let preparation_cpu = ThreadCpuStamp::start();
    let (a, b) = maintenance();
    let task = pon_work::task_id(&a, &b).unwrap();
    let mut searches = Vec::new();
    for index in 0..ATTACKS {
        // Distinct fresh headers, not repeated accepted-block identities.
        let nonce = 10_000 + number * ATTACKS as u64 + index as u64;
        searches.push(search_from_zero(
            genesis_header(&settings, target, nonce, task),
            &a,
            &b,
            SEARCH_BUDGET,
        ));
    }
    let all_preparation_thread_cpu_ns = cpu_elapsed(preparation_cpu);
    let all_preparation_wall_ns = ns(build_start);
    // Construction above finishes before this phase generates any honest proof.
    let owner = Arc::new(Mutex::new(node));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let (shared, signal) = (owner.clone(), stop.clone());
    let worker = thread::spawn(move || {
        match public_v3::serve_public_protected_v3(
            listener,
            shared,
            Duration::from_secs(30),
            signal,
            server,
        ) {
            Ok(metrics) => json!({"metrics": metrics, "error": null}),
            Err(error) => json!({"metrics": null, "error": error.to_string()}),
        }
    });
    let service = RunningService {
        stop,
        worker: Some(worker),
    };
    let client = Client {
        address,
        settings: settings.clone(),
        epoch,
    };
    let barrier = Arc::new(Barrier::new(3));
    let (attack_client, attack_barrier) = (client.clone(), barrier.clone());
    let attack = thread::spawn(move || {
        let worker_cpu = ThreadCpuStamp::start();
        attack_barrier.wait();
        let mut records = Vec::new();
        for (index, search) in searches.into_iter().enumerate() {
            let submission_start = Instant::now();
            let wire = search.observation["packet"].as_str().map(str::to_owned);
            // Exhaustion remains None and never starts a submitted proof.
            let call = wire.map(|packet| {
                attack_client.call("from_zero", 100 + index as u8, Request::Submit { packet })
            });
            records.push(json!({"construction": search.observation, "call": call,
                "submission_total_wall_ns": ns(submission_start)}));
        }
        // This enclosing interval also charges request cloning, failures and
        // diagnostic construction between individual client-call intervals.
        let attacker_worker_cpu_ns = cpu_elapsed(worker_cpu);
        (records, attacker_worker_cpu_ns)
    });
    let (read_client, read_barrier) = (client.clone(), barrier.clone());
    let reads = thread::spawn(move || {
        read_barrier.wait();
        (0..PROBES)
            .map(|_| read_client.call("honest_read", 72, Request::Head))
            .collect::<Vec<_>>()
    });
    barrier.wait();
    let honest_start = Instant::now();
    let honest_cpu = ThreadCpuStamp::start();
    let honest = producer.mine(
        vec![],
        settings.genesis_time() + 2 + number,
        ingress::now().unwrap(),
    );
    // Node may use scoped workers. This clock measures only the coordinator;
    // it is not the honest producer's aggregate CPU or a fair attack ratio.
    let honest_build_coordinator_cpu_ns = cpu_elapsed(honest_cpu);
    let honest_build_wall_ns = ns(honest_start);
    let (honest_call, honest_build_error) = match honest {
        Ok(packet) => (
            Some(client.call(
                "honest_submit",
                73,
                Request::Submit {
                    packet: hex::encode(packet.encode().unwrap()),
                },
            )),
            None,
        ),
        Err(error) => (None, Some(error.to_string())),
    };
    let (attack_rows, attacker_worker_cpu_ns) = attack.join().unwrap();
    // Preparation finished before the worker was spawned: these intervals are
    // disjoint. Inner search/call clocks must not be added to this total again.
    let attacker_preparation_and_worker_cpu_ns = all_preparation_thread_cpu_ns
        .zip(attacker_worker_cpu_ns)
        .and_then(|(preparation, worker)| preparation.checked_add(worker));
    let read_rows = reads.join().unwrap();
    let service_outcome = service.finish();
    let node = Arc::try_unwrap(owner).ok().unwrap().into_inner().unwrap();
    let actual = node.read_active().unwrap();
    let expected = producer.read_active().unwrap();
    let state_equal = actual.0 == expected.0 && actual.2 == expected.2;
    let returned_on_time = |r: &Value| r["status"] == "ok" && r["returned_after_deadline"] == false;
    let read_successes = read_rows.iter().filter(|r| returned_on_time(r)).count();
    let no_attack_accepted = attack_rows
        .iter()
        .all(|r| r["call"].is_null() || r["call"]["status"] != "ok");
    let late_rejections = attack_rows
        .iter()
        .filter(|r| {
            r["call"]["status"] == "refused"
                && r["call"]["response"]["value"]["error"] == "WORK:Transcript"
        })
        .count() as u64;
    let metrics = &service_outcome["metrics"];
    // These are measurements from the existing one shared service domain, not
    // estimated operation counts or invented zero measurements on clock failure.
    let cpu_known = metrics["mutation_cpu_clock_failures"] == 0
        && metrics["mutation_full_work_cpu_ns"]
            .as_u64()
            .is_some_and(|n| n > 0)
        && metrics["mutation_cpu_charged_ns"]
            .as_u64()
            .zip(metrics["mutation_full_work_cpu_ns"].as_u64())
            .is_some_and(|(all, work)| all >= work);
    let work_complete = metrics["work_started"]
        .as_u64()
        .is_some_and(|n| n > late_rejections)
        && metrics["work_failed"]
            .as_u64()
            .is_some_and(|n| n >= late_rejections)
        && metrics["work_finished"] == metrics["work_started"];
    let constructed_hits = attack_rows
        .iter()
        .filter(|row| row["construction"]["status"] == "target_hit_unverified")
        .count();
    let exhausted_searches = attack_rows
        .iter()
        .filter(|row| row["construction"]["status"] == "exhausted")
        .count();
    let submitted_attacks = attack_rows
        .iter()
        .filter(|row| !row["call"].is_null())
        .count();
    let construction_cpu_known = attacker_preparation_and_worker_cpu_ns.is_some()
        && attack_rows.iter().all(|row| {
            row["construction"]["attacker_cpu_ns"].as_u64().is_some()
                && (row["call"].is_null() || row["call"]["client_thread_cpu_ns"].as_u64().is_some())
        });
    let client_cpu_known = read_rows
        .iter()
        .all(|row| row["client_thread_cpu_ns"].as_u64().is_some())
        && honest_call
            .as_ref()
            .is_some_and(|row| row["client_thread_cpu_ns"].as_u64().is_some());
    let complete_denominators = attack_rows.len() == ATTACKS
        && constructed_hits + exhausted_searches == ATTACKS
        && submitted_attacks == constructed_hits
        && read_rows.len() == PROBES;
    let passed = service_outcome["error"].is_null()
        && no_attack_accepted
        && late_rejections > 0
        && read_successes == PROBES
        && complete_denominators
        && construction_cpu_known
        && client_cpu_known
        && honest_call.as_ref().is_some_and(returned_on_time)
        && state_equal
        && cpu_known
        && work_complete;
    (
        node,
        json!({
            "phase": number, "construction_count": ATTACKS,
            "complete_phase_wall_ns": ns(complete_phase_start),
            "all_preparation_wall_ns": all_preparation_wall_ns,
            "all_preparation_thread_cpu_ns": all_preparation_thread_cpu_ns,
            "attacker_worker_cpu_ns": attacker_worker_cpu_ns,
            "attacker_preparation_and_worker_cpu_ns": attacker_preparation_and_worker_cpu_ns,
            "attacker_total_scope": "two disjoint preparation/worker intervals; includes inner trial/call diagnostics; excludes parent thread spawn/join, public context acquisition and final report file output",
            "constructed_hits": constructed_hits, "exhausted_searches": exhausted_searches,
            "submitted_attacks": submitted_attacks, "complete_denominators": complete_denominators,
            "attacker_and_client_cpu_known": construction_cpu_known && client_cpu_known,
            "all_preparation_cpu_includes_construction_subintervals": true,
            "from_zero": attack_rows, "honest_reads": read_rows,
            "honest_submit": honest_call, "honest_build_error": honest_build_error,
            "honest_build_wall_ns": honest_build_wall_ns,
            "honest_build_coordinator_cpu_ns": honest_build_coordinator_cpu_ns,
            "honest_build_aggregate_cpu_ns": null,
            "honest_worker_cpu_measured_by_this_clock": false,
            "honest_producer_scope": "unchanged default native producer; not claimed cheapest",
            "late_transcript_rejections": late_rejections, "honest_read_successes": read_successes,
            "no_attack_accepted": no_attack_accepted, "cpu_measurements_known": cpu_known,
            "all_started_work_finished": work_complete, "full_native_state_equal": state_equal,
            "service": service_outcome, "finite_target_met": passed,
        }),
    )
}

#[test]
fn from_zero_service_shares_cpu_with_honest_work_and_reopened_owner() {
    let temporary = tempfile::tempdir().unwrap();
    let output = std::env::var_os("TRNM_PUBLIC_V3_FROM_ZERO_DIR")
        .map(std::path::PathBuf::from)
        .or_else(|| {
            // The full workspace lane does not use the standalone driver.
            // Keep its actual failure reports inside the existing upload root,
            // rather than deleting them with a temporary directory on unwind.
            std::env::var_os("TRNM_CI_RECEIPT_DIR")
                .map(|root| std::path::PathBuf::from(root).join("public-v3-from-zero-suite"))
        });
    let path = if let Some(path) = output {
        fs::create_dir(&path).unwrap(); // Never overwrite an earlier observation.
        path
    } else {
        temporary.path().to_path_buf()
    };
    let settings = Settings::development(Some(ingress::now().unwrap() - 100)).unwrap();
    let receiver = path.join("receiver");
    let mut node = Node::open(&receiver, settings.clone(), 2).unwrap();
    node.enable_local_mempool(PoolLimits {
        max_records: 16,
        max_bytes: 32768,
        max_group_members: 4,
        critical_reserve: 0,
        max_removals: 64,
        preview_miner: development_public(0).unwrap(),
    })
    .unwrap();
    let context_start = Instant::now();
    let target = node.expected_target(settings.genesis()).unwrap();
    let public_context_read_wall_ns = ns(context_start);
    let mut producer = Node::open(&path.join("producer"), settings.clone(), 2).unwrap();
    let server = PublicServer::new(identity(71), policy()).unwrap();
    let domain = server.mutation_cpu_domain();
    let epoch = Instant::now();
    let (node, first) = phase(0, node, &mut producer, server, target, epoch);
    let before = node.read_active().unwrap();
    drop(node);
    let reopen_start = Instant::now();
    let reopened = Node::open(&receiver, settings.clone(), 2).unwrap();
    let after = reopened.read_active().unwrap();
    let reopen_wall_ns = ns(reopen_start);
    let reopen_equal = before == after;
    // Crucially retain the exact CPU domain, rather than mint a fresh service
    // burst on the owner reopen. This is still same-process, not a power cut.
    let server = PublicServer::with_continuous_domain(identity(71), policy(), &domain).unwrap();
    let (node, second) = phase(1, reopened, &mut producer, server, target, epoch);
    let passed =
        reopen_equal && first["finite_target_met"] == true && second["finite_target_met"] == true;
    let report = json!({
        "schema": "public-v3-local-from-zero-service-v2", "network": hex::encode(settings.network()),
        "parameters": hex::encode(settings.parameters()), "genesis": hex::encode(settings.genesis()),
        "target": hex::encode(target), "policy_id": hex::encode(policy().id()),
        "public_context_read_wall_ns": public_context_read_wall_ns,
        "phases": [first, second], "reopen_wall_ns": reopen_wall_ns, "reopen_state_equal": reopen_equal,
        "cpu_domain_retained_across_owner_reopen": true,
        "scope": "finite local TCP; from-zero preparation and calling-thread client CPU, with real shared receiver CPU; zero claimed C; default honest producer; same-process owner reopen; no aggregate honest CPU or global speedup/energy ratio",
        "budget_depletion_demonstrated": false,
        "all_requested_reads_required_on_time": true,
        "public_network_ready": false, "independent_accepted": false,
        "work_profile_qualified": false, "resource_fairness_qualified": false,
        "physical_power_loss": false, "production_activation": false, "finite_target_met": passed,
    });
    fs::write(
        path.join("report.json"),
        serde_json::to_vec_pretty(&report).unwrap(),
    )
    .unwrap();
    drop(node);
    drop(producer);
    println!(
        "{}",
        json!({"schema": report["schema"], "finite_target_met": passed, "public_network_ready": false})
    );
    assert!(
        passed,
        "see retained from-zero trials, request failures and service CPU observations"
    );
    sustained_observation(&path);
}

#[test]
fn from_zero_search_preserves_misses_exhaustion_and_full_replay_rejection() {
    let (a, b) = maintenance();
    let task = pon_work::task_id(&a, &b).unwrap();
    let mut target = [255; 32];
    target[0] = 7;
    // A fixed wire fixture, not a development ledger or a mined parent.
    let header = Header {
        network: [1; 32],
        parameters: [2; 32],
        parent: [3; 32],
        height: 1,
        timestamp: 1_750_000_001,
        target,
        miner: [4; 32],
        transactions: sequence_root("transactions", &[]),
        state: [0; 32],
        receipts: [0; 32],
        work_task: task,
        nonce: 10_000,
    };
    let found = search_from_zero(header.clone(), &a, &b, SEARCH_BUDGET);
    let packet = found
        .packet
        .as_ref()
        .expect("this fixed bounded fixture must hit");
    let trials = found.observation["attempts"].as_array().unwrap();
    // Cross-language fixed bytes; generated by the separate Python scalar reader.
    assert_eq!(
        hex::encode(header.challenge()),
        "dfb0f6857b75ffec4d4260e2cc7a6585684bf7e9a977678b4c49fe067c2b5f9a"
    );
    assert_eq!(trials.len(), 22);
    assert_eq!(
        hex::encode(hash(b"from-zero-fixture", &[&packet.encode().unwrap()])),
        "27ef60d9135b2d228d533fa8f28c473b36e1758433d0638e83bc60e1bba2cbe0"
    );
    for (index, row) in trials.iter().enumerate() {
        assert_eq!(row["nonce"], index as u64);
        assert_eq!(row["target_hit"], index + 1 == trials.len());
    }
    assert_eq!(found.observation["winner_nonce"], (trials.len() - 1) as u64);
    let mut tiles = 0;
    let mut products = 0;
    let mut capabilities = 0;
    let error = pon_work::verify_reference_with_progress(
        header.challenge(),
        task,
        target,
        &packet.proof,
        &mut |point| {
            match point {
                pon_work::VerificationProgress::TranscriptTile { .. } => tiles += 1,
                pon_work::VerificationProgress::BeforeProduct => products += 1,
                pon_work::VerificationProgress::BeforeVerifiedWork => capabilities += 1,
                _ => {}
            }
            Ok::<(), ()>(())
        },
    )
    .unwrap_err();
    assert_eq!(
        error,
        pon_work::VerificationError::Relation(pon_work::WorkError::Transcript)
    );
    assert_eq!(tiles, 512);
    assert_eq!((products, capabilities), (0, 0));
    assert_eq!(
        pon_work::verify(header.challenge(), task, target, &packet.proof).unwrap_err(),
        pon_work::WorkError::Transcript
    );
    assert_eq!(
        pon_work::verify_limb(header.challenge(), task, target, &packet.proof).unwrap_err(),
        pon_work::WorkError::Transcript
    );
    // Nonzero target: genuine bounded misses, not the zero-target admission filter.
    let mut hard = header.clone();
    hard.target = [0; 32];
    hard.target[31] = 1;
    let exhausted = search_from_zero(hard, &a, &b, 64);
    assert!(exhausted.packet.is_none());
    assert_eq!(exhausted.observation["status"], "exhausted");
    assert_eq!(
        exhausted.observation["attempts"].as_array().unwrap().len(),
        64
    );
    assert!(exhausted.observation["winner_nonce"].is_null());
    assert!(exhausted.observation["packet"].is_null());
    let no_budget = search_from_zero(header, &a, &b, 0);
    assert!(no_budget.packet.is_none());
    assert_eq!(no_budget.observation["attempts"], json!([]));
    assert_eq!(no_budget.observation["setup_calls"], 1);
}

#[test]
fn caller_cpu_clock_keeps_missing_overflow_and_wrong_owner_distinct() {
    // Expiry is exercised through the actual client, not a timer-only mock.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let epoch = Instant::now();
    let client = Client {
        address: listener.local_addr().unwrap(),
        settings: Settings::development(Some(1_750_000_000)).unwrap(),
        epoch,
    };
    let start = Instant::now();
    assert_eq!(
        call_deadline(start, None),
        start + Duration::from_millis(CALL_MS)
    );
    assert_eq!(call_deadline(start, Some(start)), start);
    assert_eq!(call_deadline(start, Some(epoch)), epoch);
    assert_eq!(
        call_deadline(start, Some(start + Duration::from_secs(4))),
        start + Duration::from_millis(CALL_MS)
    );
    let row = client.call_before("expired_pressure", 72, Request::Head, Some(epoch));
    assert_eq!(row["status"], "error");
    assert_eq!(row["error"], "PUBLIC_CLIENT_DEADLINE");
    assert_eq!(row["effective_deadline_at_ns"], 0);
    assert_eq!(row["metrics"]["solution_trials"], 0);
    assert_eq!(row["metrics"]["failed_stage"], "construction");
    assert!(
        matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
    );
    assert_eq!(checked_cpu_ns(0, 0), Some(0));
    assert_eq!(checked_cpu_ns(1, 999_999_999), Some(1_999_999_999));
    assert_eq!(checked_cpu_ns(-1, 0), None);
    assert_eq!(checked_cpu_ns(0, -1), None);
    assert_eq!(checked_cpu_ns(0, 1_000_000_000), None);
    assert_eq!(checked_cpu_ns(i64::MAX, 0), None);
    assert_eq!(cpu_elapsed(None), None);
    let wrong_owner = ThreadCpuStamp {
        owner: thread::current().id(),
        value: 0,
    };
    assert_eq!(
        thread::spawn(move || wrong_owner.finish()).join().unwrap(),
        None
    );
    #[cfg(target_os = "linux")]
    {
        let actual = ThreadCpuStamp::start().expect("Linux thread CPU clock required");
        let mut bytes = [1u8; 32];
        for _ in 0..128 {
            bytes = hash(b"test-thread-cpu", &[std::hint::black_box(&bytes)]);
        }
        std::hint::black_box(bytes);
        assert!(actual.finish().is_some_and(|value| value > 0));
        let reversed = ThreadCpuStamp {
            owner: thread::current().id(),
            value: u64::MAX,
        };
        assert_eq!(reversed.finish(), None);
    }
}

// Additional mandatory observation in the existing exact-named service test.
// Original finite v2 report and all its assertions remain unchanged.
const PRESSURE_MS: u64 = 4_000;
const PRESSURE_WORKERS: usize = 16;
const PRESSURE_CALLS_PER_WORKER: usize = 1_024;

fn compact_pressure_call(mut row: Value, packet_index: Option<usize>) -> Value {
    // Full immutable packets are retained once in the construction table. Do
    // not retain another 98-KiB hex string for every retransmitted false proof.
    let request = row.as_object_mut().unwrap().remove("request").unwrap();
    let bytes = serde_json::to_vec(&request).unwrap();
    row["recorded_request_digest"] = json!(hex::encode(hash(
        b"pressure-recorded-request-v1",
        &[&bytes]
    )));
    row["recorded_request_bytes"] = json!(bytes.len());
    row["packet_index"] = json!(packet_index);
    row
}

fn sustained_phase(
    number: u64,
    node: Node,
    producer: &mut Node,
    server: PublicServer,
    epoch: Instant,
) -> (Node, Value) {
    let settings = node.settings().clone();
    let target = node.expected_target(settings.genesis()).unwrap();
    let domain = server.mutation_cpu_domain();
    let initial_budget = domain.observe().unwrap();
    let (a, b) = maintenance();
    let task = pon_work::task_id(&a, &b).unwrap();
    let prep_wall = Instant::now();
    let prep_cpu = ThreadCpuStamp::start();
    let searches: Vec<_> = (0..16)
        .map(|i| {
            search_from_zero(
                genesis_header(&settings, target, 50_000 + number * 16 + i, task),
                &a,
                &b,
                SEARCH_BUDGET,
            )
        })
        .collect();
    let preparation_cpu_ns = cpu_elapsed(prep_cpu);
    let preparation_wall_ns = ns(prep_wall);
    let construction: Vec<_> = searches.iter().map(|s| s.observation.clone()).collect();
    let packets: Arc<Vec<Option<String>>> = Arc::new(
        searches
            .iter()
            .map(|s| s.observation["packet"].as_str().map(str::to_owned))
            .collect(),
    );
    // Diagnostic verifications are not attacker preparation and precede the
    // service window. A valid proof was never acquired to build these inputs.
    let diagnostic_start = Instant::now();
    for search in &searches {
        if let Some(packet) = &search.packet {
            for verify in [
                pon_work::verify,
                pon_work::verify_reference,
                pon_work::verify_limb,
            ] {
                assert_eq!(
                    verify(packet.header.challenge(), task, target, &packet.proof).unwrap_err(),
                    pon_work::WorkError::Transcript
                );
            }
        }
    }
    let diagnostic_wall_ns = ns(diagnostic_start);
    let build_start = Instant::now();
    let build_cpu = ThreadCpuStamp::start();
    let honest_packet = producer
        .mine(
            vec![],
            settings.genesis_time() + 10 * (number + 1),
            ingress::now().unwrap(),
        )
        .unwrap();
    let honest_build_calling_thread_cpu_ns = cpu_elapsed(build_cpu);
    let honest_build_wall_ns = ns(build_start);
    let honest_wire = hex::encode(honest_packet.encode().unwrap());
    let expected_id = honest_packet.id().unwrap();

    let owner = Arc::new(Mutex::new(node));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let metrics = Arc::new(Mutex::new(public_v3::PublicMetrics::default()));
    let observer = public_v3::PublicRequestObserver::new(16_384).unwrap();
    let (shared, signal, metric_owner, capture) = (
        owner.clone(),
        stop.clone(),
        metrics.clone(),
        observer.clone(),
    );
    let service = RunningService {
        stop,
        worker: Some(thread::spawn(move || {
            match public_v3::serve_public_protected_v3_with_request_observer(
                listener,
                shared,
                Duration::from_secs(30),
                signal,
                server,
                metric_owner,
                capture,
            ) {
                Ok(metrics) => json!({"metrics": metrics, "error": null}),
                Err(error) => json!({"metrics": null, "error": error.to_string()}),
            }
        })),
    };
    let client = Client {
        address,
        settings: settings.clone(),
        epoch,
    };
    let barrier = Arc::new(Barrier::new(PRESSURE_WORKERS + 2));
    // One common attacker window, passed into every actual TCP call. Honest
    // probes retain their original two-second SLO and are reported separately;
    // joined cleanup is not credited as additional offered attack time.
    let window_start = Instant::now();
    let window_end = window_start + Duration::from_millis(PRESSURE_MS);
    let mut attacks = Vec::new();
    for worker in 0..PRESSURE_WORKERS {
        let (client, barrier, packets) = (client.clone(), barrier.clone(), packets.clone());
        attacks.push(thread::spawn(move || {
            barrier.wait();
            let cpu = ThreadCpuStamp::start();
            let started_ns = ns(epoch);
            let mut rows = Vec::new();
            for attempt in 0..PRESSURE_CALLS_PER_WORKER {
                if Instant::now() >= window_end {
                    break;
                }
                let index = (attempt * PRESSURE_WORKERS + worker) % packets.len();
                if let Some(packet) = &packets[index] {
                    let who = 80 + ((attempt + worker * 37) % 150) as u8;
                    let call = client.call_before(
                        "sustained_from_zero",
                        who,
                        Request::Submit {
                            packet: packet.clone(),
                        },
                        Some(window_end),
                    );
                    rows.push(compact_pressure_call(call, Some(index)));
                } else {
                    rows.push(json!({"status": "not_submitted_exhausted", "packet_index": index}));
                }
            }
            let cpu_ns = cpu_elapsed(cpu);
            json!({"worker": worker, "started_ns": started_ns, "ended_ns": ns(epoch),
                "calling_thread_cpu_ns": cpu_ns, "attempt_cap": PRESSURE_CALLS_PER_WORKER,
                "attempt_cap_reached": rows.len() == PRESSURE_CALLS_PER_WORKER,
                "calls": rows})
        }));
    }
    let (read_client, read_barrier) = (client.clone(), barrier.clone());
    let reads = thread::spawn(move || {
        read_barrier.wait();
        let cpu = ThreadCpuStamp::start();
        let mut rows = Vec::new();
        while Instant::now() < window_end && rows.len() < 256 {
            rows.push(compact_pressure_call(
                read_client.call("sustained_honest_read", 72, Request::Head),
                None,
            ));
            thread::sleep(
                Duration::from_millis(40).min(window_end.saturating_duration_since(Instant::now())),
            );
        }
        (rows, cpu_elapsed(cpu))
    });
    barrier.wait();
    let mut submissions = Vec::new();
    let mut budget_samples = Vec::new();
    // Retain every refusal of the SAME real packet. Once acknowledged, no
    // duplicate acknowledgement is counted as another successful native block.
    while Instant::now() < window_end && budget_samples.len() < 256 {
        budget_samples
            .push(json!({"elapsed_ns": ns(window_start), "meter": domain.observe().unwrap()}));
        if submissions.len() < 16 && !submissions.iter().any(|r: &Value| r["status"] == "ok") {
            submissions.push(compact_pressure_call(
                client.call(
                    "sustained_honest_submit",
                    73,
                    Request::Submit {
                        packet: honest_wire.clone(),
                    },
                ),
                None,
            ));
        }
        thread::sleep(
            Duration::from_millis(40).min(window_end.saturating_duration_since(Instant::now())),
        );
    }
    let attack_rows: Vec<_> = attacks.into_iter().map(|h| h.join().unwrap()).collect();
    let (read_rows, reader_cpu_ns) = reads.join().unwrap();
    let traffic_wall_ns = ns(window_start);
    let budget_at_traffic_end = domain.observe().unwrap();
    let after_pressure = client.call("post_pressure_head", 72, Request::Head);
    let service_outcome = service.finish();
    let captured = observer.snapshot();
    let node = Arc::try_unwrap(owner).ok().unwrap().into_inner().unwrap();
    let actual = node.read_active().unwrap();
    let expected = producer.read_active().unwrap();
    let no_attack_accepted = attack_rows.iter().all(|w| {
        w["calls"]
            .as_array()
            .unwrap()
            .iter()
            .all(|r| r["status"] != "ok")
    });
    let reads_on_time = read_rows
        .iter()
        .filter(|r| r["status"] == "ok" && r["returned_after_deadline"] == false)
        .count();
    let honest_admitted =
        actual.0 == expected_id && actual.0 == expected.0 && actual.2 == expected.2;
    let honest_ack_on_time = submissions
        .iter()
        .any(|r| r["status"] == "ok" && r["returned_after_deadline"] == false);
    let observations_complete = captured.records_not_retained == 0
        && captured.measurement_failures == 0
        && !captured.counter_overflow
        && captured.records.iter().all(|r| r.complete);
    let m = &service_outcome["metrics"];
    let charged = m["mutation_cpu_charged_ns"].as_u64();
    let work = m["mutation_full_work_cpu_ns"].as_u64();
    let rest = m["mutation_dispatch_excluding_work_cpu_ns"].as_u64();
    let accounting_closed = charged
        .zip(work.zip(rest))
        .is_some_and(|(all, (w, r))| w.checked_add(r) == Some(all))
        && m["mutation_cpu_clock_failures"] == 0
        && m["mutation_cpu_in_flight_after_shutdown"] == 0
        && m["mutation_cpu_unavailable_after_shutdown"] == false
        && m["work_started"] == m["work_finished"];
    let below_start_reserve_observed = budget_samples.iter().any(|r| {
        r["meter"]["stored_credit_ns"]
            .as_i64()
            .is_some_and(|v| v < 100_000_000)
    });
    let observed_debt = budget_samples.iter().any(|r| {
        r["meter"]["stored_credit_ns"]
            .as_i64()
            .is_some_and(|v| v < 0)
    });
    let mutation_cpu_refusals = m["mutation_cpu_refusals"].as_u64().unwrap_or(0);
    // Raw credit includes outstanding start reservations, and reserve refusals
    // can mean occupied workers. Neither is a causal public-depletion witness.
    let budget_pressure_observed =
        below_start_reserve_observed || observed_debt || mutation_cpu_refusals > 0;
    let attack_cpu = attack_rows.iter().try_fold(0u64, |n, r| {
        n.checked_add(r["calling_thread_cpu_ns"].as_u64()?)
    });
    let attacker_cpu_ns = preparation_cpu_ns
        .zip(attack_cpu)
        .and_then(|(p, w)| p.checked_add(w));
    let caps_not_reached = attack_rows
        .iter()
        .all(|r| r["attempt_cap_reached"] == false);
    let service_target_met = !read_rows.is_empty()
        && reads_on_time == read_rows.len()
        && honest_ack_on_time
        && honest_admitted
        && after_pressure["status"] == "ok";
    let invariant_target_met = no_attack_accepted
        && observations_complete
        && accounting_closed
        && attacker_cpu_ns.is_some()
        && service_outcome["error"].is_null();
    let mut observation = json!({
        "phase": number, "target": hex::encode(target), "initial_meter": initial_budget,
        "construction": construction, "preparation_cpu_ns": preparation_cpu_ns,
        "preparation_wall_ns": preparation_wall_ns, "diagnostic_verification_wall_ns": diagnostic_wall_ns,
        "honest_packet": hex::encode(honest_packet.encode().unwrap()),
        "honest_build_wall_ns": honest_build_wall_ns,
        "honest_build_calling_thread_cpu_ns": honest_build_calling_thread_cpu_ns,
        "honest_build_aggregate_cpu_ns": null,
        "requested_window_ns": PRESSURE_MS * 1_000_000, "traffic_and_join_wall_ns": traffic_wall_ns,
        "attacks": attack_rows, "attacker_preparation_plus_workers_cpu_ns": attacker_cpu_ns,
        "attacker_cpu_scope": "disjoint preparation plus joined client threads; excludes parent setup/join, diagnostic verifiers, server, energy and final report encoding",
        "honest_reads": read_rows, "reader_cpu_ns": reader_cpu_ns, "reads_on_time": reads_on_time,
        "honest_submissions": submissions, "post_pressure_head": after_pressure,
        "meter_samples": budget_samples, "meter_at_traffic_end": budget_at_traffic_end,
        "stored_credit_below_start_reserve_observed": below_start_reserve_observed,
        "negative_stored_credit_observed": observed_debt,
        "mutation_cpu_refusals": mutation_cpu_refusals,
        "budget_pressure_observed": budget_pressure_observed,
        "attempt_caps_not_reached": caps_not_reached, "observations": captured,
        "service": service_outcome, "no_attack_accepted": no_attack_accepted,
        "accounting_closed": accounting_closed, "full_native_state_equal": honest_admitted,
        "service_target_met": service_target_met, "invariant_target_met": invariant_target_met,
        "client_confirmed_transactions": null, "strongest_honest_producer_used": false,
        "public_network_ready": false, "resource_fairness_qualified": false,
        "work_profile_qualified": false, "production_activation": false,
    });
    observation["window_started_ns"] =
        json!(u64::try_from(window_start.duration_since(epoch).as_nanos()).unwrap());
    observation["window_ended_ns"] =
        json!(u64::try_from(window_end.duration_since(epoch).as_nanos()).unwrap());
    (node, observation)
}

fn sustained_observation(path: &std::path::Path) {
    let path = path.join("sustained");
    fs::create_dir(&path).unwrap();
    // Fixed material context is identical on both architectures. Concurrency,
    // attempted counts, outcomes and timing remain observations, not equal streams.
    let settings = Settings::development(Some(1_750_000_000)).unwrap();
    let receiver = path.join("receiver");
    let mut node = Node::open(&receiver, settings.clone(), 1).unwrap();
    node.enable_local_mempool(PoolLimits {
        max_records: 16,
        max_bytes: 32768,
        max_group_members: 4,
        critical_reserve: 0,
        max_removals: 64,
        preview_miner: development_public(0).unwrap(),
    })
    .unwrap();
    let mut producer = Node::open(&path.join("producer"), settings.clone(), 1).unwrap();
    let server = PublicServer::new(identity(71), policy()).unwrap();
    let domain = server.mutation_cpu_domain();
    let epoch = Instant::now();
    let (node, first) = sustained_phase(0, node, &mut producer, server, epoch);
    let before = node.read_active().unwrap();
    let meter_before = domain.observe().unwrap();
    drop(node);
    let reopen_start = Instant::now();
    let node = Node::open(&receiver, settings.clone(), 1).unwrap();
    let reopen_equal = before == node.read_active().unwrap();
    let server = PublicServer::with_continuous_domain(identity(71), policy(), &domain).unwrap();
    let meter_after = server.mutation_cpu_domain().observe().unwrap();
    let same_meter =
        meter_before == meter_after && domain.shares_domain_with(&server.mutation_cpu_domain());
    let reopen_wall_ns = ns(reopen_start);
    let (node, second) = sustained_phase(1, node, &mut producer, server, epoch);
    let passed = reopen_equal
        && same_meter
        && first["invariant_target_met"] == true
        && second["invariant_target_met"] == true
        && first["service_target_met"] == true
        && second["service_target_met"] == true
        && first["attempt_caps_not_reached"] == true
        && second["attempt_caps_not_reached"] == true;
    let report = json!({"schema": "public-v3-sustained-local-from-zero-v2",
        "network": hex::encode(settings.network()), "parameters": hex::encode(settings.parameters()),
        "genesis": hex::encode(settings.genesis()), "policy_id": hex::encode(policy().id()),
        "phases": [first, second], "reopen_state_equal": reopen_equal,
        "same_stored_cpu_meter_across_reopen": same_meter,
        "meter_before_reopen": meter_before, "meter_after_reopen": meter_after,
        "reopen_wall_ns": reopen_wall_ns,
        "budget_pressure_observed": first["budget_pressure_observed"] == true
            || second["budget_pressure_observed"] == true,
        "budget_depletion_demonstrated": false,
        "finite_service_target_met": passed, "independent_accepted": false,
        "physical_power_loss": false, "ordinary_hepta_entry": false,
        "public_network_ready": false, "resource_fairness_qualified": false,
        "work_profile_qualified": false, "production_activation": false});
    fs::write(
        path.join("report.json"),
        serde_json::to_vec_pretty(&report).unwrap(),
    )
    .unwrap();
    drop(node);
    drop(producer);
    println!(
        "{}",
        json!({"schema": report["schema"], "finite_service_target_met": passed,
            "report_path": path.join("report.json"),
            "phases": report["phases"].as_array().unwrap().iter().map(|phase| json!({
                "phase": phase["phase"], "service_target_met": phase["service_target_met"],
                "invariant_target_met": phase["invariant_target_met"],
                "accounting_closed": phase["accounting_closed"],
                "full_native_state_equal": phase["full_native_state_equal"],
                "reads_on_time": phase["reads_on_time"],
                "requested_reads": phase["honest_reads"].as_array().unwrap().len(),
                "measurement_failures": phase["observations"]["measurement_failures"],
                "records_not_retained": phase["observations"]["records_not_retained"]
            })).collect::<Vec<_>>()})
    );
    assert!(
        passed,
        "see sustained/report.json; failed attempts and non-depletion are retained"
    );
}
