//! Finite local from-zero W1 traffic on the existing public service CPU domain.
//! No WAN, cheapest-producer, saturation, energy or production qualification.
#[path = "support/w1_resource_cost.rs"]
mod resource_cost;
use resource_cost::{Roster, Span};
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
use trnm_mvcc_fee::continuity_v1;
use trnm_pon_node::{
    development_public,
    ingress::{
        self,
        public_v3::{
            self, PublicMetrics, PublicPolicy, PublicRequestObserver, PublicServer, Request,
        },
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
    let cpu_total = Span::start();
    let setup = Instant::now();
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
    let setup_ns = ns(setup);
    let mut attempts = Vec::new();
    let mut winner = None;
    let search = Instant::now();
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
    let search_ns = ns(search);
    let header_hex = hex::encode(header.encode());
    let packet = winner.map(|_| Packet {
        header,
        transactions: vec![],
        proof,
    });
    let encoding = Instant::now();
    let packet_hex = packet.as_ref().map(|p| hex::encode(p.encode().unwrap()));
    let encoding_ns = ns(encoding);
    let elapsed_ns = ns(total);
    let preparation_resources = cpu_total.finish();
    let observation = json!({
        "header": header_hex, "challenge": hex::encode(challenge),
        "attempt_budget": budget, "attempts": attempts,
        "winner_nonce": winner, "packet": packet_hex,
        "status": if packet.is_some() { "target_hit_unverified" } else { "exhausted" },
        "setup_calls": 1, "setup_ns": setup_ns, "search_ns": search_ns,
        "packet_encoding_ns": encoding_ns, "total_wall_ns": elapsed_ns,
        "attacker_cpu_ns": preparation_resources["thread_cpu_ns"],
        "preparation_resources": preparation_resources,
        "scope": "includes validation, allocation, every hash trial and packet encoding; thread CPU is measured separately; no matrix evaluation or proof acquisition",
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
impl Client {
    fn call(&self, lane: &str, who: u8, request: Request) -> Value {
        let start = Instant::now();
        let call_resources = Span::start();
        let started_ns = ns(self.epoch);
        let (reply, metrics) = public_v3::call_public_protected_v3_with_deadline(
            self.address,
            &request,
            &self.settings,
            identity(71).public_key(),
            &identity(who),
            policy(),
            Some(start + Duration::from_millis(CALL_MS)),
        );
        let ended_ns = ns(self.epoch);
        let elapsed_ns = ns(start);
        let late = elapsed_ns > CALL_MS * 1_000_000;
        let (status, response, error) = match reply {
            Ok(reply) => (
                if reply.ok { "ok" } else { "refused" },
                Some(serde_json::to_value(reply).unwrap()),
                None,
            ),
            Err(error) => ("error", None, Some(error.to_string())),
        };
        let resources = call_resources.finish();
        json!({
            "call_resources": resources,
            "lane": lane, "caller_fixture": who, "request": request,
            "started_ns": started_ns, "ended_ns": ended_ns,
            "elapsed_wall_ns": elapsed_ns, "deadline_ms": CALL_MS,
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
    let preparation_span = Span::start();
    let (_, _, a, b) = settings.consensus_maintenance_material().unwrap();
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
    let all_preparation_wall_ns = ns(build_start);
    let all_preparation_resources = preparation_span.finish();
    // Construction above finishes before this phase generates any honest proof.
    let owner = Arc::new(Mutex::new(node));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let (shared, signal) = (owner.clone(), stop.clone());
    let observer = PublicRequestObserver::new(64).unwrap();
    let capture = observer.clone();
    let worker = thread::spawn(move || {
        match public_v3::serve_public_protected_v3_with_request_observer(
            listener,
            shared,
            Duration::from_secs(30),
            signal,
            server,
            Arc::new(Mutex::new(PublicMetrics::default())),
            capture,
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
        attack_barrier.wait();
        let actor_span = Span::start();
        let mut records = Vec::new();
        for (index, search) in searches.into_iter().enumerate() {
            let submission_start = Instant::now();
            let wire = search.observation["packet"].as_str().map(str::to_owned);
            let call = if let Some(packet) = wire {
                Some(attack_client.call("from_zero", 100 + index as u8, Request::Submit { packet }))
            } else {
                None // Exhaustion is retained, never converted into a submitted proof.
            };
            records.push(json!({"construction": search.observation, "call": call,
                "submission_total_wall_ns": ns(submission_start)}));
        }
        (records, actor_span.finish())
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
    let honest_build_span = Span::start();
    let honest = producer
        .make_consensus_maintenance(
            producer.active().unwrap().0,
            vec![],
            development_public(0).unwrap(),
            settings.genesis_time() + 2 + number,
            SEARCH_BUDGET,
        )
        .and_then(|packet| {
            let id = producer.admit(&packet, ingress::now()?)?;
            producer.activate(id)?;
            Ok(packet)
        });
    let honest_build_wall_ns = ns(honest_start);
    let honest_build_resources = honest_build_span.finish();
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
    let (attack_rows, attack_actor_resources) = attack.join().unwrap();
    let read_rows = reads.join().unwrap();
    let service_outcome = service.finish();
    let request_snapshot = observer.snapshot();
    let requests_complete = request_snapshot.records_not_retained == 0
        && request_snapshot.measurement_failures == 0
        && !request_snapshot.counter_overflow
        && request_snapshot.records.iter().all(|r| r.complete);
    let attacker_cpu_ns = all_preparation_resources["thread_cpu_ns"]
        .as_u64()
        .zip(attack_actor_resources["thread_cpu_ns"].as_u64())
        .and_then(|(preparation, calls)| preparation.checked_add(calls));
    let service_phase_wall_ns = ns(complete_phase_start);
    let node = Arc::try_unwrap(owner).ok().unwrap().into_inner().unwrap();
    let read_span = Span::start();
    let actual = node.read_active().unwrap();
    let full_state_read_resources = read_span.finish();
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
    let passed = service_outcome["error"].is_null()
        && no_attack_accepted
        && late_rejections > 0
        && read_successes > 0
        && honest_call.as_ref().is_some_and(returned_on_time)
        && state_equal
        && cpu_known
        && work_complete
        && requests_complete
        && attacker_cpu_ns.is_some();
    (
        node,
        json!({
        "phase": number, "construction_count": ATTACKS,
        "complete_phase_wall_ns": ns(complete_phase_start),
        "all_preparation_wall_ns": all_preparation_wall_ns,
        "all_preparation_resources": all_preparation_resources,
        "attack_actor_resources": attack_actor_resources,
        "attacker_cpu_ns": attacker_cpu_ns,
        "service_phase_wall_ns": service_phase_wall_ns,
        "full_state_read_resources": full_state_read_resources,
        "honest_build_resources": honest_build_resources,
        "honest_build_cpu_is_caller_thread_only": true,
        "request_observations": request_snapshot,
        "request_observations_complete": requests_complete,
        "from_zero": attack_rows, "honest_reads": read_rows,
        "honest_submit": honest_call, "honest_build_error": honest_build_error,
        "honest_build_wall_ns": honest_build_wall_ns,
        "honest_producer_scope": "existing native consensus-maintenance constructor; not claimed cheapest",
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
    let path = if let Some(path) = std::env::var_os("TRNM_PUBLIC_V3_FROM_ZERO_DIR") {
        let path = std::path::PathBuf::from(path);
        fs::create_dir(&path).unwrap();
        path
    } else {
        temporary.path().to_path_buf()
    };
    let settings = Settings::development_with_profiles(
        Some(ingress::now().unwrap() - 100),
        "native-public-evaluation-dev-v1",
        continuity_v1::PROFILE,
    )
    .unwrap();
    let receiver = path.join("receiver");
    let mut node = Node::open(&receiver, settings.clone(), 2).unwrap();
    node.enable_local_mempool(PoolLimits {
        max_records: 8,
        max_bytes: 32768,
        max_group_members: 4,
        critical_reserve: 0,
        max_removals: 16,
        preview_miner: development_public(0).unwrap(),
    })
    .unwrap();
    let context_start = Instant::now();
    let context_span = Span::start();
    let target = node.expected_target(settings.genesis()).unwrap();
    let public_context_read_wall_ns = ns(context_start);
    let public_context_resources = context_span.finish();
    let mut producer = Node::open(&path.join("producer"), settings.clone(), 2).unwrap();
    let server = PublicServer::new(identity(71), policy()).unwrap();
    let domain = server.mutation_cpu_domain();
    let epoch = Instant::now();
    let (node, first) = phase(0, node, &mut producer, server, target, epoch);
    let before = node.read_active().unwrap();
    drop(node);
    let reopen_start = Instant::now();
    let reopen_span = Span::start();
    let reopened = Node::open(&receiver, settings.clone(), 2).unwrap();
    let after = reopened.read_active().unwrap();
    let reopen_wall_ns = ns(reopen_start);
    let reopen_resources = reopen_span.finish();
    let reopen_equal = before == after;
    // Crucially retain the exact CPU domain, rather than mint a fresh service
    // burst on the owner reopen. This is still same-process, not a power cut.
    let server = PublicServer::with_continuous_domain(identity(71), policy(), &domain).unwrap();
    let (node, second) = phase(1, reopened, &mut producer, server, target, epoch);
    // Do not let comparison time refill the budget between the two service phases.
    // All eight cold/reused arms run only after both services have joined.
    let (_, _, a, b) = settings.consensus_maintenance_material().unwrap();
    let mut roster = Roster::new();
    let mut comparisons = Vec::new();
    for (index, phase) in [&first, &second].into_iter().enumerate() {
        let packet = phase["honest_submit"]["request"]["packet"]
            .as_str()
            .and_then(|wire| hex::decode(wire).ok())
            .and_then(|bytes| Packet::decode(&bytes).ok());
        comparisons.push(match packet {
            Some(packet) => roster.compare(&packet, index as u64, &a, &b),
            None => json!({"all_equal": false, "error": "NO_NATIVE_PACKET", "rows": []}),
        });
    }
    let passed = reopen_equal
        && first["finite_target_met"] == true
        && second["finite_target_met"] == true
        && comparisons.iter().all(|row| row["all_equal"] == true);
    let report = json!({
        "schema": "public-v3-local-from-zero-service-v2", "network": hex::encode(settings.network()),
        "parameters": hex::encode(settings.parameters()), "genesis": hex::encode(settings.genesis()),
        "target": hex::encode(target), "policy_id": hex::encode(policy().id()),
        "public_context_read_wall_ns": public_context_read_wall_ns,
        "public_context_resources": public_context_resources,
        "producer_comparisons": comparisons,
        "phases": [first, second], "reopen_resources": reopen_resources, "reopen_wall_ns": reopen_wall_ns, "reopen_state_equal": reopen_equal,
        "cpu_domain_retained_across_owner_reopen": true,
        "scope": "finite local TCP; full from-zero hash trials and real shared receiver CPU; zero claimed C; untrusted state/receipt roots; eight matched cold/reused W1 producers outside concurrent service; explicit existing consensus-maintenance service sender; no global speedup or energy ratio",
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
