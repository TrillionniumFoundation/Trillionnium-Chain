//! Finite same-host, separate-process W1 economics and original public service
//! campaign. No independent operator, WAN, hardness, energy or release claim.
#[path = "support/multiprocess_support.rs"]
mod support;
#[path = "support/multiprocess_work.rs"]
mod work;

use serde_json::{json, Value};
use std::{
    fs,
    net::{SocketAddr, TcpListener},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
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
        public_v3::{self, PublicServer, Request},
    },
    Node, Packet, PoolLimits, Settings,
};
use trnm_protocol::pon_wire::{hash, Header};

const WINDOW_SECONDS: u64 = 30;
const ATTACKERS: usize = 24;
const CALL_CAP: usize = 480;
const ROUNDS: usize = 3;

struct Service {
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<Result<public_v3::PublicMetrics, String>>>,
}
impl Service {
    fn finish(mut self) -> Value {
        self.stop.store(true, Ordering::Release);
        match self.worker.take().unwrap().join() {
            Ok(result) => serde_json::to_value(result).unwrap(),
            Err(_) => json!({"error":"native service thread panicked"}),
        }
    }
}
impl Drop for Service {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

struct Actor {
    child: Child,
    report: PathBuf,
    ready: PathBuf,
    log: PathBuf,
    spawned: Instant,
}
impl Actor {
    fn spawn(path: &Path, job: Value) -> Self {
        fs::create_dir(path).unwrap();
        let job_path = path.join("job.json");
        support::write_new(&job_path, &job);
        let log = path.join("actor.log");
        let stdout = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&log)
            .unwrap();
        let stderr = stdout.try_clone().unwrap();
        let spawned = Instant::now();
        let child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "multiprocess_actor_entry",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("TRNM_MULTIPROCESS_JOB", &job_path)
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr))
            .spawn()
            .unwrap();
        Self {
            child,
            report: path.join("report.json"),
            ready: path.join("ready.json"),
            log,
            spawned,
        }
    }
    fn finish(mut self, deadline: Instant) -> Value {
        let mut forced = false;
        let status = loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                break status;
            }
            if Instant::now() >= deadline {
                self.child.kill().unwrap();
                forced = true;
                break self.child.wait().unwrap();
            }
            support::ready_sleep();
        };
        let retained = fs::read(&self.report)
            .ok()
            .and_then(|raw| serde_json::from_slice::<Value>(&raw).ok());
        json!({"pid":self.child.id(),"spawn_to_reap_wall_ns":self.spawned.elapsed().as_nanos(),"exit_success":status.success(),"exit_status":status.to_string(),
            "parent_forced_kill":forced,"report":retained,"log":self.log,"report_path":self.report})
    }
}
impl Drop for Actor {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

fn header(job: &Value) -> Header {
    Header::decode(&hex::decode(job["header"].as_str().unwrap()).unwrap()).unwrap()
}
fn check_winner(header: &Header, proof: &[u8]) -> Result<(), String> {
    pon_work::verify(header.challenge(), header.work_task, header.target, proof)
        .map(|_| ())
        .map_err(|error| format!("{error:?}"))
}
fn paid_depletion(
    meter: &public_v3::scalar_cpu::ServiceMutationCpuObservation,
    metrics: &public_v3::PublicMetrics,
    actual: Option<&public_v3::scalar_cpu::ServiceMutationCpuFlowObservation>,
    elapsed: u64,
) -> Value {
    // Exact actual credited refill separates paid cost from booked reservation
    // principal. Missing telemetry cannot qualify; the old threshold is intact.
    let depleted = actual.is_some_and(|flow| {
        flow.balance_identity_verified
            && flow.initial_credit_ns == i128::from(meter.burst_ns)
            && flow.remaining_paid_credit_ns < i128::from(meter.start_reserve_ns)
            && flow.paid_cpu_debit_ns > meter.burst_ns - meter.start_reserve_ns
    }) && metrics.mutation_cpu_clock_failures == 0
        && !meter.accounting_unavailable;
    json!({"depleted":depleted,"sample_at_ns":elapsed,"actual_flow":actual,
        "separately_observed_public_settled_cpu_ns":metrics.mutation_cpu_charged_ns,
        "observed_terminal_mutation_cpu_refusals":metrics.mutation_cpu_refusals,
        "meter":meter,"clock_failures":metrics.mutation_cpu_clock_failures,
        "domain_cpu_scope":"original metered owner plus joined scoped-worker CPU; excludes reactor authentication/response, queue waiting and separate process clocks",
        "balance_identity_has_work_or_execution_authority":false,
        "scope":"optional exact actual paid-credit identity; old threshold unchanged; terminal refusals separate because original FIFO waits for refill; no physical cost lower bound"})
}
fn hostile_work(observer: &public_v3::PublicRequestObserver, digests: &[Vec<u8>]) -> Value {
    let snapshot = observer.snapshot();
    let rows: Vec<_> = snapshot
        .records
        .iter()
        .filter(|row| {
            row.operation == Some(1)
                && row.body_digest.as_ref().is_some_and(|digest| {
                    digests.iter().any(|expected| expected.as_slice() == digest)
                })
        })
        .collect();
    json!({"matched_requests":rows.len(),"work_started":rows.iter().filter(|r|r.full_work_started).count(),
        "work_rejected":rows.iter().filter(|r|r.full_work_accepted==Some(false)).count(),
        "work_accepted":rows.iter().filter(|r|r.full_work_accepted==Some(true)).count(),
        "rejected_work_cpu_ns":rows.iter().filter(|r|r.full_work_accepted==Some(false)).try_fold(0_u64,|sum,r|sum.checked_add(r.full_work_thread_cpu_ns?)),
        "scope":"cumulative actual original receiver Submit work observations matched by exact original wire body digest"})
}
fn public_work_header() -> Header {
    let settings = support::settings();
    Header {
        network: settings.network(),
        parameters: settings.parameters(),
        parent: settings.genesis(),
        height: 1,
        timestamp: settings.genesis_time() + 10,
        target: {
            let mut target = [255; 32];
            target[0] = 127;
            target
        },
        miner: development_public(0).unwrap(),
        transactions: trnm_pon_node::sequence_root("transactions", &[]),
        state: [0; 32],
        receipts: [0; 32],
        work_task: trnm_mvcc_fee::continuity_v1::maintenance_task().unwrap(),
        nonce: 0,
    }
}
#[test]
fn paid_depletion_cannot_be_manufactured_by_reservations_or_unknown_clocks() {
    let mut meter = public_v3::scalar_cpu::ServiceMutationCpuObservation {
        schema: "local-fixture",
        stored_credit_ns: -120_000_000,
        in_flight: 2,
        accounting_unavailable: false,
        burst_ns: 2_000_000_000,
        refill_ns_per_second: 250_000_000,
        start_reserve_ns: 100_000_000,
        worker_limit: 2,
    };
    let mut metrics = public_v3::PublicMetrics {
        mutation_cpu_refusals: 1,
        mutation_cpu_charged_ns: 200_000_000,
        ..Default::default()
    };
    assert_eq!(
        paid_depletion(&meter, &metrics, None, 1_000_000_000)["depleted"],
        false
    );
    metrics.mutation_cpu_charged_ns = 2_200_000_000;
    assert_eq!(
        paid_depletion(&meter, &metrics, None, 1_000_000_000)["depleted"],
        false
    );
    metrics.mutation_cpu_refusals = 0;
    assert_eq!(
        paid_depletion(&meter, &metrics, None, 1_000_000_000)["depleted"],
        false
    );
    metrics.mutation_cpu_refusals = 1;
    meter.accounting_unavailable = true;
    assert_eq!(
        paid_depletion(&meter, &metrics, None, 1_000_000_000)["depleted"],
        false
    );
}
#[test]
fn independent_hostile_construction_preserves_exact_rejection_stage_and_misses() {
    let original = public_work_header();
    let producer = work::Producer::new(6).unwrap();
    let (legal, mut proof, attempts) = work::legal_search(&producer, original.clone()).unwrap();
    assert!(!attempts.is_empty());
    assert!(attempts.last().unwrap()["target_hit"] == true);
    assert!(attempts[..attempts.len() - 1]
        .iter()
        .all(|row| row["target_hit"] == false));
    assert!(check_winner(&legal, &proof).is_ok());
    let own_trace = proof[proof.len() - 32..].to_vec();
    work::corrupt_product(&mut proof);
    assert_eq!(&proof[proof.len() - 32..], own_trace.as_slice());
    assert_eq!(check_winner(&legal, &proof).unwrap_err(), "Product");
    let (false_proof, false_attempts) = work::from_zero(original.clone()).unwrap();
    assert_eq!(
        check_winner(&original, &false_proof).unwrap_err(),
        "Transcript"
    );
    assert!(!false_attempts.is_empty());
    let mut impossible = original;
    impossible.target = [0; 32];
    let exhausted = work::from_zero(impossible).unwrap_err();
    let records: Vec<Value> =
        serde_json::from_str(exhausted.split_once("retained_attempts=").unwrap().1).unwrap();
    assert_eq!(records.len(), 4096);
    assert!(records.iter().all(|row| row["target_hit"] == false));
}
fn cost_actor(job: &Value) -> Value {
    let index = job["method"].as_u64().unwrap() as usize;
    let template = header(job);
    let transactions: Vec<Vec<u8>> = job["transactions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| hex::decode(v.as_str().unwrap()).unwrap())
        .collect();
    let mut modes = Vec::new();
    // Alternate order by method, avoiding a fixed cold/reused warmup advantage.
    let order = if index.is_multiple_of(2) {
        [false, true]
    } else {
        [true, false]
    };
    for reused in order {
        let mut samples = Vec::new();
        for sample in 0..3_u64 {
            let total = Instant::now();
            let total_cpu = support::cpu();
            let before = support::rss();
            let prepared_started = Instant::now();
            let prepared_cpu = support::cpu();
            let shared = if reused {
                Some(work::Producer::new(index).unwrap())
            } else {
                None
            };
            let initial_setup_cpu_ns = support::elapsed_cpu(prepared_cpu);
            let initial_setup_wall_ns = prepared_started.elapsed().as_nanos();
            let mut searches = Vec::new();
            let mut winners = Vec::new();
            let mut errors = Vec::new();
            for search in 0..4_u64 {
                let setup_started = Instant::now();
                let setup_cpu = support::cpu();
                let cold = if reused {
                    None
                } else {
                    Some(work::Producer::new(index).unwrap())
                };
                let setup_cpu_ns = support::elapsed_cpu(setup_cpu);
                let setup_wall_ns = setup_started.elapsed().as_nanos();
                let producer = shared.as_ref().or(cold.as_ref()).unwrap();
                let mut challenge_header = template.clone();
                // Identical full challenge stream for every producer/mode.
                challenge_header.nonce = 1_000_000 + sample * 100_000 + search * 10_000;
                let search_started = Instant::now();
                let search_cpu = support::cpu();
                match work::legal_search(producer, challenge_header) {
                    Ok((winner, proof, attempts)) => {
                        let packet = Packet {
                            header: winner.clone(),
                            transactions: transactions.clone(),
                            proof,
                        };
                        let encoded = packet.encode().unwrap();
                        searches.push(json!({"search":search,"attempts":attempts,"setup_cpu_ns":setup_cpu_ns,
                            "setup_wall_ns":setup_wall_ns,"search_cpu_ns":support::elapsed_cpu(search_cpu),
                            "search_wall_ns":search_started.elapsed().as_nanos(),"winning_header":hex::encode(winner.encode()),
                            "proof_digest":hex::encode(hash(b"multiprocess-observed-proof-v1", &[&packet.proof])),
                            "encoded_packet_bytes":encoded.len(),"packet_digest":hex::encode(hash(b"multiprocess-attack-packet-v1", &[&encoded]))}));
                        winners.push((winner, packet.proof));
                    }
                    Err(error) => errors.push(error),
                }
            }
            let acquisition_cpu_ns = support::elapsed_cpu(total_cpu);
            let acquisition_wall_ns = total.elapsed().as_nanos();
            let after = support::rss();
            // Complete relation verification is an independently measured phase,
            // never counted as producer search or used to infer acquisition cost.
            let verification_started = Instant::now();
            let verification_cpu = support::cpu();
            let verified: Vec<_> = winners.iter().map(|(h, p)| check_winner(h, p)).collect();
            samples.push(json!({"sample":sample,"acquisition_cpu_ns":acquisition_cpu_ns,
                "acquisition_wall_ns":acquisition_wall_ns,"initial_setup_cpu_ns":initial_setup_cpu_ns,
                "initial_setup_wall_ns":initial_setup_wall_ns,"rss_before":before,"rss_after":after,
                "searches":searches,"errors":errors,"verified_winners":verified,
                "independent_verification_cpu_ns":support::elapsed_cpu(verification_cpu),
                "independent_verification_wall_ns":verification_started.elapsed().as_nanos()}));
        }
        modes.push(json!({"reuse_preparation":reused,"setup_calls_per_sample":if reused {1}else{4},"samples":samples}));
    }
    let mut from_zero_samples = Vec::new();
    for sample in 0..3_u64 {
        let start = Instant::now();
        let cpu = support::cpu();
        let before = support::rss();
        let mut trials = Vec::new();
        let mut proofs = Vec::new();
        for search in 0..4_u64 {
            let mut h = template.clone();
            h.nonce = 1_000_000 + sample * 100_000 + search * 10_000;
            let (proof, attempts) = work::from_zero(h.clone()).unwrap();
            let packet = Packet {
                header: h.clone(),
                transactions: transactions.clone(),
                proof,
            };
            let encoded = packet.encode().unwrap();
            trials.push(json!({"search":search,"header":hex::encode(h.encode()),"attempts":attempts,
                "packet_bytes":encoded.len(),"packet_digest":hex::encode(hash(b"multiprocess-attack-packet-v1", &[&encoded]))}));
            proofs.push((h, packet.proof));
        }
        let acquisition_cpu_ns = support::elapsed_cpu(cpu);
        let acquisition_wall_ns = start.elapsed().as_nanos();
        let after = support::rss();
        let verification_cpu = support::cpu();
        let verification_wall = Instant::now();
        let diagnostics: Vec<_> = proofs.iter().map(|(h, p)| check_winner(h, p)).collect();
        from_zero_samples.push(json!({"sample":sample,"acquisition_cpu_ns":acquisition_cpu_ns,"acquisition_wall_ns":acquisition_wall_ns,"rss_before":before,"rss_after":after,
            "searches":trials,"relation_diagnostics":diagnostics,"diagnostic_cpu_ns":support::elapsed_cpu(verification_cpu),"diagnostic_wall_ns":verification_wall.elapsed().as_nanos()}));
    }
    json!({"method":work::METHODS[index],"method_index":index,"modes":modes,"same_task_target_from_zero_samples":from_zero_samples,
        "rss":support::rss(),"scope":"actual existing maintenance producer, public exact task/target, all observed attempts; no cheapest-adversary, whole-block preparation or physical cost lower bound"})
}

fn attack_actor(job: &Value, directory: &Path) -> Value {
    let process_cpu = support::cpu();
    let entire = Instant::now();
    let template = header(job);
    let mode = job["mode"].as_str().unwrap();
    let acquisition_started = Instant::now();
    let acquisition_cpu = support::cpu();
    let rss_before = support::rss();
    let (attack_header, proof, attempts, setups) = if mode == "from-zero" {
        let (proof, attempts) = work::from_zero(template.clone()).unwrap();
        (template, proof, attempts, 0)
    } else {
        let producer = work::Producer::new(job["method"].as_u64().unwrap() as usize).unwrap();
        let (header, mut proof, attempts) = work::legal_search(&producer, template).unwrap();
        work::corrupt_product(&mut proof);
        (header, proof, attempts, 1)
    };
    let transactions: Vec<Vec<u8>> = job["transactions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| hex::decode(value.as_str().unwrap()).unwrap())
        .collect();
    let packet = Packet {
        header: attack_header,
        transactions,
        proof,
    };
    let wire = packet.encode().unwrap();
    let packet_hex = hex::encode(&wire);
    let public_body = serde_json::to_vec(&Request::Submit {
        packet: packet_hex.clone(),
    })
    .unwrap();
    let acquisition_cpu_ns = support::elapsed_cpu(acquisition_cpu);
    let acquisition_wall_ns = acquisition_started.elapsed().as_nanos();
    let diagnostic_started = Instant::now();
    let diagnostic_cpu = support::cpu();
    let diagnostic = check_winner(&packet.header, &packet.proof);
    let relation_rejection_matches_mode = diagnostic.as_ref().is_err_and(|error| {
        error
            == if mode == "from-zero" {
                "Transcript"
            } else {
                "Product"
            }
    });
    let diagnostic_cpu_ns = support::elapsed_cpu(diagnostic_cpu);
    let diagnostic_wall_ns = diagnostic_started.elapsed().as_nanos();
    let acquisition = json!({"mode":mode,"setup_calls":setups,"attempts":attempts,
        "header":hex::encode(packet.header.encode()),"packet_digest":hex::encode(hash(b"multiprocess-attack-packet-v1", &[&wire])),
        "packet_bytes":wire.len(),"proof_digest":hex::encode(hash(b"multiprocess-observed-proof-v1", &[&packet.proof])),
        "public_request_body_digest":hex::encode(hash(b"public-request-body-v3", &[&public_body])),
        "acquisition_cpu_ns":acquisition_cpu_ns,"acquisition_wall_ns":acquisition_wall_ns,
        "rss_before":rss_before,"rss_after":support::rss(),"diagnostic_result":diagnostic,"relation_rejection_matches_mode":relation_rejection_matches_mode,
        "diagnostic_cpu_ns":diagnostic_cpu_ns,"diagnostic_wall_ns":diagnostic_wall_ns,
        "scope":"own acquisition from public header/task; includes all local setup/search records and packet encoding; diagnostic verification separate"});
    // Preserve acquisition before readiness, so an interrupted actor cannot erase
    // expensive preparation or a negative relation result.
    support::write_new(&directory.join("acquisition.json"), &acquisition);
    assert!(
        relation_rejection_matches_mode,
        "own acquired input rejected at unexpected relation stage; acquisition retained"
    );
    support::write_new(
        &directory.join("ready.json"),
        &json!({"pid":std::process::id(),"mode":mode}),
    );
    let marker = PathBuf::from(job["start_marker"].as_str().unwrap());
    let ready_deadline = Instant::now() + Duration::from_secs(180);
    while !marker.exists() && Instant::now() < ready_deadline {
        support::ready_sleep();
    }
    let start: Value = serde_json::from_slice(
        &fs::read(&marker).expect("parent start marker within finite deadline"),
    )
    .unwrap();
    let epoch = start["epoch_ns"].as_u64().unwrap();
    let end = start["end_ns"].as_u64().unwrap();
    let address: SocketAddr = job["address"].as_str().unwrap().parse().unwrap();
    let settings = support::settings();
    let traffic_cpu = support::cpu();
    let traffic_started = Instant::now();
    let mut calls = Vec::new();
    let worker = job["worker"].as_u64().unwrap() as usize;
    while support::monotonic() < end && calls.len() < CALL_CAP {
        let who = 80 + ((worker * 37 + calls.len()) % 150) as u8;
        calls.push(support::call(
            address,
            &settings,
            Request::Submit {
                packet: packet_hex.clone(),
            },
            who,
            epoch,
            end,
        ));
    }
    json!({"pid":std::process::id(),"worker":worker,"mode":mode,"acquisition":acquisition,
        "calls":calls,"attempt_cap_reached":calls.len()==CALL_CAP,
        "traffic_cpu_ns":support::elapsed_cpu(traffic_cpu),"traffic_wall_ns":traffic_started.elapsed().as_nanos(),
        "entire_actor_cpu_ns":support::elapsed_cpu(process_cpu),"entire_actor_wall_ns":entire.elapsed().as_nanos(),
        "rss":support::rss(),"identity_scope":"development keys controlled by this experiment; rotating keys are not independent operators"})
}

#[test]
#[ignore = "subprocess entry; parent supplies an immutable explicit job file"]
fn multiprocess_actor_entry() {
    let path = PathBuf::from(std::env::var_os("TRNM_MULTIPROCESS_JOB").expect("parent job"));
    let job: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    let start = Instant::now();
    let cpu = support::cpu();
    let outcome = std::panic::catch_unwind(|| match job["kind"].as_str().unwrap() {
        "cost" => cost_actor(&job),
        "attack" => attack_actor(&job, path.parent().unwrap()),
        _ => panic!("unknown actor kind"),
    });
    let (result, error) = match outcome {
        Ok(value) => (Some(value), None),
        Err(error) => {
            let message = error
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| error.downcast_ref::<&str>().map(|s| s.to_string()))
                .unwrap_or_else(|| "non-string panic".to_owned());
            (None, Some(message))
        }
    };
    support::write_new(
        &path.parent().unwrap().join("report.json"),
        &json!({"kind":job["kind"],"result":result,"error":error,
        "whole_entry_cpu_ns":support::elapsed_cpu(cpu),"whole_entry_wall_ns":start.elapsed().as_nanos(),"rss":support::rss()}),
    );
    assert!(
        error.is_none(),
        "actor failed; retained report contains the actual failure"
    );
}

fn replay(node: &mut Node, packets: &[Packet]) {
    for packet in packets {
        let id = node.admit(packet, support::now()).unwrap();
        node.activate_observed(id, support::now()).unwrap();
    }
}
fn phase(
    path: &Path,
    settings: &Settings,
    seed: &[Packet],
    business: &[Packet],
    mode: Option<&str>,
    method: usize,
) -> Value {
    fs::create_dir(path).unwrap();
    let whole_started = Instant::now();
    let whole_cpu = support::cpu();
    let setup_started = Instant::now();
    let setup_cpu = support::cpu();
    let mut receiver = Node::open(&path.join("receiver"), settings.clone(), 1).unwrap();
    replay(&mut receiver, seed);
    receiver
        .enable_local_mempool(PoolLimits {
            max_records: 16,
            max_bytes: 32768,
            max_group_members: 4,
            critical_reserve: 0,
            max_removals: 64,
            preview_miner: development_public(0).unwrap(),
        })
        .unwrap();
    let mut verifier = Node::open(&path.join("independent-client"), settings.clone(), 1).unwrap();
    replay(&mut verifier, seed);
    let initial = receiver.read_active().unwrap();
    let owner = Arc::new(Mutex::new(receiver));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let metrics = Arc::new(Mutex::new(public_v3::PublicMetrics::default()));
    let live_metrics = metrics.clone();
    let observer = public_v3::PublicRequestObserver::new(16_384).unwrap();
    let server = PublicServer::new(support::identity(71), support::policy()).unwrap();
    let domain = server.mutation_cpu_domain();
    let initial_meter = domain.observe().unwrap();
    let (shared, signal, capture) = (owner.clone(), stop.clone(), observer.clone());
    let service = Service {
        stop,
        worker: Some(thread::spawn(move || {
            public_v3::serve_public_protected_v3_with_request_observer(
                listener,
                shared,
                Duration::from_secs(240),
                signal,
                server,
                metrics,
                capture,
            )
            .map_err(|error| error.to_string())
        })),
    };
    let receiver_and_verifier_setup_cpu_ns = support::elapsed_cpu(setup_cpu);
    let receiver_and_verifier_setup_wall_ns = setup_started.elapsed().as_nanos();
    let marker = path.join("start.json");
    let mut actors = Vec::new();
    let children_usage_before = support::children_usage();
    if let Some(mode) = mode {
        for worker in 0..ATTACKERS {
            let mut template = business[0].header.clone();
            template.nonce = 2_000_000 + worker as u64 * 10_000;
            actors.push(Actor::spawn(&path.join(format!("attacker-{worker:02}")),json!({"kind":"attack","mode":mode,"method":method,
            "worker":worker,"address":address.to_string(),"header":hex::encode(template.encode()),
            "transactions":business[0].transactions.iter().map(hex::encode).collect::<Vec<_>>(),"start_marker":marker})));
        }
    }
    let readiness_end = Instant::now() + Duration::from_secs(180);
    while actors
        .iter()
        .any(|actor| !actor.ready.exists() && !actor.report.exists())
        && Instant::now() < readiness_end
    {
        support::ready_sleep();
    }
    let ready_count = actors.iter().filter(|actor| actor.ready.exists()).count();
    let hostile_digests: Vec<Vec<u8>> = actors
        .iter()
        .filter_map(|actor| fs::read(actor.ready.parent().unwrap().join("acquisition.json")).ok())
        .filter_map(|raw| serde_json::from_slice::<Value>(&raw).ok())
        .filter_map(|value| {
            value["public_request_body_digest"]
                .as_str()
                .and_then(|s| hex::decode(s).ok())
        })
        .collect();
    let epoch = support::monotonic();
    let end = epoch + WINDOW_SECONDS * 1_000_000_000;
    let temporary_marker = path.join("start.tmp.json");
    support::write_new(&temporary_marker, &json!({"epoch_ns":epoch,"end_ns":end}));
    fs::rename(&temporary_marker, &marker).unwrap();
    let samples = Arc::new(Mutex::new(Vec::<Value>::new()));
    let sampling = samples.clone();
    let sample_domain = domain.clone();
    let sample_metrics = live_metrics.clone();
    let pids: Vec<_> = actors.iter().map(|actor| actor.child.id()).collect();
    let sampler = thread::spawn(move || {
        while support::monotonic() < end {
            let observation_started_ns = support::monotonic().saturating_sub(epoch);
            let observation = sample_domain
                .observe()
                .map(|meter| {
                    let actual = sample_domain.observe_actual_flow().ok().flatten();
                    paid_depletion(
                        &meter,
                        &sample_metrics.lock().unwrap(),
                        actual.as_ref(),
                        support::monotonic().saturating_sub(epoch),
                    )
                })
                .map_err(|e| e.to_string());
            let observation_ended_ns = support::monotonic().saturating_sub(epoch);
            sampling.lock().unwrap().push(json!({"at_ns":observation_ended_ns,"observation_started_ns":observation_started_ns,
                "observation_ended_ns":observation_ended_ns,"meter":observation,"attacker_process_rss":support::live_children_rss(&pids)}));
            thread::sleep(Duration::from_millis(50));
        }
    });
    // Fixed t=1,5,9 seconds, regardless of whether this finite workload reaches
    // paid-credit depletion. Honest progress and depletion stay separate facts.
    while support::monotonic() < epoch + 1_000_000_000 {
        support::ready_sleep();
    }
    let business_started = support::monotonic().saturating_sub(epoch);
    let mut submissions = Vec::new();
    let mut history = Vec::new();
    let mut confirmations = Vec::new();
    let mut errors = Vec::new();
    let mut after = initial.0;
    let mut next = 0;
    {
        for round in 0..ROUNDS {
            let scheduled = epoch
                .saturating_add(1_000_000_000)
                .saturating_add(round as u64 * 4_000_000_000);
            while support::monotonic() < scheduled.min(end) {
                support::ready_sleep();
            }
            let round_start = support::monotonic().saturating_sub(epoch);
            let hostile_before = hostile_work(&observer, &hostile_digests);
            let final_index = (round + 1) * 7;
            while next < final_index && support::monotonic() < end && submissions.len() < 128 {
                let mut row = support::call(
                    address,
                    settings,
                    Request::Submit {
                        packet: hex::encode(business[next].encode().unwrap()),
                    },
                    73,
                    epoch,
                    end,
                );
                row["packet_index"] = json!(next);
                row["height"] = json!(business[next].header.height);
                if support::on_time(&row) {
                    next += 1;
                }
                submissions.push(row);
            }
            let tip = business[final_index - 1].id().unwrap();
            let included = business[round * 7].id().unwrap();
            let transaction = hash(b"tx-id", &[&business[round * 7].transactions[0]]);
            let mut observation = None;
            while next == final_index && support::monotonic() < end && history.len() < 64 {
                let row = support::call(
                    address,
                    settings,
                    Request::History {
                        tip: hex::encode(tip),
                        after: hex::encode(after),
                    },
                    74,
                    epoch,
                    end,
                );
                if support::on_time(&row) {
                    let imported =
                        serde_json::from_value::<ingress::Page>(row["response"]["value"].clone())
                            .map_err(|e| e.to_string())
                            .and_then(|page| {
                                ingress::receive_page(
                                    &mut verifier,
                                    page,
                                    tip,
                                    after,
                                    support::now(),
                                )
                                .map_err(|e| e.to_string())
                            });
                    match imported {
                        Ok(next_after) => after = next_after,
                        Err(error) => errors.push(error),
                    }
                    if after == tip {
                        match verifier.confirmation(transaction, included, support::now()) {
                            Ok(value) => observation = Some(value),
                            Err(e) => errors.push(e.to_string()),
                        }
                    }
                }
                history.push(row);
                if observation.is_some() {
                    break;
                }
            }
            let ended = support::monotonic().saturating_sub(epoch);
            let hostile_after = hostile_work(&observer, &hostile_digests);
            let receiver_hostile_work_rejected_during_round = hostile_before["work_rejected"]
                .as_u64()
                .zip(hostile_after["work_rejected"].as_u64())
                .is_some_and(|(a, b)| b > a)
                && hostile_before["rejected_work_cpu_ns"]
                    .as_u64()
                    .zip(hostile_after["rejected_work_cpu_ns"].as_u64())
                    .is_some_and(|(a, b)| b > a);
            let confirmed = observation.as_ref().is_some_and(|value| {
                value.confirmed
                    && !value.finalized
                    && !value.execution_authority
                    && value.depth == Some(6)
            }) && support::monotonic() < end;
            confirmations.push(json!({"round":round,"started_ns":round_start,"ended_ns":ended,"confirmed_inside_pressure_window":confirmed,
                "transaction":hex::encode(transaction),"included_block":hex::encode(included),"tip":hex::encode(tip),"observation":observation,
                "receiver_hostile_before":hostile_before,"receiver_hostile_after":hostile_after,"receiver_hostile_work_rejected_during_round":receiver_hostile_work_rejected_during_round}));
            if !confirmed {
                break;
            }
        }
    }
    // Keep the fixed hostile window running after business, never drain first and
    // then retroactively count a recovery confirmation as overlap.
    let cleanup_deadline = Instant::now()
        + Duration::from_nanos(end.saturating_sub(support::monotonic()))
        + Duration::from_secs(5);
    let children: Vec<_> = actors
        .into_iter()
        .map(|actor| actor.finish(cleanup_deadline))
        .collect();
    let children_usage_after = support::children_usage();
    sampler.join().unwrap();
    let service_outcome = service.finish();
    let captured = observer.snapshot();
    let budget_samples = samples.lock().unwrap().clone();
    let depletion_meter = budget_samples
        .iter()
        .filter_map(|row| row["meter"].get("Ok"))
        .find(|row| row["depleted"] == true)
        .cloned();
    let depletion_at = depletion_meter
        .as_ref()
        .and_then(|row| row["sample_at_ns"].as_u64());
    for round in &mut confirmations {
        let start = round["started_ns"].as_u64().unwrap();
        let end = round["ended_ns"].as_u64().unwrap();
        round["paid_credit_depletion_observed_during_round"] =
            json!(budget_samples
                .iter()
                .any(|sample| sample["observation_started_ns"]
                    .as_u64()
                    .zip(sample["observation_ended_ns"].as_u64())
                    .is_some_and(|(a, b)| start <= a && a <= b && b <= end)
                    && sample["meter"]["Ok"]["depleted"] == true));
    }
    let actual = owner.lock().unwrap().read_active().unwrap();
    let checked = verifier.read_active().unwrap();
    let final_meter = domain.observe().unwrap();
    let all_confirmed = confirmations.len() == ROUNDS
        && confirmations
            .iter()
            .all(|row| row["confirmed_inside_pressure_window"] == true);
    let attack_calls: Vec<_> = children
        .iter()
        .filter_map(|child| child["report"]["result"]["calls"].as_array())
        .flat_map(|rows| rows.iter())
        .collect();
    let overlaps: Vec<_> = confirmations
        .iter()
        .map(|round| {
            let start = round["started_ns"].as_u64().unwrap();
            let end = round["ended_ns"].as_u64().unwrap();
            attack_calls
                .iter()
                .filter(|call| {
                    call["started_ns"].as_u64().is_some_and(|v| v < end)
                        && call["ended_ns"].as_u64().is_some_and(|v| v > start)
                })
                .count()
        })
        .collect();
    let successful_actors = children.iter().all(|child| {
        child["exit_success"] == true
            && child["parent_forced_kill"] == false
            && child["report"]["error"].is_null()
            && child["report"]["result"]["attempt_cap_reached"] == false
    });
    let relation_failed = captured
        .records
        .iter()
        .filter(|row| row.full_work_accepted == Some(false))
        .count();
    let relation_accepted = captured
        .records
        .iter()
        .filter(|row| row.full_work_accepted == Some(true))
        .count();
    let observer_complete = captured.records_not_retained == 0
        && captured
            .records
            .iter()
            .all(|row| row.complete && !row.observation_failed);
    let phase_criteria = all_confirmed
        && actual.0 == checked.0
        && actual.2 == checked.2
        && observer_complete
        && service_outcome.get("Ok").is_some()
        && service_outcome["Ok"]["mutation_cpu_clock_failures"] == 0
        && final_meter.in_flight == 0
        && !final_meter.accounting_unavailable
        && errors.is_empty()
        && (mode.is_none()
            || (depletion_at.is_some()
                && ready_count == ATTACKERS
                && successful_actors
                && overlaps.len() == ROUNDS
                && overlaps.iter().all(|n| *n > 0)
                && relation_failed > 0
                && relation_accepted >= ROUNDS * 7
                && confirmations
                    .iter()
                    .any(|row| row["paid_credit_depletion_observed_during_round"] == true)
                && confirmations
                    .iter()
                    .all(|row| row["receiver_hostile_work_rejected_during_round"] == true)
                && attack_calls.iter().all(|row| row["status"] != "ok")));
    json!({"mode":mode.unwrap_or("baseline"),"address":address.to_string(),"duration_seconds":WINDOW_SECONDS,
        "attacker_processes_requested":if mode.is_some(){ATTACKERS}else{0},"attacker_processes_ready":ready_count,
        "depletion_at_ns":depletion_at,"depletion_meter":depletion_meter,"genuine_budget_depletion_observed":depletion_at.is_some(),"business_started_ns":business_started,
        "receiver_and_verifier_setup_cpu_ns":receiver_and_verifier_setup_cpu_ns,"receiver_and_verifier_setup_wall_ns":receiver_and_verifier_setup_wall_ns,
        "submissions":submissions,"history":history,"confirmations":confirmations,"all_signed_rounds_confirmed_in_window":all_confirmed,
        "verifier_errors":errors,"children":children,"service_outcome":service_outcome,"receiver_observation":captured,
        "observer_complete":observer_complete,"full_work_failed":relation_failed,"full_work_accepted":relation_accepted,
        "actor_reports_successful_without_cap_or_kill":successful_actors,"attack_calls_overlapping_each_signed_round":overlaps,
        "children_os_usage_before":children_usage_before,"children_os_usage_after":children_usage_after,
        "finite_phase_criteria_met":phase_criteria,
        "budget_samples":budget_samples,"initial_meter":initial_meter,"final_meter":final_meter,
        "final_actual_flow":domain.observe_actual_flow().ok().flatten(),
        "receiver_client_state_equal":actual.0==checked.0&&actual.2==checked.2,
        "initial_tip":hex::encode(initial.0),"final_receiver_tip":hex::encode(actual.0),"final_client_tip":hex::encode(checked.0),
        "whole_parent_phase_cpu_ns":support::elapsed_cpu(whole_cpu),"whole_parent_phase_wall_ns":whole_started.elapsed().as_nanos(),"rss":support::rss()})
}

#[test]
#[ignore = "explicit finite 3x30 second separate-process local campaign and producer cost; see retained report"]
fn separate_process_work_and_signed_confirmation_campaign() {
    let output = PathBuf::from(
        std::env::var_os("TRNM_MULTIPROCESS_REPORT_DIR").expect("explicit new report directory"),
    );
    fs::create_dir(&output).unwrap();
    let outcome = std::panic::catch_unwind(|| campaign(&output));
    if let Err(error) = outcome {
        let message = error
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| error.downcast_ref::<&str>().map(|s| s.to_string()))
            .unwrap_or_else(|| "non-string panic".to_owned());
        support::write_new(
            &output.join("campaign-failure.json"),
            &json!({"error":message,"production_candidate":false,"release_ready":false,
            "scope":"actual finite experiment failure; independently retained stage and child files remain evidence"}),
        );
        panic!("campaign failed; retained {}", output.display());
    }
}
fn campaign(output: &Path) {
    eprintln!("P0 native campaign: honest 1024 signed transfers and 21 business blocks");
    let settings = support::settings();
    let preparation_started = Instant::now();
    let preparation_cpu = support::cpu();
    let mut miner = Node::open(&output.join("honest-miner"), settings.clone(), 1).unwrap();
    let mut seed = Vec::new();
    // Real funded accounts and full signed execution, not injected SQL/state or
    // a cheap verifier fixture. All processes still use the original CPU budget.
    for block in 0..4_u64 {
        let transactions = (0..256_u64)
            .map(|slot| {
                let nonce = block * 256 + slot + 1;
                support::signed_transfer(
                    &settings,
                    nonce,
                    hash(b"multiprocess-funded-account-v1", &[&nonce.to_le_bytes()]),
                )
            })
            .collect();
        let packet = miner
            .make_consensus_maintenance(
                miner.active().unwrap().0,
                transactions,
                development_public(0).unwrap(),
                settings.genesis_time() + (block + 1) * 10,
                4096,
            )
            .unwrap();
        replay(&mut miner, std::slice::from_ref(&packet));
        seed.push(packet);
    }
    let mut business = Vec::new();
    for index in 0..ROUNDS * 7 {
        let transactions = if index % 7 == 0 {
            vec![support::signed_transfer(
                &settings,
                1025 + (index / 7) as u64,
                development_public(1).unwrap(),
            )]
        } else {
            vec![]
        };
        let packet = miner
            .make_consensus_maintenance(
                miner.active().unwrap().0,
                transactions,
                development_public(0).unwrap(),
                settings.genesis_time() + (5 + index as u64) * 10,
                4096,
            )
            .unwrap();
        replay(&mut miner, std::slice::from_ref(&packet));
        business.push(packet);
    }
    let preparation = json!({"cpu_ns":support::elapsed_cpu(preparation_cpu),"wall_ns":preparation_started.elapsed().as_nanos(),
        "actual_signed_seed_transfers":1024,"seed_blocks":4,"business_blocks":business.len(),"rss":support::rss(),
        "seed":seed.iter().map(|p|json!({"id":hex::encode(p.id().unwrap()),"header":hex::encode(p.header.encode()),"transactions":p.transactions.len()})).collect::<Vec<_>>(),
        "business":business.iter().map(|p|json!({"id":hex::encode(p.id().unwrap()),"header":hex::encode(p.header.encode()),"transactions":p.transactions.iter().map(hex::encode).collect::<Vec<_>>()})).collect::<Vec<_>>()});
    support::write_new(&output.join("honest-preparation.json"), &preparation);
    let mut economics = Vec::new();
    for method in 0..work::METHODS.len() {
        eprintln!(
            "P0 native campaign: observed producer {}",
            work::METHODS[method]
        );
        let usage_before = support::children_usage();
        let actor = Actor::spawn(
            &output.join(format!("cost-{method}")),
            json!({"kind":"cost","method":method,"header":hex::encode(business[0].header.encode()),
                "transactions":business[0].transactions.iter().map(hex::encode).collect::<Vec<_>>()}),
        );
        let mut result = actor.finish(Instant::now() + Duration::from_secs(180));
        result["os_children_usage_before"] = usage_before;
        result["os_children_usage_after"] = support::children_usage();
        economics.push(result);
    }
    support::write_new(&output.join("economics.json"), &json!({"actors":economics}));
    let economics_complete = economics.len() == work::METHODS.len()
        && economics.iter().all(|actor| {
            let value = &actor["report"]["result"];
            actor["exit_success"] == true
                && actor["parent_forced_kill"] == false
                && actor["report"]["error"].is_null()
                && value["modes"].as_array().is_some_and(|modes| {
                    modes.len() == 2
                        && modes.iter().all(|mode| {
                            mode["samples"].as_array().is_some_and(|samples| {
                                samples.len() == 3
                                    && samples.iter().all(|sample| {
                                        sample["acquisition_cpu_ns"]
                                            .as_u64()
                                            .is_some_and(|cpu| cpu > 0)
                                            && sample["errors"]
                                                .as_array()
                                                .is_some_and(|errors| errors.is_empty())
                                            && sample["verified_winners"].as_array().is_some_and(
                                                |winners| {
                                                    winners.len() == 4
                                                        && winners.iter().all(|winner| {
                                                            winner.get("Ok").is_some()
                                                        })
                                                },
                                            )
                                            && sample["searches"]
                                                .as_array()
                                                .is_some_and(|searches| searches.len() == 4)
                                    })
                            })
                        })
                })
                && value["same_task_target_from_zero_samples"]
                    .as_array()
                    .is_some_and(|samples| {
                        samples.len() == 3
                            && samples.iter().all(|sample| {
                                sample["acquisition_cpu_ns"]
                                    .as_u64()
                                    .is_some_and(|cpu| cpu > 0)
                                    && sample["relation_diagnostics"].as_array().is_some_and(
                                        |rows| {
                                            rows.len() == 4
                                                && rows.iter().all(|row| row["Err"] == "Transcript")
                                        },
                                    )
                            })
                    })
        });
    // Select the best OBSERVED complete legal cold-acquisition median, retaining
    // all other methods and failures. Not a theoretical optimum or lower bound.
    let mut candidates = Vec::new();
    for actor in &economics {
        let value = &actor["report"]["result"];
        let method = value["method_index"].as_u64().unwrap() as usize;
        let cold = value["modes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["reuse_preparation"] == false)
            .unwrap();
        let mut times: Vec<_> = cold["samples"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|s| {
                s["errors"].as_array().unwrap().is_empty()
                    && s["verified_winners"].as_array().unwrap().len() == 4
                    && s["verified_winners"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .all(|v| v.get("Ok").is_some())
            })
            .filter_map(|s| s["acquisition_cpu_ns"].as_u64())
            .collect();
        times.sort_unstable();
        if times.len() == 3 {
            candidates.push((times[1], method));
        }
    }
    candidates.sort_unstable();
    let best = candidates
        .first()
        .map(|(_, method)| *method)
        .expect("actual verified producer samples; reports preserved if qualification fails");
    let mut phases = Vec::new();
    for mode in [None, Some("from-zero"), Some("late-product")] {
        eprintln!(
            "P0 native campaign: phase {} 30s / {} attacker processes",
            mode.unwrap_or("baseline"),
            if mode.is_some() { ATTACKERS } else { 0 }
        );
        let result=std::panic::catch_unwind(||phase(&output.join(mode.unwrap_or("baseline")),&settings,&seed,&business,mode,best))
            .unwrap_or_else(|error|{let message=error.downcast_ref::<String>().cloned().or_else(||error.downcast_ref::<&str>().map(|s|s.to_string())).unwrap_or_else(||"non-string panic".to_owned());
                json!({"mode":mode.unwrap_or("baseline"),"startup_or_campaign_error":message,"all_signed_rounds_confirmed_in_window":false,"genuine_budget_depletion_observed":false})});
        support::write_new(
            &output.join(format!("{}.json", mode.unwrap_or("baseline"))),
            &result,
        );
        phases.push(result);
    }
    let complete = economics_complete
        && phases
            .iter()
            .all(|p| p["finite_phase_criteria_met"] == true);
    let report = json!({"schema":"native-public-v3-separate-process-campaign-v2","scope":"finite controlled TCP loopback; separate attacker OS processes, one host and controller; original two input modes/caps and service/client policy; fixed honest schedule; actual optional paid-credit flow, no WAN/independent operator claim",
        "settings_profile":"native-public-evaluation-dev-v1 + continuity_v1 explicit maintenance","preparation":preparation,
        "economics":economics,"best_observed_cold_legal_method":work::METHODS[best],"selection_candidates_cpu_ns":candidates,
        "economics_complete":economics_complete,
        "phases":phases,"finite_experiment_criteria_met":complete,
        "work_profile_qualified":false,"cryptographic_hardness_qualified":false,"independent_operators":false,"wan_qualified":false,
        "production_candidate":false,"release_ready":false});
    support::write_new(&output.join("report.json"), &report);
    assert!(
        complete,
        "finite experiment criteria failed; full counterexample retained at {}",
        output.display()
    );
}
