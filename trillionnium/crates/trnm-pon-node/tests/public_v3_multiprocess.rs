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

#[derive(Clone, Copy)]
struct CampaignConfiguration {
    state_backend: StateBackendChoice,
    work_profile: support::WorkProfile,
}
impl CampaignConfiguration {
    fn new(
        state_backend: StateBackendChoice,
        work_profile: support::WorkProfile,
    ) -> Result<Self, &'static str> {
        if work_profile == support::WorkProfile::ArithmeticFactsV1
            && !matches!(state_backend, StateBackendChoice::AuthenticatedV1)
        {
            return Err("ARITHMETIC_CAMPAIGN_REQUIRES_AUTHENTICATED_V1");
        }
        Ok(Self {
            state_backend,
            work_profile,
        })
    }
}

fn campaign_server(work_profile: support::WorkProfile) -> (PublicServer, Option<Value>) {
    let server = PublicServer::new(support::identity(71), support::policy()).unwrap();
    if work_profile == support::WorkProfile::RawR13 {
        assert_eq!(server.resource_profile(), support::policy().id());
        assert!(server.arithmetic_facts_software_bytes().is_none());
        return (server, None);
    }
    let started = Instant::now();
    let cpu = support::cpu();
    // One new empty arithmetic owner per phase, before any service request.
    // Setup is also included in the existing receiver/verifier setup interval.
    let server = server.with_arithmetic_facts().unwrap();
    let setup_cpu_ns = support::elapsed_cpu(cpu);
    let setup_wall_ns = started.elapsed().as_nanos();
    assert_eq!(
        server.resource_profile(),
        support::policy().arithmetic_facts_id()
    );
    let software_bytes = server.arithmetic_facts_software_bytes().unwrap();
    let observation = json!({
        "schema":"public-v3-campaign-arithmetic-owner-v1",
        "initial_state":"fresh-empty-by-construction",
        "slots":pon_work::arithmetic_facts::MAX_ARITHMETIC_FACT_SLOTS,
        "retained_software_bytes":software_bytes,
        "setup_cpu_ns":setup_cpu_ns,"setup_wall_ns":setup_wall_ns,
        "scope":"one explicit server-local owner; setup nested in phase setup, not guest CPU; retained software objects, not RSS; every request's actual CPU remains paid",
        "adversarial_key_churn_service_qualified":false,
    });
    (server, Some(observation))
}

struct ClientOperationStamp {
    started_ns: u64,
    started: Instant,
    thread: thread::ThreadId,
    cpu_ns: Option<u64>,
}
impl ClientOperationStamp {
    fn start(epoch: u64) -> Self {
        Self {
            started_ns: support::monotonic().saturating_sub(epoch),
            started: Instant::now(),
            thread: thread::current().id(),
            cpu_ns: support::clock(rustix::time::ClockId::ThreadCPUTime),
        }
    }
    fn finish(self, epoch: u64) -> Value {
        let cpu_ns = (self.thread == thread::current().id())
            .then(|| support::clock(rustix::time::ClockId::ThreadCPUTime))
            .flatten()
            .zip(self.cpu_ns)
            .and_then(|(end, start)| end.checked_sub(start));
        let ended_ns = support::monotonic().saturating_sub(epoch);
        let wall_ns = u64::try_from(self.started.elapsed().as_nanos()).ok();
        json!({"started_ns":self.started_ns,"ended_ns":ended_ns,"wall_ns":wall_ns,
            "thread_cpu_ns":cpu_ns,"thread_cpu_observation_available":cpu_ns.is_some(),
            "scope":"calling client thread only; excludes scoped execution worker CPU; unknown clock is null; no deadline or acceptance authority"})
    }
}

#[derive(Clone, Copy)]
enum StateBackendChoice {
    LegacyV2,
    AuthenticatedV1,
}
impl StateBackendChoice {
    fn from_environment() -> Self {
        match std::env::var("TRNM_MULTIPROCESS_STATE_BACKEND") {
            Ok(choice) => match choice.as_str() {
                "legacy-v2" => Self::LegacyV2,
                "authenticated-v1" => Self::AuthenticatedV1,
                _ => {
                    panic!("TRNM_MULTIPROCESS_STATE_BACKEND must be legacy-v2 or authenticated-v1")
                }
            },
            Err(std::env::VarError::NotPresent) => Self::LegacyV2,
            Err(std::env::VarError::NotUnicode(_)) => {
                panic!("TRNM_MULTIPROCESS_STATE_BACKEND must be Unicode")
            }
        }
    }
    fn label(self) -> &'static str {
        match self {
            Self::LegacyV2 => "legacy-v2",
            Self::AuthenticatedV1 => "authenticated-v1",
        }
    }
    fn open(self, path: &Path, settings: Settings) -> Node {
        // The outer campaign and phase directories are create-only. Select the
        // original opener once for every fresh Node; do not migrate or retry a
        // failed authenticated namespace through the legacy implementation.
        match self {
            Self::LegacyV2 => Node::open(path, settings, 1),
            Self::AuthenticatedV1 => Node::open_with_authenticated_state(path, settings, 1),
        }
        .unwrap()
    }
}

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
        "domain_cpu_scope":"paid-envelope-v3 body digest/canonical decode, native dispatch and signed response owner CPU plus joined scoped-worker CPU; exact scheduling revision is bound by public_resource_policy; excludes reactor authentication/socket I/O, queue waiting and separate process clocks",
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
fn hostile_admission(observer: &public_v3::PublicRequestObserver, digests: &[Vec<u8>]) -> Value {
    let snapshot = observer.snapshot();
    let rows: Vec<_> = snapshot
        .records
        .iter()
        .filter(|row| {
            row.operation == Some(1)
                && row.body_digest.as_ref().is_some_and(|digest| {
                    digests.iter().any(|expected| expected.as_slice() == digest)
                })
                && row.full_work_accepted == Some(true)
                && row.dispatch_accepted == Some(false)
                && row.submit_phases.iter().any(|p| {
                    p.phase == public_v3::SubmitPhase::Admission
                        && p.completed
                        && p.accepted == Some(false)
                })
        })
        .collect();
    json!({"accepted_work_admission_refusals":rows.len(),
        "admission_cpu_ns":rows.iter().try_fold(0_u64,|sum,row|sum.checked_add(row.submit_phases.iter()
            .find(|p|p.phase==public_v3::SubmitPhase::Admission)?.thread_cpu_ns?)),
        "scope":"exact hostile bodies, valid Work followed by Admission refusal; observer has no error text, these are not all labeled ROOT"})
}
fn signed_root_response_inside(call: &Value, start: u64, end: u64, digests: &[Vec<u8>]) -> bool {
    call["started_ns"].as_u64().is_some_and(|v| v >= start)
        && call["ended_ns"].as_u64().is_some_and(|v| v <= end)
        && call["public_request_body_digest"]
            .as_str()
            .and_then(|s| hex::decode(s).ok())
            .is_some_and(|digest| digests.contains(&digest))
        && call.get("error") == Some(&Value::Null)
        && call["returned_after_window"] == false
        && call["status"] == "refused"
        && call["response"]["ok"] == false
        && call["response"]["value"]["error"] == "ROOT"
}
fn known_positive(value: &Value, keys: &[&str]) -> bool {
    keys.iter()
        .all(|key| value[key].as_u64().is_some_and(|n| n > 0))
}
fn checked_root_acquisition(value: &Value, worker: usize, method: usize) -> bool {
    let Some(attempts) = value["attempts"]
        .as_array()
        .filter(|a| !a.is_empty() && a.len() <= 4096)
    else {
        return false;
    };
    let Some(header) = value["header"]
        .as_str()
        .and_then(|s| hex::decode(s).ok())
        .and_then(|raw| Header::decode(&raw).ok())
    else {
        return false;
    };
    value["valid_work_for_root_rejection"] == true
        && value["setup_calls"] == 1
        && value["worker"] == worker
        && value["method_index"] == method
        && known_positive(
            value,
            &[
                "acquisition_cpu_ns",
                "acquisition_wall_ns",
                "diagnostic_cpu_ns",
                "diagnostic_wall_ns",
            ],
        )
        && attempts.iter().enumerate().all(|(index, row)| {
            row["nonce"] == 2_000_000 + worker as u64 * 10_000 + index as u64
                && row["target_hit"] == (index + 1 == attempts.len())
        })
        && attempts.last().unwrap()["nonce"] == header.nonce
}
fn unified_cgroup() -> String {
    fs::read_to_string("/proc/self/cgroup")
        .unwrap()
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .expect("unified cgroup")
        .to_owned()
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
    let work_profile = support::WorkProfile::from_actor_job(job)
        .expect("exact explicit actor profile, or the original raw job");
    let mut template = header(job);
    let mode = job["mode"].as_str().unwrap();
    assert!(matches!(
        mode,
        "from-zero" | "late-product" | "valid-work-root"
    ));
    let root_mode = mode == "valid-work-root";
    let acquisition_started = Instant::now();
    let acquisition_cpu = support::cpu();
    let rss_before = support::rss();
    let (attack_header, proof, attempts, setups) = if mode == "from-zero" {
        let (proof, attempts) = work::from_zero(template.clone()).unwrap();
        (template, proof, attempts, 0)
    } else {
        if root_mode {
            template.state[0] ^= 1;
        }
        let producer = work::Producer::new(job["method"].as_u64().unwrap() as usize).unwrap();
        let (header, mut proof, attempts) = work::legal_search(&producer, template).unwrap();
        if !root_mode {
            work::corrupt_product(&mut proof);
        }
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
    let mut acquisition = json!({"mode":mode,"setup_calls":setups,"attempts":attempts,
        "header":hex::encode(packet.header.encode()),"packet_digest":hex::encode(hash(b"multiprocess-attack-packet-v1", &[&wire])),
        "packet_bytes":wire.len(),"proof_digest":hex::encode(hash(b"multiprocess-observed-proof-v1", &[&packet.proof])),
        "public_request_body_digest":hex::encode(hash(b"public-request-body-v3", &[&public_body])),
        "acquisition_cpu_ns":acquisition_cpu_ns,"acquisition_wall_ns":acquisition_wall_ns,
        "rss_before":rss_before,"rss_after":support::rss(),"diagnostic_result":diagnostic,"relation_rejection_matches_mode":relation_rejection_matches_mode,
        "diagnostic_cpu_ns":diagnostic_cpu_ns,"diagnostic_wall_ns":diagnostic_wall_ns,
        "scope":"own acquisition from public header/task; includes all local setup/search records and packet encoding; diagnostic verification separate"});
    if root_mode {
        acquisition["valid_work_for_root_rejection"] = json!(diagnostic.is_ok());
        acquisition["packet_id"] = json!(hex::encode(packet.id().unwrap()));
        acquisition["worker"] = job["worker"].clone();
        acquisition["method_index"] = job["method"].clone();
    }
    // Preserve acquisition before readiness, so an interrupted actor cannot erase
    // expensive preparation or a negative relation result.
    support::write_new(&directory.join("acquisition.json"), &acquisition);
    assert!(
        if root_mode {
            diagnostic.is_ok()
        } else {
            relation_rejection_matches_mode
        },
        "own acquired input rejected at unexpected relation stage; acquisition retained"
    );
    let mut ready = json!({"pid":std::process::id(),"mode":mode});
    if root_mode {
        ready["cgroup"] = json!(unified_cgroup());
    }
    support::write_new(&directory.join("ready.json"), &ready);
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
        calls.push(support::call_with_work_profile(
            address,
            &settings,
            Request::Submit {
                packet: packet_hex.clone(),
            },
            who,
            epoch,
            end,
            work_profile,
        ));
    }
    let mut result = json!({"pid":std::process::id(),"worker":worker,"mode":mode,"acquisition":acquisition,
        "calls":calls,"attempt_cap_reached":calls.len()==CALL_CAP,
        "traffic_cpu_ns":support::elapsed_cpu(traffic_cpu),"traffic_wall_ns":traffic_started.elapsed().as_nanos(),
        "entire_actor_cpu_ns":support::elapsed_cpu(process_cpu),"entire_actor_wall_ns":entire.elapsed().as_nanos(),
        "rss":support::rss(),"identity_scope":"development keys controlled by this experiment; rotating keys are not independent operators"});
    work_profile.bind_actor_job(&mut result);
    result
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
    configuration: CampaignConfiguration,
) -> Value {
    let CampaignConfiguration {
        state_backend,
        work_profile,
    } = configuration;
    fs::create_dir(path).unwrap();
    let root_mode = mode == Some("valid-work-root");
    let controller_cgroup = root_mode.then(unified_cgroup);
    let whole_started = Instant::now();
    let whole_cpu = support::cpu();
    let setup_started = Instant::now();
    let setup_cpu = support::cpu();
    let mut receiver = state_backend.open(&path.join("receiver"), settings.clone());
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
    let mut verifier = state_backend.open(&path.join("independent-client"), settings.clone());
    replay(&mut verifier, seed);
    let initial = receiver.read_active().unwrap();
    let native_history_before = receiver.native_history_arithmetic_observation();
    let client_native_history_before = verifier.native_history_arithmetic_observation();
    let owner = Arc::new(Mutex::new(receiver));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let metrics = Arc::new(Mutex::new(public_v3::PublicMetrics::default()));
    let live_metrics = metrics.clone();
    let observer = public_v3::PublicRequestObserver::new(16_384).unwrap();
    let (server, arithmetic_owner) = campaign_server(work_profile);
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
            let mut job = json!({"kind":"attack","mode":mode,"method":method,
            "worker":worker,"address":address.to_string(),"header":hex::encode(template.encode()),
            "transactions":business[0].transactions.iter().map(hex::encode).collect::<Vec<_>>(),"start_marker":marker});
            work_profile.bind_actor_job(&mut job);
            actors.push(Actor::spawn(
                &path.join(format!("attacker-{worker:02}")),
                job,
            ));
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
    let root_readiness: Vec<Value> = if root_mode {
        actors
            .iter()
            .map(|actor| {
                fs::read(&actor.ready)
                    .ok()
                    .and_then(|raw| serde_json::from_slice(&raw).ok())
                    .unwrap_or(Value::Null)
            })
            .collect()
    } else {
        Vec::new()
    };
    let root_acquisitions: Vec<Value> = if root_mode {
        actors
            .iter()
            .map(|actor| {
                fs::read(actor.ready.parent().unwrap().join("acquisition.json"))
                    .ok()
                    .and_then(|raw| serde_json::from_slice::<Value>(&raw).ok())
                    .unwrap_or(Value::Null)
            })
            .collect()
    } else {
        Vec::new()
    };
    let root_packet_ids: Vec<[u8; 32]> = root_acquisitions
        .iter()
        .filter(|v| v["valid_work_for_root_rejection"] == true)
        .filter_map(|v| hex::decode(v["packet_id"].as_str()?).ok()?.try_into().ok())
        .collect();
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
    // Capture the Rust deadline once, just before the existing measured epoch.
    // It can only be earlier than that same 30-second pressure end; imports
    // must not acquire another 30 seconds when each History page arrives.
    let import_deadline = Instant::now() + Duration::from_secs(WINDOW_SECONDS);
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
            // Separate optional diagnostic, after the original sample interval.
            // It neither refills credit nor changes the original predicate.
            let freshness_started_ns = support::monotonic().saturating_sub(epoch);
            let credit_freshness = sample_domain
                .observe_credit_freshness()
                .map_err(|error| error.to_string());
            let freshness_ended_ns = support::monotonic().saturating_sub(epoch);
            sampling.lock().unwrap().push(json!({"at_ns":observation_ended_ns,"observation_started_ns":observation_started_ns,
                "observation_ended_ns":observation_ended_ns,"meter":observation,"attacker_process_rss":support::live_children_rss(&pids),
                "credit_freshness_started_ns":freshness_started_ns,"credit_freshness_ended_ns":freshness_ended_ns,
                "credit_freshness":credit_freshness}));
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
            let root_before = root_mode.then(|| hostile_admission(&observer, &hostile_digests));
            let final_index = (round + 1) * 7;
            while next < final_index && support::monotonic() < end && submissions.len() < 128 {
                let mut row = support::call_with_work_profile(
                    address,
                    settings,
                    Request::Submit {
                        packet: hex::encode(business[next].encode().unwrap()),
                    },
                    73,
                    epoch,
                    end,
                    work_profile,
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
                let mut row = support::call_with_work_profile(
                    address,
                    settings,
                    Request::History {
                        tip: hex::encode(tip),
                        after: hex::encode(after),
                    },
                    74,
                    epoch,
                    end,
                    work_profile,
                );
                if support::on_time(&row) {
                    let import_stamp = ClientOperationStamp::start(epoch);
                    let imported =
                        serde_json::from_value::<ingress::Page>(row["response"]["value"].clone())
                            .map_err(|e| e.to_string())
                            .and_then(|page| {
                                ingress::receive_public_page_from_before(
                                    &mut verifier,
                                    address,
                                    page,
                                    tip,
                                    after,
                                    support::now(),
                                    import_deadline,
                                )
                                .map_err(|e| e.to_string())
                            });
                    row["client_import"] = import_stamp.finish(epoch);
                    row["client_import"]["operation"] = json!(
                        "deserialize Page and ordinary receive_page, including activation only on the original complete page"
                    );
                    row["client_import"]["succeeded"] = json!(imported.is_ok());
                    match imported {
                        Ok(next_after) => after = next_after,
                        Err(error) => errors.push(error),
                    }
                    if after == tip {
                        let confirmation_stamp = ClientOperationStamp::start(epoch);
                        let result = verifier.confirmation(transaction, included, support::now());
                        row["client_confirmation"] = confirmation_stamp.finish(epoch);
                        row["client_confirmation"]["operation"] =
                            json!("ordinary verifier confirmation after the original complete-page activation");
                        row["client_confirmation"]["succeeded"] = json!(result.is_ok());
                        match result {
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
            let root_after = root_mode.then(|| hostile_admission(&observer, &hostile_digests));
            // Live snapshots are not atomic. ROOT evidence conservatively ends
            // after both snapshots, still inside the original fixed phase end.
            let ended = if root_mode {
                support::monotonic().saturating_sub(epoch)
            } else {
                ended
            };
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
            if let Some((before, after)) = root_before.zip(root_after) {
                let progressed = ["accepted_work_admission_refusals", "admission_cpu_ns"]
                    .iter()
                    .all(|key| {
                        before[key]
                            .as_u64()
                            .zip(after[key].as_u64())
                            .is_some_and(|(a, b)| b > a)
                    });
                let row = confirmations.last_mut().unwrap();
                row["receiver_hostile_admission_before"] = before;
                row["receiver_hostile_admission_after"] = after;
                row["accepted_work_admission_refusal_during_round"] = json!(progressed);
            }
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
    // Diagnostic snapshots after the original service window. They do not
    // change any workload, deadline, budget, confirmation or success criterion.
    let native_history_after = owner
        .lock()
        .ok()
        .map(|node| node.native_history_arithmetic_observation());
    let client_native_history_after = verifier.native_history_arithmetic_observation();
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
    let observer_complete = captured.coverage_complete();
    let common_criteria = all_confirmed
        && actual.0 == checked.0
        && actual.2 == checked.2
        && observer_complete
        && service_outcome.get("Ok").is_some()
        && service_outcome["Ok"]["mutation_cpu_clock_failures"] == 0
        && final_meter.in_flight == 0
        && !final_meter.accounting_unavailable
        && errors.is_empty();
    let phase_criteria = !root_mode
        && common_criteria
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
    let mut report = json!({"mode":mode.unwrap_or("baseline"),"state_backend":state_backend.label(),"address":address.to_string(),"duration_seconds":WINDOW_SECONDS,
        "attacker_processes_requested":if mode.is_some(){ATTACKERS}else{0},"attacker_processes_ready":ready_count,
        "depletion_at_ns":depletion_at,"depletion_meter":depletion_meter,"genuine_budget_depletion_observed":depletion_at.is_some(),"business_started_ns":business_started,
        "receiver_and_verifier_setup_cpu_ns":receiver_and_verifier_setup_cpu_ns,"receiver_and_verifier_setup_wall_ns":receiver_and_verifier_setup_wall_ns,
        "submissions":submissions,"history":history,"confirmations":confirmations,"all_signed_rounds_confirmed_in_window":all_confirmed,
        "verifier_errors":errors,"children":children,"service_outcome":service_outcome,"receiver_observation":captured,
        "native_history_arithmetic_before":native_history_before,"native_history_arithmetic_after":native_history_after,
        "observer_complete":observer_complete,"full_work_failed":relation_failed,"full_work_accepted":relation_accepted,
        "actor_reports_successful_without_cap_or_kill":successful_actors,"attack_calls_overlapping_each_signed_round":overlaps,
        "children_os_usage_before":children_usage_before,"children_os_usage_after":children_usage_after,
        "finite_phase_criteria_met":phase_criteria,
        "budget_samples":budget_samples,"initial_meter":initial_meter,"final_meter":final_meter,
        "final_actual_flow":domain.observe_actual_flow().ok().flatten(),
        "receiver_client_state_equal":actual.0==checked.0&&actual.2==checked.2,
        "initial_tip":hex::encode(initial.0),"final_receiver_tip":hex::encode(actual.0),"final_client_tip":hex::encode(checked.0),
        "whole_parent_phase_cpu_ns":support::elapsed_cpu(whole_cpu),"whole_parent_phase_wall_ns":whole_started.elapsed().as_nanos(),"rss":support::rss()});
    report["public_resource_policy"] = work_profile.policy_observation();
    if let Some(arithmetic_owner) = arithmetic_owner {
        report["work_profile"] = json!("arithmetic-facts-v1");
        report["work_arithmetic_owner"] = arithmetic_owner;
    }
    report["completion_work_observation"] = json!(domain.observe_completion_work().ok());
    report["client_native_history_arithmetic_before"] = client_native_history_before;
    report["client_native_history_arithmetic_after"] = client_native_history_after;
    report["client_observation_scope"] = json!("bounded by the original 64 history calls; import includes complete-page activation, confirmation is separate; native snapshots exclude setup and final read_active; nested costs are not additive");
    if root_mode {
        // Concurrent mutations share this domain. Reconcile the entire closed
        // domain, never attribute overlapping paid deltas to individual calls.
        let flow = domain.observe_actual_flow().unwrap();
        let owner_cpu = captured
            .records
            .iter()
            .filter(|row| row.operation == Some(1) && row.dispatch_started)
            .try_fold(0_u64, |sum, row| {
                sum.checked_add(row.dispatch_thread_cpu_ns?)
            });
        let settled = flow.as_ref().is_some_and(|f| {
            f.balance_identity_verified
                && f.live_owners == 0
                && f.booked_reservation_ns == 0
                && f.unsettled_known_live_cpu_ns == 0
                && f.paid_cpu_debit_ns > 0
                && f.paid_cpu_debit_ns == f.settled_full_cpu_ns
                && Some(f.paid_cpu_debit_ns) == owner_cpu
                && service_outcome["Ok"]["mutation_cpu_charged_ns"].as_u64() == owner_cpu
        });
        let membership = root_readiness.len() == ATTACKERS
            && root_readiness
                .iter()
                .all(|r| r["cgroup"].as_str() == controller_cgroup.as_deref());
        let acquisition_complete = root_acquisitions.len() == ATTACKERS
            && children.len() == ATTACKERS
            && root_acquisitions
                .iter()
                .zip(children.iter())
                .zip(root_readiness.iter())
                .enumerate()
                .all(|(worker, ((acquisition, child), ready))| {
                    let result = &child["report"]["result"];
                    checked_root_acquisition(acquisition, worker, method)
                        && result["acquisition"] == *acquisition
                        && result["worker"] == worker
                        && result["pid"] == child["pid"]
                        && ready["pid"] == child["pid"]
                        && result["calls"].as_array().is_some_and(|calls| {
                            !calls.is_empty()
                                && calls.iter().all(|call| {
                                    call["public_request_body_digest"]
                                        == acquisition["public_request_body_digest"]
                                })
                        })
                })
            && root_packet_ids
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                == ATTACKERS
            && hostile_digests
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                == ATTACKERS
            && root_acquisitions
                .iter()
                .filter_map(|v| v["header"].as_str())
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                == ATTACKERS;
        for round in report["confirmations"].as_array_mut().unwrap() {
            let start = round["started_ns"].as_u64().unwrap();
            let end = round["ended_ns"].as_u64().unwrap();
            round["signed_root_responses_inside_round"] = json!(attack_calls
                .iter()
                .filter(|call| signed_root_response_inside(call, start, end, &hostile_digests))
                .count());
        }
        let final_stats = owner.lock().unwrap().stats().unwrap();
        let absent = |node: &Node| {
            root_packet_ids.len() == ATTACKERS
                && root_packet_ids.iter().all(|id| {
                    node.packet(*id)
                        .err()
                        .is_some_and(|e| e.to_string() == "UNKNOWN_PARENT")
                })
        };
        let live_absent = absent(&owner.lock().unwrap());
        drop(owner);
        let reopened = state_backend.open(&path.join("receiver"), settings.clone());
        let cold_equal =
            reopened.read_active().unwrap() == actual && reopened.stats().unwrap() == final_stats;
        let cold_absent = absent(&reopened);
        let expected_tip = business.last().unwrap().id().unwrap();
        let expected_counts = final_stats["stored_blocks"] == 26
            && final_stats["events"] == 25
            && final_stats["height"] == 25
            && actual.0 == expected_tip;
        let root_criteria = common_criteria
            && depletion_at.is_some()
            && ready_count == ATTACKERS
            && successful_actors
            && membership
            && acquisition_complete
            && settled
            && hostile_digests.len() == ATTACKERS
            && overlaps.len() == ROUNDS
            && overlaps.iter().all(|n| *n > 0)
            && report["confirmations"].as_array().unwrap().iter().all(|r| {
                r["accepted_work_admission_refusal_during_round"] == true
                    && r["signed_root_responses_inside_round"]
                        .as_u64()
                        .is_some_and(|n| n > 0)
            })
            && report["confirmations"]
                .as_array()
                .unwrap()
                .iter()
                .any(|r| r["paid_credit_depletion_observed_during_round"] == true)
            && attack_calls.iter().all(|r| r["status"] != "ok")
            && live_absent
            && cold_absent
            && cold_equal
            && expected_counts;
        report["root_supplement"] = json!({"criteria_met":root_criteria,
            "controller_cgroup":controller_cgroup,"actor_readiness":root_readiness,"aggregate_membership_verified":membership,
            "checked_acquisitions_complete":acquisition_complete,"acquisitions":root_acquisitions,
            "whole_domain_paid_reconciled":settled,"mutation_owner_cpu_ns":owner_cpu,
            "aggregate_scoped_cpu_ns":flow.as_ref().zip(owner_cpu).and_then(|(f,c)|f.paid_cpu_debit_ns.checked_sub(c)),
            "hostile_packet_ids":root_packet_ids.iter().map(hex::encode).collect::<Vec<_>>(),
            "hostile_packets_absent_live":live_absent,"hostile_packets_absent_cold":cold_absent,
            "cold_state_equal":cold_equal,"expected_legal_counts_and_tip":expected_counts,"final_stats":final_stats,
            "final_state_rows":actual.2.iter().map(|(k,v)|(hex::encode(k),hex::encode(serde_json::to_vec(v).unwrap()))).collect::<Vec<_>>(),
            "scope":"whole-domain paid CPU includes honest and hostile Submit; known zero scoped CPU from one M06 worker; ROOT reply evidence and observer refusal evidence are separate; cold reopen is after the window",
            "round_snapshot_scope":"live observer snapshots are non-atomic; ROOT round end follows the last after snapshot and must remain before the fixed phase end",
            "original_campaign_qualified":false});
    }
    report
}

#[test]
fn arithmetic_campaign_profile_binding_preserves_raw_and_rejects_partial_actor_jobs() {
    use support::WorkProfile::{ArithmeticFactsV1, RawR13};
    let original = json!({"kind":"attack","mode":"from-zero","worker":0});
    let original_bytes = serde_json::to_vec(&original).unwrap();
    let mut raw = original.clone();
    RawR13.bind_actor_job(&mut raw);
    assert_eq!(serde_json::to_vec(&raw).unwrap(), original_bytes);
    assert_eq!(support::WorkProfile::from_actor_job(&raw), Ok(RawR13));
    assert_eq!(RawR13.policy_observation(), support::policy_observation());
    assert_eq!(
        RawR13.policy_observation()["policy_id"],
        "c110c3ccb1e229c3a85f4819b1e087fa819c865b50f8bd3ab78d3b8f45206cb2"
    );
    let mut opt_in = original;
    ArithmeticFactsV1.bind_actor_job(&mut opt_in);
    assert_eq!(
        support::WorkProfile::from_actor_job(&opt_in),
        Ok(ArithmeticFactsV1)
    );
    assert_eq!(
        opt_in["public_resource_policy"]["policy_id"],
        "14ada27ef062b1e510b7d7ab470e83157e58e7752b8f27a754f64dac614146e3"
    );
    let mut malformed = Vec::new();
    for key in ["work_profile", "public_resource_policy"] {
        let mut missing = opt_in.clone();
        missing.as_object_mut().unwrap().remove(key);
        malformed.push(missing);
        let mut null = opt_in.clone();
        null[key] = Value::Null;
        malformed.push(null);
    }
    let mut unknown = opt_in.clone();
    unknown["work_profile"] = json!("raw-r13");
    malformed.push(unknown);
    let mut wrong_policy = opt_in.clone();
    wrong_policy["public_resource_policy"] = RawR13.policy_observation();
    malformed.push(wrong_policy);
    let mut wrong_bits = opt_in.clone();
    wrong_bits["public_resource_policy"]["ticket_bits"] = json!(7);
    malformed.push(wrong_bits);
    let mut extra_policy_field = opt_in;
    extra_policy_field["public_resource_policy"]["ignore_profile"] = json!(true);
    malformed.push(extra_policy_field);
    for job in malformed {
        assert_eq!(
            support::WorkProfile::from_actor_job(&job),
            Err("MULTIPROCESS_WORK_PROFILE")
        );
    }
}

#[test]
fn arithmetic_campaign_configuration_requires_the_original_measured_backend() {
    use support::WorkProfile::{ArithmeticFactsV1, RawR13};
    for backend in [
        StateBackendChoice::LegacyV2,
        StateBackendChoice::AuthenticatedV1,
    ] {
        let raw = CampaignConfiguration::new(backend, RawR13).unwrap();
        assert_eq!(raw.state_backend.label(), backend.label());
        assert_eq!(raw.work_profile, RawR13);
    }
    assert!(matches!(
        CampaignConfiguration::new(StateBackendChoice::LegacyV2, ArithmeticFactsV1),
        Err("ARITHMETIC_CAMPAIGN_REQUIRES_AUTHENTICATED_V1")
    ));
    let opt_in =
        CampaignConfiguration::new(StateBackendChoice::AuthenticatedV1, ArithmeticFactsV1).unwrap();
    assert_eq!(opt_in.state_backend.label(), "authenticated-v1");
    assert_eq!(opt_in.work_profile, ArithmeticFactsV1);
}

#[test]
fn arithmetic_campaign_server_routing_does_not_change_cpu_capacity() {
    let (raw, no_arithmetic) = campaign_server(support::WorkProfile::RawR13);
    let (opt_in, arithmetic) = campaign_server(support::WorkProfile::ArithmeticFactsV1);
    assert!(no_arithmetic.is_none());
    assert!(raw.arithmetic_facts_software_bytes().is_none());
    assert_ne!(raw.resource_profile(), opt_in.resource_profile());
    let arithmetic = arithmetic.unwrap();
    assert_eq!(arithmetic["slots"], 64);
    assert_eq!(arithmetic["initial_state"], "fresh-empty-by-construction");
    assert_eq!(arithmetic["adversarial_key_churn_service_qualified"], false);
    let charged = opt_in.arithmetic_facts_software_bytes().unwrap();
    assert_eq!(arithmetic["retained_software_bytes"], json!(charged));
    assert!(
        charged > 0 && charged <= pon_work::arithmetic_facts::MAX_ARITHMETIC_FACT_SOFTWARE_BYTES
    );
    for server in [&raw, &opt_in] {
        let meter = server.mutation_cpu_domain().observe().unwrap();
        assert_eq!(meter.burst_ns, 2_000_000_000);
        assert_eq!(meter.refill_ns_per_second, 250_000_000);
        assert_eq!(meter.start_reserve_ns, 100_000_000);
        assert_eq!(meter.worker_limit, 2);
        assert_eq!(meter.stored_credit_ns, 2_000_000_000);
        assert_eq!(meter.in_flight, 0);
    }
}

#[test]
#[ignore = "explicit finite 3x30 second separate-process local campaign and producer cost; see retained report"]
fn separate_process_work_and_signed_confirmation_campaign() {
    run_campaign(support::WorkProfile::RawR13);
}

#[test]
#[ignore = "explicit arithmetic-facts profile; same original finite 3x30 second workload, CPU and confirmation criteria; no r13 or arbitrary-key qualification"]
fn separate_process_arithmetic_facts_and_signed_confirmation_campaign() {
    run_campaign(support::WorkProfile::ArithmeticFactsV1);
}

fn run_campaign(work_profile: support::WorkProfile) {
    let state_backend = StateBackendChoice::from_environment();
    let configuration = CampaignConfiguration::new(state_backend, work_profile).unwrap();
    let output = PathBuf::from(
        std::env::var_os("TRNM_MULTIPROCESS_REPORT_DIR").expect("explicit new report directory"),
    );
    fs::create_dir(&output).unwrap();
    let outcome = std::panic::catch_unwind(|| campaign(&output, configuration));
    if let Err(error) = outcome {
        let message = error
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| error.downcast_ref::<&str>().map(|s| s.to_string()))
            .unwrap_or_else(|| "non-string panic".to_owned());
        let mut failure = json!({"error":message,"state_backend":state_backend.label(),"production_candidate":false,"release_ready":false,
            "scope":"actual finite experiment failure; independently retained stage and child files remain evidence"});
        work_profile.bind_actor_job(&mut failure);
        support::write_new(&output.join("campaign-failure.json"), &failure);
        panic!("campaign failed; retained {}", output.display());
    }
}
fn signed_campaign_seed(miner: &mut Node, settings: &Settings) -> Vec<Packet> {
    let mut seed = Vec::new();
    // Real funded accounts and full signed execution, not injected SQL/state or
    // a cheap verifier fixture. All processes still use the original CPU budget.
    for block in 0..4_u64 {
        let transactions = (0..256_u64)
            .map(|slot| {
                let nonce = block * 256 + slot + 1;
                support::signed_transfer(
                    settings,
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
        replay(miner, std::slice::from_ref(&packet));
        seed.push(packet);
    }
    seed
}

fn signed_campaign_business(miner: &mut Node, settings: &Settings) -> Vec<Packet> {
    let mut business = Vec::new();
    for index in 0..ROUNDS * 7 {
        let transactions = if index % 7 == 0 {
            vec![support::signed_transfer(
                settings,
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
        replay(miner, std::slice::from_ref(&packet));
        business.push(packet);
    }
    business
}

fn campaign(output: &Path, configuration: CampaignConfiguration) {
    let CampaignConfiguration {
        state_backend,
        work_profile,
    } = configuration;
    eprintln!("P0 native campaign: honest 1024 signed transfers and 21 business blocks");
    let settings = support::settings();
    let preparation_started = Instant::now();
    let preparation_cpu = support::cpu();
    let mut miner = state_backend.open(&output.join("honest-miner"), settings.clone());
    let seed = signed_campaign_seed(&mut miner, &settings);
    let business = signed_campaign_business(&mut miner, &settings);
    let preparation = json!({"state_backend":state_backend.label(),"cpu_ns":support::elapsed_cpu(preparation_cpu),"wall_ns":preparation_started.elapsed().as_nanos(),
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
        let mut result=std::panic::catch_unwind(||phase(&output.join(mode.unwrap_or("baseline")),&settings,&seed,&business,mode,best,configuration))
            .unwrap_or_else(|error|{let message=error.downcast_ref::<String>().cloned().or_else(||error.downcast_ref::<&str>().map(|s|s.to_string())).unwrap_or_else(||"non-string panic".to_owned());
                json!({"mode":mode.unwrap_or("baseline"),"state_backend":state_backend.label(),"startup_or_campaign_error":message,"all_signed_rounds_confirmed_in_window":false,"genuine_budget_depletion_observed":false})});
        if work_profile == support::WorkProfile::ArithmeticFactsV1
            && result.get("public_resource_policy").is_none()
        {
            work_profile.bind_actor_job(&mut result);
        }
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
    let mut report = json!({"schema":"native-public-v3-separate-process-campaign-v2","scope":"finite controlled TCP loopback; separate attacker OS processes, one host and controller; original two input modes/caps and service/client policy; fixed honest schedule; actual optional paid-credit flow, no WAN/independent operator claim",
        "state_backend":state_backend.label(),
        "settings_profile":"native-public-evaluation-dev-v1 + continuity_v1 explicit maintenance","preparation":preparation,
        "economics":economics,"best_observed_cold_legal_method":work::METHODS[best],"selection_candidates_cpu_ns":candidates,
        "economics_complete":economics_complete,
        "phases":phases,"finite_experiment_criteria_met":complete,
        "work_profile_qualified":false,"cryptographic_hardness_qualified":false,"independent_operators":false,"wan_qualified":false,
        "production_candidate":false,"release_ready":false});
    report["public_resource_policy"] = work_profile.policy_observation();
    if work_profile == support::WorkProfile::ArithmeticFactsV1 {
        report["schema"] = json!("native-public-v3-arithmetic-facts-separate-process-campaign-v1");
        report["work_profile"] = json!("arithmetic-facts-v1");
        report["scope"] = json!("explicit arithmetic-facts profile; same original finite controlled TCP loopback workload, raw producer/attack construction, CPU/deadline/cap/confirmation/depletion criteria; fresh server-local owner per phase; work observations separate actual recomputation from reused mathematical facts; not original r13, arbitrary-key service, WAN or independent-operator qualification");
        report["original_r13_campaign_qualified"] = json!(false);
        report["adversarial_key_churn_service_qualified"] = json!(false);
    }
    support::write_new(&output.join("report.json"), &report);
    assert!(
        complete,
        "finite experiment criteria failed; full counterexample retained at {}",
        output.display()
    );
}

#[test]
#[ignore = "explicit single 30s baseline + 30s ROOT supplement; use the pinned resource runner"]
fn separate_process_root_rejection_and_signed_confirmation_supplement() {
    let output = PathBuf::from(
        std::env::var_os("TRNM_ROOT_SUPPLEMENT_REPORT_DIR")
            .expect("explicit fresh supplemental report directory"),
    );
    fs::create_dir(&output).unwrap();
    let setup_started = Instant::now();
    let setup_cpu = support::cpu();
    let settings = support::settings();
    let backend = StateBackendChoice::AuthenticatedV1;
    let mut producer = backend.open(&output.join("honest-miner"), settings.clone());
    let seed = signed_campaign_seed(&mut producer, &settings);
    let business = signed_campaign_business(&mut producer, &settings);
    assert_eq!(seed.len(), 4);
    assert!(seed.iter().all(|p| p.transactions.len() == 256));
    assert_eq!(business.len(), 21);
    assert_eq!(business[0].header.parent, seed[3].id().unwrap());
    assert_eq!(business[0].header.height, 5);
    assert_eq!(business[0].transactions.len(), 1);
    assert_eq!(
        trnm_protocol::pon_wire::Envelope::decode(&business[0].transactions[0])
            .unwrap()
            .nonce,
        1025
    );
    let expected = producer.read_active().unwrap();
    let expected_stats = producer.stats().unwrap();
    let expected_rows: Vec<_> = expected
        .2
        .iter()
        .map(|(k, v)| (hex::encode(k), hex::encode(serde_json::to_vec(v).unwrap())))
        .collect();
    let preparation = json!({"cpu_ns":support::elapsed_cpu(setup_cpu),"wall_ns":setup_started.elapsed().as_nanos(),
        "seed_packets":seed.iter().map(|p|hex::encode(p.encode().unwrap())).collect::<Vec<_>>(),
        "business_packets":business.iter().map(|p|hex::encode(p.encode().unwrap())).collect::<Vec<_>>(),
        "expected_stats":expected_stats,"expected_state_rows":expected_rows,
        "scope":"all real signing, Node search attempts, execution and durable reference preparation; Node search denominator unavailable; no injected State"});
    support::write_new(&output.join("preparation.json"), &preparation);
    drop(producer);
    let mut phases = Vec::new();
    for mode in [None, Some("valid-work-root")] {
        let name = mode.unwrap_or("baseline");
        let configuration =
            CampaignConfiguration::new(backend, support::WorkProfile::RawR13).unwrap();
        let result = std::panic::catch_unwind(||phase(&output.join(name),&settings,&seed,&business,mode,0,configuration))
            .unwrap_or_else(|error|json!({"mode":name,"startup_or_campaign_error":error.downcast_ref::<String>()
                .cloned().or_else(||error.downcast_ref::<&str>().map(|s|s.to_string())).unwrap_or_else(||"non-string panic".to_owned())}));
        support::write_new(&output.join(format!("{name}.json")), &result);
        phases.push(result);
    }
    let root = &phases[1]["root_supplement"];
    let producer_state_equal =
        root["final_stats"] == expected_stats && root["final_state_rows"] == json!(expected_rows);
    let preparation_known = known_positive(&preparation, &["cpu_ns", "wall_ns"]);
    let passed = preparation_known
        && phases[0]["finite_phase_criteria_met"] == true
        && root["criteria_met"] == true
        && producer_state_equal;
    support::write_new(
        &output.join("report.json"),
        &json!({
        "schema":"native-public-v3-root-supplement-v1","supplemental_criteria_met":passed,
        "state_backend":"authenticated-v1","m06_workers":1,"producer_method":work::METHODS[0],
        "seed_transfers":1024,"seed_blocks":4,"business_blocks":21,"phase_seconds":30,
        "actor_call_cap":CALL_CAP,"planned_complete_runs":1,"producer_state_equal":producer_state_equal,"preparation_cost_known":preparation_known,
        "preparation":preparation,"phases":phases,
        "scope":"one predeclared same-host baseline and ROOT cohort; signed client ROOT replies separate from observer Admission refusals; not the original cheap-proof campaign",
        "original_campaign_qualified":false,"work_profile_qualified":false,"independent_operators":false,
        "wan_qualified":false,"production_candidate":false,"production_activation":false}),
    );
    assert!(
        passed,
        "supplemental criteria failed; preserve {}",
        output.display()
    );
}

#[test]
fn root_acquisition_receipt_refuses_unknown_cost_and_incomplete_search() {
    let mut header = public_work_header();
    header.nonce = 2_000_000;
    let receipt = json!({"valid_work_for_root_rejection":true,"setup_calls":1,"worker":0,"method_index":0,
        "header":hex::encode(header.encode()),"attempts":[{"nonce":2_000_000,"target_hit":true}],
        "acquisition_cpu_ns":1,"acquisition_wall_ns":2,"diagnostic_cpu_ns":3,"diagnostic_wall_ns":4});
    assert!(checked_root_acquisition(&receipt, 0, 0));
    for key in [
        "acquisition_cpu_ns",
        "acquisition_wall_ns",
        "diagnostic_cpu_ns",
        "diagnostic_wall_ns",
    ] {
        for missing in [Value::Null, json!(0)] {
            let mut bad = receipt.clone();
            bad[key] = missing;
            assert!(!checked_root_acquisition(&bad, 0, 0));
        }
    }
    for attempts in [
        json!([]),
        json!([{"nonce":2_000_000,"target_hit":false}]),
        json!([{"nonce":2_000_001,"target_hit":true}]),
        json!([{"nonce":2_000_000,"target_hit":true},{"nonce":2_000_001,"target_hit":true}]),
    ] {
        let mut bad = receipt.clone();
        bad["attempts"] = attempts;
        assert!(!checked_root_acquisition(&bad, 0, 0));
    }
    assert!(!checked_root_acquisition(&receipt, 1, 0));
    assert!(!checked_root_acquisition(&receipt, 0, 1));
    assert!(!known_positive(
        &json!({"cpu_ns":null,"wall_ns":1}),
        &["cpu_ns", "wall_ns"]
    ));
}

#[test]
fn root_reply_overlap_requires_signed_refusal_inside_the_whole_window() {
    let digests = vec![vec![7; 32]];
    let row = json!({"started_ns":10,"ended_ns":20,"status":"refused","error":null,"returned_after_window":false,
        "public_request_body_digest":hex::encode(&digests[0]),"response":{"ok":false,"value":{"error":"ROOT"}}});
    assert!(signed_root_response_inside(&row, 10, 20, &digests));
    assert!(!signed_root_response_inside(&row, 11, 20, &digests));
    assert!(!signed_root_response_inside(&row, 10, 19, &digests));
    assert!(!signed_root_response_inside(&row, 10, 20, &[]));
    for error in [
        "PUBLIC_MUTATION_CPU_BUDGET",
        "PUBLIC_CLIENT_DEADLINE",
        "Product",
    ] {
        let mut other = row.clone();
        other["response"]["value"]["error"] = json!(error);
        assert!(!signed_root_response_inside(&other, 10, 20, &digests));
    }
    let mut unknown = row;
    unknown["ended_ns"] = Value::Null;
    assert!(!signed_root_response_inside(&unknown, 10, 20, &digests));
}

#[test]
fn valid_work_state_root_replays_are_paid_without_admission() {
    root_replay_component_cost(false);
}

#[test]
#[ignore = "explicit fixed 1024-signed-seed component cost; not a saturation campaign"]
fn signed_seed_state_root_replay_component_cost() {
    root_replay_component_cost(true);
}

// Keep the original eight-transaction/two-worker regression and its positive
// scoped-worker assertion. The additional fixture uses the original campaign's
// exact four seed blocks and first business transaction, with one M06 worker.
fn root_replay_component_cost(signed_seed: bool) {
    let output = std::env::var_os("TRNM_CI_RECEIPT_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| tempfile::tempdir().unwrap().keep())
        .join(if signed_seed {
            "signed-seed-root-component-cost"
        } else {
            "valid-work-root-rejection"
        });
    fs::create_dir(&output).unwrap();
    let preparation_started = Instant::now();
    let preparation_cpu = support::cpu();
    let settings = support::settings();
    let workers = if signed_seed { 1 } else { 2 };
    let open =
        |path: &Path| Node::open_with_authenticated_state(path, settings.clone(), workers).unwrap();
    let setup_started = Instant::now();
    let setup_cpu = support::cpu();
    let mut producer = open(&output.join("producer"));
    let seed = if signed_seed {
        signed_campaign_seed(&mut producer, &settings)
    } else {
        Vec::new()
    };
    let producer_setup_cost = json!({"cpu_ns":support::elapsed_cpu(setup_cpu),
        "wall_ns":setup_started.elapsed().as_nanos(),"seed_blocks":seed.len(),
        "signed_seed_transfers":seed.iter().map(|p|p.transactions.len()).sum::<usize>(),
        "scope":"fresh owner open; all actual seed signing, search, execution and durable replay; Node search attempt counts unavailable, not omitted from CPU"});
    support::write_new(&output.join("producer-setup.json"), &producer_setup_cost);
    let reference_started = Instant::now();
    let reference_cpu = support::cpu();
    let transactions = if signed_seed {
        vec![support::signed_transfer(
            &settings,
            1025,
            development_public(1).unwrap(),
        )]
    } else {
        (1..=8)
            .map(|sequence| {
                support::signed_transfer(&settings, sequence, development_public(1).unwrap())
            })
            .collect()
    };
    let reference = producer
        .make_consensus_maintenance(
            producer.active().unwrap().0,
            transactions,
            development_public(0).unwrap(),
            settings.genesis_time() + if signed_seed { 50 } else { 10 },
            4096,
        )
        .unwrap();
    let reference_cost = json!({"cpu_ns":support::elapsed_cpu(reference_cpu),
        "wall_ns":reference_started.elapsed().as_nanos(),"attempt_count":null,
        "scope":"actual reference construction; Node does not expose its search denominator"});
    let reference_accept_started = Instant::now();
    let reference_accept_cpu = support::cpu();
    replay(&mut producer, std::slice::from_ref(&reference));
    let expected = producer.read_active().unwrap();
    let expected_stats = producer.stats().unwrap();
    drop(producer);
    let reference_accept_cost = json!({"cpu_ns":support::elapsed_cpu(reference_accept_cpu),
        "wall_ns":reference_accept_started.elapsed().as_nanos(),
        "scope":"producer reference replay, expected-state readback and close; includes legal commit, not ROOT-refusal cost"});
    if signed_seed {
        assert_eq!(seed.len(), 4);
        assert!(seed.iter().all(|p| p.transactions.len() == 256));
        assert_eq!(seed.last().unwrap().header.height, 4);
        assert_eq!(reference.header.parent, seed.last().unwrap().id().unwrap());
        assert_eq!(reference.header.height, 5);
        assert_eq!(reference.transactions.len(), 1);
        assert_eq!(
            trnm_protocol::pon_wire::Envelope::decode(&reference.transactions[0])
                .unwrap()
                .nonce,
            1025
        );
    }
    let mut wrong_header = reference.header.clone();
    wrong_header.state[0] ^= 1;
    let acquisition_started = Instant::now();
    let acquisition_cpu = support::cpu();
    let search = work::Producer::new(0)
        .map_err(|error| format!("{error:?}"))
        .and_then(|producer| work::legal_search(&producer, wrong_header));
    let acquisition = json!({"method":work::METHODS[0],"cpu_ns":support::elapsed_cpu(acquisition_cpu),
        "wall_ns":acquisition_started.elapsed().as_nanos(),
        "all_attempts_or_error":search.as_ref().map(|(_, _, attempts)| attempts).map_err(String::as_str),
        "scope":"actual prepared producer plus changed-header search; calling process CPU, not a fastest-attacker bound"});
    support::write_new(&output.join("acquisition.json"), &acquisition);
    let (header, proof, attempts) =
        search.expect("actual search failure retained in acquisition.json");
    let wrong = Packet {
        header,
        proof,
        transactions: reference.transactions.clone(),
    };
    let verify_reference_started = Instant::now();
    let verify_reference_cpu = support::cpu();
    let reference_verified = check_winner(&reference.header, &reference.proof);
    let verify_reference_cost = json!({"cpu_ns":support::elapsed_cpu(verify_reference_cpu),
        "wall_ns":verify_reference_started.elapsed().as_nanos()});
    let verify_wrong_started = Instant::now();
    let verify_wrong_cpu = support::cpu();
    let wrong_verified = check_winner(&wrong.header, &wrong.proof);
    let verify_wrong_cost = json!({"cpu_ns":support::elapsed_cpu(verify_wrong_cpu),
        "wall_ns":verify_wrong_started.elapsed().as_nanos()});
    let encoding_started = Instant::now();
    let encoding_cpu = support::cpu();
    let seed_encoded: Vec<_> = seed
        .iter()
        .map(|p| hex::encode(p.encode().unwrap()))
        .collect();
    let reference_encoded = hex::encode(reference.encode().unwrap());
    let wrong_encoded = hex::encode(wrong.encode().unwrap());
    let fixture_encoding_cost = json!({"cpu_ns":support::elapsed_cpu(encoding_cpu),
        "wall_ns":encoding_started.elapsed().as_nanos()});
    let preparation_cost = json!({"cpu_ns":support::elapsed_cpu(preparation_cpu),
        "wall_ns":preparation_started.elapsed().as_nanos(),
        "scope":"calling process preparation including all setup/search attempts, legal replay, independent W1 checks and fixture encoding; component costs are nested, do not add this total to components"});
    support::write_new(
        &output.join("fixture.json"),
        &json!({
        "reference_packet":reference_encoded,"wrong_root_packet":wrong_encoded,
        "seed_packets":seed_encoded,"m06_workers":workers,"parent_height":reference.header.height-1,
        "producer_setup_cost":producer_setup_cost,"reference_acceptance_cost":reference_accept_cost,
        "independent_reference_w1_verification_cost":verify_reference_cost,
        "independent_wrong_root_w1_verification_cost":verify_wrong_cost,
        "fixture_packet_encoding_cost":fixture_encoding_cost,"preparation_cost":preparation_cost,
        "reference_cost":reference_cost,"acquisition":acquisition,
        "strict_reference_verification":reference_verified,"strict_changed_header_verification":wrong_verified,
        "signed_transactions":reference.transactions.len(),"attempt_count":attempts.len()}),
    );
    assert!(reference_verified.is_ok() && wrong_verified.is_ok());
    assert!(acquisition["cpu_ns"].as_u64().is_some_and(|ns| ns > 0));
    assert_ne!(wrong.header.challenge(), reference.header.challenge());
    let mut normalized = wrong.header.clone();
    normalized.state = reference.header.state;
    normalized.nonce = reference.header.nonce;
    assert_eq!(normalized, reference.header);
    assert!(!attempts.is_empty() && attempts.last().unwrap()["target_hit"] == true);
    assert!(attempts[..attempts.len() - 1]
        .iter()
        .all(|row| row["target_hit"] == false));

    let run = |node: Node, packet: &Packet, count: usize, accepted: bool, label: &str| {
        let encoding_started = Instant::now();
        let encoding_cpu = support::cpu();
        let wire = hex::encode(packet.encode().unwrap());
        let request = || Request::Submit {
            packet: wire.clone(),
        };
        let body = serde_json::to_vec(&request()).unwrap();
        let digest = hash(b"public-request-body-v3", &[&body]);
        let encoding_cost = json!({"cpu_ns":support::elapsed_cpu(encoding_cpu),
            "wall_ns":encoding_started.elapsed().as_nanos(),"body_bytes":body.len(),
            "scope":"actual packet encode, hex, Submit body JSON and body digest before service startup; each public call retains its own client preparation and handshake costs"});
        let owner = Arc::new(Mutex::new(node));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let metrics = Arc::new(Mutex::new(public_v3::PublicMetrics::default()));
        let observer = public_v3::PublicRequestObserver::new(16).unwrap();
        let server = PublicServer::new(support::identity(71), support::policy()).unwrap();
        let domain = server.mutation_cpu_domain();
        let initial_flow = domain.observe_actual_flow().unwrap();
        let (shared, signal, capture) = (owner.clone(), stop.clone(), observer.clone());
        let service = Service {
            stop,
            worker: Some(thread::spawn(move || {
                public_v3::serve_public_protected_v3_with_request_observer(
                    listener,
                    shared,
                    Duration::from_secs(30),
                    signal,
                    server,
                    metrics,
                    capture,
                )
                .map_err(|error| error.to_string())
            })),
        };
        let epoch = support::monotonic();
        let end = epoch + 30_000_000_000;
        let mut calls = Vec::new();
        for index in 0..count {
            let before = domain.observe_actual_flow().unwrap();
            let client_started = ClientOperationStamp::start(epoch);
            let response = support::call(address, &settings, request(), 72, epoch, end);
            let client_cost = client_started.finish(epoch);
            // Native dispatch joins M06 workers and finishes the paid permit
            // after response signing, before delivery. No other mutation uses this domain.
            let after = domain.observe_actual_flow().unwrap();
            let paid_cpu_ns = before
                .as_ref()
                .zip(after.as_ref())
                .and_then(|(a, b)| b.paid_cpu_debit_ns.checked_sub(a.paid_cpu_debit_ns));
            let quiescent = [&before, &after].iter().all(|flow| {
                flow.as_ref().is_some_and(|f| {
                    f.balance_identity_verified
                        && f.live_owners == 0
                        && f.booked_reservation_ns == 0
                        && f.unsettled_known_live_cpu_ns == 0
                        && f.paid_cpu_debit_ns == f.settled_full_cpu_ns
                })
            });
            calls.push(
                json!({"ordinal":index,"reuse":if index == 0 {"first"} else {"warm"},
                "call":response,"client_thread_cost":client_cost,"flow_before":before,"flow_after":after,
                "quiescent":quiescent,"paid_owner_plus_scoped_worker_cpu_ns":paid_cpu_ns,
                "native_stats_after":owner.lock().unwrap().stats().unwrap()}),
            );
        }
        let service_outcome = service.finish();
        let captured = observer.snapshot();
        let final_flow = domain.observe_actual_flow().unwrap();
        let final_meter = domain.observe().unwrap();
        let mut stages_match = captured.coverage_complete() && captured.records.len() == count;
        // Sequential calls and exact complete coverage bind each recorded body
        // and its owner sample to that call's isolated settled CPU delta.
        for (index, (call, row)) in calls.iter_mut().zip(&captured.records).enumerate() {
            let scoped = call["paid_owner_plus_scoped_worker_cpu_ns"]
                .as_u64()
                .zip(row.dispatch_thread_cpu_ns)
                .and_then(|(paid, owner)| paid.checked_sub(owner));
            call["receiver_connection_id"] = json!(row.connection_id);
            call["dispatch_owner_thread_cpu_ns"] = json!(row.dispatch_thread_cpu_ns);
            call["scoped_worker_cpu_ns"] = json!(scoped);
            stages_match &= row.operation == Some(1)
                && row.connection_id == u64::try_from(index + 1).ok()
                && row.body_digest == Some(digest)
                && row.full_work_started
                && row.full_work_accepted == Some(true)
                && row.full_work_thread_cpu_ns.is_some_and(|ns| ns > 0)
                && row.dispatch_accepted == Some(accepted)
                && row.submit_phases.iter().any(|p| {
                    p.phase == public_v3::SubmitPhase::Work
                        && p.started
                        && p.completed
                        && p.accepted == Some(true)
                })
                && row.submit_phases.iter().any(|p| {
                    p.phase == public_v3::SubmitPhase::Admission
                        && p.started
                        && p.completed
                        && p.accepted == Some(accepted)
                })
                && row.submit_phases.iter().any(|p| {
                    p.phase == public_v3::SubmitPhase::SubmitResult
                        && p.started == accepted
                        && p.completed == accepted
                        && p.accepted == accepted.then_some(true)
                })
                && row.dispatch_thread_cpu_ns.is_some_and(|ns| ns > 0)
                && if signed_seed {
                    // One transaction and one M06 worker execute on the owner;
                    // known zero child CPU is valid, unlike an unknown sample.
                    scoped == Some(0)
                } else {
                    scoped.is_some_and(|ns| ns > 0)
                };
        }
        let replies_match = calls.iter().all(|row| {
            row["quiescent"] == true
                && row["client_thread_cost"]["thread_cpu_ns"]
                    .as_u64()
                    .is_some_and(|ns| ns > 0)
                && row["call"]["public_request_body_digest"] == hex::encode(digest)
                && row["call"]["status"] == if accepted { "ok" } else { "refused" }
                && row["call"]["response"]["ok"] == accepted
                && row["call"]["response"]["identity_authority"] == false
                && row["call"]["response"]["public_network_ready"] == false
                && (accepted || row["call"]["response"]["value"]["error"] == "ROOT")
        });
        let total_paid = initial_flow
            .as_ref()
            .zip(final_flow.as_ref())
            .and_then(|(a, b)| b.paid_cpu_debit_ns.checked_sub(a.paid_cpu_debit_ns));
        let sum = calls.iter().try_fold(0_u64, |sum, call| {
            sum.checked_add(call["paid_owner_plus_scoped_worker_cpu_ns"].as_u64()?)
        });
        let settled = final_meter.in_flight == 0
            && !final_meter.accounting_unavailable
            && total_paid.is_some_and(|ns| ns > 0)
            && total_paid == sum
            && service_outcome["Ok"]["mutation_cpu_charged_ns"].as_u64() == total_paid
            && service_outcome["Ok"]["mutation_cpu_clock_failures"] == 0;
        let encoding_measured = encoding_cost["cpu_ns"].as_u64().is_some_and(|ns| ns > 0)
            && encoding_cost["wall_ns"].as_u64().is_some_and(|ns| ns > 0);
        let result = json!({"calls":calls,"body_digest":hex::encode(digest),"observer":captured,
            "request_encoding_cost":encoding_cost,"encoding_measured":encoding_measured,
            "initial_flow":initial_flow,"final_flow":final_flow,"final_meter":final_meter,
            "total_paid_owner_plus_scoped_worker_cpu_ns":total_paid,"service":service_outcome,
            "stages_match":stages_match,"replies_match":replies_match,"settled":settled});
        support::write_new(&output.join(format!("{label}.json")), &result);
        let node = Arc::try_unwrap(owner)
            .ok()
            .expect("joined service released the sole owner")
            .into_inner()
            .unwrap();
        (node, result)
    };
    let receiver_path = output.join("receiver");
    let receiver_setup_started = Instant::now();
    let receiver_setup_cpu = support::cpu();
    let mut receiver = open(&receiver_path);
    replay(&mut receiver, &seed);
    // Match the original campaign's trusted owner setup before taking the
    // no-admission baseline; cold reopen must retain this exact configuration.
    let pool_context = receiver
        .enable_local_mempool(PoolLimits {
            max_records: 16,
            max_bytes: 32768,
            max_group_members: 4,
            critical_reserve: 0,
            max_removals: 64,
            preview_miner: development_public(0).unwrap(),
        })
        .unwrap();
    let initial = receiver.read_active().unwrap();
    let initial_stats = receiver.stats().unwrap();
    let receiver_setup_cost = json!({"cpu_ns":support::elapsed_cpu(receiver_setup_cpu),
        "wall_ns":receiver_setup_started.elapsed().as_nanos(),
        "scope":"fresh receiver open, real seed replay, original mempool setup and baseline readback; first request has no preceding ROOT replay but is not OS-cache-cold"});
    let (receiver, rejected) = run(receiver, &wrong, 3, false, "rejections");
    let live_unchanged =
        receiver.read_active().unwrap() == initial && receiver.stats().unwrap() == initial_stats;
    drop(receiver);
    let reopened = open(&receiver_path);
    assert_eq!(
        reopened.pool_status_snapshot().unwrap().context,
        hex::encode(pool_context)
    );
    let cold_unchanged =
        reopened.read_active().unwrap() == initial && reopened.stats().unwrap() == initial_stats;
    let absent_error = |node: &Node| {
        node.packet(wrong.id().unwrap())
            .err()
            .map(|e| e.to_string())
    };
    let wrong_absent = absent_error(&reopened);
    // The clean, physically reopened owner starts a second ordinary service
    // epoch solely for legal acceptance; it is not a debt/refill recovery claim.
    let (receiver, legal) = run(reopened, &reference, 1, true, "legal-after-reopen");
    let legal_equal =
        receiver.read_active().unwrap() == expected && receiver.stats().unwrap() == expected_stats;
    drop(receiver);
    let reopened = open(&receiver_path);
    assert_eq!(
        reopened.pool_status_snapshot().unwrap().context,
        hex::encode(pool_context)
    );
    let legal_cold_equal = reopened.read_active().unwrap() == expected
        && reopened.stats().unwrap() == expected_stats
        && reopened
            .packet(reference.id().unwrap())
            .unwrap()
            .encode()
            .unwrap()
            == reference.encode().unwrap();
    let still_absent = absent_error(&reopened);
    drop(reopened);
    let each_rejection_unchanged = rejected["calls"]
        .as_array()
        .unwrap()
        .iter()
        .all(|call| call["native_stats_after"] == initial_stats);
    let preparation_measured = [
        &producer_setup_cost,
        &reference_cost,
        &reference_accept_cost,
        &acquisition,
        &verify_reference_cost,
        &verify_wrong_cost,
        &fixture_encoding_cost,
        &preparation_cost,
        &receiver_setup_cost,
    ]
    .iter()
    .all(|cost| {
        cost["cpu_ns"].as_u64().is_some_and(|ns| ns > 0)
            && cost["wall_ns"].as_u64().is_some_and(|ns| ns > 0)
    });
    let passed = [&rejected, &legal].iter().all(|r| {
        r["stages_match"] == true
            && r["replies_match"] == true
            && r["settled"] == true
            && r["encoding_measured"] == true
    }) && preparation_measured
        && live_unchanged
        && cold_unchanged
        && each_rejection_unchanged
        && wrong_absent.as_deref() == Some("UNKNOWN_PARENT")
        && still_absent.as_deref() == Some("UNKNOWN_PARENT")
        && legal_equal
        && legal_cold_equal;
    support::write_new(
        &output.join("report.json"),
        &json!({
        "schema":if signed_seed {"public-v3-signed-seed-root-component-cost-v1"} else {"public-v3-valid-work-root-rejection-v1"},"passed":passed,
        "m06_workers":workers,"signed_seed_transfers":seed.iter().map(|p|p.transactions.len()).sum::<usize>(),
        "receiver_setup_cost":receiver_setup_cost,"preparation_measured":preparation_measured,
        "cost_scope":"process CPU during sequential preparation; nested totals must not be double-counted; support::call process CPU includes this in-process receiver, while client_thread_cost isolates client CPU",
        "pool_context":hex::encode(pool_context),
        "scope":"three sequential identical valid-W1 false-root bodies; actual M06 refusal and native-state readback; ordinary service crash-fence metadata is outside no-admission claim",
        "reference_packet_id":hex::encode(reference.id().unwrap()),"wrong_packet_id":hex::encode(wrong.id().unwrap()),
        "initial_stats":initial_stats,"expected_stats":expected_stats,
        "live_unchanged":live_unchanged,"cold_unchanged":cold_unchanged,
        "each_rejection_unchanged":each_rejection_unchanged,"wrong_absence_error":wrong_absent,
        "wrong_absence_after_legal_error":still_absent,"legal_equal":legal_equal,"legal_cold_equal":legal_cold_equal,
        "rejections":rejected,"legal_after_cold_reopen":legal,
        "depletion_qualified":false,"original_campaign_qualified":false,
        "work_profile_qualified":false,"production_activation":false}),
    );
    assert!(
        passed,
        "valid-W1 ROOT regression failed; retained {}",
        output.display()
    );
}
