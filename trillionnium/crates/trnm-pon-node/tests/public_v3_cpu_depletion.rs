//! Actual shared-domain W1 replay depletion followed by public service recovery.
//! Trusted local replay drives the meter; this is NOT public hostile saturation,
//! a cheapest-attacker experiment, an independently operated network or power loss.
#![cfg(target_os = "linux")]

use serde_json::{json, Value};
use std::{
    fs,
    net::TcpListener,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use trnm_crypto_primitives::pon_work;
use trnm_pon_node::{
    development_public,
    ingress::{
        self,
        public_v3::{self, PublicPolicy, PublicServer, Request, ServiceMutationCpuDomain},
        DevelopmentIdentity,
    },
    maintenance, sequence_root, Node, Packet, PoolLimits, Settings,
};
use trnm_protocol::pon_wire::{hash, Header};

const ROUNDS: usize = 3;
const SEARCH_LIMIT: u64 = 4096;
const REPLAY_LIMIT: usize = 100_000;
const CALL_LIMIT: Duration = Duration::from_secs(2);

fn identity(n: u8) -> DevelopmentIdentity {
    DevelopmentIdentity::from_secret_hex(&hex::encode([n; 32])).unwrap()
}
fn policy() -> PublicPolicy {
    PublicPolicy::new(8, CALL_LIMIT).unwrap()
}
fn elapsed_ns(epoch: Instant) -> u64 {
    epoch.elapsed().as_nanos().try_into().unwrap()
}

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

// Only public task material and hash trials create this unverified packet.
// Repeated native verification below is LOCAL load, not an attacker cost claim.
fn false_packet(node: &Node) -> Packet {
    let settings = node.settings();
    let (a, b) = maintenance();
    let header = Header {
        network: settings.network(),
        parameters: settings.parameters(),
        parent: settings.genesis(),
        height: 1,
        timestamp: settings.genesis_time() + 1,
        target: node.expected_target(settings.genesis()).unwrap(),
        miner: development_public(0).unwrap(),
        transactions: sequence_root("transactions", &[]),
        state: [0; 32],
        receipts: [0; 32],
        work_task: pon_work::task_id(&a, &b).unwrap(),
        nonce: 91_000,
    };
    let challenge = header.challenge();
    let trace = (0..SEARCH_LIMIT)
        .map(|nonce| hash(b"local-cpu-depletion-fixture-v1", &[&challenge, &nonce.to_le_bytes()]))
        .find(|trace| hash(b"ticket", &[&challenge, trace]) <= header.target)
        .expect("fixed bounded public fixture must produce a ticket hit");
    let mut proof = Vec::with_capacity(pon_work::PROOF_BYTES);
    proof.extend_from_slice(b"PNW1");
    for matrix in [&a, &b] {
        for value in matrix {
            proof.extend_from_slice(&value.to_le_bytes());
        }
    }
    proof.resize(pon_work::PROOF_BYTES, 0);
    proof[pon_work::PROOF_BYTES - 32..].copy_from_slice(&trace);
    Packet { header, transactions: vec![], proof }
}

fn deplete(domain: &ServiceMutationCpuDomain, packet: &Packet, deadline: Instant) -> Value {
    let before = domain.observe().unwrap();
    let started = Instant::now();
    // Never alter credit, refill, worker limit or start reserve. Failure to
    // observe actual depletion is a failed experiment, not a fabricated result.
    let operation = loop {
        match domain.begin() {
            Ok(operation) => break operation,
            Err(error) => {
                if !domain.accounting_available() || Instant::now() >= deadline {
                    return json!({"depletion_observed": false, "begin_error": error.to_string(),
                        "meter_before": before, "meter_after": domain.observe().unwrap()});
                }
                thread::sleep(Duration::from_millis(10));
            }
        }
    };
    let mut replays = 0;
    let mut refusal = None;
    while replays < REPLAY_LIMIT && Instant::now() < deadline {
        assert_eq!(
            pon_work::verify_reference(
                packet.header.challenge(), packet.header.work_task,
                packet.header.target, &packet.proof,
            ).unwrap_err(),
            pon_work::WorkError::Transcript,
        );
        replays += 1;
        if let Err(error) = operation.checkpoint() {
            refusal = Some(error.to_string());
            break;
        }
    }
    let at_refusal = domain.observe().unwrap();
    let settlement = operation.finish();
    let after = domain.observe().unwrap();
    let observed = refusal.as_deref() == Some("PUBLIC_MUTATION_CPU_BUDGET")
        && settlement.live_refused && !settlement.accounting_unavailable
        && settlement.total_cpu_ns.is_some_and(|cpu| cpu > 0)
        && at_refusal.stored_credit_ns < i128::from(at_refusal.start_reserve_ns)
        && !after.accounting_unavailable && after.in_flight == 0;
    json!({"depletion_observed": observed, "meter_before": before,
        "meter_at_refusal": at_refusal, "meter_after": after,
        "replays": replays, "replay_limit": REPLAY_LIMIT,
        "cap_reached": replays == REPLAY_LIMIT, "refusal": refusal,
        "settlement": settlement, "wall_ns": elapsed_ns(started),
        "scope": "actual owner-thread full W1 replay and checkpoints; trusted local load"})
}

#[test]
fn actual_replay_depletion_public_recovery_and_same_epoch_reopen() {
    let temporary = tempfile::tempdir().unwrap();
    let output = std::env::var_os("TRNM_PUBLIC_V3_DEPLETION_DIR")
        .map(std::path::PathBuf::from)
        .or_else(|| std::env::var_os("TRNM_CI_RECEIPT_DIR")
            .map(|root| std::path::PathBuf::from(root).join("actual-cpu-depletion")));
    let path = if let Some(path) = output {
        fs::create_dir(&path).unwrap();
        path
    } else {
        temporary.path().to_path_buf()
    };
    let settings = Settings::development(Some(1_750_000_000)).unwrap();
    let receiver_path = path.join("receiver");
    let mut node = Node::open(&receiver_path, settings.clone(), 1).unwrap();
    node.enable_local_mempool(PoolLimits {
        max_records: 16, max_bytes: 32768, max_group_members: 4,
        critical_reserve: 0, max_removals: 64, preview_miner: development_public(0).unwrap(),
    }).unwrap();
    let false_work = false_packet(&node);
    let mut producer = Node::open(&path.join("producer"), settings.clone(), 1).unwrap();
    let honest_packets: Vec<_> = (0..ROUNDS).map(|index| {
        producer.mine(vec![], settings.genesis_time() + 10 * (index as u64 + 1),
                      ingress::now().unwrap()).unwrap()
    }).collect();
    let expected = producer.read_active().unwrap();
    let server = PublicServer::new(identity(71), policy()).unwrap();
    let domain = server.mutation_cpu_domain();
    let initial = domain.observe().unwrap();
    assert_eq!((initial.burst_ns, initial.refill_ns_per_second,
                initial.start_reserve_ns, initial.worker_limit),
               (2_000_000_000, 250_000_000, 100_000_000, 2));
    let owner = Arc::new(Mutex::new(node));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let (shared, signal) = (owner.clone(), stop.clone());
    let service = RunningService { stop, worker: Some(thread::spawn(move || {
        match public_v3::serve_public_protected_v3(
            listener, shared, Duration::from_secs(90), signal, server,
        ) {
            Ok(metrics) => json!({"metrics": metrics, "error": null}),
            Err(error) => json!({"metrics": null, "error": error.to_string()}),
        }
    })) };
    let epoch = Instant::now();
    let deadline = epoch + Duration::from_secs(60);
    let mut rounds = Vec::new();
    for (index, packet) in honest_packets.iter().enumerate() {
        let pressure = deplete(&domain, &false_work, deadline);
        let started = Instant::now();
        let (reply, transport) = public_v3::call_public_protected_v3_with_deadline(
            address, &Request::Submit { packet: hex::encode(packet.encode().unwrap()) },
            &settings, identity(71).public_key(), &identity(73), policy(),
            Some((started + CALL_LIMIT).min(deadline)),
        );
        let elapsed = started.elapsed();
        let (acknowledged, response, error) = match reply {
            Ok(reply) => (reply.ok, Some(serde_json::to_value(reply).unwrap()), None),
            Err(error) => (false, None, Some(error.to_string())),
        };
        let read_started = Instant::now();
        let (read, read_transport) = public_v3::call_public_protected_v3_with_deadline(
            address, &Request::Head, &settings, identity(71).public_key(),
            &identity(72), policy(), Some((read_started + CALL_LIMIT).min(deadline)),
        );
        let read_on_time = read.as_ref().is_ok_and(|reply| reply.ok)
            && read_started.elapsed() <= CALL_LIMIT;
        let active_id = owner.lock().unwrap().read_active().unwrap().0;
        let expected_id = packet.id().unwrap();
        rounds.push(json!({"round": index + 1, "local_pressure": pressure,
            "honest_acknowledged": acknowledged, "submit_on_time": elapsed <= CALL_LIMIT,
            "submit_wall_ns": elapsed.as_nanos(), "submit_response": response,
            "submit_error": error, "transport": transport,
            "head_on_time": read_on_time, "head_transport": read_transport,
            "active_id": hex::encode(active_id), "expected_id": hex::encode(expected_id),
            "active_packet_equal": active_id == expected_id}));
    }
    let service_outcome = service.finish();
    let node = Arc::try_unwrap(owner).ok().unwrap().into_inner().unwrap();
    let before = node.read_active().unwrap();
    let full_state_equal = before.0 == expected.0 && before.2 == expected.2;
    let before_meter = domain.observe().unwrap();
    drop(node);
    let reopened = Node::open(&receiver_path, settings.clone(), 1).unwrap();
    let reopened_equal = before == reopened.read_active().unwrap();
    let resumed = PublicServer::with_continuous_domain(identity(71), policy(), &domain).unwrap();
    let same_epoch = domain.shares_domain_with(&resumed.mutation_cpu_domain())
        && before_meter == resumed.mutation_cpu_domain().observe().unwrap();
    let passed = rounds.len() == ROUNDS && rounds.iter().all(|round| {
        round["local_pressure"]["depletion_observed"] == true
            && round["local_pressure"]["cap_reached"] == false
            && round["honest_acknowledged"] == true && round["submit_on_time"] == true
            && round["head_on_time"] == true && round["active_packet_equal"] == true
    }) && full_state_equal && reopened_equal && same_epoch
        && service_outcome["error"].is_null() && before_meter.in_flight == 0
        && !before_meter.accounting_unavailable;
    let report = json!({"schema": "public-v3-actual-local-replay-depletion-v1",
        "network": hex::encode(settings.network()), "parameters": hex::encode(settings.parameters()),
        "policy_id": hex::encode(policy().id()), "initial_meter": initial, "rounds": rounds,
        "false_work_packet": hex::encode(false_work.encode().unwrap()),
        "full_native_state_equal": full_state_equal, "reopen_state_equal": reopened_equal,
        "same_cpu_epoch_across_reopen": same_epoch, "final_meter": before_meter,
        "service": service_outcome, "wall_ns": elapsed_ns(epoch), "passed": passed,
        "scope": "trusted local W1 replay depletion, then real public submit/head recovery; no live remote attack",
        "public_hostile_saturation_qualified": false, "work_profile_qualified": false,
        "resource_fairness_qualified": false, "independent_accepted": false,
        "physical_power_loss": false, "production_activation": false});
    fs::write(path.join("report.json"), serde_json::to_vec_pretty(&report).unwrap()).unwrap();
    println!("{}", json!({"schema": report["schema"], "passed": passed}));
    assert!(passed, "retain actual-cpu-depletion/report.json; no inferred or synthetic depletion");
}
