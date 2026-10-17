//! Controlled real-W1 receiver CPU debt and independent network confirmation.
//! The work that drains the shared budget uses its real owner-side accounting
//! operation, not a remotely authenticated paid TCP request. This is explicitly
//! not a proof of permissionless attacker-induced depletion or Sybil fairness.
use serde_json::{json, Value};
use std::{
    hint::black_box,
    net::{SocketAddr, TcpListener},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};
use trnm_crypto_primitives::{pon_work, sign_hex, signing_key_from_hex};
use trnm_pon_node::{
    development_public,
    ingress::{
        self,
        public_v3::{self, PublicPolicy, PublicServer, Request},
        DevelopmentIdentity,
    },
    Node, Packet, PoolLimits, Result, Settings,
};
use trnm_protocol::pon_wire::{hash, Envelope};

const POLICY_TIME: Duration = Duration::from_secs(2);
const MAX_W1_PRELOAD: usize = 100_000;

fn identity(n: u8) -> DevelopmentIdentity {
    DevelopmentIdentity::from_secret_hex(&hex::encode([n; 32])).unwrap()
}
fn transfer(settings: &Settings) -> Vec<u8> {
    let mut payload = development_public(1).unwrap().to_vec();
    payload.extend(1u64.to_le_bytes());
    let mut tx = Envelope {
        network: settings.network(),
        sender: development_public(0).unwrap(),
        nonce: 1,
        expiry: 2000,
        fee_limit: 1_000_000,
        tag: 1,
        payload,
        signature: [0; 64],
    };
    let key =
        signing_key_from_hex(&hex::encode(hash(b"DEV-ONLY-KEY", &[&0u64.to_le_bytes()]))).unwrap();
    tx.signature = hex::decode(sign_hex(&key, &tx.signing_digest().unwrap()))
        .unwrap()
        .try_into()
        .unwrap();
    tx.encode().unwrap()
}
fn false_ticket(producer: &mut Node) -> Packet {
    let parent = producer.active().unwrap().0;
    let reference = producer
        .make(
            parent,
            vec![],
            development_public(0).unwrap(),
            producer.settings().genesis_time() + 2,
            4096,
        )
        .unwrap();
    pon_work::verify(
        reference.header.challenge(),
        reference.header.work_task,
        reference.header.target,
        &reference.proof,
    )
    .unwrap();
    let mut forged = reference.clone();
    let n = forged.proof.len() - 32;
    let challenge = forged.header.challenge();
    let found = (0u64..4096)
        .map(|nonce| {
            hash(
                b"public-v3-debt-false-trace",
                &[&challenge, &nonce.to_le_bytes()],
            )
        })
        .find(|trace| {
            trace.as_slice() != &reference.proof[n..]
                && hash(b"ticket", &[&challenge, trace]) <= forged.header.target
        })
        .unwrap();
    forged.proof[n..].copy_from_slice(&found);
    assert_eq!(
        pon_work::verify(
            forged.header.challenge(),
            forged.header.work_task,
            forged.header.target,
            &forged.proof,
        )
        .unwrap_err(),
        pon_work::WorkError::Transcript
    );
    forged
}

struct Service {
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<Result<public_v3::PublicMetrics>>>,
}
impl Service {
    fn finish(mut self) -> Result<public_v3::PublicMetrics> {
        self.stop.store(true, Ordering::Release);
        self.worker
            .take()
            .unwrap()
            .join()
            .map_err(|_| "SERVICE_PANIC")?
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
fn tcp(
    addr: SocketAddr,
    settings: &Settings,
    who: u8,
    request: &Request,
) -> (Option<Value>, Value) {
    let now = Instant::now();
    let (reply, metrics) = public_v3::call_public_protected_v3_with_deadline(
        addr,
        request,
        settings,
        identity(71).public_key(),
        &identity(who),
        PublicPolicy::new(8, POLICY_TIME).unwrap(),
        Some(now + POLICY_TIME),
    );
    match reply {
        Ok(r) => {
            let ok = r.ok;
            let value = r.value;
            (
                ok.then_some(value.clone()),
                json!({"ok":ok,"response":value,"elapsed_ns":now.elapsed().as_nanos(),
                    "client_metrics":metrics}),
            )
        }
        Err(e) => (
            None,
            json!({"ok":false,"error":e.to_string(),"elapsed_ns":now.elapsed().as_nanos(),
                "client_metrics":metrics}),
        ),
    }
}

#[test]
fn real_w1_verification_cpu_debt_blocks_then_recovers_paid_tcp_and_confirmations() {
    let temporary = tempfile::tempdir().unwrap();
    let path = std::env::var_os("TRNM_W1_DEBT_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| temporary.path().to_path_buf());
    std::fs::create_dir_all(&path).unwrap();
    let settings = Settings::development(Some(1_750_000_000)).unwrap();
    let receiver_path = path.join("receiver");
    let mut node = Node::open(&receiver_path, settings.clone(), 1).unwrap();
    // Same original native public service readiness boundary as the known-good
    // network-only fixture. The guest listener never enables its own mempool.
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
    let mut verifier = Node::open(&path.join("independent-consumer"), settings.clone(), 1).unwrap();
    let forged = false_ticket(&mut producer);

    // Native evidence, not a fabricated clock or directly assigned credit.
    let original =
        PublicServer::new(identity(71), PublicPolicy::new(8, POLICY_TIME).unwrap()).unwrap();
    let meter = original.mutation_cpu_domain();
    let initial = meter.observe().unwrap();
    assert_eq!(initial.burst_ns, 2_000_000_000);
    assert_eq!(initial.refill_ns_per_second, 250_000_000);
    assert_eq!(initial.start_reserve_ns, 100_000_000);
    assert_eq!(initial.stored_credit_ns, 2_000_000_000);

    let owner_operation = meter.begin().unwrap();
    let started = Instant::now();
    let mut complete_invalid_replays = 0usize;
    let mut refused = None;
    for i in 0..MAX_W1_PRELOAD {
        black_box(
            pon_work::verify(
                forged.header.challenge(),
                forged.header.work_task,
                forged.header.target,
                &forged.proof,
            )
            .unwrap_err(),
        );
        complete_invalid_replays += 1;
        if i % 64 == 63 {
            if let Err(e) = owner_operation.checkpoint() {
                refused = Some(e.to_string());
                break;
            }
        }
        assert!(
            started.elapsed() <= Duration::from_secs(16),
            "bounded native W1 budget exercise did not reach refusal"
        );
    }
    let owner_settlement = owner_operation.finish();
    let low_credit = meter.observe().unwrap();
    let flow_after_preload = meter.observe_actual_flow().unwrap();
    let preload_report = json!({
        "schema":"pon-w1-controlled-original-budget-debit-v1",
        "preload_is_network_attack":false,
        "preload_native_W1_complete_invalid_replays":complete_invalid_replays,
        "preload_wall_ns":started.elapsed().as_nanos(),
        "preload_real_thread_CPU_settlement":owner_settlement,
        "initial":initial,
        "low_credit":low_credit,
        "flow_after_preload":flow_after_preload,
        "refusal":refused,
        "work_profile_qualified":false,"resource_fairness_qualified":false,
        "production_activation":false
    });
    std::fs::write(
        path.join("preload.json"),
        serde_json::to_vec_pretty(&preload_report).unwrap(),
    )
    .unwrap();
    println!("W1_BUDGET_PRELOAD={}", preload_report);
    assert!(refused
        .as_deref()
        .is_some_and(|s| s.contains("PUBLIC_MUTATION_CPU_BUDGET")));
    assert!(complete_invalid_replays > 256);
    assert!(owner_settlement.live_refused);
    assert!(!owner_settlement.accounting_unavailable);
    assert_eq!(low_credit.in_flight, 0);
    assert!(low_credit.stored_credit_ns < i128::from(low_credit.start_reserve_ns));
    assert!(flow_after_preload.is_some_and(|f| f.balance_identity_verified));
    let start_refusal = meter.begin().err().unwrap().to_string();
    assert_eq!(start_refusal, "PUBLIC_MUTATION_CPU_BUDGET");

    // Reconstruct only the listener against the SAME already debited CPU domain;
    // it must not remint a new burst or grant a model/ledger capability.
    let server = PublicServer::with_continuous_domain(
        identity(71),
        PublicPolicy::new(8, POLICY_TIME).unwrap(),
        &meter,
    )
    .unwrap();
    assert!(server.mutation_cpu_domain().shares_domain_with(&meter));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let owner = Arc::new(Mutex::new(node));
    let stop = Arc::new(AtomicBool::new(false));
    let (shared, signal) = (owner.clone(), stop.clone());
    let service = Service {
        stop,
        worker: Some(thread::spawn(move || {
            public_v3::serve_public_protected_v3(
                listener,
                shared,
                Duration::from_secs(30),
                signal,
                server,
            )
        })),
    };

    // Full remote incorrect proofs and real honest work use the ordinary 2s
    // client deadline and paid grant; do not substitute Head for a transaction.
    let mut attack_rows = Vec::new();
    let raw_forged = hex::encode(forged.encode().unwrap());
    let end = Instant::now() + Duration::from_secs(13);
    while attack_rows.len() < 12 && Instant::now() < end {
        let who = 80 + (attack_rows.len() % 12) as u8;
        let (value, row) = tcp(
            addr,
            &settings,
            who,
            &Request::Submit {
                packet: raw_forged.clone(),
            },
        );
        assert!(value.is_none());
        attack_rows.push(row);
        thread::sleep(Duration::from_millis(70));
    }
    let mut packets = Vec::new();
    let mut transaction_queries = Vec::new();
    for height in 0..9usize {
        let transactions = if height == 0 {
            vec![transfer(&settings)]
        } else {
            vec![]
        };
        let packet = producer
            .mine(
                transactions,
                settings.genesis_time() + 10 * (height as u64 + 1),
                ingress::now().unwrap(),
            )
            .unwrap();
        for raw in &packet.transactions {
            transaction_queries.push((
                Envelope::decode(raw).unwrap().id().unwrap(),
                packet.id().unwrap(),
            ));
        }
        packets.push(packet);
    }
    let mut honest_rows = Vec::new();
    let all_end = Instant::now() + Duration::from_secs(21);
    for (position, packet) in packets.iter().enumerate() {
        let expected_id = packet.id().unwrap();
        let wire = hex::encode(packet.encode().unwrap());
        let mut retry_count = 0usize;
        loop {
            if Instant::now() >= all_end {
                let snapshot = json!({
                    "schema":"pon-w1-controlled-debt-failed-honest-stage-v1",
                    "source_scope":"actual W1 replay charged by local owner, not an authenticated remote attack",
                    "block_ordinal":position,
                    "expected_id":hex::encode(expected_id),
                    "last_attempt":honest_rows.last(),
                    "attack_rows":attack_rows,
                    "honest_rows":honest_rows,
                    "shared_meter":meter.observe().unwrap(),
                    "shared_flow":meter.observe_actual_flow().unwrap(),
                    "deadline_seconds":21,
                });
                std::fs::write(
                    path.join("failed-honest.json"),
                    serde_json::to_vec_pretty(&snapshot).unwrap(),
                )
                .unwrap();
                panic!("honest business unconfirmed; exact failed-honest.json retained");
            }
            let (result, row) = tcp(
                addr,
                &settings,
                73,
                &Request::Submit {
                    packet: wire.clone(),
                },
            );
            if retry_count < 4 || retry_count % 8 == 0 {
                println!(
                    "HONEST_ATTEMPT block={} retry={} reply={} credit={}",
                    position,
                    retry_count,
                    row,
                    meter.observe().unwrap().stored_credit_ns
                );
            }
            honest_rows.push(row);
            if result
                .as_ref()
                .is_some_and(|r| r["block"] == hex::encode(expected_id))
            {
                break;
            }
            retry_count += 1;
            thread::sleep(Duration::from_millis(80));
        }
    }
    let head = tcp(addr, &settings, 72, &Request::Head);
    let tip = hex::encode(packets.last().unwrap().id().unwrap());
    assert_eq!(head.0.as_ref().unwrap()["tip"], tip);
    let mut after = hex::encode(settings.genesis());
    for packet in &packets {
        let (page, row) = tcp(
            addr,
            &settings,
            72,
            &Request::History {
                tip: tip.clone(),
                after: after.clone(),
            },
        );
        honest_rows.push(row);
        let page = page.unwrap();
        let rows = page["packets"].as_array().unwrap();
        assert_eq!(rows.len(), 1);
        let raw = hex::decode(rows[0].as_str().unwrap()).unwrap();
        let authenticated = Packet::decode(&raw).unwrap();
        assert_eq!(raw, packet.encode().unwrap());
        let id = verifier
            .admit(&authenticated, ingress::now().unwrap())
            .unwrap();
        verifier
            .activate_observed(id, ingress::now().unwrap())
            .unwrap();
        after = hex::encode(id);
    }
    let independent_confirmations = verifier
        .confirmations(&transaction_queries, ingress::now().unwrap())
        .unwrap();
    let confirmed = independent_confirmations
        .observations
        .iter()
        .filter(|x| x.confirmed && !x.reorged && !x.finalized && !x.execution_authority)
        .count();
    let metrics = service.finish().unwrap();
    assert_eq!(attack_rows.len(), 12);
    assert!(attack_rows
        .iter()
        .all(|row| row["ok"] == false && row["response"]["error"] == "WORK:Transcript"));
    assert_eq!(metrics.work_failed, attack_rows.len() as u64);
    assert_eq!(metrics.work_started, metrics.work_finished);
    assert_eq!(metrics.work_started, 9 + attack_rows.len() as u64);
    assert_eq!(honest_rows.len(), 18);
    assert!(honest_rows.iter().all(|row| row["ok"] == true));
    let actual = Arc::try_unwrap(owner).ok().unwrap().into_inner().unwrap();
    let state_equal = actual.read_active().unwrap() == verifier.read_active().unwrap();
    let ending = meter.observe().unwrap();
    let flow_after = meter.observe_actual_flow().unwrap();
    let report = json!({
        "schema":"pon-w1-controlled-cpu-debt-native-recovery-v1",
        "source_scope":"controlled owner precharge of actual incorrect W1 relation; remote attackers did not generate CPU debt",
        "preload":preload_report,
        "hostile_network_rows":attack_rows,
        "honest_rows":honest_rows,
        "original_native_metrics":metrics,
        "immediate_new_start_budget_refusal":start_refusal,
        "shared_cpu_final_meter":ending,
        "shared_cpu_exact_flow":flow_after,
        "confirmed_transactions":confirmed,
        "independent_reexecution_state_equal":state_equal,
        "physical_power_loss":false,
        "public_network_ready":false,
        "work_profile_qualified":false,
        "resource_fairness_qualified":false,
        "production_activation":false
    });
    std::fs::write(
        path.join("report.json"),
        serde_json::to_vec_pretty(&report).unwrap(),
    )
    .unwrap();
    println!(
        "W1_DEBT_RESUME_SUMMARY={}",
        json!({
            "confirmed_transactions":confirmed,
            "native_work_failed":metrics.work_failed,
            "native_mutation_cpu_refusals":metrics.mutation_cpu_refusals,
            "full_work_charged_ns":metrics.mutation_full_work_cpu_ns,
            "low_credit":low_credit.stored_credit_ns,
            "state_equal":state_equal
        })
    );
    assert_eq!(confirmed, 1);
    assert!(state_equal);
    assert!(metrics.work_failed > 0);
    assert_eq!(metrics.mutation_cpu_clock_failures, 0);
    assert_eq!(metrics.mutation_cpu_in_flight_after_shutdown, 0);
    assert!(flow_after.is_some_and(|f| f.balance_identity_verified));
}
