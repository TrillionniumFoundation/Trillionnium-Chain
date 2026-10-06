//! Saved finite local service observations; not WAN, independent-operator or PoN cost qualification.
use serde_json::{json, Value};
use std::{
    fs,
    io::Write,
    net::{Shutdown, SocketAddr, TcpListener, TcpStream},
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Barrier, Mutex,
    },
    thread,
    time::{Duration, Instant},
};
use trnm_crypto_primitives::{pon_work, sign_hex, signing_key_from_hex};
use trnm_mvcc_fee::pon_executor;
use trnm_pon_node::{
    development_public,
    ingress::{
        self,
        public_v3::{self, PublicMetrics, PublicPolicy, PublicRequestObserver, PublicServer, Request},
        DevelopmentIdentity,
    },
    Node, PoolLimits, Settings,
};
use trnm_protocol::pon_wire::{hash, Envelope};

const PROBES: usize = 16;
const ATTACKS: usize = 16;
const FALSE_TRANSCRIPTS: usize = 8;
const MAX_GAP_NS: u64 = 2_000_000_000;
const MAX_CALL_MS: u64 = 500;
fn identity(n: u8) -> DevelopmentIdentity {
    DevelopmentIdentity::from_secret_hex(&hex::encode([n; 32])).unwrap()
}
fn ns(start: Instant) -> u64 {
    start.elapsed().as_nanos().try_into().unwrap()
}
fn snapshot(node: &Node) -> Value {
    let (tip, generation, state) = node.read_active().unwrap();
    json!({"tip":hex::encode(tip),"generation":generation,"state_root":hex::encode(pon_executor::root(&state).unwrap()),"stats":node.stats().unwrap()})
}
fn transfer(settings: &Settings, nonce: u64) -> Vec<u8> {
    let mut payload = development_public(1).unwrap().to_vec();
    payload.extend(1u64.to_le_bytes());
    let mut tx = Envelope {
        network: settings.network(),
        sender: development_public(0).unwrap(),
        nonce,
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
fn false_transcript(producer: &mut Node, phase: u64) -> (String, Value) {
    let total = Instant::now();
    let parent = producer.active().unwrap().0;
    let start = Instant::now();
    let reference = producer
        .make(
            parent,
            vec![],
            development_public(0).unwrap(),
            producer.settings().genesis_time() + phase * 2 + 2,
            4096,
        )
        .unwrap();
    let construction_ns = ns(start);
    let h = &reference.header;
    let start = Instant::now();
    pon_work::verify(h.challenge(), h.work_task, h.target, &reference.proof).unwrap();
    let reference_verification_ns = ns(start);
    let reference_bytes = reference.encode().unwrap();
    let challenge = h.challenge();
    let mut forged = reference.clone();
    let trace_offset = forged.proof.len() - 32;
    let start = Instant::now();
    let mut found = None;
    for nonce in 0..4096u64 {
        let trace = hash(
            b"public-v3-false-trace-v2",
            &[&challenge, &nonce.to_le_bytes()],
        );
        let ticket = hash(b"ticket", &[&challenge, &trace]);
        if trace.as_slice() != &reference.proof[trace_offset..] && ticket <= h.target {
            forged.proof[trace_offset..].copy_from_slice(&trace);
            found = Some(nonce + 1);
            break;
        }
    }
    let ticket_search_ns = ns(start);
    let ticket_trials = found.expect("bounded false-trace ticket search");
    let forged_packet = hex::encode(forged.encode().unwrap());
    let total_preparation_ns = ns(total);
    let fixture = json!({"reference_packet":hex::encode(reference_bytes),"forged_packet":forged_packet,"construction_ns":construction_ns,"reference_verification_ns":reference_verification_ns,"total_preparation_ns":total_preparation_ns,"ticket_search_ns":ticket_search_ns,"ticket_trials":ticket_trials,"scope":"real reference construction and verification followed by hash-only false-trace search; not a fastest-attacker bound"});
    (forged_packet, fixture)
}
// This producer accepts only an untrusted statement and a finite hash budget.
// It has no Node, prepared task, product evaluator or previously valid proof.
fn fake_trace_search(
    challenge: [u8; 32],
    target: [u8; 32],
    budget: u64,
) -> (Option<[u8; 32]>, Value) {
    assert!(budget <= 4096);
    let start = Instant::now();
    let mut attempts = Vec::new();
    let mut found = None;
    for nonce in 0..budget {
        let trace = hash(
            b"public-v3-from-zero-trace-v1",
            &[&challenge, &nonce.to_le_bytes()],
        );
        let ticket = hash(b"ticket", &[&challenge, &trace]);
        let hit = ticket <= target;
        attempts.push(json!({"nonce":nonce,"trace":hex::encode(trace),"ticket":hex::encode(ticket),"hit":hit}));
        if hit {
            found = Some(trace);
            break;
        }
    }
    let elapsed_ns = ns(start);
    let winners = u64::from(found.is_some());
    let per_winner_ns = found.map(|_| elapsed_ns);
    (
        found,
        json!({"target":hex::encode(target),"budget":budget,"attempts":attempts,"winners":winners,"elapsed_ns":elapsed_ns,"per_winner_ns":per_winner_ns}),
    )
}
fn from_zero_transcript(node: &Node, phase: u64) -> (Option<String>, Value) {
    let total = Instant::now();
    let start = Instant::now();
    let settings = node.settings();
    let parent = node.active().unwrap().0;
    let (a, b) = trnm_pon_node::maintenance();
    let header = trnm_protocol::pon_wire::Header {
        network: settings.network(),
        parameters: settings.parameters(),
        parent,
        height: phase * 2 + 1,
        timestamp: settings.genesis_time() + phase * 2 + 2,
        target: node.expected_target(parent).unwrap(),
        miner: development_public(0).unwrap(),
        transactions: trnm_pon_node::sequence_root("transactions", &[]),
        // State/product/receipts are deliberately not computed. Passing context
        // and the cheap ticket filter must still lead to full W1 rejection.
        state: [0; 32],
        receipts: [0; 32],
        work_task: pon_work::task_id(&a, &b).unwrap(),
        nonce: 0,
    };
    let mut proof = Vec::with_capacity(pon_work::PROOF_BYTES);
    proof.extend_from_slice(b"PNW1");
    for matrix in [&a, &b] {
        for value in matrix {
            proof.extend_from_slice(&value.to_le_bytes());
        }
    }
    proof.resize(pon_work::PROOF_BYTES, 0);
    let challenge = header.challenge();
    let setup_ns = ns(start);
    let (trace, search) = fake_trace_search(challenge, header.target, 4096);
    let start = Instant::now();
    let packet = trace.map(|trace| {
        proof[pon_work::PROOF_BYTES - 32..].copy_from_slice(&trace);
        trnm_pon_node::Packet {
            header: header.clone(),
            transactions: vec![],
            proof,
        }
    });
    let encoded = packet.as_ref().map(|p| hex::encode(p.encode().unwrap()));
    let encode_ns = ns(start);
    let construction_ns = ns(total);

    // Independent diagnostic controls run only after construction has ended.
    // They are neither costs paid by the attack builder nor server CPU samples.
    let (empty, empty_search) = fake_trace_search(challenge, header.target, 0);
    assert!(empty.is_none());
    let mut tiny_target = [0; 32];
    tiny_target[31] = 1;
    let (exhausted, exhausted_search) = fake_trace_search(challenge, tiny_target, 1);
    assert!(exhausted.is_none());
    let mut audit = Vec::new();
    if let Some(packet) = &packet {
        for kernel in ["production", "scalar-reference", "limb"] {
            let mut tiles = 0;
            let mut product_started = false;
            let mut verified_boundary = false;
            let mut observe = |point| {
                match point {
                    pon_work::VerificationProgress::TranscriptTile { .. } => tiles += 1,
                    pon_work::VerificationProgress::BeforeProduct => product_started = true,
                    pon_work::VerificationProgress::BeforeVerifiedWork => verified_boundary = true,
                    _ => {}
                }
                Ok::<(), std::convert::Infallible>(())
            };
            let start = Instant::now();
            let result = match kernel {
                "production" => pon_work::verify_with_progress(
                    challenge,
                    header.work_task,
                    header.target,
                    &packet.proof,
                    &mut observe,
                ),
                "scalar-reference" => pon_work::verify_reference_with_progress(
                    challenge,
                    header.work_task,
                    header.target,
                    &packet.proof,
                    &mut observe,
                ),
                _ => pon_work::verify_limb_with_progress(
                    challenge,
                    header.work_task,
                    header.target,
                    &packet.proof,
                    &mut observe,
                ),
            };
            let elapsed_ns = ns(start);
            assert_eq!(
                result.unwrap_err(),
                pon_work::VerificationError::Relation(pon_work::WorkError::Transcript)
            );
            assert_eq!(tiles, 512);
            assert!(!product_started && !verified_boundary);
            audit.push(json!({"kernel":kernel,"elapsed_ns":elapsed_ns,"transcript_tiles":tiles,"product_started":product_started,"verified_boundary":verified_boundary,"error":"Transcript"}));
        }
    }
    let fixture = json!({"packet":encoded,"header":hex::encode(header.encode()),"setup_ns":setup_ns,"search":search,"encode_ns":encode_ns,"construction_ns":construction_ns,"empty_search":empty_search,"exhausted_search":exhausted_search,"audit_verifications":audit,"scope":"public legacy maintenance operands; arbitrary zero state, receipts and claimed product; hash-only from-zero construction before all verifier audits; one retained packet reused by four paid calls"});
    (encoded, fixture)
}

#[derive(Clone)]
struct Client {
    address: SocketAddr,
    settings: Settings,
    epoch: Instant,
    phase: u64,
    records: Arc<Mutex<Vec<Value>>>,
}
impl Client {
    fn call(&self, lane: &str, who: u8, request: Request) -> bool {
        self.call_built(lane, who, || request)
    }
    fn call_built(&self, lane: &str, who: u8, build: impl FnOnce() -> Request) -> bool {
        let start = Instant::now();
        let started_ns = ns(self.epoch);
        let request = build();
        let (reply, metrics) = public_v3::call_public_protected_v3_with_deadline(
            self.address,
            &request,
            &self.settings,
            identity(71).public_key(),
            &identity(who),
            PublicPolicy::new(8, Duration::from_secs(2)).unwrap(),
            Some(start + Duration::from_millis(MAX_CALL_MS)),
        );
        let ended_ns = ns(self.epoch);
        let ok = reply.as_ref().is_ok_and(|r| r.ok);
        let (response, error, status) = match reply {
            Ok(r) => (
                Some(serde_json::to_value(r).unwrap()),
                None,
                if ok { "ok" } else { "refused" },
            ),
            Err(e) => (None, Some(e.to_string()), "error"),
        };
        self.records.lock().unwrap().push(json!({"phase":self.phase,"lane":lane,"caller_fixture":who,"request":request,"started_ns":started_ns,"ended_ns":ended_ns,"status":status,"response":response,"error":error,"metrics":metrics,"unpaid_written_bytes":null}));
        ok
    }
    fn unpaid(&self) {
        let started_ns = ns(self.epoch);
        let mut written_bytes = None;
        let result = (|| {
            let mut stream =
                TcpStream::connect_timeout(&self.address, Duration::from_millis(MAX_CALL_MS))?;
            stream.set_write_timeout(Some(Duration::from_millis(MAX_CALL_MS)))?;
            stream.write_all(&[0; 4])?;
            written_bytes = Some(4u64);
            stream.shutdown(Shutdown::Both)?;
            Ok::<_, std::io::Error>(())
        })();
        self.records.lock().unwrap().push(json!({"phase":self.phase,"lane":"unpaid_invalid","caller_fixture":null,"request":null,"started_ns":started_ns,"ended_ns":ns(self.epoch),"status":if result.is_ok(){"sent"}else{"error"},"response":null,"error":result.as_ref().err().map(ToString::to_string),"metrics":null,"unpaid_written_bytes":written_bytes}));
    }
}
fn phase(
    number: u64,
    node: Node,
    producer: &mut Node,
    records: Arc<Mutex<Vec<Value>>>,
    epoch: Instant,
    path: &Path,
) -> (Node, Value) {
    let settings = node.settings().clone();
    let context = node.pool_status_snapshot().unwrap().context;
    assert_eq!(node.active().unwrap().0, producer.active().unwrap().0);
    // Construct the from-zero arm before any valid reference proof is acquired.
    let (from_zero_packet, from_zero_fixture) = from_zero_transcript(producer, number);
    fs::write(
        path.join(format!("from-zero-{number}.json")),
        serde_json::to_vec_pretty(&from_zero_fixture).unwrap(),
    )
    .unwrap();
    let from_zero_packet = from_zero_packet.expect("retained from-zero search exhausted");
    let (forged_packet, false_transcript_fixture) = false_transcript(producer, number);
    let owner = Arc::new(Mutex::new(node));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let (shared, signal) = (owner.clone(), stop.clone());
    let observer = PublicRequestObserver::new(128).unwrap();
    let capture = observer.clone();
    let worker = thread::spawn(move || {
        public_v3::serve_public_protected_v3_with_request_observer(
            listener,
            shared,
            Duration::from_secs(30),
            signal,
            PublicServer::new(
                identity(71),
                PublicPolicy::new(8, Duration::from_secs(2)).unwrap(),
            )
            .unwrap(),
            Arc::new(Mutex::new(PublicMetrics::default())),
            capture,
        )
        .unwrap()
    });
    let client = Client {
        address,
        settings: settings.clone(),
        epoch,
        phase: number,
        records: records.clone(),
    };
    let barrier = Arc::new(Barrier::new(5));
    let started_ns = ns(epoch);
    let spawn = |kind: u8| {
        let (client, barrier, forged_packet, from_zero_packet) = (
            client.clone(),
            barrier.clone(),
            forged_packet.clone(),
            from_zero_packet.clone(),
        );
        thread::spawn(move || {
            barrier.wait();
            let attempts = match kind {
                0 => PROBES,
                3 => FALSE_TRANSCRIPTS,
                _ => ATTACKS,
            };
            for i in 0..attempts {
                if kind == 0 {
                    client.call("honest_probe", 72, Request::Head);
                } else if kind == 1 {
                    // Rotating public guest keys have no ledger authority. This is a
                    // paid malformed-packet load, not a full matrix-work cost attack.
                    client.call(
                        "paid_invalid",
                        100 + (i % 8) as u8,
                        Request::Submit {
                            packet: "00".into(),
                        },
                    );
                } else if kind == 2 {
                    client.unpaid();
                } else {
                    // Keep eight paid W1 calls and the same server budget.
                    // Alternate both arms, reversing order after the restart.
                    let from_zero = (i + client.phase as usize) % 2 == 1;
                    client.call_built(
                        if from_zero {
                            "paid_from_zero"
                        } else {
                            "paid_false_transcript"
                        },
                        120 + (i % 8) as u8,
                        || Request::Submit {
                            packet: if from_zero {
                                from_zero_packet.clone()
                            } else {
                                forged_packet.clone()
                            },
                        },
                    );
                }
                thread::sleep(Duration::from_millis(10));
            }
        })
    };
    let workers = [spawn(0), spawn(1), spawn(2), spawn(3)];
    barrier.wait();
    let mut mutations_ok = true;
    for offset in 0..2 {
        let nonce = number * 2 + offset + 1;
        let tx = transfer(&settings, nonce);
        mutations_ok &= client.call("honest_mutation", 73, Request::PoolStatus);
        mutations_ok &= client.call(
            "honest_mutation",
            73,
            Request::PoolSubmitBundle {
                pool_context: context.clone(),
                transactions: vec![hex::encode(&tx)],
            },
        );
        let packet = producer
            .mine(
                vec![tx],
                settings.genesis_time() + nonce + 1,
                ingress::now().unwrap(),
            )
            .unwrap();
        mutations_ok &= client.call(
            "honest_mutation",
            73,
            Request::Submit {
                packet: hex::encode(packet.encode().unwrap()),
            },
        );
        mutations_ok &= client.call("honest_mutation", 73, Request::Head);
    }
    for thread in workers {
        thread.join().unwrap();
    }
    // A real socket closes before any request reaches the receiver. Retain the
    // complete failed client attempt; it is not relabeled as a successful probe.
    let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
    let fault_client = Client {
        address: proxy.local_addr().unwrap(),
        ..client.clone()
    };
    let close = thread::spawn(move || {
        let (socket, _) = proxy.accept().unwrap();
        drop(socket);
    });
    let injected_fault_refused = !fault_client.call("injected_eof", 72, Request::Head);
    close.join().unwrap();
    let ended_ns = ns(epoch);
    stop.store(true, Ordering::Release);
    let metrics = worker.join().unwrap();
    let server_observations = observer.snapshot();
    let resource_observations_complete = server_observations.records_not_retained == 0
        && server_observations.measurement_failures == 0
        && !server_observations.counter_overflow
        && server_observations.accepted_connections_seen == metrics.accepted_connections
        && server_observations.records.len() as u64 == metrics.accepted_connections
        && server_observations.records.iter().all(|r| r.complete);
    let node = Arc::try_unwrap(owner).ok().unwrap().into_inner().unwrap();
    let owner_state = snapshot(&node);
    let producer_state = snapshot(producer);
    let byte_equal_state = node.read_active().unwrap().2 == producer.read_active().unwrap().2;
    let rows = records.lock().unwrap();
    let mut probe_ends: Vec<_> = rows
        .iter()
        .filter(|r| r["phase"] == number && r["lane"] == "honest_probe" && r["status"] == "ok")
        .map(|r| r["ended_ns"].as_u64().unwrap())
        .collect();
    probe_ends.sort_unstable();
    let probe_successes = probe_ends.len();
    probe_ends.insert(0, started_ns);
    probe_ends.push(ended_ns);
    let max_gap = probe_ends.windows(2).map(|w| w[1] - w[0]).max().unwrap();
    let all_invalid_refused = rows
        .iter()
        .filter(|r| r["phase"] == number && r["lane"] == "paid_invalid")
        .all(|r| r["status"] != "ok");
    let false_rows: Vec<_> = rows
        .iter()
        .filter(|r| r["phase"] == number && r["lane"] == "paid_false_transcript")
        .collect();
    let false_transcript_rejections = false_rows
        .iter()
        .filter(|r| {
            r["status"] == "refused" && r["response"]["value"]["error"] == "WORK:Transcript"
        })
        .count();
    let false_transcript_load_refused = false_rows.iter().all(|r| r["status"] != "ok");
    let from_zero_rows: Vec<_> = rows
        .iter()
        .filter(|r| r["phase"] == number && r["lane"] == "paid_from_zero")
        .collect();
    let from_zero_rejections = from_zero_rows
        .iter()
        .filter(|r| {
            r["status"] == "refused" && r["response"]["value"]["error"] == "WORK:Transcript"
        })
        .count();
    let from_zero_load_refused = from_zero_rows.iter().all(|r| r["status"] != "ok");
    let total_rejections = false_transcript_rejections + from_zero_rejections;
    let full_work_observed = false_transcript_rejections > 0
        && from_zero_rejections > 0
        && metrics.work_started >= 2 + total_rejections as u64
        && metrics.work_failed >= total_rejections as u64
        && metrics.work_finished == metrics.work_started;
    let pass = mutations_ok
        && probe_successes > 0
        && max_gap <= MAX_GAP_NS
        && injected_fault_refused
        && all_invalid_refused
        && false_transcript_load_refused
        && from_zero_load_refused
        && resource_observations_complete
        && full_work_observed
        && byte_equal_state
        && owner_state["tip"] == producer_state["tip"];
    (
        node,
        json!({"phase":number,"started_ns":started_ns,"ended_ns":ended_ns,"honest_probe_successes":probe_successes,"honest_probe_max_gap_ns":max_gap,"mutations_ok":mutations_ok,"injected_fault_refused":injected_fault_refused,"invalid_paid_requests_refused":all_invalid_refused,"false_transcript_load_refused":false_transcript_load_refused,"false_transcript_rejections":false_transcript_rejections,"full_work_observed":full_work_observed,"false_transcript_fixture":false_transcript_fixture,"from_zero_fixture":from_zero_fixture,"from_zero_rejections":from_zero_rejections,"from_zero_load_refused":from_zero_load_refused,"byte_equal_producer_state":byte_equal_state,"owner":owner_state,"producer":producer_state,"server_metrics":metrics,"server_observations":server_observations,"resource_observations_complete":resource_observations_complete,"finite_target_met":pass}),
    )
}
fn campaign(path: &Path) -> Value {
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
    let mut producer = Node::open(&path.join("producer"), settings.clone(), 2).unwrap();
    let epoch = Instant::now();
    let records = Arc::new(Mutex::new(Vec::new()));
    let (node, first) = phase(0, node, &mut producer, records.clone(), epoch, path);
    let before = snapshot(&node);
    drop(node);
    let reopened = Node::open(&receiver, settings.clone(), 2).unwrap();
    let after = snapshot(&reopened);
    let restart_equal =
        before["tip"] == after["tip"] && before["state_root"] == after["state_root"];
    let (node, second) = phase(1, reopened, &mut producer, records.clone(), epoch, path);
    drop(node);
    drop(producer);
    let mut attempts = Arc::try_unwrap(records).ok().unwrap().into_inner().unwrap();
    attempts.sort_by_key(|r| r["started_ns"].as_u64().unwrap());
    for (index, row) in attempts.iter_mut().enumerate() {
        row["ordinal"] = json!(index + 1);
    }
    let mut probe_completions: Vec<_> = attempts
        .iter()
        .filter(|r| r["lane"] == "honest_probe" && r["status"] == "ok")
        .map(|r| r["ended_ns"].as_u64().unwrap())
        .collect();
    probe_completions.sort_unstable();
    probe_completions.insert(0, first["started_ns"].as_u64().unwrap());
    probe_completions.push(second["ended_ns"].as_u64().unwrap());
    let max_gap_including_restart = probe_completions
        .windows(2)
        .map(|w| w[1] - w[0])
        .max()
        .unwrap();
    let met = restart_equal
        && max_gap_including_restart <= MAX_GAP_NS
        && first["finite_target_met"] == true
        && second["finite_target_met"] == true;
    json!({"schema":"public-v3-local-mixed-service-v3","transport_profile":public_v3::PROFILE,"policy_id":hex::encode(PublicPolicy::new(8,Duration::from_secs(2)).unwrap().id()),"bits":8,"ttl_ms":2000,"network":hex::encode(settings.network()),"parameters":hex::encode(settings.parameters()),"genesis":hex::encode(settings.genesis()),"genesis_time":settings.genesis_time(),"call_deadline_ms":MAX_CALL_MS,"phase_count":2,"probes_per_phase":PROBES,"paid_attempts_per_phase":ATTACKS,"unpaid_attempts_per_phase":ATTACKS,"false_transcript_attempts_per_phase":FALSE_TRANSCRIPTS / 2,"from_zero_attempts_per_phase":FALSE_TRANSCRIPTS / 2,"honest_probe_gap_target_ns":MAX_GAP_NS,"honest_probe_max_gap_including_restart_ns":max_gap_including_restart,"gap_rule":"phase boundaries and consecutive successful honest Head completions; includes failed attempts and idle scheduling; finite observation only","scope":"one process, local TCP, public development identities; alternating reference-seeded and from-zero false-transcript W1 with unchanged shared server budget, malformed packets and unpaid prefixes; not a public fairness or fastest-attacker bound","restart":{"kind":"same-process-owner-and-server-restart","before":before,"after":after,"same_active_state":restart_equal},"phases":[first,second],"attempts":attempts,"finite_target_met":met,"public_network_ready":false,"independent_accepted":false,"resource_fairness_qualified":false,"work_profile_qualified":false,"physical_power_loss":false,"production_activation":false})
}
#[test]
fn public_v3_mixed_calls_reopen_with_complete_failure_denominators() {
    let temporary = tempfile::tempdir().unwrap();
    let path = if let Some(path) = std::env::var_os("TRNM_PUBLIC_V3_CAMPAIGN_DIR") {
        let path = std::path::PathBuf::from(path);
        fs::create_dir(&path).unwrap();
        path
    } else {
        temporary.path().to_path_buf()
    };
    let report = campaign(&path);
    fs::write(
        path.join("report.json"),
        serde_json::to_vec_pretty(&report).unwrap(),
    )
    .unwrap();
    println!(
        "{}",
        json!({"schema":report["schema"],"attempts":report["attempts"].as_array().unwrap().len(),"finite_target_met":report["finite_target_met"],"public_network_ready":false})
    );
    assert_eq!(
        report["finite_target_met"], true,
        "see retained request and phase outcomes"
    );
}
