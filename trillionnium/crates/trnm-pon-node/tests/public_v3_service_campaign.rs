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
        public_v3::{self, PublicPolicy, PublicServer, Request},
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
    let fixture = json!({"reference_packet":hex::encode(reference_bytes),"forged_packet":forged_packet,"construction_ns":construction_ns,"reference_verification_ns":reference_verification_ns,"ticket_search_ns":ticket_search_ns,"ticket_trials":ticket_trials,"scope":"real reference construction and verification followed by hash-only false-trace search; not a fastest-attacker bound"});
    (forged_packet, fixture)
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
        let start = Instant::now();
        let started_ns = ns(self.epoch);
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
) -> (Node, Value) {
    let settings = node.settings().clone();
    let context = node.pool_status_snapshot().unwrap().context;
    assert_eq!(node.active().unwrap().0, producer.active().unwrap().0);
    let (forged_packet, false_transcript_fixture) = false_transcript(producer, number);
    let owner = Arc::new(Mutex::new(node));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let (shared, signal) = (owner.clone(), stop.clone());
    let worker = thread::spawn(move || {
        public_v3::serve_public_protected_v3(
            listener,
            shared,
            Duration::from_secs(30),
            signal,
            PublicServer::new(
                identity(71),
                PublicPolicy::new(8, Duration::from_secs(2)).unwrap(),
            )
            .unwrap(),
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
        let (client, barrier, forged_packet) =
            (client.clone(), barrier.clone(), forged_packet.clone());
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
                    client.call(
                        "paid_false_transcript",
                        120 + (i % 8) as u8,
                        Request::Submit {
                            packet: forged_packet.clone(),
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
    let full_work_observed = false_transcript_rejections > 0
        && metrics.work_started >= 2 + false_transcript_rejections as u64
        && metrics.work_failed >= false_transcript_rejections as u64
        && metrics.work_finished == metrics.work_started;
    let pass = mutations_ok
        && probe_successes > 0
        && max_gap <= MAX_GAP_NS
        && injected_fault_refused
        && all_invalid_refused
        && false_transcript_load_refused
        && full_work_observed
        && byte_equal_state
        && owner_state["tip"] == producer_state["tip"];
    (
        node,
        json!({"phase":number,"started_ns":started_ns,"ended_ns":ended_ns,"honest_probe_successes":probe_successes,"honest_probe_max_gap_ns":max_gap,"mutations_ok":mutations_ok,"injected_fault_refused":injected_fault_refused,"invalid_paid_requests_refused":all_invalid_refused,"false_transcript_load_refused":false_transcript_load_refused,"false_transcript_rejections":false_transcript_rejections,"full_work_observed":full_work_observed,"false_transcript_fixture":false_transcript_fixture,"byte_equal_producer_state":byte_equal_state,"owner":owner_state,"producer":producer_state,"server_metrics":metrics,"finite_target_met":pass}),
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
    let (node, first) = phase(0, node, &mut producer, records.clone(), epoch);
    let before = snapshot(&node);
    drop(node);
    let reopened = Node::open(&receiver, settings.clone(), 2).unwrap();
    let after = snapshot(&reopened);
    let restart_equal =
        before["tip"] == after["tip"] && before["state_root"] == after["state_root"];
    let (node, second) = phase(1, reopened, &mut producer, records.clone(), epoch);
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
    json!({"schema":"public-v3-local-mixed-service-v2","transport_profile":public_v3::PROFILE,"policy_id":hex::encode(PublicPolicy::new(8,Duration::from_secs(2)).unwrap().id()),"bits":8,"ttl_ms":2000,"network":hex::encode(settings.network()),"parameters":hex::encode(settings.parameters()),"genesis":hex::encode(settings.genesis()),"genesis_time":settings.genesis_time(),"call_deadline_ms":MAX_CALL_MS,"phase_count":2,"probes_per_phase":PROBES,"paid_attempts_per_phase":ATTACKS,"unpaid_attempts_per_phase":ATTACKS,"false_transcript_attempts_per_phase":FALSE_TRANSCRIPTS,"honest_probe_gap_target_ns":MAX_GAP_NS,"honest_probe_max_gap_including_restart_ns":max_gap_including_restart,"gap_rule":"phase boundaries and consecutive successful honest Head completions; includes failed attempts and idle scheduling; finite observation only","scope":"one process, local TCP, public development identities; paid false-transcript W1 and malformed-packet load with unpaid prefixes; not a public fairness or fastest-attacker bound","restart":{"kind":"same-process-owner-and-server-restart","before":before,"after":after,"same_active_state":restart_equal},"phases":[first,second],"attempts":attempts,"finite_target_met":met,"public_network_ready":false,"independent_accepted":false,"resource_fairness_qualified":false,"work_profile_qualified":false,"physical_power_loss":false,"production_activation":false})
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

#[cfg(target_os = "linux")]
mod network_only_business {
    //! The receiver has no local load/debit hook. Every charged mutation comes
    //! through paid public TCP. A separate native consumer reexecutes downloaded
    //! packets before observing confirmation; an ACK/Head is not that proof.
    use super::*;
    use std::sync::atomic::AtomicU64;
    use trnm_pon_node::{Packet, Result};

    const WORKERS: usize = 4;
    const CALLS_PER_WORKER: usize = 512;
    const WINDOW: Duration = Duration::from_secs(6);
    const CALL_LIMIT: Duration = Duration::from_secs(2);
    const BLOCKS: usize = 9;
    const BUSINESS_BLOCKS: usize = 3;
    const TRANSACTIONS: usize = 8;

    fn cpu_ns() -> Option<u64> {
        use rustix::time::{clock_gettime_dynamic, ClockId, DynamicClockId};
        let now = clock_gettime_dynamic(DynamicClockId::Known(ClockId::ThreadCPUTime)).ok()?;
        let seconds = u64::try_from(now.tv_sec).ok()?;
        let nanos = u64::try_from(now.tv_nsec).ok()?;
        if nanos >= 1_000_000_000 {
            return None;
        }
        seconds.checked_mul(1_000_000_000)?.checked_add(nanos)
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

    fn call(
        address: SocketAddr,
        settings: &Settings,
        epoch: Instant,
        who: u8,
        request: &Request,
    ) -> (Option<Value>, Value) {
        let started = Instant::now();
        let started_ns = ns(epoch);
        let cpu_before = cpu_ns();
        let (outcome, metrics) = public_v3::call_public_protected_v3_with_deadline(
            address,
            request,
            settings,
            identity(71).public_key(),
            &identity(who),
            PublicPolicy::new(8, CALL_LIMIT).unwrap(),
            Some(started + CALL_LIMIT),
        );
        let elapsed_cpu = cpu_before.and_then(|before| cpu_ns()?.checked_sub(before));
        let ended_ns = ns(epoch);
        match outcome {
            Ok(reply) => {
                let ok = reply.ok;
                let value = reply.value;
                let row = json!({"caller_fixture":who,"started_ns":started_ns,
                    "ended_ns":ended_ns,"ok":ok,"on_time":started.elapsed()<=CALL_LIMIT,
                    "client_thread_cpu_ns":elapsed_cpu,"transport":metrics,
                    "response":if ok {Value::Null}else{value.clone()},"error":null});
                (ok.then_some(value), row)
            }
            Err(error) => (
                None,
                json!({"caller_fixture":who,"started_ns":started_ns,
                "ended_ns":ended_ns,"ok":false,"on_time":started.elapsed()<=CALL_LIMIT,
                "client_thread_cpu_ns":elapsed_cpu,"transport":metrics,
                "response":null,"error":error.to_string()}),
            ),
        }
    }

    #[test]
    fn network_only_business_confirmations_survive_rotating_false_work() {
        let temporary = tempfile::tempdir().unwrap();
        let path = match std::env::var_os("TRNM_CI_RECEIPT_DIR") {
            Some(root) => {
                let path = std::path::PathBuf::from(root).join("network-only-business");
                fs::create_dir(&path).unwrap();
                path
            }
            None => temporary.path().to_path_buf(),
        };
        let settings = Settings::development(Some(1_750_000_000)).unwrap();
        let receiver_path = path.join("receiver");
        let mut receiver =
            Node::open_with_authenticated_state(&receiver_path, settings.clone(), 2).unwrap();
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
        let mut producer = Node::open(&path.join("producer"), settings.clone(), 1).unwrap();
        // Keep full acquisition and bounded trace-search costs rather than
        // presenting the supplied strategy as a physical lower bound.
        let attacks: Vec<_> = (0..WORKERS)
            .map(|i| false_transcript(&mut producer, i as u64))
            .collect();
        let mut queries = Vec::new();
        let packets: Vec<_> = (0..BLOCKS)
            .map(|height| {
                let transactions: Vec<_> = if height < BUSINESS_BLOCKS {
                    (0..TRANSACTIONS)
                        .map(|offset| {
                            transfer(&settings, (height * TRANSACTIONS + offset + 1) as u64)
                        })
                        .collect()
                } else {
                    Vec::new()
                };
                let packet = producer
                    .mine(
                        transactions,
                        settings.genesis_time() + (height as u64 + 1) * 10,
                        ingress::now().unwrap(),
                    )
                    .unwrap();
                for raw in &packet.transactions {
                    queries.push((
                        Envelope::decode(raw).unwrap().id().unwrap(),
                        packet.id().unwrap(),
                    ));
                }
                packet
            })
            .collect();
        let expected = producer.read_active().unwrap();
        let owner = Arc::new(Mutex::new(receiver));
        let server =
            PublicServer::new(identity(71), PublicPolicy::new(8, CALL_LIMIT).unwrap()).unwrap();
        let domain = server.mutation_cpu_domain();
        let initial_meter = domain.observe().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let observer =
            public_v3::PublicRequestObserver::new(WORKERS * CALLS_PER_WORKER + 128).unwrap();
        let metrics = Arc::new(Mutex::new(public_v3::PublicMetrics::default()));
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
            })),
        };
        let epoch = Instant::now();
        let end = epoch + WINDOW;
        let barrier = Barrier::new(WORKERS + 1);
        let completed = AtomicU64::new(0);
        let mut honest_rows = Vec::new();
        let mut consumer =
            Node::open_with_authenticated_state(&path.join("consumer"), settings.clone(), 1)
                .unwrap();
        let (attack_rows, honest_result) = thread::scope(|scope| {
            let handles: Vec<_> = attacks.iter().enumerate().map(|(worker,(wire,_))| {
                let (barrier,completed,settings) = (&barrier,&completed,&settings);
                scope.spawn(move || {
                    barrier.wait();
                    let mut rows = Vec::new();
                    for attempt in 0..CALLS_PER_WORKER {
                        if Instant::now() >= end { break; }
                        let who = 80 + ((worker * 37 + attempt) % 150) as u8;
                        let (_,row) = call(address,settings,epoch,who,&Request::Submit {packet:wire.clone()});
                        rows.push(row);
                        completed.fetch_add(1,Ordering::Release);
                    }
                    json!({"worker":worker,"cap_reached":rows.len()==CALLS_PER_WORKER,"calls":rows})
                })
            }).collect();
            barrier.wait();
            while completed.load(Ordering::Acquire) == 0 && Instant::now() < end {
                thread::sleep(Duration::from_millis(1));
            }
            let result = (|| -> Result<()> {
                for packet in &packets {
                    let (reply, mut row) = call(
                        address,
                        &settings,
                        epoch,
                        73,
                        &Request::Submit {
                            packet: hex::encode(packet.encode()?),
                        },
                    );
                    row["kind"] = json!("honest_submit");
                    row["block"] = json!(hex::encode(packet.id()?));
                    row["transactions"] = json!(packet.transactions.len());
                    honest_rows.push(row);
                    if reply
                        .as_ref()
                        .is_none_or(|r| r["block"] != hex::encode(packet.id().unwrap()))
                    {
                        return Err("NETWORK_ONLY_SUBMIT".into());
                    }
                }
                let tip = hex::encode(packets.last().unwrap().id()?);
                let (head, mut row) = call(address, &settings, epoch, 72, &Request::Head);
                row["kind"] = json!("head");
                honest_rows.push(row);
                if head.as_ref().is_none_or(|h| h["tip"] != tip) {
                    return Err("NETWORK_ONLY_HEAD".into());
                }
                let mut after = hex::encode(settings.genesis());
                for expected_packet in &packets {
                    let (page, mut row) = call(
                        address,
                        &settings,
                        epoch,
                        72,
                        &Request::History {
                            tip: tip.clone(),
                            after: after.clone(),
                        },
                    );
                    row["kind"] = json!("history");
                    honest_rows.push(row);
                    let page = page.ok_or("NETWORK_ONLY_HISTORY")?;
                    if page["tip"] != tip
                        || page["after"] != after
                        || page["network"] != hex::encode(settings.network())
                        || page["parameters"] != hex::encode(settings.parameters())
                        || page["genesis"] != hex::encode(settings.genesis())
                    {
                        return Err("NETWORK_ONLY_CONTEXT".into());
                    }
                    let rows = page["packets"].as_array().ok_or("NETWORK_ONLY_PAGE")?;
                    if rows.len() != 1 {
                        return Err("NETWORK_ONLY_PAGE".into());
                    }
                    let raw = hex::decode(rows[0].as_str().ok_or("NETWORK_ONLY_PACKET")?)
                        .map_err(|_| "NETWORK_ONLY_PACKET")?;
                    // No direct producer-to-consumer copy supplies authority.
                    let packet = Packet::decode(&raw)?;
                    let id = consumer.admit(&packet, ingress::now()?)?;
                    consumer.activate_observed(id, ingress::now()?)?;
                    if raw != expected_packet.encode()?
                        || page["next"] != hex::encode(id)
                        || page["complete"] != (hex::encode(id) == tip)
                    {
                        return Err("NETWORK_ONLY_HISTORY_BYTES".into());
                    }
                    after = hex::encode(id);
                }
                Ok(())
            })();
            let rows = handles
                .into_iter()
                .map(|h| h.join().unwrap())
                .collect::<Vec<_>>();
            (rows, result)
        });
        let server_result = service.finish();
        let observations = observer.snapshot();
        let receiver = Arc::try_unwrap(owner).ok().unwrap().into_inner().unwrap();
        let receiver_state = receiver.read_active().unwrap();
        let consumer_state = consumer.read_active().unwrap();
        let confirmation = consumer.confirmations(&queries, ingress::now().unwrap());
        let confirmed = confirmation.as_ref().map_or(0, |batch| {
            batch
                .observations
                .iter()
                .filter(|o| o.confirmed && !o.reorged && !o.finalized && !o.execution_authority)
                .count()
        });
        let full_state_equal = receiver_state == expected && consumer_state == expected;
        drop(receiver);
        let reopened =
            Node::open_with_authenticated_state(&receiver_path, settings.clone(), 2).unwrap();
        let reopen_equal = reopened.read_active().unwrap() == expected;
        let final_meter = domain.observe().unwrap();
        let calls = attack_rows
            .iter()
            .flat_map(|r| r["calls"].as_array().unwrap())
            .collect::<Vec<_>>();
        let honest_start = honest_rows.first().unwrap()["started_ns"].as_u64().unwrap();
        let honest_end = honest_rows.last().unwrap()["ended_ns"].as_u64().unwrap();
        let overlap = calls
            .iter()
            .filter(|r| {
                r["started_ns"].as_u64().unwrap() < honest_end
                    && r["ended_ns"].as_u64().unwrap() > honest_start
            })
            .count();
        let pass = honest_result.is_ok()
            && server_result.as_ref().is_ok_and(|m| {
                m.work_failed > 0
                    && m.work_started == m.work_finished
                    && m.mutation_cpu_clock_failures == 0
                    && m.peak_connections <= 64
                    && m.peak_paid_body_bytes <= 8 * 1024 * 1024
                    && m.peak_output_reserved_bytes <= 32 * 1024 * 1024
                    && m.mutation_cpu_in_flight_after_shutdown == 0
                    && m.paid_body_reserved_bytes_after_shutdown == 0
                    && m.output_reserved_bytes_after_shutdown == 0
                    && m.mutating_grants_after_shutdown == 0
                    && m.read_grants_after_shutdown == 0
            })
            && overlap > 0
            && !calls.is_empty()
            && calls.iter().all(|r| r["ok"] == false)
            && honest_rows
                .iter()
                .all(|r| r["ok"] == true && r["on_time"] == true)
            && confirmed == BUSINESS_BLOCKS * TRANSACTIONS
            && full_state_equal
            && reopen_equal
            && observations.records_not_retained == 0
            && observations.measurement_failures == 0
            && !observations.counter_overflow
            && observations.records.iter().all(|r| r.complete)
            && final_meter.in_flight == 0
            && !final_meter.accounting_unavailable;
        let mut report = json!({"schema":"public-v3-network-only-business-v1","passed":pass,
            "network":hex::encode(settings.network()),"parameters":hex::encode(settings.parameters()),
            "policy":hex::encode(PublicPolicy::new(8,CALL_LIMIT).unwrap().id()),
            "window_ns":WINDOW.as_nanos(),"workers":WORKERS,"calls_per_worker":CALLS_PER_WORKER,
            "supplied_attack_fixtures":attacks.iter().map(|(_,r)|r).collect::<Vec<_>>(),
            "attack_workers":attack_rows,"honest_calls":honest_rows,"overlapping_false_calls":overlap,
            "initial_meter":initial_meter,"final_meter":final_meter,"observations":observations,
            "full_state_equal":full_state_equal,"reopen_equal":reopen_equal,
            "business_transactions":queries.len(),"native_verified_confirmed_transactions":confirmed,
            "no_local_depletion_hook":true,"independent_accepted":false,
            "work_profile_qualified":false,"resource_fairness_qualified":false,
            "physical_power_loss":false,"wan_tps":null,"production_activation":false});
        report["service"] = json!(server_result.as_ref().ok());
        report["service_error"] = json!(server_result.as_ref().err().map(ToString::to_string));
        report["honest_error"] = json!(honest_result.as_ref().err().map(ToString::to_string));
        report["confirmation"] = json!(confirmation.as_ref().ok());
        report["confirmation_error"] = json!(confirmation.as_ref().err().map(ToString::to_string));
        report["scope"]=json!("bounded same-process loopback public TCP load; original r9 resource policy; reference-acquired false traces and rotating keys; distinct native consumer reexecutes downloaded history; prebuilt blocks/logical timestamps; not independent operators, physical cost lower bound, remote exhaustion guarantee, saturated TPS or WAN");
        fs::write(
            path.join("report.json"),
            serde_json::to_vec_pretty(&report).unwrap(),
        )
        .unwrap();
        println!(
            "{}",
            json!({"schema":report["schema"],"passed":pass,"confirmed":confirmed,"false_calls":calls.len(),"overlap":overlap})
        );
        assert!(
            pass,
            "retain network-only-business/report.json and original failure"
        );
    }
}
