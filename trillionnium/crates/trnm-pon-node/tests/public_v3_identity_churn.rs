//! Real paid TCP/W1 prefix. This is not the separate 30s honest-service campaign.
#[allow(dead_code)]
#[path = "support/multiprocess_support.rs"]
mod support;
use serde_json::{json, Value};
use std::{
    collections::BTreeSet,
    fs,
    net::TcpListener,
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};
use support::{identity, policy, signed_transfer as transfer, write_new as save};
use trnm_crypto_primitives::pon_work::PreparedTask;
use trnm_pon_node::{
    development_public,
    ingress::public_v3::{self, PublicMetrics, PublicRequestObserver, PublicServer, Request},
    Node, Packet, PoolLimits, Settings,
};
use trnm_protocol::pon_wire::hash;

#[allow(dead_code)]
#[path = "support/identity_churn_evidence.rs"]
mod evidence;
#[path = "support/identity_churn_work.rs"]
mod identity_work;
use identity_work::{
    acquire, cpu, elapsed, seed, valid_construction, CAPACITY, PREFIX_SECONDS, SCHEMA, SEARCH_LIMIT,
};

struct Service {
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<PublicMetrics>>,
}
impl Service {
    fn finish(&mut self) -> PublicMetrics {
        self.stop.store(true, Ordering::Release);
        self.worker.take().unwrap().join().unwrap()
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

fn prefix(path: &Path, count: usize, seconds: u64) -> Value {
    prefix_with_profile(path, count, seconds, false)
}
fn prefix_with_profile(path: &Path, count: usize, seconds: u64, v2: bool) -> Value {
    let schema = if v2 { identity_work::SCHEMA_V2 } else { SCHEMA };
    let mut evidence = evidence::Budget::new(evidence::PREFIX_BYTES);
    fs::create_dir(path).unwrap();
    let settings = Settings::development_with_profiles(
        Some(1_750_000_000),
        "native-public-evaluation-dev-v1",
        trnm_mvcc_fee::continuity_v1::PROFILE,
    )
    .unwrap();
    let mut miner =
        Node::open_with_authenticated_state(&path.join("miner"), settings.clone(), 1).unwrap();
    let seed_start = cpu();
    let packets = seed(&mut miner, &settings);
    let template = miner
        .make_consensus_maintenance(
            miner.active().unwrap().0,
            vec![transfer(&settings, 1025, development_public(1).unwrap())],
            development_public(0).unwrap(),
            settings.genesis_time() + 50,
            SEARCH_LIMIT,
        )
        .unwrap();
    save(
        &path.join("seed.json"),
        &json!({"schema":schema,"packets":packets.iter().map(|p|hex::encode(p.encode().unwrap())).collect::<Vec<_>>(),
        "template":hex::encode(template.encode().unwrap()),"preparation_thread_cpu_ns":elapsed(seed_start),
        "node_search_attempt_counts":null,"scope":"real four blocks/1024 signed transfers; Node aggregate preparation includes unexposed search attempts"}),
    );
    let mut receiver =
        Node::open_with_authenticated_state(&path.join("receiver"), settings.clone(), 1).unwrap();
    for p in &packets {
        let id = receiver
            .admit(p, settings.genesis_time() + 100_000)
            .unwrap();
        receiver.activate(id).unwrap();
    }
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
    let before = receiver.read_active().unwrap();
    let before_stats = receiver.stats().unwrap();
    let owner = Arc::new(Mutex::new(receiver));
    let observer = PublicRequestObserver::new(16_384).unwrap();
    let server = PublicServer::new(identity(71), policy()).unwrap();
    let domain = server.mutation_cpu_domain();
    let initial = domain.observe_completion_work().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let (signal, node, capture) = (stop.clone(), owner.clone(), observer.clone());
    let mut service = Service {
        stop,
        worker: Some(thread::spawn(move || {
            public_v3::serve_public_protected_v3_with_request_observer(
                listener,
                node,
                Duration::from_secs(seconds),
                signal,
                server,
                Arc::new(Mutex::new(PublicMetrics::default())),
                capture,
            )
            .unwrap()
        })),
    };
    let (_, _, a, b) = settings.consensus_maintenance_material().unwrap();
    let setup_cpu = cpu();
    let producer = PreparedTask::new(&a, &b).unwrap();
    let setup_cpu_ns = elapsed(setup_cpu);
    save(
        &path.join("plan.json"),
        &json!({"schema":schema,"requested":count,"outer_seconds":seconds,"search_attempt_limit":SEARCH_LIMIT,
        "registry_capacity":CAPACITY,"actors":1,"profile":hex::encode(policy().id()),"initial":initial,
        "producer":"prepared-generic","setup_calls":1,"setup_thread_cpu_ns":setup_cpu_ns,
        "scope":"same-host serial capacity component, genuine TCP and paid validation; not the full 24-actor service campaign"}),
    );
    let end = Instant::now() + Duration::from_secs(seconds);
    let mut identities = BTreeSet::new();
    let mut rows = Vec::new();
    let mut error = None;
    for index in 0..count {
        if Instant::now() >= end {
            error = Some("outer-deadline".to_owned());
            break;
        }
        let acquired = if v2 {
            identity_work::acquire_v2(&template, &producer, index, path, end, &mut evidence)
        } else {
            acquire(&template, &producer, index, path, end)
        };
        let Some((packet, receipt)) = acquired else {
            error = Some("construction-failed".to_owned());
            break;
        };
        if !(if v2 {
            identity_work::valid_construction_v2(&receipt, &template, index)
        } else {
            valid_construction(&receipt, &template, index)
        }) || !identities.insert(receipt["completion_identity"].as_str().unwrap().to_owned())
        {
            error = Some("construction-evidence".to_owned());
            break;
        }
        let started = Instant::now();
        let client_cpu = cpu();
        let request = Request::Submit {
            packet: hex::encode(packet.encode().unwrap()),
        };
        let body = serde_json::to_vec(&request).unwrap();
        let (reply, metrics) = public_v3::call_public_protected_v3_with_deadline(
            address,
            &request,
            &settings,
            identity(71).public_key(),
            &identity(80),
            policy(),
            Some(end.min(started + Duration::from_secs(2))),
        );
        let call = json!({"schema":schema,"index":index,"completion_identity":receipt["completion_identity"],
            "body_digest":hex::encode(hash(b"public-request-body-v3", &[&body])),"packet_id":hex::encode(packet.id().unwrap()),
            "reply":reply.as_ref().ok(),"error":reply.as_ref().err().map(ToString::to_string),"metrics":metrics,
            "client_thread_cpu_ns":elapsed(client_cpu),"wall_ns":started.elapsed().as_nanos(),"occupancy":domain.observe_completion_work().unwrap()});
        let call_path = path.join(format!("{index:05}-call.json"));
        if v2 {
            evidence
                .write(&call_path, &call, evidence::CALL_BYTES)
                .unwrap();
        } else {
            save(&call_path, &call);
        }
        rows.push(call);
    }
    let metrics = service.finish();
    let captured = observer.snapshot();
    let final_work = domain.observe_completion_work().unwrap();
    let flow = domain.observe_actual_flow().unwrap();
    let absent = |node: &Node| {
        rows.iter().all(|call| {
            node.packet(
                hex::decode(call["packet_id"].as_str().unwrap())
                    .unwrap()
                    .try_into()
                    .unwrap(),
            )
            .err()
            .is_some_and(|e| e.to_string() == "UNKNOWN_PARENT")
        })
    };
    let live_unchanged = {
        let node = owner.lock().unwrap();
        node.read_active().unwrap() == before
            && node.stats().unwrap() == before_stats
            && absent(&node)
    };
    drop(owner);
    let cold = Node::open_with_authenticated_state(&path.join("receiver"), settings, 1).unwrap();
    let cold_unchanged = cold.read_active().unwrap() == before
        && cold.stats().unwrap() == before_stats
        && absent(&cold);
    let matched = rows.iter().all(|call| {
        captured
            .records
            .iter()
            .filter(|r| {
                r.body_digest.map(hex::encode).as_deref() == call["body_digest"].as_str()
                    && r.full_work_accepted == Some(true)
                    && r.dispatch_accepted == Some(false)
                    && r.full_work_thread_cpu_ns.is_some_and(|n| n > 0)
                    && r.complete
            })
            .count()
            == 1
            && call["error"].is_null()
            && call["reply"]["ok"] == false
            && call["reply"]["value"]["error"] == "ROOT"
            && call["client_thread_cpu_ns"].as_u64().is_some_and(|n| n > 0)
    });
    let owner_cpu = captured
        .records
        .iter()
        .try_fold(0_u64, |sum, r| sum.checked_add(r.dispatch_thread_cpu_ns?));
    let settled = flow.as_ref().is_some_and(|f| {
        f.balance_identity_verified
            && f.live_owners == 0
            && f.booked_reservation_ns == 0
            && f.unsettled_known_live_cpu_ns == 0
            && f.paid_cpu_debit_ns == f.settled_full_cpu_ns
            && f.paid_cpu_debit_ns > 0
            && f.paid_cpu_debit_ns == metrics.mutation_cpu_charged_ns
            && Some(f.paid_cpu_debit_ns) == owner_cpu
    });
    let component_pass = error.is_none()
        && rows.len() == count
        && identities.len() == count
        && matched
        && settled
        && live_unchanged
        && cold_unchanged
        && setup_cpu_ns.is_some_and(|n| n > 0)
        && captured.records.len() == count
        && captured.records_not_retained == 0
        && captured.measurement_failures == 0
        && !captured.counter_overflow
        && initial.retained_identities == 0
        && final_work.retained_identities == count.min(CAPACITY)
        && final_work.full_capacity_skips == count.saturating_sub(CAPACITY) as u64
        && final_work.repeated_identity_skips == 0;
    let mut report = json!({"schema":schema,"component_pass":component_pass,"requested":count,"calls":rows,"error":error,
        "completion_work":final_work,"actual_flow":flow,"metrics":metrics,"receiver_observation":captured,
        "live_unchanged":live_unchanged,"cold_unchanged":cold_unchanged,"paid_settled":settled,
        "capacity_crossed":component_pass && count>CAPACITY,"honest_service_qualified":false,"work_hardness_accepted":false,
        "original_campaign_qualified":false,"independent_operators":false,"wan_qualified":false,"production_activation":false});
    if v2 {
        report["evidence_budget"] = evidence.summary();
        report["full_v2_io_boundary_implemented"] = json!(false);
        report["scope"] = json!("small acquisition control only; no 24-process, memory/VM, whole-artifact or honest-service qualification");
    }
    save(&path.join("report.json"), &report);
    report
}

#[test]
#[ignore = "reviewed short v2 full-attempt acquisition control only; not full campaign qualification"]
fn three_real_full_attempt_receipts_and_preprove_cap_v2_control() {
    let out =
        std::env::var_os("TRNM_IDENTITY_CONTROL_V2_DIR").expect("fresh explicit v2 directory");
    let out = Path::new(&out);
    let report = prefix_with_profile(out, 3, 30, true);
    assert_eq!(report["component_pass"], true, "{report}");
    assert_eq!(report["capacity_crossed"], false);
    let seed: Value = serde_json::from_slice(&fs::read(out.join("seed.json")).unwrap()).unwrap();
    let template =
        Packet::decode(&hex::decode(seed["template"].as_str().unwrap()).unwrap()).unwrap();
    let (_, _, a, b) = support::settings()
        .consensus_maintenance_material()
        .unwrap();
    let producer = PreparedTask::new(&a, &b).unwrap();
    let cap_path = out.join("cap-negative");
    fs::create_dir(&cap_path).unwrap();
    let mut budget = evidence::Budget::new(2 * evidence::CALL_BYTES);
    assert!(identity_work::acquire_v2(
        &template,
        &producer,
        3,
        &cap_path,
        Instant::now() + Duration::from_secs(2),
        &mut budget
    )
    .is_none());
    let terminal: Value =
        serde_json::from_slice(&fs::read(cap_path.join("00003-construction.json")).unwrap())
            .unwrap();
    assert_eq!(terminal["error"], "evidence-cap");
    assert_eq!(terminal["attempts"], json!([]));
    assert_eq!(terminal["evidence_budget"]["cap_reached"], true);
    assert!(budget.used <= budget.limit && cap_path.join("00003-started.json").exists());
    assert!(identity_work::acquire_v2(
        &template,
        &producer,
        4,
        &cap_path,
        Instant::now() + Duration::from_secs(2),
        &mut budget
    )
    .is_none());
    assert!(!cap_path.join("00004-started.json").exists());
    for index in 0..3 {
        let row: Value = serde_json::from_slice(
            &fs::read(out.join(format!("{index:05}-construction.json"))).unwrap(),
        )
        .unwrap();
        assert!(identity_work::valid_construction_v2(&row, &template, index));
        let mut missing = row;
        missing["attempts"][0]["proof"] = Value::Null;
        assert!(!identity_work::valid_construction_v2(
            &missing, &template, index
        ));
    }
}

#[test]
fn three_real_fresh_w1_packets_cross_tcp_pay_and_fail_root_without_capacity_claim() {
    let temp = tempfile::tempdir().unwrap();
    let out = std::env::var_os("TRNM_IDENTITY_CONTROL_RETAIN_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| temp.path().join("control"));
    let report = prefix(&out, 3, 30);
    assert_eq!(report["component_pass"], true, "{report}");
    assert_eq!(report["capacity_crossed"], false);
    let plan: Value = serde_json::from_slice(&fs::read(out.join("plan.json")).unwrap()).unwrap();
    let costs: Vec<_> = (0..3).map(|index| {
        let c: Value = serde_json::from_slice(&fs::read(out.join(format!("{index:05}-construction.json"))).unwrap()).unwrap();
        json!({"index":index,"attempts":c["attempts"].as_array().unwrap().len(),
            "construction_thread_cpu_ns":c["construction_thread_cpu_ns"],"construction_wall_ns":c["construction_wall_ns"],
            "verification_thread_cpu_ns":c["verification_thread_cpu_ns"]})
    }).collect();
    eprintln!(
        "IDENTITY_CONTROL_COSTS={}",
        json!({"plan":plan,"constructions":costs,
        "paid_cpu_ns":report["actual_flow"]["paid_cpu_debit_ns"],"calls":report["calls"],"qualification":false})
    );
    let seed: Value = serde_json::from_slice(&fs::read(out.join("seed.json")).unwrap()).unwrap();
    let template =
        Packet::decode(&hex::decode(seed["template"].as_str().unwrap()).unwrap()).unwrap();
    let original: Value =
        serde_json::from_slice(&fs::read(out.join("00000-construction.json")).unwrap()).unwrap();
    assert!(valid_construction(&original, &template, 0));
    for key in [
        "construction_thread_cpu_ns",
        "verification_thread_cpu_ns",
        "completion_identity",
        "packet",
    ] {
        let mut bad = original.clone();
        bad[key] = Value::Null;
        assert!(!valid_construction(&bad, &template, 0), "{key}");
    }
    let mut missing = original.clone();
    missing["attempts"] = json!([]);
    assert!(!valid_construction(&missing, &template, 0));
    assert!(
        !valid_construction(&original, &template, 1),
        "replay cannot become a new index"
    );
}

#[test]
#[ignore = "explicit 4097 real paid complete-W1 TCP requests; original resource policy; not honest-service qualification"]
fn real_paid_w1_identity_capacity_prefix() {
    let path =
        std::env::var_os("TRNM_IDENTITY_PREFIX_DIR").expect("fresh explicit output directory");
    let report = prefix(Path::new(&path), CAPACITY + 1, PREFIX_SECONDS);
    assert_eq!(
        report["component_pass"],
        true,
        "preserve {}",
        Path::new(&path).display()
    );
    assert_eq!(report["capacity_crossed"], true);
}
