//! One live receiver/CPU epoch from real prefix through the fixed honest window.
use super::{
    actor, honest,
    plan::{Job, Mode, Plan, JOB_SCHEMA, SCHEMA},
    support,
};
use serde_json::{json, Value};
use std::{
    fs,
    io::Write,
    net::TcpListener,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};
use trnm_pon_node::{
    development_public,
    ingress::public_v3::{self, PublicMetrics, PublicRequestObserver, PublicServer},
    Node, Packet, PoolLimits, Settings,
};

fn read(path: &Path) -> Option<Value> {
    serde_json::from_slice(&fs::read(path).ok()?).ok()
}
fn publish(path: &Path, value: &Value) {
    let temporary = path.with_extension("tmp.json");
    support::write_new(&temporary, value);
    fs::rename(temporary, path).unwrap();
}
struct Actor {
    child: Child,
    path: PathBuf,
    started_ns: u64,
}
impl Actor {
    fn spawn(job: Job) -> Self {
        fs::create_dir(&job.output).unwrap();
        let path = job.output.clone();
        support::write_new(&path.join("job.json"), &serde_json::to_value(job).unwrap());
        let log = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(path.join("actor.log"))
            .unwrap();
        let started_ns = support::monotonic();
        let child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "identity_actor_entry",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("TRNM_IDENTITY_ACTOR_JOB", path.join("job.json"))
            .stdout(Stdio::from(log.try_clone().unwrap()))
            .stderr(Stdio::from(log))
            .spawn()
            .unwrap();
        Self {
            child,
            path,
            started_ns,
        }
    }
    fn finish(mut self, deadline: Instant) -> Value {
        let mut killed = false;
        let status = loop {
            if let Some(s) = self.child.try_wait().unwrap() {
                break s;
            }
            if Instant::now() >= deadline {
                self.child.kill().unwrap();
                killed = true;
                break self.child.wait().unwrap();
            }
            support::ready_sleep();
        };
        json!({"pid":self.child.id(),"started_ns":self.started_ns,"reaped_ns":support::monotonic(),
            "exit_success":status.success(),"exit_status":status.to_string(),"parent_forced_kill":killed,
            "directory":self.path.file_name().unwrap().to_str().unwrap(),"ready":read(&self.path.join("ready.json")),
            "prefix_finished":read(&self.path.join("prefix-finished.json")),"report":read(&self.path.join("report.json"))})
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
struct Service {
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<Result<PublicMetrics, String>>>,
}
impl Service {
    fn finish(&mut self) -> Result<PublicMetrics, String> {
        self.stop.store(true, Ordering::Release);
        self.worker.take().unwrap().join().unwrap()
    }
}
impl Drop for Service {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(w) = self.worker.take() {
            let _ = w.join();
        }
    }
}
struct Sampler {
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<usize>>,
}
impl Sampler {
    fn finish(&mut self) -> usize {
        self.stop.store(true, Ordering::Release);
        self.worker.take().unwrap().join().unwrap()
    }
}
impl Drop for Sampler {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(w) = self.worker.take() {
            let _ = w.join();
        }
    }
}
fn replay(node: &mut Node, packets: &[Packet]) {
    for p in packets {
        let id = node.admit(p, support::now()).unwrap();
        node.activate(id).unwrap();
    }
}

pub fn phase(
    path: &Path,
    settings: &Settings,
    seed: &[Packet],
    business: &[Packet],
    mode: Mode,
    plan: &Plan,
) -> Value {
    fs::create_dir(path).unwrap();
    let mut receiver =
        Node::open_with_authenticated_state(&path.join("receiver"), settings.clone(), 1).unwrap();
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
    let mut verifier =
        Node::open_with_authenticated_state(&path.join("independent-client"), settings.clone(), 1)
            .unwrap();
    replay(&mut verifier, seed);
    let initial_state = receiver.read_active().unwrap();
    let initial_stats = receiver.stats().unwrap();
    let owner = Arc::new(Mutex::new(receiver));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let observer = PublicRequestObserver::new(16_384).unwrap();
    let server = PublicServer::new(support::identity(71), support::policy()).unwrap();
    let domain = server.mutation_cpu_domain();
    let initial_work = domain.observe_completion_work().unwrap();
    let initial_flow = domain.observe_actual_flow().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let (signal, node, capture) = (stop.clone(), owner.clone(), observer.clone());
    let metrics = Arc::new(Mutex::new(PublicMetrics::default()));
    let counters = metrics.clone();
    let lifetime = Duration::from_secs(
        plan.readiness_seconds
            + plan.prefix_seconds
            + plan.pressure_seconds
            + 2 * plan.cleanup_seconds,
    );
    let mut service = Service {
        stop,
        worker: Some(thread::spawn(move || {
            public_v3::serve_public_protected_v3_with_request_observer(
                listener, node, lifetime, signal, server, counters, capture,
            )
            .map_err(|e| e.to_string())
        })),
    };
    let binary = actor::binary_sha256();
    let source_commit = std::env::var("TRNM_IDENTITY_SOURCE_HEAD").unwrap_or_default();
    let source_tree = std::env::var("TRNM_IDENTITY_SOURCE_TREE").unwrap_or_default();
    if plan.qualification {
        assert_eq!(source_commit.len(), 40);
        assert_eq!(source_tree.len(), 40);
    }
    let controller_cgroup = actor::cgroup();
    let children_usage_before = support::children_usage();
    let mut actors = Vec::new();
    for worker in 0..plan.actors {
        actors.push(Actor::spawn(Job {
            schema: JOB_SCHEMA.into(),
            plan: plan.clone(),
            mode,
            worker,
            address: address.to_string(),
            template_packet: hex::encode(business[0].encode().unwrap()),
            output: path.join(format!("actor-{worker:02}")),
            prefix_marker: path.join("prefix-start.json"),
            pressure_marker: path.join("pressure-start.json"),
            source_commit: source_commit.clone(),
            source_tree: source_tree.clone(),
            binary_sha256: binary.clone(),
        }));
    }
    let ready_deadline = Instant::now() + Duration::from_secs(plan.readiness_seconds);
    while Instant::now() < ready_deadline
        && actors.iter().any(|a| {
            read(&a.path.join("ready.json")).is_none() && !a.path.join("report.json").exists()
        })
    {
        support::ready_sleep();
    }
    let ready: Vec<_> = actors
        .iter()
        .map(|a| read(&a.path.join("ready.json")))
        .collect();
    let sample_stop = Arc::new(AtomicBool::new(false));
    let sampling_stop = sample_stop.clone();
    let sample_domain = domain.clone();
    let sample_path = path.join("samples.jsonl");
    let mut sampler = Sampler {
        stop: sample_stop,
        worker: Some(thread::spawn(move || {
            let mut output = fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(sample_path)
                .unwrap();
            let mut count = 0;
            while !sampling_stop.load(Ordering::Acquire) {
                let observation_started_ns = support::monotonic();
                let meter = sample_domain.observe().map_err(|e| e.to_string());
                let flow = sample_domain
                    .observe_actual_flow()
                    .map_err(|e| e.to_string());
                let work = sample_domain
                    .observe_completion_work()
                    .map_err(|e| e.to_string());
                let fresh = sample_domain
                    .observe_credit_freshness()
                    .map_err(|e| e.to_string());
                let observation_ended_ns = support::monotonic();
                let row = json!({"schema":SCHEMA,"kind":"sample","index":count,"observation_started_ns":observation_started_ns,
                "observation_ended_ns":observation_ended_ns,"meter":meter.as_ref().ok(),"actual_flow":flow.as_ref().ok().and_then(|v|v.as_ref()),
                "completion_work":work.as_ref().ok(),"credit_freshness":fresh.as_ref().ok().and_then(|v|v.as_ref()),
                "query_results":{"meter":meter,"actual_flow":flow,"completion_work":work,"credit_freshness":fresh}});
                output
                    .write_all(&serde_json::to_vec(&row).unwrap())
                    .unwrap();
                output.write_all(b"\n").unwrap();
                output.sync_data().unwrap();
                count += 1;
                thread::sleep(Duration::from_millis(50));
            }
            output.sync_all().unwrap();
            count
        })),
    };
    let prefix_epoch = support::monotonic();
    let prefix_end = prefix_epoch + plan.prefix_seconds * 1_000_000_000;
    publish(
        &path.join("prefix-start.json"),
        &json!({"schema":SCHEMA,"epoch_ns":prefix_epoch,"end_ns":prefix_end}),
    );
    while support::monotonic() < prefix_end
        && actors.iter().any(|a| {
            read(&a.path.join("prefix-finished.json")).is_none()
                && !a.path.join("report.json").exists()
        })
    {
        support::ready_sleep();
    }
    let post_prefix_work = domain.observe_completion_work().unwrap();
    let post_prefix_flow = domain.observe_actual_flow().unwrap();
    let epoch = support::monotonic();
    let end = epoch + plan.pressure_seconds * 1_000_000_000;
    publish(
        &path.join("pressure-start.json"),
        &json!({"schema":SCHEMA,"epoch_ns":epoch,"end_ns":end}),
    );
    let honest = honest::rounds(
        address,
        settings,
        business,
        &mut verifier,
        &observer,
        plan,
        (epoch, end),
    );
    while support::monotonic() < end {
        support::ready_sleep();
    }
    let pressure_final_work = domain.observe_completion_work().unwrap();
    let pressure_final_flow = domain.observe_actual_flow().unwrap();
    let sample_count = sampler.finish();
    let cleanup = Instant::now() + Duration::from_secs(plan.cleanup_seconds);
    let children: Vec<_> = actors.into_iter().map(|a| a.finish(cleanup)).collect();
    let children_usage_after = support::children_usage();
    let service_outcome = service.finish();
    let captured = observer.snapshot();
    let final_work = domain.observe_completion_work().unwrap();
    let final_flow = domain.observe_actual_flow().unwrap();
    let final_state = owner.lock().unwrap().read_active().unwrap();
    let final_stats = owner.lock().unwrap().stats().unwrap();
    let mut hostile = Vec::new();
    for worker in 0..plan.actors {
        for stage in ["prefix", "pressure"] {
            let dir = path.join(format!("actor-{worker:02}/{stage}"));
            if let Ok(files) = fs::read_dir(dir) {
                for file in files.flatten() {
                    let name = file.file_name();
                    if name.to_string_lossy().ends_with("-construction.json") {
                        let row = read(&file.path()).unwrap();
                        if let Some(wire) = row["packet"].as_str() {
                            let p = Packet::decode(&hex::decode(wire).unwrap()).unwrap();
                            let id = p.id().unwrap();
                            let absent = owner
                                .lock()
                                .unwrap()
                                .packet(id)
                                .err()
                                .is_some_and(|e| e.to_string() == "UNKNOWN_PARENT");
                            hostile.push(json!({"file":format!("actor-{worker:02}/{stage}/{}",name.to_string_lossy()),"packet_id":hex::encode(id),"live_absent":absent}));
                        }
                    }
                }
            }
        }
    }
    drop(owner);
    let cold =
        Node::open_with_authenticated_state(&path.join("receiver"), settings.clone(), 1).unwrap();
    for row in &mut hostile {
        let id = hex::decode(row["packet_id"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        row["cold_absent"] = json!(cold
            .packet(id)
            .err()
            .is_some_and(|e| e.to_string() == "UNKNOWN_PARENT"));
    }
    let cold_equal =
        cold.read_active().unwrap() == final_state && cold.stats().unwrap() == final_stats;
    let owner_cpu = captured
        .records
        .iter()
        .filter(|r| r.operation == Some(1) && r.dispatch_started)
        .try_fold(0_u64, |s, r| s.checked_add(r.dispatch_thread_cpu_ns?));
    let settled = final_flow.as_ref().is_some_and(|f| {
        f.balance_identity_verified
            && f.live_owners == 0
            && f.booked_reservation_ns == 0
            && f.unsettled_known_live_cpu_ns == 0
            && f.paid_cpu_debit_ns == f.settled_full_cpu_ns
            && f.paid_cpu_debit_ns > 0
            && Some(f.paid_cpu_debit_ns) == owner_cpu
            && service_outcome
                .as_ref()
                .is_ok_and(|m| m.mutation_cpu_charged_ns == f.paid_cpu_debit_ns)
    });
    let mut report = json!({"schema":SCHEMA,"kind":"phase","mode":mode,"plan":plan,"parent_pid":std::process::id(),"controller_cgroup":controller_cgroup,
        "source_commit":source_commit,"source_tree":source_tree,"binary_sha256":binary,"actor_readiness":ready,"children":children,
        "prefix_epoch_ns":prefix_epoch,"prefix_end_ns":prefix_end,"pressure_epoch_ns":epoch,"pressure_end_ns":end,
        "initial_work":initial_work,"initial_flow":initial_flow,"post_prefix_work":post_prefix_work,"post_prefix_flow":post_prefix_flow});
    let measurements = json!({
        "pressure_final_work":pressure_final_work,"pressure_final_flow":pressure_final_flow,"final_work":final_work,"final_flow":final_flow,
        "honest":honest,"receiver_observation":captured,"service_outcome":service_outcome,"owner_cpu_ns":owner_cpu,"paid_settled":settled,
        "sample_file":"samples.jsonl","sample_count":sample_count,"children_usage_before":children_usage_before,"children_usage_after":children_usage_after,
        "hostile_candidates":hostile,"cold_equal":cold_equal,"initial_stats":initial_stats,"final_stats":final_stats,
        "initial_tip":hex::encode(initial_state.0),"final_tip":hex::encode(final_state.0),"independent_operators":false,"wan_qualified":false,
        "cost_status":"UNKNOWN_FULL_ATTEMPT_BYTES_NOT_RETAINED","work_hardness_accepted":false,"production_activation":false});
    report
        .as_object_mut()
        .unwrap()
        .extend(measurements.as_object().unwrap().clone());
    support::write_new(&path.join("report.json"), &report);
    report
}
