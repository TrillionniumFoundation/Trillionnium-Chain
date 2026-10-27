//! Finite loopback stress with unique false traces, honest interleaving and cold reopen.
//! No fairness, work-hardness or physical-network qualification is inferred.
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    io::Write,
    net::{SocketAddr, TcpListener},
    path::Path,
    sync::{
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use trnm_crypto_primitives::pon_work::{self, PreparedTask};
use trnm_pon_node::{
    development_public,
    ingress::{
        self,
        public_v3::{
            self, PublicPolicy, PublicRequestObserver, PublicServer, ServiceMutationCpuDomain,
        },
    },
    Node, Packet, PoolLimits, Settings,
};

type Result<T> = std::result::Result<T, Box<dyn Error + Send + Sync>>;
const SCHEMA: &str = "pon-pure-ingress-campaign-v1";

fn cpu() -> Option<u64> {
    use rustix::time::{clock_gettime_dynamic, ClockId, DynamicClockId};
    let t = clock_gettime_dynamic(DynamicClockId::Known(ClockId::ThreadCPUTime)).ok()?;
    u64::try_from(t.tv_sec)
        .ok()?
        .checked_mul(1_000_000_000)?
        .checked_add(u64::try_from(t.tv_nsec).ok()?)
}
fn delta(before: Option<u64>) -> Option<u64> {
    before.zip(cpu()).and_then(|(a, b)| b.checked_sub(a))
}
fn emit(mut row: Value) -> Result<()> {
    static WRITTEN: AtomicUsize = AtomicUsize::new(0);
    row["schema"] = json!(SCHEMA);
    let terminal = row["kind"] == "terminal";
    let mut bytes = serde_json::to_vec(&row)?;
    bytes.push(b'\n');
    let cap = 64 * 1024 * 1024 - if terminal { 0 } else { 4096 };
    if bytes.len() > 1024 * 1024 {
        return Err("REPORT_ROW_BOUND".into());
    }
    WRITTEN
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
            n.checked_add(bytes.len()).filter(|n| *n <= cap)
        })
        .map_err(|_| "REPORT_TOTAL_BOUND")?;
    let mut out = std::io::stdout().lock();
    out.write_all(&bytes)?;
    out.flush()?;
    Ok(())
}
#[derive(Clone, Copy)]
struct Plan {
    baseline: u64,
    attack: u64,
    receivers: usize,
    attackers: usize,
    groups: u64,
}
fn options() -> Result<Plan> {
    let mut p = Plan {
        baseline: 15,
        attack: 45,
        receivers: 2,
        attackers: 4,
        groups: 8192,
    };
    let mut args = std::env::args().skip(1);
    let mut seen = BTreeSet::new();
    while let Some(key) = args.next() {
        if !seen.insert(key.clone()) {
            return Err("DUPLICATE_OPTION".into());
        }
        let value: u64 = args.next().ok_or("OPTION_VALUE")?.parse()?;
        match key.as_str() {
            "--baseline-seconds" => p.baseline = value,
            "--attack-seconds" => p.attack = value,
            "--receivers" => p.receivers = usize::try_from(value)?,
            "--attack-workers" => p.attackers = usize::try_from(value)?,
            "--max-groups" => p.groups = value,
            _ => return Err("UNKNOWN_OPTION".into()),
        }
    }
    if !(1..=300).contains(&p.baseline)
        || !(1..=600).contains(&p.attack)
        || !(1..=2).contains(&p.receivers)
        || !(1..=16).contains(&p.attackers)
        || !(16..=8192).contains(&p.groups)
    {
        return Err("CAMPAIGN_LIMIT".into());
    }
    Ok(p)
}
#[derive(Clone)]
struct Endpoint {
    receiver: usize,
    listener: usize,
    address: SocketAddr,
    key: String,
}
struct Fleet {
    owners: Vec<Arc<Mutex<Node>>>,
    domains: Vec<ServiceMutationCpuDomain>,
    endpoints: Vec<Endpoint>,
    observers: Vec<PublicRequestObserver>,
    workers: Vec<JoinHandle<trnm_pon_node::Result<public_v3::PublicMetrics>>>,
    stop: Arc<AtomicBool>,
}
impl Fleet {
    fn open(
        root: &Path,
        settings: &Settings,
        p: Plan,
        lifetime: Duration,
        phase: &str,
    ) -> Result<Self> {
        let policy = PublicPolicy::pure_pon(Duration::from_secs(2))?;
        let mut f = Self {
            owners: vec![],
            domains: vec![],
            endpoints: vec![],
            observers: vec![],
            workers: vec![],
            stop: Arc::new(AtomicBool::new(false)),
        };
        for receiver in 0..p.receivers {
            let mut node = Node::open(
                &root.join(format!("receiver-{receiver}")),
                settings.clone(),
                1,
            )?;
            node.enable_local_mempool(PoolLimits {
                max_records: 16,
                max_bytes: 32768,
                max_group_members: 16,
                critical_reserve: 0,
                max_removals: 32,
                preview_miner: development_public(0)?,
            })?;
            let owner = Arc::new(Mutex::new(node));
            for listener_index in 0..2usize {
                let identity = ingress::DevelopmentIdentity::from_secret_hex(&hex::encode(
                    [80 + (receiver * 2 + listener_index) as u8; 32],
                ))?;
                let key = identity.public_key().to_owned();
                let server = if listener_index == 0 {
                    let server = PublicServer::new_process_cold(identity, policy)?;
                    f.domains.push(server.mutation_cpu_domain());
                    server
                } else {
                    PublicServer::with_continuous_domain(identity, policy, &f.domains[receiver])?
                };
                let listener = TcpListener::bind("127.0.0.1:0")?;
                f.endpoints.push(Endpoint {
                    receiver,
                    listener: listener_index,
                    address: listener.local_addr()?,
                    key,
                });
                let observer = PublicRequestObserver::new(16384)?;
                f.observers.push(observer.clone());
                let owner = owner.clone();
                let stop = f.stop.clone();
                f.workers.push(thread::spawn(move || {
                    public_v3::serve_public_protected_v3_with_request_observer(
                        listener,
                        owner,
                        lifetime,
                        stop,
                        server,
                        Arc::new(Mutex::new(public_v3::PublicMetrics::default())),
                        observer,
                    )
                }));
            }
            let initial = f.domains[receiver].observe()?;
            if initial.stored_credit_ns != 0 {
                return Err("COLD_REOPEN_MINTED_CREDIT".into());
            }
            emit(
                json!({"kind":"receiver_start","phase":phase,"receiver":receiver,"listeners":2,
                "budget":initial,"state":owner.lock().map_err(|_|"OWNER")?.stats()?}),
            )?;
            f.owners.push(owner);
        }
        Ok(f)
    }
    fn finish(&mut self, phase: &str) -> Result<()> {
        self.stop.store(true, Ordering::Release);
        for (index, worker) in self.workers.drain(..).enumerate() {
            let metrics = worker.join().map_err(|_| "SERVER_PANIC")??;
            emit(
                json!({"kind":"listener_end","phase":phase,"receiver":index/2,"listener":index%2,"metrics":metrics}),
            )?;
        }
        for (index, domain) in self.domains.iter().enumerate() {
            let flow = domain.observe_actual_flow()?.ok_or("CPU_FLOW_UNKNOWN")?;
            if !flow.balance_identity_verified
                || flow.live_owners != 0
                || flow.booked_reservation_ns != 0
            {
                return Err("CPU_FLOW_UNBALANCED".into());
            }
            emit(
                json!({"kind":"receiver_end","phase":phase,"receiver":index,"budget":domain.observe()?,
                "flow":flow,"completion_work":domain.observe_completion_work()?,
                "state":self.owners[index].lock().map_err(|_|"OWNER")?.stats()?}),
            )?;
        }
        Ok(())
    }
}
impl Drop for Fleet {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        for worker in self.workers.drain(..) {
            let _ = worker.join();
        }
    }
}

#[derive(Clone)]
struct Call {
    sequence: u64,
    honest: bool,
    receiver: usize,
    body: [u8; 32],
    latency: u64,
    ok: bool,
    transport_cpu: Option<u64>,
    error: String,
}
#[derive(Default)]
struct Produced {
    groups: u64,
    preparation_wall: u128,
    preparation_cpu: Option<u64>,
    calls: Vec<Call>,
}
fn add(sum: &mut Option<u64>, next: Option<u64>) {
    *sum = sum.zip(next).and_then(|(a, b)| a.checked_add(b));
}

#[allow(clippy::too_many_arguments)]
fn worker(
    settings: &Settings,
    seed: &Packet,
    prepared: &PreparedTask,
    endpoints: &[Endpoint],
    plan: Plan,
    phase: &str,
    phase_index: u64,
    worker_id: usize,
    honest: bool,
    deadline: Instant,
    sequence: &AtomicU64,
) -> Result<Produced> {
    let policy = PublicPolicy::pure_pon(Duration::from_secs(2))?;
    let mut totals = Produced {
        preparation_cpu: Some(0),
        ..Produced::default()
    };
    while Instant::now() < deadline {
        let local = sequence.fetch_add(1, Ordering::Relaxed);
        if local >= plan.groups {
            break;
        }
        let seq = phase_index * 100_000 + local;
        let started = Instant::now();
        let before = cpu();
        let mut packet = seed.clone();
        let mut trials = 0u64;
        let mut found = false;
        for attempt in 0..4096u64 {
            packet.header.nonce = (seq + 1) * 65536 + attempt;
            let challenge = packet.header.challenge();
            if honest {
                packet.proof = prepared
                    .prove(challenge)
                    .map_err(|e| format!("HONEST_WORK:{e:?}"))?;
            } else {
                let false_trace = pon_work::hash(
                    b"pure-ingress-invalid-trace-v1",
                    &[&seq.to_le_bytes(), &attempt.to_le_bytes()],
                );
                packet.proof[pon_work::PROOF_BYTES - 32..].copy_from_slice(&false_trace);
            }
            trials += 1;
            let ticket = pon_work::hash(
                b"ticket",
                &[&challenge, &packet.proof[pon_work::PROOF_BYTES - 32..]],
            );
            if ticket <= packet.header.target {
                found = true;
                break;
            }
        }
        if !found {
            return Err("FINITE_SEARCH_EXHAUSTED".into());
        }
        pon_work::precheck_proof_statement(
            packet.header.challenge(),
            packet.header.work_task,
            packet.header.target,
            &packet.proof,
        )
        .map_err(|e| format!("PRECHECK:{e:?}"))?;
        let bytes = packet.encode()?;
        let digest = hex::encode(Sha256::digest(&bytes));
        let request = public_v3::Request::Submit {
            packet: hex::encode(bytes),
        };
        let raw = serde_json::to_vec(&request)?;
        let body = trnm_protocol::pon_wire::hash(b"public-request-body-v3", &[&raw]);
        let secret = pon_work::hash(
            b"pure-ingress-caller-v1",
            &[&seq.to_le_bytes(), &(worker_id as u64).to_le_bytes()],
        );
        let caller = ingress::DevelopmentIdentity::from_secret_hex(&hex::encode(secret))?;
        let preparation_cpu = delta(before);
        let preparation_wall = started.elapsed().as_nanos();
        totals.groups += 1;
        totals.preparation_wall += preparation_wall;
        add(&mut totals.preparation_cpu, preparation_cpu);
        emit(
            json!({"kind":"prepared_packet","phase":phase,"sequence":seq,"honest":honest,
            "packet_sha256":digest,"body_digest":hex::encode(body),"generation_trials":trials,
            "preparation_wall_ns":preparation_wall,"preparation_thread_cpu_ns":preparation_cpu,
            "receiver_fanout":plan.receivers,"transport_hash_trials":0}),
        )?;
        for receiver in 0..plan.receivers {
            let endpoint = &endpoints[receiver * 2 + (local as usize + worker_id) % 2];
            let started = Instant::now();
            let before = cpu();
            let (result, metrics) = public_v3::call_public_protected_v3_with_deadline(
                endpoint.address,
                &request,
                settings,
                &endpoint.key,
                &caller,
                policy,
                Some(deadline + Duration::from_secs(5)),
            );
            let transport_cpu = delta(before);
            let latency = u64::try_from(started.elapsed().as_nanos())?;
            if metrics.solution_trials != 0 {
                return Err("TRANSPORT_HASHCASH_APPEARED".into());
            }
            let (ok, error) = match result {
                Ok(reply) => (
                    reply.ok,
                    if reply.ok {
                        String::new()
                    } else {
                        reply.value.to_string()
                    },
                ),
                Err(error) => (false, error.to_string()),
            };
            emit(
                json!({"kind":"client_call","phase":phase,"sequence":seq,"honest":honest,
                "receiver":endpoint.receiver,"listener":endpoint.listener,"body_digest":hex::encode(body),
                "accepted":ok,"error":error,"latency_ns":latency,"thread_cpu_ns":transport_cpu,
                "metrics":metrics}),
            )?;
            if ok && !honest {
                return Err("INVALID_TRACE_ACCEPTED".into());
            }
            totals.calls.push(Call {
                sequence: seq,
                honest,
                receiver,
                body,
                latency,
                ok,
                transport_cpu,
                error,
            });
        }
    }
    Ok(totals)
}
fn percentile(mut values: Vec<u64>, percent: usize) -> Option<u64> {
    if values.is_empty() {
        return None;
    }
    values.sort_unstable();
    let rank = (values.len() * percent).div_ceil(100);
    values.get(rank.saturating_sub(1)).copied()
}

#[allow(clippy::too_many_arguments)]
fn phase(
    root: &Path,
    settings: &Settings,
    seed: &Packet,
    prepared: &PreparedTask,
    p: Plan,
    index: u64,
    name: &str,
    seconds: u64,
    attackers: usize,
) -> Result<()> {
    let mut fleet = Fleet::open(root, settings, p, Duration::from_secs(seconds + 35), name)?;
    let fetcher = ingress::DevelopmentIdentity::from_secret_hex(&hex::encode([200; 32]))?;
    let endpoint = &fleet.endpoints[0];
    let (fetched, fetch_metrics) = public_v3::fetch_public_task_bootstrap(
        endpoint.address,
        settings,
        &endpoint.key,
        &fetcher,
        PublicPolicy::pure_pon(Duration::from_secs(2))?,
        None,
    );
    if fetched? != settings.public_task_bootstrap()? || fetch_metrics.solution_trials != 0 {
        return Err("PUBLIC_BOOTSTRAP_FETCH".into());
    }
    let start = Instant::now();
    let deadline = start + Duration::from_secs(seconds);
    let sequence = AtomicU64::new(0);
    let outcomes = thread::scope(|scope| {
        let mut threads = Vec::new();
        for id in 0..=attackers {
            let endpoints = &fleet.endpoints;
            let sequence = &sequence;
            threads.push(scope.spawn(move || {
                worker(
                    settings,
                    seed,
                    prepared,
                    endpoints,
                    p,
                    name,
                    index,
                    id,
                    id == 0,
                    deadline,
                    sequence,
                )
            }));
        }
        threads
            .into_iter()
            .map(|t| t.join().map_err(|_| "CLIENT_PANIC".into()).and_then(|r| r))
            .collect::<Result<Vec<_>>>()
    })?;
    let elapsed = start.elapsed().as_nanos();
    fleet.finish(name)?;
    let mut calls = Vec::new();
    let mut generated = 0u64;
    let mut preparation_cpu = Some(0u64);
    let mut preparation_wall = 0u128;
    for produced in outcomes {
        generated += produced.groups;
        add(&mut preparation_cpu, produced.preparation_cpu);
        preparation_wall += produced.preparation_wall;
        calls.extend(produced.calls);
    }
    let by_body: BTreeMap<_, _> = calls
        .iter()
        .map(|c| ((c.receiver, c.body), (c.sequence, c.honest)))
        .collect();
    if by_body.len() != calls.len() {
        return Err("DUPLICATE_PACKET_AT_RECEIVER".into());
    }
    for (listener, observer) in fleet.observers.iter().enumerate() {
        let snapshot = observer.snapshot();
        emit(
            json!({"kind":"observation_coverage","phase":name,"receiver":listener/2,"listener":listener%2,
            "complete":snapshot.coverage_complete(),"seen":snapshot.accepted_connections_seen,
            "omitted":snapshot.records_not_retained,"failures":snapshot.measurement_failures}),
        )?;
        for row in snapshot.records {
            let association = row
                .body_digest
                .and_then(|digest| by_body.get(&(listener / 2, digest)).copied());
            emit(
                json!({"kind":"receiver_observation","phase":name,"receiver":listener/2,"listener":listener%2,
                "sequence":association.map(|x|x.0),"honest":association.map(|x|x.1),
                "body_digest":row.body_digest.map(hex::encode),"full_work_started":row.full_work_started,
                "full_work_accepted":row.full_work_accepted,"full_work_thread_cpu_ns":row.full_work_thread_cpu_ns,
                "dispatch_thread_cpu_ns":row.dispatch_thread_cpu_ns,"complete":row.complete,
                "observation_failed":row.observation_failed,"terminal_phase":row.terminal_phase}),
            )?;
        }
    }
    for honest in [true, false] {
        let selected: Vec<_> = calls.iter().filter(|c| c.honest == honest).collect();
        let accepted = selected.iter().filter(|c| c.ok).count();
        let mut reasons = BTreeMap::<&str, u64>::new();
        let mut transport_cpu = Some(0u64);
        for c in &selected {
            if !c.ok {
                *reasons.entry(&c.error).or_default() += 1;
            }
            add(&mut transport_cpu, c.transport_cpu);
        }
        emit(
            json!({"kind":"class_summary","phase":name,"honest":honest,"calls":selected.len(),
            "accepted_receiver_calls":accepted,"errors":reasons,"client_transport_thread_cpu_ns":transport_cpu,
            "all_call_p50_ns":percentile(selected.iter().map(|c|c.latency).collect(),50),
            "all_call_p99_ns":percentile(selected.iter().map(|c|c.latency).collect(),99),
            "accepted_p99_ns":percentile(selected.iter().filter(|c|c.ok).map(|c|c.latency).collect(),99),
            "accepted_receiver_calls_per_second":(accepted as f64)*1e9/(elapsed as f64),
            "elapsed_including_client_tails_ns":elapsed}),
        )?;
    }
    let honest_all_receivers = BTreeMap::<u64, usize>::from_iter(
        calls
            .iter()
            .filter(|c| c.honest)
            .map(|c| (c.sequence, 0usize)),
    );
    let mut honest_all_receivers = honest_all_receivers;
    for c in calls.iter().filter(|c| c.honest && c.ok) {
        *honest_all_receivers.get_mut(&c.sequence).ok_or("GROUP")? += 1;
    }
    emit(
        json!({"kind":"phase_terminal","phase":name,"requested_seconds":seconds,
        "elapsed_including_client_tails_ns":elapsed,"generated_unique_packets":generated,
        "honest_unique_packets_accepted_by_all_receivers":honest_all_receivers.values().filter(|n|**n==p.receivers).count(),
        "packet_preparation_wall_ns":preparation_wall,"packet_preparation_thread_cpu_ns":preparation_cpu,
        "group_bound_reached":sequence.load(Ordering::Relaxed)>=p.groups,
        "work_hardness_qualified":false,"public_fairness_qualified":false}),
    )?;
    Ok(())
}
fn run() -> Result<()> {
    let p = options()?;
    let root = tempfile::tempdir()?;
    let genesis = ingress::now()?.checked_sub(100).ok_or("CLOCK")?;
    let settings = Settings::development_with_profiles(
        Some(genesis),
        "native-public-evaluation-dev-v1",
        trnm_mvcc_fee::continuity_v1::PROFILE,
    )?;
    let producer = Node::open(&root.path().join("producer"), settings.clone(), 1)?;
    let begin = Instant::now();
    let before = cpu();
    let bundle = settings.public_task_bootstrap()?;
    let seed = producer.make_public_bootstrap(
        &bundle,
        settings.genesis(),
        vec![],
        development_public(3)?,
        genesis + 11,
        4096,
    )?;
    let seed_cpu = delta(before);
    let seed_wall = begin.elapsed().as_nanos();
    let (a, b) = trnm_mvcc_fee::continuity_v1::maintenance_matrices();
    let before = cpu();
    let begin = Instant::now();
    let prepared = PreparedTask::new(&a, &b).map_err(|e| format!("SETUP:{e:?}"))?;
    let setup_cpu = delta(before);
    let setup_wall = begin.elapsed().as_nanos();
    emit(
        json!({"kind":"begin","receivers":p.receivers,"listeners_per_receiver":2,
        "baseline_seconds":p.baseline,"attack_seconds_per_phase":p.attack,"attack_workers":p.attackers,
        "genesis_time":genesis,"native_seed_header":hex::encode(seed.header.encode()),
        "input_seed":"source-fixed caller/trace domains; unique sequence phase*100000+counter; native seed miner development_public(3)",
        "warmup":"none; cold baseline and both cold attack phases are retained",
        "max_groups_per_phase":p.groups,"seed_acquired_once":true,"seed_acquisition_wall_ns":seed_wall,
        "seed_acquisition_thread_cpu_ns":seed_cpu,"honest_preparation_wall_ns":setup_wall,
        "honest_preparation_thread_cpu_ns":setup_cpu,"native_seed_packet_sha256":hex::encode(Sha256::digest(seed.encode()?)),
        "resource_profile":hex::encode(PublicPolicy::pure_pon(Duration::from_secs(2))?.id()),
        "scope":"one host, real TCP, two listeners share each receiver CPU owner; distinct receivers have independent original budgets; same prepared invalid packet fans out once per receiver; all failures and unknown clocks retained",
        "model_useful_output_credit":0,"work_hardness_qualified":false,"public_fairness_qualified":false}),
    )?;
    phase(
        root.path(),
        &settings,
        &seed,
        &prepared,
        p,
        0,
        "honest-cold",
        p.baseline,
        0,
    )?;
    phase(
        root.path(),
        &settings,
        &seed,
        &prepared,
        p,
        1,
        "attack-cold-reopen",
        p.attack,
        p.attackers,
    )?;
    phase(
        root.path(),
        &settings,
        &seed,
        &prepared,
        p,
        2,
        "attack-second-reopen",
        p.attack,
        p.attackers,
    )?;
    emit(
        json!({"kind":"terminal","status":"complete","work_hardness_qualified":false,
        "public_fairness_qualified":false,"production_qualified":false}),
    )
}
fn main() {
    if let Err(error) = run() {
        let _ = emit(
            json!({"kind":"terminal","status":"failed","error":error.to_string(),
    "work_hardness_qualified":false,"public_fairness_qualified":false,"production_qualified":false}),
        );
        eprintln!("{error}");
        std::process::exit(1);
    }
}
