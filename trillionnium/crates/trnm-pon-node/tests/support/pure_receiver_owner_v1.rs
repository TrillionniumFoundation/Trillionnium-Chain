//! Independent, explicitly named receiver-process supplement. The original
//! campaign and runtime are unchanged. All observation IPC and local loopback
//! identity work is included in this child's wait4 cost, never removed from it.
use super::*;
use std::{
    io::{self, Read, Write},
    os::unix::net::{UnixListener, UnixStream},
    process::{Command, Stdio},
};
use trnm_pon_node::host_kernel_parent::{require_host_kernel_budget, FIXED_PUBLIC_KERNEL_PARENT};

const PHASE_SCHEMA: &str = "pon-pure-receiver-owner-phase-v1";
const CAMPAIGN_SCHEMA: &str = "pon-pure-receiver-owner-campaign-v1";
const NODE_SCHEMA: &str = "pon-pure-receiver-node-v1";
const FRAME_LIMIT: usize = 32 * 1024;
const TRACE_LIMIT: usize = 16 * 1024 * 1024;
const REPORT_LIMIT: u64 = 64 * 1024 * 1024;
const IPC_SCOPE: &str = "Private local observation IPC; its receiver-side CPU and publication work are included in receiver wait4. It grants no live ingress, consensus, credit, deadline or fixed-parent authority.";
const OWNER_SCOPE: &str = "Independent receiver child lifetime with the real Node, two protected public reactors and their joined worker threads. Includes startup, seed replay, loopback identities, observation IPC, final publication and teardown. Parent honest client, sampler and attacker siblings are excluded. Linux waited-descendant usage is nested, not added again; absence of unobserved descendants is not physically authenticated.";

fn error(value: impl ToString) -> io::Error {
    io::Error::other(value.to_string())
}

fn encode(value: &Value) -> io::Result<Vec<u8>> {
    let raw = serde_json::to_vec(value).map_err(error)?;
    if raw.is_empty() || raw.len() > FRAME_LIMIT {
        return Err(error("RECEIVER_IPC_FRAME_BOUND"));
    }
    Ok(raw)
}

fn send(stream: &mut UnixStream, raw: &[u8]) -> io::Result<()> {
    if raw.is_empty() || raw.len() > FRAME_LIMIT {
        return Err(error("RECEIVER_IPC_FRAME_BOUND"));
    }
    stream.write_all(&(raw.len() as u32).to_be_bytes())?;
    stream.write_all(raw)
}

fn receive(stream: &mut UnixStream) -> io::Result<Vec<u8>> {
    let mut prefix = [0; 4];
    stream.read_exact(&mut prefix)?;
    let length = u32::from_be_bytes(prefix) as usize;
    if length == 0 || length > FRAME_LIMIT {
        return Err(error("RECEIVER_IPC_FRAME_BOUND"));
    }
    let mut raw = vec![0; length];
    stream.read_exact(&mut raw)?;
    Ok(raw)
}

#[derive(Default)]
struct FrameCapture {
    sent_frame_bytes: usize,
    prefix: Vec<u8>,
    payload: Vec<u8>,
}

fn remaining(deadline: Instant) -> io::Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|left| !left.is_zero())
        .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "RECEIVER_IPC_ABSOLUTE_DEADLINE"))
}
fn write_before(
    stream: &mut UnixStream,
    raw: &[u8],
    deadline: Instant,
    sent: &mut usize,
) -> io::Result<()> {
    let mut position = 0;
    while position < raw.len() {
        stream.set_write_timeout(Some(remaining(deadline)?))?;
        match stream.write(&raw[position..]) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "receiver control send closed",
                ))
            }
            Ok(count) => {
                position += count;
                *sent += count;
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
        remaining(deadline)?;
    }
    Ok(())
}
fn read_before(
    stream: &mut UnixStream,
    raw: &mut Vec<u8>,
    required: usize,
    deadline: Instant,
) -> io::Result<()> {
    let mut chunk = [0_u8; 1024];
    while raw.len() < required {
        stream.set_read_timeout(Some(remaining(deadline)?))?;
        let amount = (required - raw.len()).min(chunk.len());
        match stream.read(&mut chunk[..amount]) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "receiver control receive closed",
                ))
            }
            Ok(count) => raw.extend_from_slice(&chunk[..count]),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
        remaining(deadline)?;
    }
    Ok(())
}
fn exchange_before(
    stream: &mut UnixStream,
    request: &[u8],
    deadline: Instant,
    capture: &mut FrameCapture,
) -> io::Result<()> {
    write_before(
        stream,
        &(request.len() as u32).to_be_bytes(),
        deadline,
        &mut capture.sent_frame_bytes,
    )?;
    write_before(stream, request, deadline, &mut capture.sent_frame_bytes)?;
    receive_before(stream, deadline, capture)
}

fn receive_before(
    stream: &mut UnixStream,
    deadline: Instant,
    capture: &mut FrameCapture,
) -> io::Result<()> {
    read_before(stream, &mut capture.prefix, 4, deadline)?;
    let size = u32::from_be_bytes(capture.prefix.as_slice().try_into().unwrap()) as usize;
    if size == 0 || size > FRAME_LIMIT {
        return Err(error("RECEIVER_IPC_FRAME_BOUND"));
    }
    read_before(stream, &mut capture.payload, size, deadline)
}

fn parsed(raw: &[u8]) -> io::Result<Value> {
    serde_json::from_slice(raw).map_err(error)
}

fn sha(raw: &[u8]) -> String {
    hex::encode(Sha256::digest(raw))
}

fn file_binding(path: &Path, name: &str, limit: u64) -> io::Result<(Value, Vec<u8>)> {
    let held = support::cost_directory(path)?;
    let raw =
        support::cost_file_bytes(&held, name, limit, Instant::now() + Duration::from_secs(5))?;
    Ok((
        json!({"bytes":raw.len(),"sha256":sha(&raw),"error":null}),
        raw,
    ))
}

struct Control {
    stream: UnixStream,
    pid: u32,
    sequence: u64,
    rows: Vec<Value>,
    bytes: usize,
    output: PathBuf,
}
impl Control {
    fn call(&mut self, operation: &str, timeout: Duration) -> io::Result<Value> {
        self.call_until(operation, Instant::now() + timeout)
    }
    fn call_until(&mut self, operation: &str, deadline: Instant) -> io::Result<Value> {
        let started = support::monotonic();
        let request = json!({"schema":"pon-receiver-control-request-v1","sequence":self.sequence,"operation":operation});
        let raw_request = encode(&request)?;
        let mut frame = FrameCapture::default();
        let result = exchange_before(&mut self.stream, &raw_request, deadline, &mut frame);
        let raw_response = result.as_ref().ok().map(|()| &frame.payload);
        self.bytes = self
            .bytes
            .saturating_add(raw_request.len())
            .saturating_add(frame.payload.len());
        let decoded = raw_response.map(|raw| parsed(raw)).transpose();
        let response = decoded.as_ref().ok().and_then(Option::as_ref);
        let failure = result
            .as_ref()
            .err()
            .map(ToString::to_string)
            .or_else(|| decoded.as_ref().err().map(ToString::to_string));
        self.rows
            .push(json!({"sequence":self.sequence,"operation":operation,
            "started_monotonic_ns":started,"ended_monotonic_ns":support::monotonic(),
            "request_hex":hex::encode(&raw_request),"response_hex":raw_response.map(hex::encode),
            "request_sha256":sha(&raw_request),"response_sha256":raw_response.map(|raw|sha(raw)),
            "sent_frame_bytes":frame.sent_frame_bytes,"response_prefix_hex":hex::encode(&frame.prefix),
            "response_payload_hex":hex::encode(&frame.payload),"error":failure}));
        self.sequence += 1;
        if self.rows.len() > 2048 || self.bytes > TRACE_LIMIT {
            return Err(error("RECEIVER_IPC_TRACE_BOUND"));
        }
        let value = response
            .ok_or_else(|| error(failure.unwrap_or_else(|| "RECEIVER_IPC_RESPONSE".to_owned())))?;
        if value["schema"] != "pon-receiver-control-response-v1"
            || value["pid"] != self.pid
            || value["sequence"] != self.sequence - 1
            || value["operation"] != operation
        {
            return Err(error("RECEIVER_IPC_ASSOCIATION"));
        }
        Ok(value["value"].clone())
    }
    fn trace(&self) -> Value {
        json!({"schema":"pon-receiver-control-trace-v2","scope":IPC_SCOPE,
            "parent_pid":std::process::id(),"receiver_pid":self.pid,"frame_limit":FRAME_LIMIT,
            "trace_payload_limit":TRACE_LIMIT,"payload_bytes":self.bytes,"exchanges":self.rows,
            "physical_authentication":false})
    }
}

impl Drop for Control {
    fn drop(&mut self) {
        // Preserve every issued observation request, including an unfinished
        // receive, on an unwind or child failure. No overwrite or retry.
        if let Ok(raw) = serde_json::to_vec_pretty(&self.trace()) {
            if let Ok(mut file) = fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(self.output.join("receiver-control-trace.json"))
            {
                let _ = file.write_all(&raw);
                let _ = file.write_all(b"\n");
            }
        }
    }
}

struct Receiver {
    child: support::process_cost::ObservedChild,
    output: PathBuf,
    deadline: Instant,
    reaped: bool,
}
impl Receiver {
    fn finish(&mut self) -> Value {
        assert!(!self.reaped, "receiver has exactly one owner reap");
        let value = self.child.finish(self.deadline);
        self.reaped = true;
        support::write_new(&self.output.join("receiver-wait4.json"), &value);
        value
    }
}
impl Drop for Receiver {
    fn drop(&mut self) {
        if !self.reaped {
            // Failure retains the actual cancellation/reap. A partial campaign
            // cannot obtain qualification by losing its receiver terminal.
            let value = self.child.finish(self.deadline.min(Instant::now()));
            self.reaped = true;
            if let Ok(raw) = serde_json::to_vec_pretty(&value) {
                if let Ok(mut file) = fs::OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .open(self.output.join("receiver-wait4.json"))
                {
                    let _ = file.write_all(&raw);
                    let _ = file.write_all(b"\n");
                }
            }
        }
    }
}

struct Stop(Arc<AtomicBool>);
impl Drop for Stop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

fn child_run(job: &Value, path: &Path) -> io::Result<()> {
    fixed_parent::receiver_entry(path)?;
    support::process_cost::enable_receiver_subreaper()?;
    let settings = support::settings();
    let mut stream = UnixStream::connect(
        job["control_socket"]
            .as_str()
            .ok_or_else(|| error("RECEIVER_SOCKET"))?,
    )?;
    stream.set_read_timeout(Some(Duration::from_secs(240)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let seed: Vec<Packet> = job["seed_packets"]
        .as_array()
        .ok_or_else(|| error("RECEIVER_SEED"))?
        .iter()
        .map(|p| {
            hex::decode(p.as_str().unwrap())
                .map_err(error)
                .and_then(|raw| Packet::decode(&raw).map_err(error))
        })
        .collect::<io::Result<_>>()?;
    let honest: BTreeSet<[u8; 32]> = job["honest_body_digests"]
        .as_array()
        .ok_or_else(|| error("RECEIVER_HONEST"))?
        .iter()
        .map(|p| {
            hex::decode(p.as_str().unwrap())
                .map_err(error)
                .and_then(|raw| raw.try_into().map_err(|_| error("RECEIVER_DIGEST")))
        })
        .collect::<io::Result<_>>()?;
    let mut node =
        Node::open_with_authenticated_state(&path.join("receiver"), settings, 1).map_err(error)?;
    replay(&mut node, &seed);
    node.enable_local_mempool(PoolLimits {
        max_records: 16,
        max_bytes: 32768,
        max_group_members: 4,
        critical_reserve: 0,
        max_removals: 64,
        preview_miner: development_public(0).unwrap(),
    })
    .map_err(error)?;
    let initial = active_position(&node);
    let owner = Arc::new(Mutex::new(node));
    let listeners = [
        TcpListener::bind("127.0.0.1:0")?,
        TcpListener::bind("127.0.0.1:0")?,
    ];
    let addresses: Vec<_> = listeners
        .iter()
        .map(TcpListener::local_addr)
        .collect::<io::Result<_>>()?;
    // Always attempt exactly the existing fixed parent, read-only. A missing or
    // ineligible parent remains unknown; no alternate parent is ever created.
    let kernel = require_host_kernel_budget(addresses[0], Some(FIXED_PUBLIC_KERNEL_PARENT));
    let kernel_open_error = kernel.as_ref().err().map(ToString::to_string);
    let kernel = kernel.ok().flatten();
    let kernel_before = kernel.as_ref().map(|k| k.bound_resource_sample());
    let ready = json!({"schema":"pon-receiver-ready-v1","pid":std::process::id(),
        "addresses":addresses.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "initial_tip":hex::encode(initial.0),"initial_height":initial.1,"initial_generation":initial.2,
        "subreaper_enabled":true,"experiment":job["experiment"]});
    send(&mut stream, &encode(&ready)?)?;
    let arm_raw = receive(&mut stream)?;
    let arm = parsed(&arm_raw)?;
    if arm != json!({"schema":"pon-receiver-control-request-v1","sequence":0,"operation":"arm"}) {
        return Err(error("RECEIVER_ARM_REQUIRED"));
    }
    let first = PublicServer::new_process_cold(support::identity(71), support::policy())
        .map_err(error)?
        .with_pure_admission_v2()
        .map_err(error)?;
    let domain = first.mutation_cpu_domain();
    let second =
        PublicServer::with_continuous_domain(support::identity(71), support::policy(), &domain)
            .map_err(error)?
            .with_pure_admission_v2()
            .map_err(error)?;
    let shared = domain.shares_domain_with(&second.mutation_cpu_domain());
    let initial_budget = domain.observe().map_err(error)?;
    let initial_flow = domain.observe_actual_flow().map_err(error)?;
    let initial_admission = domain.observe_pure_admission().map_err(error)?;
    let stop = Arc::new(AtomicBool::new(false));
    let mut observers = Vec::new();
    let mut meters = Vec::new();
    let epoch = support::monotonic();
    let mut controls = Vec::new();
    let mut snapshots = Vec::new();
    let mut received_stop = false;
    let mut control_error = None;
    let services = thread::scope(|scope| {
        let mut workers = Vec::new();
        for (listener, server) in listeners.into_iter().zip([first, second]) {
            assert_eq!(
                server.resource_profile(),
                support::policy().pure_admission_v2_id()
            );
            let observer = PublicRequestObserver::new(16_384).unwrap();
            let meter = Arc::new(Mutex::new(public_v3::PublicMetrics::default()));
            observers.push(observer.clone());
            meters.push(meter.clone());
            let owner = owner.clone();
            let stop = stop.clone();
            workers.push(scope.spawn(move || {
                public_v3::serve_public_protected_v3_with_request_observer(
                    listener,
                    owner,
                    Duration::from_secs(240),
                    stop,
                    server,
                    meter,
                    observer,
                )
                .map_err(|e| e.to_string())
            }));
        }
        let stop_on_exit = Stop(stop.clone());
        let control_result = (|| -> io::Result<()> {
            support::write_new(
                &path.join("start.tmp"),
                &json!({"epoch_monotonic_ns":epoch}),
            );
            fs::rename(path.join("start.tmp"), path.join("start.json"))?;
            let mut sequence = 0_u64;
            let mut request_raw = arm_raw;
            loop {
                let request = parsed(&request_raw)?;
                if request["schema"] != "pon-receiver-control-request-v1"
                    || request["sequence"] != sequence
                {
                    return Err(error("RECEIVER_CONTROL_SEQUENCE"));
                }
                let operation = request["operation"]
                    .as_str()
                    .ok_or_else(|| error("RECEIVER_OPERATION"))?;
                let value = match operation {
                    "arm" if sequence == 0 => json!({"epoch_monotonic_ns":epoch}),
                    "sample" => {
                        let started = support::monotonic().saturating_sub(epoch);
                        if started >= WINDOW_NS {
                            let response = encode(
                                &json!({"schema":"pon-receiver-control-response-v1","pid":std::process::id(),
                                "sequence":sequence,"operation":operation,"value":{"phase_closed":true,"started_ns":started}}),
                            )?;
                            send(&mut stream, &response)?;
                            controls.push(json!({"sequence":sequence,"operation":operation,"request_sha256":sha(&request_raw),"response_sha256":sha(&response)}));
                            sequence += 1;
                            request_raw = receive(&mut stream)?;
                            continue;
                        }
                        let budget = domain.observe().map_err(error)?;
                        let flow = domain.observe_actual_flow().map_err(error)?;
                        let credit_freshness = domain.observe_credit_freshness().map_err(error)?;
                        let admission = domain.observe_pure_admission().map_err(error)?;
                        let clock_failures: u64 = meters
                            .iter()
                            .map(|m| m.lock().unwrap().mutation_cpu_clock_failures)
                            .sum();
                        let mut sample = json!({"started_ns":started,"ended_ns":support::monotonic().saturating_sub(epoch),
                            "budget":budget,"flow":flow,"credit_freshness":credit_freshness,"admission":admission,"clock_failures":clock_failures});
                        sample["depleted"] = json!(is_depleted(&sample));
                        sample
                    }
                    "hostile" => {
                        let name = format!("hostile-{sequence}.json");
                        support::write_new(
                            &path.join(&name),
                            &hostile_snapshot(&observers, &honest, epoch),
                        );
                        let (binding, _) = file_binding(path, &name, REPORT_LIMIT)?;
                        let value = json!({"file":name,"binding":binding});
                        snapshots.push(value.clone());
                        value
                    }
                    "stop" => {
                        received_stop = true;
                        controls.push(json!({"sequence":sequence,"operation":operation,"request_sha256":sha(&request_raw),"response_sha256":null}));
                        break;
                    }
                    _ => return Err(error("RECEIVER_CONTROL_OPERATION")),
                };
                let response = encode(
                    &json!({"schema":"pon-receiver-control-response-v1","pid":std::process::id(),
                    "sequence":sequence,"operation":operation,"value":value}),
                )?;
                send(&mut stream, &response)?;
                controls.push(json!({"sequence":sequence,"operation":operation,"request_sha256":sha(&request_raw),"response_sha256":sha(&response)}));
                sequence += 1;
                if sequence >= 2048 {
                    return Err(error("RECEIVER_CONTROL_COUNT"));
                }
                request_raw = receive(&mut stream)?;
            }
            Ok(())
        })();
        if let Err(failure) = control_result {
            control_error = Some(failure.to_string());
        }
        drop(stop_on_exit);
        workers
            .into_iter()
            .map(|w| serde_json::to_value(w.join().unwrap()).unwrap())
            .collect::<Vec<_>>()
    });
    let capture: Vec<_> = observers
        .iter()
        .map(|o| {
            let s = o.snapshot();
            json!({"coverage_complete":s.coverage_complete(),"snapshot":s})
        })
        .collect();
    let active = active_position(&owner.lock().unwrap());
    let final_budget = domain.observe().map_err(error)?;
    let final_flow = domain.observe_actual_flow().map_err(error)?;
    let final_admission = domain.observe_pure_admission().map_err(error)?;
    drop(owner);
    drop(observers);
    drop(meters);
    drop(domain);
    let kernel_after = kernel.as_ref().map(|k| k.bound_resource_sample());
    let kernel_delta = kernel_before
        .as_ref()
        .and_then(|b| b.as_ref().ok())
        .zip(kernel_after.as_ref().and_then(|a| a.as_ref().ok()))
        .map(|(before, after)| after.cpu_delta_since(before));
    let report = json!({"schema":NODE_SCHEMA,"pid":std::process::id(),"experiment":job["experiment"],
        "phase":job["phase"],"epoch_monotonic_ns":epoch,"window_ns":WINDOW_NS,"scope":OWNER_SCOPE,
        "policy":support::policy_observation(),"listeners":2,"shared_cpu_domain":shared,
        "initial_budget":initial_budget,"initial_flow":initial_flow,"initial_admission":initial_admission,
        "final_budget":final_budget,"final_flow":final_flow,"final_admission":final_admission,
        "services":services,"observations":capture,"receiver_tip":hex::encode(active.0),
        "receiver_height":active.1,"receiver_generation":active.2,"control_receipts":controls,
        "hostile_snapshots":snapshots,"received_stop":received_stop,"control_error":control_error,
        "owned_reactors_joined":2,"node_owner_dropped":true,
        "kernel_parent":{"path":FIXED_PUBLIC_KERNEL_PARENT,"open_error":kernel_open_error,
            "before":kernel_before.map(|v|v.map_err(|e|e.to_string())),"after":kernel_after.map(|v|v.map_err(|e|e.to_string())),
            "delta":kernel_delta.map(|v|v.map_err(|e|e.to_string())),"created_or_modified":false,
            "scope":"Existing fixed parent aggregate counters, if eligible; includes other members and is not exclusive receiver CPU."},
        "physical_authentication":false,"public_fairness_qualified":false,"production_qualified":false});
    support::write_new(&path.join("receiver-report.json"), &report);
    support::write_new(
        &path.join("receiver-family-observation-v1.json"),
        &support::process_cost::family_observation(),
    );
    support::write_new(
        &path.join("receiver-child-ownership-v1.json"),
        &support::process_cost::child_ownership_probe(),
    );
    if received_stop && control_error.is_none() {
        let (binding, _) = file_binding(path, "receiver-report.json", REPORT_LIMIT)?;
        let response = encode(
            &json!({"schema":"pon-receiver-control-response-v1","pid":std::process::id(),
            "sequence":report["control_receipts"].as_array().unwrap().len()-1,"operation":"stop","value":{"report":binding}}),
        )?;
        send(&mut stream, &response)?;
    }
    if control_error.is_some() {
        return Err(error("RECEIVER_CONTROL_FAILED"));
    }
    Ok(())
}

#[test]
#[ignore = "exact receiver subprocess entry; invoked only by the independent supplement/control"]
fn receiver_process_entry() {
    let job_path = PathBuf::from(std::env::var_os("TRNM_RECEIVER_OWNER_JOB").unwrap());
    let path = job_path.parent().unwrap();
    let job: Value = serde_json::from_slice(&fs::read(&job_path).unwrap()).unwrap();
    let result = std::panic::catch_unwind(|| child_run(&job, path));
    let failure = match result {
        Ok(Ok(())) => None,
        Ok(Err(e)) => Some(e.to_string()),
        Err(e) => Some(
            e.downcast_ref::<String>()
                .cloned()
                .or_else(|| e.downcast_ref::<&str>().map(|s| s.to_string()))
                .unwrap_or_else(|| "receiver panic".to_owned()),
        ),
    };
    if let Some(failure) = &failure {
        support::write_new(
            &path.join("receiver-failure.json"),
            &json!({"schema":"pon-receiver-failure-v1","pid":std::process::id(),"error":failure}),
        );
        if !path.join("receiver-family-observation-v1.json").exists() {
            support::write_new(
                &path.join("receiver-family-observation-v1.json"),
                &support::process_cost::family_observation(),
            );
        }
    }
    if failure.is_some() && !path.join("receiver-child-ownership-v1.json").exists() {
        support::write_new(
            &path.join("receiver-child-ownership-v1.json"),
            &support::process_cost::child_ownership_probe(),
        );
    }
    assert!(failure.is_none(), "receiver failure retained: {failure:?}");
}

fn start_receiver(
    path: &Path,
    socket: &Path,
    seed: &[Packet],
    honest: &BTreeSet<[u8; 32]>,
    mode: &str,
    experiment: &str,
) -> io::Result<(Receiver, Control, Value)> {
    start_receiver_placed(path, socket, seed, honest, mode, experiment, None)
}

fn start_receiver_placed(
    path: &Path,
    socket: &Path,
    seed: &[Packet],
    honest: &BTreeSet<[u8; 32]>,
    mode: &str,
    experiment: &str,
    mut placement: Option<&mut fixed_parent::Placement>,
) -> io::Result<(Receiver, Control, Value)> {
    let listener = UnixListener::bind(socket)?;
    listener.set_nonblocking(true)?;
    support::write_new(
        &path.join("receiver-job.json"),
        &json!({"schema":"pon-receiver-job-v1","phase":mode,
        "experiment":experiment,"control_socket":socket,"seed_packets":seed.iter().map(|p|hex::encode(p.encode().unwrap())).collect::<Vec<_>>(),
        "honest_body_digests":honest.iter().map(hex::encode).collect::<Vec<_>>()}),
    );
    let log = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path.join("receiver.log"))?;
    let mut command = Command::new(std::env::current_exe()?);
    command
        .args([
            "--exact",
            "receiver_owner::receiver_process_entry",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("TRNM_RECEIVER_OWNER_JOB", path.join("receiver-job.json"))
        .stdout(Stdio::from(log.try_clone()?))
        .stderr(Stdio::from(log));
    if let Some(placement) = placement.as_deref_mut() {
        placement.configure(&mut command, path)?;
    }
    let child = support::process_cost::ObservedChild::spawn(&mut command)?;
    // Drops the pre-exec closure's parent-side capability before any honest
    // client, attacker or sampler starts. The receiver exec closed its copy.
    drop(command);
    let ready_deadline_arm_before = support::monotonic();
    let deadline = Instant::now() + Duration::from_secs(180);
    let ready_deadline_arm_after = support::monotonic();
    let receiver = Receiver {
        child,
        output: path.to_owned(),
        deadline,
        reaped: false,
    };
    let (mut stream, _) = loop {
        match listener.accept() {
            Ok(value) => break value,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return Err(error("RECEIVER_READY_DEADLINE"));
                }
                support::pause();
            }
            Err(e) => return Err(e),
        }
    };
    let ready_started = support::monotonic();
    let mut capture = FrameCapture::default();
    let received = receive_before(&mut stream, deadline, &mut capture);
    support::write_new(
        &path.join("receiver-ready-exchange-v1.json"),
        &json!({"schema":"pon-receiver-ready-exchange-v1","pid":receiver.child.id(),
            "started_monotonic_ns":ready_started,"ended_monotonic_ns":support::monotonic(),
            "deadline_arm_before_monotonic_ns":ready_deadline_arm_before,
            "deadline_arm_after_monotonic_ns":ready_deadline_arm_after,
            "startup_budget_ns":180_000_000_000_u64,
            "original_owner_deadline":true,"timeout_restarted_between_reads":false,
            "prefix_hex":hex::encode(&capture.prefix),"payload_hex":hex::encode(&capture.payload),
            "error":received.as_ref().err().map(ToString::to_string),"physical_authentication":false}),
    );
    received?;
    let raw = capture.payload;
    let ready = parsed(&raw)?;
    if ready["schema"] != "pon-receiver-ready-v1"
        || ready["pid"] != receiver.child.id()
        || ready["subreaper_enabled"] != true
    {
        return Err(error("RECEIVER_READY_IDENTITY"));
    }
    support::write_new(&path.join("receiver-ready.json"), &ready);
    if let Some(placement) = placement {
        placement.after_spawn(path, receiver.child.id())?;
    }
    let control = Control {
        stream,
        pid: receiver.child.id(),
        sequence: 0,
        rows: Vec::new(),
        bytes: 0,
        output: path.to_owned(),
    };
    Ok((receiver, control, ready))
}

fn hostile(control: &Arc<Mutex<Control>>, path: &Path) -> io::Result<Value> {
    let response = control
        .lock()
        .unwrap()
        .call("hostile", Duration::from_secs(2))?;
    let name = response["file"]
        .as_str()
        .ok_or_else(|| error("RECEIVER_HOSTILE_FILE"))?;
    if !name.starts_with("hostile-") || !name.ends_with(".json") || name.contains('/') {
        return Err(error("RECEIVER_HOSTILE_PATH"));
    }
    let (binding, raw) = file_binding(path, name, REPORT_LIMIT)?;
    if binding != response["binding"] {
        return Err(error("RECEIVER_HOSTILE_BINDING"));
    }
    parsed(&raw)
}

fn capture_receiver(
    path: &Path,
    cost: &Value,
    receiver_pid: u32,
    complete: bool,
) -> io::Result<()> {
    let begin = support::monotonic();
    let deadline = Instant::now() + Duration::from_secs(5);
    let held = support::cost_directory(path)?;
    let mut files = serde_json::Map::new();
    let mut all = complete;
    for (name, limit) in [
        ("receiver-report.json", REPORT_LIMIT),
        ("receiver-family-observation-v1.json", 1024 * 1024),
        ("receiver.log", 1024 * 1024),
        ("receiver-wait4.json", 1024 * 1024),
        ("receiver-ready.json", 1024 * 1024),
        ("receiver-control-trace.json", 64 * 1024 * 1024),
        ("receiver-job.json", REPORT_LIMIT),
    ] {
        let binding = match support::cost_file_bytes(&held, name, limit, deadline) {
            Ok(raw) => json!({"bytes":raw.len(),"sha256":sha(&raw),"error":null}),
            Err(e) => {
                all = false;
                json!({"bytes":null,"sha256":null,"error":e.to_string()})
            }
        };
        files.insert(name.to_owned(), binding);
    }
    support::write_new(
        &path.join("receiver-owner-binding-v1.json"),
        &json!({"schema":"pon-pure-receiver-owner-binding-v1",
        "scope":OWNER_SCOPE,"parent_pid":std::process::id(),"receiver_pid":receiver_pid,"cost":cost,
        "started_monotonic_ns":begin,"ended_monotonic_ns":support::monotonic(),"read_budget_ns":5_000_000_000_u64,
        "capture_complete":all,"files":files,"physical_authentication":false,"public_fairness_qualified":false,"production_qualified":false}),
    );
    Ok(())
}

fn receiver_report_or_retain_failure(
    path: &Path,
    phase: &str,
    partial: impl FnOnce() -> Value,
) -> io::Result<Value> {
    match file_binding(path, "receiver-report.json", REPORT_LIMIT).and_then(|(_, raw)| parsed(&raw))
    {
        Ok(report) => Ok(report),
        Err(cause) => {
            // Missing/malformed terminal output is not a successful receiver
            // report. Retain the actual controller-side observations before
            // the enclosing failure path unwinds and closes its owned child.
            support::write_new(
                &path.join("receiver-report-failure-v1.json"),
                &json!({"schema":"pon-pure-receiver-report-failure-v1", "phase":phase,
                    "error":cause.to_string(),"error_kind":format!("{:?}", cause.kind()),
                    "partial_controller_observations":partial(),
                    "receiver_report_available":false,"finite_qualification":false,
                    "original_campaign_qualification":false,"physical_authentication":false,
                    "public_fairness_qualified":false,"production_qualified":false,
                    "work_hardness_qualified":false,"installation_authorized":false}),
            );
            Err(cause)
        }
    }
}

#[test]
fn native_receiver_terminal_failure_retains_partial_without_inventing_report() {
    for malformed in [false, true] {
        let path = tempfile::tempdir().unwrap();
        if malformed {
            fs::write(path.path().join("receiver-report.json"), b"{truncated").unwrap();
        }
        let partial = json!({"scope":"synthetic parser control only", "rounds":[{"ended_ns":45_000_000_000u64}],
            "receiver_wait4":{"exit_success":false},"original_window_ns":WINDOW_NS,
            "actors":[{"pid":321,"exit_success":false,"parent_forced_kill":false}],
            "actor_process_costs":[{"pid":321,"successful_reaps":1,"exit_success":false,
                "rusage":{"total_cpu_ns":123456}}]});
        let result = receiver_report_or_retain_failure(path.path(), "baseline", || partial.clone());
        assert!(result.is_err());
        let retained: Value = serde_json::from_slice(
            &fs::read(path.path().join("receiver-report-failure-v1.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(retained["partial_controller_observations"], partial);
        assert_eq!(
            retained["partial_controller_observations"]["actors"],
            partial["actors"]
        );
        assert_eq!(
            retained["partial_controller_observations"]["actor_process_costs"],
            partial["actor_process_costs"]
        );
        assert_eq!(retained["finite_qualification"], false);
        assert_eq!(retained["receiver_report_available"], false);
        assert_ne!(retained["schema"], PHASE_SCHEMA);
        if !malformed {
            assert!(!path.path().join("receiver-report.json").exists());
        }
    }
    let path = tempfile::tempdir().unwrap();
    let valid = json!({"schema":NODE_SCHEMA, "scope":"synthetic parser control only"});
    support::write_new(&path.path().join("receiver-report.json"), &valid);
    assert_eq!(
        receiver_report_or_retain_failure(path.path(), "baseline", || panic!(
            "valid report must not synthesize failure"
        ))
        .unwrap(),
        valid
    );
    assert!(!path.path().join("receiver-report-failure-v1.json").exists());
}

#[test]
fn native_receiver_ready_deadline_retains_partial_prefix_and_body() {
    let mut observations = Vec::new();
    for prefix_only in [true, false] {
        let (mut receiver, mut peer) = UnixStream::pair().unwrap();
        let frame = [0_u8, 0, 0, 5, b'r', b'e', b'a', b'd', b'y'];
        let split = if prefix_only { 3 } else { 5 };
        // The partial bytes exist before the read begins; the final bytes are
        // withheld beyond the one absolute deadline, never a renewed read cap.
        peer.write_all(&frame[..split]).unwrap();
        let sender = thread::spawn(move || {
            thread::sleep(Duration::from_millis(200));
            peer.write_all(&frame[split..])
        });
        let started = support::monotonic();
        let deadline = Instant::now() + Duration::from_millis(100);
        let mut capture = FrameCapture::default();
        let result = receive_before(&mut receiver, deadline, &mut capture);
        let ended = support::monotonic();
        drop(receiver);
        let tail = sender.join().unwrap();
        let valid = result.is_err()
            && capture.prefix == frame[..if prefix_only { 3 } else { 4 }]
            && capture.payload == if prefix_only { &b""[..] } else { &b"r"[..] };
        observations.push(json!({"prefix_only":prefix_only,"assertions_passed":valid,
            "started_monotonic_ns":started,"ended_monotonic_ns":ended,
            "deadline_allowance_ns":100_000_000u64,
            "prefix_hex":hex::encode(&capture.prefix),"payload_hex":hex::encode(&capture.payload),
            "error":result.as_ref().err().map(ToString::to_string),
            "late_peer_write_error":tail.err().map(|e|e.to_string())}));
    }
    if let Some(output) = std::env::var_os("TRNM_RECEIVER_READY_CONTROL_OUT") {
        support::write_new(
            &PathBuf::from(output),
            &json!({
            "schema":"pon-receiver-ready-deadline-control-v1","observations":observations,
            "original_ready_budget_seconds":180,"qualification_budget_changed":false,
            "physical_authentication":false}),
        );
    }
    assert!(
        observations.iter().all(|r| r["assertions_passed"] == true),
        "readiness absolute-deadline observations: {observations:?}"
    );
}

#[test]
fn native_receiver_ipc_deadline_retains_partial_frame() {
    let temp = tempfile::tempdir().unwrap();
    let output = std::env::var_os("TRNM_RECEIVER_IPC_CONTROL_OUT")
        .map(PathBuf::from)
        .unwrap_or_else(|| temp.path().join("ipc-control.json"));
    let (parent, mut peer) = UnixStream::pair().unwrap();
    let sender = thread::spawn(move || {
        let request = receive(&mut peer).unwrap();
        let request = parsed(&request).unwrap();
        let response = encode(
            &json!({"schema":"pon-receiver-control-response-v1","pid":123,
            "sequence":request["sequence"],"operation":"stop","value":{}}),
        )
        .unwrap();
        // Deliberate fragmented slow peer: a refreshed full timeout after the
        // prefix would admit the last bytes; the one absolute deadline cannot.
        thread::sleep(Duration::from_millis(100));
        let _ = peer.write_all(&(response.len() as u32).to_be_bytes());
        let _ = peer.write_all(&response[..1]);
        thread::sleep(Duration::from_millis(200));
        let _ = peer.write_all(&response[1..]);
    });
    let mut control = Control {
        stream: parent,
        pid: 123,
        sequence: 0,
        rows: Vec::new(),
        bytes: 0,
        output: temp.path().to_owned(),
    };
    let deadline = Instant::now() + Duration::from_millis(200);
    let result = control.call_until("stop", deadline);
    let trace = control.trace();
    sender.join().unwrap();
    let passed = result.is_err()
        && trace["exchanges"][0]["response_hex"].is_null()
        && trace["exchanges"][0]["response_prefix_hex"]
            .as_str()
            .is_some_and(|v| v.len() == 8)
        && trace["exchanges"][0]["response_payload_hex"]
            .as_str()
            .is_some_and(|v| v.len() == 2);
    support::write_new(
        &output,
        &json!({"schema":"pon-receiver-ipc-native-control-v1","passed":passed,"trace":trace,
        "expected_absolute_deadline_ms":200,"partial_prefix_and_payload_retained":passed,"physical_authentication":false}),
    );
    assert!(
        passed,
        "IPC must reject the late full frame and retain its partial raw bytes: {trace}"
    );
}

#[test]
fn native_receiver_owner_isolation_and_shutdown() {
    let temp = tempfile::tempdir().unwrap();
    let path = std::env::var_os("TRNM_RECEIVER_OWNER_CONTROL_OUT")
        .map(PathBuf::from)
        .unwrap_or_else(|| temp.path().join("control"));
    fs::create_dir(&path).unwrap();
    let (mut receiver, mut control, ready) = start_receiver(
        &path,
        &temp.path().join("ipc"),
        &[],
        &BTreeSet::new(),
        "control",
        "native-control",
    )
    .unwrap();
    assert_ne!(receiver.child.id(), std::process::id());
    assert_eq!(ready["addresses"].as_array().unwrap().len(), 2);
    let armed = control.call("arm", Duration::from_secs(5)).unwrap();
    let epoch = armed["epoch_monotonic_ns"].as_u64().unwrap();
    // A domain snapshot does not prove reactor startup. Complete an actual
    // signed read through each service before requesting normal shutdown.
    // This is only the short control; the fixed supplement gains no warm-up.
    for address in ready["addresses"].as_array().unwrap() {
        let row = support::call(
            address.as_str().unwrap().parse().unwrap(),
            &support::settings(),
            Request::Head,
            73,
            epoch,
        )
        .expect("short control read entered its original window");
        assert!(
            support::on_time(&row),
            "real receiver readiness read failed: {row}"
        );
    }
    let sample = control.call("sample", Duration::from_secs(2)).unwrap();
    assert_eq!(sample["clock_failures"], 0);
    receiver.deadline = Instant::now() + Duration::from_secs(5);
    control.call_until("stop", receiver.deadline).unwrap();
    support::write_new(&path.join("receiver-control-trace.json"), &control.trace());
    let cost = receiver.finish();
    assert_eq!(cost["exit_success"], true);
    assert_eq!(cost["parent_forced_kill"], false);
    assert_eq!(cost["successful_reaps"], 1);
    let (_, raw) = file_binding(&path, "receiver-report.json", REPORT_LIMIT).unwrap();
    let report = parsed(&raw).unwrap();
    assert_eq!(report["services"].as_array().unwrap().len(), 2);
    assert!(
        report["services"]
            .as_array()
            .unwrap()
            .iter()
            .all(|value| value["Ok"].is_object()),
        "real receiver service terminals: {}",
        report["services"]
    );
    assert_eq!(report["owned_reactors_joined"], 2);
    assert_eq!(report["node_owner_dropped"], true);
    let (_, raw) = file_binding(&path, "receiver-family-observation-v1.json", 1024 * 1024).unwrap();
    let family = parsed(&raw).unwrap();
    assert_eq!(family["child_subreaper"], true);
    // Preserve procfs unavailability, including the earlier ENOENT control.
    // Only the independent kernel probe supplies this separate finite basis.
    let (_, raw) = file_binding(&path, "receiver-child-ownership-v1.json", 1024 * 1024).unwrap();
    let probe = parsed(&raw).unwrap();
    assert_eq!(probe["child_subreaper"], true);
    assert_eq!(
        probe["no_eligible_children_at_probe"], true,
        "kernel ownership observation: {probe}"
    );
    assert!(
        family["observed_child_pids"]
            .as_array()
            .is_some_and(Vec::is_empty),
        "procfs observed children: {family}"
    );
    capture_receiver(&path, &cost, receiver.child.id(), true).unwrap();
    support::capture_child_ownership_binding(
        &path,
        &json!({"phase":"control","receiver_pid":receiver.child.id()}),
        true,
    )
    .unwrap();
}

fn receiver_phase(
    path: &Path,
    settings: &Settings,
    seed: &[Packet],
    business: &[Packet],
    mode: &str,
    client_mode: pure_history_client::ClientMode,
) -> Value {
    receiver_phase_inner(path, settings, seed, business, mode, None, client_mode)
}

pub(super) fn fixed_parent_phase(
    path: &Path,
    settings: &Settings,
    seed: &[Packet],
    business: &[Packet],
    mode: &str,
    placement: &mut fixed_parent::Placement,
) -> Value {
    receiver_phase_inner(
        path,
        settings,
        seed,
        business,
        mode,
        Some(placement),
        pure_history_client::ClientMode::OriginalOuter,
    )
}

fn receiver_phase_inner(
    path: &Path,
    settings: &Settings,
    seed: &[Packet],
    business: &[Packet],
    mode: &str,
    mut placement: Option<&mut fixed_parent::Placement>,
    client_mode: pure_history_client::ClientMode,
) -> Value {
    assert!(
        placement.is_none() || client_mode == pure_history_client::ClientMode::OriginalOuter,
        "the separate receiver-placement experiment cannot borrow the sole client Host parent"
    );
    fs::create_dir(path).unwrap();
    let ipc_dir = tempfile::tempdir().unwrap();
    let requests: Vec<_> = business
        .iter()
        .map(|p| Request::Submit {
            packet: hex::encode(p.encode().unwrap()),
        })
        .collect();
    let honest: BTreeSet<_> = requests.iter().map(support::body_digest).collect();
    let (mut receiver, control, ready) = start_receiver_placed(
        path,
        &ipc_dir.path().join("control"),
        seed,
        &honest,
        mode,
        "receiver-owner-supplement",
        placement.as_deref_mut(),
    )
    .unwrap();
    let receiver_pid = receiver.child.id();
    let addresses: Vec<SocketAddr> = ready["addresses"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().parse().unwrap())
        .collect();
    let mut verifier = pure_history_client::Client::start(
        &path.join("independent-client"),
        settings,
        seed,
        client_mode,
    );
    let initial_tip = verifier.initial_tip();
    assert_eq!(hex::encode(initial_tip), ready["initial_tip"]);
    let mut actors = Vec::new();
    if mode != "baseline" {
        for actor in 0..ATTACKERS {
            actors.push(support::Actor::spawn(
                &path.join(format!("actor-{actor}")),
                json!({
                "actor":actor,"mode":mode,"address":addresses[actor%2].to_string(),
                "header":hex::encode(business[0].header.encode()),
                "transactions":business[0].transactions.iter().map(hex::encode).collect::<Vec<_>>(),
                "start_path":path.join("start.json"),"policy":support::policy_observation()}),
            ));
        }
    }
    let ready_deadline = Instant::now() + Duration::from_secs(180);
    while !actors.iter().all(support::Actor::ready) {
        assert!(
            Instant::now() < ready_deadline,
            "supplement attacker preparation did not complete"
        );
        support::pause();
    }
    if let Some(placement) = placement {
        placement
            .actors_ready(path, if mode == "baseline" { 0 } else { ATTACKERS })
            .unwrap();
    }
    let control = Arc::new(Mutex::new(control));
    let arm = control
        .lock()
        .unwrap()
        .call("arm", Duration::from_secs(5))
        .unwrap();
    let epoch = arm["epoch_monotonic_ns"].as_u64().unwrap();
    // Identical phase-plus-cleanup deadline; IPC and final publication do not
    // gain a new five-second allowance after this one has expired.
    receiver.deadline = Instant::now()
        + Duration::from_nanos((epoch + WINDOW_NS).saturating_sub(support::monotonic()))
        + Duration::from_secs(5);
    let sample_control = control.clone();
    let sampler = thread::spawn(move || {
        let mut samples = Vec::new();
        let mut failures = Vec::new();
        while support::phase_entry_ns(epoch, support::monotonic()).is_some() {
            match sample_control
                .lock()
                .unwrap()
                .call("sample", Duration::from_secs(2))
            {
                Ok(sample) if sample["phase_closed"] == true => break,
                Ok(sample) => samples.push(sample),
                Err(e) => {
                    failures.push(e.to_string());
                    break;
                }
            }
            thread::sleep(Duration::from_millis(50));
        }
        (samples, failures)
    });
    let mut submissions = Vec::new();
    let mut histories = Vec::new();
    let mut rounds = Vec::new();
    let mut errors = Vec::new();
    let mut next = 0;
    let mut after = initial_tip;
    for round in 0..ROUNDS {
        let scheduled = 1_000_000_000 + round as u64 * 4_000_000_000;
        while support::monotonic() < epoch + scheduled {
            support::pause();
        }
        let started = support::monotonic().saturating_sub(epoch);
        let before = hostile(&control, path).unwrap();
        let final_index = (round + 1) * 7;
        while next < final_index
            && support::monotonic() < epoch + WINDOW_NS
            && submissions.len() < 128
        {
            let Some(mut row) = support::call(
                addresses[next % 2],
                settings,
                requests[next].clone(),
                73,
                epoch,
            ) else {
                break;
            };
            row["packet_index"] = json!(next);
            row["listener"] = json!(next % 2);
            if support::on_time(&row) {
                next += 1;
            }
            submissions.push(row);
        }
        let tip = business[final_index - 1].id().unwrap();
        let included = business[round * 7].id().unwrap();
        let transaction = hash(b"tx-id", &[&business[round * 7].transactions[0]]);
        let mut observation = None;
        while next == final_index
            && support::monotonic() < epoch + WINDOW_NS
            && histories.len() < 64
        {
            let request = Request::History {
                tip: hex::encode(tip),
                after: hex::encode(after),
            };
            let Some(mut row) =
                support::call(addresses[round % 2], settings, request.clone(), 74, epoch)
            else {
                break;
            };
            row["request"] = serde_json::to_value(request).unwrap();
            row["listener"] = json!(round % 2);
            if support::on_time(&row) {
                let (imported, measurement) = verifier.import(
                    addresses[round % 2],
                    row["response"]["value"].clone(),
                    tip,
                    after,
                    support::now(),
                    epoch,
                );
                row["client_import"] = measurement;
                match imported {
                    Ok(value) => after = value,
                    Err(error) => errors.push(error),
                }
                if after == tip {
                    let (value, measurement) =
                        verifier.confirmation(transaction, included, support::now(), epoch);
                    row["client_confirmation"] = measurement;
                    match value {
                        Ok(value) => observation = Some(value),
                        Err(error) => errors.push(error.to_string()),
                    }
                }
            }
            histories.push(row);
            if observation.is_some() {
                break;
            }
        }
        let after_snapshot = hostile(&control, path).unwrap();
        let ended = support::monotonic().saturating_sub(epoch);
        let confirmed = observation.as_ref().is_some_and(|v| {
            v["confirmed"] == true
                && v["finalized"] == false
                && v["execution_authority"] == false
                && v["depth"] == 6
        }) && ended < WINDOW_NS;
        rounds.push(json!({"round":round,"scheduled_ns":scheduled,"started_ns":started,"ended_ns":ended,
            "confirmed_inside_pressure_window":confirmed,"observation":observation,
            "transaction":hex::encode(transaction),"included_block":hex::encode(included),"tip":hex::encode(tip),
            "hostile_before":before,"hostile_after":after_snapshot}));
        if !confirmed {
            break;
        }
    }

    let cleanup = receiver.deadline;
    let (actors, actor_process_costs): (Vec<_>, Vec<_>) = actors
        .into_iter()
        .map(|a| a.finish_with_process_cost(cleanup))
        .unzip();
    let (samples, sampling_errors) = sampler.join().unwrap();
    errors.extend(sampling_errors);
    let stop_result = control
        .lock()
        .unwrap()
        .call_until("stop", receiver.deadline);
    if let Err(e) = &stop_result {
        errors.push(e.to_string());
    }
    support::write_new(
        &path.join("receiver-control-trace.json"),
        &control.lock().unwrap().trace(),
    );
    let cost = receiver.finish();
    let captured = capture_receiver(path, &cost, receiver_pid, stop_result.is_ok());
    if let Err(e) = captured {
        errors.push(e.to_string());
    }
    let mut report = receiver_report_or_retain_failure(path, mode, || json!({
        "parent_pid":std::process::id(),"receiver_pid":receiver_pid,
        "receiver_wait4":cost,"actors":actors,"actor_process_costs":actor_process_costs,
        "submissions":submissions,"history":histories,
        "rounds":rounds,"samples":samples,"errors":errors,
        "original_window_ns":WINDOW_NS,"original_actor_call_cap":CALL_CAP,
        "client_execution_profile":if client_mode == pure_history_client::ClientMode::FixedHostV1 {
            history_verifier::PURE_CLIENT_PROFILE
        } else { "original-outer" }
    })).unwrap_or_else(|cause| panic!("receiver terminal report unavailable; actual partial observations retained: {cause}"));
    for round in &mut rounds {
        let a = round["started_ns"].as_u64().unwrap();
        let b = round["ended_ns"].as_u64().unwrap();
        round["depletion_observed_during_round"] = json!(samples.iter().any(|s| s["started_ns"]
            .as_u64()
            .zip(s["ended_ns"].as_u64())
            .is_some_and(|(x, y)| a <= x && x <= y && y <= b)
            && is_depleted(s)));
        round["overlapping_attack_calls"] = json!(actors
            .iter()
            .filter_map(|a| a["report"]["result"]["calls"].as_array())
            .flatten()
            .filter(|c| c["started_ns"]
                .as_u64()
                .zip(c["ended_ns"].as_u64())
                .zip(c["deadline_ns"].as_u64())
                .is_some_and(|((x, y), deadline)| x < b && y.min(deadline) > a))
            .count());
    }

    let (client_tip, client_height, client_generation) = verifier.snapshot_position();
    let client_process = verifier.finish();
    report["schema"] = json!(PHASE_SCHEMA);
    report["parent_pid"] = json!(std::process::id());
    report["receiver_pid"] = json!(receiver_pid);
    report["receiver_exit_success"] = cost["exit_success"].clone();
    report["receiver_parent_forced_kill"] = cost["parent_forced_kill"].clone();
    report["ready_actors"] = json!(if mode == "baseline" { 0 } else { ATTACKERS });
    report["actors"] = json!(actors);
    report["submissions"] = json!(submissions);
    report["history"] = json!(histories);
    report["rounds"] = json!(rounds);
    report["samples"] = json!(samples);
    report["client_tip"] = json!(hex::encode(client_tip));
    report["client_height"] = json!(client_height);
    report["client_generation"] = json!(client_generation);
    report["errors"] = json!(errors);
    report["work_hardness_qualified"] = json!(false);
    report["installation_authorized"] = json!(false);
    report["original_campaign_qualification"] = json!(false);
    pure_history_client::bind_phase(&mut report, client_process, &addresses);
    if let Err(e) = support::capture_attacker_cost_bindings(path, &report) {
        eprintln!("supplement thread-cost binding: {e}");
    }
    if let Err(e) = support::capture_actor_process_costs(path, &report, &actor_process_costs) {
        eprintln!("supplement process-cost binding: {e}");
    }
    if let Err(e) = support::capture_child_ownership_binding(path, &report, false) {
        eprintln!("supplement actor ownership binding: {e}");
    }
    if let Err(e) = support::capture_child_ownership_binding(path, &report, true) {
        eprintln!("supplement receiver ownership binding: {e}");
    }
    report
}

#[test]
#[ignore = "independent 90-second receiver subprocess supplement; original campaign is separate"]
fn whole_receiver_owner_pressure_v1() {
    run_receiver_campaign(pure_history_client::ClientMode::OriginalOuter);
}

#[test]
#[ignore = "new independent receiver and fixed-Host client composition; original finite gates remain"]
fn whole_receiver_owner_pressure_fixed_host_client_v1() {
    run_receiver_campaign(pure_history_client::ClientMode::FixedHostV1);
}

fn run_receiver_campaign(client_mode: pure_history_client::ClientMode) {
    let output = PathBuf::from(
        std::env::var_os("TRNM_RECEIVER_OWNER_V1_OUT").expect("create-only supplement output"),
    );
    fs::create_dir(&output).unwrap();
    let settings = support::settings();
    let (seed, business) = prepare(&output, &settings);
    let mut summaries = Vec::new();
    for mode in ["baseline", "from-zero", "correct-product-false-trace"] {
        eprintln!("receiver-owner supplement: {mode}, fixed 30s, same 24 actors / 2s calls, independent receiver PID");
        let result = std::panic::catch_unwind(|| {
            receiver_phase(
                &output.join(mode),
                &settings,
                &seed,
                &business,
                mode,
                client_mode,
            )
        });
        match result {
            Ok(report) => {
                let confirmed = report["rounds"].as_array().is_some_and(|r| {
                    r.len() == ROUNDS
                        && r.iter()
                            .all(|r| r["confirmed_inside_pressure_window"] == true)
                });
                support::write_new(&output.join(format!("{mode}.json")), &report);
                summaries.push(json!({"phase":mode,"file":format!("{mode}.json"),"all_rounds_confirmed":confirmed,"error":null}));
            }
            Err(e) => {
                let message = e
                    .downcast_ref::<String>()
                    .cloned()
                    .or_else(|| e.downcast_ref::<&str>().map(|s| s.to_string()))
                    .unwrap_or_else(|| "supplement panic".to_owned());
                support::write_new(
                    &output.join(format!("{mode}-failure.json")),
                    &json!({"schema":"pon-receiver-phase-failure-v1","phase":mode,"error":message}),
                );
                summaries.push(json!({"phase":mode,"file":format!("{mode}.json"),"all_rounds_confirmed":false,"error":message}));
            }
        }
    }
    support::write_new(
        &output.join("campaign.json"),
        &json!({"schema":CAMPAIGN_SCHEMA,"scope":OWNER_SCOPE,
        "window_ns":WINDOW_NS,"attackers":ATTACKERS,"actor_call_cap":CALL_CAP,"rounds":ROUNDS,
        "policy":support::policy_observation(),"phases":summaries,"original_campaign_qualification":false,
        "fixed_parent_provisioned":false,"physical_authentication":false,"public_fairness_qualified":false,
        "production_qualified":false,"work_hardness_qualified":false,"installation_authorized":false}),
    );
    pure_history_client::write_composition(&output, client_mode, "receiver-owner-supplement");
    assert!(
        summaries
            .iter()
            .all(|s| s["all_rounds_confirmed"] == true && s["error"].is_null()),
        "supplement failed; original and partial observations retained"
    );
}
