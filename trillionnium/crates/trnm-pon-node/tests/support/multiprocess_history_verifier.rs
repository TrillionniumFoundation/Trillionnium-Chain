//! The real public History importer has its own persistent OS process inside
//! the original administrator-provisioned fixed kernel parent. The campaign's
//! producer, attacker, receiver and observer remain in the original outer
//! 4-CPU/16-GiB service. No production guard or loopback exception is changed.
#[path = "multiprocess_history_lifeline.rs"]
mod lifeline;
#[path = "multiprocess_history_lifeline_native.rs"]
mod lifeline_native;

use super::{support, ClientOperationStamp, StateBackendChoice};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    net::SocketAddr,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};
use trnm_mvcc_fee::pon_executor::State;
use trnm_pon_node::{host_kernel_parent, ingress, Packet};
use trnm_protocol::pon_wire::Hash;

const MAX_MESSAGE_BYTES: u64 = 32 * 1024 * 1024;
const MAX_REQUESTS: u64 = 132; // Original <=64 imports, <=64 confirmations, snapshot and finish.
const PARENT: &str = host_kernel_parent::FIXED_PUBLIC_KERNEL_PARENT;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum ResourceProfile {
    Strict,
    GraphFenceV1,
}
impl ResourceProfile {
    fn label(self) -> &'static str {
        match self {
            Self::Strict => "strict-every-native-checkpoint-v1",
            Self::GraphFenceV1 => ingress::HISTORY_GRAPH_RESOURCE_PROFILE_V1,
        }
    }
    fn process_schema(self) -> &'static str {
        match self {
            Self::Strict => "native-public-history-verifier-process-v2",
            Self::GraphFenceV1 => "native-public-history-verifier-graph-fence-process-v1",
        }
    }
    fn entry_schema(self) -> &'static str {
        match self {
            Self::Strict => "native-public-history-verifier-entry-v2",
            Self::GraphFenceV1 => "native-public-history-verifier-graph-fence-entry-v1",
        }
    }
    fn from_job(job: &Value) -> Self {
        match job["history_resource_profile"].as_str().unwrap() {
            "strict-every-native-checkpoint-v1" => Self::Strict,
            ingress::HISTORY_GRAPH_RESOURCE_PROFILE_V1 => Self::GraphFenceV1,
            _ => panic!("explicit current History resource profile required"),
        }
    }
}

fn read(path: &Path) -> Value {
    let mut raw = Vec::new();
    File::open(path)
        .unwrap()
        .take(MAX_MESSAGE_BYTES + 1)
        .read_to_end(&mut raw)
        .unwrap();
    assert!(raw.len() as u64 <= MAX_MESSAGE_BYTES, "bounded fixture IPC");
    serde_json::from_slice(&raw).unwrap()
}
fn publish(path: &Path, value: &Value) {
    let raw = serde_json::to_vec(value).unwrap();
    assert!(raw.len() as u64 <= MAX_MESSAGE_BYTES, "bounded fixture IPC");
    assert!(!path.exists(), "fresh sequence-bound fixture response");
    let temporary = path.with_extension("pending");
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&temporary)
        .unwrap();
    file.write_all(&raw).unwrap();
    file.sync_all().unwrap();
    fs::rename(temporary, path).unwrap();
}
fn sha(path: &Path) -> String {
    let mut file = File::open(path).unwrap();
    let mut hash = Sha256::new();
    let mut buffer = [0_u8; 65536];
    loop {
        let count = file.read(&mut buffer).unwrap();
        if count == 0 {
            return hex::encode(hash.finalize());
        }
        hash.update(&buffer[..count]);
    }
}
fn short_file(path: &Path) -> String {
    let mut raw = String::new();
    File::open(path)
        .unwrap()
        .take(4097)
        .read_to_string(&mut raw)
        .unwrap();
    assert!(raw.len() <= 4096, "bounded kernel observation");
    raw.trim().to_owned()
}
fn membership(pid: u32) -> String {
    let raw = short_file(&PathBuf::from(format!("/proc/{pid}/cgroup")));
    assert_eq!(raw.lines().count(), 1, "unified v2 cgroup");
    raw.strip_prefix("0::").unwrap().to_owned()
}
/// Read-only OS observations do not create a KernelBudget. The actual child
/// separately invokes the production checker before Node setup and every call.
fn parent_observation() -> Value {
    let path = Path::new(PARENT);
    assert_eq!(fs::canonicalize(path).unwrap(), path);
    let metadata = fs::symlink_metadata(path).unwrap();
    assert!(metadata.is_dir() && metadata.uid() == 0 && metadata.mode() & 0o022 == 0);
    let mut cpu = serde_json::Map::new();
    for line in short_file(&path.join("cpu.stat")).lines() {
        let mut parts = line.split_ascii_whitespace();
        let key = parts.next().unwrap();
        let value: u64 = parts.next().unwrap().parse().unwrap();
        assert!(parts.next().is_none());
        assert!(cpu.insert(key.to_owned(), json!(value)).is_none());
    }
    for key in ["usage_usec", "nr_periods", "nr_throttled", "throttled_usec"] {
        assert!(cpu[key].is_u64());
    }
    json!({
        "path":PARENT,"device":metadata.dev(),"inode":metadata.ino(),
        "uid":metadata.uid(),"mode":metadata.mode(),
        "boot_id":short_file(Path::new("/proc/sys/kernel/random/boot_id")),
        "cpu.max":short_file(&path.join("cpu.max")),
        "cpu.max.burst":short_file(&path.join("cpu.max.burst")),
        "memory.max":short_file(&path.join("memory.max")),
        "memory.swap.max":short_file(&path.join("memory.swap.max")),
        "pids.max":short_file(&path.join("pids.max")),
        "pids.current":short_file(&path.join("pids.current")).parse::<u64>().unwrap(),
        "memory.current":short_file(&path.join("memory.current")).parse::<u64>().unwrap(),
        "cpu.stat":cpu,
    })
}

pub(super) struct Verifier {
    child: Child,
    // Keep the private controller end until the actual service has exited,
    // including its outer report/fsync tail. There is no early disarm.
    _controller_lifeline: lifeline::ControllerLifeline,
    unit: String,
    path: PathBuf,
    sequence: u64,
    ready: Value,
    before: Value,
    outer_cgroup: String,
    binary_sha256: String,
    finished: bool,
    spawned: Instant,
    resource_profile: ResourceProfile,
}
impl Verifier {
    pub(super) fn start(path: &Path, backend: StateBackendChoice, seed: &[Packet]) -> Self {
        Self::start_inner(path, backend, seed, None)
    }
    pub(super) fn start_with_graph_resource_fence_v1(
        path: &Path,
        backend: StateBackendChoice,
        seed: &[Packet],
    ) -> Self {
        Self::start_with_profile(path, backend, seed, None, ResourceProfile::GraphFenceV1)
    }
    fn start_inner(
        path: &Path,
        backend: StateBackendChoice,
        seed: &[Packet],
        cut: Option<&str>,
    ) -> Self {
        Self::start_with_profile(path, backend, seed, cut, ResourceProfile::Strict)
    }
    fn start_with_profile(
        path: &Path,
        backend: StateBackendChoice,
        seed: &[Packet],
        cut: Option<&str>,
        resource_profile: ResourceProfile,
    ) -> Self {
        assert!(
            cut.is_none() || resource_profile == ResourceProfile::Strict,
            "the original actual owner-death controls retain strict imports"
        );
        fs::create_dir(path).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        let executable = fs::canonicalize(std::env::current_exe().unwrap()).unwrap();
        let binary_sha256 = sha(&executable);
        let outer_cgroup = membership(std::process::id());
        assert!(
            !outer_cgroup.starts_with("/trnmponpublic.slice/"),
            "the original outer campaign budget must remain independent"
        );
        let loopback: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let refused = host_kernel_parent::require_host_kernel_budget(loopback, Some(PARENT));
        assert_eq!(
            refused.err().unwrap().to_string(),
            "PUBLIC_HOST_KERNEL_CONTEXT",
            "the real outer process cannot impersonate the public verifier"
        );
        let before = parent_observation();
        assert_eq!(
            before["pids.current"], 0,
            "fresh sole verifier under the shared fixed parent"
        );
        let job_path = path.join("job.json");
        publish(
            &job_path,
            &json!({
                "kind":"history-verifier", "backend":backend.label(),
                "seed":seed.iter().map(|packet|hex::encode(packet.encode().unwrap())).collect::<Vec<_>>(),
                "binary_sha256":binary_sha256,
                "parent":PARENT,
                "owner_death_control":cut,
                "history_resource_profile":resource_profile.label(),
                "controller_observation":{
                    "pid":std::process::id(),
                    "uid":rustix::process::getuid().as_raw(),
                    "gid":rustix::process::getgid().as_raw(),
                },
            }),
        );
        let unit = format!(
            "trnm-campaign-verifier-{}-{}.service",
            std::process::id(),
            support::monotonic()
        );
        let log = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(path.join("actor.log"))
            .unwrap();
        let error_log = log.try_clone().unwrap();
        // The actual self-pidfd is queued before the privileged launcher can
        // start. sudo -n and systemd-run --pipe pass this original stdin FD.
        let (controller_lifeline, actor_input) = lifeline::channel_for_current_process().unwrap();
        let spawned = Instant::now();
        // Only the administrative launcher is privileged. The test ELF and
        // every verifier descendant run as the original unprivileged user.
        let mut launch = Command::new("sudo");
        launch
            .args([
                "-n",
                "systemd-run",
                "--wait",
                "--pipe",
                "--service-type=exec",
                "--expand-environment=no",
                "--slice=trnmponpublic.slice",
            ])
            .arg(format!("--unit={unit}"))
            .arg(format!("--uid={}", rustix::process::getuid().as_raw()))
            .arg(format!("--gid={}", rustix::process::getgid().as_raw()))
            .args([
                "--property=KillMode=control-group",
                "--property=TimeoutStopSec=5s",
                "--property=RuntimeMaxSec=240s",
                "--property=NoNewPrivileges=yes",
                "--property=ProtectControlGroups=yes",
                "--property=Nice=10",
            ])
            .arg(format!(
                "--setenv=TRNM_MULTIPROCESS_JOB={}",
                job_path.display()
            ));
        if cut.is_none() {
            launch.arg("--collect");
        }
        launch
            .arg(&executable)
            .args([
                "--exact",
                "multiprocess_actor_entry",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .stdin(actor_input)
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(error_log));
        let child = launch.spawn().unwrap();
        let mut verifier = Self {
            child,
            _controller_lifeline: controller_lifeline,
            unit,
            path: path.to_owned(),
            sequence: 0,
            ready: Value::Null,
            before,
            outer_cgroup,
            binary_sha256,
            finished: false,
            spawned,
            resource_profile,
        };
        publish(
            &path.join("launch.json"),
            &json!({
                "schema":"native-history-verifier-launch-v1", "unit":verifier.unit,
                "controller_pid":std::process::id(), "launcher_pid":verifier.child.id(),
                "binary_sha256":verifier.binary_sha256,"parent":PARENT,
                "original_outer_cgroup":verifier.outer_cgroup,"parent_before_spawn":verifier.before,
                "job_sha256":sha(&job_path),"controller_capability_prequeued":true,
                "owner_death_control":cut,
                "history_resource_profile":resource_profile.label(),"collect_on_exit":cut.is_none(),
            }),
        );
        verifier.ready = verifier.wait_file(&path.join("ready.json"));
        assert_eq!(verifier.ready["binary_sha256"], verifier.binary_sha256);
        assert_eq!(
            verifier.ready["history_resource_profile"],
            resource_profile.label()
        );
        let pid = u32::try_from(verifier.ready["pid"].as_u64().unwrap()).unwrap();
        assert_eq!(
            sha(&PathBuf::from(format!("/proc/{pid}/exe"))),
            verifier.binary_sha256
        );
        let actual = membership(pid);
        assert_eq!(actual, format!("/trnmponpublic.slice/{}", verifier.unit));
        assert_eq!(verifier.ready["cgroup"], actual);
        assert_eq!(verifier.ready["public_host_kernel_checked"], true);
        assert_eq!(verifier.ready["wrong_parent_refused"], true);
        assert_eq!(
            verifier.ready["controller_lifeline"]["controller"],
            json!({"pid":std::process::id(),
                "uid":rustix::process::getuid().as_raw(),
                "gid":rustix::process::getgid().as_raw()})
        );
        assert_eq!(
            verifier.ready["controller_lifeline"]["armed_before_node_open"],
            true
        );
        assert_eq!(
            verifier.ready["controller_lifeline"]["watch_until_process_exit"],
            true
        );
        verifier
    }
    fn wait_file(&mut self, path: &Path) -> Value {
        let deadline = Instant::now() + Duration::from_secs(180);
        while !path.is_file() {
            assert!(
                self.child.try_wait().unwrap().is_none(),
                "verifier exited before its real response; actor.log retained"
            );
            assert!(
                Instant::now() < deadline,
                "bounded verifier response wait; original phase deadline remains unchanged"
            );
            thread::sleep(Duration::from_millis(2));
        }
        read(path)
    }
    fn call(&mut self, mut request: Value) -> Value {
        assert!(self.sequence < MAX_REQUESTS);
        request["sequence"] = json!(self.sequence);
        let raw = serde_json::to_vec(&request).unwrap();
        let request_sha256 = hex::encode(Sha256::digest(&raw));
        let request_path = self.path.join(format!("request-{:03}.json", self.sequence));
        publish(&request_path, &request);
        let response_path = self
            .path
            .join(format!("response-{:03}.json", self.sequence));
        let response = self.wait_file(&response_path);
        assert_eq!(response["sequence"], self.sequence);
        assert_eq!(response["request_sha256"], request_sha256);
        assert_eq!(response["binary_sha256"], self.binary_sha256);
        assert_eq!(response["measurement"]["sequence"], self.sequence);
        assert_eq!(response["measurement"]["process_id"], self.ready["pid"]);
        self.sequence += 1;
        response
    }
    pub(super) fn before(&self) -> Value {
        self.ready["native_history_arithmetic"].clone()
    }
    pub(super) fn import(
        &mut self,
        source: SocketAddr,
        page: Value,
        tip: Hash,
        after: Hash,
        clock: u64,
        epoch: u64,
    ) -> (Result<Hash, String>, Value) {
        let response = self.call(
            json!({"operation":"import", "source":source.to_string(), "page":page,
            "tip":tip,"after":after,"clock":clock,"epoch":epoch}),
        );
        let result = if let Some(error) = response["error"].as_str() {
            Err(error.to_owned())
        } else {
            serde_json::from_value(response["value"].clone()).map_err(|error| error.to_string())
        };
        (result, response["measurement"].clone())
    }
    pub(super) fn confirmation(
        &mut self,
        transaction: Hash,
        included: Hash,
        clock: u64,
        epoch: u64,
    ) -> (Result<Value, String>, Value) {
        let response = self.call(
            json!({"operation":"confirmation", "transaction":transaction,
            "included":included,"clock":clock,"epoch":epoch}),
        );
        let result = if let Some(error) = response["error"].as_str() {
            Err(error.to_owned())
        } else {
            Ok(response["value"].clone())
        };
        (result, response["measurement"].clone())
    }
    pub(super) fn snapshot(&mut self) -> ((Hash, u64, State), Value) {
        let response = self.call(json!({"operation":"snapshot"}));
        assert!(response["error"].is_null());
        (
            serde_json::from_value(response["value"]["active"].clone()).unwrap(),
            response["value"]["native_history_arithmetic"].clone(),
        )
    }
    pub(super) fn finish(mut self) -> Value {
        let response = self.call(json!({"operation":"finish"}));
        assert!(response["error"].is_null());
        let deadline = Instant::now() + Duration::from_secs(10);
        let status = loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                break status;
            }
            assert!(
                Instant::now() < deadline,
                "verifier did not exit and close its cgroup"
            );
            thread::sleep(Duration::from_millis(2));
        };
        let after = parent_observation();
        assert_eq!(
            after["pids.current"], 0,
            "no verifier descendant may escape settlement"
        );
        let report = read(&self.path.join("report.json"));
        let completed = status.success() && report["error"].is_null();
        self.finished = true;
        json!({"schema":self.resource_profile.process_schema(), "unit":self.unit,
            "history_resource_profile":self.resource_profile.label(),
            "ready":self.ready,"report":report,"completed_successfully":completed,
            "exit_success":status.success(),"parent_forced_kill":false,
            "request_count":self.sequence,"binary_sha256":self.binary_sha256,
            "original_outer_cgroup":self.outer_cgroup,"parent_before_spawn":self.before,
            "parent_after_reap":after,"spawn_to_reap_wall_ns":self.spawned.elapsed().as_nanos(),
            "outer_process_cpu_excludes_verifier":true,
            "scope":"same-host test actor; actual original fixed25-percent parent, all descendants; separate whole-process and whole-parent CPU, never add nested intervals or infer physical reservations"})
    }
}
impl Drop for Verifier {
    fn drop(&mut self) {
        if !self.finished {
            let _ = Command::new("sudo")
                .args(["-n", "systemctl", "stop", &self.unit])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
            let _ = self.child.wait();
        }
    }
}

pub(super) fn run(job: &Value, path: &Path) -> Value {
    let started = Instant::now();
    let process_cpu = support::cpu();
    // This returns only after the kernel-pidfd/EOF watcher is actually armed.
    // It remains detached and owns the original capabilities through OS exit;
    // neither native errors nor returning this function can cancel it.
    let owner = lifeline::arm_until_process_exit().unwrap();
    let controller = json!({"pid":owner.peer_pid,"uid":owner.peer_uid,"gid":owner.peer_gid});
    assert_eq!(job["controller_observation"], controller);
    let controller_lifeline = json!({
        "schema":"native-history-controller-lifeline-v1",
        "capability":"anonymous-unix-stream+prequeued-self-pidfd",
        "controller":controller,"armed_before_node_open":true,
        "watch_until_process_exit":true,
        "scope":"kernel-observed owner death or private EOF causes asynchronous self exit; no atomic zero-instruction guarantee and no fabricated clean settlement",
    });
    assert_eq!(job["parent"], PARENT);
    let resource_profile = ResourceProfile::from_job(job);
    assert!(job["owner_death_control"].is_null() || resource_profile == ResourceProfile::Strict);
    let binary_sha256 = sha(&std::env::current_exe().unwrap());
    assert_eq!(job["binary_sha256"], binary_sha256);
    let source: SocketAddr = "127.0.0.1:1".parse().unwrap();
    let kernel = host_kernel_parent::require_host_kernel_budget(source, Some(PARENT))
        .unwrap()
        .unwrap();
    kernel.verify().unwrap();
    let parent_before = parent_observation();
    let wrong_parent_refused =
        host_kernel_parent::require_host_kernel_budget(source, Some("/sys/fs/cgroup"))
            .err()
            .is_some_and(|error| error.to_string() == "PUBLIC_HOST_KERNEL_PARENT");
    assert!(wrong_parent_refused);
    let backend = match job["backend"].as_str().unwrap() {
        "authenticated-v1" => StateBackendChoice::AuthenticatedV1,
        "legacy-v2" => StateBackendChoice::LegacyV2,
        _ => panic!("explicit original state backend"),
    };
    let mut node = backend.open(&path.join("native"), support::settings());
    lifeline_native::boundary(
        job,
        path,
        "after-node-open-before-seed",
        || json!({"actual_native_open_returned":true,"active":node.read_active().unwrap()}),
    );
    for raw in job["seed"].as_array().unwrap() {
        kernel.verify().unwrap();
        let packet = Packet::decode(&hex::decode(raw.as_str().unwrap()).unwrap()).unwrap();
        let id = node.admit(&packet, support::now()).unwrap();
        node.activate_observed(id, support::now()).unwrap();
        kernel.verify().unwrap();
    }
    let ready = json!({"pid":std::process::id(),"cgroup":membership(std::process::id()),
        "calling_thread_cgroup":short_file(Path::new("/proc/thread-self/cgroup")),
        "binary_sha256":binary_sha256,"public_host_kernel_checked":true,
        "history_resource_profile":resource_profile.label(),
        "history_graph_resource":node.history_graph_resource_observation_v1().unwrap(),
        "controller_lifeline":controller_lifeline,
        "wrong_parent_refused":wrong_parent_refused,"parent":parent_observation(),
        "setup_process_cpu_ns":support::elapsed_cpu(process_cpu),"setup_wall_ns":started.elapsed().as_nanos(),
        "native_history_arithmetic":node.native_history_arithmetic_observation()});
    publish(&path.join("ready.json"), &ready);
    // The original actors may legitimately spend up to 180s becoming ready
    // before the unchanged 30s pressure window. This matches the administrative
    // 240s service lifetime and never extends a campaign or phase deadline.
    let deadline = started + Duration::from_secs(240);
    let mut calls = Vec::new();
    for sequence in 0..MAX_REQUESTS {
        let request_path = path.join(format!("request-{sequence:03}.json"));
        while !request_path.is_file() {
            assert!(
                Instant::now() < deadline,
                "finite verifier request lifetime"
            );
            thread::sleep(Duration::from_millis(2));
        }
        let request = read(&request_path);
        assert_eq!(request["sequence"], sequence);
        let request_sha256 = sha(&request_path);
        kernel.verify().unwrap();
        let call_cpu = support::cpu();
        let call_started = Instant::now();
        let operation = request["operation"].as_str().unwrap();
        let epoch = request["epoch"].as_u64().unwrap_or(0);
        let stamp = ClientOperationStamp::start(epoch);
        let result: Result<Value, String> = match operation {
            "import" => serde_json::from_value::<ingress::Page>(request["page"].clone())
                .map_err(|error| error.to_string())
                .and_then(|page| {
                    let address: SocketAddr = request["source"].as_str().unwrap().parse().unwrap();
                    let import = match resource_profile {
                        ResourceProfile::Strict => ingress::receive_public_page_from,
                        ResourceProfile::GraphFenceV1 => {
                            ingress::receive_public_page_with_graph_resource_fence_v1
                        }
                    };
                    import(
                        &mut node,
                        address,
                        page,
                        serde_json::from_value(request["tip"].clone()).unwrap(),
                        serde_json::from_value(request["after"].clone()).unwrap(),
                        request["clock"].as_u64().unwrap(),
                    )
                    .map(|hash| json!(hash))
                    .map_err(|error| error.to_string())
                }),
            "confirmation" => node
                .confirmation(
                    serde_json::from_value(request["transaction"].clone()).unwrap(),
                    serde_json::from_value(request["included"].clone()).unwrap(),
                    request["clock"].as_u64().unwrap(),
                )
                .map(|observation| json!(observation))
                .map_err(|error| error.to_string()),
            "snapshot" => node
                .read_active()
                .map(|active| {
                    json!({"active":active,
                "native_history_arithmetic":node.native_history_arithmetic_observation()})
                })
                .map_err(|error| error.to_string()),
            "finish" => Ok(json!({"closing_original_node":true})),
            _ => panic!("unknown verifier operation"),
        };
        if operation == "import" {
            lifeline_native::boundary(job, path, "after-public-import-before-response", || {
                assert!(
                    result.is_ok(),
                    "death control requires actual successful strict public import"
                );
                json!({"actual_strict_public_import_returned":true,
                    "returned_value":result.as_ref().unwrap(),"active":node.read_active().unwrap(),
                    "request_sha256":request_sha256,"sequence":sequence})
            });
        }
        let mut measurement = stamp.finish(epoch);
        measurement["process_cpu_ns"] = json!(support::elapsed_cpu(call_cpu));
        measurement["history_resource_profile"] = json!(resource_profile.label());
        measurement["history_graph_resource"] =
            node.history_graph_resource_observation_v1().unwrap();
        measurement["process_wall_ns"] = json!(call_started.elapsed().as_nanos());
        measurement["process_id"] = json!(std::process::id());
        measurement["sequence"] = json!(sequence);
        measurement["scope"] = json!("actual isolated verifier thread and entire verifier process; process includes scoped workers; both nested in whole-parent cgroup, not parent orchestration CPU");
        kernel.verify().unwrap();
        let (value, error) = match result {
            Ok(value) => (Some(value), None),
            Err(error) => (None, Some(error)),
        };
        let response = json!({"sequence":sequence,"request_sha256":request_sha256,
            "binary_sha256":binary_sha256,"value":value,"error":error,"measurement":measurement});
        publish(
            &path.join(format!("response-{sequence:03}.json")),
            &response,
        );
        calls.push(
            json!({"sequence":sequence,"operation":operation,"request_sha256":request_sha256,
            "response_sha256":sha(&path.join(format!("response-{sequence:03}.json"))),
            "succeeded":error.is_none(),"measurement":measurement}),
        );
        if operation == "finish" {
            let history_graph_resource = node.history_graph_resource_observation_v1().unwrap();
            drop(node);
            kernel.verify().unwrap();
            return json!({"schema":resource_profile.entry_schema(), "pid":std::process::id(),
                "history_resource_profile":resource_profile.label(),"history_graph_resource":history_graph_resource,
                "cgroup":membership(std::process::id()),"binary_sha256":binary_sha256,
                "controller_lifeline":controller_lifeline,
                "calls":calls,"whole_verifier_process_cpu_ns":support::elapsed_cpu(process_cpu),
                "process_cpu_since_start_ns":support::cpu(),
                "whole_verifier_wall_ns":started.elapsed().as_nanos(),"parent_before":parent_before,
                "parent_after_node_close":parent_observation(),"rss":support::rss(),"clean_node_close":true});
        }
    }
    panic!("finite verifier request count exhausted without close")
}

/// The ordinary entry wrapper invokes this after run has returned and before
/// serializing/fsyncing its final report. The owner watcher remains armed.
pub(super) fn after_run_return(job: &Value, path: &Path, result: Option<&Value>) {
    lifeline_native::boundary(job, path, "after-node-close-before-report", || {
        let result = result.expect("death control requires a real successful Node result");
        assert_eq!(result["clean_node_close"], true);
        json!({"actual_node_close_returned":true,"actual_runner_returned":true,
            "entry_schema":result["schema"],"clean_node_close":result["clean_node_close"]})
    });
}
