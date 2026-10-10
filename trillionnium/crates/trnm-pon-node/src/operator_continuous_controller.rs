//! Protected same-operator control pipe and separately granted receiver.
//! Root fixes every launch digest/key/context; the pipe never signs or issues grants.
use crate::ingress::{
    self,
    public_v3::{PublicMetrics, PublicPolicy, PublicServer},
    DevelopmentIdentity,
};
use crate::{
    ensure, operator_continuous_policy as policy, ContinuousSearchRequest, Node, Packet, Result,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    fs::{self, OpenOptions},
    io::Read,
    net::{SocketAddr, TcpListener},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};
pub const MAX_FRAME_BYTES: usize = 4 * 1024 * 1024;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReceiverService {
    listen: SocketAddr,
    secret_path: PathBuf,
    public_key: String,
    bits: u8,
    lifetime_ms: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Launch {
    schema: String,
    source_commit: String,
    node_policy_source: String,
    registry2_package: String,
    store: PathBuf,
    maximum_steps: u32,
    wall_seconds: u64,
    inputs: policy::Inputs,
    receiver_service: Option<ReceiverService>,
}
pub struct OutsideLaunch<'a> {
    pub path: &'a Path,
    pub sha256: &'a str,
    pub registry_key: &'a str,
    pub task_key: &'a str,
    pub source_commit: &'a str,
    pub node_policy_source: &'a str,
    pub registry2_package: &'a str,
}
#[derive(Deserialize)]
#[serde(tag = "purpose", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Step {
    Refresh {
        inputs: Box<policy::Inputs>,
    },
    Search {
        operation_id: String,
        transactions: Vec<String>,
    },
    Pool {
        operation_id: String,
        command: Box<crate::operator_continuous_pool::Command>,
    },
    LeaseReconcile {
        inputs: Box<policy::LeaseTransitionInput>,
    },
    WinnerValidation {
        packet: String,
        search_operation: String,
    },
    ReceiverValidation {
        packet: String,
    },
    Activate {
        block: String,
        receiver: bool,
    },
    ReadScopeSnapshot {
        operation_id: String,
    },
    ReadStatus {},
    ReadPoolSnapshot {},
    ReadProcessCpuSnapshot {},
    ReadHead {},
    ReadHistory {
        tip: String,
        after: String,
    },
    CancelEpoch {},
}
fn held_configuration(path: &Path, limit: u64) -> Result<Vec<u8>> {
    ensure(path.is_absolute(), "OWNER_CONTINUOUS_CONFIG_ABSOLUTE")?;
    let uid = rustix::process::geteuid().as_raw();
    let before = fs::symlink_metadata(path)?;
    ensure(
        before.is_file()
            && !before.file_type().is_symlink()
            && before.nlink() == 1
            && before.uid() == uid
            && before.mode() & 0o7777 == 0o600
            && before.len() > 0
            && before.len() <= limit,
        "OWNER_CONTINUOUS_CONFIG_FILE",
    )?;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    let mut raw = Vec::new();
    (&mut file).take(limit + 1).read_to_end(&mut raw)?;
    let identity = |m: &fs::Metadata| {
        (
            m.dev(),
            m.ino(),
            m.len(),
            m.mode(),
            m.uid(),
            m.nlink(),
            m.mtime(),
            m.mtime_nsec(),
            m.ctime(),
            m.ctime_nsec(),
        )
    };
    ensure(
        identity(&before) == identity(&file.metadata()?)
            && identity(&before) == identity(&fs::symlink_metadata(path)?)
            && raw.len() as u64 == before.len(),
        "OWNER_CONTINUOUS_CONFIG_IDENTITY",
    )?;
    Ok(raw)
}
fn read_launch(outside: &OutsideLaunch<'_>) -> Result<Launch> {
    let raw = held_configuration(outside.path, MAX_FRAME_BYTES as u64)?;
    ensure(
        crate::operator_task_policy::digest_bytes(&raw) == outside.sha256,
        "OWNER_CONTINUOUS_LAUNCH_SHA",
    )?;
    let config: Launch = serde_json::from_slice(&raw)?;
    ensure(
        config.schema == "restricted-owner-continuous-launch-v2"
            && config.source_commit == outside.source_commit
            && config.node_policy_source == outside.node_policy_source
            && config.registry2_package == outside.registry2_package
            && config.store.is_absolute()
            && (1..=65536).contains(&config.maximum_steps)
            && (1..=2580).contains(&config.wall_seconds),
        "OWNER_CONTINUOUS_OUTSIDE_LAUNCH",
    )?;
    policy::validate_protected_inputs(
        &config.inputs,
        outside.registry_key,
        outside.task_key,
        outside.source_commit,
        outside.node_policy_source,
        outside.registry2_package,
    )
    .map_err(|_| "OWNER_CONTINUOUS_PROTECTED_CONTEXT")?;
    Ok(config)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RecoveryLaunch {
    schema: String,
    source_commit: String,
    node_policy_source: String,
    registry2_package: String,
    journal_path: PathBuf,
    expected_uid: u32,
    expected_journal: crate::operator_continuous_history::Anchor,
    input: crate::operator_continuous_recovery::Input,
}
/// A separately guardian-closed, protected metadata action. It never opens a
/// Node or creates a clean-close record. Outside fixes the original wait4 and
/// full known-prefix proof before authorizing this actual residual settlement.
pub fn prepare_known_unclean_restart(outside: OutsideLaunch<'_>) -> Result<Value> {
    let raw = held_configuration(outside.path, MAX_FRAME_BYTES as u64)?;
    ensure(
        crate::operator_task_policy::digest_bytes(&raw) == outside.sha256,
        "OWNER_CONTINUOUS_RECOVERY_LAUNCH_SHA",
    )?;
    let config: RecoveryLaunch = serde_json::from_slice(&raw)?;
    let identity = &config.input.authority.identity;
    ensure(
        config.schema == "restricted-continuous-known-unclean-recovery-launch-v1"
            && config.source_commit == outside.source_commit
            && config.node_policy_source == outside.node_policy_source
            && config.registry2_package == outside.registry2_package
            && identity.registry_key == outside.registry_key
            && identity.task_key == outside.task_key
            && identity.source_commit == outside.source_commit
            && identity.node_policy_source == outside.node_policy_source
            && identity.registry2_package == outside.registry2_package
            && config.expected_uid == rustix::process::geteuid().as_raw()
            && config.journal_path.is_absolute(),
        "OWNER_CONTINUOUS_RECOVERY_PROTECTED_CONTEXT",
    )?;
    let now =
        crate::operator_task_policy::now_ns().map_err(|_| "OWNER_CONTINUOUS_RECOVERY_CLOCK")?;
    let verified = crate::operator_continuous_recovery::authenticate(&config.input, identity, now)
        .map_err(|_| "OWNER_CONTINUOUS_RECOVERY_AUTHORITY")?;
    let mut journal = crate::operator_continuous_history::Journal::open(
        &config.journal_path,
        config.expected_uid,
        identity,
        &config.expected_journal,
    )
    .map_err(|_| "OWNER_CONTINUOUS_RECOVERY_FULL_PREFIX")?;
    journal
        .record_known_unclean_process(&verified)
        .map_err(|_| "OWNER_CONTINUOUS_RECOVERY_SETTLEMENT")?;
    Ok(
        json!({"schema":"restricted-continuous-known-unclean-recovery-result-v1",
        "closed_process_receipt_sha256":verified.body.closed_process_receipt_sha256,
        "process_start_scope":verified.body.process_start_scope,
        "known_scope_total_cpu_ns":verified.body.known_scope_total_cpu_ns,
        "closed_process_total_cpu_ns":verified.body.closed_process_total_cpu_ns,
        "residual_cpu_ns":verified.body.residual_cpu_ns,"journal_head":journal.anchor(),
        "exact_usage_digest":journal.usage_digest().map_err(|_|"OWNER_CONTINUOUS_RECOVERY_USAGE")?,
        "native_opened":false,"clean_close_created":false,"refund":false,"credit_granted_ns":0,
        "public_network_ready":false}),
    )
}

fn packet(value: &str) -> Result<Packet> {
    ensure(
        value.len() <= 2 * 1024 * 1024,
        "OWNER_CONTINUOUS_PACKET_LIMIT",
    )?;
    let raw = hex::decode(value).map_err(|_| "OWNER_CONTINUOUS_PACKET_HEX")?;
    ensure(hex::encode(&raw) == value, "OWNER_CONTINUOUS_PACKET_HEX")?;
    Packet::decode(&raw)
}
struct Completion {
    parent: Option<String>,
    generation: Option<u64>,
    journal_head: Option<Value>,
    frame_recorded: bool,
    errors: Vec<&'static str>,
}
fn step_result(step: u32, native: Result<Value>, metadata: Completion) -> Value {
    let (result, native_error) = match native {
        Ok(value) => (Some(value), None),
        Err(error) => (
            None,
            Some(error.to_string().chars().take(256).collect::<String>()),
        ),
    };
    json!({"schema":"restricted-owner-continuous-step-result-v2","step":step,"parent":metadata.parent,"generation":metadata.generation,"journal_head":metadata.journal_head,"control_frame_recorded":metadata.frame_recorded,"metadata_errors":metadata.errors,"result":result,"native_error":native_error,"public_network_ready":false,"anonymous_fairness":false,"task_source_authenticated":false,"funding_balance_verified":false,"economic_hardness":false,"hard_CPU_preemption":false})
}
pub struct Controller {
    node: Arc<Mutex<Node>>,
    model: Vec<u8>,
    input: Vec<u8>,
    deadline: Instant,
    maximum_steps: u32,
    completed_steps: u32,
    source_commit: String,
    node_policy_source: String,
    registry2_package: String,
    registry_key: String,
    task_key: String,
    startup: Value,
    stop: Arc<AtomicBool>,
    receiver: Option<thread::JoinHandle<Result<PublicMetrics>>>,
    closed: bool,
}
impl Controller {
    pub fn open_pinned(outside: OutsideLaunch<'_>, started: Instant) -> Result<Self> {
        let config = read_launch(&outside)?;
        let deadline = started
            .checked_add(Duration::from_secs(config.wall_seconds))
            .ok_or("OWNER_CONTINUOUS_DEADLINE")?;
        ensure(Instant::now() < deadline, "OWNER_CONTINUOUS_DEADLINE")?;
        let (node, model, input) =
            Node::open_operator_continuous_checkpoint(&config.store, config.inputs, deadline)?;
        let startup = node.continuous_startup_receipt()?;
        let cpu = node.continuous_cpu_domain()?;
        let node = Arc::new(Mutex::new(node));
        let stop = Arc::new(AtomicBool::new(false));
        let receiver = if let Some(service) = config.receiver_service {
            let raw = held_configuration(&service.secret_path, 128)?;
            let text = std::str::from_utf8(&raw)
                .map_err(|_| "OWNER_CONTINUOUS_SECRET_CODEC")?
                .trim();
            ensure(text.len() == 64, "OWNER_CONTINUOUS_SECRET_CODEC")?;
            let identity = DevelopmentIdentity::from_secret_hex(text)
                .map_err(|_| "OWNER_CONTINUOUS_SECRET_CODEC")?;
            ensure(
                identity.public_key() == service.public_key,
                "OWNER_CONTINUOUS_SERVER_PUBLIC_KEY",
            )?;
            let public_policy =
                PublicPolicy::new(service.bits, Duration::from_millis(service.lifetime_ms))?;
            let server = PublicServer::with_continuous_domain(identity, public_policy, &cpu)?;
            let listener = TcpListener::bind(service.listen)?;
            let owner = node.clone();
            let stopping = stop.clone();
            let lifetime = deadline.saturating_duration_since(Instant::now());
            ensure(!lifetime.is_zero(), "OWNER_CONTINUOUS_DEADLINE")?;
            Some(thread::spawn(move || {
                ingress::public_v3::serve_public_protected_v3(
                    listener, owner, lifetime, stopping, server,
                )
            }))
        } else {
            None
        };
        Ok(Self {
            node,
            model,
            input,
            deadline,
            maximum_steps: config.maximum_steps,
            completed_steps: 0,
            source_commit: outside.source_commit.into(),
            node_policy_source: outside.node_policy_source.into(),
            registry2_package: outside.registry2_package.into(),
            registry_key: outside.registry_key.into(),
            task_key: outside.task_key.into(),
            startup,
            stop,
            receiver,
            closed: false,
        })
    }
    pub fn deadline(&self) -> Instant {
        self.deadline
    }
    pub fn startup(&self) -> &Value {
        &self.startup
    }
    pub fn apply(&mut self, raw: &[u8]) -> Result<Value> {
        ensure(
            !self.closed
                && Instant::now() < self.deadline
                && self.completed_steps < self.maximum_steps
                && !raw.is_empty()
                && raw.len() <= MAX_FRAME_BYTES,
            "OWNER_CONTINUOUS_FRAME_LIMIT",
        )?;
        let step: Step = serde_json::from_slice(raw)?;
        let mut node = self
            .node
            .lock()
            .map_err(|_| "OWNER_CONTINUOUS_NODE_POISONED")?;
        let frame = node.begin_continuous_control_frame()?;
        self.completed_steps = self
            .completed_steps
            .checked_add(1)
            .ok_or("OWNER_CONTINUOUS_FRAME_LIMIT")?;
        let native = (|| -> Result<Value> {
            Ok(match step {
                Step::Refresh { inputs } => {
                    policy::validate_protected_inputs(
                        &inputs,
                        &self.registry_key,
                        &self.task_key,
                        &self.source_commit,
                        &self.node_policy_source,
                        &self.registry2_package,
                    )
                    .map_err(|_| "OWNER_CONTINUOUS_PROTECTED_CONTEXT")?;
                    node.refresh_operator_continuous_view(*inputs)?;
                    json!({"refreshed":true,"work_capability_issued":false})
                }
                Step::Search {
                    operation_id,
                    transactions,
                } => {
                    ensure(transactions.len() <= 256, "OWNER_CONTINUOUS_TX_LIMIT")?;
                    let mut raws = Vec::new();
                    for value in transactions {
                        ensure(value.len() <= 4096, "OWNER_CONTINUOUS_TX_LIMIT")?;
                        let bytes = hex::decode(&value).map_err(|_| "OWNER_CONTINUOUS_TX_HEX")?;
                        ensure(hex::encode(&bytes) == value, "OWNER_CONTINUOUS_TX_HEX")?;
                        raws.push(bytes);
                    }
                    let found = node.search_owned_continuous_window(ContinuousSearchRequest {
                        operation_id: &operation_id,
                        transactions: raws,
                        model: &self.model,
                        input: &self.input,
                        stop: &self.stop,
                        deadline: self.deadline,
                    })?;
                    let packet = found
                        .packet
                        .as_ref()
                        .map(Packet::encode)
                        .transpose()?
                        .map(hex::encode);
                    json!({"search":found,"packet":packet})
                }
                Step::Pool {
                    operation_id,
                    command,
                } => serde_json::to_value(
                    node.operate_owned_continuous_pool(&operation_id, *command)?,
                )?,
                Step::LeaseReconcile { inputs } => {
                    serde_json::to_value(node.reconcile_owned_continuous_lease(*inputs)?)?
                }
                Step::WinnerValidation {
                    packet: value,
                    search_operation,
                } => serde_json::to_value(node.validate_owned_continuous_winner(
                    packet(&value)?,
                    &search_operation,
                    ingress::now()?,
                )?)?,
                Step::ReceiverValidation { packet: value } => serde_json::to_value(
                    node.receive_owned_continuous_packet(packet(&value)?, ingress::now()?)?,
                )?,
                Step::Activate { block, receiver } => {
                    serde_json::to_value(node.activate_owned_continuous_packet(
                        crate::digest(&block)?,
                        receiver,
                        ingress::now()?,
                    )?)?
                }
                Step::ReadScopeSnapshot { operation_id } => {
                    node.continuous_scope_receipt(&operation_id)?
                }
                Step::ReadStatus {} => node.stats()?,
                Step::ReadPoolSnapshot {} => node.continuous_pool_snapshot()?,
                Step::ReadProcessCpuSnapshot {} => node.continuous_process_cpu_snapshot()?,
                Step::ReadHead {} => node.public_head_metadata()?,
                Step::ReadHistory { tip, after } => {
                    let mut progress =
                        |_| ensure(Instant::now() < self.deadline, "OWNER_CONTINUOUS_DEADLINE");
                    let packets = node.public_history_packet(
                        crate::digest(&tip)?,
                        crate::digest(&after)?,
                        8192,
                        &mut progress,
                    )?;
                    let rows = packets
                        .iter()
                        .map(|p| p.encode().map(hex::encode))
                        .collect::<Result<Vec<_>>>()?;
                    json!({"packets":rows})
                }
                Step::CancelEpoch {} => {
                    json!({"cancelled":node.cancel_continuous_epoch()?,"refund":false})
                }
            })
        })();
        // Complete Root frame count is persisted AFTER the action. This avoids
        // a circular hash in the externally pinned budget prior journal. A
        // panic/unwind before this append leaves a held-FD terminal unknown.
        let frame_recorded = frame.finish(raw);
        let mut metadata_errors = Vec::new();
        if !frame_recorded {
            metadata_errors.push("JOURNAL_FRAME_UNAVAILABLE");
        }
        let journal_head = match node.continuous_journal_head() {
            Ok(value) => Some(value),
            Err(_) => {
                metadata_errors.push("JOURNAL_HEAD_UNAVAILABLE");
                None
            }
        };
        let (parent, generation) = match node.active() {
            Ok((p, g)) => (Some(hex::encode(p)), Some(g)),
            Err(_) => {
                metadata_errors.push("ACTIVE_METADATA_UNAVAILABLE");
                (None, None)
            }
        };
        if !metadata_errors.is_empty() {
            node.mark_continuous_metadata_unknown();
        }
        Ok(step_result(
            self.completed_steps,
            native,
            Completion {
                parent,
                generation,
                journal_head,
                frame_recorded,
                errors: metadata_errors,
            },
        ))
    }
    pub fn close(&mut self) -> Result<Value> {
        ensure(!self.closed, "OWNER_CONTINUOUS_ALREADY_CLOSED")?;
        self.stop.store(true, Ordering::Release);
        let metrics = self
            .receiver
            .take()
            .map(|worker| {
                worker
                    .join()
                    .map_err(|_| crate::Error::from("OWNER_CONTINUOUS_RECEIVER_PANIC"))
                    .and_then(|result| result)
            })
            .transpose()?;
        let checkpoint = self
            .node
            .lock()
            .map_err(|_| "OWNER_CONTINUOUS_NODE_POISONED")?
            .close_continuous_checkpoint()?;
        self.closed = true;
        Ok(
            json!({"schema":"restricted-owner-continuous-pipe-closed-v2","checkpoint":checkpoint,"receiver_metrics":metrics,"public_network_ready":false,"original8193_qualification":false}),
        )
    }
}
impl Drop for Controller {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.receiver.take() {
            let _actual = worker.join();
        }
    }
}
#[cfg(all(test, target_os = "linux"))]
#[path = "operator_continuous_controller_tests.rs"]
mod tests;
