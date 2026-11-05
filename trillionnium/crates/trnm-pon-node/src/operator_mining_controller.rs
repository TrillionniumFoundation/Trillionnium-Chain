//! Root-owned local finite controller. This is neither a public miner RPC nor
//! anonymous task authorization. Every refresh is a full outside-signed view.
use crate::{
    ensure, ingress::public_v3::ServiceMutationCpuDomain, operator_mining_policy as policy, Node,
    Packet, Result,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    fs::{self, OpenOptions},
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::atomic::AtomicBool,
    time::{Duration, Instant},
};
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Launch {
    pub schema: String,
    pub source_commit: String,
    pub node_policy_source: String,
    pub registry2_package: String,
    pub store: PathBuf,
    pub maximum_steps: u32,
    pub wall_seconds: u64,
    pub inputs: policy::Inputs,
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
    WinnerValidation {
        packet: String,
    },
    Activate {
        block: String,
    },
    CancelEpoch {},
    ReadStatus {},
}
/// Full regular-file descriptor identity and outside digest, never a request
/// path. The externally passed key pair cannot be replaced by the file itself.
fn read_launch(
    path: &Path,
    expected_sha256: &str,
    registry_key: &str,
    task_key: &str,
    source_commit: &str,
    node_policy_source: &str,
    registry2_package: &str,
) -> Result<Launch> {
    ensure(path.is_absolute(), "OWNER_MINING_LAUNCH_ABSOLUTE")?;
    let uid = rustix::process::geteuid().as_raw();
    let before = fs::symlink_metadata(path)?;
    ensure(
        before.is_file()
            && !before.file_type().is_symlink()
            && before.nlink() == 1
            && before.uid() == uid
            && before.mode() & 0o7777 == 0o600
            && before.len() > 0
            && before.len() <= 262144,
        "OWNER_MINING_LAUNCH_FILE",
    )?;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    let mut raw = Vec::new();
    (&mut file).take(262145).read_to_end(&mut raw)?;
    let after = file.metadata()?;
    let visible = fs::symlink_metadata(path)?;
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
        identity(&before) == identity(&after)
            && identity(&after) == identity(&visible)
            && raw.len() as u64 == before.len()
            && crate::operator_task_policy::digest_bytes(&raw) == expected_sha256,
        "OWNER_MINING_LAUNCH_IDENTITY",
    )?;
    let config: Launch = serde_json::from_slice(&raw)?;
    ensure(
        config.schema == "restricted-owner-finite-mining-launch-v1"
            && config.store.is_absolute()
            && (1..=32).contains(&config.maximum_steps)
            && (1..=90).contains(&config.wall_seconds)
            && config.source_commit == source_commit
            && config.node_policy_source == node_policy_source
            && config.registry2_package == registry2_package
            && config.inputs.authority.registry_key == registry_key
            && config.inputs.authority.task_key == task_key,
        "OWNER_MINING_OUTSIDE_LAUNCH",
    )?;
    policy::validate_protected_inputs(
        &config.inputs,
        source_commit,
        node_policy_source,
        registry2_package,
    )
    .map_err(|_| "OWNER_MINING_PROTECTED_CONTEXT")?;
    Ok(config)
}
pub struct Controller {
    node: Node,
    model: Vec<u8>,
    input: Vec<u8>,
    cpu: ServiceMutationCpuDomain,
    deadline: Instant,
    maximum_steps: u32,
    completed_steps: u32,
    source_commit: String,
    node_policy_source: String,
    registry2_package: String,
    registry_key: String,
    task_key: String,
    startup_cpu: Value,
}
impl Controller {
    pub fn startup_cpu(&self) -> &Value {
        &self.startup_cpu
    }
    pub fn deadline(&self) -> Instant {
        self.deadline
    }
    /// The standalone scalar domain is explicitly local to this one finite
    /// controller. A service actor must instead use PublicServer's actual domain
    /// when invoking the Node API; no shared service epoch is claimed here.
    #[allow(clippy::too_many_arguments)]
    pub fn open_pinned(
        path: &Path,
        expected_sha256: &str,
        registry_key: &str,
        task_key: &str,
        source_commit: &str,
        node_policy_source: &str,
        registry2_package: &str,
        started: Instant,
    ) -> Result<Self> {
        let config = read_launch(
            path,
            expected_sha256,
            registry_key,
            task_key,
            source_commit,
            node_policy_source,
            registry2_package,
        )?;
        Self::open(config, started)
    }
    fn open(config: Launch, started: Instant) -> Result<Self> {
        let deadline = started
            .checked_add(Duration::from_secs(config.wall_seconds))
            .ok_or("OWNER_MINING_DEADLINE")?;
        ensure(Instant::now() < deadline, "OWNER_MINING_DEADLINE")?;
        let registry_key = config.inputs.authority.registry_key.clone();
        let task_key = config.inputs.authority.task_key.clone();
        let cpu = ServiceMutationCpuDomain::standalone();
        let (mut node, model, input) =
            Node::open_operator_mining_checkpoint(&config.store, config.inputs, &cpu)?;
        ensure(Instant::now() < deadline, "OWNER_MINING_DEADLINE")?;
        let startup_cpu = serde_json::to_value(node.take_mining_startup_cpu()?)?;
        Ok(Self {
            node,
            model,
            input,
            cpu,
            deadline,
            maximum_steps: config.maximum_steps,
            completed_steps: 0,
            source_commit: config.source_commit,
            node_policy_source: config.node_policy_source,
            registry2_package: config.registry2_package,
            registry_key,
            task_key,
            startup_cpu,
        })
    }
    /// Bounded complete Root control frame. Public traffic cannot reach this
    /// controller. Search never authorizes validation, activation or Pool work.
    pub fn apply(&mut self, raw: &[u8]) -> Result<Value> {
        ensure(
            Instant::now() < self.deadline
                && self.completed_steps < self.maximum_steps
                && !raw.is_empty()
                && raw.len() <= 262144,
            "OWNER_MINING_FRAME_LIMIT",
        )?;
        let step: Step = serde_json::from_slice(raw)?;
        self.completed_steps = self
            .completed_steps
            .checked_add(1)
            .ok_or("OWNER_MINING_FRAME_LIMIT")?;
        let result = match step {
            Step::Refresh { inputs } => {
                ensure(
                    inputs.authority.registry_key == self.registry_key
                        && inputs.authority.task_key == self.task_key,
                    "OWNER_MINING_KEYS_CHANGED",
                )?;
                policy::validate_protected_inputs(
                    &inputs,
                    &self.source_commit,
                    &self.node_policy_source,
                    &self.registry2_package,
                )
                .map_err(|_| "OWNER_MINING_PROTECTED_CONTEXT")?;
                self.node
                    .refresh_operator_mining_task_view(*inputs, &self.cpu)?;
                json!({"refreshed":true,"work_capability_issued":false})
            }
            Step::Search {
                operation_id,
                transactions,
            } => {
                ensure(transactions.len() <= 256, "OWNER_MINING_TRANSACTIONS")?;
                let mut raws = Vec::new();
                for hex in transactions {
                    ensure(hex.len() <= 4096, "OWNER_MINING_TRANSACTIONS")?;
                    let bytes = hex::decode(&hex).map_err(|_| "OWNER_MINING_TRANSACTION_HEX")?;
                    ensure(hex::encode(&bytes) == hex, "OWNER_MINING_TRANSACTION_HEX")?;
                    raws.push(bytes);
                }
                let found = self.node.search_owned_mining_window(
                    &operation_id,
                    raws,
                    &self.model,
                    &self.input,
                    &self.cpu,
                    &AtomicBool::new(false),
                    self.deadline,
                )?;
                let packet = found
                    .packet
                    .as_ref()
                    .map(Packet::encode)
                    .transpose()?
                    .map(hex::encode);
                json!({"search":found,"packet":packet})
            }
            Step::WinnerValidation { packet } => {
                ensure(
                    packet.len() <= 2 * 1024 * 1024,
                    "OWNER_MINING_PACKET_LENGTH",
                )?;
                let raw = hex::decode(&packet).map_err(|_| "OWNER_MINING_PACKET_HEX")?;
                ensure(hex::encode(&raw) == packet, "OWNER_MINING_PACKET_HEX")?;
                let packet = Packet::decode(&raw).map_err(|_| "OWNER_MINING_PACKET_WIRE")?;
                serde_json::to_value(self.node.validate_owned_mining_winner(
                    packet,
                    crate::ingress::now()?,
                    &self.cpu,
                )?)?
            }
            Step::Activate { block } => {
                let target = crate::digest(&block)?;
                serde_json::to_value(self.node.activate_owned_mining_winner(
                    target,
                    crate::ingress::now()?,
                    &self.cpu,
                )?)?
            }
            Step::CancelEpoch {} => {
                json!({"cancelled":self.node.mining_epoch_cancellation()?.cancel(),
                "refund":false})
            }
            Step::ReadStatus {} => self.node.stats()?,
        };
        Ok(
            json!({"schema":"restricted-owner-finite-mining-step-result-v1",
            "step":self.completed_steps,"result":result,"public_network_ready":false,
            "task_source_authenticated":false,"funding_balance_verified":false,
            "economic_hardness":false,"globally_cheapest_miner":false,"hard_CPU_preemption":false}),
        )
    }
}
#[cfg(test)]
#[path = "operator_mining_controller_tests.rs"]
mod tests;
