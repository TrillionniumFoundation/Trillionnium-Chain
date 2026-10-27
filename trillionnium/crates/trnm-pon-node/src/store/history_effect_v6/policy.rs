//! Fresh local V6 signatures. Parsing does not construct a verified capability.
use super::*;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

pub(super) const DOMAIN: &[u8] = b"TRNM-HISTORY-EFFECT-RECOVERY-V6";
pub(super) const MAX_ENVELOPE: usize = 65_536;
const MAX_PROTECTED_INPUT: u64 = 512 * 1024;

pub(super) fn digest(raw: &[u8]) -> String {
    crate::operator_task_policy::digest_bytes(raw)
}
pub(super) fn encoded<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec(value)?)
}
pub(super) fn id(value: &str, bytes: usize) -> Result<()> {
    ensure(
        value.len() == bytes * 2
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "HISTORY_V6_ID",
    )
}
pub(super) fn now() -> Result<u64> {
    crate::operator_task_policy::now_ns().map_err(|_| "HISTORY_V6_CLOCK".into())
}
fn window(issued: u64, expires: u64, at: u64) -> Result<()> {
    ensure(
        issued <= at && at < expires && expires > issued && expires - issued <= 86_400_000_000_000,
        "HISTORY_V6_WINDOW",
    )
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Identity {
    pub schema: String,
    pub owner: String,
    pub store: String,
    pub network: String,
    pub parameters: String,
    pub genesis: String,
    pub source_commit: String,
    pub registry_key: String,
    pub task_key: String,
}
impl Identity {
    pub fn validate(&self) -> Result<()> {
        ensure(
            self.schema == "restricted-history-effect-identity-v6"
                && self.registry_key != self.task_key,
            "HISTORY_V6_IDENTITY",
        )?;
        for value in [
            &self.owner,
            &self.store,
            &self.network,
            &self.parameters,
            &self.genesis,
            &self.registry_key,
            &self.task_key,
        ] {
            id(value, 32)?;
        }
        id(&self.source_commit, 20)
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        Ok(digest(&encoded(self)?))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Anchor {
    pub sequence: u64,
    pub digest: String,
}
impl Anchor {
    pub fn empty() -> Self {
        Self {
            sequence: 0,
            digest: "00".repeat(32),
        }
    }
    pub fn validate(&self) -> Result<()> {
        id(&self.digest, 32)?;
        ensure(
            self.sequence <= 4096 && (self.sequence != 0 || self.digest == "00".repeat(32)),
            "HISTORY_V6_ANCHOR",
        )
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Frontier {
    pub block: String,
    pub root: String,
    pub generation: u64,
}
impl Frontier {
    pub fn validate(&self) -> Result<()> {
        id(&self.block, 32)?;
        id(&self.root, 32)?;
        ensure(self.generation <= i64::MAX as u64, "HISTORY_V6_GENERATION")
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct ExecutionParent {
    pub block: String,
    pub root: String,
    pub height: u64,
}
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Usage {
    pub cpu_ns: u64,
    pub material_bytes: u64,
    pub received_bytes: u64,
    pub operations: u64,
}
impl Usage {
    pub fn add(self, rhs: Self) -> Result<Self> {
        Ok(Self {
            cpu_ns: self
                .cpu_ns
                .checked_add(rhs.cpu_ns)
                .ok_or("HISTORY_V6_BUDGET")?,
            material_bytes: self
                .material_bytes
                .checked_add(rhs.material_bytes)
                .ok_or("HISTORY_V6_BUDGET")?,
            received_bytes: self
                .received_bytes
                .checked_add(rhs.received_bytes)
                .ok_or("HISTORY_V6_BUDGET")?,
            operations: self
                .operations
                .checked_add(rhs.operations)
                .ok_or("HISTORY_V6_BUDGET")?,
        })
    }
    pub fn fits(self, limit: Self) -> bool {
        self.cpu_ns <= limit.cpu_ns
            && self.material_bytes <= limit.material_bytes
            && self.received_bytes <= limit.received_bytes
            && self.operations <= limit.operations
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Budget {
    pub schema: String,
    pub identity: Identity,
    pub budget_id: String,
    pub sequence: u64,
    pub outside_anchor: Anchor,
    pub lifetime_ceiling: Usage,
    pub nonce_first: u64,
    pub nonce_last: u64,
    pub work_nonce_first: u64,
    pub work_nonce_last: u64,
    pub issued_ns: u64,
    pub expires_ns: u64,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(super) enum Purpose {
    Startup,
    Validation,
    Activation,
    Close,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Operation {
    pub schema: String,
    pub identity: Identity,
    pub budget_id: String,
    pub operation_id: String,
    pub request_nonce: u64,
    pub epoch: String,
    pub purpose: Purpose,
    pub owner_frontier: Frontier,
    pub outside_spent_anchor: Anchor,
    pub execution_parent: Option<ExecutionParent>,
    pub packet_sha256: Option<String>,
    pub target: String,
    pub target_root: String,
    pub validation_operation_id: Option<String>,
    pub activation_operation_id: Option<String>,
    pub binding: Option<crate::operator_continuous_recipient::DeclaredBinding>,
    pub allowance: Usage,
    pub issued_ns: u64,
    pub expires_ns: u64,
}
impl Operation {
    pub fn validate(&self, at: u64) -> Result<()> {
        self.identity.validate()?;
        self.owner_frontier.validate()?;
        self.outside_spent_anchor.validate()?;
        window(self.issued_ns, self.expires_ns, at)?;
        ensure(
            self.schema == "restricted-history-effect-operation-v6"
                && self.request_nonce > 0
                && self.allowance.operations == 1
                && self.allowance.cpu_ns > 0
                && self.allowance.cpu_ns <= 60_000_000_000
                && self.allowance.material_bytes <= 32 * 1024 * 1024
                && self.allowance.received_bytes <= 2 * 1024 * 1024,
            "HISTORY_V6_OPERATION",
        )?;
        for value in [
            &self.budget_id,
            &self.operation_id,
            &self.epoch,
            &self.target,
            &self.target_root,
        ] {
            id(value, 32)?;
        }
        if matches!(self.purpose, Purpose::Startup | Purpose::Close) {
            ensure(
                self.execution_parent.is_none()
                    && self.packet_sha256.is_none()
                    && self.validation_operation_id.is_none()
                    && self.activation_operation_id.is_none()
                    && self.target == self.owner_frontier.block
                    && self.target_root == self.owner_frontier.root,
                "HISTORY_V6_STARTUP",
            )?;
        } else {
            let parent = self.execution_parent.as_ref().ok_or("HISTORY_V6_PARENT")?;
            id(&parent.block, 32)?;
            id(&parent.root, 32)?;
            ensure(parent.height < i64::MAX as u64, "HISTORY_V6_HEIGHT")?;
            id(
                self.packet_sha256.as_deref().ok_or("HISTORY_V6_PACKET")?,
                32,
            )?;
            let validation = self
                .validation_operation_id
                .as_deref()
                .ok_or("HISTORY_V6_PAIR")?;
            let activation = self
                .activation_operation_id
                .as_deref()
                .ok_or("HISTORY_V6_PAIR")?;
            id(validation, 32)?;
            id(activation, 32)?;
            ensure(
                validation != activation
                    && match self.purpose {
                        Purpose::Validation => validation == self.operation_id,
                        Purpose::Activation => activation == self.operation_id,
                        Purpose::Startup | Purpose::Close => false,
                    },
                "HISTORY_V6_PAIR",
            )?;
        }
        crate::operator_continuous_recipient::declared_binding_digest(
            self.binding.as_ref().ok_or("HISTORY_V6_TASK")?,
        )
        .map_err(|_| "HISTORY_V6_TASK")?;
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct EffectMarker {
    pub schema: String,
    pub identity_sha256: String,
    pub owner: String,
    pub store: String,
    pub epoch: String,
    pub operation_id: String,
    pub purpose: Purpose,
    pub intent_sha256: String,
    pub packet_sha256: String,
    pub target: String,
    pub target_root: String,
    pub validation_operation_id: String,
    pub activation_operation_id: String,
    pub before: Frontier,
    pub after: Frontier,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct ClosedProcess {
    pub schema: String,
    pub epoch: String,
    pub executable_sha256: String,
    pub intent_sha256: String,
    pub original_journal: Anchor,
    pub owned_namespace_pid: u64,
    pub observed_visible_pid: u64,
    pub observed_starttime_ticks: u64,
    pub pidfd_identity_verified: bool,
    pub actual_wait4: bool,
    pub signal: i32,
    pub all_descendants_closed: bool,
    pub descendants: Vec<u64>,
    pub descendant_accounting_profile: String,
    pub fixture_selector: String,
    pub historical_process_tree_observed: bool,
    pub cpu_counter_profile: String,
    pub reported_user_seconds: String,
    pub reported_system_seconds: String,
    pub user_cpu_microseconds: u64,
    pub system_cpu_microseconds: u64,
    pub reported_cpu_upper_bound_ns: u64,
    pub marker: Option<EffectMarker>,
    pub actual_frontier: Frontier,
    pub physical_cost_qualified: bool,
}
impl ClosedProcess {
    pub fn validate(&self) -> Result<()> {
        self.original_journal.validate()?;
        self.actual_frontier.validate()?;
        id(&self.epoch, 32)?;
        id(&self.executable_sha256, 32)?;
        id(&self.intent_sha256, 32)?;
        let upper = self
            .user_cpu_microseconds
            .checked_add(self.system_cpu_microseconds)
            .and_then(|v| v.checked_add(2))
            .and_then(|v| v.checked_mul(1000))
            .ok_or("HISTORY_V6_CPU_BOUND")?;
        ensure(
            self.schema == "actual-history-effect-closed-process-v6"
                && self.owned_namespace_pid > 0
                && self.observed_visible_pid > 0
                && self.observed_starttime_ticks > 0
                && self.pidfd_identity_verified
                && self.actual_wait4
                && self.signal == 9
                && self.all_descendants_closed
                && self.descendants.is_empty()
                && self.descendant_accounting_profile
                    == "source-bound-native-thread-only-fixture-v1"
                && self.fixture_selector
                    == "store::history_effect_v6::tests::history_effect_v6_process_child_helper"
                && !self.historical_process_tree_observed
                && self.cpu_counter_profile == "linux-wait4-timeval-quantized-v1"
                && self.reported_cpu_upper_bound_ns == upper
                && !self.physical_cost_qualified,
            "HISTORY_V6_CLOSED_PROCESS_REQUIRED",
        )?;
        for (reported, units) in [
            (&self.reported_user_seconds, self.user_cpu_microseconds),
            (&self.reported_system_seconds, self.system_cpu_microseconds),
        ] {
            ensure(reported.len() <= 64, "HISTORY_V6_CPU_COUNTER")?;
            let value = reported
                .parse::<f64>()
                .map_err(|_| "HISTORY_V6_CPU_COUNTER")?;
            ensure(
                value.is_finite()
                    && (0.0..=86_400.0).contains(&value)
                    && (value * 1_000_000.0 - units as f64).abs() <= 0.001,
                "HISTORY_V6_CPU_COUNTER",
            )?;
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Recovery {
    pub schema: String,
    pub identity: Identity,
    pub request_nonce: u64,
    pub outside_anchor: Anchor,
    pub pending_operation_id: String,
    pub intent_sha256: String,
    pub closed_process_sha256: String,
    pub actual_frontier: Frontier,
    pub marker_sha256: Option<String>,
    pub issued_ns: u64,
    pub expires_ns: u64,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Envelope<T> {
    pub body: T,
    pub registry_signature: String,
    pub task_signature: String,
}
pub(super) fn message<T: Serialize>(kind: u8, role: u8, body: &T) -> Result<Vec<u8>> {
    let raw = encoded(body)?;
    ensure(raw.len() <= MAX_ENVELOPE, "HISTORY_V6_ENVELOPE_LIMIT")?;
    let mut result = DOMAIN.to_vec();
    result.extend([kind, role]);
    result.extend((raw.len() as u32).to_le_bytes());
    result.extend(raw);
    Ok(result)
}
fn authenticate<T: Serialize + DeserializeOwned>(
    raw: &[u8],
    kind: u8,
    identity: &Identity,
) -> Result<T> {
    identity.validate()?;
    ensure(
        !raw.is_empty() && raw.len() <= MAX_ENVELOPE,
        "HISTORY_V6_ENVELOPE_LIMIT",
    )?;
    let envelope: Envelope<T> = serde_json::from_slice(raw)?;
    trnm_crypto_primitives::verify_hex_strict(
        &identity.registry_key,
        &message(kind, 1, &envelope.body)?,
        &envelope.registry_signature,
    )
    .map_err(|_| "HISTORY_V6_SIGNATURE")?;
    trnm_crypto_primitives::verify_hex_strict(
        &identity.task_key,
        &message(kind, 2, &envelope.body)?,
        &envelope.task_signature,
    )
    .map_err(|_| "HISTORY_V6_SIGNATURE")?;
    Ok(envelope.body)
}
pub(super) struct VerifiedBudget {
    pub body: Budget,
    pub envelope_sha256: String,
    _verified: (),
}
pub(super) struct VerifiedOperation {
    pub body: Operation,
    pub intent_sha256: String,
    _verified: (),
}
pub(super) struct VerifiedRecovery {
    pub body: Recovery,
    pub closed: ClosedProcess,
    pub envelope_sha256: String,
    _verified: (),
}
pub(super) fn budget(raw: &[u8], identity: &Identity, at: u64) -> Result<VerifiedBudget> {
    let body: Budget = authenticate(raw, b'B', identity)?;
    ensure(
        body.identity == *identity
            && body.schema == "restricted-history-effect-budget-v6"
            && body.sequence > 0
            && body.sequence <= 4096
            && body.lifetime_ceiling.operations <= 256
            && body.nonce_first <= body.nonce_last
            && body.work_nonce_first <= body.work_nonce_last,
        "HISTORY_V6_BUDGET",
    )?;
    id(&body.budget_id, 32)?;
    body.outside_anchor.validate()?;
    window(body.issued_ns, body.expires_ns, at)?;
    Ok(VerifiedBudget {
        body,
        envelope_sha256: digest(raw),
        _verified: (),
    })
}
pub(super) fn operation(raw: &[u8], identity: &Identity, at: u64) -> Result<VerifiedOperation> {
    let body: Operation = authenticate(raw, b'O', identity)?;
    ensure(body.identity == *identity, "HISTORY_V6_IDENTITY")?;
    body.validate(at)?;
    let intent_sha256 = digest(&message(b'I', 0, &body)?);
    Ok(VerifiedOperation {
        body,
        intent_sha256,
        _verified: (),
    })
}
pub(super) fn recovery(
    raw: &[u8],
    closed_raw: &[u8],
    identity: &Identity,
    at: u64,
) -> Result<VerifiedRecovery> {
    let body: Recovery = authenticate(raw, b'R', identity)?;
    ensure(
        body.identity == *identity
            && body.schema == "restricted-history-effect-reconciliation-v6"
            && body.request_nonce > 0,
        "HISTORY_V6_RECOVERY",
    )?;
    window(body.issued_ns, body.expires_ns, at)?;
    body.outside_anchor.validate()?;
    body.actual_frontier.validate()?;
    for value in [
        &body.pending_operation_id,
        &body.intent_sha256,
        &body.closed_process_sha256,
    ] {
        id(value, 32)?;
    }
    ensure(
        !closed_raw.is_empty() && closed_raw.len() <= MAX_ENVELOPE,
        "HISTORY_V6_CLOSED_LIMIT",
    )?;
    let closed: ClosedProcess = serde_json::from_slice(closed_raw)?;
    closed.validate()?;
    ensure(
        digest(closed_raw) == body.closed_process_sha256
            && closed.original_journal == body.outside_anchor
            && closed.intent_sha256 == body.intent_sha256
            && closed.actual_frontier == body.actual_frontier
            && closed
                .marker
                .as_ref()
                .map(|m| encoded(m).map(|raw| digest(&raw)))
                .transpose()?
                == body.marker_sha256,
        "HISTORY_V6_RECOVERY_BINDING",
    )?;
    Ok(VerifiedRecovery {
        body,
        closed,
        envelope_sha256: digest(raw),
        _verified: (),
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RecoveryInput {
    pub signed: Vec<u8>,
    pub closed_process: Vec<u8>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Configuration {
    pub schema: String,
    pub identity: Identity,
    pub journal_path: PathBuf,
    pub outside_latest_anchor: Anchor,
    pub signed_budget: Vec<u8>,
    pub signed_startup: Vec<u8>,
    pub materials: Vec<crate::operator_task_policy::MaterialInput>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RecoveryConfiguration {
    pub schema: String,
    pub identity: Identity,
    pub journal_path: PathBuf,
    pub outside_latest_anchor: Anchor,
    pub recovery: RecoveryInput,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct BudgetConfiguration {
    pub schema: String,
    pub identity: Identity,
    pub journal_path: PathBuf,
    pub outside_latest_anchor: Anchor,
    pub signed_budget: Vec<u8>,
}
pub struct ProtectedHistoryV6BudgetInput {
    pub(super) config: BudgetConfiguration,
    pub(super) expected_uid: u32,
    _file: fs::File,
}
impl ProtectedHistoryV6BudgetInput {
    pub fn load(path: &Path, expected_uid: u32, expected_sha256: &str) -> Result<Self> {
        let (raw, file) = protected_file(path, expected_uid, expected_sha256)?;
        let config: BudgetConfiguration = serde_json::from_slice(&raw)?;
        ensure(
            config.schema == "restricted-history-effect-budget-input-v6",
            "HISTORY_V6_CONFIGURATION",
        )?;
        config.identity.validate()?;
        config.outside_latest_anchor.validate()?;
        ensure(config.journal_path.is_absolute(), "HISTORY_V6_JOURNAL_PATH")?;
        Ok(Self {
            config,
            expected_uid,
            _file: file,
        })
    }
}
/// Only a bounded, ownership/permission/digest checked local file creates this
/// value. A network request cannot choose authority keys or a latest anchor.
pub struct ProtectedHistoryV6Input {
    pub(super) config: Configuration,
    pub(super) expected_uid: u32,
    _file: fs::File,
}
impl ProtectedHistoryV6Input {
    pub fn load(path: &Path, expected_uid: u32, expected_sha256: &str) -> Result<Self> {
        let (raw, file) = protected_file(path, expected_uid, expected_sha256)?;
        let config: Configuration = serde_json::from_slice(&raw)?;
        ensure(
            config.schema == "restricted-history-effect-launch-v6",
            "HISTORY_V6_CONFIGURATION",
        )?;
        config.identity.validate()?;
        config.outside_latest_anchor.validate()?;
        ensure(config.journal_path.is_absolute(), "HISTORY_V6_JOURNAL_PATH")?;
        Ok(Self {
            config,
            expected_uid,
            _file: file,
        })
    }
}
pub struct ProtectedHistoryV6RecoveryInput {
    pub(super) config: RecoveryConfiguration,
    pub(super) expected_uid: u32,
    _file: fs::File,
}
impl ProtectedHistoryV6RecoveryInput {
    pub fn load(path: &Path, expected_uid: u32, expected_sha256: &str) -> Result<Self> {
        let (raw, file) = protected_file(path, expected_uid, expected_sha256)?;
        let config: RecoveryConfiguration = serde_json::from_slice(&raw)?;
        ensure(
            config.schema == "restricted-history-effect-recovery-input-v6",
            "HISTORY_V6_CONFIGURATION",
        )?;
        config.identity.validate()?;
        config.outside_latest_anchor.validate()?;
        ensure(config.journal_path.is_absolute(), "HISTORY_V6_JOURNAL_PATH")?;
        Ok(Self {
            config,
            expected_uid,
            _file: file,
        })
    }
}
fn protected_file(
    path: &Path,
    expected_uid: u32,
    expected_sha256: &str,
) -> Result<(Vec<u8>, fs::File)> {
    id(expected_sha256, 32)?;
    ensure(path.is_absolute(), "HISTORY_V6_PROTECTED_PATH")?;
    ensure(
        rustix::process::geteuid().as_raw() == expected_uid,
        "HISTORY_V6_PROTECTED_UID",
    )?;
    let parent = fs::symlink_metadata(path.parent().ok_or("HISTORY_V6_PROTECTED_PATH")?)?;
    ensure(
        parent.is_dir()
            && !parent.file_type().is_symlink()
            && parent.uid() == expected_uid
            && parent.mode() & 0o077 == 0,
        "HISTORY_V6_PROTECTED_PARENT",
    )?;
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let metadata = file.metadata()?;
    ensure(
        metadata.is_file()
            && metadata.uid() == expected_uid
            && metadata.mode() & 0o077 == 0
            && metadata.nlink() == 1
            && metadata.len() > 0
            && metadata.len() <= MAX_PROTECTED_INPUT,
        "HISTORY_V6_PROTECTED_FILE",
    )?;
    let mut raw = Vec::new();
    std::io::Read::by_ref(&mut file)
        .take(MAX_PROTECTED_INPUT + 1)
        .read_to_end(&mut raw)?;
    ensure(
        raw.len() as u64 == metadata.len() && digest(&raw) == expected_sha256,
        "HISTORY_V6_PROTECTED_DIGEST",
    )?;
    Ok((raw, file))
}
