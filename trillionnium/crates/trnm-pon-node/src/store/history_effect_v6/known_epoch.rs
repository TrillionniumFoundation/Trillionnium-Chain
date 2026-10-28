//! A separately authorized retirement of an interrupted, fully settled epoch.
//! This is neither CleanClose nor an unknown-scope CPU reconciliation. The
//! original per-scope receipts, reservations and epoch/operation nonces survive.
use super::*;
use policy::{Anchor, Identity, Operation, Usage};
use serde::{Deserialize, Serialize};

const DOMAIN: &[u8] = b"TRNM-HISTORY-KNOWN-EPOCH-RETIREMENT-V1";
pub(super) const RECORD_SCHEMA: &str = "restricted-history-known-epoch-retirement-record-v1";
pub(super) const FIXTURE_SELECTOR: &str =
    "store::history_effect_v6::tests::history_known_epoch_process_child_helper";

/// Derived exclusively by full replay of the original individually checked
/// scopes. NotStarted contributes no receipt or allowance to the CPU sums.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct KnownEpoch {
    pub schema: String,
    pub epoch: String,
    pub startup_operation_id: String,
    pub startup_intent_sha256: String,
    pub startup_envelope_sha256: String,
    pub before_startup: Anchor,
    pub startup_at_ns: u64,
    pub known_operations: u64,
    pub not_started_operations: u64,
    pub known_cpu_ns: u64,
    pub known_allowance_cpu_ns: u64,
    pub terminal_transcript_sha256: String,
    pub frontier: Frontier,
}
impl KnownEpoch {
    pub fn start(op: &Operation, signed: &[u8], intent: &str, at: u64) -> Result<Self> {
        Ok(Self {
            schema: "restricted-history-known-epoch-snapshot-v1".into(),
            epoch: op.epoch.clone(),
            startup_operation_id: op.operation_id.clone(),
            startup_intent_sha256: intent.into(),
            startup_envelope_sha256: policy::digest(signed),
            before_startup: op.outside_spent_anchor.clone(),
            startup_at_ns: at,
            known_operations: 0,
            not_started_operations: 0,
            known_cpu_ns: 0,
            known_allowance_cpu_ns: 0,
            terminal_transcript_sha256: policy::digest(&policy::encoded(&(
                "restricted-history-known-epoch-start-v1",
                op,
                intent,
                at,
            ))?),
            frontier: op.owner_frontier.clone(),
        })
    }
    pub fn terminal(&mut self, pending: &journal::Pending, event: &journal::Event) -> Result<()> {
        ensure(
            self.epoch == pending.operation.epoch,
            "HISTORY_RETIRE_EPOCH",
        )?;
        match event {
            journal::Event::Settlement { cpu, marker, .. } => {
                ensure(cpu.known(), "HISTORY_RETIRE_UNKNOWN_SCOPE")?;
                let actual = cpu.total_cpu_ns.ok_or("HISTORY_RETIRE_UNKNOWN_SCOPE")?;
                ensure(
                    actual <= pending.operation.allowance.cpu_ns,
                    "HISTORY_RETIRE_SCOPE_CEILING",
                )?;
                self.known_operations += 1;
                self.known_cpu_ns = self
                    .known_cpu_ns
                    .checked_add(actual)
                    .ok_or("HISTORY_RETIRE_CPU_SUM")?;
                self.known_allowance_cpu_ns = self
                    .known_allowance_cpu_ns
                    .checked_add(pending.operation.allowance.cpu_ns)
                    .ok_or("HISTORY_RETIRE_CPU_SUM")?;
                // A known refusal can carry an incorrect requested frontier;
                // only a durable effect marker can change the derived actual
                // frontier. A failed/no-effect scope must not rewind it.
                if let Some(marker) = marker {
                    self.frontier = marker.after.clone();
                }
            }
            journal::Event::NotStarted { .. } => self.not_started_operations += 1,
            _ => return Err("HISTORY_RETIRE_TERMINAL_KIND".into()),
        }
        self.terminal_transcript_sha256 = policy::digest(&policy::encoded(&(
            "restricted-history-known-epoch-terminal-v1",
            &self.terminal_transcript_sha256,
            &pending.operation,
            &pending.intent_sha256,
            event,
        ))?);
        Ok(())
    }
    pub fn digest(&self) -> Result<String> {
        Ok(policy::digest(&policy::encoded(self)?))
    }
}

/// This schema is deliberately distinct from a V6 pending-intent receipt. Its
/// only admitted process contract is the pinned, one-startup native helper.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct ClosedProcess {
    pub schema: String,
    pub epoch: String,
    pub source_commit: String,
    pub executable_sha256: String,
    pub fixture_source_sha256: String,
    pub guardian_source_sha256: String,
    pub launch_configuration_sha256: String,
    pub signed_startup: Vec<u8>,
    pub original_journal: Anchor,
    pub known_epoch_sha256: String,
    pub process_spawn_before_ns: u64,
    pub process_reaped_after_ns: u64,
    pub observed_epoch_start_count: u64,
    pub observed_epoch_terminal_count: u64,
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
    pub actual_frontier: Frontier,
    pub physical_cost_qualified: bool,
}
impl ClosedProcess {
    fn validate(&self, body: &Authorization) -> Result<()> {
        self.original_journal.validate()?;
        self.actual_frontier.validate()?;
        for id in [
            &self.epoch,
            &self.executable_sha256,
            &self.fixture_source_sha256,
            &self.guardian_source_sha256,
            &self.launch_configuration_sha256,
            &self.known_epoch_sha256,
        ] {
            policy::id(id, 32)?;
        }
        policy::id(&self.source_commit, 20)?;
        let epoch = &body.known_epoch;
        let startup = policy::operation(&self.signed_startup, &body.identity, epoch.startup_at_ns)?;
        ensure(
            startup.body.purpose == Purpose::Startup
                && startup.body.epoch == epoch.epoch
                && startup.body.operation_id == epoch.startup_operation_id
                && startup.intent_sha256 == epoch.startup_intent_sha256
                && startup.body.outside_spent_anchor == epoch.before_startup
                && policy::digest(&self.signed_startup) == epoch.startup_envelope_sha256,
            "HISTORY_RETIRE_STARTUP_BINDING",
        )?;
        let upper = self
            .user_cpu_microseconds
            .checked_add(self.system_cpu_microseconds)
            .and_then(|v| v.checked_add(2))
            .and_then(|v| v.checked_mul(1000))
            .ok_or("HISTORY_RETIRE_CPU_BOUND")?;
        ensure(
            self.schema == "actual-history-known-epoch-closed-process-v1"
                && self.source_commit == body.identity.source_commit
                && self.epoch == epoch.epoch
                && self.executable_sha256 == body.executable_sha256
                && self.fixture_source_sha256 == body.fixture_source_sha256
                && self.guardian_source_sha256 == body.guardian_source_sha256
                && self.original_journal == body.outside_anchor
                && self.known_epoch_sha256 == epoch.digest()?
                && self.process_spawn_before_ns > 0
                && self.process_spawn_before_ns <= epoch.startup_at_ns
                && epoch.startup_at_ns < self.process_reaped_after_ns
                && self.process_reaped_after_ns <= body.issued_ns
                && self.process_reaped_after_ns - self.process_spawn_before_ns <= 90_000_000_000
                && self.observed_epoch_start_count == 1
                && self.observed_epoch_terminal_count == 0
                && self.owned_namespace_pid > 0
                && self.observed_visible_pid > 0
                && self.observed_starttime_ticks > 0
                && self.pidfd_identity_verified
                && self.actual_wait4
                && self.signal == 9
                && self.all_descendants_closed
                && self.descendants.is_empty()
                && self.descendant_accounting_profile
                    == "source-bound-single-epoch-native-thread-only-fixture-v1"
                && self.fixture_selector == FIXTURE_SELECTOR
                && !self.historical_process_tree_observed
                && self.cpu_counter_profile == "linux-wait4-timeval-quantized-v1"
                && self.reported_cpu_upper_bound_ns == upper
                && self.actual_frontier == body.actual_frontier
                && self.actual_frontier == epoch.frontier
                && !self.physical_cost_qualified,
            "HISTORY_RETIRE_CLOSED_PROCESS_REQUIRED",
        )?;
        for (reported, units) in [
            (&self.reported_user_seconds, self.user_cpu_microseconds),
            (&self.reported_system_seconds, self.system_cpu_microseconds),
        ] {
            ensure(reported.len() <= 64, "HISTORY_RETIRE_CPU_COUNTER")?;
            let value = reported
                .parse::<f64>()
                .map_err(|_| "HISTORY_RETIRE_CPU_COUNTER")?;
            ensure(
                value.is_finite()
                    && (0.0..=86_400.0).contains(&value)
                    && (value * 1_000_000.0 - units as f64).abs() <= 0.001,
                "HISTORY_RETIRE_CPU_COUNTER",
            )?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Authorization {
    pub schema: String,
    pub identity: Identity,
    pub request_nonce: u64,
    pub outside_anchor: Anchor,
    pub known_epoch: KnownEpoch,
    pub original_spent: Usage,
    pub original_used_operations: u64,
    pub executable_sha256: String,
    pub fixture_source_sha256: String,
    pub guardian_source_sha256: String,
    pub closed_process_sha256: String,
    pub actual_frontier: Frontier,
    pub issued_ns: u64,
    pub expires_ns: u64,
}
pub(super) struct Verified {
    pub body: Authorization,
    pub closed: ClosedProcess,
    pub envelope_sha256: String,
    _verified: (),
}
pub(super) fn message(role: u8, body: &Authorization) -> Result<Vec<u8>> {
    let raw = policy::encoded(body)?;
    ensure(raw.len() <= policy::MAX_ENVELOPE, "HISTORY_RETIRE_ENVELOPE")?;
    let mut result = DOMAIN.to_vec();
    result.extend([b'E', role]);
    result.extend((raw.len() as u32).to_le_bytes());
    result.extend(raw);
    Ok(result)
}
pub(super) fn verify(
    signed: &[u8],
    closed_raw: &[u8],
    identity: &Identity,
    at: u64,
) -> Result<Verified> {
    identity.validate()?;
    ensure(
        !signed.is_empty()
            && signed.len() <= policy::MAX_ENVELOPE
            && !closed_raw.is_empty()
            && closed_raw.len() <= policy::MAX_ENVELOPE,
        "HISTORY_RETIRE_ENVELOPE",
    )?;
    let envelope: policy::Envelope<Authorization> = serde_json::from_slice(signed)?;
    for (role, key, signature) in [
        (1, &identity.registry_key, &envelope.registry_signature),
        (2, &identity.task_key, &envelope.task_signature),
    ] {
        trnm_crypto_primitives::verify_hex_strict(key, &message(role, &envelope.body)?, signature)
            .map_err(|_| "HISTORY_RETIRE_SIGNATURE")?;
    }
    let body = envelope.body;
    ensure(
        body.schema == "restricted-history-known-epoch-retirement-authorization-v1"
            && body.identity == *identity
            && body.request_nonce > 0
            && body.issued_ns <= at
            && at < body.expires_ns
            && body.expires_ns - body.issued_ns <= 86_400_000_000_000,
        "HISTORY_RETIRE_AUTHORIZATION",
    )?;
    body.outside_anchor.validate()?;
    body.actual_frontier.validate()?;
    policy::id(&body.closed_process_sha256, 32)?;
    policy::id(&body.executable_sha256, 32)?;
    policy::id(&body.fixture_source_sha256, 32)?;
    policy::id(&body.guardian_source_sha256, 32)?;
    ensure(
        policy::digest(closed_raw) == body.closed_process_sha256,
        "HISTORY_RETIRE_CLOSED_DIGEST",
    )?;
    let closed: ClosedProcess = serde_json::from_slice(closed_raw)?;
    closed.validate(&body)?;
    Ok(Verified {
        body,
        closed,
        envelope_sha256: policy::digest(signed),
        _verified: (),
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Configuration {
    schema: String,
    identity: Identity,
    journal_path: PathBuf,
    outside_latest_anchor: Anchor,
    expected_executable_sha256: String,
    expected_fixture_source_sha256: String,
    expected_guardian_source_sha256: String,
    signed_retirement: Vec<u8>,
    closed_process: Vec<u8>,
}
pub struct ProtectedHistoryKnownEpochRetirementV1Input {
    config: Configuration,
    expected_uid: u32,
    _file: File,
}
impl ProtectedHistoryKnownEpochRetirementV1Input {
    pub fn load(path: &Path, expected_uid: u32, expected_sha256: &str) -> Result<Self> {
        let (raw, file) = policy::protected_file(path, expected_uid, expected_sha256)?;
        let config: Configuration = serde_json::from_slice(&raw)?;
        ensure(
            config.schema == "restricted-history-known-epoch-retirement-input-v1",
            "HISTORY_RETIRE_CONFIGURATION",
        )?;
        config.identity.validate()?;
        config.outside_latest_anchor.validate()?;
        policy::id(&config.expected_executable_sha256, 32)?;
        policy::id(&config.expected_fixture_source_sha256, 32)?;
        policy::id(&config.expected_guardian_source_sha256, 32)?;
        ensure(config.journal_path.is_absolute(), "HISTORY_V6_JOURNAL_PATH")?;
        Ok(Self {
            config,
            expected_uid,
            _file: file,
        })
    }
}

/// Admit one explicit administrative record after an externally observed process
/// death. The read-only Native checks confer no execution or reorg capability.
/// A later Startup still needs its own fresh epoch, signature and outside anchor.
pub fn retire_history_known_epoch_v1(
    path: &Path,
    input: ProtectedHistoryKnownEpochRetirementV1Input,
) -> Result<Value> {
    ensure(path.is_absolute(), "HISTORY_V6_NATIVE_PATH")?;
    let config = input.config;
    let verified = verify(
        &config.signed_retirement,
        &config.closed_process,
        &config.identity,
        policy::now()?,
    )?;
    ensure(
        verified.body.outside_anchor == config.outside_latest_anchor
            && verified.body.executable_sha256 == config.expected_executable_sha256
            && verified.body.fixture_source_sha256 == config.expected_fixture_source_sha256
            && verified.body.guardian_source_sha256 == config.expected_guardian_source_sha256,
        "HISTORY_RETIRE_OUTSIDE_BINDING",
    )?;
    let mut journal = journal::Journal::open(
        &config.journal_path,
        input.expected_uid,
        &config.identity,
        &config.outside_latest_anchor,
    )?;
    journal.check_retirement(&verified)?;
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let dm = directory.metadata()?;
    ensure(
        dm.is_dir() && dm.uid() == input.expected_uid && dm.mode() & 0o077 == 0,
        "HISTORY_V6_NATIVE_DIRECTORY",
    )?;
    let owner = recovery::private_file(&path.join("owner.lock"), input.expected_uid)?;
    owner.try_lock_exclusive()?;
    let native = recovery::private_file(&path.join("native.sqlite"), input.expected_uid)?;
    let before = native.metadata()?;
    ensure(
        !path.join("initializing.json").exists(),
        "HISTORY_V6_INITIALIZATION_UNKNOWN",
    )?;
    for name in ["native.sqlite-wal", "native.sqlite-shm"] {
        plain(&path.join(name))?;
    }
    let expected_marker = storage::owner_marker(&config.identity, &config.journal_path)?;
    let marker_file =
        recovery::private_file(&path.join("owner-task-policy.required"), input.expected_uid)?;
    ensure(
        marker_file.metadata()?.len() <= 65536,
        "HISTORY_V6_NATIVE_MARKER",
    )?;
    let mut marker_raw = Vec::new();
    marker_file.take(65537).read_to_end(&mut marker_raw)?;
    ensure(marker_raw == expected_marker, "HISTORY_V6_NATIVE_MARKER")?;
    let db = Connection::open_with_flags(
        path.join("native.sqlite"),
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    db.execute_batch("PRAGMA trusted_schema=OFF; PRAGMA query_only=ON; BEGIN;")?;
    let reference = Connection::open_in_memory()?;
    reference.execute_batch(&StateBackend::HistoryEffectV6.ddl())?;
    ensure(
        schema(&db)? == schema(&reference)?,
        "HISTORY_V6_NATIVE_SCHEMA",
    )?;
    for (key, value) in [
        ("schema", StateBackend::HistoryEffectV6.schema_id().to_vec()),
        (
            "parameters",
            hex::decode(&config.identity.parameters).map_err(|_| "HISTORY_V6_ID")?,
        ),
        (
            "genesis",
            hex::decode(&config.identity.genesis).map_err(|_| "HISTORY_V6_ID")?,
        ),
        ("operator_task_policy", expected_marker),
    ] {
        let actual: Vec<u8> =
            db.query_row("SELECT value FROM metadata WHERE key=?", [key], |r| {
                r.get(0)
            })?;
        ensure(actual == value, "HISTORY_V6_NATIVE_CONTEXT")?;
    }
    storage::no_pending_reorg(&db)?;
    let frontier = storage::frontier(&db)?;
    ensure(
        frontier == verified.body.actual_frontier,
        "HISTORY_RETIRE_NATIVE_FRONTIER",
    )?;
    storage::verify_known_markers(&db, &journal, None)?;
    let after = fs::symlink_metadata(path.join("native.sqlite"))?;
    let visible_directory = fs::symlink_metadata(path)?;
    ensure(
        before.dev() == after.dev()
            && before.ino() == after.ino()
            && dm.dev() == visible_directory.dev()
            && dm.ino() == visible_directory.ino(),
        "HISTORY_V6_NATIVE_CHANGED",
    )?;
    journal.ready()?;
    let before_journal = journal.observation();
    journal.retire(&config.signed_retirement, &config.closed_process)?;
    Ok(serde_json::json!({
        "schema":"restricted-history-known-epoch-retirement-result-v1",
        "signed_retirement_sha256":verified.envelope_sha256,
        "before":before_journal,"journal":journal.observation(),
        "original_known_epoch":verified.body.known_epoch,"closed_process":verified.closed,
        "actual_frontier":frontier,"original_per_scope_receipts_preserved":true,
        "spent_reservations_preserved":true,"new_cpu_receipt_created":false,
        "clean_close_created":false,"native_effect_repeated":false,"new_cpu_epoch_created":false,
        "physical_cost_qualified":false,"production_qualified":false
    }))
}
