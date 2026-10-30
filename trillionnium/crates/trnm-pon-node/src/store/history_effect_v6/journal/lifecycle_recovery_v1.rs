//! Close a source-bound dead Startup or Close without rewriting its receipt.
//! Native initialization stays in the ordinary paid Startup transaction. This
//! administrative record neither deletes a database nor grants work authority.
use super::*;
use policy::Envelope;

const DOMAIN: &[u8] = b"TRNM-HISTORY-LIFECYCLE-RECOVERY-V1";
pub(in crate::store::history_effect_v6) const RECORD_SCHEMA: &str =
    "restricted-history-lifecycle-record-v1";

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(in crate::store::history_effect_v6) enum Closure {
    PendingStartup,
    PendingClose,
    SettledStartup,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(in crate::store::history_effect_v6) enum Database {
    Absent,
    Empty,
    Genesis,
    Ready,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(in crate::store::history_effect_v6) struct Snapshot {
    pub declared_frontier: Frontier,
    pub actual_frontier: Option<Frontier>,
    pub initializing_sha256: Option<String>,
    pub database: Database,
}

impl Snapshot {
    fn validate(&self) -> Result<()> {
        self.declared_frontier.validate()?;
        if let Some(actual) = &self.actual_frontier {
            actual.validate()?;
        }
        if let Some(digest) = &self.initializing_sha256 {
            policy::id(digest, 32)?;
        }
        ensure(
            match self.database {
                Database::Absent => self.actual_frontier.is_none(),
                Database::Empty => {
                    self.actual_frontier.is_none() && self.initializing_sha256.is_some()
                }
                Database::Genesis => {
                    self.actual_frontier.is_some() && self.initializing_sha256.is_some()
                }
                Database::Ready => {
                    self.actual_frontier.is_some() && self.initializing_sha256.is_none()
                }
            },
            "HISTORY_LIFECYCLE_V1_SNAPSHOT",
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(in crate::store::history_effect_v6) struct NoNativeProof {
    pub schema: String,
    pub pins: startup_no_native_v1::Pins,
    pub namespace_parent: PathBuf,
    pub journal_path: PathBuf,
    pub expected_uid: u32,
    pub birth: startup_no_native_v1::NamespaceSnapshot,
    pub before: startup_no_native_v1::NamespaceSnapshot,
    pub after: startup_no_native_v1::NamespaceSnapshot,
    pub namespace_created_exclusively: bool,
    pub namespace_prepared_ns: u64,
    pub lease_acquired_ns: u64,
    pub lease_held_from_process_spawn_through_reap: bool,
    pub signed_startup: Vec<u8>,
    pub startup_intent_at_ns: u64,
    pub child_configuration_sha256: String,
    pub startup_configuration_sha256: String,
    pub process_spawn_before_ns: u64,
    pub process_reaped_after_ns: u64,
}

impl NoNativeProof {
    fn validate(&self, body: &Authorization, closed: &ClosedProcess) -> Result<()> {
        self.pins.validate()?;
        self.birth.validate(self.expected_uid)?;
        self.before.validate(self.expected_uid)?;
        self.after.validate(self.expected_uid)?;
        policy::id(&self.child_configuration_sha256, 32)?;
        policy::id(&self.startup_configuration_sha256, 32)?;
        let startup = policy::operation(
            &self.signed_startup,
            &body.identity,
            self.startup_intent_at_ns,
        )?;
        ensure(
            self.schema == "actual-history-lifecycle-no-native-proof-v1"
                && body.closure != Closure::PendingClose
                && body.snapshot.database == Database::Absent
                && body.snapshot.actual_frontier.is_none()
                && body.snapshot.initializing_sha256.is_none()
                && self.pins.source_commit == body.identity.source_commit
                && self.pins.executable_sha256 == closed.executable_sha256
                && self.namespace_parent.is_absolute()
                && self.journal_path.is_absolute()
                && !self.journal_path.starts_with(&self.namespace_parent)
                && self.birth == self.before
                && self.before == self.after
                && self.namespace_created_exclusively
                && self.lease_held_from_process_spawn_through_reap
                && self.namespace_prepared_ns > 0
                && self.lease_acquired_ns > 0
                && self.lease_acquired_ns <= self.process_spawn_before_ns
                && self.namespace_prepared_ns <= startup.body.issued_ns
                && startup.body.issued_ns <= self.process_spawn_before_ns
                && self.process_spawn_before_ns <= self.startup_intent_at_ns
                && self.startup_intent_at_ns < self.process_reaped_after_ns
                && self.process_reaped_after_ns <= body.issued_ns
                && self.process_reaped_after_ns - self.process_spawn_before_ns <= 90_000_000_000
                && startup.body.purpose == Purpose::Startup
                && startup.body.operation_id == body.operation_id
                && startup.body.epoch == body.epoch
                && startup.body.owner_frontier == body.snapshot.declared_frontier
                && startup.intent_sha256 == body.intent_sha256,
            "HISTORY_LIFECYCLE_V1_NO_NATIVE_BINDING",
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(in crate::store::history_effect_v6) struct ClosedProcess {
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
    pub declared_frontier: Frontier,
    pub actual_frontier: Option<Frontier>,
    pub database: Database,
    pub initializing_sha256: Option<String>,
    pub no_native: Option<NoNativeProof>,
    pub physical_cost_qualified: bool,
}
impl ClosedProcess {
    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            declared_frontier: self.declared_frontier.clone(),
            actual_frontier: self.actual_frontier.clone(),
            database: self.database,
            initializing_sha256: self.initializing_sha256.clone(),
        }
    }
    pub fn validate(&self) -> Result<()> {
        self.original_journal.validate()?;
        self.snapshot().validate()?;
        policy::id(&self.epoch, 32)?;
        policy::id(&self.executable_sha256, 32)?;
        policy::id(&self.intent_sha256, 32)?;
        let upper = self
            .user_cpu_microseconds
            .checked_add(self.system_cpu_microseconds)
            .and_then(|v| v.checked_add(2))
            .and_then(|v| v.checked_mul(1000))
            .ok_or("HISTORY_V6_CPU_BOUND")?;
        ensure(
            self.schema == "actual-history-lifecycle-closed-process-v1"
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
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::store::history_effect_v6) struct Authorization {
    pub schema: String,
    pub identity: Identity,
    pub executable_sha256: String,
    pub budget_id: String,
    pub renewal_budget: Option<Vec<u8>>,
    pub reconciliation_id: String,
    pub request_nonce: u64,
    pub epoch: String,
    pub outside_anchor: Anchor,
    pub operation_id: String,
    pub intent_sha256: String,
    pub closed_process_sha256: String,
    pub closure: Closure,
    pub snapshot: Snapshot,
    pub allowance: Usage,
    pub issued_ns: u64,
    pub expires_ns: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Configuration {
    schema: String,
    identity: Identity,
    expected_source_commit: String,
    expected_executable_sha256: String,
    expected_no_native_pins: Option<startup_no_native_v1::Pins>,
    expected_namespace_parent: Option<PathBuf>,
    journal_path: PathBuf,
    outside_latest_anchor: Anchor,
    signed: Vec<u8>,
    closed_process: Vec<u8>,
}

pub struct ProtectedHistoryLifecycleV1Input {
    config: Configuration,
    expected_uid: u32,
    _file: File,
}
impl ProtectedHistoryLifecycleV1Input {
    pub fn load(path: &Path, expected_uid: u32, expected_sha256: &str) -> Result<Self> {
        let (raw, file) = policy::protected_file(path, expected_uid, expected_sha256)?;
        let config: Configuration = serde_json::from_slice(&raw)?;
        ensure(
            config.schema == "restricted-history-lifecycle-input-v1",
            "HISTORY_LIFECYCLE_V1_CONFIGURATION",
        )?;
        config.identity.validate()?;
        policy::id(&config.expected_source_commit, 20)?;
        policy::id(&config.expected_executable_sha256, 32)?;
        ensure(
            config.expected_source_commit == config.identity.source_commit,
            "HISTORY_LIFECYCLE_V1_SOURCE_PIN",
        )?;
        match (
            &config.expected_no_native_pins,
            &config.expected_namespace_parent,
        ) {
            (Some(pins), Some(parent)) => {
                pins.validate()?;
                ensure(
                    pins.source_commit == config.expected_source_commit
                        && pins.executable_sha256 == config.expected_executable_sha256
                        && parent.is_absolute()
                        && !config.journal_path.starts_with(parent),
                    "HISTORY_LIFECYCLE_V1_NO_NATIVE_PINS",
                )?;
            }
            (None, None) => {}
            _ => return Err("HISTORY_LIFECYCLE_V1_NO_NATIVE_PINS".into()),
        }
        config.outside_latest_anchor.validate()?;
        ensure(config.journal_path.is_absolute(), "HISTORY_V6_JOURNAL_PATH")?;
        Ok(Self {
            config,
            expected_uid,
            _file: file,
        })
    }
}

pub(in crate::store::history_effect_v6) struct Verified {
    body: Authorization,
    closed: ClosedProcess,
}

pub(in crate::store::history_effect_v6) fn message(
    role: u8,
    body: &Authorization,
) -> Result<Vec<u8>> {
    let raw = policy::encoded(body)?;
    ensure(
        raw.len() <= policy::MAX_ENVELOPE,
        "HISTORY_LIFECYCLE_V1_ENVELOPE",
    )?;
    let mut bytes = DOMAIN.to_vec();
    bytes.extend([b'L', role]);
    bytes.extend((raw.len() as u32).to_le_bytes());
    bytes.extend(raw);
    Ok(bytes)
}

fn authenticate(
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
        "HISTORY_LIFECYCLE_V1_ENVELOPE",
    )?;
    let envelope: Envelope<Authorization> = serde_json::from_slice(signed)?;
    for (role, key, signature) in [
        (1, &identity.registry_key, &envelope.registry_signature),
        (2, &identity.task_key, &envelope.task_signature),
    ] {
        trnm_crypto_primitives::verify_hex_strict(key, &message(role, &envelope.body)?, signature)
            .map_err(|_| "HISTORY_LIFECYCLE_V1_SIGNATURE")?;
    }
    let body = envelope.body;
    ensure(
        body.schema == "restricted-history-lifecycle-authorization-v1"
            && body.identity == *identity
            && body.request_nonce > 0
            && body.allowance.operations == 1
            && (1..=60_000_000_000).contains(&body.allowance.cpu_ns)
            && body.allowance.material_bytes == 0
            && body.allowance.received_bytes == 0
            && body.issued_ns <= at
            && at < body.expires_ns
            && body.expires_ns - body.issued_ns <= 86_400_000_000_000,
        "HISTORY_LIFECYCLE_V1_AUTHORIZATION",
    )?;
    for value in [
        &body.budget_id,
        &body.executable_sha256,
        &body.reconciliation_id,
        &body.epoch,
        &body.operation_id,
        &body.intent_sha256,
        &body.closed_process_sha256,
    ] {
        policy::id(value, 32)?;
    }
    body.outside_anchor.validate()?;
    body.snapshot.validate()?;
    ensure(
        body.closure != Closure::PendingClose || body.snapshot.database == Database::Ready,
        "HISTORY_LIFECYCLE_V1_SNAPSHOT",
    )?;
    let closed: ClosedProcess = serde_json::from_slice(closed_raw)?;
    closed.validate()?;
    ensure(
        policy::digest(closed_raw) == body.closed_process_sha256
            && closed.executable_sha256 == body.executable_sha256
            && closed.epoch == body.epoch
            && closed.original_journal == body.outside_anchor
            && closed.intent_sha256 == body.intent_sha256
            && closed.snapshot() == body.snapshot
            && closed.marker.is_none()
            && closed.reported_cpu_upper_bound_ns <= body.allowance.cpu_ns,
        "HISTORY_LIFECYCLE_V1_CLOSED_BINDING",
    )?;
    if let Some(proof) = &closed.no_native {
        proof.validate(&body, &closed)?;
    }
    Ok(Verified { body, closed })
}

impl State {
    fn check_lifecycle(&self, verified: &Verified, at: u64) -> Result<()> {
        let body = &verified.body;
        ensure(
            self.reorg_continuation.is_none() && self.reorg_not_started.is_none(),
            "HISTORY_LIFECYCLE_V1_REORG_REQUIRES_CONTINUATION",
        )?;
        let (operation, intent, envelope, intent_at) = match body.closure {
            Closure::PendingStartup | Closure::PendingClose => {
                let pending = self
                    .pending
                    .as_ref()
                    .ok_or("HISTORY_LIFECYCLE_V1_PENDING_REQUIRED")?;
                ensure(
                    pending.operation.purpose
                        == if body.closure == Closure::PendingStartup {
                            Purpose::Startup
                        } else {
                            Purpose::Close
                        }
                        && verified.closed.reported_cpu_upper_bound_ns
                            <= pending.operation.allowance.cpu_ns,
                    "HISTORY_LIFECYCLE_V1_ORIGINAL_ALLOWANCE",
                )?;
                (
                    &pending.operation,
                    &pending.intent_sha256,
                    &pending.envelope_sha256,
                    pending.intent_at_ns,
                )
            }
            Closure::SettledStartup => {
                ensure(self.pending.is_none(), "HISTORY_LIFECYCLE_V1_PENDING_DEBT")?;
                let last = self
                    .last_settled
                    .as_ref()
                    .ok_or("HISTORY_LIFECYCLE_V1_KNOWN_REQUIRED")?;
                // This exact receipt covers the original operation scope.
                // The whole-process wait4 upper bound also includes startup
                // and post-settlement work; authenticate bounds it by the
                // fresh management allowance, which apply debits in full.
                // Unknown debt above has no exact receipt and therefore uses
                // the whole-process bound against its original allowance.
                ensure(
                    last.operation.purpose == Purpose::Startup
                        && last.marker.is_none()
                        && last.native_id.is_none()
                        && last.native_error.as_ref().is_some_and(|s| !s.is_empty())
                        && last.cpu.known()
                        && last.cpu.total_cpu_ns.is_some_and(|cpu| {
                            cpu <= last.operation.allowance.cpu_ns
                                && cpu <= verified.closed.reported_cpu_upper_bound_ns
                        }),
                    "HISTORY_LIFECYCLE_V1_FAILED_STARTUP_REQUIRED",
                )?;
                (
                    &last.operation,
                    &last.intent_sha256,
                    &last.envelope_sha256,
                    last.intent_at_ns,
                )
            }
        };
        ensure(
            body.outside_anchor == self.anchor
                && body.operation_id == operation.operation_id
                && &body.intent_sha256 == intent
                && body.epoch == operation.epoch
                && self.epoch.as_ref() == Some(&body.epoch)
                && operation.owner_frontier == body.snapshot.declared_frontier,
            "HISTORY_LIFECYCLE_V1_ORIGINAL_BINDING",
        )?;
        if let Some(proof) = &verified.closed.no_native {
            ensure(
                &policy::digest(&proof.signed_startup) == envelope
                    && proof.startup_intent_at_ns == intent_at,
                "HISTORY_LIFECYCLE_V1_NO_NATIVE_ORIGINAL_INTENT",
            )?;
        }
        // A refused requested frontier is still the declared original intent.
        // Close cannot change the actual epoch frontier. Startup records its
        // requested frontier before reading Native and can legitimately fail
        // that comparison; its closure must not pretend the request was SQL.
        let expected_epoch_frontier = if operation.purpose == Purpose::Close {
            body.snapshot.actual_frontier.as_ref()
        } else {
            Some(&body.snapshot.declared_frontier)
        };
        ensure(
            self.epoch_frontier.as_ref() == expected_epoch_frontier,
            "HISTORY_LIFECYCLE_V1_EPOCH_FRONTIER",
        )?;
        if body.snapshot.database != Database::Ready {
            ensure(
                operation.purpose == Purpose::Startup && self.markers.is_empty(),
                "HISTORY_LIFECYCLE_V1_INITIAL_FRONTIER",
            )?;
            if let Some(actual) = &body.snapshot.actual_frontier {
                ensure(
                    actual.block == body.identity.genesis && actual.generation == 0,
                    "HISTORY_LIFECYCLE_V1_INITIAL_FRONTIER",
                )?;
            }
        }
        let (budget, _) =
            self.select_management_budget(body.renewal_budget.as_deref(), &body.identity, at)?;
        // Like settled-epoch recovery, NEW administrative authorization may
        // close expired work. It grants no old work rights; a subsequent paid
        // Startup still needs a current budget and fresh signed operation.
        ensure(
            body.budget_id == budget.budget_id
                && budget.issued_ns <= at
                && body.request_nonce > self.nonces
                && (budget.nonce_first..=budget.nonce_last).contains(&body.request_nonce)
                && !self.used.contains(&body.reconciliation_id)
                && self
                    .spent
                    .add(body.allowance)?
                    .fits(budget.lifetime_ceiling),
            "HISTORY_LIFECYCLE_V1_FRESH_ALLOWANCE",
        )
    }
    pub(super) fn apply_lifecycle(
        &mut self,
        signed: &[u8],
        closed_process: &[u8],
        identity: &Identity,
        at: u64,
    ) -> Result<()> {
        let verified = authenticate(signed, closed_process, identity, at)?;
        self.check_lifecycle(&verified, at)?;
        let (budget, budget_envelope) = self.select_management_budget(
            verified.body.renewal_budget.as_deref(),
            &verified.body.identity,
            at,
        )?;
        // Both signatures, the unchanged old debt, actual Native prefix and
        // any explicit replacement budget are checked before one append.
        // This atomic management event does not relax the ordinary Budget
        // pending-debt refusal and cannot use a renewal to forgive old overrun.
        self.budget_ids.insert(budget.budget_id.clone());
        self.budget = Some(budget);
        self.budget_envelope = Some(budget_envelope);
        self.spent = self.spent.add(verified.body.allowance)?;
        self.nonces = verified.body.request_nonce;
        self.used.insert(verified.body.reconciliation_id);
        if verified.body.closure == Closure::SettledStartup {
            self.reconciled_settled_epochs += 1;
        } else {
            self.reconciled_unknown += 1;
        }
        self.pending = None;
        self.epoch = None;
        self.epoch_frontier = None;
        self.last_settled = None;
        Ok(())
    }
}

fn optional_file(path: &Path, uid: u32) -> Result<Option<File>> {
    match fs::symlink_metadata(path) {
        Ok(_) => recovery::private_file(path, uid).map(Some),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}
fn read_small(file: &mut File) -> Result<Vec<u8>> {
    ensure(
        file.metadata()?.len() <= 65536,
        "HISTORY_LIFECYCLE_V1_FILE_LIMIT",
    )?;
    file.seek(SeekFrom::Start(0))?;
    let mut raw = Vec::new();
    std::io::Read::by_ref(file)
        .take(65537)
        .read_to_end(&mut raw)?;
    ensure(raw.len() <= 65536, "HISTORY_LIFECYCLE_V1_FILE_LIMIT")?;
    Ok(raw)
}
fn require_visible(file: &File, path: &Path, uid: u32) -> Result<()> {
    let held = file.metadata()?;
    let named = fs::symlink_metadata(path)?;
    ensure(
        held.is_file()
            && held.uid() == uid
            && held.mode() & 0o077 == 0
            && held.nlink() == 1
            && named.nlink() == 1
            && !named.file_type().is_symlink()
            && held.dev() == named.dev()
            && held.ino() == named.ino()
            && held.mode() == named.mode()
            && held.len() == named.len(),
        "HISTORY_LIFECYCLE_V1_FILE_CHANGED",
    )
}
struct HeldNative {
    _db: Option<Connection>,
    _files: Vec<(PathBuf, File)>,
    _directory: File,
}

fn bounded_frontier(db: &Connection) -> Result<Frontier> {
    let (tip, root, generation): (Vec<u8>, Vec<u8>, u64) = db.query_row(
        "SELECT substr(a.tip,1,33),substr(b.state_root,1,33),a.generation FROM active a JOIN blocks b ON b.id=a.tip WHERE a.singleton=1",
        [], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?)),
    )?;
    let frontier = Frontier {
        block: hex::encode(bytes32(tip)?),
        root: hex::encode(bytes32(root)?),
        generation,
    };
    frontier.validate()?;
    Ok(frontier)
}

fn genesis_only(db: &Connection, identity: &Identity) -> Result<()> {
    let genesis = hex::decode(&identity.genesis).map_err(|_| "HISTORY_V6_ID")?;
    let block_count: u64 = db.query_row(
        "SELECT count(*) FROM (SELECT 1 FROM blocks LIMIT 2)",
        [],
        |r| r.get(0),
    )?;
    let genesis_row: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM blocks WHERE id=? AND parent IS NULL AND height=0 AND chainwork=zeroblob(64) AND packet IS NULL)",
        [genesis.as_slice()], |r| r.get(0),
    )?;
    let snapshot_count: u64 = db.query_row(
        "SELECT count(*) FROM (SELECT 1 FROM snapshots LIMIT 2)",
        [],
        |r| r.get(0),
    )?;
    let snapshot_exists: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM snapshots WHERE block=?)",
        [genesis.as_slice()],
        |r| r.get(0),
    )?;
    let wrong_slot: bool =
        db.query_row("SELECT EXISTS(SELECT 1 FROM kv WHERE slot!=0)", [], |r| {
            r.get(0)
        })?;
    let active: bool = db.query_row("SELECT EXISTS(SELECT 1 FROM active WHERE singleton=1 AND tip=? AND generation=0 AND state_slot=0)", [genesis.as_slice()], |r| r.get(0))?;
    ensure(
        block_count == 1
            && genesis_row
            && snapshot_count == 1
            && snapshot_exists
            && !wrong_slot
            && active,
        "HISTORY_LIFECYCLE_V1_INITIAL_EFFECT",
    )?;
    // The schema was already compared with the exact selected Native DDL.
    // Check every non-genesis table, including ancestry tables, for effects.
    for key in schema(db)?.keys() {
        let Some(table) = key.strip_prefix("table:") else {
            continue;
        };
        if ["metadata", "blocks", "active", "kv", "snapshots"].contains(&table) {
            continue;
        }
        ensure(
            !table.is_empty()
                && table.len() <= 64
                && table
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_'),
            "HISTORY_LIFECYCLE_V1_SCHEMA_NAME",
        )?;
        let any: bool =
            db.query_row(&format!("SELECT EXISTS(SELECT 1 FROM {table})"), [], |r| {
                r.get(0)
            })?;
        ensure(!any, "HISTORY_LIFECYCLE_V1_INITIAL_EFFECT")?;
    }
    Ok(())
}

struct HeldPrefix {
    _native: Option<HeldNative>,
    _no_native: Option<startup_no_native_v1::HeldNamespace>,
}

fn hold_prefix(
    path: &Path,
    config: &Configuration,
    uid: u32,
    journal: &Journal,
    verified: &Verified,
) -> Result<HeldPrefix> {
    if let Some(proof) = &verified.closed.no_native {
        ensure(
            verified.body.outside_anchor == config.outside_latest_anchor
                && verified.body.executable_sha256 == config.expected_executable_sha256
                && verified.body.identity.source_commit == config.expected_source_commit
                && config.expected_no_native_pins.as_ref() == Some(&proof.pins)
                && config.expected_namespace_parent.as_ref() == Some(&proof.namespace_parent)
                && proof.journal_path == config.journal_path
                && proof.expected_uid == uid
                && path
                    == proof
                        .namespace_parent
                        .join(startup_no_native_v1::NATIVE_NAME),
            "HISTORY_LIFECYCLE_V1_NO_NATIVE_OUTSIDE_PINS",
        )?;
        let held = startup_no_native_v1::hold_bound_namespace(
            &proof.namespace_parent,
            &config.journal_path,
            &config.identity,
            &proof.pins.preparation_sha256,
            proof.after.clone(),
            uid,
        )?;
        journal.ready()?;
        held.check()?;
        Ok(HeldPrefix {
            _native: None,
            _no_native: Some(held),
        })
    } else {
        ensure(
            config.expected_no_native_pins.is_none() && config.expected_namespace_parent.is_none(),
            "HISTORY_LIFECYCLE_V1_NO_NATIVE_OUTSIDE_PINS",
        )?;
        Ok(HeldPrefix {
            _native: Some(hold_native(path, config, uid, journal, verified)?),
            _no_native: None,
        })
    }
}

fn hold_native(
    path: &Path,
    config: &Configuration,
    uid: u32,
    journal: &Journal,
    verified: &Verified,
) -> Result<HeldNative> {
    ensure(path.is_absolute(), "HISTORY_V6_NATIVE_PATH")?;
    ensure(
        verified.body.outside_anchor == config.outside_latest_anchor
            && verified.body.executable_sha256 == config.expected_executable_sha256
            && verified.body.identity.source_commit == config.expected_source_commit,
        "HISTORY_LIFECYCLE_V1_OUTSIDE_PINS",
    )?;
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let dm = directory.metadata()?;
    ensure(
        dm.is_dir() && dm.uid() == uid && dm.mode() & 0o077 == 0,
        "HISTORY_V6_NATIVE_DIRECTORY",
    )?;
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        ensure(
            [
                "owner.lock",
                "owner-task-policy.required",
                "initializing.json",
                "native.sqlite",
                "native.sqlite-wal",
                "native.sqlite-shm",
            ]
            .iter()
            .any(|name| entry.file_name() == *name),
            "HISTORY_LIFECYCLE_V1_NAMESPACE",
        )?;
    }
    let mut files = Vec::new();
    let owner_path = path.join("owner.lock");
    if let Some(owner) = optional_file(&owner_path, uid)? {
        owner.try_lock_exclusive()?;
        files.push((owner_path, owner));
    }
    let owner_exists = !files.is_empty();
    let marker_path = path.join("owner-task-policy.required");
    let mut marker = recovery::private_file(&marker_path, uid)?;
    let expected_marker = storage::owner_marker(&config.identity, &config.journal_path)?;
    ensure(
        read_small(&mut marker)? == expected_marker,
        "HISTORY_V6_NATIVE_MARKER",
    )?;
    files.push((marker_path, marker));
    let initialization_path = path.join("initializing.json");
    let initialization = optional_file(&initialization_path, uid)?;
    let expected_initialization = canonical(&serde_json::json!({
        "schema":hex::encode(StateBackend::HistoryEffectV6.schema_id()),
        "parameters":config.identity.parameters, "genesis":config.identity.genesis,
    }))?;
    let initializing_sha256 = if let Some(mut initialization) = initialization {
        ensure(
            owner_exists && read_small(&mut initialization)? == expected_initialization,
            "HISTORY_LIFECYCLE_V1_INITIALIZATION_CONTEXT",
        )?;
        files.push((initialization_path, initialization));
        Some(policy::digest(&expected_initialization))
    } else {
        None
    };
    let native_path = path.join("native.sqlite");
    let native = optional_file(&native_path, uid)?;
    let database_exists = native.is_some();
    for name in ["native.sqlite-wal", "native.sqlite-shm"] {
        let sidecar_path = path.join(name);
        if let Some(sidecar) = optional_file(&sidecar_path, uid)? {
            ensure(
                database_exists && owner_exists,
                "HISTORY_LIFECYCLE_V1_ORPHAN_SIDECAR",
            )?;
            files.push((sidecar_path, sidecar));
        }
    }
    let (db, database, actual_frontier) = if let Some(native) = native {
        ensure(owner_exists, "HISTORY_LIFECYCLE_V1_OWNER_REQUIRED")?;
        files.push((native_path, native));
        let db = Connection::open_with_flags(
            path.join("native.sqlite"),
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        db.execute_batch("PRAGMA trusted_schema=OFF; PRAGMA query_only=ON; BEGIN;")?;
        let current = schema(&db)?;
        if current.is_empty() {
            ensure(
                initializing_sha256.is_some(),
                "HISTORY_LIFECYCLE_V1_INITIALIZATION_REQUIRED",
            )?;
            (Some(db), Database::Empty, None)
        } else {
            let expected = Connection::open_in_memory()?;
            expected.execute_batch(&StateBackend::HistoryEffectV6.ddl())?;
            ensure(current == schema(&expected)?, "HISTORY_V6_NATIVE_SCHEMA")?;
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
                ("operator_task_policy", expected_marker.clone()),
            ] {
                let (actual, length): (Vec<u8>, u64) = db.query_row(
                    "SELECT substr(value,1,65537),length(value) FROM metadata WHERE key=?",
                    [key],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )?;
                ensure(
                    actual == value && length == value.len() as u64,
                    "HISTORY_V6_NATIVE_CONTEXT",
                )?;
            }
            storage::no_pending_reorg(&db)?;
            let actual = bounded_frontier(&db)?;
            ensure(
                storage::read_marker(&db, &verified.body.operation_id)?.is_none(),
                "HISTORY_LIFECYCLE_V1_UNEXPECTED_EFFECT",
            )?;
            storage::verify_known_markers(&db, journal, None)?;
            let kind = if initializing_sha256.is_some() {
                genesis_only(&db, &config.identity)?;
                Database::Genesis
            } else {
                Database::Ready
            };
            (Some(db), kind, Some(actual))
        }
    } else {
        (None, Database::Absent, None)
    };
    let actual = Snapshot {
        declared_frontier: verified.body.snapshot.declared_frontier.clone(),
        actual_frontier,
        initializing_sha256,
        database,
    };
    ensure(
        actual == verified.body.snapshot,
        "HISTORY_LIFECYCLE_V1_SQL_SNAPSHOT",
    )?;
    let visible_directory = fs::symlink_metadata(path)?;
    ensure(
        !visible_directory.file_type().is_symlink()
            && dm.dev() == visible_directory.dev()
            && dm.ino() == visible_directory.ino(),
        "HISTORY_V6_NATIVE_CHANGED",
    )?;
    journal.ready()?;
    for (name, file) in &mut files {
        require_visible(file, name, uid)?;
        if name
            .file_name()
            .is_some_and(|n| n == "owner-task-policy.required")
        {
            ensure(
                read_small(file)? == expected_marker,
                "HISTORY_V6_NATIVE_MARKER",
            )?;
        } else if name.file_name().is_some_and(|n| n == "initializing.json") {
            ensure(
                read_small(file)? == expected_initialization,
                "HISTORY_LIFECYCLE_V1_INITIALIZATION_CONTEXT",
            )?;
        }
    }
    // A missing held file must remain missing; no administrative recreation.
    for name in ["owner.lock", "initializing.json", "native.sqlite"] {
        let entry = path.join(name);
        if !files.iter().any(|(p, _)| p == &entry) {
            ensure(
                matches!(fs::symlink_metadata(entry), Err(e) if e.kind() == std::io::ErrorKind::NotFound),
                "HISTORY_V6_NATIVE_CHANGED",
            )?;
        }
    }
    Ok(HeldNative {
        _db: db,
        _files: files,
        _directory: directory,
    })
}

pub fn prepare_history_lifecycle_v1_recovery(
    path: &Path,
    input: ProtectedHistoryLifecycleV1Input,
) -> Result<Value> {
    let config = input.config;
    let verified = authenticate(
        &config.signed,
        &config.closed_process,
        &config.identity,
        policy::now()?,
    )?;
    let mut journal = Journal::open_existing(
        &config.journal_path,
        input.expected_uid,
        &config.identity,
        &config.outside_latest_anchor,
    )?;
    journal.state.check_lifecycle(&verified, policy::now()?)?;
    let _held = hold_prefix(path, &config, input.expected_uid, &journal, &verified)?;
    let before = journal.observation();
    journal.append(Event::LifecycleReconciledV1 {
        signed: config.signed,
        closed_process: config.closed_process,
    })?;
    Ok(serde_json::json!({
        "schema":"restricted-history-lifecycle-result-v1", "prior_journal":before,
        "journal":journal.observation(), "snapshot":verified.body.snapshot,
        "closed_process":verified.closed, "additional_conservative_debit":verified.body.allowance,
        "original_allowances_refunded":false, "original_receipts_rewritten":false,
        "clean_close_fabricated":false, "native_initialization_executed":false,
        "new_cpu_epoch_created":false, "work_authority_granted":false,
        "production_qualified":false,
    }))
}

pub fn repair_history_lifecycle_v1_publication(
    path: &Path,
    input: ProtectedHistoryLifecycleV1Input,
    publication_input: ProtectedHistoryJournalPublicationV1Input,
) -> Result<Value> {
    let config = input.config;
    publication::repair_with_validation(publication_input, |journal, frame| {
        let Event::LifecycleReconciledV1 {
            signed,
            closed_process,
        } = &frame.event
        else {
            return Err("HISTORY_LIFECYCLE_V1_PUBLICATION_EVENT".into());
        };
        ensure(
            frame.schema == RECORD_SCHEMA
                && signed == &config.signed
                && closed_process == &config.closed_process
                && journal.identity() == &config.identity
                && journal.path() == config.journal_path,
            "HISTORY_LIFECYCLE_V1_PUBLICATION_BINDING",
        )?;
        let verified = authenticate(signed, closed_process, &config.identity, frame.at_ns)?;
        journal.state.check_lifecycle(&verified, frame.at_ns)?;
        hold_prefix(path, &config, input.expected_uid, journal, &verified)
    })
}
