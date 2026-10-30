//! A new, finite authority for one exact interrupted reorganization attempt.
//! The old operation is never restarted or refunded. A real closed-process
//! observation and a new predebit authorize three fresh, named operations.
use super::*;
use policy::{Anchor, ClosedProcess, Envelope, Identity, Operation, Usage};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const DOMAIN: &[u8] = b"TRNM-HISTORY-REORG-CONTINUATION-V1";
pub(super) const RECORD_SCHEMA: &str = "restricted-history-reorg-continuation-record-v1";

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(super) enum Closure {
    PendingUnknown,
    SettledKnown,
    NotStarted,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Snapshot {
    pub old_frontier: Frontier,
    pub target: String,
    pub target_root: String,
    pub generation: u64,
    pub cursor: u64,
    pub steps: u64,
    pub steps_sha256: String,
    pub staging_sha256: String,
}
impl Snapshot {
    fn validate(&self) -> Result<()> {
        self.old_frontier.validate()?;
        for value in [
            &self.target,
            &self.target_root,
            &self.steps_sha256,
            &self.staging_sha256,
        ] {
            policy::id(value, 32)?;
        }
        ensure(
            self.old_frontier.generation.checked_add(1) == Some(self.generation)
                && self.generation <= i64::MAX as u64
                && self.steps > 0
                // The original History marker/block inventory admits at most
                // 256 blocks; detach plus attach therefore fits this bound.
                && self.steps <= 512
                && self.cursor <= self.steps
                && self.target != self.old_frontier.block,
            "HISTORY_REORG_V1_SNAPSHOT",
        )
    }
    pub(super) fn same_plan(&self, prior: &Self) -> bool {
        self.old_frontier == prior.old_frontier
            && self.target == prior.target
            && self.target_root == prior.target_root
            && self.generation == prior.generation
            && self.steps == prior.steps
            && self.steps_sha256 == prior.steps_sha256
            && self.cursor >= prior.cursor
    }
}

/// Bind the actual typed SQLite rows, including the staging slot. This does
/// not assert that their State root is correct; original paid Native replay
/// continues to verify every resulting State and the final publication.
pub(super) fn snapshot(
    db: &Connection,
    progress: &mut dyn FnMut() -> Result<()>,
) -> Result<Snapshot> {
    progress()?;
    let rows: Vec<ReorgRow> = db
        .prepare(
            "SELECT substr(old_tip,1,33),substr(new_tip,1,33),generation,cursor,done FROM reorg ORDER BY singleton LIMIT 2",
        )?
        .query_map([], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
        })?
        .collect::<std::result::Result<_, _>>()?;
    ensure(rows.len() == 1, "HISTORY_REORG_V1_EXACT_ROW")?;
    let (old, target, generation, cursor, done) = &rows[0];
    let old = bytes32(old.clone())?;
    let target = bytes32(target.clone())?;
    let old_frontier = storage::frontier(db)?;
    ensure(
        *done == 0 && old_frontier.block == hex::encode(old),
        "HISTORY_REORG_V1_UNPUBLISHED",
    )?;
    let root: Vec<u8> = db.query_row(
        "SELECT substr(state_root,1,33) FROM blocks WHERE id=?",
        [target.as_slice()],
        |r| r.get(0),
    )?;
    let mut steps = Vec::new();
    let mut query =
        db.prepare("SELECT ordinal,kind,substr(block,1,33) FROM steps ORDER BY ordinal LIMIT 513")?;
    let mut rows = query.query([])?;
    while let Some(row) = rows.next()? {
        progress()?;
        let ordinal: u64 = row.get(0)?;
        let kind: u64 = row.get(1)?;
        let block: Vec<u8> = row.get(2)?;
        ensure(
            ordinal == steps.len() as u64 && kind <= 1 && steps.len() < 512,
            "HISTORY_REORG_V1_STEPS",
        )?;
        steps.push((ordinal, kind, hex::encode(bytes32(block)?)));
    }
    let steps_raw = policy::encoded(&steps)?;
    // Use exactly the complete-State Native key/cell limits. Hash as rows
    // stream so a valid 65,536 x 4,096-byte State gains no lower total cap.
    let mut staging = Sha256::new();
    staging.update(b"TRNM-HISTORY-REORG-STAGING-V1");
    let mut query = db.prepare(
        "SELECT CASE WHEN typeof(key)='text' THEN CAST(substr(CAST(key AS BLOB),1,161) AS TEXT) ELSE key END,
         CASE WHEN typeof(value)='blob' THEN substr(value,1,4097) ELSE value END,
         length(CAST(key AS BLOB)),length(CAST(value AS BLOB))
         FROM kv WHERE slot=? ORDER BY key",
    )?;
    let mut rows = query.query([generation])?;
    let mut count = 0usize;
    while let Some(row) = rows.next()? {
        progress()?;
        let key_length: i64 = row.get(2)?;
        let value_length: i64 = row.get(3)?;
        ensure(
            count < trnm_mvcc_fee::continuity_v1::MAX_KEYS
                && (0..=160).contains(&key_length)
                && (0..=4096).contains(&value_length),
            "HISTORY_REORG_V1_STAGING_LIMIT",
        )?;
        let key: String = row.get(0)?;
        let value: Vec<u8> = row.get(1)?;
        ensure(
            key.len() as i64 == key_length && value.len() as i64 == value_length,
            "HISTORY_REORG_V1_STAGING_LIMIT",
        )?;
        staging.update((key.len() as u32).to_le_bytes());
        staging.update(key.as_bytes());
        staging.update((value.len() as u32).to_le_bytes());
        staging.update(value);
        count += 1;
    }
    let snapshot = Snapshot {
        old_frontier,
        target: hex::encode(target),
        target_root: hex::encode(bytes32(root)?),
        generation: *generation,
        cursor: *cursor,
        steps: steps.len() as u64,
        steps_sha256: policy::digest(&steps_raw),
        staging_sha256: hex::encode(staging.finalize()),
    };
    snapshot.validate()?;
    progress()?;
    Ok(snapshot)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Original {
    pub operation: Operation,
    pub intent_sha256: String,
    pub envelope_sha256: String,
    pub intent_at_ns: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Authorization {
    pub schema: String,
    pub identity: Identity,
    pub executable_sha256: String,
    pub budget_id: String,
    // Full original dual-signed Budget bytes, additionally bound by this new
    // domain. Present only for an atomic administrative renewal plus closure.
    pub renewal_budget: Option<Vec<u8>>,
    pub continuation_id: String,
    pub previous_continuation_id: Option<String>,
    pub request_nonce: u64,
    pub outside_anchor: Anchor,
    pub closure: Closure,
    pub closed_operation_id: String,
    pub closed_intent_sha256: String,
    pub closed_epoch: String,
    pub closed_process_sha256: String,
    pub original: Original,
    pub snapshot: Snapshot,
    pub next_epoch: String,
    pub startup_operation_id: String,
    pub validation_operation_id: String,
    pub activation_operation_id: String,
    pub allowance: Usage,
    pub issued_ns: u64,
    pub expires_ns: u64,
}
impl Authorization {
    pub(super) fn check_operation(&self, operation: &Operation) -> Result<()> {
        let original = &self.original.operation;
        ensure(
            operation.epoch == self.next_epoch
                && operation.owner_frontier == self.snapshot.old_frontier
                && operation.binding == original.binding,
            "HISTORY_REORG_V1_ATTEMPT_BINDING",
        )?;
        if operation.purpose == Purpose::Startup {
            return ensure(
                operation.operation_id == self.startup_operation_id,
                "HISTORY_REORG_V1_STARTUP_ID",
            );
        }
        ensure(
            match operation.purpose {
                Purpose::Validation => operation.operation_id == self.validation_operation_id,
                Purpose::Activation => operation.operation_id == self.activation_operation_id,
                Purpose::Startup | Purpose::Close => false,
            } && operation.target == original.target
                && operation.target_root == original.target_root
                && operation.packet_sha256 == original.packet_sha256
                && operation.execution_parent == original.execution_parent
                && operation.validation_operation_id.as_ref()
                    == Some(&self.validation_operation_id)
                && operation.activation_operation_id.as_ref()
                    == Some(&self.activation_operation_id),
            "HISTORY_REORG_V1_EFFECT_ID",
        )
    }
    pub(super) fn completes(&self, marker: &EffectMarker) -> bool {
        marker.purpose == Purpose::Activation
            && marker.epoch == self.next_epoch
            && marker.operation_id == self.activation_operation_id
            && marker.before == self.snapshot.old_frontier
            && marker.after.block == self.snapshot.target
            && marker.after.root == self.snapshot.target_root
            && marker.after.generation == self.snapshot.generation
            && marker.validation_operation_id == self.validation_operation_id
            && marker.activation_operation_id == self.activation_operation_id
    }
}

pub(super) struct Verified {
    pub body: Authorization,
    pub closed: ClosedProcess,
}
pub(super) fn message(role: u8, body: &Authorization) -> Result<Vec<u8>> {
    let raw = policy::encoded(body)?;
    ensure(
        raw.len() <= policy::MAX_ENVELOPE,
        "HISTORY_REORG_V1_ENVELOPE",
    )?;
    let mut message = DOMAIN.to_vec();
    message.extend([b'R', role]);
    message.extend((raw.len() as u32).to_le_bytes());
    message.extend(raw);
    Ok(message)
}
pub(super) fn authenticate(
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
        "HISTORY_REORG_V1_ENVELOPE",
    )?;
    let envelope: Envelope<Authorization> = serde_json::from_slice(signed)?;
    for (role, key, signature) in [
        (1, &identity.registry_key, &envelope.registry_signature),
        (2, &identity.task_key, &envelope.task_signature),
    ] {
        trnm_crypto_primitives::verify_hex_strict(key, &message(role, &envelope.body)?, signature)
            .map_err(|_| "HISTORY_REORG_V1_SIGNATURE")?;
    }
    let body = envelope.body;
    ensure(
        body.schema == "restricted-history-reorg-continuation-authorization-v1"
            && body.identity == *identity
            && body.original.operation.identity == *identity
            && body.original.operation.purpose == Purpose::Activation
            && body.request_nonce > 0
            && body.allowance.operations == 1
            && (1..=60_000_000_000).contains(&body.allowance.cpu_ns)
            && body.allowance.material_bytes == 0
            && body.allowance.received_bytes == 0
            && body.issued_ns <= at
            && at < body.expires_ns
            && body.expires_ns - body.issued_ns <= 86_400_000_000_000,
        "HISTORY_REORG_V1_AUTHORIZATION",
    )?;
    for value in [
        &body.executable_sha256,
        &body.budget_id,
        &body.continuation_id,
        &body.closed_operation_id,
        &body.closed_intent_sha256,
        &body.closed_epoch,
        &body.closed_process_sha256,
        &body.next_epoch,
        &body.startup_operation_id,
        &body.validation_operation_id,
        &body.activation_operation_id,
        &body.original.intent_sha256,
        &body.original.envelope_sha256,
    ] {
        policy::id(value, 32)?;
    }
    if let Some(previous) = &body.previous_continuation_id {
        policy::id(previous, 32)?;
    }
    let fresh = [
        &body.continuation_id,
        &body.startup_operation_id,
        &body.validation_operation_id,
        &body.activation_operation_id,
    ]
    .into_iter()
    .collect::<std::collections::BTreeSet<_>>();
    ensure(fresh.len() == 4, "HISTORY_REORG_V1_DISTINCT_IDS")?;
    body.outside_anchor.validate()?;
    body.snapshot.validate()?;
    body.original
        .operation
        .validate(body.original.intent_at_ns)?;
    ensure(
        body.original.operation.owner_frontier == body.snapshot.old_frontier
            && body.original.operation.target == body.snapshot.target
            && body.original.operation.target_root == body.snapshot.target_root,
        "HISTORY_REORG_V1_ORIGINAL_TARGET",
    )?;
    let closed: ClosedProcess = serde_json::from_slice(closed_raw)?;
    closed.validate()?;
    ensure(
        policy::digest(closed_raw) == body.closed_process_sha256
            && closed.executable_sha256 == body.executable_sha256
            && closed.epoch == body.closed_epoch
            && closed.original_journal == body.outside_anchor
            && closed.intent_sha256 == body.closed_intent_sha256
            && closed.actual_frontier == body.snapshot.old_frontier
            && closed.reported_cpu_upper_bound_ns <= body.allowance.cpu_ns,
        "HISTORY_REORG_V1_CLOSED_BINDING",
    )?;
    Ok(Verified { body, closed })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Configuration {
    schema: String,
    identity: Identity,
    expected_source_commit: String,
    expected_executable_sha256: String,
    journal_path: PathBuf,
    outside_latest_anchor: Anchor,
    signed: Vec<u8>,
    closed_process: Vec<u8>,
}
pub struct ProtectedHistoryReorgContinuationV1Input {
    config: Configuration,
    expected_uid: u32,
    _file: File,
}
impl ProtectedHistoryReorgContinuationV1Input {
    pub fn load(path: &Path, expected_uid: u32, expected_sha256: &str) -> Result<Self> {
        let (raw, file) = policy::protected_file(path, expected_uid, expected_sha256)?;
        let config: Configuration = serde_json::from_slice(&raw)?;
        ensure(
            config.schema == "restricted-history-reorg-continuation-input-v1",
            "HISTORY_REORG_V1_CONFIGURATION",
        )?;
        config.identity.validate()?;
        policy::id(&config.expected_source_commit, 20)?;
        policy::id(&config.expected_executable_sha256, 32)?;
        ensure(
            config.expected_source_commit == config.identity.source_commit,
            "HISTORY_REORG_V1_SOURCE_PIN",
        )?;
        config.outside_latest_anchor.validate()?;
        ensure(config.journal_path.is_absolute(), "HISTORY_V6_JOURNAL_PATH")?;
        Ok(Self {
            config,
            expected_uid,
            _file: file,
        })
    }
}

struct HeldNative {
    _db: Connection,
    _marker: File,
    _native: File,
    _owner: File,
    _directory: File,
}
fn hold_native(
    path: &Path,
    config: &Configuration,
    uid: u32,
    journal: &journal::Journal,
    verified: &Verified,
) -> Result<HeldNative> {
    ensure(path.is_absolute(), "HISTORY_V6_NATIVE_PATH")?;
    ensure(
        verified.body.outside_anchor == config.outside_latest_anchor
            && verified.body.executable_sha256 == config.expected_executable_sha256,
        "HISTORY_REORG_V1_OUTSIDE_PINS",
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
    let owner = recovery::private_file(&path.join("owner.lock"), uid)?;
    owner.try_lock_exclusive()?;
    let native = recovery::private_file(&path.join("native.sqlite"), uid)?;
    let before = native.metadata()?;
    ensure(
        !path.join("initializing.json").exists(),
        "HISTORY_V6_INITIALIZATION_UNKNOWN",
    )?;
    for name in ["native.sqlite-wal", "native.sqlite-shm"] {
        plain(&path.join(name))?;
    }
    let expected_marker = storage::owner_marker(&config.identity, &config.journal_path)?;
    let mut marker = recovery::private_file(&path.join("owner-task-policy.required"), uid)?;
    ensure(
        marker.metadata()?.len() <= 65536,
        "HISTORY_V6_NATIVE_MARKER",
    )?;
    let mut raw = Vec::new();
    std::io::Read::by_ref(&mut marker)
        .take(65537)
        .read_to_end(&mut raw)?;
    ensure(raw == expected_marker, "HISTORY_V6_NATIVE_MARKER")?;
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
    for (key, expected) in [
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
        let actual: Vec<u8> =
            db.query_row("SELECT value FROM metadata WHERE key=?", [key], |r| {
                r.get(0)
            })?;
        ensure(actual == expected, "HISTORY_V6_NATIVE_CONTEXT")?;
    }
    ensure(
        snapshot(&db, &mut || Ok(()))? == verified.body.snapshot,
        "HISTORY_REORG_V1_SQL_SNAPSHOT",
    )?;
    let marker_readback = storage::read_marker(&db, &verified.body.closed_operation_id)?;
    ensure(
        marker_readback == verified.closed.marker,
        "HISTORY_V6_SQL_MARKER_BINDING",
    )?;
    storage::verify_known_markers(&db, journal, marker_readback.as_ref())?;
    let visible = fs::symlink_metadata(path.join("native.sqlite"))?;
    let visible_dir = fs::symlink_metadata(path)?;
    ensure(
        before.dev() == visible.dev()
            && before.ino() == visible.ino()
            && dm.dev() == visible_dir.dev()
            && dm.ino() == visible_dir.ino(),
        "HISTORY_V6_NATIVE_CHANGED",
    )?;
    journal.ready()?;
    epoch_recovery_v1::require_visible(&owner, &path.join("owner.lock"), uid)?;
    epoch_recovery_v1::require_visible(&native, &path.join("native.sqlite"), uid)?;
    epoch_recovery_v1::require_visible(&marker, &path.join("owner-task-policy.required"), uid)?;
    marker.seek(SeekFrom::Start(0))?;
    let mut marker_again = Vec::new();
    std::io::Read::by_ref(&mut marker)
        .take(65537)
        .read_to_end(&mut marker_again)?;
    ensure(marker_again == expected_marker, "HISTORY_V6_NATIVE_MARKER")?;
    Ok(HeldNative {
        _db: db,
        _marker: marker,
        _native: native,
        _owner: owner,
        _directory: directory,
    })
}

pub fn prepare_history_reorg_continuation_v1(
    path: &Path,
    input: ProtectedHistoryReorgContinuationV1Input,
) -> Result<Value> {
    let config = input.config;
    let verified = authenticate(
        &config.signed,
        &config.closed_process,
        &config.identity,
        policy::now()?,
    )?;
    let mut journal = journal::Journal::open_existing(
        &config.journal_path,
        input.expected_uid,
        &config.identity,
        &config.outside_latest_anchor,
    )?;
    journal.check_reorg_continuation(&verified, policy::now()?)?;
    let _held = hold_native(path, &config, input.expected_uid, &journal, &verified)?;
    let before = journal.observation();
    journal.prepare_reorg_continuation(&config.signed, &config.closed_process)?;
    Ok(serde_json::json!({
        "schema":"restricted-history-reorg-continuation-result-v1",
        "before":before,"journal":journal.observation(),"snapshot":verified.body.snapshot,
        "closed_process":verified.closed,"original_receipt_preserved":true,
        "original_allowance_refunded":false,"native_effect_repeated":false,
        "new_cpu_epoch_created":false,"new_cpu_receipt_created":false,
        "whole_history_p0_closed":false,"partial_initialization_qualified":false,
        "production_qualified":false,
    }))
}

pub fn repair_history_reorg_continuation_v1_publication(
    path: &Path,
    input: ProtectedHistoryReorgContinuationV1Input,
    publication: ProtectedHistoryJournalPublicationV1Input,
) -> Result<Value> {
    let config = input.config;
    journal::publication::repair_with_validation(publication, |journal, frame| {
        let journal::Event::ReorgContinuationPreparedV1 {
            signed,
            closed_process,
        } = &frame.event
        else {
            return Err("HISTORY_REORG_V1_PUBLICATION_EVENT".into());
        };
        ensure(
            frame.schema == RECORD_SCHEMA
                && signed == &config.signed
                && closed_process == &config.closed_process
                && journal.identity() == &config.identity
                && journal.path() == config.journal_path,
            "HISTORY_REORG_V1_PUBLICATION_BINDING",
        )?;
        let verified = authenticate(signed, closed_process, &config.identity, frame.at_ns)?;
        journal.check_reorg_continuation(&verified, frame.at_ns)?;
        hold_native(path, &config, input.expected_uid, journal, &verified)
    })
}
