//! Explicit closure of an actually dead epoch with no pending V6 operation.
//! A separate signature and record namespace cannot forgive original debt or
//! manufacture a clean close. The complete dead-process upper bound is charged
//! again under a fresh finite allowance before another epoch can start.
use super::*;
use policy::{Anchor, ClosedProcess, Envelope, Identity, Usage};
use serde::{Deserialize, Serialize};

const DOMAIN: &[u8] = b"TRNM-HISTORY-SETTLED-EPOCH-RECOVERY-V1";
pub(super) const RECORD_SCHEMA: &str = "restricted-history-settled-epoch-record-v1";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Authorization {
    pub schema: String,
    pub identity: Identity,
    pub executable_sha256: String,
    pub budget_id: String,
    pub reconciliation_id: String,
    pub request_nonce: u64,
    pub epoch: String,
    pub outside_anchor: Anchor,
    pub last_operation_id: String,
    pub last_intent_sha256: String,
    pub closed_process_sha256: String,
    pub actual_frontier: Frontier,
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
    journal_path: PathBuf,
    outside_latest_anchor: Anchor,
    signed: Vec<u8>,
    closed_process: Vec<u8>,
}

/// Only a bounded protected input with an independently pinned frontier creates
/// this capability. A locally parsed journal never chooses its own authority.
pub struct ProtectedHistorySettledEpochV1Input {
    config: Configuration,
    expected_uid: u32,
    _file: File,
}
impl ProtectedHistorySettledEpochV1Input {
    pub fn load(path: &Path, expected_uid: u32, expected_sha256: &str) -> Result<Self> {
        let (raw, file) = policy::protected_file(path, expected_uid, expected_sha256)?;
        let config: Configuration = serde_json::from_slice(&raw)?;
        ensure(
            config.schema == "restricted-history-settled-epoch-input-v1",
            "HISTORY_EPOCH_V1_CONFIGURATION",
        )?;
        config.identity.validate()?;
        policy::id(&config.expected_source_commit, 20)?;
        policy::id(&config.expected_executable_sha256, 32)?;
        ensure(
            config.expected_source_commit == config.identity.source_commit,
            "HISTORY_EPOCH_V1_SOURCE_PIN",
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

pub(super) struct Verified {
    pub body: Authorization,
    pub closed: ClosedProcess,
}
pub(super) fn message(role: u8, body: &Authorization) -> Result<Vec<u8>> {
    let raw = policy::encoded(body)?;
    ensure(
        raw.len() <= policy::MAX_ENVELOPE,
        "HISTORY_EPOCH_V1_ENVELOPE",
    )?;
    let mut message = DOMAIN.to_vec();
    message.extend([b'E', role]);
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
        "HISTORY_EPOCH_V1_ENVELOPE",
    )?;
    let envelope: Envelope<Authorization> = serde_json::from_slice(signed)?;
    for (role, key, signature) in [
        (1, &identity.registry_key, &envelope.registry_signature),
        (2, &identity.task_key, &envelope.task_signature),
    ] {
        trnm_crypto_primitives::verify_hex_strict(key, &message(role, &envelope.body)?, signature)
            .map_err(|_| "HISTORY_EPOCH_V1_SIGNATURE")?;
    }
    let body = envelope.body;
    ensure(
        body.schema == "restricted-history-settled-epoch-authorization-v1"
            && body.identity == *identity
            && body.request_nonce > 0
            && body.allowance.operations == 1
            && body.allowance.cpu_ns > 0
            && body.allowance.material_bytes == 0
            && body.allowance.received_bytes == 0
            && body.issued_ns <= at
            && at < body.expires_ns
            && body.expires_ns - body.issued_ns <= 86_400_000_000_000,
        "HISTORY_EPOCH_V1_AUTHORIZATION",
    )?;
    for value in [
        &body.budget_id,
        &body.executable_sha256,
        &body.reconciliation_id,
        &body.epoch,
        &body.last_operation_id,
        &body.last_intent_sha256,
        &body.closed_process_sha256,
    ] {
        policy::id(value, 32)?;
    }
    body.outside_anchor.validate()?;
    body.actual_frontier.validate()?;
    let closed: ClosedProcess = serde_json::from_slice(closed_raw)?;
    closed.validate()?;
    ensure(
        policy::digest(closed_raw) == body.closed_process_sha256
            && closed.executable_sha256 == body.executable_sha256
            && closed.epoch == body.epoch
            && closed.original_journal == body.outside_anchor
            && closed.intent_sha256 == body.last_intent_sha256
            && closed.actual_frontier == body.actual_frontier
            && closed.reported_cpu_upper_bound_ns <= body.allowance.cpu_ns,
        "HISTORY_EPOCH_V1_CLOSED_BINDING",
    )?;
    Ok(Verified { body, closed })
}

/// Close only a source-bound, terminated epoch whose last operation already has
/// a known retained settlement. This appends a NEW namespace record, leaves all
/// old allowances and receipts intact, and adds a conservative full-process
/// debit. It creates neither a Native owner nor a CPU credit/measurement.
pub fn prepare_history_settled_epoch_v1_recovery(
    path: &Path,
    input: ProtectedHistorySettledEpochV1Input,
) -> Result<Value> {
    ensure(path.is_absolute(), "HISTORY_V6_NATIVE_PATH")?;
    let config = input.config;
    let verified = authenticate(
        &config.signed,
        &config.closed_process,
        &config.identity,
        policy::now()?,
    )?;
    ensure(
        verified.body.outside_anchor == config.outside_latest_anchor,
        "HISTORY_EPOCH_V1_OUTSIDE_ANCHOR",
    )?;
    ensure(
        verified.body.executable_sha256 == config.expected_executable_sha256
            && verified.body.identity.source_commit == config.expected_source_commit,
        "HISTORY_EPOCH_V1_SOURCE_PIN",
    )?;
    let mut journal = journal::Journal::open_existing(
        &config.journal_path,
        input.expected_uid,
        &config.identity,
        &config.outside_latest_anchor,
    )?;
    journal.check_settled_epoch(&verified, policy::now()?)?;
    let _native = hold_native(path, &config, input.expected_uid, &journal, &verified)?;
    let before = journal.observation();
    journal.reconcile_settled_epoch(&config.signed, &config.closed_process)?;
    Ok(serde_json::json!({
        "schema":"restricted-history-settled-epoch-result-v1",
        "prior_journal":before,"journal":journal.observation(),
        "closed_epoch":verified.body.epoch,"last_operation_id":verified.body.last_operation_id,
        "actual_frontier":verified.body.actual_frontier,"closed_process":verified.closed,
        "additional_conservative_debit":verified.body.allowance,
        "original_settlements_preserved":true,"original_allowances_refunded":false,
        "clean_close_fabricated":false,"native_effect_repeated":false,
        "new_cpu_epoch_created":false,"exact_residual_cpu_claimed":false,
        "whole_history_p0_closed":false,"production_qualified":false,
    }))
}

struct HeldNative {
    _db: Connection,
    _marker_file: File,
    _native: File,
    _directory: File,
    _owner: File,
}
fn hold_native(
    path: &Path,
    config: &Configuration,
    expected_uid: u32,
    journal: &journal::Journal,
    verified: &Verified,
) -> Result<HeldNative> {
    // Keep the owner, directory and exact SQLite file held throughout the
    // read-only transaction AND append. An actual live owner cannot pass.
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let dm = directory.metadata()?;
    ensure(
        dm.is_dir() && dm.uid() == expected_uid && dm.mode() & 0o077 == 0,
        "HISTORY_V6_NATIVE_DIRECTORY",
    )?;
    let owner = recovery::private_file(&path.join("owner.lock"), expected_uid)?;
    owner.try_lock_exclusive()?;
    let native = recovery::private_file(&path.join("native.sqlite"), expected_uid)?;
    let before = native.metadata()?;
    ensure(
        !path.join("initializing.json").exists(),
        "HISTORY_V6_INITIALIZATION_UNKNOWN",
    )?;
    for name in ["native.sqlite-wal", "native.sqlite-shm"] {
        plain(&path.join(name))?;
    }
    let expected_marker = storage::owner_marker(&config.identity, &config.journal_path)?;
    let mut marker_file =
        recovery::private_file(&path.join("owner-task-policy.required"), expected_uid)?;
    ensure(
        marker_file.metadata()?.len() <= 65536,
        "HISTORY_V6_NATIVE_MARKER",
    )?;
    let mut marker_raw = Vec::new();
    std::io::Read::by_ref(&mut marker_file)
        .take(65537)
        .read_to_end(&mut marker_raw)?;
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
    storage::no_pending_reorg(&db)?;
    let frontier = storage::frontier(&db)?;
    ensure(
        frontier == verified.body.actual_frontier,
        "HISTORY_EPOCH_V1_NATIVE_FRONTIER",
    )?;
    let actual_marker = storage::read_marker(&db, &verified.body.last_operation_id)?;
    ensure(
        actual_marker == verified.closed.marker,
        "HISTORY_EPOCH_V1_NATIVE_MARKER",
    )?;
    storage::verify_known_markers(&db, journal, None)?;
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
    require_visible(&owner, &path.join("owner.lock"), expected_uid)?;
    require_visible(&native, &path.join("native.sqlite"), expected_uid)?;
    require_visible(
        &marker_file,
        &path.join("owner-task-policy.required"),
        expected_uid,
    )?;
    marker_file.seek(SeekFrom::Start(0))?;
    let mut marker_again = Vec::new();
    std::io::Read::by_ref(&mut marker_file)
        .take(65537)
        .read_to_end(&mut marker_again)?;
    ensure(marker_again == expected_marker, "HISTORY_V6_NATIVE_MARKER")?;
    Ok(HeldNative {
        _db: db,
        _marker_file: marker_file,
        _native: native,
        _directory: directory,
        _owner: owner,
    })
}

/// Publication of a complete settled-epoch frame keeps the original recovery
/// pins and native-state checks. The old event is checked at frame.at_ns; only
/// the NEW publication authorization must be current at repair time.
pub fn repair_history_settled_epoch_v1_publication(
    path: &Path,
    input: ProtectedHistorySettledEpochV1Input,
    publication: ProtectedHistoryJournalPublicationV1Input,
) -> Result<Value> {
    ensure(path.is_absolute(), "HISTORY_V6_NATIVE_PATH")?;
    let config = input.config;
    journal::publication::repair_with_validation(publication, |journal, frame| {
        let journal::Event::SettledEpochReconciledV1 {
            signed,
            closed_process,
        } = &frame.event
        else {
            return Err("HISTORY_EPOCH_V1_PUBLICATION_EVENT".into());
        };
        ensure(
            frame.schema == RECORD_SCHEMA
                && signed == &config.signed
                && closed_process == &config.closed_process
                && journal.identity() == &config.identity
                && journal.path() == config.journal_path.as_path(),
            "HISTORY_EPOCH_V1_PUBLICATION_BINDING",
        )?;
        let verified = authenticate(signed, closed_process, &config.identity, frame.at_ns)?;
        ensure(
            verified.body.outside_anchor == config.outside_latest_anchor
                && verified.body.executable_sha256 == config.expected_executable_sha256
                && verified.body.identity.source_commit == config.expected_source_commit,
            "HISTORY_EPOCH_V1_SOURCE_PIN",
        )?;
        journal.check_settled_epoch(&verified, frame.at_ns)?;
        hold_native(path, &config, input.expected_uid, journal, &verified)
    })
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
        "HISTORY_EPOCH_V1_FILE_CHANGED",
    )
}
