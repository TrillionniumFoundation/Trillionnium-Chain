//! Read-only native reconciliation. This administrative action has no Node,
//! Work verifier, CPU epoch, active-state setter or automatic best-tip choice.
use super::*;

fn private_file(path: &Path, uid: u32) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let m = file.metadata()?;
    let visible = fs::symlink_metadata(path)?;
    ensure(
        m.is_file()
            && m.uid() == uid
            && m.mode() & 0o077 == 0
            && m.nlink() == 1
            && visible.dev() == m.dev()
            && visible.ino() == m.ino()
            && !visible.file_type().is_symlink(),
        "HISTORY_V6_NATIVE_FILE",
    )?;
    Ok(file)
}

/// A receipt digest alone creates no authority: this consumes a bounded
/// protected configuration, verifies both new-domain outside signatures and
/// requires the independently supplied latest spent anchor. It leaves the
/// original unknown split and entire reservation in the append-only journal.
pub fn prepare_history_effect_v6_recovery(
    path: &Path,
    input: ProtectedHistoryV6RecoveryInput,
) -> Result<Value> {
    ensure(path.is_absolute(), "HISTORY_V6_NATIVE_PATH")?;
    let config = input.config;
    let verified = policy::recovery(
        &config.recovery.signed,
        &config.recovery.closed_process,
        &config.identity,
        policy::now()?,
    )?;
    ensure(
        verified.body.outside_anchor == config.outside_latest_anchor,
        "HISTORY_V6_OUTSIDE_ANCHOR",
    )?;
    let mut journal = journal::Journal::open(
        &config.journal_path,
        input.expected_uid,
        &config.identity,
        &config.outside_latest_anchor,
    )?;
    journal.check_recovery(&verified)?;
    let pending = journal.pending().cloned().ok_or("HISTORY_V6_NO_PENDING")?;
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let dm = directory.metadata()?;
    ensure(
        dm.is_dir() && dm.uid() == input.expected_uid && dm.mode() & 0o077 == 0,
        "HISTORY_V6_NATIVE_DIRECTORY",
    )?;
    // The original process must no longer hold either journal or Node lock.
    // This supplements, and does not replace, signed actual wait4/descendants.
    let owner = private_file(&path.join("owner.lock"), input.expected_uid)?;
    owner.try_lock_exclusive()?;
    let native = private_file(&path.join("native.sqlite"), input.expected_uid)?;
    let before = native.metadata()?;
    ensure(
        !path.join("initializing.json").exists(),
        "HISTORY_V6_INITIALIZATION_UNKNOWN",
    )?;
    for name in ["native.sqlite-wal", "native.sqlite-shm"] {
        plain(&path.join(name))?;
    }
    let expected_marker = storage::owner_marker(&config.identity, &config.journal_path)?;
    let marker_file = private_file(&path.join("owner-task-policy.required"), input.expected_uid)?;
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
    let actual_frontier = storage::frontier(&db)?;
    ensure(
        actual_frontier == verified.body.actual_frontier,
        "HISTORY_V6_RECOVERY_FRONTIER",
    )?;
    let actual_marker = storage::read_marker(&db, &pending.operation.operation_id)?;
    ensure(
        actual_marker == verified.closed.marker,
        "HISTORY_V6_SQL_MARKER_BINDING",
    )?;
    storage::verify_known_markers(&db, &journal, actual_marker.as_ref())?;
    if let Some(marker) = &actual_marker {
        journal::check_marker(&pending, marker)?;
    } else {
        ensure(
            actual_frontier == pending.operation.owner_frontier,
            "HISTORY_V6_UNMARKED_EFFECT",
        )?;
        // A target may predate a reuse attempt, but then a retained independently
        // accounted validation marker must already authenticate that packet.
        let target = hex::decode(&pending.operation.target).map_err(|_| "HISTORY_V6_ID")?;
        let exists: bool = db.query_row(
            "SELECT EXISTS(SELECT 1 FROM blocks WHERE id=?)",
            [target],
            |r| r.get(0),
        )?;
        if exists {
            ensure(
                journal.markers().values().any(|m| {
                    m.purpose == Purpose::Validation
                        && m.target == pending.operation.target
                        && Some(&m.packet_sha256) == pending.operation.packet_sha256.as_ref()
                }),
                "HISTORY_V6_UNMARKED_EFFECT",
            )?;
        }
    }
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
    // No Native write occurred. The only new durable fact is that the exact
    // unknown original scope is prepaid-covered under the named counter model.
    // New work still requires an independently signed fresh startup and claim.
    journal.reconcile(&config.recovery)?;
    Ok(
        serde_json::json!({"schema":"restricted-history-effect-recovery-result-v6",
        "journal":journal.observation(),"actual_frontier":actual_frontier,"actual_marker":actual_marker,
        "original_operation":pending.operation.operation_id,"original_intent":pending.intent_sha256,
        "original_allowance_kept_spent":pending.operation.allowance,
        "original_cpu_split":if pending.observed_receipt.as_ref().is_some_and(|r|r.known()) {
            "observed-known-receipt-preserved-effect-unresolved"
        } else { "unknown-preserved" },
        "original_observed_receipt":pending.observed_receipt,
        "closed_process":verified.closed,
        "signed_recovery_sha256":verified.envelope_sha256,"native_effect_repeated":false,
        "new_cpu_epoch_created":false,"physical_cost_qualified":false,"production_qualified":false}),
    )
}
