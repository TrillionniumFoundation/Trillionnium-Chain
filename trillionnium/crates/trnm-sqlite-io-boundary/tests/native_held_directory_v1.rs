//! Proposed finite held-directory controls. Source candidate only: not built or run.
//! Four fresh processes, no reset, default-VFS open, new dependency, or full bridge claim.
#![cfg(target_os = "linux")]
#![forbid(unsafe_code)]

use rusqlite::{config::DbConfig, OpenFlags, MAIN_DB};
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::ffi::{OsStr, OsString};
use std::fs::{self, DirBuilder, File, Metadata, OpenOptions};
use std::io::{self, Write};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{symlink, DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use trnm_sqlite_io_boundary::{
    NativeIoLease, NativeIoOwner, RootReceipt, DOMAIN, DOMAIN_BYTES, FILE_BYTES, OBJECTS_PER_ROOT,
    ROOT_COUNT,
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
const CASES: [&str; 4] = [
    "held_parent_rename_sqlite_cold",
    "nondirectory_parent_claim",
    "bad_basename_escape_claim",
    "existing_symlink_claim",
];
const CASE_SECONDS: u64 = 30;
const WHOLE_SECONDS: u64 = 300;
const JSON_BYTES: usize = 2 * 1024 * 1024;

fn require(condition: bool, explanation: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(io::Error::other(explanation).into())
    }
}
fn private_dir(path: &Path) -> Result<()> {
    DirBuilder::new().mode(0o700).create(path)?;
    Ok(())
}
fn write_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let raw = serde_json::to_vec_pretty(value)?;
    require(raw.len() < JSON_BYTES, "finite JSON evidence capacity")?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(&raw)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}
fn read_json(path: &Path) -> Option<Value> {
    let bytes = fs::read(path).ok()?;
    if bytes.len() >= JSON_BYTES {
        return None;
    }
    serde_json::from_slice(&bytes).ok()
}
fn sentinel(path: &Path, contents: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(contents)?;
    file.sync_all()?;
    Ok(())
}
fn held_directory(path: &Path) -> Result<File> {
    Ok(OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?)
}
fn identity(metadata: &Metadata) -> (u64, u64) {
    (metadata.dev(), metadata.ino())
}
fn names(base: &Path, prefix: &str) -> [PathBuf; ROOT_COUNT] {
    std::array::from_fn(|i| base.join(format!("{prefix}-{i}")))
}
fn parent_inputs(parent: &File, prefix: &str) -> Result<[(File, OsString); ROOT_COUNT]> {
    let mut values = Vec::with_capacity(ROOT_COUNT);
    for i in 0..ROOT_COUNT {
        values.push((parent.try_clone()?, OsString::from(format!("{prefix}-{i}"))));
    }
    values
        .try_into()
        .map_err(|_| io::Error::other("seven parent inputs").into())
}
fn basename_bytes(name: &OsStr) -> Vec<u8> {
    name.as_bytes().to_vec()
}
fn listing(path: &Path) -> Result<Vec<Vec<u8>>> {
    let mut result = fs::read_dir(path)?
        .map(|item| item.map(|entry| basename_bytes(&entry.file_name())))
        .collect::<io::Result<Vec<_>>>()?;
    result.sort();
    Ok(result)
}
fn healthy(receipt: &RootReceipt) -> Result<()> {
    require(receipt.schema == DOMAIN, "original root receipt schema")?;
    require(receipt.owner_pid == std::process::id(), "actual owner PID")?;
    require(
        receipt.logical_bytes_limit == 3 * FILE_BYTES,
        "original root byte cap",
    )?;
    require(
        receipt.retained_object_limit == 3,
        "original three object cap",
    )?;
    require(
        receipt.objects.len() <= 3 && receipt.retained_objects_peak <= 3,
        "object peak",
    )?;
    require(receipt.high_water_sum <= 3 * FILE_BYTES, "logical byte sum")?;
    require(
        receipt.retained_logical_bytes_peak <= 3 * FILE_BYTES,
        "logical byte peak",
    )?;
    require(
        !receipt.allocated_blocks_hard_cap_implemented,
        "no physical block quota claim",
    )?;
    require(receipt.lifecycle_complete, "complete original lifecycle")?;
    require(
        receipt.secondary_failures_complete,
        "complete original secondary failures",
    )?;
    require(
        receipt.quarantine_entries_complete,
        "complete original quarantine",
    )?;
    require(
        receipt.lifecycle.len() <= 1024 && receipt.cleanup_lifecycle.len() <= 256,
        "original lifecycle counts",
    )?;
    require(
        receipt.lifecycle_serialized_bytes_cap == 655_360,
        "original lifecycle byte cap",
    )?;
    require(
        receipt.lifecycle_serialized_bytes <= receipt.lifecycle_serialized_bytes_cap,
        "lifecycle bytes",
    )?;
    require(
        !receipt.failed
            && receipt.first_failure.is_none()
            && receipt.first_failure_sqlite_code.is_none(),
        "healthy original root",
    )?;
    require(
        receipt.secondary_failures.is_empty() && receipt.denied_operations == 0,
        "no hidden denial",
    )?;
    require(
        receipt.quarantined_actual_states == 0 && receipt.quarantined_sqlite_codes.is_empty(),
        "no unknown close",
    )?;
    require(
        receipt
            .objects
            .iter()
            .all(|o| o.high_water_bytes <= FILE_BYTES && o.actual_last_bytes <= FILE_BYTES),
        "original per-file cap",
    )?;
    let ids: BTreeSet<_> = receipt
        .objects
        .iter()
        .filter_map(|o| o.device.zip(o.inode))
        .collect();
    require(
        ids.len()
            == receipt
                .objects
                .iter()
                .filter(|o| o.device.is_some())
                .count(),
        "distinct real object identities",
    )
}
fn closed(receipt: &RootReceipt) -> Result<()> {
    healthy(receipt)?;
    require(
        receipt
            .objects
            .iter()
            .all(|o| o.handles == 0 && o.pending_opens == 0 && o.shm_references == 0),
        "all actual file and mapping references closed",
    )
}
fn snapshot(base: &Path, label: &str, lease: &NativeIoLease) -> Result<RootReceipt> {
    let receipt = lease.receipt()?;
    write_json(&base.join(format!("{label}.json")), &receipt)?;
    healthy(&receipt)?;
    require(
        (receipt.root_device, receipt.root_inode) == lease.identity(),
        "same held root identity",
    )?;
    Ok(receipt)
}
fn actual_named(lease: &NativeIoLease, receipt: &RootReceipt, name: &str) -> Result<(u64, u64)> {
    let object = receipt
        .objects
        .iter()
        .find(|o| o.basename == name)
        .ok_or_else(|| io::Error::other("missing real named object"))?;
    let metadata = fs::symlink_metadata(lease.directory().join(name))?;
    require(
        metadata.is_file() && !metadata.file_type().is_symlink() && metadata.nlink() == 1,
        "real private regular inode",
    )?;
    require(
        object.device.zip(object.inode) == Some(identity(&metadata)),
        "actual named inode equals ledger",
    )?;
    require(
        object.actual_last_bytes == metadata.len() && object.linked,
        "actual named length and link",
    )?;
    Ok(identity(&metadata))
}
fn rw_flags() -> OpenFlags {
    OpenFlags::SQLITE_OPEN_READ_WRITE
        | OpenFlags::SQLITE_OPEN_CREATE
        | OpenFlags::SQLITE_OPEN_NO_MUTEX
}

// Kept outside catch_unwind: even an unexpected successful negative case remains
// available to the finalizer. No unexpected owner is silently dropped or certified.
#[derive(Default)]
struct CaseState {
    owners: Vec<NativeIoOwner>,
}
fn reject(
    state: &mut CaseState,
    operation: std::result::Result<NativeIoOwner, trnm_sqlite_io_boundary::BoundaryError>,
) -> (bool, String) {
    match operation {
        Ok(owner) => {
            state.owners.push(owner);
            (
                false,
                "UNEXPECTED owner accepted; retained for actual final receipts".into(),
            )
        }
        Err(error) => (true, error.to_string()),
    }
}
fn consumed_retries(base: &Path, parent: &File, state: &mut CaseState) -> Result<Value> {
    let old = reject(state, NativeIoOwner::create(names(base, "old-retry")));
    let new = reject(
        state,
        NativeIoOwner::create_at(parent_inputs(parent, "new-retry")?),
    );
    let observed = json!({"absolute_retry_rejected":old.0,"absolute_error":old.1,
        "held_retry_rejected":new.0,"held_error":new.1});
    write_json(&base.join("both-factories-claim-retries.json"), &observed)?;
    require(
        old.0
            && new.0
            && old.1.contains("claim already consumed")
            && new.1.contains("claim already consumed"),
        "one shared claim stays consumed after first failure",
    )?;
    require(
        names(base, "old-retry").iter().all(|p| !p.exists()),
        "rejected old factory made no roots",
    )?;
    require(
        (0..ROOT_COUNT).all(|i| !base.join("parent").join(format!("new-retry-{i}")).exists()),
        "rejected held factory made no roots",
    )?;
    Ok(observed)
}
fn negative_case(case: &str, base: &Path, state: &mut CaseState) -> Result<Value> {
    let parent_path = base.join("parent");
    private_dir(&parent_path)?;
    let parent = held_directory(&parent_path)?;
    let parent_id = identity(&parent.metadata()?);
    let protected = base.join("outside-bounded-roots");
    private_dir(&protected)?;
    let protected_file = protected.join("sentinel");
    sentinel(&protected_file, b"held-directory-negative-sentinel\n")?;
    let before = fs::symlink_metadata(&protected_file)?;
    let before_bytes = fs::read(&protected_file)?;
    let protected_id = identity(&held_directory(&protected)?.metadata()?);
    let mut inputs = parent_inputs(&parent, "root")?;
    match case {
        "nondirectory_parent_claim" => inputs[0].0 = File::open(&protected_file)?,
        "bad_basename_escape_claim" => inputs[0].1 = OsString::from("../escape-root"),
        "existing_symlink_claim" => symlink(&protected, parent_path.join("root-0"))?,
        _ => return Err(io::Error::other("negative case whitelist").into()),
    }
    let original_symlink = if case == "existing_symlink_claim" {
        Some((
            identity(&fs::symlink_metadata(parent_path.join("root-0"))?),
            fs::read_link(parent_path.join("root-0"))?,
        ))
    } else {
        None
    };
    let input_ids = inputs.iter().map(|(file, name)| {
        let m = file.metadata()?;
        Ok(json!({"device":m.dev(),"inode":m.ino(),"is_directory":m.is_dir(),"basename_bytes":basename_bytes(name)}))
    }).collect::<io::Result<Vec<Value>>>()?;
    write_json(&base.join("consumed-input-handles.json"), &input_ids)?;
    let rejected = reject(state, NativeIoOwner::create_at(inputs));
    let after = fs::symlink_metadata(&protected_file)?;
    let observed = json!({"case":case,"rejected":rejected.0,"error":rejected.1,
        "parent_before":parent_id,"parent_after":identity(&parent.metadata()?),
        "sentinel_before":[before.dev(),before.ino(),before.len()],
        "sentinel_after":[after.dev(),after.ino(),after.len()],
        "sentinel_before_bytes":before_bytes,"sentinel_after_bytes":fs::read(&protected_file)?,
        "protected_directory_before":protected_id,"protected_directory_after":identity(&held_directory(&protected)?.metadata()?),
        "original_symlink":original_symlink.as_ref().map(|(id,target)|json!({"identity":id,"target_bytes":basename_bytes(target.as_os_str())})),
        "after_symlink":if case == "existing_symlink_claim" {
            Some(json!({"identity":identity(&fs::symlink_metadata(parent_path.join("root-0"))?),"target_bytes":basename_bytes(fs::read_link(parent_path.join("root-0"))?.as_os_str())}))
        } else { None },
        "sentinel_bytes_unchanged":fs::read(&protected_file)? == before_bytes,
        "protected_entries":listing(&protected)?,"parent_entries":listing(&parent_path)?,
        "escape_entry_absent":!base.join("escape-root").exists(),
        "symlink_remains":fs::symlink_metadata(parent_path.join("root-0")).ok().is_some_and(|m| m.file_type().is_symlink())});
    write_json(&base.join("first-rejection-and-sentinel.json"), &observed)?;
    // Probe the consumed claim even if the first operation was incorrectly accepted.
    // Both error strings and any unexpectedly returned owners are retained first.
    let retries = consumed_retries(base, &parent, state)?;
    require(rejected.0, "invalid input unexpectedly returned an owner")?;
    if case == "nondirectory_parent_claim" {
        require(
            rejected.1.contains("held root parent is not a directory"),
            "actual handle type rejection",
        )?;
    } else if case == "bad_basename_escape_claim" {
        require(
            rejected.1.contains("one normal root basename required"),
            "actual one-basename rejection",
        )?;
    }
    require(
        identity(&after) == identity(&before) && after.len() == before.len(),
        "outside sentinel inode and length unchanged",
    )?;
    require(
        fs::read(&protected_file)? == before_bytes,
        "outside sentinel contents unchanged",
    )?;
    require(
        listing(&protected)? == vec![b"sentinel".to_vec()],
        "outside target directory unchanged",
    )?;
    require(
        identity(&held_directory(&protected)?.metadata()?) == protected_id,
        "outside target directory inode unchanged",
    )?;
    require(
        identity(&parent.metadata()?) == parent_id && !base.join("escape-root").exists(),
        "held parent and escape boundary",
    )?;
    if case == "existing_symlink_claim" {
        require(
            fs::symlink_metadata(parent_path.join("root-0"))?
                .file_type()
                .is_symlink(),
            "preexisting symlink not replaced",
        )?;
        let current = (
            identity(&fs::symlink_metadata(parent_path.join("root-0"))?),
            fs::read_link(parent_path.join("root-0"))?,
        );
        require(
            original_symlink.as_ref() == Some(&current),
            "original symlink inode and link target unchanged",
        )?;
        require(
            listing(&parent_path)? == vec![b"root-0".to_vec()],
            "no additional roots on existing symlink failure",
        )?;
    } else {
        require(
            listing(&parent_path)?.is_empty(),
            "no root created before first invalid handle/name rejection",
        )?;
    }
    Ok(
        json!({"rejection":observed,"claim_retries":retries,"outside_means_owned_fixture_outside_seven_roots":true}),
    )
}

fn positive_case(base: &Path, state: &mut CaseState) -> Result<Value> {
    let original = base.join("parent");
    let renamed = base.join("renamed-parent");
    let renamed_again = base.join("renamed-again-parent");
    private_dir(&original)?;
    let held = held_directory(&original)?;
    let held_id = identity(&held.metadata()?);
    let inputs = parent_inputs(&held, "root")?;
    let input_ids = inputs
        .iter()
        .map(|(file, name)| {
            let m = file.metadata()?;
            Ok(json!({"device":m.dev(),"inode":m.ino(),"basename_bytes":basename_bytes(name)}))
        })
        .collect::<io::Result<Vec<Value>>>()?;
    write_json(&base.join("consumed-input-handles.json"), &input_ids)?;
    // The actual pathname attack occurs after all seven File values are opened.
    fs::rename(&original, &renamed)?;
    private_dir(&original)?;
    sentinel(
        &original.join("replacement-sentinel"),
        b"replacement must not receive roots\n",
    )?;
    let replacement_id = identity(&held_directory(&original)?.metadata()?);
    require(
        replacement_id != held_id,
        "replacement must be a different real inode",
    )?;
    let owner = NativeIoOwner::create_at(inputs)?;
    state.owners.push(owner);
    let owner = &state.owners[0];
    let initial = owner.receipts()?;
    write_json(&base.join("initial-seven-roots.json"), &initial)?;
    require(initial.len() == ROOT_COUNT, "seven actual roots")?;
    let mut identities = BTreeSet::new();
    let mut actual_roots = Vec::new();
    for (index, receipt) in initial.iter().enumerate() {
        healthy(receipt)?;
        let actual = held_directory(&renamed.join(format!("root-{index}")))?.metadata()?;
        require(
            identity(&actual) == (receipt.root_device, receipt.root_inode),
            "created child lies under original held inode",
        )?;
        require(
            actual.mode() & 0o077 == 0 && actual.uid() == held.metadata()?.uid(),
            "private original owned child",
        )?;
        require(
            !original.join(format!("root-{index}")).exists(),
            "no root in replacement pathname",
        )?;
        identities.insert(identity(&actual));
        actual_roots.push(json!({"root_index":index,"device":actual.dev(),"inode":actual.ino(),"mode":actual.mode(),"uid":actual.uid()}));
    }
    require(
        identities.len() == ROOT_COUNT,
        "seven distinct actual root inodes",
    )?;
    write_json(
        &base.join("rename-and-real-root-identities.json"),
        &json!({
        "held_parent_before":held_id,"held_parent_after":identity(&held.metadata()?),
        "renamed_path_parent":identity(&held_directory(&renamed)?.metadata()?),
        "replacement_parent":replacement_id,"roots":actual_roots,
        "replacement_entries":listing(&original)?}),
    )?;
    require(
        identity(&held.metadata()?) == held_id,
        "held parent survives rename",
    )?;
    require(
        listing(&original)? == vec![b"replacement-sentinel".to_vec()],
        "replacement path untouched",
    )?;
    let lease = owner.lease(0)?;
    let cold_lease = lease.clone();
    let db_path = lease.directory().join("native.sqlite");
    let writer = lease.open(&db_path, rw_flags())?;
    writer.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; CREATE TABLE t(id INTEGER PRIMARY KEY,v TEXT NOT NULL); INSERT INTO t VALUES(1,'actual-parent');")?;
    require(!writer.is_readonly(MAIN_DB)?, "real writer")?;
    require(
        writer.query_row::<i64, _, _>("PRAGMA page_size", [], |r| r.get(0))? == 4096,
        "ordinary unchanged 4KiB profile",
    )?;
    require(
        writer.query_row::<i64, _, _>("PRAGMA synchronous", [], |r| r.get(0))? == 2,
        "original FULL synchronous",
    )?;
    require(
        writer.query_row::<String, _, _>("PRAGMA journal_mode", [], |r| r.get(0))? == "wal",
        "actual WAL mode",
    )?;
    let reader = lease.open(
        &db_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    require(
        reader.is_readonly(MAIN_DB)?,
        "real OS-readonly SQLite connection",
    )?;
    require(
        reader.db_config(DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE)?,
        "readonly close config retained",
    )?;
    reader.execute_batch("PRAGMA query_only=ON;")?;
    require(
        reader.query_row::<i64, _, _>("PRAGMA query_only", [], |r| r.get(0))? == 1,
        "actual readonly query-only policy",
    )?;
    require(
        reader.query_row::<String, _, _>("SELECT v FROM t WHERE id=1", [], |r| r.get(0))?
            == "actual-parent",
        "actual readonly parent read",
    )?;
    writer.execute("INSERT INTO t VALUES(2,'actual-upgrade')", [])?;
    require(
        reader.query_row::<i64, _, _>("SELECT count(*) FROM t", [], |r| r.get(0))? == 2,
        "readonly sees real committed upgrade",
    )?;
    let concurrent = snapshot(base, "writer-and-readonly-live", &lease)?;
    let db_id = actual_named(&lease, &concurrent, "native.sqlite")?;
    actual_named(&lease, &concurrent, "native.sqlite-wal")?;
    actual_named(&lease, &concurrent, "native.sqlite-shm")?;
    require(
        concurrent
            .objects
            .iter()
            .any(|o| o.basename == "native.sqlite" && o.handles == 2),
        "two actual main handles",
    )?;
    require(
        concurrent
            .objects
            .iter()
            .any(|o| o.basename == "native.sqlite-shm" && o.shm_references >= 2),
        "two real WAL mapping references",
    )?;
    // Exercise writer-first / readonly-last close; no reset, checkpoint bypass,
    // ledger drain, changed flags or successful-error reinterpretation.
    drop(writer);
    drop(reader);
    let no_connections = snapshot(base, "all-original-connections-closed", &lease)?;
    closed(&no_connections)?;
    // The same root/lease must survive another real ancestor path replacement.
    fs::rename(&renamed, &renamed_again)?;
    private_dir(&renamed)?;
    sentinel(
        &renamed.join("second-replacement-sentinel"),
        b"cold reopen must use original root FD\n",
    )?;
    let second_replacement_id = identity(&held_directory(&renamed)?.metadata()?);
    require(
        second_replacement_id != held_id && identity(&held.metadata()?) == held_id,
        "second actual replacement identity",
    )?;
    drop(lease);
    let cold = cold_lease.open(&cold_lease.directory().join("native.sqlite"), rw_flags())?;
    require(
        cold.query_row::<i64, _, _>("SELECT count(*) FROM t", [], |r| r.get(0))? == 2,
        "durable cold row count",
    )?;
    require(
        cold.query_row::<String, _, _>("SELECT v FROM t WHERE id=2", [], |r| r.get(0))?
            == "actual-upgrade",
        "durable cold upgraded value",
    )?;
    let reopened = snapshot(base, "same-lease-cold-live", &cold_lease)?;
    require(
        actual_named(&cold_lease, &reopened, "native.sqlite")? == db_id,
        "same original database inode after cold reopen",
    )?;
    require(
        reopened.retained_logical_bytes_peak >= concurrent.retained_logical_bytes_peak,
        "original peak did not reset",
    )?;
    require(
        reopened.lifecycle.len() >= no_connections.lifecycle.len()
            && reopened.cleanup_lifecycle.len() >= no_connections.cleanup_lifecycle.len(),
        "lifecycle lengths did not rewind",
    )?;
    require(
        serde_json::to_value(&reopened.lifecycle[..no_connections.lifecycle.len()])?
            == serde_json::to_value(&no_connections.lifecycle)?,
        "original lifecycle prefix retained",
    )?;
    require(
        serde_json::to_value(
            &reopened.cleanup_lifecycle[..no_connections.cleanup_lifecycle.len()],
        )? == serde_json::to_value(&no_connections.cleanup_lifecycle)?,
        "original cleanup prefix retained",
    )?;
    drop(cold);
    let final_root = snapshot(base, "same-lease-cold-closed", &cold_lease)?;
    closed(&final_root)?;
    let final_all = owner.receipts()?;
    let mut second_actual_roots = Vec::new();
    for (index, receipt) in final_all.iter().enumerate() {
        let actual = held_directory(&renamed_again.join(format!("root-{index}")))?.metadata()?;
        require(
            identity(&actual) == (receipt.root_device, receipt.root_inode),
            "all seven roots still beneath original held parent",
        )?;
        second_actual_roots.push(json!({"index":index,"device":actual.dev(),"inode":actual.ino()}));
    }
    write_json(
        &base.join("second-rename-and-cold-identities.json"),
        &json!({
        "held_parent":identity(&held.metadata()?),"original_parent":held_id,
        "actual_parent_at_final_path":identity(&held_directory(&renamed_again)?.metadata()?),
        "second_replacement":second_replacement_id,"roots":second_actual_roots,
        "first_replacement_entries":listing(&original)?,"second_replacement_entries":listing(&renamed)?,
        "same_database_inode":db_id,"all_original_connections_closed_before_reopen":true}),
    )?;
    require(
        listing(&original)? == vec![b"replacement-sentinel".to_vec()]
            && listing(&renamed)? == vec![b"second-replacement-sentinel".to_vec()],
        "both replacement paths untouched through cold reopen",
    )?;
    require(
        fs::read(original.join("replacement-sentinel"))? == b"replacement must not receive roots\n",
        "first replacement sentinel contents",
    )?;
    require(
        fs::read(renamed.join("second-replacement-sentinel"))?
            == b"cold reopen must use original root FD\n",
        "second replacement sentinel contents",
    )?;
    Ok(
        json!({"consumed_parent_files":7,"actual_parent_inode":held_id,"replacement_parent_inode":replacement_id,
        "second_replacement_parent_inode":second_replacement_id,"database_inode":db_id,
        "cold_reopen_same_lease":true,"cold_means_all_SQLite_connections_closed":true,
        "OS_page_cache_cold_claimed":false,"real_readonly_connection":true,"page_size":4096,"synchronous":2,
        "all_seven_roots_beneath_original_held_inode":true,"new_W1_proofs":0}),
    )
}

fn finalize(base: &Path, state: &CaseState, expected_owners: usize) -> Vec<String> {
    let mut errors = Vec::new();
    let mut rows = Vec::new();
    if state.owners.len() != expected_owners {
        errors.push(format!(
            "actual owners {} != expected {expected_owners}",
            state.owners.len()
        ));
    }
    for (index, owner) in state.owners.iter().enumerate() {
        match owner.receipts() {
            Ok(receipts) => {
                if receipts.len() != ROOT_COUNT {
                    errors.push(format!("owner {index} root count"));
                }
                for (root, receipt) in receipts.iter().enumerate() {
                    if let Err(error) = closed(receipt) {
                        errors.push(format!("owner {index} root {root}: {error}"));
                    }
                }
                rows.push(json!({"owner_index":index,"receipts":receipts}));
            }
            Err(error) => errors.push(format!(
                "owner {index} actual receipts unavailable: {error}"
            )),
        }
    }
    if let Err(error) = write_json(
        &base.join("final-owned-roots.json"),
        &json!({
        "actual_owner_count":state.owners.len(),"expected_owner_count":expected_owners,
        "owners":rows,"errors":errors,"missing_receipts_are_failures":true,
        "published_root_FDs_remain_held_until_actual_process_terminal":true}),
    ) {
        errors.push(format!("persist actual finalization: {error}"));
    }
    errors
}
fn tick(pid: u32) -> Option<String> {
    let raw = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    Some(
        raw.rsplit_once(')')?
            .1
            .split_whitespace()
            .nth(19)?
            .to_owned(),
    )
}
fn inherited_limits(base: &Path) -> Result<()> {
    let raw = fs::read_to_string("/proc/self/limits")?;
    write_json(
        &base.join("actual-inherited-process-limits.json"),
        &json!({"raw_proc_self_limits":raw,
        "required_AS_bytes":3_u64*1024*1024*1024,"required_FSIZE_bytes":16_u64*1024*1024,
        "cgroup_CPU_memory_nice_and_total_disk_must_be_independently_collected":true}),
    )?;
    for (name, expected) in [
        ("Max address space", "3221225472"),
        ("Max file size", "16777216"),
    ] {
        let line = raw
            .lines()
            .find_map(|line| line.strip_prefix(name))
            .ok_or_else(|| io::Error::other("required inherited limit missing"))?;
        let fields = line.split_whitespace().collect::<Vec<_>>();
        require(
            fields.len() == 3
                && fields[0] == expected
                && fields[1] == expected
                && fields[2] == "bytes",
            "original hard and soft inherited resource limit",
        )?;
    }
    Ok(())
}

struct OwnedChild {
    process: Child,
    original_tick: Option<String>,
    waited: bool,
}
impl Drop for OwnedChild {
    fn drop(&mut self) {
        if !self.waited {
            // Only our direct unreaped Child is ever signalled or waited here.
            // A missing persisted terminal remains FAIL; Drop creates no receipt.
            let _ = self.process.kill();
            let _ = self.process.wait();
        }
    }
}

#[test]
#[ignore = "reviewed finite held-FD control only; fresh external evidence directory and original limits required"]
fn finite_native_held_directory_controls_v1() -> Result<()> {
    let base = PathBuf::from(
        std::env::var_os("TRNM_PN1_HELD_V1_DIR")
            .ok_or_else(|| io::Error::other("explicit fresh owned output directory"))?,
    );
    require(base.is_absolute(), "absolute output path")?;
    private_dir(&base)?;
    inherited_limits(&base)?;
    let executable = File::open("/proc/self/exe")?;
    let binary = executable.metadata()?;
    let whole_start = Instant::now();
    let mut terminals = Vec::new();
    for case in CASES {
        require(
            whole_start.elapsed() < Duration::from_secs(WHOLE_SECONDS),
            "original whole 300-second finite deadline",
        )?;
        let directory = base.join(case);
        private_dir(&directory)?;
        let stream = |name| {
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(directory.join(name))
        };
        let child = Command::new(format!("/proc/self/fd/{}", executable.as_raw_fd()))
            .args([
                "native_held_directory_v1_case_child",
                "--exact",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("TRNM_PN1_HELD_V1_CASE", case)
            .env("TRNM_PN1_HELD_V1_CASE_DIR", &directory)
            .env("TRNM_PN1_HELD_V1_EXE_DEV", binary.dev().to_string())
            .env("TRNM_PN1_HELD_V1_EXE_INO", binary.ino().to_string())
            .env("RUST_BACKTRACE", "0")
            .stdout(Stdio::from(stream("child.stdout")?))
            .stderr(Stdio::from(stream("child.stderr")?))
            .spawn()?;
        let pid = child.id();
        let mut child = OwnedChild {
            process: child,
            original_tick: tick(pid),
            waited: false,
        };
        let start = Instant::now();
        let mut admitted = false;
        let mut timed_out = false;
        let mut controller_error = None;
        loop {
            if child.process.try_wait()?.is_some() {
                break;
            }
            if !admitted {
                if let Some(ready) = read_json(&directory.join("child-start.json")) {
                    let observed = tick(pid);
                    let valid = ready["pid"].as_u64() == Some(u64::from(pid))
                        && ready["case"].as_str() == Some(case)
                        && ready["executable_dev"].as_u64() == Some(binary.dev())
                        && ready["executable_ino"].as_u64() == Some(binary.ino())
                        && observed.is_some()
                        && child.original_tick == observed
                        && ready["kernel_start_tick"].as_str() == observed.as_deref();
                    if !valid {
                        controller_error = Some("actual child identity binding failed".to_owned());
                        child.process.kill()?;
                        break;
                    }
                    write_json(
                        &directory.join("parent-go.json"),
                        &json!({"pid":pid,"kernel_start_tick":observed}),
                    )?;
                    admitted = true;
                }
            }
            if start.elapsed() > Duration::from_secs(CASE_SECONDS)
                || whole_start.elapsed() > Duration::from_secs(WHOLE_SECONDS)
            {
                timed_out = true;
                child.process.kill()?;
                break;
            }
            thread::sleep(Duration::from_millis(5));
        }
        let status = child.process.wait()?;
        child.waited = true;
        let same_identity_alive = child
            .original_tick
            .as_ref()
            .is_some_and(|original| tick(pid).as_ref() == Some(original));
        let result = read_json(&directory.join("case-result.json"));
        let row = json!({"case":case,"pid":pid,"kernel_start_tick":child.original_tick,
            "alive_and_bound_before_release":admitted,"wait_completed":true,
            "exit_code":status.code(),"success":status.success(),"timed_out":timed_out,
            "original_PID_identity_alive_after_wait":same_identity_alive,
            "controller_error":controller_error,"elapsed_ns":start.elapsed().as_nanos(),
            "case_receipt_present":result.is_some(),"case_result_ok":result.as_ref().and_then(|v|v["ok"].as_bool()),
            "CPU_wait4_measurement_claimed":false});
        write_json(&directory.join("parent-observed-terminal.json"), &row)?;
        terminals.push(row);
    }
    write_json(
        &base.join("all-planned-child-terminals.json"),
        &json!({
        "schema":"pn1-native-held-directory-controls-v1","planned_cases":CASES,"terminals":terminals,
        "original_case_seconds":CASE_SECONDS,"original_whole_seconds":WHOLE_SECONDS,
        "full_W1_4097_qualified":false,"Node_AuthenticatedV1_requalified":false,
        "full_campaign_held_FD_bridge_implemented":false,"component_only":true}),
    )?;
    require(
        terminals.len() == CASES.len()
            && terminals.iter().all(|row| {
                row["alive_and_bound_before_release"] == true
                    && row["wait_completed"] == true
                    && row["exit_code"] == 0
                    && row["success"] == true
                    && row["timed_out"] == false
                    && row["original_PID_identity_alive_after_wait"] == false
                    && row["controller_error"].is_null()
                    && row["case_result_ok"] == true
            }),
        "one or more real held-directory controls failed; preserve all artifacts",
    )
}

#[test]
#[ignore = "fresh-process child selected only by the reviewed finite held-directory controller"]
fn native_held_directory_v1_case_child() -> Result<()> {
    let case = std::env::var("TRNM_PN1_HELD_V1_CASE")?;
    require(CASES.contains(&case.as_str()), "four-case child whitelist")?;
    let base = PathBuf::from(
        std::env::var_os("TRNM_PN1_HELD_V1_CASE_DIR")
            .ok_or_else(|| io::Error::other("explicit child directory"))?,
    );
    require(base.is_absolute(), "absolute child directory")?;
    let executable = fs::metadata("/proc/self/exe")?;
    require(
        executable.dev().to_string() == std::env::var("TRNM_PN1_HELD_V1_EXE_DEV")?
            && executable.ino().to_string() == std::env::var("TRNM_PN1_HELD_V1_EXE_INO")?,
        "actual child executable identity",
    )?;
    let pid = std::process::id();
    let original_tick = tick(pid).ok_or_else(|| io::Error::other("actual child start tick"))?;
    write_json(
        &base.join("child-start.json"),
        &json!({"case":case,"pid":pid,
        "kernel_start_tick":original_tick,"executable_dev":executable.dev(),"executable_ino":executable.ino()}),
    )?;
    let wait_start = Instant::now();
    let go = loop {
        if let Some(go) = read_json(&base.join("parent-go.json")) {
            break go;
        }
        require(
            wait_start.elapsed() < Duration::from_secs(CASE_SECONDS),
            "original child admission deadline",
        )?;
        thread::sleep(Duration::from_millis(5));
    };
    require(
        go["pid"].as_u64() == Some(u64::from(pid))
            && go["kernel_start_tick"].as_str() == Some(original_tick.as_str()),
        "parent release identity",
    )?;
    let mut state = CaseState::default();
    let work = catch_unwind(AssertUnwindSafe(|| -> Result<Value> {
        inherited_limits(&base)?;
        require(
            ROOT_COUNT == 7
                && OBJECTS_PER_ROOT == 3
                && FILE_BYTES == 16 * 1024 * 1024
                && DOMAIN_BYTES == 336 * 1024 * 1024,
            "original immutable resource partition",
        )?;
        if case == CASES[0] {
            positive_case(&base, &mut state)
        } else {
            negative_case(&case, &base, &mut state)
        }
    }));
    // All work-only connection locals have dropped before this unconditional snapshot.
    let finalization_errors = finalize(&base, &state, usize::from(case == CASES[0]));
    let (observation, error, work_panic) = match work {
        Ok(Ok(value)) => (Some(value), None, false),
        Ok(Err(error)) => (None, Some(error.to_string()), false),
        Err(payload) => {
            let message = payload
                .downcast_ref::<&str>()
                .map(|s| (*s).to_owned())
                .or_else(|| payload.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "non-string panic".to_owned());
            (None, Some(message), true)
        }
    };
    let ok = error.is_none() && !work_panic && finalization_errors.is_empty();
    write_json(
        &base.join("case-result.json"),
        &json!({
        "schema":"pn1-native-held-directory-case-v1","case":case,"pid":pid,
        "kernel_start_tick":original_tick,"ok":ok,"work_panic":work_panic,
        "error":error,"observed":observation,"finalization_errors":finalization_errors,
        "component_only":true,"full_guard_enabled":false,"full_W1_4097_qualified":false,
        "Node_AuthenticatedV1_requalified":false,"full_campaign_held_FD_bridge_implemented":false}),
    )?;
    require(
        ok,
        "real held-directory case failed; raw failure and final roots retained",
    )?;
    println!("finite-native-held-directory-case-complete {case}");
    Ok(())
}
