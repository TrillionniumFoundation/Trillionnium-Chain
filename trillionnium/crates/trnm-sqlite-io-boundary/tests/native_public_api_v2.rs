//! Proposed Linux-only finite native public-API controls v2. NOT BUILT / NOT RUN.
//! Intended destination, only after review: trnm-sqlite-io-boundary/tests/native_public_api_v2.rs.
//! No Node, W1 work, sockets, private hooks, static resets or process-default-VFS opens.
#![cfg(target_os = "linux")]
#![forbid(unsafe_code)]

use rusqlite::{params, OpenFlags, TransactionBehavior};
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use trnm_sqlite_io_boundary::{
    registered_receipt, NativeIoLease, NativeIoOwner, RootReceipt, DOMAIN, DOMAIN_BYTES,
    FILE_BYTES, OBJECTS_PER_ROOT, ROOT_COUNT,
};

const CASES: [&str; 10] = [
    "rollback_to_wal",
    "multiple_connections",
    "same_lease_cold_reopen",
    "real_file_cap_sticky",
    "attach_uri_path_refusals",
    "memory_real_deleted_temp",
    "memory_drop_order",
    "disk_drop_order",
    "failed_owner_claim_consumed",
    "bare_named_memory_permanent_registration",
];
const CASE_SECONDS: u64 = 30; // New finite controller only; never a W1 call/pressure limit.
const JSON_BYTES: usize = 2 * 1024 * 1024;

// Even a controller assertion/metadata I/O panic must not abandon this stage's child.
// A missing failure terminal is still FAIL; Drop does not manufacture a persisted receipt.
struct OwnedChild {
    process: Child,
    original_tick: Option<String>,
    waited: bool,
}
impl Drop for OwnedChild {
    fn drop(&mut self) {
        if !self.waited {
            if self
                .original_tick
                .as_ref()
                .is_some_and(|t| tick(self.process.id()).as_ref() == Some(t))
            {
                let _ = self.process.kill();
            }
            let _ = self.process.wait();
        }
    }
}
fn read_complete_json(path: &Path) -> Option<Value> {
    let raw = fs::read(path).ok()?;
    if raw.len() >= JSON_BYTES {
        return None;
    }
    serde_json::from_slice(&raw).ok()
}

fn private_dir(path: &Path) {
    DirBuilder::new()
        .mode(0o700)
        .create(path)
        .expect("fresh owned directory");
}
fn write_json(path: &Path, value: &impl Serialize) {
    let raw = serde_json::to_vec_pretty(value).expect("serialize actual observation");
    assert!(
        raw.len() < JSON_BYTES,
        "finite observation exceeds declared metadata cap"
    );
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .expect("create-only observation; preserve any previous file");
    file.write_all(&raw).expect("write observation");
    file.write_all(b"\n").expect("write newline");
    file.sync_all().expect("persist finite observation");
}
fn fresh_paths(base: &Path, prefix: &str) -> [PathBuf; ROOT_COUNT] {
    std::array::from_fn(|index| base.join(format!("{prefix}-{index}")))
}
fn flags() -> OpenFlags {
    OpenFlags::SQLITE_OPEN_READ_WRITE
        | OpenFlags::SQLITE_OPEN_CREATE
        | OpenFlags::SQLITE_OPEN_NO_MUTEX
}
fn owner(base: &Path) -> NativeIoOwner {
    assert_eq!(ROOT_COUNT, 7);
    assert_eq!(OBJECTS_PER_ROOT, 3);
    assert_eq!(FILE_BYTES, 16 * 1024 * 1024);
    assert_eq!(DOMAIN_BYTES, 336 * 1024 * 1024);
    let value = NativeIoOwner::create(fresh_paths(base, "root")).expect("one fresh owner");
    let receipts = value.receipts().expect("all seven actual roots");
    assert_eq!(receipts.len(), ROOT_COUNT);
    let ids: BTreeSet<_> = receipts
        .iter()
        .map(|r| (r.root_device, r.root_inode))
        .collect();
    assert_eq!(
        ids.len(),
        ROOT_COUNT,
        "seven distinct real directory inodes"
    );
    write_json(&base.join("initial-seven-roots.json"), &receipts);
    value
}
fn validate(receipt: &RootReceipt) {
    assert_eq!(receipt.schema, DOMAIN);
    assert_eq!(receipt.owner_pid, std::process::id());
    assert_eq!(receipt.logical_bytes_limit, 3 * FILE_BYTES);
    assert_eq!(receipt.retained_object_limit, 3);
    assert!(receipt.objects.len() <= 3 && receipt.retained_objects_peak <= 3);
    assert!(receipt.high_water_sum <= 3 * FILE_BYTES);
    assert!(receipt.retained_logical_bytes_peak <= 3 * FILE_BYTES);
    assert!(
        !receipt.allocated_blocks_hard_cap_implemented,
        "logical inode-length boundary must not be relabelled a physical-block quota"
    );
    assert!(
        receipt.lifecycle_complete,
        "missing lifecycle evidence is not a finite pass"
    );
    assert!(receipt.lifecycle_serialized_bytes <= receipt.lifecycle_serialized_bytes_cap);
    assert!(receipt
        .objects
        .iter()
        .all(|o| o.high_water_bytes <= FILE_BYTES && o.actual_last_bytes <= FILE_BYTES));
    let ids: BTreeSet<_> = receipt
        .objects
        .iter()
        .filter_map(|o| o.device.zip(o.inode))
        .collect();
    assert_eq!(
        ids.len(),
        receipt
            .objects
            .iter()
            .filter(|o| o.device.is_some())
            .count()
    );
}
fn snapshot(base: &Path, label: &str, lease: &NativeIoLease) -> RootReceipt {
    let receipt = lease.receipt().expect("actual root receipt");
    write_json(&base.join(format!("{label}.json")), &receipt); // Retain before assertions.
    validate(&receipt);
    assert_eq!((receipt.root_device, receipt.root_inode), lease.identity());
    receipt
}
fn healthy(receipt: &RootReceipt) {
    assert!(!receipt.failed && receipt.first_failure.is_none());
    assert!(receipt.first_failure_sqlite_code.is_none());
    assert_eq!(receipt.quarantined_actual_states, 0);
}
fn closed(receipt: &RootReceipt) {
    assert!(
        receipt
            .objects
            .iter()
            .all(|o| o.handles == 0 && o.pending_opens == 0 && o.shm_references == 0),
        "actual handles/mappings must close before their charge is released"
    );
    assert_eq!(
        receipt.quarantined_actual_states, 0,
        "unknown lower close is not a healthy close pass"
    );
}
fn actual_named(lease: &NativeIoLease, receipt: &RootReceipt, name: &str) {
    let o = receipt
        .objects
        .iter()
        .find(|o| o.basename == name)
        .expect("retained named object");
    let m = fs::symlink_metadata(lease.directory().join(name)).expect("actual named inode");
    assert!(m.is_file() && !m.file_type().is_symlink());
    assert_eq!(o.device.zip(o.inode), Some((m.dev(), m.ino())));
    assert_eq!(o.actual_last_bytes, m.len());
    assert!(m.len() <= FILE_BYTES && m.nlink() == 1 && o.linked);
}
fn open(lease: &NativeIoLease) -> trnm_sqlite_io_boundary::OwnedConnection {
    lease
        .open(&lease.directory().join("native.sqlite"), flags())
        .expect("bounded real SQLite open")
}
fn tick(pid: u32) -> Option<String> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    Some(
        stat.rsplit_once(')')?
            .1
            .split_whitespace()
            .nth(19)?
            .to_owned(),
    )
}
fn actual_fds() -> Vec<Value> {
    fs::read_dir("/proc/self/fd")
        .expect("owned-process FD observation")
        .filter_map(|entry| {
            let p = entry.ok()?.path();
            let m = fs::metadata(&p).ok()?; // Enumeration's already-closed FD is not a target match.
            Some(
                json!({"fd":p.file_name()?.to_str()?,"dev":m.dev(),"ino":m.ino(),
            "length":m.len(),"links":m.nlink(),"regular":m.is_file()}),
            )
        })
        .collect()
}
fn fd_has(rows: &[Value], dev: u64, ino: u64) -> bool {
    rows.iter()
        .any(|x| x["dev"].as_u64() == Some(dev) && x["ino"].as_u64() == Some(ino))
}
fn rollback_to_wal(base: &Path) -> Value {
    let owner = owner(base);
    let lease = owner.lease(0).unwrap();
    let mut db = open(&lease);
    let page: i64 = db.query_row("PRAGMA page_size", [], |r| r.get(0)).unwrap();
    assert_eq!(
        page, 4096,
        "ordinary default-page control; full Node profile not changed"
    );
    db.execute_batch(
        "PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL;
        CREATE TABLE t(id INTEGER PRIMARY KEY, v TEXT NOT NULL); INSERT INTO t VALUES(1,'parent');",
    )
    .unwrap();
    {
        let tx = db.transaction().unwrap();
        tx.execute("UPDATE t SET v='uncommitted'", []).unwrap();
        let r = snapshot(base, "rollback-journal-live", &lease);
        healthy(&r);
        actual_named(&lease, &r, "native.sqlite-journal");
        assert!(r
            .objects
            .iter()
            .any(|o| o.basename == "native.sqlite-journal" && o.handles > 0));
        tx.rollback().unwrap();
    }
    assert_eq!(
        db.query_row::<String, _, _>("SELECT v FROM t", [], |r| r.get(0))
            .unwrap(),
        "parent"
    );
    {
        let tx = db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        tx.execute("INSERT INTO t VALUES(2,'committed')", [])
            .unwrap();
        tx.commit().unwrap();
    }
    {
        let mut save = db.savepoint_with_name("public_proxy").unwrap();
        save.execute("DELETE FROM t WHERE id=2", []).unwrap();
        save.rollback().unwrap();
        save.commit().unwrap();
    }
    {
        let save = db.savepoint().unwrap();
        save.execute("INSERT INTO t VALUES(3,'saved')", []).unwrap();
        save.commit().unwrap();
    }
    let mode: String = db
        .query_row("PRAGMA journal_mode=WAL", [], |r| r.get(0))
        .unwrap();
    assert_eq!(mode, "wal");
    db.execute("UPDATE t SET v='wal-parent' WHERE id=1", [])
        .unwrap();
    let r = snapshot(base, "wal-and-shm-live", &lease);
    healthy(&r);
    for name in ["native.sqlite", "native.sqlite-wal", "native.sqlite-shm"] {
        actual_named(&lease, &r, name);
    }
    assert!(r
        .objects
        .iter()
        .any(|o| o.basename == "native.sqlite-shm" && o.shm_references > 0));
    assert_eq!(
        db.query_row::<i64, _, _>("SELECT count(*) FROM t", [], |r| r.get(0))
            .unwrap(),
        3
    );
    drop(db);
    let end = snapshot(base, "connection-closed", &lease);
    healthy(&end);
    closed(&end);
    json!({"page_size":page,"rollback_then_wal":true,"rows":3})
}
fn multiple_connections(base: &Path) -> Value {
    let owner = owner(base);
    let lease = owner.lease(0).unwrap();
    let writer = open(&lease);
    writer
        .execute_batch(
            "PRAGMA journal_mode=WAL; CREATE TABLE t(x INTEGER); INSERT INTO t VALUES(1);",
        )
        .unwrap();
    let mut reader = open(&lease);
    let tx = reader.transaction().unwrap();
    assert_eq!(
        tx.query_row::<i64, _, _>("SELECT count(*) FROM t", [], |r| r.get(0))
            .unwrap(),
        1
    );
    writer.execute("INSERT INTO t VALUES(2)", []).unwrap();
    assert_eq!(
        tx.query_row::<i64, _, _>("SELECT count(*) FROM t", [], |r| r.get(0))
            .unwrap(),
        1
    );
    let both = snapshot(base, "two-connections-and-live-read-snapshot", &lease);
    healthy(&both);
    let refs = both
        .objects
        .iter()
        .find(|o| o.basename == "native.sqlite-shm")
        .unwrap()
        .shm_references;
    assert!(refs >= 2);
    assert_eq!(
        both.objects
            .iter()
            .find(|o| o.basename == "native.sqlite")
            .unwrap()
            .handles,
        2
    );
    actual_named(&lease, &both, "native.sqlite-shm");
    tx.commit().unwrap();
    drop(reader);
    let one = snapshot(base, "reader-really-closed", &lease);
    healthy(&one);
    assert_eq!(
        one.objects
            .iter()
            .find(|o| o.basename == "native.sqlite")
            .unwrap()
            .handles,
        1
    );
    assert!(
        one.objects
            .iter()
            .find(|o| o.basename == "native.sqlite-shm")
            .unwrap()
            .shm_references
            < refs
    );
    assert_eq!(
        writer
            .query_row::<i64, _, _>("SELECT sum(x) FROM t", [], |r| r.get(0))
            .unwrap(),
        3
    );
    drop(writer);
    let end = snapshot(base, "last-close-and-unmap", &lease);
    healthy(&end);
    closed(&end);
    assert!(end
        .cleanup_lifecycle
        .iter()
        .any(|e| e.action == "underlying-shm-unmap" && e.shm_references == 0));
    json!({"snapshot_read_rows":1,"final_sum":3,"two_actual_connections":true})
}
fn same_lease_cold_reopen(base: &Path) -> Value {
    let owner = owner(base);
    let lease = owner.lease(0).unwrap();
    let cold = lease.clone();
    let identity = lease.identity();
    let db = open(&lease);
    db.execute_batch("PRAGMA journal_mode=WAL; CREATE TABLE t(v TEXT); INSERT INTO t VALUES('real-parent-version');").unwrap();
    let before = snapshot(base, "before-cold-close", &lease);
    healthy(&before);
    drop(db);
    let no_connections = snapshot(base, "all-original-connections-closed", &lease);
    closed(&no_connections);
    healthy(&no_connections);
    drop(lease);
    let db = open(&cold);
    assert_eq!(cold.identity(), identity);
    assert_eq!(
        db.query_row::<String, _, _>("SELECT v FROM t", [], |r| r.get(0))
            .unwrap(),
        "real-parent-version"
    );
    let after = snapshot(base, "same-lease-cold-readback", &cold);
    healthy(&after);
    assert!(after.retained_logical_bytes_peak >= before.retained_logical_bytes_peak);
    drop(db);
    let end = snapshot(base, "cold-close", &cold);
    closed(&end);
    healthy(&end);
    json!({"same_lease_identity":identity,"cold_readback":"real-parent-version","cold_means_all_SQLite_connections_closed":true})
}
fn real_file_cap_sticky(base: &Path) -> Value {
    let owner = owner(base);
    let lease = owner.lease(0).unwrap();
    let db = open(&lease);
    // Independent finite file-cap profile. Never alters the original Node's default page size.
    db.execute_batch("PRAGMA page_size=65536; PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; CREATE TABLE payload(v BLOB);").unwrap();
    assert_eq!(
        db.query_row::<i64, _, _>("PRAGMA page_size", [], |r| r.get(0))
            .unwrap(),
        65536
    );
    let error = db
        .execute(
            "INSERT INTO payload VALUES(zeroblob(?1))",
            params![FILE_BYTES as i64],
        )
        .expect_err("real SQLite growth must exceed16MiB and refuse");
    let failed = snapshot(base, "actual-cap-first-failure", &lease);
    write_json(
        &base.join("actual-sqlite-write-error.json"),
        &json!({"error":error.to_string(),"insert_blob_bytes":FILE_BYTES,"page_size":65536}),
    );
    assert!(failed.failed);
    assert_eq!(
        failed.first_failure.as_deref(),
        Some("pre-growth inode length cap")
    );
    assert_eq!(failed.first_failure_sqlite_code, Some(13)); // SQLITE_FULL, not an evidence/slot cap.
    assert!(failed
        .objects
        .iter()
        .any(|o| o.basename == "native.sqlite" && o.high_water_bytes == FILE_BYTES));
    assert!(failed
        .lifecycle
        .iter()
        .any(|e| e.basename == "native.sqlite" && e.actual_last_bytes > 0));
    assert!(db
        .execute("INSERT INTO payload VALUES(zeroblob(65536))", [])
        .is_err());
    assert!(lease
        .open(&lease.directory().join("native.sqlite"), flags())
        .is_err());
    // Explicit frozen safe-factory contract now denies new memory factories on a failed root too.
    assert!(lease.open_in_memory().is_err());
    if let Ok(second) = owner.lease(0) {
        assert!(second
            .open(&second.directory().join("native.sqlite"), flags())
            .is_err());
    }
    let sticky = snapshot(base, "cap-stays-latched", &lease);
    assert_eq!(sticky.first_failure, failed.first_failure);
    assert_eq!(
        sticky.first_failure_sqlite_code,
        failed.first_failure_sqlite_code
    );
    assert!(sticky.failed);
    drop(db);
    let end = snapshot(base, "cap-error-after-real-close", &lease);
    closed(&end);
    assert_eq!(end.first_failure, failed.first_failure);
    json!({"profile":"finite-64KiB-page-real-cap-only","attempted_blob_bytes":FILE_BYTES,"first_failure":failed.first_failure,"sticky":true,"original_4KiB_full_profile_qualified":false})
}
fn attach_uri_path_refusals(base: &Path) -> Value {
    let owner = owner(base);
    let lease = owner.lease(0).unwrap();
    let db = open(&lease);
    db.execute_batch("CREATE TABLE t(x INTEGER); INSERT INTO t VALUES(7);")
        .unwrap();
    let outside = base.join("outside.sqlite");
    let outside_text = outside.to_str().unwrap();
    assert!(db
        .execute("ATTACH DATABASE ?1 AS escaped", params![outside_text])
        .is_err());
    assert!(db
        .execute(
            "ATTACH DATABASE ?1 AS escaped_uri",
            params![format!("file:{outside_text}?mode=rwc")]
        )
        .is_err());
    assert!(db.execute("VACUUM INTO ?1", params![outside_text]).is_err());
    assert!(lease
        .open(&lease.directory().join("../escape.sqlite"), flags())
        .is_err());
    assert!(lease
        .open(&lease.directory().join("other.sqlite"), flags())
        .is_err());
    assert!(lease
        .open(
            &PathBuf::from(format!(
                "file:{}?mode=rwc",
                lease.directory().join("native.sqlite").display()
            )),
            flags() | OpenFlags::SQLITE_OPEN_URI
        )
        .is_err());
    assert!(
        !outside.exists()
            && !base.join("escape.sqlite").exists()
            && !base.join("root-0/escape.sqlite").exists()
    );
    assert_eq!(
        db.query_row::<i64, _, _>("SELECT x FROM t", [], |r| r.get(0))
            .unwrap(),
        7
    );
    let before = snapshot(base, "policy-refusals-original-db-still-readable", &lease);
    healthy(&before);
    drop(db);
    let end = snapshot(base, "policy-case-closed", &lease);
    healthy(&end);
    closed(&end);
    json!({"ATTACH_and_VACUUM_INTO_refused":true,"URI_and_parent_escape_refused":true,"outside_file_created":false})
}
fn fill_real_temp(db: &mut trnm_sqlite_io_boundary::OwnedConnection) {
    db.execute_batch("PRAGMA temp_store=FILE; PRAGMA temp.page_size=65536; PRAGMA temp.cache_size=1; PRAGMA temp.cache_spill=ON; CREATE TEMP TABLE spilled(id INTEGER PRIMARY KEY,payload BLOB);").unwrap();
    assert_eq!(
        db.query_row::<i64, _, _>("PRAGMA temp_store", [], |r| r.get(0))
            .unwrap(),
        1
    );
    assert_eq!(
        db.query_row::<i64, _, _>("PRAGMA temp.page_size", [], |r| r.get(0))
            .unwrap(),
        65536
    );
    assert_eq!(
        db.query_row::<i64, _, _>("PRAGMA temp.cache_size", [], |r| r.get(0))
            .unwrap(),
        1
    );
    let tx = db.transaction().unwrap();
    {
        let mut insert = tx
            .prepare("INSERT INTO spilled VALUES(?1,zeroblob(16384))")
            .unwrap();
        for id in 0..128_i64 {
            insert.execute(params![id]).unwrap();
        }
    }
    tx.commit().unwrap();
}
fn memory_real_deleted_temp(base: &Path) -> Value {
    let owner = owner(base);
    let lease = owner.lease(0).unwrap();
    let mut db = lease.open_in_memory().unwrap();
    fill_real_temp(&mut db);
    let first = snapshot(base, "memory-main-real-temp-open", &lease);
    healthy(&first);
    let temp = first
        .objects
        .iter()
        .find(|o| {
            o.basename.starts_with("trnm-temp-")
                && !o.linked
                && o.handles > 0
                && o.actual_last_bytes > 0
        })
        .expect("must observe actual deleted-open temp, not a PRAGMA-only pass")
        .clone();
    let id = temp
        .device
        .zip(temp.inode)
        .expect("actual temp inode identity");
    let fds = actual_fds();
    write_json(&base.join("deleted-open-actual-fds.json"), &fds);
    assert!(fds.iter().any(|f| f["dev"].as_u64() == Some(id.0)
        && f["ino"].as_u64() == Some(id.1)
        && f["links"].as_u64() == Some(0)
        && f["length"].as_u64().is_some_and(|n| n > 0)));
    assert!(first.high_water_sum >= temp.high_water_bytes);
    {
        let mut statement = db
            .prepare("SELECT id,length(payload) FROM spilled ORDER BY payload,id DESC")
            .unwrap();
        let mut rows = statement.query([]).unwrap();
        let row = rows.next().unwrap().expect("sort first row");
        assert_eq!(row.get::<_, i64>(0).unwrap(), 127);
        assert_eq!(row.get::<_, i64>(1).unwrap(), 16384);
        let live = snapshot(base, "rows-and-statement-still-live", &lease);
        healthy(&live);
        assert!(live
            .objects
            .iter()
            .any(|o| o.generation == temp.generation && !o.linked && o.handles > 0));
        for expected in (0..127_i64).rev() {
            let row = rows.next().unwrap().expect("all actual ordered rows");
            assert_eq!(row.get::<_, i64>(0).unwrap(), expected);
        }
        assert!(rows.next().unwrap().is_none());
    }
    let retained = snapshot(base, "statement-closed-temp-connection-still-live", &lease);
    healthy(&retained);
    assert!(retained
        .objects
        .iter()
        .any(|o| o.generation == temp.generation && o.handles > 0));
    drop(db);
    let end = snapshot(base, "memory-and-temp-really-closed", &lease);
    healthy(&end);
    closed(&end);
    assert!(!end.objects.iter().any(|o| o.generation == temp.generation));
    assert_eq!(end.high_water_sum, 0);
    assert!(end.retained_logical_bytes_peak >= first.retained_logical_bytes_peak);
    assert!(end
        .cleanup_lifecycle
        .iter()
        .any(|e| e.generation == temp.generation
            && e.action == "underlying-close"
            && e.handles == 0));
    assert!(
        !fd_has(&actual_fds(), id.0, id.1),
        "deleted-open inode FD remains after last real close"
    );
    json!({"rows":128,"bytes_per_row":16384,"temp_page_size":65536,"deleted_open_inode":id,"actual_temp_spill_observed":true,"sorter_separate_disk_spill_claimed":false})
}
fn assert_seven_published_roots_held(rows: &[Value], roots: &[RootReceipt]) {
    assert_eq!(roots.len(), ROOT_COUNT);
    for r in roots {
        let count = rows
            .iter()
            .filter(|f| {
                f["dev"].as_u64() == Some(r.root_device) && f["ino"].as_u64() == Some(r.root_inode)
            })
            .count();
        assert_eq!(
            count, 1,
            "one original held FD per published root; no duplicate root FD growth"
        );
    }
}
fn drop_order(base: &Path, memory: bool) -> Value {
    let owner = owner(base);
    let roots = owner.receipts().unwrap();
    let lease = owner.lease(0).unwrap();
    // V2 contract: explicitly publish all seven, rather than assuming create eagerly registers.
    let names: Vec<String> = (0..ROOT_COUNT)
        .map(|i| owner.lease(i).unwrap().vfs_name().to_owned())
        .collect();
    assert_eq!(names.iter().collect::<BTreeSet<_>>().len(), ROOT_COUNT);
    let mut db = if memory {
        lease.open_in_memory().unwrap()
    } else {
        open(&lease)
    };
    db.execute_batch("CREATE TABLE t(x INTEGER); INSERT INTO t VALUES(1);")
        .unwrap();
    let live = snapshot(base, "before-external-owner-and-lease-drop", &lease);
    healthy(&live);
    let file_ids: BTreeSet<_> = live
        .objects
        .iter()
        .filter_map(|o| o.device.zip(o.inode))
        .collect();
    drop(owner);
    drop(lease);
    let held = actual_fds();
    write_json(
        &base.join("published-root-lifetime-after-owner-drop.json"),
        &held,
    );
    assert_seven_published_roots_held(&held, &roots);
    {
        let tx = db.transaction().unwrap();
        tx.execute("INSERT INTO t VALUES(2)", []).unwrap();
        tx.commit().unwrap();
    }
    assert_eq!(
        db.query_row::<i64, _, _>("SELECT sum(x) FROM t", [], |r| r.get(0))
            .unwrap(),
        3
    );
    drop(db);
    let after = actual_fds();
    write_json(
        &base.join("connection-closed-published-roots-still-held.json"),
        &after,
    );
    assert!(
        file_ids.iter().all(|&(dev, ino)| !fd_has(&after, dev, ino)),
        "actual SQLite file FD survives its final connection close"
    );
    assert_seven_published_roots_held(&after, &roots);
    let retained = registered_receipt(&names[0]).expect("owned snapshot, no observing lease/Arc");
    write_json(
        &base.join("after-owner-drop-registered-receipt.json"),
        &retained,
    );
    validate(&retained);
    healthy(&retained);
    closed(&retained);
    let retry = fresh_paths(base, "retry-root");
    assert!(retry.iter().all(|p| !p.exists()));
    let error = NativeIoOwner::create(retry)
        .err()
        .expect("owner drop does not reset process claim");
    assert!(error.to_string().contains("claim already consumed"));
    json!({"memory":memory,"sum_after_external_owner_drop":3,"actual_SQLite_file_FDs_closed":true,
        "published_root_FDs_retained_until_process_terminal":7,"second_owner_claim_refused":true,
        "old_v1_all_root_FDs_close_assertion_not_claimed":true})
}
fn failed_owner_claim_consumed(base: &Path) -> Value {
    let paths = fresh_paths(base, "root");
    private_dir(&paths[0]);
    let first = NativeIoOwner::create(paths)
        .err()
        .expect("existing root must fail, never silently reused");
    let retry = fresh_paths(base, "retry-root");
    assert!(retry.iter().all(|p| !p.exists()));
    let second = NativeIoOwner::create(retry)
        .err()
        .expect("failed claim stays consumed");
    assert!(second.to_string().contains("claim already consumed"));
    write_json(
        &base.join("both-owner-errors.json"),
        &json!({"initial_error":first.to_string(),"second_error":second.to_string(),"original_existing_root_retained":base.join("root-0").exists()}),
    );
    json!({"failed_initial_claim_not_reset":true,"SQLite_execution_claimed_by_this_case":false})
}

fn bare_named_memory_permanent_registration(base: &Path) -> Value {
    let owner = owner(base);
    let roots = owner.receipts().unwrap();
    let lease = owner.lease(0).unwrap();
    let names: Vec<String> = (0..ROOT_COUNT)
        .map(|i| owner.lease(i).unwrap().vfs_name().to_owned())
        .collect();
    assert_eq!(names.iter().collect::<BTreeSet<_>>().len(), ROOT_COUNT);
    let name = lease.vfs_name().to_owned();
    let root_id = lease.identity();
    for _ in 0..64 {
        let repeated = owner.lease(0).unwrap();
        assert_eq!(repeated.vfs_name(), name.as_str());
    }
    write_json(
        &base.join("seven-observed-names-and-reuse.json"),
        &json!({"names":names,"root_zero":name,"repeated_same_root_leases":64,
        "registry_enumeration_performed":false,"no_additional_registration_requires_pinned_single_publication_source":true}),
    );
    // Deliberately SAFE bare rusqlite, not OwnedConnection and not a lease-backed wrapper.
    let mut bare =
        rusqlite::Connection::open_in_memory_with_flags_and_vfs(flags(), name.as_str()).unwrap();
    let before = registered_receipt(&name).unwrap();
    write_json(
        &base.join("bare-memory-before-all-strong-callers-drop.json"),
        &before,
    );
    validate(&before);
    healthy(&before);
    assert!(
        before.objects.is_empty(),
        "no FileState Arc may mask the pVfs-only lifetime"
    );
    drop(lease);
    drop(owner);
    // This first operation follows drop with only String names, owned receipt VALUES and bare Connection.
    // Do not call a factory/observer that creates a new strong owner before exercising xCurrentTime.
    let first_now: f64 = bare
        .query_row("SELECT julianday('now')", [], |r| r.get(0))
        .unwrap();
    assert!(first_now.is_finite() && first_now > 0.0);
    // Both actual time and FILE-temp operations precede the first after-drop registry snapshot.
    bare.execute_batch("PRAGMA temp_store=FILE; PRAGMA temp.page_size=65536; PRAGMA temp.cache_size=1; PRAGMA temp.cache_spill=ON; CREATE TEMP TABLE spilled(id INTEGER PRIMARY KEY,payload BLOB);").unwrap();
    assert_eq!(
        bare.query_row::<i64, _, _>("PRAGMA temp_store", [], |r| r.get(0))
            .unwrap(),
        1
    );
    assert_eq!(
        bare.query_row::<i64, _, _>("PRAGMA temp.page_size", [], |r| r.get(0))
            .unwrap(),
        65536
    );
    assert_eq!(
        bare.query_row::<i64, _, _>("PRAGMA temp.cache_size", [], |r| r.get(0))
            .unwrap(),
        1
    );
    assert!(
        bare.query_row::<i64, _, _>("PRAGMA temp.cache_spill", [], |r| r.get(0))
            .unwrap()
            > 0
    );
    {
        let tx = bare.transaction().unwrap();
        {
            let mut insert = tx
                .prepare("INSERT INTO spilled VALUES(?1,zeroblob(16384))")
                .unwrap();
            for id in 0..128_i64 {
                insert.execute(params![id]).unwrap();
            }
        }
        tx.commit().unwrap();
    }
    assert_eq!(
        bare.query_row::<i64, _, _>("SELECT sum(length(payload)) FROM spilled", [], |r| r.get(0))
            .unwrap(),
        128 * 16384
    );
    let live = registered_receipt(&name).unwrap();
    write_json(
        &base.join("bare-real-temp-charged-to-original-root.json"),
        &live,
    );
    validate(&live);
    healthy(&live);
    assert_eq!((live.root_device, live.root_inode), root_id);
    let temp = live
        .objects
        .iter()
        .find(|o| {
            o.basename.starts_with("trnm-temp-")
                && !o.linked
                && o.handles > 0
                && o.actual_last_bytes > 0
        })
        .expect("actual deleted-open temp required")
        .clone();
    let id = temp.device.zip(temp.inode).expect("actual temp identity");
    let fd_rows = actual_fds();
    write_json(
        &base.join("bare-real-temp-actual-deleted-fd.json"),
        &fd_rows,
    );
    assert_seven_published_roots_held(&fd_rows, &roots);
    assert!(fd_rows.iter().any(|f| f["dev"].as_u64() == Some(id.0)
        && f["ino"].as_u64() == Some(id.1)
        && f["links"].as_u64() == Some(0)
        && f["length"].as_u64().is_some_and(|n| n > 0)));
    assert!(live.high_water_sum >= temp.high_water_bytes && temp.high_water_bytes > 0);
    drop(bare);
    let after = registered_receipt(&name).unwrap();
    write_json(
        &base.join("bare-last-close-domain-retained-charge-released.json"),
        &after,
    );
    validate(&after);
    healthy(&after);
    closed(&after);
    assert_eq!(after.high_water_sum, 0);
    assert!(after.retained_logical_bytes_peak >= live.retained_logical_bytes_peak);
    assert!(after
        .cleanup_lifecycle
        .iter()
        .any(|e| e.generation == temp.generation
            && e.action == "underlying-close"
            && e.handles == 0));
    assert!(!fd_has(&actual_fds(), id.0, id.1));
    assert_seven_published_roots_held(&actual_fds(), &roots);
    // Reopen a bare memory client by the SAME exact retained name without any owner/lease factory.
    let second =
        rusqlite::Connection::open_in_memory_with_flags_and_vfs(flags(), name.as_str()).unwrap();
    let second_now: f64 = second
        .query_row("SELECT julianday('now')", [], |r| r.get(0))
        .unwrap();
    assert!(second_now.is_finite() && second_now > 0.0);
    drop(second);
    json!({"bare_memory_only_before_first_callback":true,"first_julianday":first_now,"second_julianday":second_now,
        "same_registered_name_reused_64_times":true,"published_names":7,"registered_root_identity":root_id,
        "deleted_open_temp_inode":id,"temp_page_size":65536,"temp_payload_bytes":128*16384,
        "all_registered_root_FDs_retained_until_real_child_terminal":true,"direct_registry_enumeration_or_unsafe_FFI":false})
}

#[test]
#[ignore = "new finite component control; requires reviewed fresh external owned output directory"]
fn finite_native_public_api_controls_v2() {
    let base = PathBuf::from(
        std::env::var_os("TRNM_PN1_VFS_FINITE_CONTROL_V2_DIR")
            .expect("explicit external fresh evidence directory"),
    );
    assert!(base.is_absolute());
    private_dir(&base);
    let executable = File::open("/proc/self/exe").expect("held actual native ELF");
    let binary = executable.metadata().unwrap();
    let mut terminals = Vec::new();
    for case in CASES {
        let directory = base.join(case);
        private_dir(&directory);
        let stdout = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(directory.join("child.stdout"))
            .unwrap();
        let stderr = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(directory.join("child.stderr"))
            .unwrap();
        // Native ELF exec resolves this still-live CLOEXEC FD before exec closes it.
        // No inheritable FD flags, unsafe pre_exec, additional sandbox or resource-limit changes.
        let process = Command::new(format!("/proc/self/fd/{}", executable.as_raw_fd()))
            .args([
                "native_public_api_v2_case_child",
                "--exact",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("TRNM_PN1_VFS_V2_CASE", case)
            .env("TRNM_PN1_VFS_V2_CASE_DIR", &directory)
            .env("TRNM_PN1_VFS_V2_EXE_DEV", binary.dev().to_string())
            .env("TRNM_PN1_VFS_V2_EXE_INO", binary.ino().to_string())
            .env("RUST_BACKTRACE", "0")
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr))
            .spawn()
            .expect("owned finite child");
        let pid = process.id();
        let mut child = OwnedChild {
            original_tick: tick(pid),
            process,
            waited: false,
        };
        let start = Instant::now();
        let mut identity = None;
        let mut admitted = false;
        let mut timed_out = false;
        loop {
            if child.process.try_wait().unwrap().is_some() {
                break;
            }
            if let Some(ready) = (!admitted)
                .then(|| read_complete_json(&directory.join("child-start.json")))
                .flatten()
            {
                let observed = tick(pid);
                assert_eq!(ready["pid"].as_u64(), Some(u64::from(pid)));
                assert_eq!(ready["executable_dev"].as_u64(), Some(binary.dev()));
                assert_eq!(ready["executable_ino"].as_u64(), Some(binary.ino()));
                assert!(observed.is_some());
                assert_eq!(ready["kernel_start_tick"].as_str(), observed.as_deref());
                identity = observed;
                write_json(
                    &directory.join("parent-go.json"),
                    &json!({"pid":pid,"kernel_start_tick":identity}),
                );
                admitted = true;
            }
            if start.elapsed() > Duration::from_secs(CASE_SECONDS) {
                timed_out = true;
                child
                    .process
                    .kill()
                    .expect("kill only this owned unreaped child");
                break;
            }
            thread::sleep(Duration::from_millis(5));
        }
        let status = child
            .process
            .wait()
            .expect("actual owned child wait terminal");
        child.waited = true;
        let original_alive = identity
            .as_ref()
            .is_some_and(|v| tick(pid).as_ref() == Some(v));
        let row = json!({"case":case,"pid":pid,"kernel_start_tick":identity,"alive_and_bound_before_release":admitted,
            "wait_completed":true,"exit_code":status.code(),"success":status.success(),"timed_out":timed_out,
            "original_PID_identity_alive_after_wait":original_alive,"elapsed_ns":start.elapsed().as_nanos(),
            "case_receipt_present":directory.join("case-result.json").is_file(),"CPU_wait4_measurement_claimed":false});
        write_json(&directory.join("parent-observed-terminal.json"), &row);
        terminals.push(row);
    }
    write_json(
        &base.join("all-planned-child-terminals.json"),
        &json!({"schema":"pn1-vfs-finite-native-public-api-control-v2",
        "planned_cases":CASES,"terminals":terminals,"registered_root_lifetime":"published roots persist until each real child terminal","full_W1_4097_qualified":false,"Node_AuthenticatedV1_integrated":false}),
    );
    assert!(
        terminals
            .iter()
            .all(|r| r["alive_and_bound_before_release"] == true
                && r["success"] == true
                && r["timed_out"] == false
                && r["original_PID_identity_alive_after_wait"] == false
                && r["case_receipt_present"] == true),
        "one or more finite native cases failed; preserve all raw roots and diagnostics"
    );
}

#[test]
#[ignore = "only spawned once per named case by the finite parent"]
fn native_public_api_v2_case_child() {
    let case = std::env::var("TRNM_PN1_VFS_V2_CASE").expect("explicit child case");
    assert!(CASES.contains(&case.as_str()));
    let base = PathBuf::from(std::env::var_os("TRNM_PN1_VFS_V2_CASE_DIR").unwrap());
    assert!(base.is_absolute());
    let executable = fs::metadata("/proc/self/exe").unwrap();
    assert_eq!(
        executable.dev().to_string(),
        std::env::var("TRNM_PN1_VFS_V2_EXE_DEV").unwrap()
    );
    assert_eq!(
        executable.ino().to_string(),
        std::env::var("TRNM_PN1_VFS_V2_EXE_INO").unwrap()
    );
    let pid = std::process::id();
    let identity = tick(pid).expect("actual child kernel identity");
    write_json(
        &base.join("child-start.json"),
        &json!({"pid":pid,"kernel_start_tick":identity,"case":case,"executable_dev":executable.dev(),"executable_ino":executable.ino()}),
    );
    let start = Instant::now();
    let go = loop {
        if let Some(value) = read_complete_json(&base.join("parent-go.json")) {
            break value;
        }
        assert!(start.elapsed() < Duration::from_secs(CASE_SECONDS));
        thread::sleep(Duration::from_millis(5));
    };
    assert_eq!(go["pid"].as_u64(), Some(u64::from(pid)));
    assert_eq!(go["kernel_start_tick"].as_str(), Some(identity.as_str()));
    let observed = match case.as_str() {
        "rollback_to_wal" => rollback_to_wal(&base),
        "multiple_connections" => multiple_connections(&base),
        "same_lease_cold_reopen" => same_lease_cold_reopen(&base),
        "real_file_cap_sticky" => real_file_cap_sticky(&base),
        "attach_uri_path_refusals" => attach_uri_path_refusals(&base),
        "memory_real_deleted_temp" => memory_real_deleted_temp(&base),
        "memory_drop_order" => drop_order(&base, true),
        "disk_drop_order" => drop_order(&base, false),
        "failed_owner_claim_consumed" => failed_owner_claim_consumed(&base),
        "bare_named_memory_permanent_registration" => {
            bare_named_memory_permanent_registration(&base)
        }
        _ => unreachable!(),
    };
    write_json(
        &base.join("case-result.json"),
        &json!({"schema":"pn1-vfs-finite-native-case-observation-v2","case":case,
        "pid":pid,"observed":observed,"component_only":true,"full_guard_enabled":false,"full_W1_4097_qualified":false}),
    );
    println!("finite-native-case-complete {case}");
}
