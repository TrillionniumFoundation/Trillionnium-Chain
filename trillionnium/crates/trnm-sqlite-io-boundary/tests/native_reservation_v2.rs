//! One finite, real public-API experiment in its own integration-test process.
//! This is not W1, the three-FD component, a physical quota, or public service.
#![cfg(target_os = "linux")]
#![forbid(unsafe_code)]

use rusqlite::OpenFlags;
use serde::Serialize;
use std::fs::{self, DirBuilder, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use trnm_sqlite_io_boundary::{
    NativeIoLease, NativeIoOwner, RootReceipt, FILE_BYTES, GROWTH_QUANTUM_BYTES_V2,
    RESERVATION_DOMAIN_V2, ROOT_COUNT,
};

fn persist(path: &Path, value: &impl Serialize) {
    let raw = serde_json::to_vec_pretty(value).unwrap();
    assert!(raw.len() <= 2 * 1024 * 1024);
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    output.write_all(&raw).unwrap();
    output.sync_all().unwrap();
}
fn capture(base: &Path, name: &str, lease: &NativeIoLease) -> RootReceipt {
    let receipt = lease.receipt().unwrap();
    persist(&base.join(name), &receipt);
    assert_eq!(receipt.schema, RESERVATION_DOMAIN_V2);
    assert_eq!(
        receipt.growth_reservation_quantum_bytes,
        Some(GROWTH_QUANTUM_BYTES_V2)
    );
    assert_eq!(receipt.logical_bytes_limit, 3 * FILE_BYTES);
    assert_eq!(receipt.retained_object_limit, 3);
    assert_eq!(receipt.lifecycle_serialized_bytes_cap, 655360);
    assert!(receipt.lifecycle.len() <= 1024 && receipt.cleanup_lifecycle.len() <= 256);
    assert!(!receipt.allocated_blocks_hard_cap_implemented);
    receipt
}
fn path(lease: &NativeIoLease) -> PathBuf {
    lease.directory().join("native.sqlite")
}
fn flags() -> OpenFlags {
    OpenFlags::SQLITE_OPEN_READ_WRITE
        | OpenFlags::SQLITE_OPEN_CREATE
        | OpenFlags::SQLITE_OPEN_NO_MUTEX
}

#[test]
fn real_small_writes_cold_reopen_and_unreserved_growth_refusal_v2() {
    let base = std::env::var_os("TRNM_NATIVE_RESERVATION_V2_OUTPUT")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            std::env::temp_dir().join(format!(
                "trnm-native-reservation-v2-{}-{}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ))
        });
    assert!(base.is_absolute());
    DirBuilder::new().mode(0o700).create(&base).unwrap();
    println!(
        "retained native reservation-v2 evidence: {}",
        base.display()
    );
    let owner = NativeIoOwner::create_with_reservation_v2(std::array::from_fn(|i| {
        base.join(format!("root-{i}"))
    }))
    .unwrap();
    persist(&base.join("initial-roots.json"), &owner.receipts().unwrap());
    let lease = owner.lease(0).unwrap();
    assert!(lease
        .vfs_name()
        .starts_with("trnm-pn1-owned-inode-reservation-v2-"));
    let mut db = lease.open(&path(&lease), flags()).unwrap();
    db.execute_batch("PRAGMA page_size=4096; PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0; PRAGMA cache_size=-128; CREATE TABLE payload(id INTEGER PRIMARY KEY, bytes BLOB NOT NULL);").unwrap();
    {
        let tx = db.transaction().unwrap();
        {
            let mut insert = tx
                .prepare("INSERT INTO payload(id,bytes) VALUES(?1,zeroblob(4096))")
                .unwrap();
            for id in 0..1400 {
                insert.execute([id]).unwrap();
            }
        }
        tx.commit().unwrap();
    }
    let count: i64 = db
        .query_row("SELECT COUNT(*) FROM payload", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 1400);
    drop(db);
    let first = capture(&base, "small-writes-closed.json", &lease);
    assert!(!first.failed && first.first_failure.is_none());
    assert_eq!(first.denied_operations, 0);
    assert!(first.lifecycle_complete && first.quarantine_entries_complete);
    assert!(first.callback_operations > 1024);
    assert!(first.lifecycle.len() < 1017);
    assert!(first.high_water_sum <= 3 * FILE_BYTES);
    assert!(first
        .objects
        .iter()
        .all(|o| o.handles == 0 && o.pending_opens == 0 && o.shm_references == 0));
    let cold = lease
        .open(&path(&lease), OpenFlags::SQLITE_OPEN_READ_ONLY)
        .unwrap();
    let count: i64 = cold
        .query_row("SELECT COUNT(*) FROM payload", [], |row| row.get(0))
        .unwrap();
    let integrity: String = cold
        .query_row("PRAGMA integrity_check", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 1400);
    assert_eq!(integrity, "ok");
    drop(cold);
    let closed = capture(&base, "cold-reopen-closed.json", &lease);
    assert!(!closed.failed && closed.lifecycle_complete);

    // Mutate only this test's private inode. A later observation must not
    // retroactively supply reservation credit for this unexpected length.
    let attacked = owner.lease(1).unwrap();
    let db = attacked.open(&path(&attacked), flags()).unwrap();
    db.execute_batch("CREATE TABLE x(value INTEGER);").unwrap();
    drop(db);
    let before = capture(&base, "before-unreserved-growth.json", &attacked);
    let reserved = before
        .objects
        .iter()
        .find(|o| o.basename == "native.sqlite")
        .unwrap()
        .high_water_bytes;
    assert!(reserved > 0 && reserved < FILE_BYTES);
    OpenOptions::new()
        .write(true)
        .open(path(&attacked))
        .unwrap()
        .set_len(reserved + 1)
        .unwrap();
    assert!(attacked.open(&path(&attacked), flags()).is_err());
    let refused = capture(&base, "unreserved-growth-refused.json", &attacked);
    assert!(refused.failed);
    assert_eq!(
        refused.first_failure_sqlite_code,
        Some(rusqlite::ffi::SQLITE_FULL)
    );
    assert_eq!(
        refused.first_failure.as_deref(),
        Some("actual inode length exceeds prior reservation")
    );
    assert_eq!(
        refused
            .objects
            .iter()
            .find(|o| o.basename == "native.sqlite")
            .unwrap()
            .high_water_bytes,
        reserved
    );
    assert!(attacked.open_in_memory().is_err());

    let retry: [PathBuf; ROOT_COUNT] =
        std::array::from_fn(|i| base.join(format!("forbidden-retry-{i}")));
    assert!(NativeIoOwner::create(retry.clone()).is_err());
    assert!(retry.iter().all(|p| !p.exists()));
    persist(
        &base.join("final-all-roots.json"),
        &owner.receipts().unwrap(),
    );
    fs::write(base.join("SCOPE.txt"), "Finite real public-API experiment only. Original V1 controls remain separate. No W1, three-FD component, physical quota, full writer, public fairness or release qualification. All evidence and databases remain in this unique test directory.\n").unwrap();
}
