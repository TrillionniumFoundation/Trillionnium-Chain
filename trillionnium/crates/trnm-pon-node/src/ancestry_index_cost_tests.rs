//! Optional read-only replay of the retained #674 failure's actual 4,105-page
//! index workload. It does not perform paid transport, W1, state execution or
//! the original Host budget, and cannot qualify cold sync or confirmed TPS.
use super::*;
use rustix::time::{clock_gettime_dynamic, ClockId, DynamicClockId};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fmt::Write as _, fs::File, io::Read, os::unix::ffi::OsStrExt, path::PathBuf, time::Instant,
};

fn cpu_ns() -> u128 {
    let value = clock_gettime_dynamic(DynamicClockId::Known(ClockId::ThreadCPUTime)).unwrap();
    assert!(value.tv_sec >= 0 && value.tv_nsec >= 0);
    value.tv_sec as u128 * 1_000_000_000 + value.tv_nsec as u128
}

fn digest_file(path: &std::path::Path) -> String {
    let mut source = File::open(path).unwrap();
    let mut hash = Sha256::new();
    let mut bytes = [0_u8; 64 * 1024];
    loop {
        let count = source.read(&mut bytes).unwrap();
        if count == 0 {
            return hex::encode(hash.finalize());
        }
        hash.update(&bytes[..count]);
    }
}

fn immutable_readonly(path: &std::path::Path) -> Connection {
    // Escape every original Unix pathname byte, including '/', '?' and '%'.
    // There is no lossy UTF-8 conversion, authority, or filename-supplied URI
    // option. SQLite percent-decodes the path before opening the immutable DB.
    let mut uri = String::from("file:");
    for byte in path.as_os_str().as_bytes() {
        write!(uri, "%{byte:02X}").unwrap();
    }
    uri.push_str("?mode=ro&immutable=1");
    Connection::open_with_flags(
        uri,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_URI,
    )
    .unwrap()
}

fn pinned_snapshot(
    source: &std::path::Path,
    expected: &str,
) -> (tempfile::TempDir, PathBuf, Connection) {
    // The retained artifact contains a checkpointed main file. A readonly
    // SQLite open of its original WAL-mode name would also consume a later,
    // unpinned -wal. Copy only the exact main-file bytes into a fresh private
    // directory and explicitly ignore all sidecars with immutable=1. Hash the
    // copy too: a concurrent source replacement cannot change this input.
    assert_eq!(digest_file(source), expected, "retained main database");
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("retained.sqlite");
    std::fs::copy(source, &path).unwrap();
    assert_eq!(
        digest_file(&path),
        expected,
        "copied retained main database"
    );
    let db = immutable_readonly(&path);
    (directory, path, db)
}

#[test]
fn pinned_history_snapshot_ignores_unbound_wal_and_escapes_exact_path_bytes() {
    use std::{ffi::OsString, os::unix::ffi::OsStringExt};

    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join(OsString::from_vec(
        b"history ?mode=rw&immutable=0#%\xff.sqlite".to_vec(),
    ));
    let writer = Connection::open(&path).unwrap();
    writer
        .execute_batch(
            "PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0;
         CREATE TABLE retained(value INTEGER NOT NULL);
         INSERT INTO retained VALUES(7); PRAGMA wal_checkpoint(TRUNCATE);",
        )
        .unwrap();
    let expected = digest_file(&path);
    writer.execute("UPDATE retained SET value=99", []).unwrap();
    // The valid newer WAL changes what ordinary readonly SQL observes while
    // leaving the pinned main-file bytes identical: this was the old hole.
    assert_eq!(digest_file(&path), expected);
    let ordinary =
        Connection::open_with_flags(&path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    let read = |db: &Connection| {
        db.query_row("SELECT value FROM retained", [], |row| row.get::<_, i64>(0))
            .unwrap()
    };
    assert_eq!(read(&ordinary), 99);
    drop(ordinary);
    let sidecar = |suffix: &str| {
        let mut name = path.as_os_str().to_os_string();
        name.push(suffix);
        PathBuf::from(name)
    };
    let wal = sidecar("-wal");
    let shm = sidecar("-shm");
    assert!(std::fs::metadata(&wal).unwrap().len() > 0);
    let unchanged = (digest_file(&wal), digest_file(&shm));
    // Direct immutable access also proves '?'/'#'/'%' and a non-UTF8 byte
    // address the literal source path and cannot inject mode=rw.
    let exact_path = immutable_readonly(&path);
    assert_eq!(read(&exact_path), 7);
    assert!(exact_path
        .execute("UPDATE retained SET value=1", [])
        .is_err());
    drop(exact_path);
    let (_isolated, copied, snapshot) = pinned_snapshot(&path, &expected);
    assert_eq!(read(&snapshot), 7);
    assert!(snapshot.execute("UPDATE retained SET value=1", []).is_err());
    drop(snapshot);
    assert_eq!(digest_file(&copied), expected);
    assert_eq!(digest_file(&path), expected);
    assert_eq!((digest_file(&wal), digest_file(&shm)), unchanged);
    // Keep the writer alive until all source-byte/sidecar observations finish;
    // closing the final WAL connection may otherwise checkpoint legitimately.
    drop(writer);
}

#[test]
#[ignore = "read-only retained #674 artifact: set TRNM_RETAINED_HISTORY_DIRECTORY; not original Host/cold-sync acceptance"]
fn retained_4105_actual_history_index_cost() {
    let directory = PathBuf::from(std::env::var_os("TRNM_RETAINED_HISTORY_DIRECTORY").unwrap());
    // These are exact members of the downloaded artifact ZIP whose SHA256 was
    // independently matched to GitHub's artifact metadata before extraction.
    // Shape, copied source labels or a successful 4,105-row query alone cannot
    // attribute some other database to that historical failure.
    let mut metadata = std::collections::BTreeMap::new();
    for (name, expected) in [
        (
            "source.json",
            "4ff48ad4c111cc81056b8bd34eee0c763322ab922907881b1ed1931a5a0b0fcc",
        ),
        (
            "long-history/config.json",
            "144378e064c9825a1c3cfce2119d352262222496eb49b2ee6e0a030c7093c4d7",
        ),
        (
            "long-history/source.json",
            "1d0c4058a421d39e2f45a8ab57b4a64b46bf5df2a83c91bd52e7fb5e3daef269",
        ),
        (
            "long-history/summary.json",
            "8dc451e058b8b3b2de85a1294f8b9e004befd330471c6387e31d5c0f037dff17",
        ),
    ] {
        let bytes = std::fs::read(directory.join(name)).unwrap();
        assert_eq!(
            hex::encode(Sha256::digest(&bytes)),
            expected,
            "retained artifact member {name}"
        );
        let value: Value = serde_json::from_slice(&bytes).unwrap();
        assert!(metadata.insert(name, value).is_none());
    }
    // Parse precisely the bytes just hashed; do not reopen a mutable pathname
    // between attribution and interpretation of source/configuration labels.
    let read = |name: &str| -> Value { metadata.get(name).unwrap().clone() };
    let source = read("source.json");
    assert_eq!(
        source["tested_commit"],
        "605af09da34ca72665f822200a2f3e75573e6052"
    );
    assert_eq!(
        source["tested_tree"],
        "1ebba227627ad37309310e8773b55b9087596e59"
    );
    assert_eq!(read("long-history/summary.json")["passed"], false);
    let config = read("long-history/config.json");
    assert_eq!(config["blocks"], 4105);
    let field = |name: &str| -> Hash {
        hex::decode(config[name].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap()
    };
    let context = Context {
        network: field("network"),
        parameters: field("parameters"),
        genesis: field("genesis"),
        packet_profile: None,
    };
    let path = directory.join("long-history/validator/native.sqlite");
    let before = digest_file(&path);
    assert_eq!(
        before,
        "8605605c79a74981574420d0a4a0c7a960b0022fc9e4d08d598f9757eee10d8d"
    );
    let (_isolated_snapshot, copied_path, db) = pinned_snapshot(&path, &before);
    let ids = db
        .prepare("SELECT id,height FROM blocks ORDER BY height,id")
        .unwrap()
        .query_map([], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, u64>(1)?))
        })
        .unwrap()
        .map(|value| {
            let (bytes, height) = value.unwrap();
            (bytes32(bytes).unwrap(), height)
        })
        .collect::<Vec<_>>();
    assert_eq!(ids.len(), 4106);
    assert_eq!(ids[0], (context.genesis, 0));
    for (height, row) in ids.iter().enumerate() {
        assert_eq!(row.1, height as u64);
    }
    let tip = ids[4105].0;
    let mut reference = None;
    let mut observations = Vec::new();
    // Balanced order; capacity zero executes a fresh prepare for every lookup,
    // matching the former query_row path. Both modes perform every real read,
    // byte/parent/seal check, budget debit and cancellation callback.
    for capacity in [0, 64, 64, 0] {
        db.set_prepared_statement_cache_capacity(capacity);
        db.flush_prepared_statement_cache();
        let mut result_hash = Sha256::new();
        let mut per_page = Vec::with_capacity(4105);
        let mut charged = 0_u64;
        let mut callbacks = 0_u64;
        let started = Instant::now();
        let cpu = cpu_ns();
        for (index, after) in ids[..4105].iter().enumerate() {
            let page_started = Instant::now();
            let mut last_charge = 0;
            let lookup =
                next_public_request(&db, context, tip, after.0, READ_SQL_BUDGET, &mut |used| {
                    assert!(used >= last_charge);
                    last_charge = used;
                    callbacks += 1;
                    Ok(())
                })
                .unwrap();
            assert_eq!(lookup.next, Some(ids[index + 1].0));
            assert_eq!(lookup.height, index as u64 + 1);
            assert_eq!(last_charge, lookup.sql_lookups);
            assert!(lookup.sql_lookups <= READ_SQL_BUDGET);
            charged += lookup.sql_lookups;
            result_hash.update(lookup.next.unwrap());
            result_hash.update(lookup.height.to_le_bytes());
            result_hash.update(lookup.sql_lookups.to_le_bytes());
            per_page.push(page_started.elapsed().as_nanos());
        }
        let cpu = cpu_ns().checked_sub(cpu).unwrap();
        let wall = started.elapsed().as_nanos();
        let result = (hex::encode(result_hash.finalize()), charged, callbacks);
        if let Some(expected) = &reference {
            assert_eq!(&result, expected);
        } else {
            reference = Some(result.clone());
        }
        per_page.sort_unstable();
        let quantile = |percent: usize| per_page[(per_page.len() * percent).div_ceil(100) - 1];
        observations.push(json!({
            "prepared_statement_cache_capacity": capacity,
            "pages": 4105, "sql_lookups": charged, "progress_callbacks": callbacks,
            "output_and_lookup_sha256": result.0,
            "wall_ns": wall, "calling_thread_cpu_ns": cpu,
            "page_wall_p50_ns": quantile(50), "page_wall_p95_ns": quantile(95),
            "page_wall_p99_ns": quantile(99), "page_wall_max_ns": per_page[4104],
        }));
    }
    drop(db);
    assert_eq!(digest_file(&copied_path), before);
    assert_eq!(digest_file(&path), before);
    println!(
        "{}",
        json!({
            "schema": "retained-4105-actual-index-cost-v1",
            "artifact_id": 13068992474_u64,
            "artifact_zip_sha256": "911c97580825950fc3b9785b4e4b786d72163555d943d70d763367a3d4a3845f",
            "retained_source": source, "database_sha256": before,
            "sql_input": "private byte-pinned main-file copy; immutable=1 ignores unpinned WAL/journal sidecars",
            "observations": observations,
            "scope": "read-only original 4105-block index input; local cost diagnostic only",
            "paid_transport_executed": false, "w1_replay_executed": false,
            "state_execution_executed": false, "original_host_gate_executed": false,
            "cold_sync_accepted": false, "confirmed_transaction_tps": false,
            "production_activation": false,
        })
    );
}
