use super::*;
use crate::cell::{CellCacheConfigV4, CellCacheUsageV2};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

fn config() -> CellCacheConfigV4 {
    CellCacheConfigV4 {
        max_database_bytes: 262_144,
        max_logical_bytes: 1_048_576,
        max_chunk_rows: 1024,
        max_manifest_rows: 64,
    }
}
fn chunk(byte: u8, size: usize) -> (CellChunkV1, Vec<u8>) {
    let bytes = vec![byte; size];
    (
        CellChunkV1 {
            size: size as u32,
            sha256: Sha256::digest(&bytes).into(),
        },
        bytes,
    )
}
fn bytes(path: &Path, suffix: &str) -> u64 {
    fs::metadata(crate::cell::cache_wal::sidecar(path, suffix)).map_or(0, |m| m.len())
}
fn reader(path: &Path) -> Connection {
    let reader = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    reader.execute_batch("BEGIN").unwrap();
    let _: u64 = reader
        .query_row("SELECT count(*) FROM cell_chunks_v1", [], |r| r.get(0))
        .unwrap();
    reader
}
fn limits(path: &Path) {
    assert!(fs::metadata(path).unwrap().len() <= config().max_database_bytes);
    assert!(bytes(path, "-wal") <= config().max_wal_bytes().unwrap());
    assert!(bytes(path, "-shm") <= config().max_shm_bytes().unwrap());
}

#[test]
fn maximum_supported_image_cap_reads_back_exact_pager_limit_without_reserving_it() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("maximum.sqlite");
    let largest = CellCacheConfigV4 {
        max_database_bytes: 2_199_023_255_552,
        ..config()
    };
    let cache = CellStoreV1::open(&path, largest).unwrap();
    let pages: u64 = cache
        .connection
        .pragma_query_value(None, "max_page_count", |r| r.get(0))
        .unwrap();
    assert_eq!(pages, 536_870_912);
    assert!(largest.max_wal_bytes().unwrap() > largest.max_database_bytes);
    assert!(largest.max_shm_bytes().unwrap() > 32768);
    assert!(fs::metadata(path).unwrap().len() < 262_144);
    let invalid = CellCacheConfigV4 {
        max_database_bytes: u64::MAX,
        ..largest
    };
    assert!(invalid.max_wal_bytes().is_err());
    assert!(invalid.max_shm_bytes().is_err());
}

#[test]
fn held_reader_refuses_entire_eight_chunk_batch_then_original_retry_survives_cold_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("reader.sqlite");
    let cache = CellStoreV1::open(&path, config()).unwrap();
    let (first, payload) = chunk(1, 16_384);
    cache.put_chunk(&first, &payload).unwrap();
    let before = cache.cache_usage().unwrap();
    let snapshot = reader(&path);
    let wal_before = bytes(&path, "-wal");
    let cells: Vec<_> = (2..=9).map(|n| chunk(n, 1024)).collect();
    let batch: Vec<_> = cells.iter().map(|(c, b)| (c, b.as_slice())).collect();
    for _ in 0..32 {
        assert!(matches!(
            cache.put_chunk_batch(&batch),
            Err(CellErrorV1::CacheWriterBusy)
        ));
        assert_eq!(cache.cache_usage().unwrap(), before);
        assert_eq!(bytes(&path, "-wal"), wal_before);
        limits(&path);
    }
    for (c, _) in &cells {
        assert!(cache.chunk(c.sha256).unwrap().is_none());
    }
    let saved: Vec<u8> = snapshot
        .query_row(
            "SELECT bytes FROM cell_chunks_v1 WHERE hash=?1",
            [first.sha256.as_slice()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(saved, payload);
    snapshot.execute_batch("ROLLBACK").unwrap();
    cache.put_chunk_batch(&batch).unwrap();
    cache.put_chunk_batch(&batch).unwrap();
    let expected = CellCacheUsageV2 {
        logical_bytes: before.logical_bytes + 8 * (1024 + 32),
        chunk_rows: 9,
        manifest_rows: 0,
    };
    assert_eq!(cache.cache_usage().unwrap(), expected);
    limits(&path);
    drop(cache);
    for cache in [
        CellStoreV1::open_read_only(&path).unwrap(),
        CellStoreV1::open(&path, config()).unwrap(),
    ] {
        assert_eq!(cache.cache_usage().unwrap(), expected);
        assert_eq!(cache.chunk(first.sha256).unwrap(), Some(payload.clone()));
        for (c, b) in &cells {
            assert_eq!(cache.chunk(c.sha256).unwrap(), Some(b.clone()));
        }
    }
}

#[test]
fn all_mutating_entries_and_corrupt_deletion_share_prewrite_reader_refusal() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("entries.sqlite");
    let cache = CellStoreV1::open(&path, config()).unwrap();
    let (first, payload) = chunk(1, 16_384);
    cache.put_chunk(&first, &payload).unwrap();
    let external = Connection::open(&path).unwrap();
    external
        .execute(
            "UPDATE cell_chunks_v1 SET bytes=?1",
            [vec![2_u8; payload.len()]],
        )
        .unwrap();
    let before = cache.cache_usage().unwrap();
    let snapshot = reader(&path);
    let wal_before = bytes(&path, "-wal");
    let (second, data) = chunk(3, 1024);
    assert!(matches!(
        cache.put_chunk(&second, &data),
        Err(CellErrorV1::CacheWriterBusy)
    ));
    let context = CellContextV1 {
        family: "wal-test".into(),
        base: [1; 32],
        parent: [2; 32],
        tokenizer: [3; 32],
        layout: [4; 32],
        runtime: [5; 32],
    };
    let manifest =
        CellManifestV1::new(context, 16_384, first.sha256, 16_384, vec![first.clone()]).unwrap();
    assert!(matches!(
        cache.put_manifest(manifest.id(), &manifest.encode()),
        Err(CellErrorV1::CacheWriterBusy)
    ));
    assert!(matches!(
        cache.chunk(first.sha256),
        Err(CellErrorV1::CacheWriterBusy)
    ));
    assert!(matches!(
        CellStoreV1::open(&path, config()),
        Err(CellErrorV1::CacheWriterBusy)
    ));
    assert_eq!(bytes(&path, "-wal"), wal_before);
    assert_eq!(cache.cache_usage().unwrap(), before);
    let ro = CellStoreV1::open_read_only(&path).unwrap();
    assert!(ro.chunk(first.sha256).unwrap().is_none());
    assert_eq!(ro.cache_usage().unwrap(), before);
    drop(ro);
    snapshot.execute_batch("ROLLBACK").unwrap();
    assert!(cache.chunk(first.sha256).unwrap().is_none());
    assert_eq!(cache.cache_usage().unwrap().chunk_rows, 0);
    cache.put_chunk(&first, &payload).unwrap();
    assert_eq!(cache.chunk(first.sha256).unwrap(), Some(payload));
    limits(&path);
}

#[test]
fn repeated_real_dirty_transactions_keep_one_generation_wal_and_derived_shm_bounds() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("pressure.sqlite");
    let cache = CellStoreV1::open(&path, config()).unwrap();
    for n in 1..=128 {
        let (c, b) = chunk(n, 256);
        cache.put_chunk(&c, &b).unwrap();
        let pages: u64 = cache
            .connection
            .pragma_query_value(None, "page_count", |r| r.get(0))
            .unwrap();
        let wal = bytes(&path, "-wal");
        assert!(wal >= 32);
        assert_eq!((wal - 32) % 4120, 0);
        assert!((wal - 32) / 4120 <= pages + 16);
        limits(&path);
        assert_eq!(
            cache.cache_usage().unwrap().logical_bytes,
            u64::from(n) * (256 + 32)
        );
    }
    let snapshot = reader(&path);
    let before = bytes(&path, "-wal");
    for n in 129..=160 {
        let (c, b) = chunk(n, 256);
        assert!(matches!(
            cache.put_chunk(&c, &b),
            Err(CellErrorV1::CacheWriterBusy)
        ));
        assert_eq!(bytes(&path, "-wal"), before);
    }
    snapshot.execute_batch("ROLLBACK").unwrap();
    let spill: u64 = cache
        .connection
        .pragma_query_value(None, "cache_spill", |r| r.get(0))
        .unwrap();
    let sync: u64 = cache
        .connection
        .pragma_query_value(None, "synchronous", |r| r.get(0))
        .unwrap();
    assert_eq!((spill, sync), (0, 2));
}

#[test]
fn cold_writer_refuses_oversized_wal_or_shm_without_truncating_foreign_bytes() {
    for suffix in ["-wal", "-shm"] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("oversized.sqlite");
        drop(CellStoreV1::open(&path, config()).unwrap());
        let sidecar = crate::cell::cache_wal::sidecar(&path, suffix);
        let limit = if suffix == "-wal" {
            config().max_wal_bytes().unwrap()
        } else {
            config().max_shm_bytes().unwrap()
        };
        File::create(&sidecar).unwrap().set_len(limit + 1).unwrap();
        let before = fs::read(&sidecar).unwrap();
        assert!(CellStoreV1::open(&path, config()).is_err());
        assert_eq!(fs::read(sidecar).unwrap(), before);
    }
}

struct OwnedChild(Child);
impl Drop for OwnedChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn killed_supported_writer_keeps_committed_prefix_and_retries_original_batch_after_recovery() {
    const CHILD_PATH: &str = "TRNM_CELL_WAL_CRASH_CHILD_PATH";
    if let Some(path) = std::env::var_os(CHILD_PATH) {
        let path = std::path::PathBuf::from(path);
        let cache = CellStoreV1::open(&path, config()).unwrap();
        let (first, payload) = chunk(1, 1024);
        cache.put_chunk(&first, &payload).unwrap();
        cache
            .write::<()>(|connection| {
                for n in 2..=9 {
                    let (c, b) = chunk(n, 1024);
                    connection.execute(
                        "INSERT INTO cell_chunks_v1(hash,bytes) VALUES(?1,?2)",
                        params![c.sha256.as_slice(), b],
                    )?;
                }
                fs::write(
                    path.with_extension("ready"),
                    b"uncommitted original eight-row transaction",
                )?;
                let deadline = Instant::now() + Duration::from_secs(10);
                while Instant::now() < deadline {
                    std::thread::sleep(Duration::from_millis(1));
                }
                panic!("parent did not terminate its owned transaction child");
            })
            .unwrap();
        panic!("uncommitted child must never report commit success");
    }
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("crash.sqlite");
    let mut child = OwnedChild(Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "cell::store::wal_tests::killed_supported_writer_keeps_committed_prefix_and_retries_original_batch_after_recovery", "--nocapture", "--test-threads=1"])
        .env(CHILD_PATH, &path).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap());
    let deadline = Instant::now() + Duration::from_secs(10);
    while !path.with_extension("ready").exists() {
        assert!(
            child.0.try_wait().unwrap().is_none(),
            "child exited before uncommitted transaction"
        );
        assert!(Instant::now() < deadline, "owned child startup deadline");
        std::thread::sleep(Duration::from_millis(1));
    }
    child.0.kill().unwrap();
    assert!(!child.0.wait().unwrap().success());
    let expected = CellCacheUsageV2 {
        logical_bytes: 1024 + 32,
        chunk_rows: 1,
        manifest_rows: 0,
    };
    let (first, payload) = chunk(1, 1024);
    for cache in [
        CellStoreV1::open_read_only(&path).unwrap(),
        CellStoreV1::open(&path, config()).unwrap(),
    ] {
        assert_eq!(cache.cache_usage().unwrap(), expected);
        assert_eq!(cache.chunk(first.sha256).unwrap(), Some(payload.clone()));
        for n in 2..=9 {
            assert!(cache.chunk(chunk(n, 1024).0.sha256).unwrap().is_none());
        }
    }
    let cache = CellStoreV1::open(&path, config()).unwrap();
    let cells: Vec<_> = (2..=9).map(|n| chunk(n, 1024)).collect();
    let batch: Vec<_> = cells.iter().map(|(c, b)| (c, b.as_slice())).collect();
    cache.put_chunk_batch(&batch).unwrap();
    cache.put_chunk_batch(&batch).unwrap();
    assert_eq!(
        cache.cache_usage().unwrap(),
        CellCacheUsageV2 {
            logical_bytes: 9 * (1024 + 32),
            chunk_rows: 9,
            manifest_rows: 0
        }
    );
    limits(&path);
}
