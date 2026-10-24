use super::*;
use std::{io::Write, sync::Barrier};

const CAP: u64 = 262_144;
fn image_config() -> CellCacheConfigV3 {
    CellCacheConfigV3 {
        max_database_bytes: CAP,
        ..cache_config()
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
fn full(result: CellResultV1<()>) {
    match result {
        Err(CellErrorV1::Sql(rusqlite::Error::SqliteFailure(error, message))) => {
            eprintln!("actual SQLite error: {error:?} {message:?}");
            assert_eq!(error.code, rusqlite::ErrorCode::DiskFull);
            assert_eq!(error.extended_code, 13);
        }
        other => panic!("expected native SQLITE_FULL, got {other:?}"),
    }
}
fn bounded(path: &Path) {
    let db = Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    let pages: u64 = db
        .pragma_query_value(None, "page_count", |r| r.get(0))
        .unwrap();
    let size: u64 = db
        .pragma_query_value(None, "page_size", |r| r.get(0))
        .unwrap();
    assert_eq!(size, 4096);
    assert!(pages.checked_mul(size).unwrap() <= CAP);
    assert!(fs::metadata(path).unwrap().len() <= CAP);
}

#[test]
fn real_full_rolls_back_entire_eight_chunk_batch_and_survives_both_cold_modes() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("full.sqlite");
    let config = image_config();
    let cache = CellStoreV1::open(&path, config).unwrap();
    let (baseline, bytes) = chunk(1, 16_384);
    cache.put_chunk(&baseline, &bytes).unwrap();
    let usage = cache.cache_usage().unwrap();
    let cells: Vec<_> = (2..=9).map(|n| chunk(n, 65_536)).collect();
    let batch: Vec<_> = cells.iter().map(|(c, b)| (c, b.as_slice())).collect();
    assert!(config.max_logical_bytes > 8 * 65_568 + usage.logical_bytes);
    full(cache.put_chunk_batch(&batch));
    assert_eq!(cache.cache_usage().unwrap(), usage);
    assert_eq!(cache.chunk(baseline.sha256).unwrap(), Some(bytes.clone()));
    for (c, _) in &cells {
        assert!(cache.chunk(c.sha256).unwrap().is_none());
    }
    bounded(&path);
    // Observe actual checkpoint and its return tuple; this is not a WAL cap.
    let db = Connection::open(&path).unwrap();
    let result: (i64, i64, i64) = db
        .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?))
        })
        .unwrap();
    assert_eq!(result.0, 0);
    bounded(&path);
    drop(db);
    drop(cache);
    bounded(&path);
    for cache in [
        CellStoreV1::open_read_only(&path).unwrap(),
        CellStoreV1::open(&path, config).unwrap(),
    ] {
        assert_eq!(cache.cache_usage().unwrap(), usage);
        assert_eq!(cache.chunk(baseline.sha256).unwrap(), Some(bytes.clone()));
        for (c, _) in &cells {
            assert!(cache.chunk(c.sha256).unwrap().is_none());
        }
    }
}

#[test]
fn two_real_writers_and_a_fresh_reopen_cannot_reset_the_page_cap() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("writers.sqlite");
    drop(CellStoreV1::open(&path, image_config()).unwrap());
    let gate = Arc::new(Barrier::new(3));
    let handles: Vec<_> = (1..=2)
        .map(|n| {
            let path = path.clone();
            let gate = gate.clone();
            thread::spawn(move || {
                let cache = CellStoreV1::open(&path, image_config()).unwrap();
                let (c, b) = chunk(n, 131_072);
                gate.wait();
                cache.put_chunk(&c, &b)
            })
        })
        .collect();
    gate.wait();
    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    for result in results.into_iter().filter(|r| r.is_err()) {
        full(result);
    }
    bounded(&path);
    // A stock new SQLite connection has no persistent max_page_count setting.
    let db = Connection::open(&path).unwrap();
    let unpinned: u64 = db
        .pragma_query_value(None, "max_page_count", |r| r.get(0))
        .unwrap();
    assert!(unpinned > CAP / 4096);
    drop(db);
    let cache = CellStoreV1::open(&path, image_config()).unwrap();
    let before = cache.cache_usage().unwrap();
    let (c, b) = chunk(99, 131_072);
    full(cache.put_chunk(&c, &b));
    assert_eq!(cache.cache_usage().unwrap(), before);
    drop(cache);
    bounded(&path);
    assert_eq!(
        CellStoreV1::open_read_only(&path)
            .unwrap()
            .cache_usage()
            .unwrap(),
        before
    );
}

#[test]
fn overpage_padding_and_wrong_page_size_are_refused_without_cold_rewrite() {
    for damage in ["overpage", "tail-padding", "page-size"] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("damaged.sqlite");
        drop(CellStoreV1::open(&path, image_config()).unwrap());
        if damage == "tail-padding" {
            let mut f = fs::OpenOptions::new().append(true).open(&path).unwrap();
            f.write_all(&vec![0; CAP as usize]).unwrap();
            f.sync_all().unwrap();
        } else {
            let db = Connection::open(&path).unwrap();
            if damage == "overpage" {
                let (c, b) = chunk(5, 524_288);
                db.execute(
                    "INSERT INTO cell_chunks_v1 VALUES(?1,?2)",
                    params![c.sha256.as_slice(), b],
                )
                .unwrap();
                let pages: u64 = db
                    .pragma_query_value(None, "page_count", |r| r.get(0))
                    .unwrap();
                assert!(pages > CAP / 4096);
            } else {
                db.execute_batch("PRAGMA journal_mode=DELETE; PRAGMA page_size=8192; VACUUM")
                    .unwrap();
                assert_eq!(
                    db.pragma_query_value::<u64, _>(None, "page_size", |r| r.get(0))
                        .unwrap(),
                    8192
                );
            }
        }
        let before = fs::read(&path).unwrap();
        assert!(CellStoreV1::open_read_only(&path).is_err(), "{damage}");
        assert_eq!(fs::read(&path).unwrap(), before, "reader {damage}");
        assert!(
            CellStoreV1::open(&path, image_config()).is_err(),
            "{damage}"
        );
        assert_eq!(fs::read(&path).unwrap(), before, "writer {damage}");
    }
}

#[test]
fn fourth_config_is_immutable_exact_finite_and_old_tcl2_is_not_migrated() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.sqlite");
    let cache = CellStoreV1::open(&path, image_config()).unwrap();
    let db = Connection::open(&path).unwrap();
    for sql in [
        "UPDATE cell_cache_quota_v3 SET max_database_bytes=max_database_bytes+4096",
        "DELETE FROM cell_cache_quota_v3",
        "INSERT OR REPLACE INTO cell_cache_quota_v3 VALUES(1,1,1,1,262144,0,0,0)",
    ] {
        assert!(db.execute(sql, []).is_err(), "{sql}");
    }
    assert!(matches!(
        CellStoreV1::open(
            &path,
            CellCacheConfigV3 {
                max_database_bytes: CAP + 4096,
                ..image_config()
            }
        ),
        Err(CellErrorV1::Invalid("cache configuration differs"))
    ));
    for limit in [0, 4096, CAP + 1, u64::MAX] {
        let absent = dir.path().join(format!("invalid-{limit}"));
        assert!(CellStoreV1::open(
            &absent,
            CellCacheConfigV3 {
                max_database_bytes: limit,
                ..image_config()
            }
        )
        .is_err());
        assert!(!absent.exists());
    }
    drop(db);
    drop(cache);
    // Full original 14-object TCL2 catalog, counters and actual payload.
    let old = dir.path().join("old-tcl2.sqlite");
    let db = Connection::open(&old).unwrap();
    db.execute_batch(ORIGINAL_TCL2_SCHEMA).unwrap();
    assert_eq!(
        db.query_row::<u64, _, _>("SELECT count(*) FROM sqlite_schema", [], |r| r.get(0))
            .unwrap(),
        14
    );
    let (c, b) = chunk(8, 16_384);
    db.execute(
        "INSERT INTO cell_chunks_v1 VALUES(?1,?2)",
        params![c.sha256.as_slice(), b],
    )
    .unwrap();
    drop(db);
    let before = fs::read(&old).unwrap();
    for result in [
        CellStoreV1::open(&old, image_config()),
        CellStoreV1::open_read_only(&old),
    ] {
        assert!(matches!(
            result,
            Err(CellErrorV1::Invalid("cache namespace"))
        ))
    }
    assert_eq!(fs::read(&old).unwrap(), before);
}

#[test]
fn held_reader_with_real_changes_allows_wal_to_exceed_the_main_database_cap() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("wal.sqlite");
    let cache = CellStoreV1::open(&path, image_config()).unwrap();
    let (c, b) = chunk(1, 16_384);
    cache.put_chunk(&c, &b).unwrap();
    let before = cache.cache_usage().unwrap();
    let reader =
        Connection::open_with_flags(&path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    reader.execute_batch("BEGIN").unwrap();
    let saved: Vec<u8> = reader
        .query_row("SELECT bytes FROM cell_chunks_v1", [], |r| r.get(0))
        .unwrap();
    for _ in 0..32 {
        cache.put_chunk(&c, &b).unwrap();
    }
    // Exact no-op UPSERTs do not dirty pages on bundled SQLite 3.46. Preserve
    // those retries, then exercise real bounded writes instead of claiming that
    // no-op traffic itself makes WAL frames (the initial failed control is kept).
    for byte in 2..=33 {
        let (next, bytes) = chunk(byte, 256);
        cache.put_chunk(&next, &bytes).unwrap();
        cache.put_chunk(&next, &bytes).unwrap();
    }
    let wal = path.with_extension("sqlite-wal");
    let wal_bytes = fs::metadata(wal).unwrap().len();
    eprintln!("main DB cap={CAP}; held-reader WAL length={wal_bytes}");
    assert!(wal_bytes > CAP);
    bounded(&path);
    assert_eq!(
        cache.cache_usage().unwrap().logical_bytes,
        before.logical_bytes + 32 * (256 + 32)
    );
    assert_eq!(saved, b);
    reader.execute_batch("ROLLBACK").unwrap();
}

#[test]
fn original_maximum_eight_by_four_mib_batch_remains_admissible() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("maximum-batch.sqlite");
    let cache = CellStoreV1::open(&path, cache_config()).unwrap();
    let cells: Vec<_> = (1..=8)
        .map(|n| chunk(n, MAX_CHUNK_BYTES as usize))
        .collect();
    let batch: Vec<_> = cells.iter().map(|(c, b)| (c, b.as_slice())).collect();
    cache.put_chunk_batch(&batch).unwrap();
    assert_eq!(
        cache.cache_usage().unwrap(),
        CellCacheUsageV2 {
            logical_bytes: 8 * (u64::from(MAX_CHUNK_BYTES) + 32),
            chunk_rows: 8,
            manifest_rows: 0
        }
    );
    drop(cache);
    let cache = CellStoreV1::open_read_only(&path).unwrap();
    for (c, b) in cells {
        assert_eq!(cache.chunk(c.sha256).unwrap(), Some(b));
    }
    assert!(fs::metadata(&path).unwrap().len() <= cache_config().max_database_bytes);
}

// Frozen original DDL fixture; no production migration or legacy reader.
const ORIGINAL_TCL2_SCHEMA: &str = r#"-- Original TCL2/schema2 fixture from 4e49725; must be rejected unchanged.
CREATE TABLE cell_manifests_v1 (
            id BLOB PRIMARY KEY CHECK(length(id)=32),
            wire BLOB NOT NULL CHECK(length(wire) BETWEEN 1 AND 1048576)) STRICT;
CREATE TABLE cell_chunks_v1 (
            hash BLOB PRIMARY KEY CHECK(length(hash)=32),
            bytes BLOB NOT NULL CHECK(length(bytes) BETWEEN 1 AND 4194304)) STRICT;
CREATE TABLE cell_cache_quota_v2 (
            singleton INTEGER PRIMARY KEY CHECK(singleton=1),
            max_bytes INTEGER NOT NULL CHECK(max_bytes BETWEEN 1 AND 1099511627776),
            max_chunks INTEGER NOT NULL CHECK(max_chunks BETWEEN 1 AND 1048576),
            max_manifests INTEGER NOT NULL CHECK(max_manifests BETWEEN 1 AND 1048576),
            used_bytes INTEGER NOT NULL, chunk_rows INTEGER NOT NULL, manifest_rows INTEGER NOT NULL,
            CONSTRAINT cell_cache_capacity CHECK(
                typeof(used_bytes)='integer' AND used_bytes BETWEEN 0 AND max_bytes AND
                typeof(chunk_rows)='integer' AND chunk_rows BETWEEN 0 AND max_chunks AND
                typeof(manifest_rows)='integer' AND manifest_rows BETWEEN 0 AND max_manifests)) STRICT;
CREATE TRIGGER cache_config_immutable
            BEFORE UPDATE OF singleton,max_bytes,max_chunks,max_manifests ON cell_cache_quota_v2
            BEGIN SELECT RAISE(ABORT,'cache_config_immutable'); END;
CREATE TRIGGER cache_config_no_delete
            BEFORE DELETE ON cell_cache_quota_v2
            BEGIN SELECT RAISE(ABORT,'cache_config_immutable'); END;
CREATE TRIGGER cache_config_no_replace
            BEFORE INSERT ON cell_cache_quota_v2 WHEN EXISTS(SELECT 1 FROM cell_cache_quota_v2)
            BEGIN SELECT RAISE(ABORT,'cache_config_immutable'); END;
CREATE TRIGGER cache_chunk_insert AFTER INSERT ON cell_chunks_v1 BEGIN
                 UPDATE cell_cache_quota_v2 SET used_bytes=used_bytes+(length(NEW.bytes)+32),
                 chunk_rows=chunk_rows+1 WHERE singleton=1; END;
CREATE TRIGGER cache_chunk_update AFTER UPDATE ON cell_chunks_v1 BEGIN
                 UPDATE cell_cache_quota_v2 SET used_bytes=used_bytes+(length(NEW.bytes)-length(OLD.bytes)),
                 chunk_rows=chunk_rows+0 WHERE singleton=1; END;
CREATE TRIGGER cache_chunk_delete AFTER DELETE ON cell_chunks_v1 BEGIN
                 UPDATE cell_cache_quota_v2 SET used_bytes=used_bytes+(-length(OLD.bytes)-32),
                 chunk_rows=chunk_rows-1 WHERE singleton=1; END;
CREATE TRIGGER cache_manifest_insert AFTER INSERT ON cell_manifests_v1 BEGIN
                 UPDATE cell_cache_quota_v2 SET used_bytes=used_bytes+(length(NEW.wire)+32),
                 manifest_rows=manifest_rows+1 WHERE singleton=1; END;
CREATE TRIGGER cache_manifest_update AFTER UPDATE ON cell_manifests_v1 BEGIN
                 UPDATE cell_cache_quota_v2 SET used_bytes=used_bytes+(length(NEW.wire)-length(OLD.wire)),
                 manifest_rows=manifest_rows+0 WHERE singleton=1; END;
CREATE TRIGGER cache_manifest_delete AFTER DELETE ON cell_manifests_v1 BEGIN
                 UPDATE cell_cache_quota_v2 SET used_bytes=used_bytes+(-length(OLD.wire)-32),
                 manifest_rows=manifest_rows-1 WHERE singleton=1; END;
INSERT INTO cell_cache_quota_v2 VALUES(1,67108864,4096,256,0,0,0);
PRAGMA application_id=1413696562; PRAGMA user_version=2;
"#;
