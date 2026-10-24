use super::*;
use std::sync::Barrier;

fn material(byte: u8) -> (CellManifestV1, Vec<u8>) {
    let bytes = vec![byte; 16_384];
    let digest = Sha256::digest(&bytes).into();
    let manifest = CellManifestV1::new(
        context(),
        bytes.len() as u64,
        digest,
        16_384,
        vec![CellChunkV1 {
            size: bytes.len() as u32,
            sha256: digest,
        }],
    )
    .unwrap();
    (manifest, bytes)
}

#[test]
fn persistent_whole_cache_counts_catalog_payload_keys_and_exact_dedup() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("quota.sqlite");
    let (first, bytes) = material(1);
    let (second, second_bytes) = material(2);
    let config = CellCacheConfigV3 {
        max_database_bytes: 128 * 1024 * 1024,
        max_logical_bytes: (bytes.len() + first.encode().len() + 64) as u64 * 2,
        max_chunk_rows: 2,
        max_manifest_rows: 2,
    };
    let cache = CellStoreV1::open(&path, config).unwrap();
    for (manifest, payload) in [(&first, &bytes), (&second, &second_bytes)] {
        cache
            .put_manifest(manifest.id(), &manifest.encode())
            .unwrap();
        cache.put_chunk(&manifest.chunks()[0], payload).unwrap();
    }
    let full = CellCacheUsageV2 {
        logical_bytes: config.max_logical_bytes,
        chunk_rows: 2,
        manifest_rows: 2,
    };
    assert_eq!(cache.cache_usage().unwrap(), full);
    // A full cache must still allow an exact same-row UPSERT, including its
    // BEFORE INSERT phase; no temporary duplicate admission may be charged.
    cache.put_manifest(first.id(), &first.encode()).unwrap();
    cache.put_chunk(&first.chunks()[0], &bytes).unwrap();
    let (third, third_bytes) = material(3);
    assert!(matches!(
        cache.put_manifest(third.id(), &third.encode()),
        Err(CellErrorV1::CacheQuotaExceeded)
    ));
    assert!(matches!(
        cache.put_chunk(&third.chunks()[0], &third_bytes),
        Err(CellErrorV1::CacheQuotaExceeded)
    ));
    assert_eq!(cache.cache_usage().unwrap(), full);
    drop(cache);
    assert_eq!(
        CellStoreV1::open(&path, config)
            .unwrap()
            .cache_usage()
            .unwrap(),
        full
    );
    assert_eq!(
        CellStoreV1::open_read_only(&path)
            .unwrap()
            .cache_usage()
            .unwrap(),
        full
    );
    assert!(matches!(
        CellStoreV1::open(
            &path,
            CellCacheConfigV3 {
                max_database_bytes: 128 * 1024 * 1024,
                max_logical_bytes: config.max_logical_bytes + 1,
                ..config
            }
        ),
        Err(CellErrorV1::Invalid("cache configuration differs"))
    ));
}

#[test]
fn eight_member_quota_failure_rolls_back_all_rows_and_duplicate_batch_charges_once() {
    let directory = tempfile::tempdir().unwrap();
    let cells: Vec<_> = (1..=8).map(material).collect();
    let refs: Vec<_> = cells
        .iter()
        .map(|(manifest, bytes)| (&manifest.chunks()[0], bytes.as_slice()))
        .collect();
    let config = CellCacheConfigV3 {
        max_database_bytes: 128 * 1024 * 1024,
        max_logical_bytes: 7 * (16_384 + 32),
        max_chunk_rows: 7,
        max_manifest_rows: 1,
    };
    let path = directory.path().join("batch.sqlite");
    let cache = CellStoreV1::open(&path, config).unwrap();
    assert!(matches!(
        cache.put_chunk_batch(&refs),
        Err(CellErrorV1::CacheQuotaExceeded)
    ));
    assert_eq!(
        cache.cache_usage().unwrap(),
        CellCacheUsageV2 {
            logical_bytes: 0,
            chunk_rows: 0,
            manifest_rows: 0
        }
    );
    for (manifest, _) in &cells {
        assert!(cache.chunk(manifest.chunks()[0].sha256).unwrap().is_none());
    }
    drop(cache);
    let cache = CellStoreV1::open(&path, config).unwrap();
    cache.put_chunk_batch(&[refs[0]; 8]).unwrap();
    cache.put_chunk_batch(&[refs[0]; 8]).unwrap();
    assert_eq!(
        cache.cache_usage().unwrap(),
        CellCacheUsageV2 {
            logical_bytes: 16_384 + 32,
            chunk_rows: 1,
            manifest_rows: 0
        }
    );
}

#[test]
fn two_actual_writer_connections_serialize_capacity_and_shared_hash_dedup() {
    for same_hash in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("concurrent.sqlite");
        let config = CellCacheConfigV3 {
            max_database_bytes: 128 * 1024 * 1024,
            max_logical_bytes: 16_384 + 32,
            max_chunk_rows: 1,
            max_manifest_rows: 1,
        };
        drop(CellStoreV1::open(&path, config).unwrap());
        let gate = Arc::new(Barrier::new(3));
        let handles: Vec<_> = (1..=2)
            .map(|byte| {
                let path = path.clone();
                let gate = gate.clone();
                thread::spawn(move || {
                    let cache = CellStoreV1::open(&path, config).unwrap();
                    let (manifest, bytes) = material(if same_hash { 1 } else { byte });
                    gate.wait();
                    cache.put_chunk(&manifest.chunks()[0], &bytes)
                })
            })
            .collect();
        gate.wait();
        let results: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();
        assert_eq!(
            results.iter().filter(|value| value.is_ok()).count(),
            if same_hash { 2 } else { 1 }
        );
        assert!(results
            .iter()
            .all(|value| value.is_ok() || matches!(value, Err(CellErrorV1::CacheQuotaExceeded))));
        assert_eq!(
            CellStoreV1::open(&path, config)
                .unwrap()
                .cache_usage()
                .unwrap(),
            CellCacheUsageV2 {
                logical_bytes: 16_384 + 32,
                chunk_rows: 1,
                manifest_rows: 0
            }
        );
    }
}

#[test]
fn cold_open_rejects_counter_and_exact_trigger_corruption_without_reset() {
    for damage in ["counter", "trigger", "table"] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("damaged.sqlite");
        let config = cache_config();
        let cache = CellStoreV1::open(&path, config).unwrap();
        let (manifest, bytes) = material(9);
        cache.put_chunk(&manifest.chunks()[0], &bytes).unwrap();
        drop(cache);
        let db = Connection::open(&path).unwrap();
        match damage {
            "counter" => { db.execute("UPDATE cell_cache_quota_v3 SET used_bytes=0", []).unwrap(); }
            "trigger" => db.execute_batch("DROP TRIGGER cache_chunk_insert;
                CREATE TRIGGER cache_chunk_insert AFTER INSERT ON cell_chunks_v1 BEGIN SELECT 1; END;").unwrap(),
            _ => db.execute_batch("ALTER TABLE cell_chunks_v1 ADD COLUMN unexpected INTEGER;").unwrap(),
        }
        assert!(CellStoreV1::open(&path, config).is_err());
        assert!(CellStoreV1::open_read_only(&path).is_err());
        assert_eq!(
            db.query_row::<u64, _, _>("SELECT count(*) FROM cell_chunks_v1", [], |row| row.get(0))
                .unwrap(),
            1
        );
    }
}

#[test]
fn foreign_catalog_count_and_large_strings_are_refused_without_database_rewrite() {
    for mode in [
        "many-objects",
        "long-sql",
        "long-name",
        "sqlite-like-hidden-trigger",
    ] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("cache.sqlite");
        let config = cache_config();
        drop(CellStoreV1::open(&path, config).unwrap());
        let db = rusqlite::Connection::open(&path).unwrap();
        match mode {
            "many-objects" => {
                for index in 0..128 {
                    db.execute_batch(&format!("CREATE TABLE extra_{index}(value INTEGER) STRICT"))
                        .unwrap();
                }
            }
            "long-sql" => db
                .execute_batch(&format!(
                    "CREATE TABLE extra(value INTEGER /*{}*/) STRICT",
                    "x".repeat(65536)
                ))
                .unwrap(),
            "long-name" => db
                .execute_batch(&format!(
                    "CREATE TABLE extra_{}(value INTEGER) STRICT",
                    "x".repeat(65536)
                ))
                .unwrap(),
            _ => db
                .execute_batch(
                    "CREATE TRIGGER sqliteXshadow BEFORE INSERT ON cell_chunks_v1
                BEGIN SELECT RAISE(IGNORE); END",
                )
                .unwrap(),
        }
        drop(db);
        let before = std::fs::read(&path).unwrap();
        assert!(CellStoreV1::open_read_only(&path).is_err(), "{mode}");
        assert_eq!(std::fs::read(&path).unwrap(), before, "{mode} read-only");
        assert!(CellStoreV1::open(&path, config).is_err(), "{mode}");
        assert_eq!(std::fs::read(&path).unwrap(), before, "{mode} writer");
    }
}

#[test]
fn immutable_configuration_and_integer_bounds_cannot_reset_allowance() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("bounds.sqlite");
    let config = cache_config();
    let cache = CellStoreV1::open(&path, config).unwrap();
    let db = Connection::open(&path).unwrap();
    for sql in [
        "UPDATE cell_cache_quota_v3 SET max_bytes=max_bytes+1",
        "DELETE FROM cell_cache_quota_v3",
        "INSERT OR REPLACE INTO cell_cache_quota_v3 VALUES(1,1,1,1,262144,0,0,0)",
        "UPDATE cell_cache_quota_v3 SET used_bytes=9223372036854775807+1",
        "UPDATE cell_cache_quota_v3 SET chunk_rows=-1",
    ] {
        assert!(db.execute(sql, []).is_err(), "{sql}");
    }
    assert_eq!(
        cache.cache_usage().unwrap(),
        CellCacheUsageV2 {
            logical_bytes: 0,
            chunk_rows: 0,
            manifest_rows: 0
        }
    );
    let invalid = directory.path().join("must-not-create.sqlite");
    assert!(CellStoreV1::open(
        &invalid,
        CellCacheConfigV3 {
            max_database_bytes: 128 * 1024 * 1024,
            max_logical_bytes: u64::MAX,
            ..config
        }
    )
    .is_err());
    assert!(!invalid.exists());
    let old = directory.path().join("old-v1.sqlite");
    let old_db = Connection::open(&old).unwrap();
    old_db
        .execute_batch(
            "CREATE TABLE original(bytes BLOB); INSERT INTO original VALUES(X'01');
        PRAGMA application_id=1413696561; PRAGMA user_version=1;",
        )
        .unwrap();
    assert!(CellStoreV1::open(&old, config).is_err());
    assert_eq!(
        old_db
            .query_row::<Vec<u8>, _, _>("SELECT bytes FROM original", [], |row| row.get(0))
            .unwrap(),
        vec![1]
    );
}

#[test]
fn actual_corrupt_chunk_deletion_returns_only_its_logical_cache_allowance() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("delete.sqlite");
    let (manifest, bytes) = material(12);
    let config = CellCacheConfigV3 {
        max_database_bytes: 128 * 1024 * 1024,
        max_logical_bytes: 16_384 + 32,
        max_chunk_rows: 1,
        max_manifest_rows: 1,
    };
    let cache = CellStoreV1::open(&path, config).unwrap();
    cache.put_chunk(&manifest.chunks()[0], &bytes).unwrap();
    Connection::open(&path)
        .unwrap()
        .execute(
            "UPDATE cell_chunks_v1 SET bytes=?1",
            [vec![99_u8; bytes.len()]],
        )
        .unwrap();
    assert!(cache.chunk(manifest.chunks()[0].sha256).unwrap().is_none());
    assert_eq!(
        cache.cache_usage().unwrap(),
        CellCacheUsageV2 {
            logical_bytes: 0,
            chunk_rows: 0,
            manifest_rows: 0
        }
    );
    cache.put_chunk(&manifest.chunks()[0], &bytes).unwrap();
    assert_eq!(
        cache.cache_usage().unwrap().logical_bytes,
        config.max_logical_bytes
    );
}

#[test]
fn catalog_and_chunk_row_limits_apply_even_with_unused_byte_allowance() {
    let directory = tempfile::tempdir().unwrap();
    let config = CellCacheConfigV3 {
        max_chunk_rows: 1,
        max_manifest_rows: 1,
        ..cache_config()
    };
    let cache = CellStoreV1::open(&directory.path().join("rows.sqlite"), config).unwrap();
    let (first, bytes) = material(51);
    let (second, other) = material(52);
    cache.put_manifest(first.id(), &first.encode()).unwrap();
    cache.put_chunk(&first.chunks()[0], &bytes).unwrap();
    let before = cache.cache_usage().unwrap();
    assert!(before.logical_bytes < config.max_logical_bytes);
    assert!(matches!(
        cache.put_manifest(second.id(), &second.encode()),
        Err(CellErrorV1::CacheQuotaExceeded)
    ));
    assert!(matches!(
        cache.put_chunk(&second.chunks()[0], &other),
        Err(CellErrorV1::CacheQuotaExceeded)
    ));
    assert_eq!(cache.cache_usage().unwrap(), before);
}

#[test]
fn ordinary_authorized_fetches_share_one_persistent_quota_and_failed_fetch_keeps_charge() {
    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("source.sqlite");
    let origin = CellStoreV1::open(&source, cache_config()).unwrap();
    let (first, bytes) = material(41);
    let (second, other) = material(42);
    for (manifest, bytes) in [(&first, &bytes), (&second, &other)] {
        origin
            .put_manifest(manifest.id(), &manifest.encode())
            .unwrap();
        origin.put_chunk(&manifest.chunks()[0], bytes).unwrap();
    }
    let peer = Peer::start(&source);
    let path = directory.path().join("consumer.sqlite");
    let config = CellCacheConfigV3 {
        max_database_bytes: 128 * 1024 * 1024,
        max_logical_bytes: (bytes.len() + first.encode().len() + 64) as u64,
        max_chunk_rows: 1,
        max_manifest_rows: 2,
    };
    let consumer = CellStoreV1::open(&path, config).unwrap();
    fetch_cell(&consumer, first.id(), &[peer.address], limits()).unwrap();
    assert!(matches!(
        fetch_cell(&consumer, second.id(), &[peer.address], limits()),
        Err(CellErrorV1::CacheQuotaExceeded)
    ));
    assert_eq!(
        consumer.cache_usage().unwrap().logical_bytes,
        config.max_logical_bytes
    );
    drop(consumer);
    let partial_path = directory.path().join("partial.sqlite");
    let partial_config = CellCacheConfigV3 {
        max_database_bytes: 128 * 1024 * 1024,
        max_logical_bytes: first.encode().len() as u64 + 32,
        max_chunk_rows: 1,
        max_manifest_rows: 1,
    };
    let partial = CellStoreV1::open(&partial_path, partial_config).unwrap();
    assert!(matches!(
        fetch_cell(&partial, first.id(), &[peer.address], limits()),
        Err(CellErrorV1::CacheQuotaExceeded)
    ));
    drop(partial);
    let partial = CellStoreV1::open(&partial_path, partial_config).unwrap();
    assert_eq!(
        partial.cache_usage().unwrap(),
        CellCacheUsageV2 {
            logical_bytes: partial_config.max_logical_bytes,
            chunk_rows: 0,
            manifest_rows: 1
        }
    );
    assert!(partial.manifest(first.id()).unwrap().is_some());
    assert!(partial.chunk(first.chunks()[0].sha256).unwrap().is_none());
    // A later failed download must retain the actual already-committed batch,
    // not just a manifest. Nine distinct chunks force the original 8+1 flush.
    let payload: Vec<_> = (60_u8..69).flat_map(|byte| vec![byte; 16_384]).collect();
    let chunks: Vec<_> = payload
        .chunks(16_384)
        .map(|part| CellChunkV1 {
            size: part.len() as u32,
            sha256: Sha256::digest(part).into(),
        })
        .collect();
    let nine = CellManifestV1::new(
        context(),
        payload.len() as u64,
        Sha256::digest(&payload).into(),
        16_384,
        chunks,
    )
    .unwrap();
    origin.put_manifest(nine.id(), &nine.encode()).unwrap();
    for (chunk, bytes) in nine.chunks().iter().zip(payload.chunks(16_384)) {
        origin.put_chunk(chunk, bytes).unwrap();
    }
    let prefix_path = directory.path().join("verified-prefix.sqlite");
    let prefix_config = CellCacheConfigV3 {
        max_database_bytes: 128 * 1024 * 1024,
        max_logical_bytes: nine.encode().len() as u64 + 32 + 8 * (16_384 + 32),
        max_chunk_rows: 8,
        max_manifest_rows: 1,
    };
    let prefix = CellStoreV1::open(&prefix_path, prefix_config).unwrap();
    assert!(matches!(
        fetch_cell(&prefix, nine.id(), &[peer.address], limits()),
        Err(CellErrorV1::CacheQuotaExceeded)
    ));
    drop(prefix);
    let prefix = CellStoreV1::open(&prefix_path, prefix_config).unwrap();
    assert_eq!(
        prefix.cache_usage().unwrap(),
        CellCacheUsageV2 {
            logical_bytes: prefix_config.max_logical_bytes,
            chunk_rows: 8,
            manifest_rows: 1
        }
    );
    let mut kept = 0;
    for (chunk, bytes) in nine.chunks().iter().zip(payload.chunks(16_384)) {
        if let Some(actual) = prefix.chunk(chunk.sha256).unwrap() {
            assert_eq!(actual, bytes);
            kept += 1;
        }
    }
    assert_eq!(kept, 8);
}

#[test]
fn unowned_database_with_literal_lookalike_prefix_is_not_claimed_or_rewritten() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("foreign.sqlite");
    let db = Connection::open(&path).unwrap();
    db.execute_batch(
        "CREATE TABLE sqliteXforeign(value INTEGER) STRICT;
        INSERT INTO sqliteXforeign VALUES(7)",
    )
    .unwrap();
    drop(db);
    let before = std::fs::read(&path).unwrap();
    assert!(matches!(
        CellStoreV1::open(&path, cache_config()),
        Err(CellErrorV1::Invalid("foreign cache database"))
    ));
    assert_eq!(std::fs::read(&path).unwrap(), before);
    let db = Connection::open(&path).unwrap();
    assert_eq!(
        db.query_row::<i64, _, _>("PRAGMA application_id", [], |row| row.get(0))
            .unwrap(),
        0
    );
    assert_eq!(
        db.query_row::<i64, _, _>("PRAGMA user_version", [], |row| row.get(0))
            .unwrap(),
        0
    );
    assert_eq!(
        db.query_row::<i64, _, _>("SELECT value FROM sqliteXforeign", [], |row| row.get(0))
            .unwrap(),
        7
    );
}
