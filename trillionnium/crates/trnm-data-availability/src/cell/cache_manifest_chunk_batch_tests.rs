use super::*;
use crate::cell::{CellCacheConfigV4, CellCacheUsageV2};
use std::time::Duration;

type Material = (CellDigestV1, Vec<u8>, Vec<u8>);

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(10)
}

fn config() -> CellCacheConfigV4 {
    CellCacheConfigV4 {
        max_database_bytes: 64 * 1024 * 1024,
        max_logical_bytes: 48 * 1024 * 1024,
        max_chunk_rows: 64,
        max_manifest_rows: 64,
    }
}

fn material(byte: u8, size: usize) -> Material {
    let bytes = vec![byte; size];
    let digest = Sha256::digest(&bytes).into();
    let manifest = CellManifestV1::new(
        CellContextV1 {
            family: "manifest-chunk-batch".into(),
            base: [1; 32],
            parent: [2; 32],
            tokenizer: [3; 32],
            layout: [4; 32],
            runtime: [5; 32],
        },
        bytes.len() as u64,
        digest,
        MAX_CHUNK_BYTES,
        vec![CellChunkV1 {
            size: bytes.len() as u32,
            sha256: digest,
        }],
    )
    .unwrap();
    (manifest.id(), manifest.encode(), bytes)
}

fn references(materials: &[Material]) -> Vec<(CellDigestV1, &[u8], &[u8])> {
    materials
        .iter()
        .map(|(pinned, wire, bytes)| (*pinned, wire.as_slice(), bytes.as_slice()))
        .collect()
}

fn usage(materials: &[Material]) -> CellCacheUsageV2 {
    CellCacheUsageV2 {
        logical_bytes: materials
            .iter()
            .map(|(_, wire, bytes)| (wire.len() + bytes.len() + 64) as u64)
            .sum(),
        chunk_rows: materials.len() as u64,
        manifest_rows: materials.len() as u64,
    }
}

fn assert_present(cache: &CellStoreV1, materials: &[Material]) {
    for (pinned, wire, bytes) in materials {
        let manifest = CellManifestV1::decode(wire).unwrap();
        assert_eq!(cache.manifest(*pinned).unwrap(), Some(manifest.clone()));
        assert_eq!(
            cache.chunk(manifest.chunks()[0].sha256).unwrap(),
            Some(bytes.clone())
        );
        cache.verify_complete(&manifest).unwrap();
    }
}

fn assert_limits(path: &Path, config: CellCacheConfigV4) {
    assert!(fs::metadata(path).unwrap().len() <= config.max_database_bytes);
    for (suffix, limit) in [
        ("-wal", config.max_wal_bytes().unwrap()),
        ("-shm", config.max_shm_bytes().unwrap()),
    ] {
        let actual = fs::metadata(crate::cell::cache_wal::sidecar(path, suffix))
            .map_or(0, |metadata| metadata.len());
        assert!(actual <= limit);
    }
}

#[test]
fn single_chunk_batch_bad_last_payload_or_manifest_pin_keeps_no_prefix() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bad-last.sqlite");
    let cache = CellStoreV1::open(&path, config()).unwrap();
    let before = cache.cache_usage().unwrap();
    let original: Vec<_> = (1..=6).map(|byte| material(byte, 1024)).collect();
    for mode in 0..4 {
        let mut changed = original.clone();
        match mode {
            0 => changed[5].2[0] ^= 1,
            1 => changed[5].0[0] ^= 1,
            2 => {
                let old = CellManifestV1::decode(&changed[5].1).unwrap();
                let malformed = CellManifestV1::new(
                    old.context().clone(),
                    old.size(),
                    [99; 32],
                    old.chunk_bytes(),
                    old.chunks().to_vec(),
                )
                .unwrap();
                changed[5].0 = malformed.id();
                changed[5].1 = malformed.encode();
            }
            _ => {
                let (_, wire, bytes) = material(6, 16_384);
                let one = CellManifestV1::decode(&wire).unwrap();
                let multiple = CellManifestV1::new(
                    one.context().clone(),
                    32_768,
                    one.payload_sha256(),
                    16_384,
                    vec![one.chunks()[0].clone(); 2],
                )
                .unwrap();
                changed[5] = (multiple.id(), multiple.encode(), bytes);
            }
        }
        assert!(cache
            .put_single_chunk_manifests_with_deadline(&references(&changed), deadline())
            .is_err());
        assert_eq!(cache.cache_usage().unwrap(), before);
        for (pinned, wire, _) in &original {
            let manifest = CellManifestV1::decode(wire).unwrap();
            assert!(cache.manifest(*pinned).unwrap().is_none());
            assert!(cache.chunk(manifest.chunks()[0].sha256).unwrap().is_none());
        }
        assert_limits(&path, config());
    }
}

#[test]
fn single_chunk_batch_each_logical_quota_rolls_back_pairs_and_original_retry_is_idempotent() {
    let materials: Vec<_> = (1..=6).map(|byte| material(byte, 1024)).collect();
    let refs = references(&materials);
    for bound in 0..3 {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("quota.sqlite");
        let mut finite = config();
        match bound {
            0 => finite.max_chunk_rows = 5,
            1 => finite.max_manifest_rows = 5,
            _ => finite.max_logical_bytes = usage(&materials).logical_bytes - 1,
        }
        let cache = CellStoreV1::open(&path, finite).unwrap();
        let before = cache.cache_usage().unwrap();
        assert!(matches!(
            cache.put_single_chunk_manifests_with_deadline(&refs, deadline()),
            Err(CellErrorV1::CacheQuotaExceeded)
        ));
        assert_eq!(cache.cache_usage().unwrap(), before);
        assert_limits(&path, finite);
        drop(cache);
        let cache = CellStoreV1::open(&path, finite).unwrap();
        assert_eq!(cache.cache_usage().unwrap(), before);
        for _ in 0..2 {
            cache
                .put_single_chunk_manifests_with_deadline(&refs[..5], deadline())
                .unwrap();
            assert_eq!(cache.cache_usage().unwrap(), usage(&materials[..5]));
        }
        assert_limits(&path, finite);
        drop(cache);
        let cache = CellStoreV1::open_read_only(&path).unwrap();
        assert_present(&cache, &materials[..5]);
        let absent = CellManifestV1::decode(&materials[5].1).unwrap();
        assert!(cache.manifest(materials[5].0).unwrap().is_none());
        assert!(cache.chunk(absent.chunks()[0].sha256).unwrap().is_none());
    }
}

#[test]
fn single_chunk_batch_real_sqlite_full_rolls_back_pairs_and_preserves_cold_prefix() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("physical-full.sqlite");
    let finite = CellCacheConfigV4 {
        max_database_bytes: 262_144,
        ..config()
    };
    let cache = CellStoreV1::open(&path, finite).unwrap();
    let baseline = [material(20, 16_384)];
    cache
        .put_single_chunk_manifests_with_deadline(&references(&baseline), deadline())
        .unwrap();
    let before = cache.cache_usage().unwrap();
    let materials: Vec<_> = (1..=6).map(|byte| material(byte, 65_536)).collect();
    let attempted = usage(&materials);
    assert!(before.logical_bytes + attempted.logical_bytes < finite.max_logical_bytes);
    assert!(before.chunk_rows + attempted.chunk_rows < finite.max_chunk_rows);
    assert!(before.manifest_rows + attempted.manifest_rows < finite.max_manifest_rows);
    assert!(
        materials
            .iter()
            .map(|(_, _, bytes)| bytes.len() as u64)
            .sum::<u64>()
            > finite.max_database_bytes
    );
    match cache.put_single_chunk_manifests_with_deadline(&references(&materials), deadline()) {
        Err(CellErrorV1::Sql(rusqlite::Error::SqliteFailure(error, message))) => {
            eprintln!("actual SQLite error: {error:?} {message:?}");
            assert_eq!(error.code, rusqlite::ErrorCode::DiskFull);
            assert_eq!(error.extended_code, 13);
        }
        other => panic!("expected native SQLITE_FULL, got {other:?}"),
    }
    assert_eq!(cache.cache_usage().unwrap(), before);
    assert_present(&cache, &baseline);
    assert_limits(&path, finite);
    drop(cache);
    for read_only in [true, false] {
        let reopened = if read_only {
            CellStoreV1::open_read_only(&path).unwrap()
        } else {
            CellStoreV1::open(&path, finite).unwrap()
        };
        assert_eq!(reopened.cache_usage().unwrap(), before);
        assert_present(&reopened, &baseline);
        for (pinned, wire, _) in &materials {
            let manifest = CellManifestV1::decode(wire).unwrap();
            assert!(reopened.manifest(*pinned).unwrap().is_none());
            assert!(reopened
                .chunk(manifest.chunks()[0].sha256)
                .unwrap()
                .is_none());
        }
        let pages: u64 = reopened
            .connection
            .pragma_query_value(None, "page_count", |row| row.get(0))
            .unwrap();
        let page_size: u64 = reopened
            .connection
            .pragma_query_value(None, "page_size", |row| row.get(0))
            .unwrap();
        assert_eq!(page_size, 4096);
        assert!(pages.checked_mul(page_size).unwrap() <= finite.max_database_bytes);
        assert_limits(&path, finite);
    }
    // A supported smaller retry keeps the same physical limit. It cannot
    // reset that limit by opening a fresh writer, or charge a duplicate twice.
    let cache = CellStoreV1::open(&path, finite).unwrap();
    let expected = [baseline[0].clone(), materials[0].clone()];
    for _ in 0..2 {
        cache
            .put_single_chunk_manifests_with_deadline(&references(&materials[..1]), deadline())
            .unwrap();
        assert_eq!(cache.cache_usage().unwrap(), usage(&expected));
    }
    assert_limits(&path, finite);
    drop(cache);
    let reopened = CellStoreV1::open_read_only(&path).unwrap();
    assert_eq!(reopened.cache_usage().unwrap(), usage(&expected));
    assert_present(&reopened, &expected);
}

#[test]
fn single_chunk_batch_held_reader_refuses_whole_batch_then_cold_retry_preserves_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("reader.sqlite");
    let cache = CellStoreV1::open(&path, config()).unwrap();
    let first = [material(20, 1024)];
    cache
        .put_single_chunk_manifests_with_deadline(&references(&first), deadline())
        .unwrap();
    let before = cache.cache_usage().unwrap();
    let reader = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    reader.execute_batch("BEGIN").unwrap();
    let count: u64 = reader
        .query_row("SELECT count(*) FROM cell_chunks_v1", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 1);
    let wal = crate::cell::cache_wal::sidecar(&path, "-wal");
    let wal_before = fs::metadata(&wal).unwrap().len();
    let materials: Vec<_> = (1..=6).map(|byte| material(byte, 1024)).collect();
    let refs = references(&materials);
    for _ in 0..2 {
        assert!(matches!(
            cache.put_single_chunk_manifests_with_deadline(&refs, deadline()),
            Err(CellErrorV1::CacheWriterBusy)
        ));
        assert_eq!(cache.cache_usage().unwrap(), before);
        assert_eq!(fs::metadata(&wal).unwrap().len(), wal_before);
        assert_limits(&path, config());
    }
    reader.execute_batch("ROLLBACK").unwrap();
    drop(reader);
    for _ in 0..2 {
        cache
            .put_single_chunk_manifests_with_deadline(&refs, deadline())
            .unwrap();
    }
    let all: Vec<_> = first.into_iter().chain(materials).collect();
    assert_eq!(cache.cache_usage().unwrap(), usage(&all));
    assert_limits(&path, config());
    drop(cache);
    let cache = CellStoreV1::open_read_only(&path).unwrap();
    assert_present(&cache, &all);
}

#[test]
fn single_chunk_batch_expired_empty_and_input_bounds_do_not_write() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bounds.sqlite");
    let cache = CellStoreV1::open(&path, config()).unwrap();
    let before = cache.cache_usage().unwrap();
    let small = [material(1, 1024)];
    let refs = references(&small);
    assert!(cache
        .put_single_chunk_manifests_with_deadline(&refs, Instant::now() - Duration::from_millis(1),)
        .is_err());
    assert!(cache
        .put_single_chunk_manifests_with_deadline(&[], deadline())
        .is_err());
    assert!(cache
        .put_single_chunk_manifests_with_deadline(&[refs[0]; 9], deadline())
        .is_err());
    // Eight maximum-size payload references fit the old payload-only ceiling,
    // but their manifest wires exceed the new combined 32 MiB input bound.
    let large = [material(2, MAX_CHUNK_BYTES as usize)];
    let large_refs = references(&large);
    assert!(cache
        .put_single_chunk_manifests_with_deadline(&[large_refs[0]; 8], deadline())
        .is_err());
    assert_eq!(cache.cache_usage().unwrap(), before);
    assert_limits(&path, config());
}
