use super::*;
use crate::cell::{CellCacheConfigV4, CellCacheUsageV2, CellChunkV1, CellContextV1, CellErrorV1};
use sha2::{Digest, Sha256};
use std::{fs, path::Path, time::Duration};

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(10)
}

fn manifest(tag: u8, payloads: &[Vec<u8>]) -> CellManifestV1 {
    let mut full = Sha256::new();
    for payload in payloads {
        full.update(payload);
    }
    CellManifestV1::new(
        CellContextV1 {
            family: "cache-discard".into(),
            base: [tag; 32],
            parent: [0; 32],
            tokenizer: [0; 32],
            layout: [0; 32],
            runtime: [0; 32],
        },
        payloads.iter().map(|payload| payload.len() as u64).sum(),
        full.finalize().into(),
        16_384,
        payloads
            .iter()
            .map(|payload| CellChunkV1 {
                size: payload.len() as u32,
                sha256: Sha256::digest(payload).into(),
            })
            .collect(),
    )
    .unwrap()
}

fn publish(cache: &CellStoreV1, manifest: &CellManifestV1, payloads: &[Vec<u8>]) {
    for (chunk, payload) in manifest.chunks().iter().zip(payloads) {
        cache.put_chunk(chunk, payload).unwrap();
    }
    cache
        .put_manifest(manifest.id(), &manifest.encode())
        .unwrap();
    cache.verify_complete(manifest).unwrap();
}

fn assert_files_bounded(path: &Path, config: CellCacheConfigV4) {
    assert!(fs::metadata(path).unwrap().len() <= config.max_database_bytes);
    for (suffix, bound) in [
        ("-wal", config.max_wal_bytes().unwrap()),
        ("-shm", config.max_shm_bytes().unwrap()),
    ] {
        let sidecar = crate::cell::cache_wal::sidecar(path, suffix);
        assert!(fs::metadata(sidecar).map_or(0, |metadata| metadata.len()) <= bound);
    }
}

#[test]
fn discard_reclaims_exact_quota_for_different_bytes_after_reopen() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("bounded-cache.sqlite");
    // The same hash occurs twice in the payload, but occupies and frees one row.
    let first_payloads = vec![vec![1; 16_384]; 2];
    let second_payloads = vec![vec![2; 16_384]; 2];
    let first = manifest(1, &first_payloads);
    let second = manifest(2, &second_payloads);
    let config = CellCacheConfigV4 {
        max_database_bytes: 262_144,
        max_logical_bytes: 16_384 + 32 + first.encode().len() as u64 + 32,
        max_chunk_rows: 1,
        max_manifest_rows: 1,
    };
    let cache = CellStoreV1::open(&path, config).unwrap();
    publish(&cache, &first, &first_payloads);
    let full = CellCacheUsageV2 {
        logical_bytes: config.max_logical_bytes,
        chunk_rows: 1,
        manifest_rows: 1,
    };
    assert_eq!(cache.cache_usage().unwrap(), full);
    assert!(cache
        .put_chunk(&second.chunks()[0], &second_payloads[0])
        .is_err());
    assert_eq!(cache.cache_usage().unwrap(), full);
    cache.discard_manifest_until(&first, deadline()).unwrap();
    let empty = CellCacheUsageV2 {
        logical_bytes: 0,
        chunk_rows: 0,
        manifest_rows: 0,
    };
    assert_eq!(cache.cache_usage().unwrap(), empty);
    assert!(cache.manifest(first.id()).unwrap().is_none());
    assert!(cache.chunk(first.chunks()[0].sha256).unwrap().is_none());
    assert_files_bounded(&path, config);
    drop(cache);

    let cache = CellStoreV1::open(&path, config).unwrap();
    assert_eq!(cache.cache_usage().unwrap(), empty);
    cache.discard_manifest_until(&first, deadline()).unwrap();
    assert_eq!(cache.cache_usage().unwrap(), empty);
    publish(&cache, &second, &second_payloads);
    assert_eq!(cache.cache_usage().unwrap(), full);
    assert_files_bounded(&path, config);
    drop(cache);

    let cache = CellStoreV1::open_read_only(&path).unwrap();
    assert_eq!(cache.cache_usage().unwrap(), full);
    cache.verify_complete(&second).unwrap();
    assert_files_bounded(&path, config);
}

#[test]
fn discard_preserves_other_manifest_owners_and_reclaims_only_unreferenced_chunks() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("shared-cache.sqlite");
    let first_payloads = vec![vec![1; 16_384], vec![2; 16_384]];
    let second_payloads = vec![vec![1; 16_384], vec![3; 16_384]];
    let unrelated_payloads = vec![vec![4; 16_384]];
    let first = manifest(1, &first_payloads);
    let second = manifest(2, &second_payloads);
    let unrelated = manifest(3, &unrelated_payloads);
    let config = CellCacheConfigV4 {
        max_database_bytes: 262_144,
        max_logical_bytes: 1_048_576,
        max_chunk_rows: 4,
        max_manifest_rows: 3,
    };
    let cache = CellStoreV1::open(&path, config).unwrap();
    publish(&cache, &first, &first_payloads);
    publish(&cache, &second, &second_payloads);
    publish(&cache, &unrelated, &unrelated_payloads);
    assert_eq!(cache.cache_usage().unwrap().chunk_rows, 4);
    cache.discard_manifest_until(&first, deadline()).unwrap();
    assert!(cache.manifest(first.id()).unwrap().is_none());
    assert_eq!(cache.manifest(second.id()).unwrap(), Some(second.clone()));
    assert_eq!(cache.cache_usage().unwrap().chunk_rows, 3);
    assert_eq!(cache.cache_usage().unwrap().manifest_rows, 2);
    cache.verify_complete(&second).unwrap();
    cache.verify_complete(&unrelated).unwrap();
    drop(cache);

    let cache = CellStoreV1::open(&path, config).unwrap();
    cache.verify_complete(&second).unwrap();
    cache.verify_complete(&unrelated).unwrap();
    // An absent original manifest does not confer ownership of shared bytes.
    cache.discard_manifest_until(&first, deadline()).unwrap();
    cache.verify_complete(&second).unwrap();
    assert_eq!(cache.cache_usage().unwrap().chunk_rows, 3);
    cache.discard_manifest_until(&second, deadline()).unwrap();
    assert_eq!(cache.cache_usage().unwrap().chunk_rows, 1);
    assert_eq!(cache.cache_usage().unwrap().manifest_rows, 1);
    cache.verify_complete(&unrelated).unwrap();
    assert_files_bounded(&path, config);
}

#[test]
fn discard_expired_or_read_only_request_preserves_cached_bytes_and_allowance() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("refused-discard.sqlite");
    let payloads = vec![vec![9; 16_384]];
    let manifest = manifest(9, &payloads);
    let config = CellCacheConfigV4 {
        max_database_bytes: 262_144,
        max_logical_bytes: 1_048_576,
        max_chunk_rows: 1,
        max_manifest_rows: 1,
    };
    let cache = CellStoreV1::open(&path, config).unwrap();
    publish(&cache, &manifest, &payloads);
    let before = cache.cache_usage().unwrap();
    assert!(cache
        .discard_manifest_until(&manifest, Instant::now() - Duration::from_secs(1))
        .is_err());
    assert_eq!(cache.cache_usage().unwrap(), before);
    cache.verify_complete(&manifest).unwrap();
    drop(cache);

    let cache = CellStoreV1::open_read_only(&path).unwrap();
    assert!(matches!(
        cache.discard_manifest_until(&manifest, deadline()),
        Err(CellErrorV1::Invalid("read-only cache"))
    ));
    assert_eq!(cache.cache_usage().unwrap(), before);
    assert_eq!(
        cache.manifest(manifest.id()).unwrap(),
        Some(manifest.clone())
    );
    cache.verify_complete(&manifest).unwrap();
    assert_files_bounded(&path, config);
}
