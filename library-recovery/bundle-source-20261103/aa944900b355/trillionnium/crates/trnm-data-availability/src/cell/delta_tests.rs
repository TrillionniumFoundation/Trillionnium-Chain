use std::{
    fs,
    path::Path,
    time::{Duration, Instant},
};

use super::*;

fn context(parent: u8) -> CellContextV1 {
    CellContextV1 {
        family: "delta-test".into(),
        base: [1; 32],
        parent: [parent; 32],
        tokenizer: [3; 32],
        layout: [4; 32],
        runtime: [5; 32],
    }
}
fn config() -> CellCacheConfigV4 {
    CellCacheConfigV4 {
        max_database_bytes: 128 * 1024 * 1024,
        max_logical_bytes: 64 * 1024 * 1024,
        max_chunk_rows: 4096,
        max_manifest_rows: 256,
    }
}
fn limits() -> CellReleaseFetchLimitsV1 {
    CellReleaseFetchLimitsV1 {
        peer: CellPeerLimitsV1 {
            request_timeout: Duration::from_millis(100),
            overall_timeout: Duration::from_secs(5),
            max_cell_bytes: 1_048_576,
            parallelism: 2,
            max_connections: 10,
            max_response_bytes: 0,
        },
        release: CellReleaseLimitsV1 {
            max_payload_bytes: 1_048_576,
            max_chunks: 64,
            deadline: Instant::now() + Duration::from_secs(5),
        },
    }
}
fn pack(store: &CellStoreV1, path: &Path, bytes: &[u8], parent: u8) -> CellManifestV1 {
    fs::write(path, bytes).unwrap();
    store.pack_file(path, context(parent), 16_384).unwrap()
}

#[test]
fn verified_delta_reuses_shared_base_and_publishes_full_exact_target() {
    let dir = tempfile::tempdir().unwrap();
    let store = CellStoreV1::open(&dir.path().join("cache.sqlite"), config()).unwrap();
    let base_bytes = [vec![11; 16_384], vec![12; 16_384]].concat();
    let target_bytes = [vec![12; 16_384], vec![13; 16_384], vec![11; 100]].concat();
    let base = pack(&store, &dir.path().join("base"), &base_bytes, 2);
    let target = pack(&store, &dir.path().join("target"), &target_bytes, 6);
    let delta = CellChunkDeltaV1::between(&base, &target).unwrap();
    let decoded = CellChunkDeltaV1::decode(&delta.encode()).unwrap();
    assert_eq!(decoded, delta);
    let plan = delta.verify(&base).unwrap();
    assert_eq!(plan.reused_chunks, 1);
    assert_eq!(plan.reused_bytes, 16_384);
    assert_eq!(plan.new_chunks, 2);
    assert_eq!(plan.new_bytes, 16_484);
    let output = dir.path().join("out");
    let (observed, fetch) = fetch_delta_to_file(
        &store,
        &delta,
        (delta.id(), base.id(), target.id()),
        &[],
        limits(),
        &output,
    )
    .unwrap();
    assert_eq!(observed, plan);
    assert_eq!(fetch.connection_attempts, 0);
    assert_eq!(fetch.downloaded_bytes, 0);
    assert_eq!(fs::read(output).unwrap(), target_bytes);
}

#[test]
fn malformed_delta_ranges_and_noncanonical_base_indices_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    let store = CellStoreV1::open(&dir.path().join("cache"), config()).unwrap();
    let base = pack(&store, &dir.path().join("base"), &vec![11; 32_768], 2);
    let target = pack(&store, &dir.path().join("target"), &vec![11; 16_384], 6);
    let delta = CellChunkDeltaV1::between(&base, &target).unwrap();
    let wire = delta.encode();
    for end in 0..wire.len() {
        assert!(CellChunkDeltaV1::decode(&wire[..end]).is_err());
    }
    let mut extra = wire.clone();
    extra.push(0);
    assert!(CellChunkDeltaV1::decode(&extra).is_err());
    let mut oversized = wire.clone();
    oversized[36..40].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(CellChunkDeltaV1::decode(&oversized).is_err());
    // Same bytes at base index 1 cannot create an alternate recipe for index 0.
    let mut alias = wire;
    let offset = alias.len() - 4;
    alias[offset..].copy_from_slice(&1u32.to_be_bytes());
    assert!(CellChunkDeltaV1::decode(&alias)
        .unwrap()
        .verify(&base)
        .is_err());
    assert!(delta.verify(&target).is_err());
}

#[test]
fn corrupt_base_fails_before_target_metadata_or_output_and_budget_covers_both_payloads() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cache");
    let store = CellStoreV1::open(&path, config()).unwrap();
    let base = pack(&store, &dir.path().join("base"), &vec![11; 16_384], 2);
    let origin = CellStoreV1::open(&dir.path().join("origin"), config()).unwrap();
    let target = pack(&origin, &dir.path().join("target"), &vec![12; 16_384], 6);
    let delta = CellChunkDeltaV1::between(&base, &target).unwrap();
    let pins = (delta.id(), base.id(), target.id());
    let output = dir.path().join("out");
    let mut cap = limits();
    cap.release.max_payload_bytes = base.size();
    assert!(fetch_delta_to_file(&store, &delta, pins, &[], cap, &output).is_err());
    assert!(store.manifest(target.id()).unwrap().is_none());
    let connection = rusqlite::Connection::open(&path).unwrap();
    connection
        .execute(
            "UPDATE cell_chunks_v1 SET bytes=zeroblob(length(bytes))",
            [],
        )
        .unwrap();
    drop(connection);
    assert!(fetch_delta_to_file(&store, &delta, pins, &[], limits(), &output).is_err());
    assert!(!output.exists());
    assert!(store.manifest(target.id()).unwrap().is_none());
}

#[test]
fn valid_chunks_cannot_bypass_target_whole_payload_hash_or_owner_pins() {
    let dir = tempfile::tempdir().unwrap();
    let store = CellStoreV1::open(&dir.path().join("cache"), config()).unwrap();
    let base = pack(&store, &dir.path().join("base"), &vec![11; 16_384], 2);
    let target = CellManifestV1::new(
        context(6),
        base.size(),
        [77; 32],
        16_384,
        base.chunks().to_vec(),
    )
    .unwrap();
    let delta = CellChunkDeltaV1::between(&base, &target).unwrap();
    let output = dir.path().join("out");
    assert!(fetch_delta_to_file(
        &store,
        &delta,
        ([9; 32], base.id(), target.id()),
        &[],
        limits(),
        &output
    )
    .is_err());
    assert!(store.manifest(target.id()).unwrap().is_none());
    assert!(fetch_delta_to_file(
        &store,
        &delta,
        (delta.id(), base.id(), target.id()),
        &[],
        limits(),
        &output
    )
    .is_err());
    assert!(!output.exists());
}
