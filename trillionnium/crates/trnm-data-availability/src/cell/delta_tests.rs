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
    let mut wrong_version = wire.clone();
    wrong_version[..4].copy_from_slice(b"TCX2");
    assert!(CellChunkDeltaV1::decode(&wrong_version).is_err());
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
fn delta_metadata_contention_spends_original_deadline_without_a_late_write() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cache");
    let store = CellStoreV1::open(&path, config()).unwrap();
    let payload = vec![11; 16_384];
    let base = pack(&store, &dir.path().join("base"), &payload, 2);
    let target = CellManifestV1::new(
        context(6),
        base.size(),
        base.payload_sha256(),
        16_384,
        base.chunks().to_vec(),
    )
    .unwrap();
    let delta = CellChunkDeltaV1::between(&base, &target).unwrap();
    let pins = (delta.id(), base.id(), target.id());
    let output = dir.path().join("out");
    let before = store.cache_usage().unwrap();
    // The competing writer holds the actual cache-owner lock. Reads of the
    // valid base still succeed, so this reaches target metadata persistence.
    let (_, competing_writer) = super::cache_wal::writer_identity(&path).unwrap();
    let permit =
        super::cache_wal::acquire(&competing_writer, Instant::now() + Duration::from_secs(1))
            .unwrap();
    let mut bounded = limits();
    bounded.peer.overall_timeout = Duration::from_millis(250);
    bounded.release.deadline = Instant::now() + Duration::from_millis(250);
    let started = Instant::now();
    let result = fetch_delta_to_file(&store, &delta, pins, &[], bounded, &output);
    let elapsed = started.elapsed();
    drop(permit);
    assert!(matches!(result, Err(CellErrorV1::CacheWriterBusy)));
    assert!(
        elapsed < Duration::from_secs(2),
        "writer extended caller budget: {elapsed:?}"
    );
    assert_eq!(store.cache_usage().unwrap(), before);
    assert!(store.manifest(target.id()).unwrap().is_none());
    assert!(!output.exists());

    // An explicit new attempt keeps the original pins and reuses actual base
    // bytes. An expired attempt never manufactures a target completion marker.
    fetch_delta_to_file(&store, &delta, pins, &[], limits(), &output).unwrap();
    assert_eq!(fs::read(output).unwrap(), payload);
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

#[test]
fn delta_reconstruction_requires_only_direct_base_even_after_many_version_steps() {
    let dir = tempfile::tempdir().unwrap();
    let origin = CellStoreV1::open(&dir.path().join("origin"), config()).unwrap();
    let base_part = vec![71; 16_384];
    let mut history = Vec::new();
    for version in 1u8..=32 {
        let payload = [base_part.clone(), vec![version; 16_384]].concat();
        let manifest = pack(&origin, &dir.path().join("input"), &payload, version);
        if let Some(previous) = history.last() {
            // Each published recipe retains a complete target; no recursive
            // instruction references an older recipe or needs its decoder.
            let delta = CellChunkDeltaV1::between(previous, &manifest).unwrap();
            assert_eq!(delta.verify(previous).unwrap().new_bytes, 16_384);
        }
        history.push(manifest);
    }
    let base = &history[30];
    let target = &history[31];
    let consumer = CellStoreV1::open(&dir.path().join("consumer"), config()).unwrap();
    consumer.put_manifest(base.id(), &base.encode()).unwrap();
    for chunk in base.chunks().iter().chain(target.chunks()) {
        consumer
            .put_chunk(chunk, &origin.chunk(chunk.sha256).unwrap().unwrap())
            .unwrap();
    }
    for ancestor in &history[..30] {
        assert!(consumer.manifest(ancestor.id()).unwrap().is_none());
    }
    let delta = CellChunkDeltaV1::between(base, target).unwrap();
    let mut bounded = limits();
    bounded.release.max_payload_bytes = base.size() + target.size();
    bounded.release.max_chunks = (base.chunks().len() + target.chunks().len()) as u64;
    let output = dir.path().join("direct-target");
    let (plan, report) = fetch_delta_to_file(
        &consumer,
        &delta,
        (delta.id(), base.id(), target.id()),
        &[],
        bounded,
        &output,
    )
    .unwrap();
    assert_eq!(plan.reused_chunks, 1);
    assert_eq!(plan.new_chunks, 1);
    assert_eq!(report.downloaded_bytes, 0);
    assert_eq!(report.connection_attempts, 0);
    assert_eq!(
        fs::read(output).unwrap(),
        [base_part, vec![32; 16_384]].concat()
    );
    assert_eq!(consumer.cache_usage().unwrap().manifest_rows, 2);
}

#[test]
fn delta_late_owner_event_preserves_published_target_but_refuses_success() {
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };

    for cancel_after_publication in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let store = CellStoreV1::open(&dir.path().join("cache"), config()).unwrap();
        let bytes = vec![49; 16_384];
        let base = pack(&store, &dir.path().join("base"), &bytes, 2);
        let target = pack(&store, &dir.path().join("target"), &bytes, 6);
        let delta = CellChunkDeltaV1::between(&base, &target).unwrap();
        let output = dir.path().join("durable-target");
        let observed_path = output.clone();
        let expected_bytes = bytes.clone();
        let cancel = Arc::new(AtomicBool::new(false));
        let event_cancel = cancel.clone();
        let mut bounded = limits();
        bounded.release.deadline = Instant::now() + Duration::from_secs(1);
        let deadline = bounded.release.deadline;
        super::delta::AFTER_TARGET_FETCH.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                assert_eq!(fs::read(&observed_path).unwrap(), expected_bytes);
                if cancel_after_publication {
                    event_cancel.store(true, Ordering::Release);
                } else {
                    std::thread::sleep(
                        deadline.saturating_duration_since(Instant::now())
                            + Duration::from_millis(1),
                    );
                }
            }));
        });
        let result = delta.fetch_cancellable_to_file(
            &store,
            (delta.id(), base.id(), target.id()),
            &[],
            bounded,
            &output,
            &cancel,
        );
        super::delta::AFTER_TARGET_FETCH.with(|hook| {
            assert!(
                hook.borrow().is_none(),
                "real target publication was not reached"
            );
        });
        if cancel_after_publication {
            assert!(matches!(result, Err(CellErrorV1::Io(error))
                if error.kind() == std::io::ErrorKind::Interrupted
                    && error.to_string().contains("CELL_OPERATION_CANCELLED")));
        } else {
            assert!(matches!(
                result,
                Err(CellErrorV1::Invalid("delta deadline"))
            ));
        }
        assert_eq!(fs::read(&output).unwrap(), bytes);
        store.verify_complete(&target).unwrap();
        assert!(!fs::read_dir(dir.path()).unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .ends_with(".partial")
        }));
    }
}
