//! Actual TCP and cache observations for repeated content-addressed chunks.
//! Payload positions stay ordered; response budgets count only received bytes.

use super::*;
use crate::cell::{CellCacheConfigV4, CellContextV1};
use rusqlite::{params, Connection};
use sha2::{Digest, Sha256};
use std::{fs, sync::Arc, thread::JoinHandle};

const CHUNK_BYTES: usize = 16_384;

fn cache_config() -> CellCacheConfigV4 {
    CellCacheConfigV4 {
        max_database_bytes: 1_048_576,
        max_logical_bytes: 1_048_576,
        max_chunk_rows: 16,
        max_manifest_rows: 16,
    }
}

fn context() -> CellContextV1 {
    CellContextV1 {
        family: "shared-chunk-test".into(),
        base: [1; 32],
        parent: [2; 32],
        tokenizer: [3; 32],
        layout: [4; 32],
        runtime: [5; 32],
    }
}

fn fixture(values: &[u8]) -> (CellManifestV1, Vec<u8>, BTreeMap<CellDigestV1, Vec<u8>>) {
    let blocks: Vec<_> = values
        .iter()
        .map(|value| vec![*value; CHUNK_BYTES])
        .collect();
    let payload = blocks.concat();
    let chunks: Vec<_> = blocks
        .iter()
        .map(|bytes| CellChunkV1 {
            size: bytes.len() as u32,
            sha256: Sha256::digest(bytes).into(),
        })
        .collect();
    let objects = chunks
        .iter()
        .map(|chunk| chunk.sha256)
        .zip(blocks)
        .collect();
    let manifest = CellManifestV1::new(
        context(),
        payload.len() as u64,
        Sha256::digest(&payload).into(),
        CHUNK_BYTES as u32,
        chunks,
    )
    .unwrap();
    (manifest, payload, objects)
}

fn limits(objects: usize, parallelism: usize) -> CellPeerLimitsV1 {
    CellPeerLimitsV1 {
        request_timeout: Duration::from_secs(1),
        overall_timeout: Duration::from_secs(5),
        max_cell_bytes: 1_048_576,
        parallelism,
        max_connections: objects as u64,
        max_response_bytes: (objects * (CHUNK_BYTES + 9)) as u64,
    }
}

struct ObjectPeer {
    address: SocketAddr,
    stop: Arc<AtomicBool>,
    requested: Arc<Mutex<Vec<CellDigestV1>>>,
    worker: Option<JoinHandle<io::Result<()>>>,
}

impl ObjectPeer {
    fn start(objects: BTreeMap<CellDigestV1, Vec<u8>>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let cancelled = Arc::clone(&stop);
        let requested = Arc::new(Mutex::new(Vec::new()));
        let observed = Arc::clone(&requested);
        let worker = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(10);
            while !cancelled.load(Ordering::Relaxed) && Instant::now() < deadline {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream.set_read_timeout(Some(Duration::from_secs(1)))?;
                        stream.set_write_timeout(Some(Duration::from_secs(1)))?;
                        let mut query = [0; 37];
                        stream.read_exact(&mut query)?;
                        if &query[..5] != b"TCQ1\x02" {
                            return Err(io::Error::other("expected pinned chunk request"));
                        }
                        let digest: CellDigestV1 = query[5..].try_into().unwrap();
                        observed.lock().unwrap().push(digest);
                        let bytes = objects
                            .get(&digest)
                            .ok_or_else(|| io::Error::other("unrequested content object"))?;
                        let mut response = b"TCS1\0".to_vec();
                        response.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
                        response.extend_from_slice(bytes);
                        // A negative client may refuse an oversized response
                        // after its header. That refusal is not a server fault.
                        let _ = stream.write_all(&response);
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(1));
                    }
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => (),
                    Err(error) => return Err(error),
                }
            }
            Ok(())
        });
        Self {
            address,
            stop,
            requested,
            worker: Some(worker),
        }
    }

    fn finish(mut self) -> Vec<CellDigestV1> {
        self.stop.store(true, Ordering::Relaxed);
        self.worker.take().unwrap().join().unwrap().unwrap();
        let requested = self.requested.lock().unwrap().clone();
        requested
    }
}

impl Drop for ObjectPeer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

#[test]
fn repeated_missing_chunks_use_one_request_per_object_with_serial_and_parallel_workers() {
    for parallelism in [1, 4] {
        for values in [&[7, 7, 7][..], &[7, 8, 7][..]] {
            let dir = tempfile::tempdir().unwrap();
            let (manifest, payload, objects) = fixture(values);
            let unique = objects.len();
            let cache =
                CellStoreV1::open(&dir.path().join("cache.sqlite"), cache_config()).unwrap();
            cache
                .put_manifest(manifest.id(), &manifest.encode())
                .unwrap();
            let peer = ObjectPeer::start(objects);
            let output = dir.path().join("complete.weights");
            let bounded = limits(unique, parallelism);
            let result =
                fetch_cell_to_file(&cache, manifest.id(), &[peer.address], bounded, &output);
            let requested = peer.finish();
            let (actual, report) = result.unwrap();
            assert_eq!(actual, manifest);
            assert_eq!(requested.len(), unique);
            assert_eq!(requested.iter().collect::<BTreeSet<_>>().len(), unique);
            assert_eq!(report.connection_attempts, unique as u64);
            assert_eq!(report.received_response_bytes, bounded.max_response_bytes);
            assert_eq!(report.downloaded_chunks, values.len());
            assert_eq!(report.downloaded_bytes, (unique * CHUNK_BYTES) as u64);
            assert_eq!(report.cached_chunks, 0);
            assert_eq!(report.payload_bytes, payload.len() as u64);
            assert_eq!(fs::read(&output).unwrap(), payload);

            // A later cache-only invocation still counts the ordered positions
            // as cache hits and requires no provider or renewed byte allowance.
            let cached = fetch_cell(
                &cache,
                manifest.id(),
                &[],
                CellPeerLimitsV1 {
                    max_response_bytes: 0,
                    ..bounded
                },
            )
            .unwrap()
            .1;
            assert_eq!(cached.cached_chunks, values.len());
            assert_eq!(cached.downloaded_chunks, 0);
            assert_eq!(cached.downloaded_bytes, 0);
            assert_eq!(cached.connection_attempts, 0);
            assert_eq!(cached.received_response_bytes, 0);
        }
    }
}

#[test]
fn repeated_corrupt_cache_content_is_repaired_with_one_original_request() {
    let dir = tempfile::tempdir().unwrap();
    let (manifest, payload, objects) = fixture(&[7, 7, 7]);
    let path = dir.path().join("cache.sqlite");
    let cache = CellStoreV1::open(&path, cache_config()).unwrap();
    cache
        .put_manifest(manifest.id(), &manifest.encode())
        .unwrap();
    let chunk = &manifest.chunks()[0];
    cache.put_chunk(chunk, &objects[&chunk.sha256]).unwrap();
    Connection::open(&path)
        .unwrap()
        .execute(
            "UPDATE cell_chunks_v1 SET bytes=?2 WHERE hash=?1",
            params![chunk.sha256.as_slice(), vec![0_u8; CHUNK_BYTES]],
        )
        .unwrap();
    let peer = ObjectPeer::start(objects);
    let output = dir.path().join("repaired.weights");
    let bounded = limits(1, 4);
    let result = fetch_cell_to_file(&cache, manifest.id(), &[peer.address], bounded, &output);
    assert_eq!(peer.finish(), [chunk.sha256]);
    let (_, report) = result.unwrap();
    assert_eq!(report.cached_chunks, 0);
    assert_eq!(report.downloaded_chunks, manifest.chunks().len());
    assert_eq!(report.received_response_bytes, bounded.max_response_bytes);
    assert_eq!(fs::read(output).unwrap(), payload);
}

#[test]
fn repeated_content_still_rejects_wrong_full_payload_and_preserves_shared_cache() {
    let dir = tempfile::tempdir().unwrap();
    let (valid, payload, objects) = fixture(&[7, 7, 7]);
    let wrong = CellManifestV1::new(
        context(),
        valid.size(),
        [0; 32],
        CHUNK_BYTES as u32,
        valid.chunks().to_vec(),
    )
    .unwrap();
    let cache = CellStoreV1::open(&dir.path().join("cache.sqlite"), cache_config()).unwrap();
    cache.put_manifest(wrong.id(), &wrong.encode()).unwrap();
    let peer = ObjectPeer::start(objects);
    let output = dir.path().join("must-not-exist");
    let result = fetch_cell_to_file(&cache, wrong.id(), &[peer.address], limits(1, 4), &output);
    assert_eq!(peer.finish(), [valid.chunks()[0].sha256]);
    assert!(matches!(
        result,
        Err(CellErrorV1::Invalid("complete payload digest"))
    ));
    assert!(!output.exists());
    assert!(!fs::read_dir(dir.path()).unwrap().any(|entry| {
        entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .ends_with(".partial")
    }));
    // A distinct correctly pinned manifest reuses the retained content object.
    cache.put_manifest(valid.id(), &valid.encode()).unwrap();
    let verified = dir.path().join("valid.weights");
    let (_, report) = fetch_cell_to_file(
        &cache,
        valid.id(),
        &[],
        CellPeerLimitsV1 {
            max_response_bytes: 0,
            ..limits(1, 4)
        },
        &verified,
    )
    .unwrap();
    assert_eq!(report.cached_chunks, valid.chunks().len());
    assert_eq!(report.connection_attempts, 0);
    assert_eq!(fs::read(verified).unwrap(), payload);
}

#[test]
fn equal_chunk_digest_with_conflicting_lengths_fails_before_any_provider_request() {
    let dir = tempfile::tempdir().unwrap();
    let (valid, _, objects) = fixture(&[7]);
    let full = valid.chunks()[0].clone();
    let conflict = CellManifestV1::new(
        context(),
        (CHUNK_BYTES + CHUNK_BYTES / 2) as u64,
        [9; 32],
        CHUNK_BYTES as u32,
        vec![
            full.clone(),
            CellChunkV1 {
                size: (CHUNK_BYTES / 2) as u32,
                sha256: full.sha256,
            },
        ],
    )
    .unwrap();
    for cached in [false, true] {
        let path = dir.path().join(format!("cache-{cached}.sqlite"));
        let cache = CellStoreV1::open(&path, cache_config()).unwrap();
        cache
            .put_manifest(conflict.id(), &conflict.encode())
            .unwrap();
        if cached {
            cache.put_chunk(&full, &objects[&full.sha256]).unwrap();
        }
        let peer = ObjectPeer::start(objects.clone());
        let output = dir.path().join(format!("must-not-exist-{cached}"));
        let result = fetch_cell_to_file(
            &cache,
            conflict.id(),
            &[peer.address],
            limits(2, 4),
            &output,
        );
        assert!(peer.finish().is_empty());
        assert!(matches!(
            result,
            Err(CellErrorV1::Invalid("chunk digest length conflict"))
        ));
        assert!(!output.exists());
    }
}
