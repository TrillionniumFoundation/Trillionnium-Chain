use super::super::{CellCacheConfigV4, CellChunkV1};
use super::*;
use std::time::Duration;

fn context() -> CellContextV1 {
    CellContextV1 {
        family: "test-runtime-root-v1".into(),
        base: [1; 32],
        parent: [2; 32],
        tokenizer: [3; 32],
        layout: [4; 32],
        runtime: [5; 32],
    }
}
fn limits() -> CellRuntimeLimitsV1 {
    CellRuntimeLimitsV1 {
        peer: CellPeerLimitsV1 {
            request_timeout: Duration::from_millis(10),
            overall_timeout: Duration::from_secs(5),
            max_cell_bytes: 4 * 1024 * 1024,
            parallelism: 1,
            max_connections: 1,
            max_response_bytes: 0,
        },
        deadline: Instant::now() + Duration::from_secs(5),
        host_bytes: HOST_CAP,
        metadata_bytes: META_CAP,
        outstanding_owned_bytes: Some(0),
    }
}
fn setup() -> (tempfile::TempDir, CellStoreV1, CellRuntimeFileV1) {
    let tmp = tempfile::tempdir().unwrap();
    fs::set_permissions(tmp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let store = CellStoreV1::open(
        &tmp.path().join("cache.db"),
        CellCacheConfigV4 {
            max_database_bytes: 262144,
            max_logical_bytes: 196608,
            max_chunk_rows: 8,
            max_manifest_rows: 8,
        },
    )
    .unwrap();
    let mut full = Sha256::new();
    let mut segments = Vec::new();
    for byte in [17u8, 91u8] {
        let data = vec![byte; 16384];
        full.update(&data);
        let hash = Sha256::digest(&data).into();
        let manifest = CellManifestV1::new(
            context(),
            data.len() as u64,
            hash,
            16384,
            vec![CellChunkV1 {
                size: 16384,
                sha256: hash,
            }],
        )
        .unwrap();
        store
            .put_manifest(manifest.id(), &manifest.encode())
            .unwrap();
        store.put_chunk(&manifest.chunks()[0], &data).unwrap();
        segments.push(manifest);
    }
    (
        tmp,
        store,
        CellRuntimeFileV1 {
            path: "python/lib/lib-original.so".into(),
            role: CellRuntimeRoleV1::Native,
            bytes: 32768,
            sha256: full.finalize().into(),
            segments,
        },
    )
}
#[test]
fn reconstructs_original_bytes_and_retires_only_disposable_rows() {
    let (tmp, mut store, file) = setup();
    let root = runtime_files_root_v1(std::slice::from_ref(&file)).unwrap();
    let report = materialize_runtime_root_v1(
        &mut store,
        tmp.path(),
        "runtime-v1",
        CellRuntimePlanV1 {
            files: std::slice::from_ref(&file),
            expected_files_root: root,
            context: &context(),
        },
        &[],
        limits(),
    )
    .unwrap();
    assert_eq!(
        (
            report.files_root,
            report.reconstructed_bytes,
            report.connection_attempts,
            report.received_response_bytes
        ),
        (root, 32768, 0, 0)
    );
    let bytes = fs::read(tmp.path().join("runtime-v1").join(&file.path)).unwrap();
    assert_eq!(<[u8; 32]>::from(Sha256::digest(&bytes)), file.sha256);
    for segment in &file.segments {
        assert!(store.manifest(segment.id()).unwrap().is_none());
        assert!(store.chunk(segment.chunks()[0].sha256).unwrap().is_none());
    }
    assert!(tmp.path().join("runtime-reservation-v1").exists());
}
#[test]
fn segment_success_cannot_publish_a_wrong_whole_file_or_refund_attempt() {
    let (tmp, mut store, mut file) = setup();
    file.sha256 = [99; 32];
    let root = runtime_files_root_v1(std::slice::from_ref(&file)).unwrap();
    let result = materialize_runtime_root_v1(
        &mut store,
        tmp.path(),
        "runtime-v1",
        CellRuntimePlanV1 {
            files: std::slice::from_ref(&file),
            expected_files_root: root,
            context: &context(),
        },
        &[],
        limits(),
    );
    assert!(matches!(
        result,
        Err(CellErrorV1::Invalid("runtime whole-file digest"))
    ));
    assert!(!tmp.path().join("runtime-v1").exists());
    assert!(tmp
        .path()
        .join("runtime-v1.partial-runtime-v1")
        .join(&file.path)
        .exists());
    let reservation = fs::read(tmp.path().join("runtime-reservation-v1")).unwrap();
    assert!(materialize_runtime_root_v1(
        &mut store,
        tmp.path(),
        "runtime-v1",
        CellRuntimePlanV1 {
            files: &[file],
            expected_files_root: root,
            context: &context(),
        },
        &[],
        limits()
    )
    .is_err());
    assert_eq!(
        fs::read(tmp.path().join("runtime-reservation-v1")).unwrap(),
        reservation
    );
}
#[test]
fn unknown_cost_and_metadata_peak_refuse_before_destructive_cache_consumption() {
    let (tmp, mut store, file) = setup();
    let root = runtime_files_root_v1(std::slice::from_ref(&file)).unwrap();
    let mut cap = limits();
    cap.outstanding_owned_bytes = None;
    assert!(matches!(
        materialize_runtime_root_v1(
            &mut store,
            tmp.path(),
            "runtime-v1",
            CellRuntimePlanV1 {
                files: std::slice::from_ref(&file),
                expected_files_root: root,
                context: &context(),
            },
            &[],
            cap
        ),
        Err(CellErrorV1::Invalid("runtime unresolved owned cost"))
    ));
    cap = limits();
    cap.host_bytes = META_CAP - 1;
    assert!(matches!(
        materialize_runtime_root_v1(
            &mut store,
            tmp.path(),
            "runtime-v1",
            CellRuntimePlanV1 {
                files: std::slice::from_ref(&file),
                expected_files_root: root,
                context: &context(),
            },
            &[],
            cap
        ),
        Err(CellErrorV1::Invalid("runtime same-owner peak admission"))
    ));
    assert!(!tmp.path().join("runtime-reservation-v1").exists());
    for segment in &file.segments {
        assert!(store.chunk(segment.chunks()[0].sha256).unwrap().is_some());
    }
}
#[test]
fn roles_paths_context_and_coverage_cannot_be_relabelled_implicitly() {
    let (_, _, file) = setup();
    let mut bad = file.clone();
    bad.path = "../host/python".into();
    assert!(runtime_files_root_v1(&[bad]).is_err());
    let mut bad = file.clone();
    bad.segments.pop();
    assert!(validate_files(
        &[bad],
        &context(),
        Instant::now() + Duration::from_secs(5),
        META_CAP
    )
    .is_err());
    let mut other = context();
    other.runtime = [8; 32];
    assert!(validate_files(
        std::slice::from_ref(&file),
        &other,
        Instant::now() + Duration::from_secs(5),
        META_CAP
    )
    .is_err());
    let mut alias = file.clone();
    alias.role = CellRuntimeRoleV1::SitePackage;
    assert_ne!(
        runtime_files_root_v1(&[file]).unwrap(),
        runtime_files_root_v1(&[alias]).unwrap()
    );
}

// This is a real bounded TCP transfer, not a pre-populated consumer cache.
// The whole 256-KiB file is larger than the consumer's 192-KiB logical cache.
fn remote_materialization(
    connections: u64,
) -> (
    CellResultV1<CellRuntimeMaterializationV1>,
    tempfile::TempDir,
    Vec<u8>,
    u64,
) {
    use std::{
        net::TcpListener,
        sync::{atomic::AtomicBool, Arc},
        thread,
    };
    let provider_root = tempfile::tempdir().unwrap();
    let provider_path = provider_root.path().join("provider.db");
    let provider = CellStoreV1::open(
        &provider_path,
        CellCacheConfigV4 {
            max_database_bytes: 1048576,
            max_logical_bytes: 786432,
            max_chunk_rows: 8,
            max_manifest_rows: 8,
        },
    )
    .unwrap();
    let mut complete = Vec::new();
    let mut segments = Vec::new();
    for byte in [23u8, 61u8] {
        let data = vec![byte; 131072];
        complete.extend_from_slice(&data);
        let hash = Sha256::digest(&data).into();
        let manifest = CellManifestV1::new(
            context(),
            data.len() as u64,
            hash,
            131072,
            vec![CellChunkV1 {
                size: 131072,
                sha256: hash,
            }],
        )
        .unwrap();
        provider
            .put_manifest(manifest.id(), &manifest.encode())
            .unwrap();
        provider.put_chunk(&manifest.chunks()[0], &data).unwrap();
        segments.push(manifest);
    }
    drop(provider);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let shutdown = Arc::new(AtomicBool::new(false));
    let stop = shutdown.clone();
    let mut peer = limits().peer;
    peer.request_timeout = Duration::from_secs(1);
    peer.max_connections = 2;
    peer.max_response_bytes = 1024 * 1024;
    let server = thread::spawn(move || {
        let provider = CellStoreV1::open_read_only(&provider_path).unwrap();
        let served = super::super::serve_cells(&listener, &provider, &stop, peer).unwrap();
        for segment in &segments {
            assert!(provider.manifest(segment.id()).unwrap().is_some());
            assert!(provider
                .chunk(segment.chunks()[0].sha256)
                .unwrap()
                .is_some());
        }
        (served, segments)
    });
    // Reconstruct the same authority-pinned manifests locally; the provider has
    // no ability to select a different whole-file identity or context.
    let segments = complete
        .chunks(131072)
        .map(|bytes| {
            let hash = Sha256::digest(bytes).into();
            CellManifestV1::new(
                context(),
                bytes.len() as u64,
                hash,
                131072,
                vec![CellChunkV1 {
                    size: 131072,
                    sha256: hash,
                }],
            )
            .unwrap()
        })
        .collect();
    let tmp = tempfile::tempdir().unwrap();
    fs::set_permissions(tmp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let mut consumer = CellStoreV1::open(
        &tmp.path().join("cache.db"),
        CellCacheConfigV4 {
            max_database_bytes: 262144,
            max_logical_bytes: 196608,
            max_chunk_rows: 8,
            max_manifest_rows: 8,
        },
    )
    .unwrap();
    let file = CellRuntimeFileV1 {
        path: "lib/runtime-original.so".into(),
        role: CellRuntimeRoleV1::Native,
        bytes: complete.len() as u64,
        sha256: Sha256::digest(&complete).into(),
        segments,
    };
    let root = runtime_files_root_v1(std::slice::from_ref(&file)).unwrap();
    let mut cap = limits();
    cap.peer = peer;
    cap.peer.max_connections = connections;
    let outcome = materialize_runtime_root_v1(
        &mut consumer,
        tmp.path(),
        "runtime-v1",
        CellRuntimePlanV1 {
            files: &[file],
            expected_files_root: root,
            context: &context(),
        },
        &[address],
        cap,
    );
    shutdown.store(true, Ordering::Relaxed);
    let (served, _) = server.join().unwrap();
    (outcome, tmp, complete, served)
}
#[test]
fn real_peer_streams_file_larger_than_cache_with_one_original_transport() {
    let (outcome, tmp, complete, served) = remote_materialization(2);
    let report = outcome.unwrap();
    assert_eq!(
        (
            report.reconstructed_bytes,
            report.connection_attempts,
            report.received_response_bytes,
            served
        ),
        (262144, 2, 262144 + 18, 2)
    );
    assert_eq!(
        fs::read(tmp.path().join("runtime-v1/lib/runtime-original.so")).unwrap(),
        complete
    );
}
#[test]
fn real_peer_cannot_renew_exhausted_connection_budget_between_segments() {
    let (outcome, tmp, complete, served) = remote_materialization(1);
    assert!(outcome.is_err());
    assert_eq!(served, 1);
    assert!(!tmp.path().join("runtime-v1").exists());
    assert_eq!(
        fs::read(
            tmp.path()
                .join("runtime-v1.partial-runtime-v1/lib/runtime-original.so")
        )
        .unwrap(),
        complete[..131072]
    );
    assert!(tmp.path().join("runtime-reservation-v1").exists());
}
