//! TCD1 is a byte-plan qualifier. These fixtures do not install or run a model.

use std::{
    fs,
    net::{SocketAddr, TcpListener},
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use sha2::{Digest, Sha256};

use super::*;

fn vector() -> serde_json::Value {
    serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../formal/pon-nakamoto-v1/vectors/cell-dependency-closure-v1.json"
    )))
    .unwrap()
}

fn fixture_closure() -> CellReleaseClosureV1 {
    let data = vector();
    CellReleaseClosureV1::decode(&hex::decode(data["wire_hex"].as_str().unwrap()).unwrap()).unwrap()
}

fn rebuild(
    closure: &CellReleaseClosureV1,
    roots: Vec<u16>,
    files: Vec<CellClosureFileV1>,
) -> CellResultV1<CellReleaseClosureV1> {
    CellReleaseClosureV1::new(
        closure.release().context().clone(),
        closure.selected_generation(),
        closure.loader_profile(),
        roots,
        files,
    )
}

fn expected(closure: &CellReleaseClosureV1) -> CellLoaderContextV1 {
    CellLoaderContextV1 {
        closure_id: closure.id(),
        context: closure.release().context().clone(),
        selected_generation: closure.selected_generation(),
        loader_profile: closure.loader_profile(),
        required_roles: vec![CellFileRoleV1::Base, CellFileRoleV1::Tokenizer],
        max_payload_bytes: 1_048_576,
        max_chunks: 64,
    }
}

fn cache_config() -> CellCacheConfigV4 {
    CellCacheConfigV4 {
        max_database_bytes: 128 * 1024 * 1024,
        max_logical_bytes: 64 * 1024 * 1024,
        max_chunk_rows: 4096,
        max_manifest_rows: 256,
    }
}

fn peer_limits() -> CellPeerLimitsV1 {
    CellPeerLimitsV1 {
        request_timeout: Duration::from_secs(2),
        overall_timeout: Duration::from_secs(15),
        max_cell_bytes: 1_048_576,
        parallelism: 1,
        max_connections: 1000,
        max_response_bytes: 4 * 1_048_576,
    }
}

fn limits() -> CellReleaseFetchLimitsV1 {
    CellReleaseFetchLimitsV1 {
        peer: peer_limits(),
        release: CellReleaseLimitsV1 {
            max_payload_bytes: 1_048_576,
            max_chunks: 64,
            deadline: Instant::now() + Duration::from_secs(15),
        },
    }
}

struct Peer {
    address: SocketAddr,
    shutdown: Arc<AtomicBool>,
    handle: Option<JoinHandle<CellResultV1<u64>>>,
}

impl Peer {
    fn start(path: &Path) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let shutdown = Arc::new(AtomicBool::new(false));
        let stop = shutdown.clone();
        let path = path.to_owned();
        let handle = thread::spawn(move || {
            let store = CellStoreV1::open(&path, cache_config())?;
            serve_cells(&listener, &store, &stop, peer_limits())
        });
        Self {
            address,
            shutdown,
            handle: Some(handle),
        }
    }

    fn finish(mut self) -> u64 {
        self.shutdown.store(true, Ordering::Relaxed);
        self.handle.take().unwrap().join().unwrap().unwrap()
    }
}

impl Drop for Peer {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn populate(store: &CellStoreV1) -> Vec<CellManifestV1> {
    vector()["manifests"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| {
            let wire = hex::decode(value["wire_hex"].as_str().unwrap()).unwrap();
            let payload = hex::decode(value["payload_hex"].as_str().unwrap()).unwrap();
            let manifest = CellManifestV1::decode(&wire).unwrap();
            store.put_manifest(manifest.id(), &wire).unwrap();
            assert_eq!(manifest.chunks().len(), 1);
            store.put_chunk(&manifest.chunks()[0], &payload).unwrap();
            manifest
        })
        .collect()
}

fn cached_chunks(store: &CellStoreV1, manifests: &[CellManifestV1]) -> usize {
    manifests
        .iter()
        .flat_map(CellManifestV1::chunks)
        .filter(|chunk| store.chunk(chunk.sha256).unwrap().is_some())
        .count()
}

#[test]
fn closure_matches_independent_python_wire_and_existing_tcm_identities() {
    let data = vector();
    let wire = hex::decode(data["wire_hex"].as_str().unwrap()).unwrap();
    let closure = fixture_closure();
    assert_eq!(closure.encode(), wire);
    assert_eq!(
        hex::encode(closure.id()),
        data["closure_id"].as_str().unwrap()
    );
    assert_eq!(closure.roots(), &[2]);
    assert_eq!(closure.files()[2].dependencies, [0, 1]);
    closure.verify_for_loader(&expected(&closure)).unwrap();
    for value in data["manifests"].as_array().unwrap() {
        let manifest =
            CellManifestV1::decode(&hex::decode(value["wire_hex"].as_str().unwrap()).unwrap())
                .unwrap();
        closure.verify_manifest(&manifest).unwrap();
        let payload = hex::decode(value["payload_hex"].as_str().unwrap()).unwrap();
        let actual: CellDigestV1 = Sha256::digest(payload).into();
        assert_eq!(actual, manifest.payload_sha256());
    }
}

#[test]
fn closure_checks_independent_owner_context_and_required_roles() {
    let closure = fixture_closure();
    let baseline = expected(&closure);
    let mut wrong = baseline.clone();
    wrong.closure_id[0] ^= 1;
    assert!(closure.verify_for_loader(&wrong).is_err());
    wrong = baseline.clone();
    wrong.context.runtime[0] ^= 1;
    assert!(closure.verify_for_loader(&wrong).is_err());
    wrong = baseline.clone();
    wrong.selected_generation += 1;
    assert!(closure.verify_for_loader(&wrong).is_err());
    wrong = baseline.clone();
    wrong.loader_profile[0] ^= 1;
    assert!(closure.verify_for_loader(&wrong).is_err());
    wrong = baseline.clone();
    wrong.required_roles = vec![CellFileRoleV1::Adapter];
    assert!(closure.verify_for_loader(&wrong).is_err());
    wrong.required_roles.clear();
    assert!(closure.verify_for_loader(&wrong).is_err());
    wrong.required_roles = vec![CellFileRoleV1::Base, CellFileRoleV1::Base];
    assert!(closure.verify_for_loader(&wrong).is_err());
    wrong = baseline.clone();
    wrong.max_payload_bytes = closure
        .files()
        .iter()
        .map(|file| file.payload_bytes)
        .sum::<u64>()
        - 1;
    assert!(closure.verify_for_loader(&wrong).is_err());
    wrong = baseline;
    wrong.max_chunks = 0;
    assert!(closure.verify_for_loader(&wrong).is_err());
}

#[test]
fn closure_refuses_path_traversal_platform_aliases_and_file_directory_conflicts() {
    let closure = fixture_closure();
    for path in [
        "../model",
        "/model",
        "base/../model",
        "base//model",
        "base/./model",
        "base\\model",
        "base/model.",
        "base/.hidden",
        "base/con.bin",
        "base/CON.bin",
        "base/com1.json",
        "base/lpt9.txt",
        "base/a:b",
        "base/model ",
        "base/模型",
        "a/b/c/d/e/f/g/h/i",
    ] {
        let mut files = closure.files().to_vec();
        files[0].path = path.into();
        assert!(
            rebuild(&closure, closure.roots().to_vec(), files).is_err(),
            "{path}"
        );
    }
    let mut files = closure.files().to_vec();
    files[0].path = "base".into();
    files[1].path = "base/tokenizer.json".into();
    assert!(rebuild(&closure, closure.roots().to_vec(), files).is_err());
    let mut files = closure.files().to_vec();
    files[1].path = files[0].path.clone();
    assert!(rebuild(&closure, closure.roots().to_vec(), files).is_err());
    let mut files = closure.files().to_vec();
    files.swap(0, 1);
    assert!(rebuild(&closure, closure.roots().to_vec(), files).is_err());
}

#[test]
fn closure_preserves_owner_readme_names_but_refuses_case_fold_aliases() {
    let closure = fixture_closure();
    let mut files = closure.files().to_vec();
    files[0].path = "base/README.md".into();
    let portable = rebuild(&closure, closure.roots().to_vec(), files.clone()).unwrap();
    assert_eq!(
        CellReleaseClosureV1::decode(&portable.encode()).unwrap(),
        portable
    );
    files[1].path = "base/readme.md".into();
    assert!(rebuild(&closure, closure.roots().to_vec(), files).is_err());
    let mut files = closure.files().to_vec();
    files[0].path = "BASE".into();
    files[1].path = "base/tokenizer.json".into();
    assert!(rebuild(&closure, closure.roots().to_vec(), files).is_err());
}

#[test]
fn closure_refuses_missing_duplicate_cyclic_and_unreachable_dependencies() {
    let closure = fixture_closure();
    for dependencies in [vec![3], vec![0, 0], vec![1, 0], vec![2], vec![0]] {
        let mut files = closure.files().to_vec();
        files[2].dependencies = dependencies;
        assert!(rebuild(&closure, vec![2], files).is_err());
    }
    let mut files = closure.files().to_vec();
    files[0].dependencies = vec![2];
    assert!(rebuild(&closure, vec![2], files).is_err());
    for roots in [vec![], vec![3], vec![2, 2], vec![2, 0], vec![0, 1]] {
        assert!(rebuild(&closure, roots, closure.files().to_vec()).is_err());
    }
    let mut files = closure.files().to_vec();
    files[1].manifest = files[0].manifest;
    assert!(rebuild(&closure, vec![2], files).is_err());
}

fn chain_files(count: usize) -> Vec<CellClosureFileV1> {
    (0..count)
        .map(|index| CellClosureFileV1 {
            path: format!("f{index:03}.bin"),
            role: CellFileRoleV1::Base,
            manifest: Sha256::digest(format!("manifest-{index}")).into(),
            payload_sha256: Sha256::digest(format!("payload-{index}")).into(),
            payload_bytes: 1,
            dependencies: if index == 0 {
                vec![]
            } else {
                vec![(index - 1) as u16]
            },
        })
        .collect()
}

#[test]
fn closure_bounds_longest_dependency_path_including_shared_subgraphs() {
    let closure = fixture_closure();
    rebuild(&closure, vec![15], chain_files(16)).unwrap();
    assert!(rebuild(&closure, vec![16], chain_files(17)).is_err());
    // Visit the leaf chain first. A later root reuses memoized descendants;
    // the depth bound must still apply to the complete path from that root.
    assert!(rebuild(&closure, vec![15, 16], chain_files(17)).is_err());
    let mut files = chain_files(4);
    files[2].dependencies = vec![0];
    files[3].dependencies = vec![1, 2];
    rebuild(&closure, vec![3], files).unwrap();
    let mut files = chain_files(256);
    for file in &mut files {
        file.dependencies.clear();
    }
    rebuild(&closure, (0..256).collect(), files).unwrap();
    assert!(rebuild(&closure, vec![256], chain_files(257)).is_err());
}

#[test]
fn closure_decoder_rejects_truncation_suffix_oversize_and_inconsistent_membership() {
    let closure = fixture_closure();
    let wire = closure.encode();
    for end in 0..wire.len() {
        assert!(
            CellReleaseClosureV1::decode(&wire[..end]).is_err(),
            "prefix {end}"
        );
    }
    let mut bad = wire.clone();
    bad.push(0);
    assert!(CellReleaseClosureV1::decode(&bad).is_err());
    assert!(CellReleaseClosureV1::decode(&vec![0; MAX_CELL_CLOSURE_BYTES_V1 + 1]).is_err());
    let mut bad = wire.clone();
    bad[44..48].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(CellReleaseClosureV1::decode(&bad).is_err());
    let release_end = 48 + closure.release().encode().len();
    let first_path_size = release_end + 2 + 2 * closure.roots().len() + 2;
    let first_role = first_path_size + 2 + closure.files()[0].path.len();
    let mut bad = wire.clone();
    bad[first_role] = 255;
    assert!(CellReleaseClosureV1::decode(&bad).is_err());
    let mut bad = wire.clone();
    bad[first_role + 1] ^= 1;
    assert!(CellReleaseClosureV1::decode(&bad).is_err());
    let mut bad = wire.clone();
    bad[release_end..release_end + 2].copy_from_slice(&257u16.to_be_bytes());
    assert!(CellReleaseClosureV1::decode(&bad).is_err());
    let mut bad = wire;
    bad[first_path_size..first_path_size + 2].copy_from_slice(&256u16.to_be_bytes());
    assert!(CellReleaseClosureV1::decode(&bad).is_err());
}

#[test]
fn closure_fetches_real_loopback_bytes_and_publishes_exact_non_authorizing_marker() {
    let directory = tempfile::tempdir().unwrap();
    let origin_path = directory.path().join("origin.sqlite");
    let origin = CellStoreV1::open(&origin_path, cache_config()).unwrap();
    let manifests = populate(&origin);
    let peer = Peer::start(&origin_path);
    let receiver =
        CellStoreV1::open(&directory.path().join("receiver.sqlite"), cache_config()).unwrap();
    let closure = fixture_closure();
    let output = directory.path().join("complete.tcd");
    let report = fetch_closure_to_file(
        &receiver,
        &closure,
        &expected(&closure),
        &[peer.address],
        limits(),
        &output,
    )
    .unwrap();
    assert_eq!(report.closure_id, closure.id());
    assert_eq!(report.selected_generation, 7);
    assert_eq!(report.release.cells, 3);
    assert_eq!(
        report.release.payload_bytes,
        manifests.iter().map(CellManifestV1::size).sum::<u64>()
    );
    assert_eq!(report.release.downloaded_chunks, 3);
    assert_eq!(report.release.connection_attempts, 6);
    assert_eq!(peer.finish(), 6);
    assert_eq!(fs::read(&output).unwrap(), closure.encode());
    assert_eq!(cached_chunks(&receiver, &manifests), 3);
    receiver
        .verify_release_complete(closure.release(), limits().release)
        .unwrap();
    assert!(!directory.path().join("CURRENT").exists());
    assert!(matches!(
        fetch_closure_to_file(
            &receiver,
            &closure,
            &expected(&closure),
            &[],
            limits(),
            &output
        ),
        Err(CellErrorV1::Invalid("release marker exists"))
    ));
    assert_eq!(fs::read(output).unwrap(), closure.encode());
}

#[test]
fn closure_rejects_last_manifest_metadata_before_fetching_any_payload() {
    let directory = tempfile::tempdir().unwrap();
    let origin_path = directory.path().join("origin.sqlite");
    let origin = CellStoreV1::open(&origin_path, cache_config()).unwrap();
    let manifests = populate(&origin);
    let peer = Peer::start(&origin_path);
    let receiver =
        CellStoreV1::open(&directory.path().join("receiver.sqlite"), cache_config()).unwrap();
    let closure = fixture_closure();
    let last_manifest = *closure.release().cells().last().unwrap();
    let mut files = closure.files().to_vec();
    files
        .iter_mut()
        .find(|file| file.manifest == last_manifest)
        .unwrap()
        .payload_sha256[0] ^= 1;
    let closure = rebuild(&closure, closure.roots().to_vec(), files).unwrap();
    let output = directory.path().join("complete.tcd");
    assert!(matches!(
        fetch_closure_to_file(
            &receiver,
            &closure,
            &expected(&closure),
            &[peer.address],
            limits(),
            &output
        ),
        Err(CellErrorV1::Invalid("closure manifest payload"))
    ));
    assert_eq!(peer.finish(), 3);
    assert_eq!(cached_chunks(&receiver, &manifests), 0);
    assert!(!output.exists());
}

#[test]
fn closure_shares_original_transport_budget_and_resumes_without_partial_marker() {
    let directory = tempfile::tempdir().unwrap();
    let origin_path = directory.path().join("origin.sqlite");
    let origin = CellStoreV1::open(&origin_path, cache_config()).unwrap();
    let manifests = populate(&origin);
    let peer = Peer::start(&origin_path);
    let receiver =
        CellStoreV1::open(&directory.path().join("receiver.sqlite"), cache_config()).unwrap();
    let closure = fixture_closure();
    let output = directory.path().join("complete.tcd");
    let mut bounded = limits();
    bounded.peer.max_connections = 5;
    assert!(fetch_closure_to_file(
        &receiver,
        &closure,
        &expected(&closure),
        &[peer.address],
        bounded,
        &output
    )
    .is_err());
    assert!(!output.exists());
    assert_eq!(cached_chunks(&receiver, &manifests), 2);
    let report = fetch_closure_to_file(
        &receiver,
        &closure,
        &expected(&closure),
        &[peer.address],
        limits(),
        &output,
    )
    .unwrap();
    assert_eq!(report.release.cached_chunks, 2);
    assert_eq!(report.release.downloaded_chunks, 1);
    assert_eq!(report.release.connection_attempts, 1);
    assert_eq!(peer.finish(), 6);
    assert_eq!(fs::read(output).unwrap(), closure.encode());
}

#[test]
fn closure_loader_chunk_budget_stops_before_payload_and_never_publishes_marker() {
    let directory = tempfile::tempdir().unwrap();
    let origin_path = directory.path().join("origin.sqlite");
    let origin = CellStoreV1::open(&origin_path, cache_config()).unwrap();
    let manifests = populate(&origin);
    let peer = Peer::start(&origin_path);
    let receiver =
        CellStoreV1::open(&directory.path().join("receiver.sqlite"), cache_config()).unwrap();
    let closure = fixture_closure();
    let mut loader = expected(&closure);
    loader.max_chunks = 2;
    let output = directory.path().join("complete.tcd");
    assert!(matches!(
        fetch_closure_to_file(
            &receiver,
            &closure,
            &loader,
            &[peer.address],
            limits(),
            &output
        ),
        Err(CellErrorV1::Invalid("release chunk budget"))
    ));
    assert_eq!(peer.finish(), 3);
    assert_eq!(cached_chunks(&receiver, &manifests), 0);
    assert!(!output.exists());
}
