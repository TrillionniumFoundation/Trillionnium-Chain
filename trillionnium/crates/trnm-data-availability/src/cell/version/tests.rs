use super::*;
use crate::cell::{CellCacheConfigV4, CellChunkV1, CellClosureFileV1, CellContextV1};
use sha2::Sha256;
use std::time::Duration;

pub(crate) fn context(runtime: CellDigestV1) -> CellContextV1 {
    CellContextV1 {
        family: "complete-version-test".into(),
        base: [1; 32],
        parent: [2; 32],
        tokenizer: [3; 32],
        layout: [4; 32],
        runtime,
    }
}

pub(crate) fn owner(closure: &CellReleaseClosureV1, role: CellFileRoleV1) -> CellLoaderContextV1 {
    CellLoaderContextV1 {
        closure_id: closure.id(),
        context: closure.release().context().clone(),
        selected_generation: closure.selected_generation(),
        loader_profile: closure.loader_profile(),
        required_roles: vec![role],
        max_payload_bytes: 1_000_000,
        max_chunks: 64,
    }
}

pub(crate) fn fixture() -> (tempfile::TempDir, CellStoreV1, CellVersionManifestV1) {
    let dir = tempfile::tempdir().unwrap();
    let store = CellStoreV1::open(
        &dir.path().join("cache.sqlite"),
        CellCacheConfigV4 {
            max_database_bytes: 64 << 20,
            max_logical_bytes: 32 << 20,
            max_chunk_rows: 128,
            max_manifest_rows: 64,
        },
    )
    .unwrap();
    let mut manifests = Vec::new();
    let mut make =
        |ctx: CellContextV1, seed: u8, path: &str, role: CellFileRoleV1, dependencies: Vec<u16>| {
            let bytes: Vec<_> = (0..32769)
                .map(|i| seed.wrapping_add((i % 251) as u8))
                .collect();
            let chunks: Vec<_> = bytes
                .chunks(16384)
                .map(|part| CellChunkV1 {
                    size: part.len() as u32,
                    sha256: Sha256::digest(part).into(),
                })
                .collect();
            let manifest = CellManifestV1::new(
                ctx,
                bytes.len() as u64,
                Sha256::digest(&bytes).into(),
                16384,
                chunks,
            )
            .unwrap();
            store
                .put_manifest(manifest.id(), &manifest.encode())
                .unwrap();
            for (chunk, data) in manifest.chunks().iter().zip(bytes.chunks(16384)) {
                store.put_chunk(chunk, data).unwrap();
            }
            let file = CellClosureFileV1 {
                path: path.into(),
                role,
                manifest: manifest.id(),
                payload_sha256: manifest.payload_sha256(),
                payload_bytes: manifest.size(),
                dependencies,
            };
            manifests.push(manifest);
            file
        };
    let env_context = context([5; 32]);
    let env_files = vec![
        make(
            env_context.clone(),
            11,
            "libraries.bin",
            CellFileRoleV1::Configuration,
            vec![],
        ),
        make(
            env_context.clone(),
            12,
            "runtime.bin",
            CellFileRoleV1::Configuration,
            vec![0],
        ),
    ];
    let environment =
        CellReleaseClosureV1::new(env_context, 1, [6; 32], vec![1], env_files).unwrap();
    let model_context = context(environment.id());
    let model_files = vec![
        make(
            model_context.clone(),
            21,
            "base.bin",
            CellFileRoleV1::Base,
            vec![1],
        ),
        make(
            model_context.clone(),
            22,
            "tokenizer.json",
            CellFileRoleV1::Tokenizer,
            vec![],
        ),
    ];
    let closure =
        CellReleaseClosureV1::new(model_context, 2, [7; 32], vec![0], model_files).unwrap();
    let model = CellModelReleaseRootV1::new(closure, vec![]).unwrap();
    manifests.sort_by_key(CellManifestV1::id);
    let version = CellVersionManifestV1::new(model, environment, manifests).unwrap();
    (dir, store, version)
}

fn limits() -> CellReleaseLimitsV1 {
    CellReleaseLimitsV1 {
        max_payload_bytes: 1_000_000,
        max_chunks: 64,
        deadline: Instant::now() + Duration::from_secs(10),
    }
}

#[test]
fn complete_version_roundtrip_and_actual_model_environment_readback() {
    let (_dir, store, version) = fixture();
    assert_eq!(
        CellVersionManifestV1::decode(&version.encode()).unwrap(),
        version
    );
    let model = owner(version.model().closure(), CellFileRoleV1::Base);
    let environment = owner(version.environment(), CellFileRoleV1::Configuration);
    let expected = CellVersionLoaderContextV1 {
        commitment: version.commitment(),
        model: &model,
        environment: &environment,
    };
    let report = version.verify_cached(&store, &expected, limits()).unwrap();
    assert_eq!(
        (report.manifests, report.payload_bytes, report.chunks),
        (4, 4 * 32769, 12)
    );
    assert_eq!(
        report.environment_closure,
        version.model().closure().release().context().runtime
    );
}

#[test]
fn complete_version_matches_independent_python_framing_vector() {
    let (_dir, _store, version) = fixture();
    let vector: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../formal/pon-nakamoto-v1/vectors/cell-complete-version-v1.json"
    )))
    .unwrap();
    assert_eq!(
        hex::encode(version.encode()),
        vector["wire_hex"].as_str().unwrap()
    );
    assert_eq!(
        hex::encode(version.commitment()),
        vector["commitment_sha512"].as_str().unwrap()
    );
    assert_eq!(
        hex::encode(version.model().id()),
        vector["model_root"].as_str().unwrap()
    );
    assert_eq!(
        hex::encode(version.environment().id()),
        vector["environment_closure"].as_str().unwrap()
    );
}

#[test]
fn complete_version_covers_exact_canonical_manifest_set() {
    let (_dir, _store, version) = fixture();
    let mut omitted = version.clone();
    omitted.manifests.pop();
    assert!(omitted.validate().is_err());
    let mut duplicate = version.clone();
    duplicate.manifests[1] = duplicate.manifests[0].clone();
    assert!(duplicate.validate().is_err());
    let mut reordered = version.clone();
    reordered.manifests.swap(0, 1);
    assert!(reordered.validate().is_err());
    let mut foreign = version.clone();
    foreign.manifests.push(foreign.manifests[0].clone());
    assert!(foreign.validate().is_err());
}

#[test]
fn same_release_files_with_different_dependency_graph_change_complete_commitment() {
    let (_dir, _store, version) = fixture();
    let original = version.model.closure();
    let mut files = original.files().to_vec();
    files[0].dependencies.clear();
    let changed = CellReleaseClosureV1::new(
        original.release().context().clone(),
        original.selected_generation(),
        original.loader_profile(),
        vec![0, 1],
        files,
    )
    .unwrap();
    assert_eq!(original.release().id(), changed.release().id());
    let alternate = CellVersionManifestV1::new(
        CellModelReleaseRootV1::new(changed, vec![]).unwrap(),
        version.environment.clone(),
        version.manifests.clone(),
    )
    .unwrap();
    assert_ne!(alternate.commitment(), version.commitment());
}

#[test]
fn environment_binding_requires_exact_declared_runtime_closure() {
    let (_dir, _store, version) = fixture();
    let env = version.environment();
    let changed = CellReleaseClosureV1::new(
        env.release().context().clone(),
        env.selected_generation() + 1,
        env.loader_profile(),
        env.roots().to_vec(),
        env.files().to_vec(),
    )
    .unwrap();
    assert!(
        CellVersionManifestV1::new(version.model.clone(), changed, version.manifests.clone())
            .is_err()
    );
}

#[test]
fn full_version_rejects_missing_environment_payload_after_successful_readback() {
    let (dir, store, version) = fixture();
    let model = owner(version.model().closure(), CellFileRoleV1::Base);
    let environment = owner(version.environment(), CellFileRoleV1::Configuration);
    let expected = CellVersionLoaderContextV1 {
        commitment: version.commitment(),
        model: &model,
        environment: &environment,
    };
    version.verify_cached(&store, &expected, limits()).unwrap();
    let id = version.environment().files()[0].manifest;
    let manifest = version.manifests().iter().find(|m| m.id() == id).unwrap();
    let db = rusqlite::Connection::open(dir.path().join("cache.sqlite")).unwrap();
    db.execute(
        "DELETE FROM cell_chunks_v1 WHERE hash = ?1",
        [manifest.chunks()[0].sha256.as_slice()],
    )
    .unwrap();
    store
        .verify_release_complete(version.model.closure().release(), limits())
        .unwrap();
    assert!(version.verify_cached(&store, &expected, limits()).is_err());
}

#[test]
fn aggregate_and_per_owner_limits_are_checked_before_payload_reads() {
    let (dir, store, version) = fixture();
    let model = owner(version.model().closure(), CellFileRoleV1::Base);
    let mut environment = owner(version.environment(), CellFileRoleV1::Configuration);
    let db = rusqlite::Connection::open(dir.path().join("cache.sqlite")).unwrap();
    db.execute("DELETE FROM cell_chunks_v1", []).unwrap();
    let expected = CellVersionLoaderContextV1 {
        commitment: version.commitment(),
        model: &model,
        environment: &environment,
    };
    let mut limited = limits();
    limited.max_payload_bytes = 4 * 32769 - 1;
    assert!(matches!(
        version.verify_cached(&store, &expected, limited),
        Err(CellErrorV1::Invalid("version aggregate read budget"))
    ));
    let mut limited = limits();
    limited.max_chunks = 11;
    assert!(matches!(
        version.verify_cached(&store, &expected, limited),
        Err(CellErrorV1::Invalid("version aggregate read budget"))
    ));
    environment.max_chunks = 5;
    let expected = CellVersionLoaderContextV1 {
        commitment: version.commitment(),
        model: &model,
        environment: &environment,
    };
    assert!(matches!(
        version.verify_cached(&store, &expected, limits()),
        Err(CellErrorV1::Invalid("version owner chunk budget"))
    ));
}

#[test]
fn version_wire_is_bounded_and_has_no_legacy_or_trailing_fallback() {
    let (_dir, _store, version) = fixture();
    let wire = version.encode();
    for count in [0, 3, 4, 8, 12, wire.len() - 1] {
        assert!(CellVersionManifestV1::decode(&wire[..count]).is_err());
    }
    let mut trailing = wire.clone();
    trailing.push(0);
    assert!(CellVersionManifestV1::decode(&trailing).is_err());
    let mut huge_frame = wire.clone();
    huge_frame[4..8].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(CellVersionManifestV1::decode(&huge_frame).is_err());
    assert!(CellVersionManifestV1::decode(&version.model.encode()).is_err());
    assert!(CellVersionManifestV1::decode(&vec![0; MAX_CELL_VERSION_BYTES_V1 + 1]).is_err());
}

#[test]
fn version_loader_scope_and_original_deadline_fail_closed() {
    let (_dir, store, version) = fixture();
    let mut model = owner(version.model().closure(), CellFileRoleV1::Base);
    let environment = owner(version.environment(), CellFileRoleV1::Configuration);
    let mut expired = limits();
    expired.deadline = Instant::now();
    let expected = CellVersionLoaderContextV1 {
        commitment: version.commitment(),
        model: &model,
        environment: &environment,
    };
    assert!(matches!(
        version.verify_cached(&store, &expected, expired),
        Err(CellErrorV1::Invalid("version deadline"))
    ));
    model.selected_generation += 1;
    let expected = CellVersionLoaderContextV1 {
        commitment: version.commitment(),
        model: &model,
        environment: &environment,
    };
    assert!(version.verify_cached(&store, &expected, limits()).is_err());
}
