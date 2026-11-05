use std::{
    fs,
    time::{Duration, Instant},
};

use super::*;

fn vector() -> serde_json::Value {
    serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../formal/pon-nakamoto-v1/vectors/cell-model-root-v1.json"
    )))
    .unwrap()
}

fn root() -> CellModelReleaseRootV1 {
    CellModelReleaseRootV1::decode(&hex::decode(vector()["wire_hex"].as_str().unwrap()).unwrap())
        .unwrap()
}

fn loader(closure: &CellReleaseClosureV1) -> CellLoaderContextV1 {
    CellLoaderContextV1 {
        closure_id: closure.id(),
        context: closure.release().context().clone(),
        selected_generation: closure.selected_generation(),
        loader_profile: closure.loader_profile(),
        required_roles: vec![
            CellFileRoleV1::Base,
            CellFileRoleV1::Tokenizer,
            CellFileRoleV1::Router,
        ],
        max_payload_bytes: 1_048_576,
        max_chunks: 64,
    }
}

fn limits() -> CellReleaseFetchLimitsV1 {
    CellReleaseFetchLimitsV1 {
        peer: CellPeerLimitsV1 {
            request_timeout: Duration::from_millis(100),
            overall_timeout: Duration::from_secs(5),
            max_cell_bytes: 1_048_576,
            parallelism: 1,
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

fn populate(store: &CellStoreV1) {
    let data: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../formal/pon-nakamoto-v1/vectors/cell-dependency-closure-v1.json"
    )))
    .unwrap();
    for member in data["manifests"].as_array().unwrap() {
        let wire = hex::decode(member["wire_hex"].as_str().unwrap()).unwrap();
        let payload = hex::decode(member["payload_hex"].as_str().unwrap()).unwrap();
        let manifest = CellManifestV1::decode(&wire).unwrap();
        store.put_manifest(manifest.id(), &wire).unwrap();
        store.put_chunk(&manifest.chunks()[0], &payload).unwrap();
    }
}

#[test]
fn independent_python_model_root_vector_and_every_truncated_prefix() {
    let data = vector();
    let wire = hex::decode(data["wire_hex"].as_str().unwrap()).unwrap();
    let root = root();
    assert_eq!(root.encode(), wire);
    assert_eq!(digest_hex(root.id()), data["model_root"]);
    for end in 0..wire.len() {
        assert!(
            CellModelReleaseRootV1::decode(&wire[..end]).is_err(),
            "prefix {end}"
        );
    }
    let mut extra = wire.clone();
    extra.push(0);
    assert!(CellModelReleaseRootV1::decode(&extra).is_err());
    let mut wrong_version = wire.clone();
    wrong_version[..4].copy_from_slice(b"TMR2");
    assert!(CellModelReleaseRootV1::decode(&wrong_version).is_err());
    let mut oversized = wire;
    oversized[4..8].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(CellModelReleaseRootV1::decode(&oversized).is_err());
}

#[test]
fn router_omission_lineage_alias_and_changed_owner_context_are_refused() {
    let root = root();
    let mut wire = root.encode();
    let router_offset = 8 + root.closure().encode().len();
    wire[router_offset] ^= 1;
    assert!(CellModelReleaseRootV1::decode(&wire).is_err());
    for parents in [
        vec![[0; 32]],
        vec![[2; 32], [1; 32]],
        vec![[1; 32]; 2],
        vec![[1; 32]; 17],
    ] {
        assert!(CellModelReleaseRootV1::new(root.closure().clone(), parents).is_err());
    }
    let mut expected = loader(root.closure());
    root.verify_for_loader(root.id(), &expected).unwrap();
    assert!(root
        .verify_for_loader(root.closure().id(), &expected)
        .is_err());
    expected.selected_generation += 1;
    assert!(root.verify_for_loader(root.id(), &expected).is_err());
    expected = loader(root.closure());
    expected.context.runtime = [91; 32];
    assert!(root.verify_for_loader(root.id(), &expected).is_err());
    expected = loader(root.closure());
    expected.loader_profile = [92; 32];
    assert!(root.verify_for_loader(root.id(), &expected).is_err());
    let without_lineage = CellModelReleaseRootV1::new(root.closure().clone(), vec![]).unwrap();
    assert_ne!(without_lineage.id(), root.id());
    assert_eq!(without_lineage.closure().id(), root.closure().id());
}

#[test]
fn actual_direct_parent_roots_require_complete_matching_family_and_older_generation() {
    let origin = CellModelReleaseRootV1::new(root().closure().clone(), vec![]).unwrap();
    let previous = origin.closure();
    let next_closure = CellReleaseClosureV1::new(
        previous.release().context().clone(),
        previous.selected_generation() + 1,
        previous.loader_profile(),
        previous.roots().to_vec(),
        previous.files().to_vec(),
    )
    .unwrap();
    let next = CellModelReleaseRootV1::new(next_closure.clone(), vec![origin.id()]).unwrap();
    next.verify_parent_roots(std::slice::from_ref(&origin))
        .unwrap();
    assert!(next.verify_parent_roots(&[]).is_err());
    assert!(next
        .verify_parent_roots(std::slice::from_ref(&next))
        .is_err());
    let same_generation = CellModelReleaseRootV1::new(previous.clone(), vec![origin.id()]).unwrap();
    assert!(same_generation
        .verify_parent_roots(std::slice::from_ref(&origin))
        .is_err());
    // The declared pin is correct in both cases. Family/generation must still
    // be checked against the actual parent, rather than only matching its hash.
    for (family, generation) in [
        ("unrelated-family", previous.selected_generation()),
        (
            previous.release().context().family.as_str(),
            previous.selected_generation() + 2,
        ),
    ] {
        let mut context = previous.release().context().clone();
        context.family = family.into();
        let parent = CellModelReleaseRootV1::new(
            CellReleaseClosureV1::new(
                context,
                generation,
                previous.loader_profile(),
                previous.roots().to_vec(),
                previous.files().to_vec(),
            )
            .unwrap(),
            vec![],
        )
        .unwrap();
        let child = CellModelReleaseRootV1::new(next_closure.clone(), vec![parent.id()]).unwrap();
        assert!(child.verify_parent_roots(&[parent]).is_err());
    }
}

#[test]
fn model_root_fetch_uses_original_closure_checks_and_publishes_only_complete_exact_root() {
    let directory = tempfile::tempdir().unwrap();
    let store = CellStoreV1::open(
        &directory.path().join("cache.sqlite"),
        CellCacheConfigV4 {
            max_database_bytes: 128 * 1024 * 1024,
            max_logical_bytes: 64 * 1024 * 1024,
            max_chunk_rows: 4096,
            max_manifest_rows: 256,
        },
    )
    .unwrap();
    let root = root();
    let output = directory.path().join("release.tmr1");
    assert!(fetch_model_release_to_file(
        &store,
        &root,
        (root.id(), &loader(root.closure())),
        &[],
        limits(),
        &output
    )
    .is_err());
    assert!(!output.exists());
    populate(&store);
    let report = fetch_model_release_to_file(
        &store,
        &root,
        (root.id(), &loader(root.closure())),
        &[],
        limits(),
        &output,
    )
    .unwrap();
    assert_eq!(fs::read(&output).unwrap(), root.encode());
    assert_eq!(report.model_root, root.id());
    assert_eq!(report.closure_id, root.closure().id());
    assert_eq!(report.release.downloaded_bytes, 0);
    assert_eq!(report.release.connection_attempts, 0);
    assert!(fetch_model_release_to_file(
        &store,
        &root,
        (root.id(), &loader(root.closure())),
        &[],
        limits(),
        &output
    )
    .is_err());
    let mut short = limits();
    short.release.max_chunks = 2;
    let denied = directory.path().join("denied.tmr1");
    assert!(fetch_model_release_to_file(
        &store,
        &root,
        (root.id(), &loader(root.closure())),
        &[],
        short,
        &denied
    )
    .is_err());
    assert!(!denied.exists());
}
