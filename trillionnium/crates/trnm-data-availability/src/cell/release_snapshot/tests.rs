use super::*;
use crate::cell::{
    CellCacheConfigV4, CellChunkV1, CellClosureFileV1, CellContextV1, CellLoaderContextV1,
    CellManifestV1, CellModelReleaseRootV1, CellReleaseClosureV1, CellStoreV1,
    CellTensorContractV1, CellTensorDTypeV1, CellTensorFileV1, CellTensorSpecV1,
};
use sha2::Sha256;
use std::{cell::Cell, time::Duration};

const RULES: &[u8] = br#"{"format":"exact-dense-fixture-v1","weights":"base.safetensors"}"#;

fn context(runtime: CellDigestV1) -> CellContextV1 {
    CellContextV1 {
        family: "release-snapshot-test".into(),
        base: [1; 32],
        parent: [2; 32],
        tokenizer: [3; 32],
        layout: [4; 32],
        runtime,
    }
}

fn dense_file() -> Vec<u8> {
    let header = br#"{"weight":{"dtype":"F32","shape":[2],"data_offsets":[0,8]}}"#;
    let mut wire = (header.len() as u64).to_le_bytes().to_vec();
    wire.extend_from_slice(header);
    for value in [1.25f32, -2.0] {
        wire.extend_from_slice(&value.to_le_bytes());
    }
    wire
}

pub(in crate::cell) fn fixture() -> (tempfile::TempDir, CellStoreV1, CellReleaseSnapshotV1) {
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
    let mut file = |ctx: CellContextV1,
                    bytes: &[u8],
                    path: &str,
                    role: CellFileRoleV1,
                    dependencies: Vec<u16>| {
        let chunks: Vec<_> = bytes
            .chunks(16384)
            .map(|chunk| CellChunkV1 {
                size: chunk.len() as u32,
                sha256: Sha256::digest(chunk).into(),
            })
            .collect();
        let manifest = CellManifestV1::new(
            ctx,
            bytes.len() as u64,
            Sha256::digest(bytes).into(),
            16384,
            chunks,
        )
        .unwrap();
        store
            .put_manifest(manifest.id(), &manifest.encode())
            .unwrap();
        for (chunk, bytes) in manifest.chunks().iter().zip(bytes.chunks(16384)) {
            store.put_chunk(chunk, bytes).unwrap();
        }
        let entry = CellClosureFileV1 {
            path: path.into(),
            role,
            manifest: manifest.id(),
            payload_sha256: manifest.payload_sha256(),
            payload_bytes: manifest.size(),
            dependencies,
        };
        manifests.push(manifest);
        entry
    };
    let env_context = context([5; 32]);
    let env_file = file(
        env_context.clone(),
        b"explicit-test-runtime",
        "runtime.bin",
        CellFileRoleV1::Configuration,
        vec![],
    );
    let environment =
        CellReleaseClosureV1::new(env_context, 1, [6; 32], vec![0], vec![env_file]).unwrap();
    let model_context = context(environment.id());
    let files = vec![
        file(
            model_context.clone(),
            &dense_file(),
            "base.safetensors",
            CellFileRoleV1::Base,
            vec![1, 2],
        ),
        file(
            model_context.clone(),
            RULES,
            "rules.json",
            CellFileRoleV1::Configuration,
            vec![],
        ),
        file(
            model_context.clone(),
            b"{\"vocabulary\":[\"yes\",\"no\"]}",
            "tokenizer.json",
            CellFileRoleV1::Tokenizer,
            vec![],
        ),
    ];
    let closure = CellReleaseClosureV1::new(model_context, 2, [7; 32], vec![0], files).unwrap();
    let root = CellModelReleaseRootV1::new(closure, vec![]).unwrap();
    let contract = CellTensorContractV1::new(
        root.id(),
        vec![CellTensorFileV1 {
            file_index: 0,
            tensors: vec![CellTensorSpecV1 {
                name: "weight".into(),
                dtype: CellTensorDTypeV1::F32,
                shape: vec![2],
            }],
        }],
    )
    .unwrap();
    let tensors = CellTensorModelManifestV1::new(root.clone(), contract).unwrap();
    manifests.sort_by_key(CellManifestV1::id);
    let version = CellVersionManifestV1::new(root, environment, manifests).unwrap();
    let snapshot = CellReleaseSnapshotV1::new(version, tensors, 1, [8; 32]).unwrap();
    (dir, store, snapshot)
}

fn owner(closure: &CellReleaseClosureV1, roles: Vec<CellFileRoleV1>) -> CellLoaderContextV1 {
    CellLoaderContextV1 {
        closure_id: closure.id(),
        context: closure.release().context().clone(),
        selected_generation: closure.selected_generation(),
        loader_profile: closure.loader_profile(),
        required_roles: roles,
        max_payload_bytes: 1 << 20,
        max_chunks: 16,
    }
}

pub(in crate::cell) fn owners(
    snapshot: &CellReleaseSnapshotV1,
) -> (CellLoaderContextV1, CellLoaderContextV1) {
    (
        owner(
            snapshot.version().model().closure(),
            vec![
                CellFileRoleV1::Base,
                CellFileRoleV1::Configuration,
                CellFileRoleV1::Tokenizer,
            ],
        ),
        owner(
            snapshot.version().environment(),
            vec![CellFileRoleV1::Configuration],
        ),
    )
}

pub(in crate::cell) fn expected<'a>(
    snapshot: &CellReleaseSnapshotV1,
    model: &'a CellLoaderContextV1,
    environment: &'a CellLoaderContextV1,
) -> CellReleaseSnapshotLoaderContextV1<'a> {
    CellReleaseSnapshotLoaderContextV1 {
        snapshot: snapshot.commitment(),
        composition_profile: snapshot.composition_profile(),
        version: CellVersionLoaderContextV1 {
            commitment: snapshot.version().commitment(),
            model,
            environment,
        },
    }
}

fn limits() -> CellResidencyConfigV1 {
    CellResidencyConfigV1 {
        max_resident_bytes: 1 << 20,
        max_resident_closures: 2,
        max_chunk_references: 16,
    }
}

fn prepare(
    store: &CellStoreV1,
    snapshot: &CellReleaseSnapshotV1,
    deadline: Instant,
    cancelled: &AtomicBool,
) -> CellResidencyV1 {
    let mut pool = CellResidencyV1::new(limits()).unwrap();
    let (model, environment) = owners(snapshot);
    for (closure, owner) in [
        (snapshot.version().model().closure(), &model),
        (snapshot.version().environment(), &environment),
    ] {
        pool.prepare_cached(store, closure, owner, deadline, cancelled)
            .unwrap();
    }
    pool
}

#[test]
fn snapshot_wire_pins_complete_version_dense_schema_and_real_rules_file() {
    let (_dir, _store, snapshot) = fixture();
    let wire = snapshot.encode();
    assert_eq!(
        CellReleaseSnapshotV1::decode_pinned(&wire, snapshot.commitment()).unwrap(),
        snapshot
    );
    let changed = CellReleaseSnapshotV1::new(
        snapshot.version().clone(),
        snapshot.tensors().clone(),
        1,
        [9; 32],
    )
    .unwrap();
    assert_ne!(changed.commitment(), snapshot.commitment());
    assert!(
        CellReleaseSnapshotV1::decode_pinned(&changed.encode(), snapshot.commitment()).is_err()
    );
    for index in [0, 2, u16::MAX] {
        assert!(CellReleaseSnapshotV1::new(
            snapshot.version().clone(),
            snapshot.tensors().clone(),
            index,
            [8; 32]
        )
        .is_err());
    }
    assert!(CellReleaseSnapshotV1::new(
        snapshot.version().clone(),
        snapshot.tensors().clone(),
        1,
        [0; 32]
    )
    .is_err());
}

#[test]
fn snapshot_rejects_another_generation_even_with_identical_payloads() {
    let (_dir, _store, snapshot) = fixture();
    let old = snapshot.version().model().closure();
    let next = CellReleaseClosureV1::new(
        old.release().context().clone(),
        old.selected_generation() + 1,
        old.loader_profile(),
        old.roots().to_vec(),
        old.files().to_vec(),
    )
    .unwrap();
    let root = CellModelReleaseRootV1::new(next, vec![]).unwrap();
    let contract =
        CellTensorContractV1::new(root.id(), snapshot.tensors().contract().files().to_vec())
            .unwrap();
    let tensors = CellTensorModelManifestV1::new(root, contract).unwrap();
    assert!(CellReleaseSnapshotV1::new(snapshot.version().clone(), tensors, 1, [8; 32]).is_err());
}

#[test]
fn snapshot_parser_rejects_unknown_quantized_profile_and_noncanonical_frames() {
    let (_dir, _store, snapshot) = fixture();
    let wire = snapshot.encode();
    let mut quantized = wire.clone();
    let contract = quantized
        .windows(4)
        .rposition(|bytes| bytes == b"TMT1")
        .unwrap();
    quantized[contract + 5] = 2;
    assert!(CellReleaseSnapshotV1::decode_pinned(&quantized, wire_commitment(&quantized)).is_err());
    let mut wrong_version = wire.clone();
    wrong_version[3] = b'2';
    let mut large_frame = wire.clone();
    large_frame[4..8].copy_from_slice(&u32::MAX.to_be_bytes());
    let mut suffix = wire.clone();
    suffix.push(0);
    for malformed in [
        wrong_version,
        large_frame,
        suffix,
        wire[..wire.len() - 1].to_vec(),
    ] {
        assert!(
            CellReleaseSnapshotV1::decode_pinned(&malformed, wire_commitment(&malformed)).is_err()
        );
    }
    assert!(CellReleaseSnapshotV1::decode_pinned(&wire, [0; 64]).is_err());
    assert!(CellReleaseSnapshotV1::decode_pinned(
        &vec![0; MAX_CELL_RELEASE_SNAPSHOT_BYTES_V1 + 1],
        snapshot.commitment()
    )
    .is_err());
}

#[test]
fn resident_snapshot_pairs_real_tensors_rules_and_environment_after_cache_removal() {
    let (dir, store, snapshot) = fixture();
    let deadline = Instant::now() + Duration::from_secs(10);
    let cancelled = AtomicBool::new(false);
    let pool = prepare(&store, &snapshot, deadline, &cancelled);
    let (model, environment) = owners(&snapshot);
    let current = expected(&snapshot, &model, &environment);
    let task = [40; 32];
    let ready = pool
        .admit_local_release_snapshot(task, &snapshot, &current, limits(), deadline, &cancelled)
        .unwrap();
    let db = rusqlite::Connection::open(dir.path().join("cache.sqlite")).unwrap();
    db.execute("DELETE FROM cell_chunks_v1", []).unwrap();
    assert_eq!(ready.task_id(), task);
    assert_eq!(ready.commitment(), snapshot.commitment());
    assert_eq!(ready.usage().resident_closures, 2);
    ready
        .with_local(task, &current, |view| {
            assert_eq!(view.version().commitment(), snapshot.version().commitment());
            assert_eq!(
                view.version().environment().closure_id(),
                environment.closure_id
            );
            let tensor = view.tensors().tensor(0, "weight").unwrap();
            assert_eq!(tensor.shape(), &[2]);
            assert_eq!(tensor.read_f32(0).unwrap(), 1.25);
            assert_eq!(tensor.read_f32(1).unwrap(), -2.0);
            assert_eq!(view.composition().path(), "rules.json");
            assert_eq!(
                view.composition()
                    .chunks()
                    .flatten()
                    .copied()
                    .collect::<Vec<_>>(),
                RULES
            );
        })
        .unwrap();
    let callbacks = Cell::new(0);
    let mut changed = expected(&snapshot, &model, &environment);
    changed.snapshot[0] ^= 1;
    assert!(ready
        .with_local(task, &changed, |_| callbacks.set(1))
        .is_err());
    changed = expected(&snapshot, &model, &environment);
    changed.composition_profile[0] ^= 1;
    assert!(ready
        .with_local(task, &changed, |_| callbacks.set(1))
        .is_err());
    changed = expected(&snapshot, &model, &environment);
    changed.version.commitment[0] ^= 1;
    assert!(ready
        .with_local(task, &changed, |_| callbacks.set(1))
        .is_err());
    let mut next_environment = environment.clone();
    next_environment.selected_generation += 1;
    changed = expected(&snapshot, &model, &next_environment);
    assert!(ready
        .with_local(task, &changed, |_| callbacks.set(1))
        .is_err());
    assert!(ready
        .with_local([41; 32], &current, |_| callbacks.set(1))
        .is_err());
    assert_eq!(callbacks.get(), 0);
    ready.with_local(task, &current, |_| ()).unwrap();
}

#[test]
fn snapshot_metadata_cannot_substitute_for_actual_tensor_schema_verification() {
    let (_dir, store, snapshot) = fixture();
    let mut files = snapshot.tensors().contract().files().to_vec();
    files[0].tensors[0].shape = vec![1, 2]; // Same bytes, a different shape.
    let contract = CellTensorContractV1::new(snapshot.version().model().id(), files).unwrap();
    let tensors =
        CellTensorModelManifestV1::new(snapshot.version().model().clone(), contract).unwrap();
    let mismatched =
        CellReleaseSnapshotV1::new(snapshot.version().clone(), tensors, 1, [8; 32]).unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    let cancelled = AtomicBool::new(false);
    let pool = prepare(&store, &snapshot, deadline, &cancelled);
    let before = pool.usage();
    let (model, environment) = owners(&mismatched);
    let current = expected(&mismatched, &model, &environment);
    assert!(pool
        .admit_local_release_snapshot(
            [40; 32],
            &mismatched,
            &current,
            limits(),
            deadline,
            &cancelled
        )
        .is_err());
    assert_eq!(pool.usage(), before);
    assert!(pool.selection().is_none());
}

#[test]
fn snapshot_cancellation_latches_on_mismatched_calls_and_cannot_be_revived() {
    let (_dir, store, snapshot) = fixture();
    let deadline = Instant::now() + Duration::from_secs(10);
    let cancelled = AtomicBool::new(false);
    let pool = prepare(&store, &snapshot, deadline, &cancelled);
    let (model, environment) = owners(&snapshot);
    let current = expected(&snapshot, &model, &environment);
    let ready = pool
        .admit_local_release_snapshot(
            [40; 32],
            &snapshot,
            &current,
            limits(),
            deadline,
            &cancelled,
        )
        .unwrap();
    let mut mismatched = expected(&snapshot, &model, &environment);
    mismatched.snapshot[0] ^= 1;
    cancelled.store(true, Ordering::Release);
    assert!(ready.with_local([40; 32], &mismatched, |_| ()).is_err());
    cancelled.store(false, Ordering::Release);
    assert!(ready.with_local([40; 32], &current, |_| ()).is_err());
}

#[test]
fn snapshot_admission_requires_the_environment_and_aggregate_task_allowance() {
    let (_dir, store, snapshot) = fixture();
    let deadline = Instant::now() + Duration::from_secs(10);
    let cancelled = AtomicBool::new(false);
    let mut pool = CellResidencyV1::new(limits()).unwrap();
    let (model, environment) = owners(&snapshot);
    let current = expected(&snapshot, &model, &environment);
    pool.prepare_cached(
        &store,
        snapshot.version().model().closure(),
        &model,
        deadline,
        &cancelled,
    )
    .unwrap();
    assert!(pool
        .admit_local_release_snapshot(
            [40; 32],
            &snapshot,
            &current,
            limits(),
            deadline,
            &cancelled
        )
        .is_err());
    pool.prepare_cached(
        &store,
        snapshot.version().environment(),
        &environment,
        deadline,
        &cancelled,
    )
    .unwrap();
    let mut limited = limits();
    limited.max_resident_bytes = pool.usage().unique_payload_bytes - 1;
    assert!(pool
        .admit_local_release_snapshot([40; 32], &snapshot, &current, limited, deadline, &cancelled)
        .is_err());
    assert!(pool
        .admit_local_release_snapshot(
            [40; 32],
            &snapshot,
            &current,
            limits(),
            Instant::now(),
            &cancelled
        )
        .is_err());
}
