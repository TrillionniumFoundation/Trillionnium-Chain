use super::*;
use crate::cell::{
    version::tests::{fixture, owner},
    CellFileRoleV1,
};
use std::time::Duration;

pub(crate) fn session(scans: u32) -> CellContentReadSessionV2 {
    CellContentReadSessionV2::new(
        CellReleaseLimitsV1 {
            max_payload_bytes: 1_000_000,
            max_chunks: 100,
            deadline: Instant::now() + Duration::from_secs(15),
        },
        scans,
    )
    .unwrap()
}

pub(crate) fn captured() -> (tempfile::TempDir, CellStoreV1, CellVersionContentV2) {
    let (dir, store, version) = fixture();
    let model = owner(version.model().closure(), CellFileRoleV1::Base);
    let environment = owner(version.environment(), CellFileRoleV1::Configuration);
    let expected = CellVersionLoaderContextV1 {
        commitment: version.commitment(),
        model: &model,
        environment: &environment,
    };
    let content =
        CellVersionContentV2::capture_cached(&version, &store, &expected, &mut session(1)).unwrap();
    (dir, store, content)
}

#[test]
fn full_content_matches_independent_python_actual_byte_vector() {
    let (_dir, _store, content) = captured();
    let vector: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../formal/pon-nakamoto-v1/vectors/cell-version-content-v2.json"
    )))
    .unwrap();
    assert_eq!(
        hex::encode(content.encode()),
        vector["wire_hex"].as_str().unwrap()
    );
    assert_eq!(
        hex::encode(content.commitment()),
        vector["commitment_sha512"].as_str().unwrap()
    );
}

#[test]
fn full_content_roundtrip_reads_actual_model_and_environment_bytes() {
    let (_dir, store, content) = captured();
    assert_eq!(
        CellVersionContentV2::decode(&content.encode()).unwrap(),
        content
    );
    assert_ne!(content.commitment(), content.version().commitment());
    let model = owner(content.version().model().closure(), CellFileRoleV1::Base);
    let environment = owner(
        content.version().environment(),
        CellFileRoleV1::Configuration,
    );
    let expected = CellVersionLoaderContextV1 {
        commitment: content.version().commitment(),
        model: &model,
        environment: &environment,
    };
    let mut budget = session(1);
    let readback = content
        .verify_cached(&store, &expected, content.commitment(), &mut budget)
        .unwrap();
    let pinned = content
        .pin_for_owner(&expected, content.commitment())
        .unwrap();
    assert_eq!(readback.content(), &content);
    assert_eq!(
        readback.usage(),
        CellContentReadUsageV2 {
            attempted_scans: 1,
            reserved_payload_bytes: 4 * 32769,
            reserved_chunks: 12
        }
    );
    for manifest in content.version().manifests() {
        for (i, chunk) in manifest.chunks().iter().enumerate() {
            let bytes = store.chunk(chunk.sha256).unwrap().unwrap();
            pinned.verify_chunk(manifest.id(), i, &bytes).unwrap();
            let mut changed = bytes;
            changed[0] ^= 1;
            assert!(pinned.verify_chunk(manifest.id(), i, &changed).is_err());
        }
    }
}

#[test]
fn complete_metadata_is_not_accepted_as_full_content_or_vice_versa() {
    let (_dir, _store, content) = captured();
    assert!(CellVersionContentV2::decode(&content.version().encode()).is_err());
    assert!(CellVersionManifestV1::decode(&content.encode()).is_err());
    for n in [0, 3, 8, content.encode().len() - 1] {
        assert!(CellVersionContentV2::decode(&content.encode()[..n]).is_err());
    }
    let mut trailing = content.encode();
    trailing.push(0);
    assert!(CellVersionContentV2::decode(&trailing).is_err());
}

#[test]
fn full_content_pin_and_actual_scan_reject_changed_digest_even_with_same_legacy_ids() {
    let (_dir, store, content) = captured();
    let model = owner(content.version().model().closure(), CellFileRoleV1::Base);
    let environment = owner(
        content.version().environment(),
        CellFileRoleV1::Configuration,
    );
    let expected = CellVersionLoaderContextV1 {
        commitment: content.version().commitment(),
        model: &model,
        environment: &environment,
    };
    let mut changed = content.clone();
    changed.contents[0].payload_sha512[63] ^= 1;
    assert_eq!(changed.version, content.version);
    assert!(changed
        .verify_cached(&store, &expected, content.commitment(), &mut session(1))
        .is_err());
    let mut budget = session(1);
    assert!(changed
        .verify_cached(&store, &expected, changed.commitment(), &mut budget)
        .is_err());
    assert_eq!(budget.usage().reserved_payload_bytes, 4 * 32769);
    changed = content.clone();
    changed.contents[0].chunks_sha512[0][63] ^= 1;
    assert!(changed
        .verify_cached(&store, &expected, changed.commitment(), &mut session(1))
        .is_err());
}

#[test]
fn full_content_chunk_checker_rejects_unpinned_or_changed_chunks() {
    let (_dir, store, content) = captured();
    let model = owner(content.version().model().closure(), CellFileRoleV1::Base);
    let environment = owner(
        content.version().environment(),
        CellFileRoleV1::Configuration,
    );
    let expected = CellVersionLoaderContextV1 {
        commitment: content.version().commitment(),
        model: &model,
        environment: &environment,
    };
    let pinned = content
        .pin_for_owner(&expected, content.commitment())
        .unwrap();
    let manifest = &content.version().manifests()[0];
    pinned.verify_manifest(manifest).unwrap();
    assert_eq!(
        pinned.payload_sha512(manifest.id()).unwrap(),
        content.contents()[0].payload_sha512()
    );
    assert!(pinned.payload_sha512([0; 32]).is_err());
    let bytes = store.chunk(manifest.chunks()[0].sha256).unwrap().unwrap();
    let mut changed = content.clone();
    changed.contents[0].chunks_sha512[0][0] ^= 1;
    assert!(changed
        .pin_for_owner(&expected, content.commitment())
        .is_err());
    assert!(changed
        .pin_for_owner(&expected, changed.commitment())
        .unwrap()
        .verify_chunk(manifest.id(), 0, &bytes)
        .is_err());
    assert!(pinned.verify_chunk([0; 32], 0, &bytes).is_err());
    assert!(pinned
        .verify_chunk(manifest.id(), usize::MAX, &bytes)
        .is_err());
    assert!(pinned
        .verify_chunk(manifest.id(), 0, &bytes[..bytes.len() - 1])
        .is_err());
}

#[test]
fn content_failed_scan_reservations_and_original_deadline_are_not_refunded() {
    let (_dir, store, content) = captured();
    let model = owner(content.version().model().closure(), CellFileRoleV1::Base);
    let environment = owner(
        content.version().environment(),
        CellFileRoleV1::Configuration,
    );
    let expected = CellVersionLoaderContextV1 {
        commitment: content.version().commitment(),
        model: &model,
        environment: &environment,
    };
    let mut changed = content.clone();
    changed.contents[0].payload_sha512[0] ^= 1;
    let mut budget = CellContentReadSessionV2::new(
        CellReleaseLimitsV1 {
            max_payload_bytes: 4 * 32769,
            max_chunks: 12,
            deadline: Instant::now() + Duration::from_secs(10),
        },
        2,
    )
    .unwrap();
    let deadline = budget.deadline();
    assert!(changed
        .verify_cached(&store, &expected, changed.commitment(), &mut budget)
        .is_err());
    assert!(content
        .verify_cached(&store, &expected, content.commitment(), &mut budget)
        .is_err());
    assert_eq!(
        budget.usage(),
        CellContentReadUsageV2 {
            attempted_scans: 2,
            reserved_payload_bytes: 4 * 32769,
            reserved_chunks: 12
        }
    );
    assert_eq!(budget.deadline(), deadline);
    budget.limits.deadline = Instant::now();
    assert!(content
        .verify_cached(&store, &expected, content.commitment(), &mut budget)
        .is_err());
    assert_eq!(budget.usage().attempted_scans, 2);
}

#[test]
fn full_content_rejects_missing_extra_reordered_and_zero_commitments() {
    let (_dir, _store, content) = captured();
    let mut value = content.clone();
    value.contents.pop();
    assert!(value.validate().is_err());
    value = content.clone();
    value.contents.push(value.contents[0].clone());
    assert!(value.validate().is_err());
    value = content.clone();
    value.contents.swap(0, 1);
    assert!(value.validate().is_err());
    value = content.clone();
    value.contents[0].chunks_sha512.pop();
    assert!(value.validate().is_err());
    value = content.clone();
    value.contents[0].payload_sha512 = [0; 64];
    assert!(value.validate().is_err());
    value = content.clone();
    value.contents[0].chunks_sha512[0] = [0; 64];
    assert!(value.validate().is_err());
}

#[test]
fn missing_actual_cache_payload_cannot_be_replaced_by_signed_metadata() {
    let (_dir, _store, content) = captured();
    let empty = tempfile::tempdir().unwrap();
    let store = CellStoreV1::open(
        &empty.path().join("empty.db"),
        crate::cell::CellCacheConfigV4 {
            max_database_bytes: 8 << 20,
            max_logical_bytes: 1 << 20,
            max_chunk_rows: 64,
            max_manifest_rows: 32,
        },
    )
    .unwrap();
    let model = owner(content.version().model().closure(), CellFileRoleV1::Base);
    let environment = owner(
        content.version().environment(),
        CellFileRoleV1::Configuration,
    );
    let expected = CellVersionLoaderContextV1 {
        commitment: content.version().commitment(),
        model: &model,
        environment: &environment,
    };
    let mut budget = session(1);
    assert!(content
        .verify_cached(&store, &expected, content.commitment(), &mut budget)
        .is_err());
    assert_eq!(budget.usage().reserved_chunks, 12);
}

#[cfg(target_os = "linux")]
#[test]
fn actual_sealed_objects_must_match_the_strong_content_pin_before_loader_handoff() {
    use crate::cell::{CellResidencyConfigV1, CellResidencyV1, CellSealedLoaderLimitsV1};
    use std::{io::Read, sync::atomic::AtomicBool};
    let (_dir, store, content) = captured();
    let model = owner(content.version().model().closure(), CellFileRoleV1::Base);
    let environment = owner(
        content.version().environment(),
        CellFileRoleV1::Configuration,
    );
    let expected = CellVersionLoaderContextV1 {
        commitment: content.version().commitment(),
        model: &model,
        environment: &environment,
    };
    let deadline = Instant::now() + Duration::from_secs(15);
    let cancelled = AtomicBool::new(false);
    let mut pool = CellResidencyV1::new(CellResidencyConfigV1 {
        max_resident_bytes: 1_000_000,
        max_resident_closures: 2,
        max_chunk_references: 100,
    })
    .unwrap();
    pool.prepare_cached(
        &store,
        content.version().model().closure(),
        &model,
        deadline,
        &cancelled,
    )
    .unwrap();
    pool.prepare_cached(
        &store,
        content.version().environment(),
        &environment,
        deadline,
        &cancelled,
    )
    .unwrap();
    for owner in [&model, &environment] {
        let bundle = pool
            .seal_declared_loader(
                owner,
                CellSealedLoaderLimitsV1 {
                    max_snapshot_bytes: 1_000_000,
                    max_files: 10,
                },
                deadline,
                &cancelled,
            )
            .unwrap();
        let proof = content
            .verify_sealed_loader(&bundle, &expected, content.commitment(), deadline)
            .unwrap();
        assert_eq!(
            proof.scope(),
            if owner.closure_id == model.closure_id {
                CellSealedContentScopeV2::Model
            } else {
                CellSealedContentScopeV2::Environment
            }
        );
        assert_eq!(proof.content(), &content);
        for declared in bundle.closure().files() {
            let mut file = proof.bundle().file(&declared.path, declared.role).unwrap();
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes).unwrap();
            let mut independent = Sha512::new();
            independent.update(b"TRNM/Cell/PayloadContent/v2\0");
            independent.update((bytes.len() as u64).to_be_bytes());
            independent.update(&bytes);
            assert_eq!(
                <[u8; 64]>::from(independent.finalize()),
                content.file(declared.manifest).unwrap().payload_sha512()
            );
        }
        let mut changed = content.clone();
        let manifest = bundle.closure().files()[0].manifest;
        let i = changed
            .contents
            .iter()
            .position(|f| f.manifest == manifest)
            .unwrap();
        changed.contents[i].payload_sha512[63] ^= 1;
        assert!(changed
            .verify_sealed_loader(&bundle, &expected, changed.commitment(), deadline)
            .is_err());
        assert!(content
            .verify_sealed_loader(&bundle, &expected, content.commitment(), Instant::now())
            .is_err());
    }
    let limits = CellSealedLoaderLimitsV1 {
        max_snapshot_bytes: 1_000_000,
        max_files: 10,
    };
    let model_bundle = pool
        .seal_declared_loader(&model, limits, deadline, &cancelled)
        .unwrap();
    let environment_bundle = pool
        .seal_declared_loader(&environment, limits, deadline, &cancelled)
        .unwrap();
    let pair = content
        .verify_sealed_version(
            &model_bundle,
            &environment_bundle,
            &expected,
            content.commitment(),
            deadline,
        )
        .unwrap();
    assert_eq!(pair.model().scope(), CellSealedContentScopeV2::Model);
    assert_eq!(
        pair.environment().scope(),
        CellSealedContentScopeV2::Environment
    );
    assert!(content
        .verify_sealed_version(
            &environment_bundle,
            &model_bundle,
            &expected,
            content.commitment(),
            deadline
        )
        .is_err());
    assert!(content
        .verify_sealed_version(
            &model_bundle,
            &model_bundle,
            &expected,
            content.commitment(),
            deadline
        )
        .is_err());
}
