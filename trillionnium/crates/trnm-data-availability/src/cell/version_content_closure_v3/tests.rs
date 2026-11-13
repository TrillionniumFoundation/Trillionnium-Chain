use super::*;
use crate::cell::{
    version::tests::{fixture, owner as loader_owner},
    version_content::tests::session,
    CellCacheConfigV4, CellFileRoleV1, CellLoaderContextV1, CellManifestV1, CellModelReleaseRootV1,
    CellReleaseClosureV1, CellReleaseLimitsV1, CellRetainedVersionEntryV1,
    CellVersionLoaderContextV1, CellVersionManifestV1,
};
use std::time::Duration;

const VERSION_BYTES: u64 = 4 * 32769;

fn successor(
    original: &CellVersionManifestV1,
    generation: u64,
    parents: Vec<[u8; 32]>,
) -> CellVersionManifestV1 {
    let before = original.model().closure();
    let closure = CellReleaseClosureV1::new(
        before.release().context().clone(),
        generation,
        before.loader_profile(),
        before.roots().to_vec(),
        before.files().to_vec(),
    )
    .unwrap();
    CellVersionManifestV1::new(
        CellModelReleaseRootV1::new(closure, parents).unwrap(),
        original.environment().clone(),
        original.manifests().to_vec(),
    )
    .unwrap()
}

fn capture(version: &CellVersionManifestV1, store: &CellStoreV1) -> CellVersionContentV2 {
    let model = loader_owner(version.model().closure(), CellFileRoleV1::Base);
    let environment = loader_owner(version.environment(), CellFileRoleV1::Configuration);
    CellVersionContentV2::capture_cached(
        version,
        store,
        &CellVersionLoaderContextV1 {
            commitment: version.commitment(),
            model: &model,
            environment: &environment,
        },
        &mut session(1),
    )
    .unwrap()
}

fn closure(
    mut versions: Vec<CellVersionContentV2>,
    root_model: [u8; 32],
) -> CellResultV1<CellVersionContentClosureV3> {
    versions.sort_by_key(CellVersionContentV2::commitment);
    let root = versions
        .iter()
        .position(|node| node.version().model().id() == root_model)
        .unwrap();
    CellVersionContentClosureV3::new(vec![root as u16], versions)
}

fn lineage_fixture() -> (tempfile::TempDir, CellStoreV1, CellVersionContentClosureV3) {
    let (dir, store, parent) = fixture();
    let child = successor(&parent, 3, vec![parent.model().id()]);
    let content = closure(
        vec![capture(&parent, &store), capture(&child, &store)],
        child.model().id(),
    )
    .unwrap();
    (dir, store, content)
}

fn with_owner<T>(
    content: &CellVersionContentClosureV3,
    run: impl FnOnce(&CellRetainedVersionSetV1, &CellRetainedSetOwnerV1<'_>) -> T,
) -> T {
    let mut entries: Vec<_> = content
        .versions()
        .iter()
        .map(|node| CellRetainedVersionEntryV1 {
            version: node.version().clone(),
            retain_from_height: 20,
            retain_until_height: 100,
        })
        .collect();
    entries.sort_by_key(|entry| entry.version.commitment());
    let retained = CellRetainedVersionSetV1::new(7, entries).unwrap();
    let pins: Vec<(CellLoaderContextV1, CellLoaderContextV1)> = retained
        .entries()
        .iter()
        .map(|entry| {
            (
                loader_owner(entry.version.model().closure(), CellFileRoleV1::Base),
                loader_owner(entry.version.environment(), CellFileRoleV1::Configuration),
            )
        })
        .collect();
    let views: Vec<_> = retained
        .entries()
        .iter()
        .zip(&pins)
        .map(|(entry, (model, environment))| CellVersionLoaderContextV1 {
            commitment: entry.version.commitment(),
            model,
            environment,
        })
        .collect();
    let owner = CellRetainedSetOwnerV1 {
        commitment: retained.commitment(),
        epoch: 7,
        current_height: 30,
        required_until_height: 90,
        versions: &views,
    };
    run(&retained, &owner)
}

fn corrupt_chunk_claim(content: &CellVersionContentV2, byte: u8) -> CellVersionContentV2 {
    let mut wire = content.encode();
    *wire.last_mut().unwrap() ^= byte;
    // Valid metadata, deliberately false SHA-512 claim; no actual bytes changed.
    CellVersionContentV2::decode(&wire).unwrap()
}

#[test]
fn tcv3_cold_cache_reads_full_model_environment_and_explicit_ancestor() {
    let (dir, store, content) = lineage_fixture();
    let decoded = CellVersionContentClosureV3::decode(&content.encode()).unwrap();
    assert_eq!(decoded, content);
    drop(store);
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
    let roots = content.root_commitments();
    let pin = CellContentLineagePinV3 {
        commitment: content.commitment(),
        roots: &roots,
    };
    with_owner(&content, |retained, owner| {
        let observed = retained
            .verify_content_lineage_cached(&decoded, &store, owner, &pin, &mut session(2))
            .unwrap();
        assert_eq!(observed.content(), &content);
        assert_eq!(observed.retained_commitment(), retained.commitment());
        assert_eq!((observed.epoch(), observed.current_height()), (7, 30));
        assert_eq!(
            observed.usage(),
            CellContentReadUsageV2 {
                attempted_scans: 2,
                reserved_payload_bytes: VERSION_BYTES * 2,
                reserved_chunks: 24,
            }
        );
        let (start, end) = observed.observation_window();
        assert!(start <= end);
    });
}

#[test]
fn tcv3_missing_parent_is_not_an_origin_or_legacy_digest_wrapper() {
    let (_dir, _store, content) = lineage_fixture();
    let child = content.versions()[usize::from(content.roots()[0])].clone();
    assert!(matches!(
        CellVersionContentClosureV3::new(vec![0], vec![child.clone()]),
        Err(CellErrorV1::Invalid("content lineage missing parent"))
    ));
    assert!(CellVersionContentClosureV3::decode(&child.version().encode()).is_err());
    assert!(CellVersionContentClosureV3::decode(&child.encode()).is_err());
    assert!(CellVersionContentClosureV3::decode(child.version().model().id().as_slice()).is_err());
}

#[test]
fn tcv3_checks_independent_full_pin_and_exact_selected_roots_before_scanning() {
    let (_dir, store, content) = lineage_fixture();
    let roots = content.root_commitments();
    let other = content
        .versions()
        .iter()
        .find(|v| v.commitment() != roots[0])
        .unwrap()
        .commitment();
    with_owner(&content, |retained, owner| {
        for (commitment, selected) in [
            ([0; 64], roots.clone()),
            (content.versions()[0].commitment(), roots.clone()),
            (content.commitment(), vec![other]),
            (content.commitment(), vec![]),
            (content.commitment(), vec![roots[0], roots[0]]),
        ] {
            let mut budget = session(4);
            assert!(retained
                .verify_content_lineage_cached(
                    &content,
                    &store,
                    owner,
                    &CellContentLineagePinV3 {
                        commitment,
                        roots: &selected
                    },
                    &mut budget,
                )
                .is_err());
            assert_eq!(budget.usage(), CellContentReadUsageV2::default());
        }
    });
}

#[test]
fn tcv3_rejects_duplicate_legacy_alias_even_when_strong_claims_differ() {
    let (_dir, store, version) = fixture();
    let first = capture(&version, &store);
    let changed = corrupt_chunk_claim(&first, 1);
    assert_eq!(first.version().model().id(), changed.version().model().id());
    assert_ne!(first.commitment(), changed.commitment());
    let mut members = vec![first, changed];
    members.sort_by_key(CellVersionContentV2::commitment);
    assert!(matches!(
        CellVersionContentClosureV3::new(vec![0, 1], members),
        Err(CellErrorV1::Invalid(
            "content lineage ambiguous legacy model alias"
        ))
    ));
}

#[test]
fn tcv3_alternate_ancestor_content_changes_root_and_cannot_pass_actual_scan() {
    let (_dir, store, content) = lineage_fixture();
    let root_model = content.versions()[usize::from(content.roots()[0])]
        .version()
        .model()
        .id();
    let mut versions = content.versions().to_vec();
    let index = versions
        .iter()
        .position(|v| v.version().model().lineage().is_empty())
        .unwrap();
    versions[index] = corrupt_chunk_claim(&versions[index], 1);
    let changed = closure(versions, root_model).unwrap();
    assert_ne!(changed.commitment(), content.commitment());
    assert_eq!(changed.root_commitments(), content.root_commitments());
    let roots = content.root_commitments();
    with_owner(&content, |retained, owner| {
        let mut budget = session(4);
        assert!(retained
            .verify_content_lineage_cached(
                &changed,
                &store,
                owner,
                &CellContentLineagePinV3 {
                    commitment: content.commitment(),
                    roots: &roots
                },
                &mut budget,
            )
            .is_err());
        assert_eq!(budget.usage().attempted_scans, 0);
        // Rebinding public metadata is not evidence of matching actual bytes.
        assert!(retained
            .verify_content_lineage_cached(
                &changed,
                &store,
                owner,
                &CellContentLineagePinV3 {
                    commitment: changed.commitment(),
                    roots: &roots
                },
                &mut budget,
            )
            .is_err());
        assert!(budget.usage().attempted_scans > 0);
    });
}

#[test]
fn tcv3_unreachable_extra_origin_and_non_decreasing_parent_generation_refuse() {
    let (_dir, store, content) = lineage_fixture();
    let root_model = content.versions()[usize::from(content.roots()[0])]
        .version()
        .model()
        .id();
    let parent = content
        .versions()
        .iter()
        .find(|v| v.version().model().lineage().is_empty())
        .unwrap();
    let unrelated = successor(parent.version(), 5, vec![]);
    let mut extra = content.versions().to_vec();
    extra.push(capture(&unrelated, &store));
    assert!(matches!(
        closure(extra, root_model),
        Err(CellErrorV1::Invalid("content lineage unreachable version"))
    ));
    let child = successor(parent.version(), 2, vec![parent.version().model().id()]);
    assert!(matches!(
        closure(
            vec![parent.clone(), capture(&child, &store)],
            child.model().id()
        ),
        Err(CellErrorV1::Invalid(
            "content lineage parent family/generation"
        ))
    ));
}

#[test]
fn tcv3_foreign_family_cannot_be_imported_as_an_ancestor() {
    let (_dir, store, parent) = fixture();
    let mut manifests = Vec::new();
    let mut rebuild = |old: &CellReleaseClosureV1, runtime: [u8; 32], generation| {
        let mut context = old.release().context().clone();
        context.family = "other-declared-family".into();
        context.runtime = runtime;
        let mut files = old.files().to_vec();
        for file in &mut files {
            let previous = parent
                .manifests()
                .iter()
                .find(|m| m.id() == file.manifest)
                .unwrap();
            let manifest = CellManifestV1::new(
                context.clone(),
                previous.size(),
                previous.payload_sha256(),
                previous.chunk_bytes(),
                previous.chunks().to_vec(),
            )
            .unwrap();
            store
                .put_manifest(manifest.id(), &manifest.encode())
                .unwrap();
            file.manifest = manifest.id();
            manifests.push(manifest);
        }
        CellReleaseClosureV1::new(
            context,
            generation,
            old.loader_profile(),
            old.roots().to_vec(),
            files,
        )
        .unwrap()
    };
    let environment = rebuild(
        parent.environment(),
        parent.environment().release().context().runtime,
        1,
    );
    let model = rebuild(parent.model().closure(), environment.id(), 3);
    manifests.sort_by_key(CellManifestV1::id);
    let child = CellVersionManifestV1::new(
        CellModelReleaseRootV1::new(model, vec![parent.model().id()]).unwrap(),
        environment,
        manifests,
    )
    .unwrap();
    assert!(matches!(
        closure(
            vec![capture(&parent, &store), capture(&child, &store)],
            child.model().id()
        ),
        Err(CellErrorV1::Invalid(
            "content lineage parent family/generation"
        ))
    ));
}

#[test]
fn tcv3_shared_transitive_ancestor_is_scanned_once_per_declared_version() {
    let (_dir, store, origin) = fixture();
    let left = successor(&origin, 3, vec![origin.model().id()]);
    let right = successor(&origin, 4, vec![origin.model().id()]);
    let mut parents = vec![left.model().id(), right.model().id()];
    parents.sort();
    let latest = successor(&origin, 5, parents);
    let content = closure(
        [&origin, &left, &right, &latest]
            .into_iter()
            .map(|v| capture(v, &store))
            .collect(),
        latest.model().id(),
    )
    .unwrap();
    let roots = content.root_commitments();
    with_owner(&content, |retained, owner| {
        let observation = retained
            .verify_content_lineage_cached(
                &content,
                &store,
                owner,
                &CellContentLineagePinV3 {
                    commitment: content.commitment(),
                    roots: &roots,
                },
                &mut session(4),
            )
            .unwrap();
        assert_eq!(
            observation.usage(),
            CellContentReadUsageV2 {
                attempted_scans: 4,
                reserved_payload_bytes: VERSION_BYTES * 4,
                reserved_chunks: 48,
            }
        );
    });
    let incomplete: Vec<_> = content
        .versions()
        .iter()
        .filter(|v| v.version().model().id() != origin.model().id())
        .cloned()
        .collect();
    assert!(matches!(
        closure(incomplete, latest.model().id()),
        Err(CellErrorV1::Invalid("content lineage missing parent"))
    ));
}

#[test]
fn tcv3_graph_rejects_cycle_and_overdeep_paths_including_shared_subgraphs() {
    assert!(matches!(
        validate_graph(&[vec![1], vec![0]], &[0]),
        Err(CellErrorV1::Invalid("content lineage cycle"))
    ));
    let mut parents = vec![vec![]];
    for index in 1..=MAX_DEPTH {
        parents.push(vec![index - 1]);
    }
    // Visiting the short shared branch first cannot hide a later long path.
    assert!(matches!(
        validate_graph(&parents, &[0, MAX_DEPTH as u16]),
        Err(CellErrorV1::Invalid("content lineage depth"))
    ));
    assert!(validate_graph(&[vec![], vec![0], vec![0], vec![1, 2]], &[3]).is_ok());
    assert!(validate_graph(&[vec![2], vec![]], &[0]).is_err());
}

#[test]
fn tcv3_member_scans_share_the_original_finite_session() {
    let (_dir, store, content) = lineage_fixture();
    let roots = content.root_commitments();
    let pin = CellContentLineagePinV3 {
        commitment: content.commitment(),
        roots: &roots,
    };
    with_owner(&content, |retained, owner| {
        let mut budget = session(1);
        let deadline = budget.deadline();
        assert!(retained
            .verify_content_lineage_cached(&content, &store, owner, &pin, &mut budget)
            .is_err());
        assert_eq!(
            budget.usage(),
            CellContentReadUsageV2 {
                attempted_scans: 1,
                reserved_payload_bytes: VERSION_BYTES,
                reserved_chunks: 12,
            }
        );
        assert!(retained
            .verify_content_lineage_cached(&content, &store, owner, &pin, &mut budget)
            .is_err());
        assert_eq!(budget.usage().attempted_scans, 1);
        assert_eq!(budget.deadline(), deadline);
    });
}

#[test]
fn tcv3_failed_late_member_keeps_both_reservations_and_no_partial_readback() {
    let (_dir, store, content) = lineage_fixture();
    let root_model = content.versions()[usize::from(content.roots()[0])]
        .version()
        .model()
        .id();
    let source = &content.versions()[1];
    let mutated = (1..=u8::MAX)
        .map(|byte| corrupt_chunk_claim(source, byte))
        .find(|member| member.commitment() > content.versions()[0].commitment())
        .unwrap();
    let changed = closure(vec![content.versions()[0].clone(), mutated], root_model).unwrap();
    let roots = changed.root_commitments();
    let pin = CellContentLineagePinV3 {
        commitment: changed.commitment(),
        roots: &roots,
    };
    with_owner(&content, |retained, owner| {
        let mut budget = CellContentReadSessionV2::new(
            CellReleaseLimitsV1 {
                max_payload_bytes: 2 * VERSION_BYTES,
                max_chunks: 24,
                deadline: Instant::now() + Duration::from_secs(15),
            },
            2,
        )
        .unwrap();
        let deadline = budget.deadline();
        assert!(matches!(
            retained.verify_content_lineage_cached(&changed, &store, owner, &pin, &mut budget,),
            Err(CellErrorV1::Invalid("content actual byte commitments"))
        ));
        assert_eq!(
            budget.usage(),
            CellContentReadUsageV2 {
                attempted_scans: 2,
                reserved_payload_bytes: 2 * VERSION_BYTES,
                reserved_chunks: 24,
            }
        );
        let real_roots = content.root_commitments();
        assert!(retained
            .verify_content_lineage_cached(
                &content,
                &store,
                owner,
                &CellContentLineagePinV3 {
                    commitment: content.commitment(),
                    roots: &real_roots
                },
                &mut budget
            )
            .is_err());
        assert_eq!(budget.usage().attempted_scans, 2);
        assert_eq!(budget.deadline(), deadline);
    });
}

#[test]
fn tcv3_requires_exact_retained_owner_set_epoch_and_window_before_reads() {
    let (_dir, store, content) = lineage_fixture();
    let roots = content.root_commitments();
    let pin = CellContentLineagePinV3 {
        commitment: content.commitment(),
        roots: &roots,
    };
    with_owner(&content, |retained, owner| {
        for (epoch, height, until) in [(6, 30, 90), (7, 19, 90), (7, 30, 101)] {
            let wrong = CellRetainedSetOwnerV1 {
                commitment: owner.commitment,
                epoch,
                current_height: height,
                required_until_height: until,
                versions: owner.versions,
            };
            let mut budget = session(4);
            assert!(retained
                .verify_content_lineage_cached(&content, &store, &wrong, &pin, &mut budget)
                .is_err());
            assert_eq!(budget.usage(), CellContentReadUsageV2::default());
        }
        let parent = content
            .versions()
            .iter()
            .find(|v| v.version().model().lineage().is_empty())
            .unwrap();
        let subset = CellVersionContentClosureV3::new(vec![0], vec![parent.clone()]).unwrap();
        let subset_roots = subset.root_commitments();
        let mut budget = session(4);
        assert!(matches!(
            retained.verify_content_lineage_cached(
                &subset,
                &store,
                owner,
                &CellContentLineagePinV3 {
                    commitment: subset.commitment(),
                    roots: &subset_roots
                },
                &mut budget
            ),
            Err(CellErrorV1::Invalid("content lineage exact retained set"))
        ));
        assert_eq!(budget.usage().attempted_scans, 0);
    });
}

#[test]
fn tcv3_missing_actual_cache_bytes_refuse_despite_complete_pinned_metadata() {
    let (dir, store, content) = lineage_fixture();
    let manifest = &content.versions()[0].version().manifests()[0];
    let db = rusqlite::Connection::open(dir.path().join("cache.sqlite")).unwrap();
    db.execute(
        "DELETE FROM cell_chunks_v1 WHERE hash = ?1",
        [manifest.chunks()[0].sha256.as_slice()],
    )
    .unwrap();
    let roots = content.root_commitments();
    with_owner(&content, |retained, owner| {
        let mut budget = session(4);
        assert!(retained
            .verify_content_lineage_cached(
                &content,
                &store,
                owner,
                &CellContentLineagePinV3 {
                    commitment: content.commitment(),
                    roots: &roots
                },
                &mut budget
            )
            .is_err());
        assert_eq!(budget.usage().attempted_scans, 1);
        assert_eq!(budget.usage().reserved_payload_bytes, VERSION_BYTES);
    });
}

#[test]
fn tcv3_namespace_canonical_order_counts_and_all_byte_boundaries_are_strict() {
    let (_dir, _store, content) = lineage_fixture();
    let wire = content.encode();
    assert_eq!(&wire[..4], b"TCV3");
    for count in [0, 3, 4, 6, 8, 10, wire.len() - 1] {
        assert!(CellVersionContentClosureV3::decode(&wire[..count]).is_err());
    }
    let mut trailing = wire.clone();
    trailing.push(0);
    assert!(CellVersionContentClosureV3::decode(&trailing).is_err());
    for (at, value) in [(4, 0u16), (4, 17), (6, 0), (6, 3), (8, 2)] {
        let mut changed = wire.clone();
        changed[at..at + 2].copy_from_slice(&value.to_be_bytes());
        assert!(CellVersionContentClosureV3::decode(&changed).is_err());
    }
    let mut huge = wire.clone();
    huge[10..14].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(CellVersionContentClosureV3::decode(&huge).is_err());
    let mut reordered = content.versions().to_vec();
    reordered.reverse();
    assert!(CellVersionContentClosureV3::new(vec![0], reordered).is_err());
    assert!(CellVersionContentClosureV3::new(vec![0, 0], content.versions().to_vec()).is_err());
    assert!(CellVersionContentClosureV3::new(vec![0], vec![]).is_err());
    assert!(
        CellVersionContentClosureV3::decode(&vec![0; MAX_CELL_CONTENT_LINEAGE_BYTES_V3 + 1])
            .is_err()
    );
}

#[test]
fn tcv3_commitment_matches_independent_python_vector_without_tcv2_domain_alias() {
    let (_dir, _store, node) = crate::cell::version_content::tests::captured();
    let content = CellVersionContentClosureV3::new(vec![0], vec![node]).unwrap();
    // Independently computed with Python hashlib/struct from the unchanged
    // cell-version-content-v2.json wire (SHA256 61ea40125a3b45e9d4eb1bf088fab5148
    // 657bff5e710c137e1a1e948b42f71f4), not from this Rust encoder's output.
    assert_eq!(content.encode().len(), 3605);
    assert_eq!(hex::encode(content.commitment()),
        "faf6d568faf68729d02e555d35ae70ed6ad98c5e5c46dd388e988b56932c6626555848dc057f81cc36b115e9d4b69036403a73c8ee7e04935f33f77c1e4ecd0f");
    for node in content.versions() {
        assert_ne!(content.commitment(), node.commitment());
        assert_ne!(content.commitment(), node.version().commitment());
    }
}
