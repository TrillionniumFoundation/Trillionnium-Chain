//! Real-file and process-crash regressions for the snapshot adapter. These do
//! not simulate consensus, establish trust anchors, or qualify physical power loss.
use super::*;
use std::process::Command;
use trnm_state_sync_v0::{chunk_merkle_root_v0, SnapshotChunkV0};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SnapshotPointV1 {
    GenerationPublished,
    BeforePointerRename,
    PointerPublished,
    PointerSynced,
}
#[derive(Clone, Copy, Debug)]
pub(super) enum SnapshotFaultV1 {
    Exit(SnapshotPointV1),
    Error(SnapshotPointV1),
}
impl AtomicSnapshotFileTargetV0 {
    pub(super) fn at_snapshot_fault_v1(
        &mut self,
        point: SnapshotPointV1,
    ) -> Result<(), DurableFileErrorV0> {
        match self.fault {
            Some(SnapshotFaultV1::Exit(expected)) if point == expected => std::process::exit(86),
            Some(SnapshotFaultV1::Error(expected)) if point == expected => {
                self.fault = None;
                Err(io::Error::other("injected snapshot publication response failure").into())
            }
            _ => Ok(()),
        }
    }
}

fn d(value: u8) -> SyncDigestV0 {
    SyncDigestV0([value; 32])
}
fn manifest() -> SnapshotManifestV0 {
    let mut value = SnapshotManifestV0 {
        chain_id: d(1),
        protocol_digest: d(2),
        height: 2,
        epoch: 1,
        state_root: d(3),
        chunk_root: d(4),
        chunk_count: 2,
        maximum_chunk_bytes: 1024,
        total_bytes: 2,
        schema_digest: d(5),
        checkpoint_digest: d(6),
        manifest_digest: d(0),
    };
    let binding = value.chunk_binding_digest();
    value.chunk_root = chunk_merkle_root_v0(&[
        SnapshotChunkV0::canonical_digest(binding, 0, b"a"),
        SnapshotChunkV0::canonical_digest(binding, 1, b"b"),
    ]);
    value.manifest_digest = value.canonical_digest();
    value
}
fn open(path: &Path) -> AtomicSnapshotFileTargetV0 {
    AtomicSnapshotFileTargetV0::open_or_initialize(path, d(10), 1, 1).unwrap()
}
fn stage(target: &mut AtomicSnapshotFileTargetV0) -> StagingIdentityV0 {
    let identity = target.begin_staging(&manifest()).unwrap();
    target.write_chunk(identity, 0, b"a").unwrap();
    target.write_chunk(identity, 1, b"b").unwrap();
    identity
}
fn install(path: &Path) {
    let mut target = open(path);
    let identity = stage(&mut target);
    target
        .commit_staging_cas(identity, d(10), &manifest())
        .unwrap();
}
fn unchanged_pointer(path: &Path) -> Vec<u8> {
    fs::read(path.join("CURRENT.v0")).unwrap()
}

#[test]
fn every_manifest_byte_is_bound_and_legacy_or_trailing_bytes_reject() {
    let original = manifest();
    let bytes = encode_manifest_v1(&original).unwrap();
    assert_eq!(bytes.len(), 296);
    // Produced by the separate Python stdlib codec, not this Rust encoder.
    // This is a storage-local reference, not independent acceptance or trust.
    let expected = include_str!("../tests/vectors/snapshot_manifest_v1.hex").trim();
    let actual: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    assert_eq!(actual, expected);
    assert_eq!(
        snapshot_integrity_v1::decode_manifest_v1(&bytes).unwrap(),
        original
    );
    for index in 0..bytes.len() {
        let mut corrupt = bytes.clone();
        corrupt[index] ^= 1;
        assert!(
            snapshot_integrity_v1::decode_manifest_v1(&corrupt).is_err(),
            "byte {index}"
        );
    }
    for prefix in 0..bytes.len() {
        assert!(snapshot_integrity_v1::decode_manifest_v1(&bytes[..prefix]).is_err());
    }
    let mut extra = bytes.clone();
    extra.push(0);
    assert!(snapshot_integrity_v1::decode_manifest_v1(&extra).is_err());
    let mut legacy = vec![0u8; 124];
    legacy[..8].copy_from_slice(b"TRNMSM00");
    assert!(snapshot_integrity_v1::decode_manifest_v1(&legacy).is_err());
}

#[test]
fn same_length_staged_chunk_corruption_cannot_publish_current() {
    let directory = tests::TestDirectory::new("snapshot-staged-tamper");
    let mut target = open(directory.path());
    let identity = stage(&mut target);
    let before = unchanged_pointer(directory.path());
    fs::write(
        directory
            .path()
            .join("staging/generation-2/chunk-00000000.bin"),
        b"z",
    )
    .unwrap();
    assert!(matches!(
        target.commit_staging_cas(identity, d(10), &manifest()),
        Err(DurableFileErrorV0::ChunkSubstitution)
    ));
    assert_eq!(unchanged_pointer(directory.path()), before);
    assert_eq!(target.current_generation(), 1);
}

#[test]
fn staged_manifest_corruption_and_full_manifest_rebinding_reject() {
    let directory = tests::TestDirectory::new("snapshot-manifest-tamper");
    let mut target = open(directory.path());
    let identity = stage(&mut target);
    let before = unchanged_pointer(directory.path());
    let mut retargeted = manifest();
    retargeted.maximum_chunk_bytes += 1;
    assert!(target
        .commit_staging_cas(identity, d(10), &retargeted)
        .is_err());
    let path = directory.path().join("staging/generation-2/MANIFEST.v0");
    let mut bytes = fs::read(&path).unwrap();
    bytes[88] ^= 1;
    fs::write(&path, bytes).unwrap();
    assert!(target
        .commit_staging_cas(identity, d(10), &manifest())
        .is_err());
    assert_eq!(unchanged_pointer(directory.path()), before);
}

#[test]
fn complete_manifest_with_the_wrong_chunk_commitment_rejects() {
    let directory = tests::TestDirectory::new("snapshot-wrong-commitment");
    let mut target = open(directory.path());
    let mut wrong = manifest();
    wrong.chunk_root = d(88);
    wrong.manifest_digest = wrong.canonical_digest();
    let identity = target.begin_staging(&wrong).unwrap();
    target.write_chunk(identity, 0, b"a").unwrap();
    target.write_chunk(identity, 1, b"b").unwrap();
    assert!(matches!(
        target.commit_staging_cas(identity, d(10), &wrong),
        Err(DurableFileErrorV0::ChunkSubstitution)
    ));
    assert_eq!(target.current_state_root(), d(10));
}

#[test]
fn reopen_checks_committed_chunk_bytes_not_just_pointer_checksum() {
    let directory = tests::TestDirectory::new("snapshot-reopen-tamper");
    install(directory.path());
    let before = unchanged_pointer(directory.path());
    fs::write(
        directory
            .path()
            .join("generations/generation-2/chunk-00000001.bin"),
        b"x",
    )
    .unwrap();
    assert!(AtomicSnapshotFileTargetV0::open_or_initialize(directory.path(), d(10), 1, 1).is_err());
    assert_eq!(unchanged_pointer(directory.path()), before);
    assert_eq!(
        fs::read(
            directory
                .path()
                .join("generations/generation-2/chunk-00000001.bin")
        )
        .unwrap(),
        b"x"
    );
}

#[test]
fn missing_current_with_retained_generation_cannot_reset_to_genesis() {
    let directory = tests::TestDirectory::new("snapshot-pointer-missing");
    install(directory.path());
    fs::remove_file(directory.path().join("CURRENT.v0")).unwrap();
    assert!(matches!(
        AtomicSnapshotFileTargetV0::open_or_initialize(directory.path(), d(99), 99, 99),
        Err(DurableFileErrorV0::RecoveryRequired(_))
    ));
    assert!(!directory.path().join("CURRENT.v0").exists());
    assert!(directory
        .path()
        .join("generations/generation-2/MANIFEST.v0")
        .exists());
}

#[test]
fn missing_or_legacy_committed_manifest_is_preserved_and_rejected() {
    for legacy in [false, true] {
        let directory = tests::TestDirectory::new("snapshot-legacy");
        install(directory.path());
        let path = directory
            .path()
            .join("generations/generation-2/MANIFEST.v0");
        if legacy {
            let mut bytes = vec![0u8; 124];
            bytes[..8].copy_from_slice(b"TRNMSM00");
            fs::write(&path, bytes).unwrap();
        } else {
            fs::remove_file(&path).unwrap();
        }
        let before = unchanged_pointer(directory.path());
        assert!(
            AtomicSnapshotFileTargetV0::open_or_initialize(directory.path(), d(10), 1, 1).is_err()
        );
        assert_eq!(unchanged_pointer(directory.path()), before);
        assert_eq!(path.exists(), legacy);
    }
}

#[test]
fn bounded_read_rejects_a_sparse_oversized_pointer_before_allocation() {
    let directory = tests::TestDirectory::new("snapshot-large-pointer");
    drop(open(directory.path()));
    let path = directory.path().join("CURRENT.v0");
    OpenOptions::new()
        .write(true)
        .open(&path)
        .unwrap()
        .set_len(1 << 32)
        .unwrap();
    assert!(AtomicSnapshotFileTargetV0::open_or_initialize(directory.path(), d(10), 1, 1).is_err());
    assert_eq!(fs::metadata(path).unwrap().len(), 1 << 32);
}

#[test]
fn admission_bounds_and_total_write_budget_have_no_partial_extra_chunk() {
    let directory = tests::TestDirectory::new("snapshot-write-cap");
    let mut target = open(directory.path());
    let mut huge = manifest();
    huge.chunk_count = u32::MAX;
    huge.manifest_digest = huge.canonical_digest();
    assert!(target.begin_staging(&huge).is_err());
    assert!(fs::read_dir(directory.path().join("staging"))
        .unwrap()
        .next()
        .is_none());
    let identity = target.begin_staging(&manifest()).unwrap();
    target.write_chunk(identity, 0, b"a").unwrap();
    target.write_chunk(identity, 0, b"a").unwrap();
    assert!(target.write_chunk(identity, 1, b"bc").is_err());
    assert!(!directory
        .path()
        .join("staging/generation-2/chunk-00000001.bin")
        .exists());
    target.write_chunk(identity, 1, b"b").unwrap();
    target
        .commit_staging_cas(identity, d(10), &manifest())
        .unwrap();
}

#[cfg(target_os = "linux")]
#[test]
fn linked_chunks_are_not_opened_as_trusted_snapshot_bytes() {
    use std::os::unix::fs::symlink;
    for hard in [false, true] {
        let directory = tests::TestDirectory::new("snapshot-linked-chunk");
        let mut target = open(directory.path());
        let identity = stage(&mut target);
        let path = directory
            .path()
            .join("staging/generation-2/chunk-00000000.bin");
        let outside = directory.path().join("untrusted-same-bytes");
        fs::write(&outside, b"a").unwrap();
        fs::remove_file(&path).unwrap();
        if hard {
            fs::hard_link(&outside, &path).unwrap();
        } else {
            symlink(&outside, &path).unwrap();
        }
        assert!(target
            .commit_staging_cas(identity, d(10), &manifest())
            .is_err());
        assert_eq!(target.current_generation(), 1);
        assert_eq!(fs::read(&outside).unwrap(), b"a");
    }
}

#[test]
fn observed_directory_or_lock_replacement_permanently_fences_owner() {
    for name in ["staging", "generations", "snapshot.lock.v0"] {
        let directory = tests::TestDirectory::new("snapshot-namespace");
        let mut target = open(directory.path());
        let original = directory.path().join(name);
        let moved = directory.path().join(format!("retained-{name}"));
        fs::rename(&original, &moved).unwrap();
        if name.ends_with(".v0") {
            fs::write(&original, b"").unwrap();
        } else {
            fs::create_dir(&original).unwrap();
        }
        assert!(target.begin_staging(&manifest()).is_err());
        fs::remove_file(&original)
            .or_else(|_| fs::remove_dir(&original))
            .unwrap();
        fs::rename(&moved, &original).unwrap();
        assert!(matches!(
            target.begin_staging(&manifest()),
            Err(DurableFileErrorV0::Poisoned)
        ));
    }
}

#[test]
fn cleanup_preflights_unknown_evidence_before_removing_any_generation() {
    let directory = tests::TestDirectory::new("snapshot-cleanup-evidence");
    {
        let mut target = open(directory.path());
        let _ = stage(&mut target);
    }
    let unknown = directory.path().join("staging/not-a-generation");
    fs::create_dir(&unknown).unwrap();
    fs::write(unknown.join("keep-evidence"), b"retain").unwrap();
    let mut target = open(directory.path());
    assert!(target.recover_unreferenced_generations().is_err());
    assert!(directory
        .path()
        .join("staging/generation-2/MANIFEST.v0")
        .exists());
    assert_eq!(fs::read(unknown.join("keep-evidence")).unwrap(), b"retain");
}

#[test]
fn post_rename_sync_uncertainty_never_returns_durable_success_or_permits_abort() {
    let directory = tests::TestDirectory::new("snapshot-sync-uncertain");
    let mut target = open(directory.path());
    let identity = stage(&mut target);
    target.fault = Some(SnapshotFaultV1::Error(SnapshotPointV1::PointerPublished));
    assert!(target
        .commit_staging_cas(identity, d(10), &manifest())
        .is_err());
    assert!(target.post_commit_directory_sync_degraded());
    assert!(matches!(
        target.abort_staging(identity),
        Err(DurableFileErrorV0::Poisoned)
    ));
    assert!(matches!(
        target.begin_staging(&manifest()),
        Err(DurableFileErrorV0::Poisoned)
    ));
    assert!(directory
        .path()
        .join("generations/generation-2/MANIFEST.v0")
        .exists());
    drop(target);
    let mut recovered = open(directory.path());
    assert_eq!(recovered.current_state_root(), manifest().state_root);
    recovered.verify_current_snapshot_v1().unwrap();
}

// This entry point is inert in the normal suite. The parent below proves an
// actual abrupt child process exit at each requested, test-only crash boundary.
#[test]
fn snapshot_crash_child() {
    let Ok(path) = std::env::var("TRNM_SNAPSHOT_CRASH_DIRECTORY") else {
        return;
    };
    let point = match std::env::var("TRNM_SNAPSHOT_CRASH_POINT").unwrap().as_str() {
        "generation" => SnapshotPointV1::GenerationPublished,
        "before-pointer" => SnapshotPointV1::BeforePointerRename,
        "pointer" => SnapshotPointV1::PointerPublished,
        "synced" => SnapshotPointV1::PointerSynced,
        other => panic!("unexpected crash point {other}"),
    };
    let mut target = open(Path::new(&path));
    let identity = stage(&mut target);
    target.fault = Some(SnapshotFaultV1::Exit(point));
    let _ = target.commit_staging_cas(identity, d(10), &manifest());
    panic!("requested crash boundary was not reached");
}

#[test]
fn four_process_crash_cuts_reopen_exact_source_or_target_and_can_continue() {
    for (point, target_committed) in [
        ("generation", false),
        ("before-pointer", false),
        ("pointer", true),
        ("synced", true),
    ] {
        let directory = tests::TestDirectory::new("snapshot-child-cut");
        let status = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "snapshot_recovery_tests::snapshot_crash_child",
                "--test-threads=1",
            ])
            .env("TRNM_SNAPSHOT_CRASH_DIRECTORY", directory.path())
            .env("TRNM_SNAPSHOT_CRASH_POINT", point)
            .status()
            .unwrap();
        assert_eq!(
            status.code(),
            Some(86),
            "{point}: child must actually reach the cut"
        );
        let mut target = open(directory.path());
        assert_eq!(
            target.current_state_root(),
            if target_committed {
                manifest().state_root
            } else {
                d(10)
            }
        );
        if !target_committed {
            target.recover_unreferenced_generations().unwrap();
            let identity = stage(&mut target);
            target
                .commit_staging_cas(identity, d(10), &manifest())
                .unwrap();
        }
        target.verify_current_snapshot_v1().unwrap();
        assert_eq!(target.current_generation(), 2);
        assert_eq!(
            fs::read(
                directory
                    .path()
                    .join("generations/generation-2/chunk-00000000.bin")
            )
            .unwrap(),
            b"a"
        );
    }
}
