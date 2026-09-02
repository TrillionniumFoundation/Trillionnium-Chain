use std::{
    fs::{self, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};
use trnm_durable_file_adapters_v0::{
    AtomicSnapshotFileTargetV0, DurableFileErrorV0, FileAuthorityCoordinatorV0,
};
use trnm_node_boundary_v0::{
    AuthorityCommandV0, AuthorityCoordinatorV0, Digest32V0 as NodeDigestV0, NodeIdentityV0,
    OperationBindingV0,
};
use trnm_state_sync_v0::{
    Digest32V0 as SyncDigestV0, NonDestructiveInstallTargetV0, SnapshotManifestV0,
    StagingIdentityV0,
};

static COUNTER: AtomicU64 = AtomicU64::new(0);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new(label: &str) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "trnm-durable-negative-{label}-{}-{timestamp}-{counter}",
            std::process::id()
        ));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn node_digest(byte: u8) -> NodeDigestV0 {
    NodeDigestV0([byte; 32])
}

fn node_identity() -> NodeIdentityV0 {
    NodeIdentityV0 {
        chain_id: node_digest(1),
        validator_id: node_digest(2),
        application_id: node_digest(3),
        generation: 1,
    }
}

fn binding() -> OperationBindingV0 {
    OperationBindingV0::derive(
        node_identity(),
        1,
        0,
        node_digest(4),
        node_digest(5),
        node_digest(6),
    )
}

fn sync_digest(byte: u8) -> SyncDigestV0 {
    SyncDigestV0([byte; 32])
}

fn manifest() -> SnapshotManifestV0 {
    let mut manifest = SnapshotManifestV0 {
        chain_id: sync_digest(1),
        protocol_digest: sync_digest(2),
        height: 2,
        epoch: 1,
        state_root: sync_digest(3),
        chunk_root: sync_digest(4),
        chunk_count: 2,
        maximum_chunk_bytes: 1024,
        total_bytes: 2,
        schema_digest: sync_digest(5),
        checkpoint_digest: sync_digest(6),
        manifest_digest: sync_digest(0),
    };
    manifest.manifest_digest = manifest.canonical_digest();
    manifest
}

#[test]
fn authority_and_snapshot_stores_reject_concurrent_writers() {
    let authority_dir = TestDirectory::new("authority-lock");
    let first = FileAuthorityCoordinatorV0::open(&authority_dir.0, node_identity()).unwrap();
    assert!(matches!(
        FileAuthorityCoordinatorV0::open(&authority_dir.0, node_identity()),
        Err(DurableFileErrorV0::LockBusy(_))
    ));
    drop(first);
    FileAuthorityCoordinatorV0::open(&authority_dir.0, node_identity()).unwrap();

    let snapshot_dir = TestDirectory::new("snapshot-lock");
    let first =
        AtomicSnapshotFileTargetV0::open_or_initialize(&snapshot_dir.0, sync_digest(10), 1, 1)
            .unwrap();
    assert!(matches!(
        AtomicSnapshotFileTargetV0::open_or_initialize(&snapshot_dir.0, sync_digest(10), 1, 1,),
        Err(DurableFileErrorV0::LockBusy(_))
    ));
    drop(first);
}

#[test]
fn any_authority_record_mutation_breaks_recovery() {
    let directory = TestDirectory::new("authority-mutation");
    {
        let mut coordinator =
            FileAuthorityCoordinatorV0::open(&directory.0, node_identity()).unwrap();
        coordinator
            .apply(AuthorityCommandV0::Begin {
                binding: binding(),
                ingress_digest: node_digest(7),
            })
            .unwrap();
    }
    let path = directory.0.join("authority.journal.v0");
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .unwrap();
    let mut byte = [0_u8; 1];
    file.seek(SeekFrom::Start(128)).unwrap();
    file.read_exact(&mut byte).unwrap();
    byte[0] ^= 0x01;
    file.seek(SeekFrom::Start(128)).unwrap();
    file.write_all(&byte).unwrap();
    file.sync_data().unwrap();
    assert!(matches!(
        FileAuthorityCoordinatorV0::open(&directory.0, node_identity()),
        Err(DurableFileErrorV0::CorruptAuthorityJournal(_))
    ));
}

#[test]
fn staging_identity_substitution_does_not_lose_the_real_handle() {
    let directory = TestDirectory::new("staging-handle");
    let mut target =
        AtomicSnapshotFileTargetV0::open_or_initialize(&directory.0, sync_digest(10), 1, 1)
            .unwrap();
    let manifest = manifest();
    let staging = target.begin_staging(&manifest).unwrap();
    let substituted = StagingIdentityV0 {
        generation: staging.generation,
        staging_digest: sync_digest(99),
    };
    assert!(matches!(
        target.abort_staging(substituted),
        Err(DurableFileErrorV0::StagingIdentityMismatch)
    ));
    target.abort_staging(staging).unwrap();
}

#[test]
fn unexpected_staging_file_blocks_current_pointer_swap() {
    let directory = TestDirectory::new("staging-extra-file");
    let initial_root = sync_digest(10);
    let mut target =
        AtomicSnapshotFileTargetV0::open_or_initialize(&directory.0, initial_root, 1, 1).unwrap();
    let manifest = manifest();
    let staging = target.begin_staging(&manifest).unwrap();
    target.write_chunk(staging, 0, b"a").unwrap();
    target.write_chunk(staging, 1, b"b").unwrap();
    fs::write(
        directory
            .0
            .join("staging")
            .join("generation-2")
            .join("unexpected.bin"),
        b"unexpected",
    )
    .unwrap();
    assert!(matches!(
        target.commit_staging_cas(staging, initial_root, &manifest),
        Err(DurableFileErrorV0::RecoveryRequired(_))
    ));
    assert_eq!(target.current_state_root(), initial_root);
}
