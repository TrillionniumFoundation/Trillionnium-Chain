use std::{fs, path::{Path, PathBuf}};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use tempfile::TempDir;
use trnm_consensus_peer_lease::{
    PayloadReplayFrameV1, PayloadReplayNamespaceV1, PayloadReplayRecoveryOwnerV1,
    PayloadReplayRecoveryStatusV1, PayloadReplayRecoveryTargetV1, PayloadReplayStoreV1,
    PeerLeaseDirectionV1,
};

fn private_tempdir(prefix: &str) -> TempDir {
    let directory = tempfile::Builder::new().prefix(prefix).tempdir().unwrap();
    #[cfg(unix)]
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    directory
}

fn private_directory(root: &Path, name: &str) -> PathBuf {
    let path = root.join(name);
    fs::create_dir(&path).unwrap();
    #[cfg(unix)]
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    path
}

fn private_file(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap();
    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

fn namespace() -> PayloadReplayNamespaceV1 {
    PayloadReplayNamespaceV1::new([1; 32], 7, [2; 32], [3; 32], [4; 32]).unwrap()
}

fn frame(namespace: PayloadReplayNamespaceV1) -> PayloadReplayFrameV1 {
    PayloadReplayFrameV1::new(
        namespace
            .scope_for([9; 32], PeerLeaseDirectionV1::Inbound)
            .unwrap(),
        namespace.run_id_hash(),
        namespace.network_context_hash(),
        [5; 32],
        1,
        0,
        2,
        11,
        [10; 32],
    )
    .unwrap()
}

fn head_path(payload: &Path) -> PathBuf {
    let name = payload.file_name().unwrap().to_str().unwrap();
    payload.with_file_name(format!(".{name}.head-v1"))
}

#[test]
fn quarantine_name_collision_preserves_existing_and_new_evidence() {
    let root = private_tempdir("trnm-payload-quarantine-collision-");
    let payload = root.path().join("frames.wal");
    let acknowledgements = private_directory(root.path(), "core-acks");
    let namespace = namespace();
    let frame = frame(namespace);
    let receipt = {
        let mut store = PayloadReplayStoreV1::open(&payload, namespace).unwrap();
        store.admit(&frame).unwrap()
    };
    let target = PayloadReplayRecoveryTargetV1::from_admission(frame, receipt);

    let head = head_path(&payload);
    let head_name = head.file_name().unwrap().to_str().unwrap();
    let retained = head.with_file_name(format!(".{head_name}.tmp-collision"));
    private_file(&retained, b"new retained head evidence");

    let collision = root.path().join(format!(
        "payload-head-recovery-evidence-{}-0-0.v1",
        std::process::id()
    ));
    private_file(&collision, b"older retained head evidence");

    let mut owner = PayloadReplayRecoveryOwnerV1::open(
        &payload,
        &acknowledgements,
        namespace,
        target,
    )
    .unwrap();
    assert!(matches!(
        owner.status().unwrap(),
        PayloadReplayRecoveryStatusV1::RecoverableResidualTemporaries { .. }
    ));
    assert!(matches!(
        owner.recover_payload_publication().unwrap(),
        PayloadReplayRecoveryStatusV1::AdmittedUnacknowledged { .. }
    ));

    assert_eq!(fs::read(&collision).unwrap(), b"older retained head evidence");
    assert!(!retained.exists());
    let preserved_new_evidence = fs::read_dir(root.path())
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("payload-head-recovery-evidence-"))
        })
        .any(|path| fs::read(path).is_ok_and(|bytes| bytes == b"new retained head evidence"));
    assert!(preserved_new_evidence);
}
