use std::{env, fs, process::Command};

use tempfile::TempDir;
use trnm_consensus_peer_lease::{
    PayloadReplayDirectionV1, PayloadReplayErrorV1, PayloadReplayFrameV1, PayloadReplayNamespaceV1,
    PayloadReplayStoreV1,
};

const CHILD_WAL_ENV: &str = "TRNM_PAYLOAD_REPLAY_CHILD_WAL_V1";
const CHILD_EXPECT_LOCKED_ENV: &str = "TRNM_PAYLOAD_REPLAY_CHILD_EXPECT_LOCKED_V1";

fn namespace() -> PayloadReplayNamespaceV1 {
    PayloadReplayNamespaceV1::new([1; 32], 9, [2; 32], [3; 32], [4; 32]).unwrap()
}

fn frame(sequence: u64) -> PayloadReplayFrameV1 {
    let namespace = namespace();
    PayloadReplayFrameV1::new(
        namespace
            .scope_for([5; 32], PayloadReplayDirectionV1::Inbound)
            .unwrap(),
        namespace.run_id_hash(),
        namespace.network_context_hash(),
        [6; 32],
        1,
        sequence,
        2,
        32,
        [0x20 + sequence as u8; 32],
    )
    .unwrap()
}

fn private_tempdir() -> TempDir {
    let directory = TempDir::new().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    }
    directory
}

/// Invoked by the parent test through the integration-test executable. With
/// no environment marker it is a no-op, so ordinary harness discovery stays
/// deterministic.
#[test]
fn payload_replay_child_helper() {
    let Some(path) = env::var_os(CHILD_WAL_ENV) else {
        return;
    };
    let store = PayloadReplayStoreV1::open(path, namespace());
    if env::var_os(CHILD_EXPECT_LOCKED_ENV).is_some() {
        assert!(matches!(store, Err(PayloadReplayErrorV1::Io(_))));
        return;
    }
    let mut store = store.unwrap();
    store.admit(&frame(0)).unwrap();
}

#[test]
fn wal_reopens_across_process_and_excludes_a_second_owner() {
    let directory = private_tempdir();
    let path = directory.path().join("payload-replay.wal");
    let binary = env::current_exe().unwrap();
    let status = Command::new(&binary)
        .arg("--exact")
        .arg("payload_replay_child_helper")
        .arg("--nocapture")
        .env(CHILD_WAL_ENV, &path)
        .status()
        .unwrap();
    assert!(status.success(), "child process did not persist replay WAL");

    let mut parent = PayloadReplayStoreV1::open(&path, namespace()).unwrap();
    assert_eq!(parent.accepted_frame_count(), 1);
    assert!(matches!(
        parent.admit(&frame(0)),
        Err(PayloadReplayErrorV1::Replay)
    ));
    parent.admit(&frame(1)).unwrap();

    // The same child cannot open or mutate the namespace while the parent
    // retains the exclusive journal owner.
    let concurrent = Command::new(binary)
        .arg("--exact")
        .arg("payload_replay_child_helper")
        .env(CHILD_WAL_ENV, &path)
        .env(CHILD_EXPECT_LOCKED_ENV, "1")
        .status()
        .unwrap();
    assert!(concurrent.success(), "second process lock check failed");
}
