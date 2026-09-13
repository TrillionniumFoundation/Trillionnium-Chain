#![cfg(unix)]
#![allow(clippy::zombie_processes)]

use std::{
    fs,
    os::unix::fs::FileTypeExt,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Child, Command},
    thread,
    time::{Duration, Instant},
};

use trnm_consensus_peer_lease::{
    ExternalPeerLeaseAuthorityV1, LeaseRejectCodeV1, PeerLeaseDirectionV1, PeerLeaseErrorV1,
    PeerLeaseScopeV1, UnixPeerLeaseClientV1,
};

fn scope() -> PeerLeaseScopeV1 {
    PeerLeaseScopeV1::new(
        [0x11; 32],
        [0x22; 32],
        PeerLeaseDirectionV1::Outbound,
        8,
        [0x33; 32],
    )
    .unwrap()
}

fn daemon_command(socket: &Path, journal: &Path, ready: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_trnm-peer-lease-daemon"));
    command
        .arg("--socket")
        .arg(socket)
        .arg("--journal")
        .arg(journal)
        .arg("--ready-file")
        .arg(ready);
    command
}

fn start_daemon(directory: &Path) -> (Child, PathBuf, PathBuf) {
    let socket = directory.join("authority.sock");
    let journal = directory.join("authority.log");
    let ready = directory.join("authority.ready");
    let _ = fs::remove_file(&socket);
    let _ = fs::remove_file(&ready);
    let child = daemon_command(&socket, &journal, &ready).spawn().unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if ready.exists() && socket.exists() {
            let metadata = fs::symlink_metadata(&socket).unwrap();
            assert!(metadata.file_type().is_socket());
            return (child, socket, journal);
        }
        thread::sleep(Duration::from_millis(10));
    }
    panic!("peer lease daemon did not become ready");
}

fn private_tempdir() -> tempfile::TempDir {
    let directory = tempfile::tempdir().unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    directory
}

fn stop_daemon(mut child: Child) {
    let _ = child.kill();
    let _ = child.wait();
}

fn wait_for_exit(mut child: Child) -> std::process::ExitStatus {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            panic!("peer lease daemon did not exit after corrupt journal");
        }
        thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn separate_daemon_process_survives_restart_and_fences_old_generation() {
    let directory = private_tempdir();
    let (child, socket, journal) = start_daemon(directory.path());
    let client = UnixPeerLeaseClientV1::connect(&socket);
    client.preflight().unwrap();
    let first = client.acquire(scope(), [0x44; 32], 1, 1_000).unwrap();
    assert_eq!(first.generation(), 1);
    let renewed = client.renew(first, 5_000).unwrap();
    assert!(renewed.expires_at_ms() > first.expires_at_ms());
    assert_eq!(client.revalidate(renewed).unwrap(), renewed);
    stop_daemon(child);

    // A fresh daemon process replays the same hash chain and retains the
    // active token.  No client-side memory is involved in this check.
    let (child, socket, _) = start_daemon(directory.path());
    let restarted = UnixPeerLeaseClientV1::connect(&socket);
    assert_eq!(restarted.revalidate(renewed).unwrap(), renewed);
    stop_daemon(child);

    // Let the lease expire, restart again, then commission generation 2.
    thread::sleep(Duration::from_millis(5_100));
    let (child, socket, _) = start_daemon(directory.path());
    let restarted = UnixPeerLeaseClientV1::connect(&socket);
    assert!(matches!(
        restarted.release(renewed),
        Err(PeerLeaseErrorV1::Rejected(LeaseRejectCodeV1::LeaseExpired))
    ));
    let second = restarted.acquire(scope(), [0x55; 32], 2, 1_000).unwrap();
    assert_eq!(second.generation(), 2);
    assert!(matches!(
        restarted.revalidate(renewed),
        Err(PeerLeaseErrorV1::Rejected(LeaseRejectCodeV1::Fenced))
    ));
    assert!(journal.exists());
    stop_daemon(child);
}

#[test]
fn separate_daemon_process_refuses_tampered_and_partial_journals() {
    let directory = private_tempdir();
    let (child, socket, journal) = start_daemon(directory.path());
    UnixPeerLeaseClientV1::connect(&socket)
        .acquire(scope(), [0x77; 32], 1, 1_000)
        .unwrap();
    stop_daemon(child);
    let mut bytes = fs::read(&journal).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0x80;
    fs::write(&journal, bytes).unwrap();
    let tamper_ready = directory.path().join("tamper.ready");
    let tampered = daemon_command(
        &directory.path().join("tamper.sock"),
        &journal,
        &tamper_ready,
    )
    .spawn()
    .unwrap();
    assert!(!wait_for_exit(tampered).success());
    assert!(!tamper_ready.exists());

    // Build a valid second journal, then remove its complete final record.
    // Startup must fail closed instead of silently replaying a valid prefix;
    // the independent head anchor supplies the missing evidence a bare hash
    // chain cannot provide.
    let partial_dir = private_tempdir();
    let (child, _socket, partial_journal) = start_daemon(partial_dir.path());
    let client = UnixPeerLeaseClientV1::connect(partial_dir.path().join("authority.sock"));
    client.acquire(scope(), [0x66; 32], 1, 1_000).unwrap();
    stop_daemon(child);
    let complete = fs::read(&partial_journal).unwrap();
    fs::write(&partial_journal, &complete[..0]).unwrap();
    let rollback_ready = partial_dir.path().join("rollback.ready");
    let rollback_child = daemon_command(
        &partial_dir.path().join("rollback.sock"),
        &partial_journal,
        &rollback_ready,
    )
    .spawn()
    .unwrap();
    assert!(!wait_for_exit(rollback_child).success());
    assert!(!rollback_ready.exists());

    // Restore the complete journal and exercise a genuine partial tail too.
    fs::write(&partial_journal, complete).unwrap();
    let mut partial = fs::read(&partial_journal).unwrap();
    partial.truncate(partial.len() - 2);
    fs::write(&partial_journal, partial).unwrap();
    let partial_ready = partial_dir.path().join("partial.ready");
    let partial_child = daemon_command(
        &partial_dir.path().join("partial.sock"),
        &partial_journal,
        &partial_ready,
    )
    .spawn()
    .unwrap();
    assert!(!wait_for_exit(partial_child).success());
    assert!(!partial_ready.exists());
}
