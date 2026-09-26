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

// Own every subprocess even when a new regression intentionally fails.
struct DaemonChildGuardV1(Child);
impl Drop for DaemonChildGuardV1 {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn daemon_disconnects_do_not_revoke_other_sessions_v1() {
    use std::{io::Write, net::Shutdown, os::unix::net::UnixStream};
    let directory = private_tempdir();
    let (child, socket, journal) = start_daemon(directory.path());
    let mut child = DaemonChildGuardV1(child);
    let client = UnixPeerLeaseClientV1::connect(&socket);
    let token = client.acquire(scope(), [0x91; 32], 1, 30_000).unwrap();
    let original = fs::read(&journal).unwrap();
    let mut partial = Vec::from(*b"TPLS");
    partial.extend_from_slice(&200u32.to_le_bytes());
    partial.resize(40, 0);
    for length in [0, 1, 7, 8, 40] {
        let mut abandoned = UnixStream::connect(&socket).unwrap();
        abandoned.write_all(&partial[..length]).unwrap();
        abandoned.shutdown(Shutdown::Both).unwrap();
        drop(abandoned);
        // A real subsequent request is the ordering barrier; no test sleep
        // or daemon restart conceals loss of the authority process.
        assert_eq!(client.revalidate(token).unwrap(), token, "prefix={length}");
        assert_eq!(fs::read(&journal).unwrap(), original);
        assert!(child.0.try_wait().unwrap().is_none());
    }
    client.release(token).unwrap();
    let successor = client.acquire(scope(), [0x92; 32], 2, 30_000).unwrap();
    assert!(matches!(
        client.revalidate(token),
        Err(PeerLeaseErrorV1::Rejected(LeaseRejectCodeV1::Fenced))
    ));
    assert_eq!(client.revalidate(successor).unwrap(), successor);
}

#[test]
fn daemon_anchor_io_failure_still_terminates_authority_v1() {
    let directory = private_tempdir();
    let (child, socket, _journal) = start_daemon(directory.path());
    let mut child = DaemonChildGuardV1(child);
    let client = UnixPeerLeaseClientV1::connect(&socket);
    let token = client.acquire(scope(), [0x93; 32], 1, 30_000).unwrap();
    // This test owns the entire temporary namespace. Force a real anchor
    // publication failure after journal append, not a simulated client error.
    let anchor = directory.path().join(".authority.log.head-v1");
    fs::remove_file(&anchor).unwrap();
    fs::create_dir(&anchor).unwrap();
    assert!(client.renew(token, 30_000).is_err());
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            assert!(!status.success());
            break;
        }
        assert!(
            Instant::now() < deadline,
            "authority continued after anchor I/O failure"
        );
        thread::sleep(Duration::from_millis(10));
    }
    assert!(client.revalidate(token).is_err());
}

#[test]
fn stalled_client_does_not_block_live_lease_operations_v1() {
    use std::{io::Write, os::unix::net::UnixStream};
    let directory = private_tempdir();
    let (child, socket, _) = start_daemon(directory.path());
    let mut child = DaemonChildGuardV1(child);
    // These connections precede the real client in the listen queue and
    // remain open. Neither an EOF nor the five-second daemon timeout helps.
    let mut partial_header = UnixStream::connect(&socket).unwrap();
    partial_header.write_all(b"TPL").unwrap();
    let mut partial_body = UnixStream::connect(&socket).unwrap();
    partial_body.write_all(b"TPLS").unwrap();
    partial_body.write_all(&200u32.to_le_bytes()).unwrap();
    partial_body.write_all(&[1, 2]).unwrap();
    let client = UnixPeerLeaseClientV1::connect(&socket).with_timeout(Duration::from_millis(750));
    let started = Instant::now();
    let token = client
        .acquire(scope(), [0xa1; 32], 1, 30_000)
        .expect("partial clients must not block unrelated lease admission");
    assert_eq!(client.revalidate(token).unwrap(), token);
    let renewed = client.renew(token, 30_000).unwrap();
    assert_eq!(client.revalidate(renewed).unwrap(), renewed);
    client.release(renewed).unwrap();
    assert!(started.elapsed() < Duration::from_secs(3));
    assert!(child.0.try_wait().unwrap().is_none());
    drop((partial_header, partial_body));
    let successor = client.acquire(scope(), [0xa2; 32], 2, 30_000).unwrap();
    assert_eq!(successor.generation(), 2);
    assert!(matches!(
        client.revalidate(renewed),
        Err(PeerLeaseErrorV1::Rejected(LeaseRejectCodeV1::Fenced))
    ));
}

#[test]
fn parallel_clients_retain_one_durable_scope_winner_v1() {
    let directory = private_tempdir();
    let (child, socket, _) = start_daemon(directory.path());
    let mut child = DaemonChildGuardV1(child);
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));
    let handles = (0..8)
        .map(|i| {
            let barrier = barrier.clone();
            let socket = socket.clone();
            thread::spawn(move || {
                let client = UnixPeerLeaseClientV1::connect(socket);
                barrier.wait();
                client.acquire(scope(), [0xb0 + i; 32], 1, 30_000)
            })
        })
        .collect::<Vec<_>>();
    let mut winner = None;
    for handle in handles {
        match handle.join().unwrap() {
            Ok(token) => assert!(winner.replace(token).is_none(), "multiple scope winners"),
            Err(error) => assert!(matches!(
                error,
                PeerLeaseErrorV1::Rejected(LeaseRejectCodeV1::AlreadyLeased)
            )),
        }
    }
    let winner = winner.expect("one durable admission");
    let client = UnixPeerLeaseClientV1::connect(&socket);
    assert_eq!(client.revalidate(winner).unwrap(), winner);
    child.0.kill().unwrap();
    child.0.wait().unwrap();
    let (restarted, socket, _) = start_daemon(directory.path());
    let _restarted = DaemonChildGuardV1(restarted);
    assert_eq!(
        UnixPeerLeaseClientV1::connect(socket)
            .revalidate(winner)
            .unwrap(),
        winner
    );
}

#[test]
fn stalled_connection_capacity_is_released_without_restarting_authority_v1() {
    use std::{io::Write, os::unix::net::UnixStream};
    let directory = private_tempdir();
    let (child, socket, journal) = start_daemon(directory.path());
    let mut child = DaemonChildGuardV1(child);
    let baseline = fs::read(&journal).unwrap();
    let mut connections = Vec::new();
    for _ in 0..64 {
        let mut stream = UnixStream::connect(&socket).unwrap();
        stream.write_all(b"T").unwrap();
        connections.push(stream);
    }
    let client = UnixPeerLeaseClientV1::connect(&socket).with_timeout(Duration::from_millis(150));
    assert!(client.acquire(scope(), [0xc1; 32], 1, 30_000).is_err());
    assert_eq!(fs::read(&journal).unwrap(), baseline);
    drop(connections);
    // The timed-out complete request might be accepted after capacity returns.
    // Exact retry must recover that same token rather than assuming rollback.
    let client = UnixPeerLeaseClientV1::connect(&socket);
    let token = client.acquire(scope(), [0xc1; 32], 1, 30_000).unwrap();
    assert_eq!(client.revalidate(token).unwrap(), token);
    assert!(child.0.try_wait().unwrap().is_none());
}
