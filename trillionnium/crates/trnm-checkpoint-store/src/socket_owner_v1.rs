//! A listener lease is local endpoint ownership, never a recovery freshness pin.
//!
//! Lock the socket name independently of the journal: two valid journals must
//! not silently replace each other's live listener. Retain the inode of the
//! socket we created, so a missing lease cannot bless a pre-existing listener.

use std::io::{Seek, SeekFrom};

use super::*;

const LEASE_MAGIC_V1: &[u8; 8] = b"TRNMCSL1";
const LEASE_BYTES_V1: usize = 8 + 8 + 8 + 4 + 4 + 8 + 8 + 8;

pub(super) struct SocketOwnerV1 {
    listener: UnixListener,
    socket_path: PathBuf,
    socket_identity: CheckpointPathIdentityV2,
    socket_record: Vec<u8>,
    parent_path: PathBuf,
    parent: File,
    parent_identity: CheckpointPathIdentityV2,
    lease_path: PathBuf,
    lease: File,
    lease_identity: CheckpointPathIdentityV2,
}

impl SocketOwnerV1 {
    pub(super) fn bind(path: &Path) -> Result<Self, ExternalCheckpointAuthorityErrorV2> {
        // This must precede every lease creation or socket unlink. In particular,
        // a rejected non-private directory must leave its listener untouched.
        let parent_path = prepare_socket_parent_v2(path)?;
        let parent = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&parent_path)?;
        let parent_identity = checkpoint_path_identity_from_file_v2(&parent)?;
        verify_checkpoint_path_identity_v2(&parent_path, parent_identity, true)?;
        let lease_path = sidecar_path_v2(path, "socket-owner-v1")?;
        let mut lease = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(&lease_path)?;
        validate_private_file_v2(&lease, "checkpoint socket lease")?;
        lease
            .try_lock_exclusive()
            .map_err(|source| ExternalCheckpointAuthorityErrorV2::Io {
                stage: "lock checkpoint socket owner",
                source,
            })?;
        let lease_identity = checkpoint_path_identity_from_file_v2(&lease)?;
        verify_checkpoint_path_identity_v2(&lease_path, lease_identity, false)?;
        let mut previous = Vec::with_capacity(LEASE_BYTES_V1 + 1);
        (&mut lease)
            .take((LEASE_BYTES_V1 + 1) as u64)
            .read_to_end(&mut previous)?;
        if !previous.is_empty()
            && (previous.len() != LEASE_BYTES_V1 || &previous[..8] != LEASE_MAGIC_V1)
        {
            return Err(ExternalCheckpointAuthorityErrorV2::InvalidConfig(
                "checkpoint socket lease record",
            ));
        }
        verify_checkpoint_path_identity_v2(&parent_path, parent_identity, true)?;
        verify_checkpoint_path_identity_v2(&lease_path, lease_identity, false)?;
        match fs::symlink_metadata(path) {
            Ok(metadata) => {
                if !valid_socket(&metadata) || previous != socket_record(&metadata) {
                    return Err(ExternalCheckpointAuthorityErrorV2::InvalidConfig(
                        "checkpoint socket is unleased or replaced",
                    ));
                }
                // Lock ownership is on the lease inode, not its pathname.
                // A copied record at a replacement inode can therefore pass
                // the lock and record checks while the original owner lives.
                // Never unlink a socket merely because the current lease inode
                // is unlocked: a reachable listener is still a live owner.
                //
                // Only an explicit connection refusal permits stale-socket
                // recovery. Busy, inaccessible and ambiguous probes fail
                // closed; none is evidence that the listener has exited.
                probe_stale_listener(path).map_err(|source| {
                    ExternalCheckpointAuthorityErrorV2::Io {
                        stage: "lock checkpoint socket owner",
                        source,
                    }
                })?;
                // A successful dead-listener probe is not an authority token:
                // recheck the exact socket object before removing its name.
                let current = fs::symlink_metadata(path)?;
                if !valid_socket(&current)
                    || !CheckpointPathIdentityV2::from_metadata(&current)
                        .same_object(CheckpointPathIdentityV2::from_metadata(&metadata))
                    || socket_record(&current) != previous
                {
                    return Err(ExternalCheckpointAuthorityErrorV2::InvalidConfig(
                        "checkpoint socket changed after liveness probe",
                    ));
                }
                fs::remove_file(path)?;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(source) => return Err(source.into()),
        }
        verify_checkpoint_path_identity_v2(&parent_path, parent_identity, true)?;
        verify_checkpoint_path_identity_v2(&lease_path, lease_identity, false)?;
        let listener =
            UnixListener::bind(path).map_err(|source| ExternalCheckpointAuthorityErrorV2::Io {
                stage: "bind checkpoint socket",
                source,
            })?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        let socket_metadata = fs::symlink_metadata(path)?;
        if !valid_socket(&socket_metadata) {
            return Err(ExternalCheckpointAuthorityErrorV2::InvalidConfig(
                "checkpoint socket shape",
            ));
        }
        let socket_identity = CheckpointPathIdentityV2::from_metadata(&socket_metadata);
        let owner = Self {
            listener,
            socket_path: path.to_path_buf(),
            socket_identity,
            socket_record: socket_record(&socket_metadata),
            parent_path,
            parent,
            parent_identity,
            lease_path,
            lease,
            lease_identity,
        };
        owner.revalidate_paths()?;
        let record = socket_record(&socket_metadata);
        // A torn lease record denies restart. It does not repair itself from
        // the socket it is supposed to authorize. Keep the locked inode stable.
        let mut lease_writer = &owner.lease;
        lease_writer.seek(SeekFrom::Start(0))?;
        lease_writer.write_all(&record)?;
        owner.lease.set_len(LEASE_BYTES_V1 as u64)?;
        owner.lease.sync_all()?;
        owner.parent.sync_all()?;
        owner.revalidate()?;
        Ok(owner)
    }

    pub(super) fn listener(&self) -> &UnixListener {
        &self.listener
    }

    pub(super) fn revalidate(&self) -> Result<(), ExternalCheckpointAuthorityErrorV2> {
        self.revalidate_paths()?;
        // Descriptor identity alone cannot detect an in-place lease rewind.
        // Compare the bounded record with this live owner's retained socket.
        let mut record = [0; LEASE_BYTES_V1];
        std::os::unix::fs::FileExt::read_exact_at(&self.lease, &mut record, 0).map_err(|_| {
            ExternalCheckpointAuthorityErrorV2::InvalidLog("checkpoint socket lease record changed")
        })?;
        if record.as_slice() != self.socket_record
            || self.lease.metadata()?.len() != LEASE_BYTES_V1 as u64
        {
            return Err(ExternalCheckpointAuthorityErrorV2::InvalidLog(
                "checkpoint socket lease record changed",
            ));
        }
        self.revalidate_paths()
    }

    fn revalidate_paths(&self) -> Result<(), ExternalCheckpointAuthorityErrorV2> {
        verify_checkpoint_path_identity_v2(&self.parent_path, self.parent_identity, true)?;
        verify_checkpoint_path_identity_v2(&self.lease_path, self.lease_identity, false)?;
        if !checkpoint_path_identity_from_file_v2(&self.parent)?.same_object(self.parent_identity)
            || !checkpoint_path_identity_from_file_v2(&self.lease)?.same_object(self.lease_identity)
        {
            return Err(ExternalCheckpointAuthorityErrorV2::InvalidLog(
                "checkpoint socket lease descriptor changed",
            ));
        }
        let metadata = fs::symlink_metadata(&self.socket_path).map_err(|_| {
            ExternalCheckpointAuthorityErrorV2::InvalidLog("checkpoint socket identity changed")
        })?;
        if !valid_socket(&metadata)
            || !CheckpointPathIdentityV2::from_metadata(&metadata).same_object(self.socket_identity)
            || socket_record(&metadata) != self.socket_record
        {
            return Err(ExternalCheckpointAuthorityErrorV2::InvalidLog(
                "checkpoint socket identity changed",
            ));
        }
        Ok(())
    }
}

fn valid_socket(metadata: &fs::Metadata) -> bool {
    metadata.file_type().is_socket() && metadata.mode() & 0o7777 == 0o600 && metadata.nlink() == 1
}

fn socket_record(metadata: &fs::Metadata) -> Vec<u8> {
    let mut record = Vec::with_capacity(LEASE_BYTES_V1);
    record.extend_from_slice(LEASE_MAGIC_V1);
    record.extend_from_slice(&metadata.dev().to_be_bytes());
    record.extend_from_slice(&metadata.ino().to_be_bytes());
    record.extend_from_slice(&metadata.uid().to_be_bytes());
    record.extend_from_slice(&(metadata.mode() & 0o7777).to_be_bytes());
    record.extend_from_slice(&metadata.nlink().to_be_bytes());
    // Include inode change time so inode-number reuse is not a stale-lease match.
    record.extend_from_slice(&metadata.ctime().to_be_bytes());
    record.extend_from_slice(&metadata.ctime_nsec().to_be_bytes());
    record
}

#[cfg(test)]
mod tests {

    // Insert into socket_owner_v1::tests. Deliberately not executed in a
    // sandbox that disallows AF_UNIX. Do not turn permission errors into skips.
    #[test]
    fn saturated_copied_lease_child_probe() {
        let Some(path) = std::env::var_os("TRNM_TEST_SATURATED_SOCKET") else {
            return; // Helper entry; parent test is the qualification selector.
        };
        match SocketOwnerV1::bind(Path::new(&path)) {
            Err(ExternalCheckpointAuthorityErrorV2::Io { stage, source }) => {
                assert_eq!(stage, "lock checkpoint socket owner");
                assert_eq!(source.kind(), io::ErrorKind::WouldBlock);
            }
            _ => panic!("saturated listener must refuse at the ownership probe"),
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn saturated_copied_lease_refuses_without_unlink_and_allows_dead_recovery() {
        use std::process::{Command, Stdio};
        use std::time::{Duration, Instant};
        struct KillOnDrop(std::process::Child);
        impl Drop for KillOnDrop {
            fn drop(&mut self) {
                if self.0.try_wait().ok().flatten().is_none() {
                    let _ = self.0.kill();
                }
                let _ = self.0.wait();
            }
        }
        let directory = private_directory();
        let path = directory.path().join("owner.sock");
        let owner = SocketOwnerV1::bind(&path).unwrap();
        // Lower backlog without accepting any connection or changing the inode.
        socket2::SockRef::from(owner.listener()).listen(0).unwrap();
        let address = socket2::SockAddr::unix(&path).unwrap();
        let mut queued = Vec::new();
        let mut saturated = false;
        for _ in 0..64 {
            let socket =
                socket2::Socket::new(socket2::Domain::UNIX, socket2::Type::STREAM, None).unwrap();
            socket.set_nonblocking(true).unwrap();
            match socket.connect(&address) {
                Ok(()) => queued.push(socket),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    saturated = true;
                    break;
                }
                Err(error) => panic!("fixture did not establish queue saturation: {error}"),
            }
        }
        assert!(saturated, "bounded fixture did not observe WouldBlock");
        let original = fs::symlink_metadata(&path).unwrap();
        let record = fs::read(&owner.lease_path).unwrap();
        let displaced = directory.path().join("retained-lease");
        fs::rename(&owner.lease_path, &displaced).unwrap();
        let mut replacement = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&owner.lease_path)
            .unwrap();
        replacement.write_all(&record).unwrap();
        replacement.sync_all().unwrap();
        drop(replacement);
        let capture_path = directory.path().join("child-output");
        let capture = File::create(&capture_path).unwrap();
        let mut child = KillOnDrop(
            Command::new(std::env::current_exe().unwrap())
                .args([
                    "socket_owner_v1::tests::saturated_copied_lease_child_probe",
                    "--exact",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env("TRNM_TEST_SATURATED_SOCKET", &path)
                .stdin(Stdio::null())
                .stdout(capture.try_clone().unwrap())
                .stderr(capture)
                .spawn()
                .unwrap(),
        );
        let deadline = Instant::now() + Duration::from_secs(5);
        let status = loop {
            if let Some(status) = child.0.try_wait().unwrap() {
                break status;
            }
            assert!(
                Instant::now() < deadline,
                "probe failed to return within test supervisor bound"
            );
            std::thread::sleep(Duration::from_millis(10));
        };
        let output = fs::read_to_string(capture_path).unwrap();
        assert!(status.success(), "child refused fixture: {output}");
        assert!(
            output.lines().any(|line| line
                == "test socket_owner_v1::tests::saturated_copied_lease_child_probe ... ok"),
            "missing exact child execution: {output}"
        );
        assert!(
            output.contains("1 passed; 0 failed; 0 ignored; 0 measured;"),
            "invalid child roster: {output}"
        );
        assert!(
            CheckpointPathIdentityV2::from_metadata(&original).same_object(
                CheckpointPathIdentityV2::from_metadata(&fs::symlink_metadata(&path).unwrap())
            )
        );
        assert_eq!(fs::read(&owner.lease_path).unwrap(), record);
        fs::remove_file(&owner.lease_path).unwrap();
        fs::rename(displaced, &owner.lease_path).unwrap();
        owner.revalidate().unwrap();
        drop(queued);
        drop(owner);
        SocketOwnerV1::bind(&path).unwrap().revalidate().unwrap();
    }

    use super::*;
    use tempfile::TempDir;

    fn private_directory() -> TempDir {
        let directory = TempDir::new().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        directory
    }

    #[test]
    fn endpoint_lease_prevents_live_socket_replacement_and_permits_owner_restart() {
        let directory = private_directory();
        let path = directory.path().join("owner.sock");
        let owner = SocketOwnerV1::bind(&path).unwrap();
        let original = fs::symlink_metadata(&path).unwrap().ino();
        assert!(SocketOwnerV1::bind(&path).is_err());
        assert_eq!(fs::symlink_metadata(&path).unwrap().ino(), original);
        owner.revalidate().unwrap();
        drop(owner);
        #[cfg(target_os = "linux")]
        {
            let restarted = SocketOwnerV1::bind(&path).unwrap();
            restarted.revalidate().unwrap();
        }
        #[cfg(not(target_os = "linux"))]
        {
            // Refusal cannot distinguish a dead owner from a full live queue
            // on these platforms; recovery must preserve the old endpoint.
            match SocketOwnerV1::bind(&path) {
                Err(ExternalCheckpointAuthorityErrorV2::Io { stage, source }) => {
                    assert_eq!(stage, "lock checkpoint socket owner");
                    assert_eq!(source.kind(), io::ErrorKind::Unsupported);
                }
                _ => panic!("unproven stale socket must not be replaced"),
            }
            assert_eq!(fs::symlink_metadata(&path).unwrap().ino(), original);
        }
    }

    #[test]
    fn fresh_lease_never_authorizes_removing_an_unleased_socket() {
        let directory = private_directory();
        let path = directory.path().join("unleased.sock");
        let listener = UnixListener::bind(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let original = fs::symlink_metadata(&path).unwrap().ino();
        for _ in 0..2 {
            assert!(SocketOwnerV1::bind(&path).is_err());
            assert_eq!(fs::symlink_metadata(&path).unwrap().ino(), original);
        }
        drop(listener);
    }

    #[test]
    fn rejected_socket_parent_preserves_existing_listener() {
        let directory = private_directory();
        let path = directory.path().join("existing.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let original = fs::symlink_metadata(&path).unwrap().ino();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o755)).unwrap();
        assert!(SocketOwnerV1::bind(&path).is_err());
        assert_eq!(fs::symlink_metadata(&path).unwrap().ino(), original);
        assert!(!sidecar_path_v2(&path, "socket-owner-v1").unwrap().exists());
        drop(listener);
    }

    #[test]
    fn live_owner_rejects_replaced_lease_path() {
        let directory = private_directory();
        let path = directory.path().join("owner.sock");
        let owner = SocketOwnerV1::bind(&path).unwrap();
        fs::rename(&owner.lease_path, directory.path().join("retained-lease")).unwrap();
        assert!(owner.revalidate().is_err());
        // A new process must not use a fresh lease to steal this live socket.
        assert!(SocketOwnerV1::bind(&path).is_err());
        drop(owner);
    }

    #[test]
    fn live_owner_rejects_replaced_socket_path() {
        let directory = private_directory();
        let path = directory.path().join("owner.sock");
        let owner = SocketOwnerV1::bind(&path).unwrap();
        fs::rename(&path, directory.path().join("retained.sock")).unwrap();
        let replacement = UnixListener::bind(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(owner.revalidate().is_err());
        drop(owner);
        // Even after the old owner exits, its lease identifies a different socket.
        assert!(SocketOwnerV1::bind(&path).is_err());
        drop(replacement);
    }

    #[test]
    fn live_owner_rejects_same_inode_lease_record_rewrite() {
        let directory = private_directory();
        let path = directory.path().join("owner.sock");
        let owner = SocketOwnerV1::bind(&path).unwrap();
        let original = fs::symlink_metadata(&owner.lease_path).unwrap().ino();
        fs::write(&owner.lease_path, [0; LEASE_BYTES_V1]).unwrap();
        assert_eq!(
            fs::symlink_metadata(&owner.lease_path).unwrap().ino(),
            original
        );
        assert!(owner.revalidate().is_err());
    }

    #[test]
    fn malformed_lease_is_refused_without_recreating_a_socket() {
        let directory = private_directory();
        let path = directory.path().join("owner.sock");
        let lease = sidecar_path_v2(&path, "socket-owner-v1").unwrap();
        fs::write(&lease, [0; LEASE_BYTES_V1]).unwrap();
        fs::set_permissions(&lease, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(matches!(
            SocketOwnerV1::bind(&path),
            Err(ExternalCheckpointAuthorityErrorV2::InvalidConfig(
                "checkpoint socket lease record"
            ))
        ));
        assert!(!path.exists());
        assert_eq!(fs::read(&lease).unwrap(), [0; LEASE_BYTES_V1]);
    }
}

// Linux only: an explicit refusal authorizes the caller's existing inode recheck.
// Success, in-progress, would-block and every ambiguous outcome refuse recovery.
#[cfg(target_os = "linux")]
fn require_refused_probe(result: std::io::Result<()>) -> std::io::Result<()> {
    match result {
        Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => Ok(()),
        Err(error) => Err(error),
        Ok(()) => Err(std::io::Error::new(
            std::io::ErrorKind::AddrInUse,
            "checkpoint socket listener is still live",
        )),
    }
}

#[cfg(target_os = "linux")]
fn probe_stale_listener(path: &std::path::Path) -> std::io::Result<()> {
    let address = socket2::SockAddr::unix(path)?;
    let socket = socket2::Socket::new(socket2::Domain::UNIX, socket2::Type::STREAM, None)?;
    socket.set_nonblocking(true)?;
    require_refused_probe(socket.connect(&address))
}

// On other Unix kernels a full live queue may also return ECONNREFUSED.
// Never infer death there, or perform an unbounded connection probe. This
// deliberately disables automatic stale-socket recovery on those platforms;
// a fresh absent endpoint still follows the existing initial bind path.
#[cfg(any(test, not(target_os = "linux")))]
fn unsupported_listener_probe(_path: &std::path::Path) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "safe stale checkpoint socket recovery is only supported on Linux",
    ))
}

#[cfg(not(target_os = "linux"))]
fn probe_stale_listener(path: &std::path::Path) -> std::io::Result<()> {
    unsupported_listener_probe(path)
}

#[cfg(test)]
mod unsupported_probe_tests {
    use super::*;

    #[test]
    fn other_unix_policy_never_probes_or_authorizes_replacement() {
        // No filesystem or socket access: even invalid paths yield the same
        // conservative rejection, rather than a connect or lookup result.
        for path in ["", "/nonexistent/checkpoint.sock", "contains\0nul"] {
            assert_eq!(
                unsupported_listener_probe(Path::new(path))
                    .unwrap_err()
                    .kind(),
                std::io::ErrorKind::Unsupported
            );
        }
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn platform_entrypoint_refuses_existing_endpoint_recovery() {
        assert_eq!(
            probe_stale_listener(Path::new("contains\0nul"))
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::Unsupported
        );
    }
}

#[cfg(all(test, target_os = "linux"))]
mod probe_policy_tests {
    use super::*;
    use std::io::{Error, ErrorKind};
    #[test]
    fn connected_listener_is_not_stale() {
        assert_eq!(
            require_refused_probe(Ok(())).unwrap_err().kind(),
            ErrorKind::AddrInUse
        );
    }
    #[test]
    fn explicit_refusal_is_only_recovery_case() {
        assert!(require_refused_probe(Err(Error::from(ErrorKind::ConnectionRefused))).is_ok());
    }
    #[test]
    fn every_other_error_stays_refused() {
        for kind in [
            ErrorKind::WouldBlock,
            ErrorKind::PermissionDenied,
            ErrorKind::Interrupted,
            ErrorKind::TimedOut,
            ErrorKind::NotFound,
            ErrorKind::ConnectionReset,
            ErrorKind::InvalidInput,
            ErrorKind::Other,
        ] {
            assert_eq!(
                require_refused_probe(Err(Error::from(kind)))
                    .unwrap_err()
                    .kind(),
                kind
            );
        }
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn linux_eagain_and_einprogress_are_not_dead_listener() {
        for errno in [11, 115] {
            assert_eq!(
                require_refused_probe(Err(Error::from_raw_os_error(errno)))
                    .unwrap_err()
                    .raw_os_error(),
                Some(errno)
            );
        }
    }
}
