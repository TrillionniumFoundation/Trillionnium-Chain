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
                // No live conforming owner can hold this inode's lease. A fresh
                // or empty lease never authorizes removing a pre-existing socket.
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
        let restarted = SocketOwnerV1::bind(&path).unwrap();
        restarted.revalidate().unwrap();
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
