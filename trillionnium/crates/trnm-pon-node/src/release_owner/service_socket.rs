//! The public socket sits outside private service storage. Only the protected
//! owner UID plus an independently pinned PQ writer can request an operation.
use super::frontier::{invalid, Result};
use super::service_configuration::Configuration;
use std::fs::{self, File};
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{SocketAddr, UnixListener, UnixStream};
use std::path::PathBuf;

pub(super) struct Socket {
    listener: UnixListener,
    parent: File,
    path: PathBuf,
    device: u64,
    inode: u64,
    uid: u32,
}
impl Socket {
    pub fn bind(configuration: &Configuration) -> Result<Self> {
        configuration.revalidate()?;
        let path = &configuration.socket;
        let parent = path
            .parent()
            .ok_or_else(|| invalid("M15 service socket parent"))?;
        if !path.is_absolute() || parent.canonicalize()? != parent || path.file_name().is_none() {
            return Err(invalid("M15 service socket canonical path"));
        }
        let held = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(parent)?;
        let meta = held.metadata()?;
        if !meta.is_dir() || meta.uid() != configuration.service_uid || meta.mode() & 0o7022 != 0 {
            return Err(invalid("M15 service socket parent ownership/mode"));
        }
        // Existing names, including stale sockets, are not silently removed.
        let listener = UnixListener::bind(path)?;
        let meta = fs::symlink_metadata(path)?;
        if !meta.file_type().is_socket()
            || meta.uid() != configuration.service_uid
            || meta.nlink() != 1
        {
            return Err(invalid("M15 service bound socket identity"));
        }
        fs::set_permissions(path, fs::Permissions::from_mode(0o666))?;
        held.sync_all()?;
        let socket = Self {
            listener,
            parent: held,
            path: path.clone(),
            device: meta.dev(),
            inode: meta.ino(),
            uid: configuration.service_uid,
        };
        socket.revalidate()?;
        Ok(socket)
    }
    pub fn revalidate(&self) -> Result<()> {
        let parent = self
            .path
            .parent()
            .ok_or_else(|| invalid("M15 socket parent"))?;
        let named_parent = fs::symlink_metadata(parent)?;
        let held = self.parent.metadata()?;
        let named = fs::symlink_metadata(&self.path)?;
        if !named_parent.is_dir()
            || named_parent.dev() != held.dev()
            || named_parent.ino() != held.ino()
            || named_parent.uid() != self.uid
            || named_parent.mode() & 0o7022 != 0
            || !named.file_type().is_socket()
            || named.dev() != self.device
            || named.ino() != self.inode
            || named.uid() != self.uid
            || named.nlink() != 1
            || named.mode() & 0o7777 != 0o666
        {
            return Err(invalid("M15 service named socket/parent changed"));
        }
        Ok(())
    }
    pub fn accept(&self) -> Result<(UnixStream, SocketAddr)> {
        self.revalidate()?;
        let accepted = self.listener.accept()?;
        self.revalidate()?;
        Ok(accepted)
    }
}
// Stale socket cleanup is an explicit protected provisioning action. This owner
// never unlinks a pathname during error/drop and cannot erase a replacement.
