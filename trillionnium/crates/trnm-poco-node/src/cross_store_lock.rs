//! Advisory authority lock for the native application `P` and validation `K`
//! namespaces.
//!
//! The two SQLite files intentionally remain separate databases.  SQLite can
//! therefore not provide an atomic transaction spanning them.  This module
//! supplies the missing *cooperating-owner* fence: every native P/K writer
//! must take an exclusive lock on their canonical authority root, while a
//! recovery audit takes a shared lock for its complete paired read.  The lock
//! is held on the root directory itself, so no replaceable lock pathname is
//! trusted; the descriptor and canonical pathname identity are checked again
//! before the guard is released.
//!
//! This is an advisory lock.  A process which writes either database without
//! taking this authority lock is outside the contract and recovery remains
//! fail-closed when its mutation is observed.  It is not a distributed lock,
//! an fsync/rollback proof, or a production activation boundary.

use std::{
    fmt, fs,
    fs::File,
    io,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
};

use fs2::FileExt;

const PRIVATE_DIRECTORY_MODE_V0: u32 = 0o700;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CrossStoreFileIdentityV0 {
    device: u64,
    inode: u64,
    owner: u32,
    mode: u32,
    links: u64,
}

impl CrossStoreFileIdentityV0 {
    fn from_metadata(metadata: &fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            owner: metadata.uid(),
            mode: metadata.mode() & 0o777,
            links: metadata.nlink(),
        }
    }
}

#[derive(Debug)]
pub(crate) enum CrossStoreLockErrorV0 {
    InvalidPath(&'static str),
    Io(&'static str, io::Error),
    Busy,
    RootIdentityChanged,
}

impl fmt::Display for CrossStoreLockErrorV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPath(detail) => {
                write!(formatter, "invalid cross-store lock path: {detail}")
            }
            Self::Io(stage, error) => write!(formatter, "cross-store lock {stage}: {error}"),
            Self::Busy => {
                formatter.write_str("cross-store authority lock is held by another owner")
            }
            Self::RootIdentityChanged => {
                formatter.write_str("cross-store authority root identity changed")
            }
        }
    }
}

impl std::error::Error for CrossStoreLockErrorV0 {}

/// One held shared or exclusive lock on a canonical authority root.
///
/// The guard is intentionally not cloneable.  Dropping it releases the
/// advisory OS lock; callers should invoke [`Self::validate_identity_v0`] at
/// the end of an audit/write window and treat an error as a poisoned cut.
pub(crate) struct CrossStoreLockGuardV0 {
    root_path: PathBuf,
    root_file: File,
    root_identity: CrossStoreFileIdentityV0,
}

impl fmt::Debug for CrossStoreLockGuardV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CrossStoreLockGuardV0")
            .field("root_path", &self.root_path)
            .field("root_identity", &self.root_identity)
            .finish_non_exhaustive()
    }
}

impl CrossStoreLockGuardV0 {
    /// Acquire a shared lock after resolving the common authority root of the
    /// application and validation namespaces.
    #[allow(dead_code)] // used by the lab recovery paired-reader boundary
    pub(crate) fn acquire_shared_for_paths_v0(
        application_path: &Path,
        validation_path: &Path,
    ) -> Result<Self, CrossStoreLockErrorV0> {
        let root = common_authority_root_v0(application_path, validation_path)?;
        Self::acquire_shared_for_root_v0(&root)
    }

    /// Acquire an exclusive lock for a writer whose caller already owns the
    /// canonical authority-root path.
    pub(crate) fn acquire_exclusive_for_root_v0(
        root: &Path,
    ) -> Result<Self, CrossStoreLockErrorV0> {
        Self::acquire_for_root_v0(root, false)
    }

    /// Acquire a shared lock for a complete paired read.
    #[allow(dead_code)] // used by lab recovery and lock adversarial tests
    pub(crate) fn acquire_shared_for_root_v0(root: &Path) -> Result<Self, CrossStoreLockErrorV0> {
        Self::acquire_for_root_v0(root, true)
    }

    /// Recheck descriptor-bound and pathname-bound root identity.
    pub(crate) fn validate_identity_v0(&self) -> Result<(), CrossStoreLockErrorV0> {
        let descriptor = self
            .root_file
            .metadata()
            .map_err(|error| CrossStoreLockErrorV0::Io("stat locked root descriptor", error))?;
        let path = fs::symlink_metadata(&self.root_path)
            .map_err(|error| CrossStoreLockErrorV0::Io("stat locked root path", error))?;
        if descriptor.file_type().is_symlink()
            || path.file_type().is_symlink()
            || !descriptor.is_dir()
            || !path.is_dir()
            || descriptor.permissions().mode() & 0o777 != PRIVATE_DIRECTORY_MODE_V0
            || path.permissions().mode() & 0o777 != PRIVATE_DIRECTORY_MODE_V0
            || CrossStoreFileIdentityV0::from_metadata(&descriptor) != self.root_identity
            || CrossStoreFileIdentityV0::from_metadata(&path) != self.root_identity
            || fs::canonicalize(&self.root_path).map_err(|error| {
                CrossStoreLockErrorV0::Io("canonicalize locked root path", error)
            })? != self.root_path
        {
            return Err(CrossStoreLockErrorV0::RootIdentityChanged);
        }
        Ok(())
    }

    fn acquire_for_root_v0(root: &Path, shared: bool) -> Result<Self, CrossStoreLockErrorV0> {
        if !root.is_absolute() || root.file_name().is_none() {
            return Err(CrossStoreLockErrorV0::InvalidPath(
                "authority root must be absolute",
            ));
        }
        let root = fs::canonicalize(root)
            .map_err(|error| CrossStoreLockErrorV0::Io("canonicalize authority root", error))?;
        let path_metadata = fs::symlink_metadata(&root)
            .map_err(|error| CrossStoreLockErrorV0::Io("stat authority root", error))?;
        if path_metadata.file_type().is_symlink()
            || !path_metadata.is_dir()
            || path_metadata.permissions().mode() & 0o777 != PRIVATE_DIRECTORY_MODE_V0
        {
            return Err(CrossStoreLockErrorV0::InvalidPath(
                "authority root must be one canonical private directory",
            ));
        }
        let root_file = File::open(&root)
            .map_err(|error| CrossStoreLockErrorV0::Io("open authority root", error))?;
        let descriptor_metadata = root_file
            .metadata()
            .map_err(|error| CrossStoreLockErrorV0::Io("stat authority root descriptor", error))?;
        let identity = CrossStoreFileIdentityV0::from_metadata(&path_metadata);
        if CrossStoreFileIdentityV0::from_metadata(&descriptor_metadata) != identity {
            return Err(CrossStoreLockErrorV0::RootIdentityChanged);
        }
        let lock_result = if shared {
            FileExt::try_lock_shared(&root_file)
        } else {
            FileExt::try_lock_exclusive(&root_file)
        };
        if let Err(error) = lock_result {
            if matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::PermissionDenied
            ) {
                return Err(CrossStoreLockErrorV0::Busy);
            }
            return Err(CrossStoreLockErrorV0::Io(
                "acquire authority root lock",
                error,
            ));
        }
        let guard = Self {
            root_path: root,
            root_file,
            root_identity: identity,
        };
        if let Err(error) = guard.validate_identity_v0() {
            // Do not leave a lock held when admission fails during the
            // descriptor/path identity fence.
            let _ = FileExt::unlock(&guard.root_file);
            return Err(error);
        }
        Ok(guard)
    }
}

impl Drop for CrossStoreLockGuardV0 {
    fn drop(&mut self) {
        let _ = FileExt::unlock(&self.root_file);
    }
}

#[allow(dead_code)] // only the lab recovery paired-reader boundary needs path joining
fn common_authority_root_v0(
    application_path: &Path,
    validation_path: &Path,
) -> Result<PathBuf, CrossStoreLockErrorV0> {
    let application_parent = canonical_parent_v0(application_path, "application")?;
    let validation_parent = canonical_parent_v0(validation_path, "validation")?;
    let root = if application_parent == validation_parent {
        application_parent
    } else {
        let application_root =
            application_parent
                .parent()
                .ok_or(CrossStoreLockErrorV0::InvalidPath(
                    "application namespace has no authority root",
                ))?;
        let validation_root =
            validation_parent
                .parent()
                .ok_or(CrossStoreLockErrorV0::InvalidPath(
                    "validation namespace has no authority root",
                ))?;
        if application_root != validation_root {
            return Err(CrossStoreLockErrorV0::InvalidPath(
                "application and validation namespaces do not share one authority root",
            ));
        }
        application_root.to_path_buf()
    };
    Ok(root)
}

#[allow(dead_code)] // called by the lab-only paired-reader path resolver
fn canonical_parent_v0(path: &Path, label: &'static str) -> Result<PathBuf, CrossStoreLockErrorV0> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or(CrossStoreLockErrorV0::InvalidPath(label))?;
    fs::canonicalize(parent)
        .map_err(|error| CrossStoreLockErrorV0::Io("canonicalize store namespace", error))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::TempDir;

    fn private_root() -> (TempDir, PathBuf, PathBuf) {
        let root = tempfile::tempdir().expect("temp root");
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))
            .expect("private root");
        let application = root.path().join("application");
        let validation = root.path().join("validation");
        std::fs::create_dir(&application).expect("application namespace");
        std::fs::create_dir(&validation).expect("validation namespace");
        (
            root,
            application.join("application.sqlite3"),
            validation.join("validation.sqlite3"),
        )
    }

    #[test]
    fn shared_lock_binds_descriptor_and_path_identity() {
        let (root, application, validation) = private_root();
        let guard = CrossStoreLockGuardV0::acquire_shared_for_paths_v0(&application, &validation)
            .expect("shared authority lock");
        let moved = root.path().with_extension("moved");
        std::fs::rename(root.path(), &moved).expect("rename old root");
        std::fs::create_dir(root.path()).expect("recreate root pathname");
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))
            .expect("recreated root permissions");
        assert!(matches!(
            guard.validate_identity_v0(),
            Err(CrossStoreLockErrorV0::RootIdentityChanged)
        ));
    }

    #[test]
    fn mismatched_namespace_roots_fail_closed() {
        let (left, application, _) = private_root();
        let (right, _, validation) = private_root();
        let error = CrossStoreLockGuardV0::acquire_shared_for_paths_v0(&application, &validation)
            .expect_err("different roots must not share an audit lock");
        assert!(matches!(error, CrossStoreLockErrorV0::InvalidPath(_)));
        drop((left, right));
    }

    #[test]
    fn shared_and_exclusive_owners_are_mutually_exclusive() {
        let (root, _, _) = private_root();

        let exclusive = CrossStoreLockGuardV0::acquire_exclusive_for_root_v0(root.path())
            .expect("exclusive authority lock");
        assert!(matches!(
            CrossStoreLockGuardV0::acquire_shared_for_root_v0(root.path()),
            Err(CrossStoreLockErrorV0::Busy)
        ));
        assert!(matches!(
            CrossStoreLockGuardV0::acquire_exclusive_for_root_v0(root.path()),
            Err(CrossStoreLockErrorV0::Busy)
        ));
        drop(exclusive);

        let shared = CrossStoreLockGuardV0::acquire_shared_for_root_v0(root.path())
            .expect("shared authority lock");
        let second_shared = CrossStoreLockGuardV0::acquire_shared_for_root_v0(root.path())
            .expect("shared locks may coexist");
        assert!(matches!(
            CrossStoreLockGuardV0::acquire_exclusive_for_root_v0(root.path()),
            Err(CrossStoreLockErrorV0::Busy)
        ));
        drop((second_shared, shared));
    }
}
