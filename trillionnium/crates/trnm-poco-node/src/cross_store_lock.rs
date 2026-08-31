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
    fs::{File, OpenOptions},
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
    ChildIdentityChanged,
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
            Self::ChildIdentityChanged => {
                formatter.write_str("cross-store child store identity changed")
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
    /// Descriptors for concrete P/K database files when a split-store writer
    /// binds them explicitly. Keeping these descriptors alive closes the
    /// pathname-to-inode gap a root-directory flock alone cannot cover.
    bound_store_files: Vec<CrossStoreBoundStoreV0>,
}

struct CrossStoreBoundStoreV0 {
    path: PathBuf,
    file: File,
    identity: CrossStoreFileIdentityV0,
}

impl fmt::Debug for CrossStoreBoundStoreV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CrossStoreBoundStoreV0")
            .field("path", &self.path)
            .field("identity", &self.identity)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for CrossStoreLockGuardV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CrossStoreLockGuardV0")
            .field("root_path", &self.root_path)
            .field("root_identity", &self.root_identity)
            .field("bound_store_files", &self.bound_store_files)
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
        let mut guard = Self::acquire_shared_for_root_v0(&root)?;
        bind_materialized_store_files_v0(&mut guard, application_path, validation_path)?;
        Ok(guard)
    }

    /// Acquire an exclusive lock after resolving the common authority root of
    /// the application and validation namespaces.
    ///
    /// Recovery/replay callers generally have the two canonical store paths,
    /// rather than a separately carried root capability.  Keeping root
    /// resolution in this module makes those callers use exactly the same
    /// canonical-path, namespace-separation and descriptor identity fence as
    /// the paired reader.
    #[allow(dead_code)] // used by the feature-gated process-2 replay owner
    pub(crate) fn acquire_exclusive_for_paths_v0(
        application_path: &Path,
        validation_path: &Path,
    ) -> Result<Self, CrossStoreLockErrorV0> {
        let root = common_authority_root_v0(application_path, validation_path)?;
        let mut guard = Self::acquire_exclusive_for_root_v0(&root)?;
        bind_materialized_store_files_v0(&mut guard, application_path, validation_path)?;
        Ok(guard)
    }

    /// Acquire the exclusive authority lock for a bootstrap writer which has
    /// only one store path so far.  Fresh P genesis/H1 installation happens
    /// before the K namespace is materialized, but it must still exclude a
    /// cooperating owner from replacing the common authority root.  The
    /// canonical `namespace/filename` layout is checked by deriving the root
    /// from the store's parent namespace; callers must not use this helper for
    /// an already split P/K operation (use [`Self::acquire_exclusive_for_paths_v0`]
    /// there so both paths are checked).
    pub(crate) fn acquire_exclusive_for_store_path_v0(
        store_path: &Path,
    ) -> Result<Self, CrossStoreLockErrorV0> {
        let root = authority_root_for_store_path_v0(store_path)?;
        Self::acquire_exclusive_for_root_v0(&root)
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

    /// Recheck descriptor-bound and pathname-bound root identity, plus any
    /// concrete P/K descriptors pinned by [`Self::bind_store_files_v0`].
    pub(crate) fn validate_identity_v0(&self) -> Result<(), CrossStoreLockErrorV0> {
        self.validate_root_identity_v0()?;
        for store in &self.bound_store_files {
            validate_bound_store_v0(store, &self.root_path)?;
        }
        Ok(())
    }

    /// Pin the concrete P and K database files to open descriptors for the
    /// remainder of this lock window. The caller must invoke this after both
    /// SQLite files exist; bootstrap paths which create the second namespace
    /// intentionally use the root-only helper until that file is materialized.
    ///
    /// Binding is strict: paths must be direct children of two distinct
    /// namespaces below this authority root, regular non-symlink files, and
    /// owned by the same uid as the private root. Every later identity check
    /// validates both the held descriptors and their canonical pathnames.
    #[allow(dead_code)] // deployed lab finalization/recovery feature only
    pub(crate) fn bind_store_files_v0(
        &mut self,
        application_path: &Path,
        validation_path: &Path,
    ) -> Result<(), CrossStoreLockErrorV0> {
        self.validate_root_identity_v0()?;
        let application = open_bound_store_v0(
            &self.root_path,
            self.root_identity.owner,
            application_path,
            "application",
        )?;
        let validation = open_bound_store_v0(
            &self.root_path,
            self.root_identity.owner,
            validation_path,
            "validation",
        )?;
        if application.path == validation.path {
            return Err(CrossStoreLockErrorV0::InvalidPath(
                "application and validation stores must be distinct",
            ));
        }
        self.bound_store_files = vec![application, validation];
        if let Err(error) = self.validate_identity_v0() {
            self.bound_store_files.clear();
            return Err(error);
        }
        Ok(())
    }

    fn validate_root_identity_v0(&self) -> Result<(), CrossStoreLockErrorV0> {
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
            bound_store_files: Vec::new(),
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
pub(crate) fn common_authority_root_v0(
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

/// Resolve the authority root for one canonical `root/namespace/store` path.
/// The root is intentionally not accepted from an untrusted basename: it is
/// derived from the canonical namespace parent and the lock acquisition then
/// applies the private-directory and descriptor/path identity fence.
pub(crate) fn authority_root_for_store_path_v0(
    store_path: &Path,
) -> Result<PathBuf, CrossStoreLockErrorV0> {
    let namespace = canonical_parent_v0(store_path, "store")?;
    namespace
        .parent()
        .map(Path::to_path_buf)
        .ok_or(CrossStoreLockErrorV0::InvalidPath(
            "store namespace has no authority root",
        ))
}

#[allow(dead_code)] // reached through the feature-gated lab owner
fn bind_materialized_store_files_v0(
    guard: &mut CrossStoreLockGuardV0,
    application_path: &Path,
    validation_path: &Path,
) -> Result<(), CrossStoreLockErrorV0> {
    // Fresh P genesis and H1 takeover call the paired-root resolver before K
    // exists. Preserve that bootstrap cut, but once both concrete files are
    // present every paired lock automatically upgrades to descriptor binding.
    let application_exists = match fs::symlink_metadata(application_path) {
        Ok(_) => true,
        Err(error) if error.kind() == io::ErrorKind::NotFound => false,
        Err(error) => return Err(CrossStoreLockErrorV0::Io("stat application store", error)),
    };
    let validation_exists = match fs::symlink_metadata(validation_path) {
        Ok(_) => true,
        Err(error) if error.kind() == io::ErrorKind::NotFound => false,
        Err(error) => return Err(CrossStoreLockErrorV0::Io("stat validation store", error)),
    };
    if application_exists && validation_exists {
        guard.bind_store_files_v0(application_path, validation_path)?;
    }
    Ok(())
}

fn open_bound_store_v0(
    root: &Path,
    root_owner: u32,
    store_path: &Path,
    label: &'static str,
) -> Result<CrossStoreBoundStoreV0, CrossStoreLockErrorV0> {
    if !store_path.is_absolute() || store_path.file_name().is_none() {
        return Err(CrossStoreLockErrorV0::InvalidPath(label));
    }
    let parent = store_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or(CrossStoreLockErrorV0::InvalidPath(label))?;
    let canonical_parent = fs::canonicalize(parent)
        .map_err(|error| CrossStoreLockErrorV0::Io("canonicalize child namespace", error))?;
    // A bound child must be exactly root/<namespace>/<file>; allowing a
    // deeper or unrelated path would make the root lock unrelated to the
    // descriptor being authenticated.
    if canonical_parent.parent() != Some(root) {
        return Err(CrossStoreLockErrorV0::InvalidPath(
            "child store namespace is outside authority root",
        ));
    }
    let path_metadata = fs::symlink_metadata(store_path).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            CrossStoreLockErrorV0::InvalidPath("child store does not exist")
        } else {
            CrossStoreLockErrorV0::Io("stat child store path", error)
        }
    })?;
    if path_metadata.file_type().is_symlink() || !path_metadata.is_file() {
        return Err(CrossStoreLockErrorV0::InvalidPath(
            "child store must be a regular non-symlink file",
        ));
    }
    let canonical_path = fs::canonicalize(store_path)
        .map_err(|error| CrossStoreLockErrorV0::Io("canonicalize child store", error))?;
    if canonical_path.parent() != Some(canonical_parent.as_path())
        || canonical_path.file_name() != store_path.file_name()
        || canonical_path != store_path
    {
        return Err(CrossStoreLockErrorV0::InvalidPath(
            "child store pathname is not canonical",
        ));
    }
    let identity = CrossStoreFileIdentityV0::from_metadata(&path_metadata);
    // The root is private, but an other-writable child would still let an
    // uncooperating same-host writer modify the database. Group-write bits are
    // tolerated for existing deployments whose umask is 0002; the enclosing
    // 0700 root keeps that group from reaching the file by pathname. Reject
    // only the externally reachable writable shape at this boundary and pin
    // all remaining metadata in the descriptor.
    if identity.links != 1 || identity.owner != root_owner || identity.mode & 0o002 != 0 {
        return Err(CrossStoreLockErrorV0::InvalidPath(
            "child store ownership or permissions are unsafe",
        ));
    }
    let file = OpenOptions::new()
        .read(true)
        .open(&canonical_path)
        .map_err(|error| CrossStoreLockErrorV0::Io("open child store descriptor", error))?;
    let descriptor = file
        .metadata()
        .map_err(|error| CrossStoreLockErrorV0::Io("stat child store descriptor", error))?;
    let descriptor_identity = CrossStoreFileIdentityV0::from_metadata(&descriptor);
    if descriptor.file_type().is_symlink()
        || !descriptor.is_file()
        || descriptor_identity != identity
    {
        return Err(CrossStoreLockErrorV0::ChildIdentityChanged);
    }
    let path_after = fs::symlink_metadata(&canonical_path)
        .map_err(|_| CrossStoreLockErrorV0::ChildIdentityChanged)?;
    if path_after.file_type().is_symlink()
        || !path_after.is_file()
        || CrossStoreFileIdentityV0::from_metadata(&path_after) != identity
    {
        return Err(CrossStoreLockErrorV0::ChildIdentityChanged);
    }
    Ok(CrossStoreBoundStoreV0 {
        path: canonical_path,
        file,
        identity,
    })
}

#[allow(dead_code)] // reached through the feature-gated lab owner
fn validate_bound_store_v0(
    store: &CrossStoreBoundStoreV0,
    root: &Path,
) -> Result<(), CrossStoreLockErrorV0> {
    let descriptor = store
        .file
        .metadata()
        .map_err(|_| CrossStoreLockErrorV0::ChildIdentityChanged)?;
    let path = fs::symlink_metadata(&store.path)
        .map_err(|_| CrossStoreLockErrorV0::ChildIdentityChanged)?;
    let canonical =
        fs::canonicalize(&store.path).map_err(|_| CrossStoreLockErrorV0::ChildIdentityChanged)?;
    if descriptor.file_type().is_symlink()
        || path.file_type().is_symlink()
        || !descriptor.is_file()
        || !path.is_file()
        || CrossStoreFileIdentityV0::from_metadata(&descriptor) != store.identity
        || CrossStoreFileIdentityV0::from_metadata(&path) != store.identity
        || canonical != store.path
        || canonical.parent().and_then(Path::parent) != Some(root)
    {
        return Err(CrossStoreLockErrorV0::ChildIdentityChanged);
    }
    Ok(())
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

    #[test]
    fn finalization_recovery_window_is_exclusive_and_identity_pinned() {
        let (root, application, validation) = private_root();
        let recovery_lock =
            CrossStoreLockGuardV0::acquire_exclusive_for_paths_v0(&application, &validation)
                .expect("finalization recovery lock");

        // A cooperating P/K writer or paired reader cannot enter while the
        // marker load, proof readback, and marker clear share this window.
        assert!(matches!(
            CrossStoreLockGuardV0::acquire_shared_for_paths_v0(&application, &validation),
            Err(CrossStoreLockErrorV0::Busy)
        ));
        assert!(matches!(
            CrossStoreLockGuardV0::acquire_exclusive_for_paths_v0(&application, &validation),
            Err(CrossStoreLockErrorV0::Busy)
        ));

        // Replacing the pathname must not make the held descriptor appear to
        // authorize a different authority root before the clear boundary.
        let moved = root.path().with_extension("moved");
        std::fs::rename(root.path(), &moved).expect("rename locked root");
        std::fs::create_dir(root.path()).expect("recreate root pathname");
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))
            .expect("recreated root permissions");
        assert!(matches!(
            recovery_lock.validate_identity_v0(),
            Err(CrossStoreLockErrorV0::RootIdentityChanged)
        ));
    }

    #[test]
    fn bound_child_descriptors_reject_store_rename_and_recreate() {
        let (_root, application, validation) = private_root();
        for path in [&application, &validation] {
            fs::write(path, b"sqlite-placeholder").expect("create child store");
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))
                .expect("private child store");
        }
        let guard =
            CrossStoreLockGuardV0::acquire_exclusive_for_paths_v0(&application, &validation)
                .expect("lock root and bind concrete P/K descriptors");
        guard
            .validate_identity_v0()
            .expect("bound descriptors initially match paths");

        let moved = application.with_extension("moved");
        fs::rename(&application, &moved).expect("rename application store");
        fs::write(&application, b"replacement").expect("recreate application pathname");
        fs::set_permissions(&application, fs::Permissions::from_mode(0o600))
            .expect("private replacement");
        assert!(matches!(
            guard.validate_identity_v0(),
            Err(CrossStoreLockErrorV0::ChildIdentityChanged)
        ));

        drop(guard);
        let _ = fs::remove_file(moved);
        let _ = fs::remove_file(application);
        let _ = fs::remove_file(validation);
    }

    #[test]
    fn child_binding_rejects_unowned_or_writable_store_shape() {
        let (root, application, validation) = private_root();
        for path in [&application, &validation] {
            fs::write(path, b"sqlite-placeholder").expect("create child store");
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))
                .expect("private child store");
        }
        fs::set_permissions(&validation, fs::Permissions::from_mode(0o602))
            .expect("make validation writable by others");
        let mut guard =
            CrossStoreLockGuardV0::acquire_exclusive_for_root_v0(root.path()).expect("lock root");
        assert!(matches!(
            guard.bind_store_files_v0(&application, &validation),
            Err(CrossStoreLockErrorV0::InvalidPath(_))
        ));
        drop(guard);
        let _ = fs::remove_file(application);
        let _ = fs::remove_file(validation);
    }

    #[test]
    fn single_store_bootstrap_resolves_the_common_root() {
        let (root, application, validation) = private_root();
        let application_root = authority_root_for_store_path_v0(&application)
            .expect("single application path resolves authority root");
        assert_eq!(application_root, root.path());
        let validation_root = authority_root_for_store_path_v0(&validation)
            .expect("single validation path resolves authority root");
        assert_eq!(validation_root, root.path());

        let exclusive = CrossStoreLockGuardV0::acquire_exclusive_for_store_path_v0(&application)
            .expect("single-store bootstrap lock");
        assert!(matches!(
            CrossStoreLockGuardV0::acquire_shared_for_paths_v0(&application, &validation),
            Err(CrossStoreLockErrorV0::Busy)
        ));
        exclusive
            .validate_identity_v0()
            .expect("single-store bootstrap identity remains pinned");
    }
}
