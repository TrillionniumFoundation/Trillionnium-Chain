//! Candidate-only G2F namespace and external anti-rollback contract.
//!
//! This module freezes the *shape* of the namespace/anchor boundary needed by
//! G2F without wiring it into a production node.  A caller opens a private
//! namespace once, retains its directory descriptor, and opens child files
//! relative to that descriptor (`openat`, `O_NOFOLLOW`, `O_CLOEXEC`).  Every
//! returned file handle carries device/inode/owner/mode/link/size/content
//! identity and can be revalidated immediately before authority use.
//!
//! The external anchor is a second, independently administered CAS domain.  It
//! binds generation, finalized height/epoch, validator-set and manifest hashes,
//! plus the descriptor-derived namespace/file identities.  The trait is only a
//! contract: no HSM/KMS/remote backend is supplied here and no Core, signer,
//! state-sync, broadcast, or activation path consumes it.  A backend must
//! durably persist its own value and reject a non-successor target; callers
//! must treat an uncertain result as requiring fresh load/reconciliation.
//!
//! This candidate boundary deliberately keeps the hostile mutants visible:
//! copied/renamed files, same-UID namespace replacement, torn same-inode
//! writes, SQLite sidecars/WAL, and local-anchor rollback all fail closed in
//! the tests.  Filesystem operations are Linux/Unix-only because the required
//! descriptor identity and effective-UID contract is not portable.

#![cfg(unix)]

use std::{
    error::Error,
    fmt,
    fs::{self, File},
    io,
    os::unix::fs::{FileExt as UnixFileExt, MetadataExt, PermissionsExt},
    path::{Component, Path, PathBuf},
};

use borsh::{BorshDeserialize, BorshSerialize};
use fs2::FileExt;
use rustix::{
    fs::{open, openat, Mode, OFlags},
    io::Errno,
    process::geteuid,
};
use sha2::{Digest, Sha256};

/// The contract is candidate-only and is not a production activation claim.
pub const POCO_NODE_G2F_NAMESPACE_IDENTITY_CONTRACT_V1: bool = true;
pub const POCO_NODE_G2F_NAMESPACE_OPENAT_DESCRIPTOR_V1: bool = true;
pub const POCO_NODE_G2F_EXTERNAL_MONOTONIC_ANCHOR_CONTRACT_V1: bool = true;
pub const POCO_NODE_G2F_NAMESPACE_PROCESS_INTEGRATION_V1: bool = false;
pub const POCO_NODE_G2F_EXTERNAL_ANCHOR_BACKEND_V1: bool = false;
pub const POCO_NODE_G2F_PRODUCTION_ACTIVATION_V1: bool = false;

const NAMESPACE_MODE_V1: u32 = 0o700;
const FILE_MODE_V1: u32 = 0o600;
const ANCHOR_MAGIC_V1: [u8; 8] = *b"TRNMG2A1";
const ANCHOR_SCHEMA_V1: u16 = 1;
const ANCHOR_DOMAIN_V1: &[u8] = b"trnm.poco-ai.g2f.external-monotonic-anchor.v1\0";
const NAMESPACE_DOMAIN_V1: &[u8] = b"trnm.poco-ai.g2f.namespace-identity.v1\0";
const FILE_DOMAIN_V1: &[u8] = b"trnm.poco-ai.g2f.file-identity.v1\0";
const MAX_ANCHOR_BYTES_V1: usize = 1024;
const DEFAULT_MAX_FILE_BYTES_V1: u64 = 256 * 1024 * 1024;

/// Typed failures for descriptor/path identity checks.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum PocoNodeG2fNamespaceErrorCodeV1 {
    InvalidPath,
    PathAlias,
    Io,
    NotDirectory,
    NotRegularFile,
    Symlink,
    OwnerMismatch,
    ModeMismatch,
    LinkCountMismatch,
    IdentityChanged,
    FileChanged,
    TornRead,
    TooLarge,
    SidecarPresent,
    InvalidComponent,
    RootBusy,
    Unsupported,
}

/// Fail-closed namespace error carrying a stable classification and detail.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PocoNodeG2fNamespaceErrorV1 {
    code: PocoNodeG2fNamespaceErrorCodeV1,
    detail: String,
}

impl PocoNodeG2fNamespaceErrorV1 {
    fn new(code: PocoNodeG2fNamespaceErrorCodeV1, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }

    pub const fn code(&self) -> PocoNodeG2fNamespaceErrorCodeV1 {
        self.code
    }
}

impl fmt::Display for PocoNodeG2fNamespaceErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "G2F namespace identity rejected: {}",
            self.detail
        )
    }
}

impl Error for PocoNodeG2fNamespaceErrorV1 {}

type NamespaceResultV1<T> = Result<T, PocoNodeG2fNamespaceErrorV1>;

fn namespace_error<T>(
    code: PocoNodeG2fNamespaceErrorCodeV1,
    detail: impl Into<String>,
) -> NamespaceResultV1<T> {
    Err(PocoNodeG2fNamespaceErrorV1::new(code, detail))
}

fn io_namespace<T>(
    code: PocoNodeG2fNamespaceErrorCodeV1,
    stage: &str,
    error: impl fmt::Display,
) -> NamespaceResultV1<T> {
    namespace_error(code, format!("{stage}: {error}"))
}

fn classify_open_error(error: Errno) -> PocoNodeG2fNamespaceErrorCodeV1 {
    // `O_NOFOLLOW` reports ELOOP for a final symlink. Preserve that typed
    // distinction instead of collapsing a path-substitution mutant into a
    // generic I/O failure.
    if error == Errno::LOOP {
        PocoNodeG2fNamespaceErrorCodeV1::Symlink
    } else {
        PocoNodeG2fNamespaceErrorCodeV1::Io
    }
}

/// Device/inode/effective-owner identity of one private namespace directory.
///
/// The fields are private so callers cannot manufacture an identity for an
/// arbitrary path.  They can only obtain one from a retained descriptor guard.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, BorshSerialize, BorshDeserialize)]
pub struct PocoNodeG2fNamespaceIdentityV1 {
    device: u64,
    inode: u64,
    owner_uid: u32,
    mode: u32,
}

impl PocoNodeG2fNamespaceIdentityV1 {
    pub const fn device(&self) -> u64 {
        self.device
    }

    pub const fn inode(&self) -> u64 {
        self.inode
    }

    pub const fn owner_uid(&self) -> u32 {
        self.owner_uid
    }

    pub const fn mode(&self) -> u32 {
        self.mode
    }

    /// Stable digest used by evidence and anchor implementations.
    pub fn digest(&self) -> [u8; 32] {
        digest_bytes(
            NAMESPACE_DOMAIN_V1,
            &borsh::to_vec(self).expect("fixed identity encoding"),
        )
    }

    fn from_metadata(metadata: &fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            owner_uid: metadata.uid(),
            mode: metadata.mode() & 0o7777,
        }
    }

    fn validate_shape(&self) -> NamespaceResultV1<()> {
        if self.device == 0 || self.inode == 0 {
            return namespace_error(
                PocoNodeG2fNamespaceErrorCodeV1::IdentityChanged,
                "namespace device/inode must be nonzero",
            );
        }
        if self.mode != NAMESPACE_MODE_V1 {
            return namespace_error(
                PocoNodeG2fNamespaceErrorCodeV1::ModeMismatch,
                format!(
                    "namespace mode is {:o}, expected {:o}",
                    self.mode, NAMESPACE_MODE_V1
                ),
            );
        }
        Ok(())
    }
}

/// Descriptor-derived identity of one regular private file.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, BorshSerialize, BorshDeserialize)]
pub struct PocoNodeG2fFileIdentityV1 {
    device: u64,
    inode: u64,
    owner_uid: u32,
    mode: u32,
    link_count: u64,
    size: u64,
    content_hash: [u8; 32],
}

impl PocoNodeG2fFileIdentityV1 {
    pub const fn device(&self) -> u64 {
        self.device
    }

    pub const fn inode(&self) -> u64 {
        self.inode
    }

    pub const fn owner_uid(&self) -> u32 {
        self.owner_uid
    }

    pub const fn mode(&self) -> u32 {
        self.mode
    }

    pub const fn link_count(&self) -> u64 {
        self.link_count
    }

    pub const fn size(&self) -> u64 {
        self.size
    }

    pub const fn content_hash(&self) -> [u8; 32] {
        self.content_hash
    }

    pub fn digest(&self) -> [u8; 32] {
        digest_bytes(
            FILE_DOMAIN_V1,
            &borsh::to_vec(self).expect("fixed identity encoding"),
        )
    }

    fn from_metadata_and_bytes(metadata: &fs::Metadata, bytes: &[u8]) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            owner_uid: metadata.uid(),
            mode: metadata.mode() & 0o7777,
            link_count: metadata.nlink(),
            size: metadata.len(),
            content_hash: digest_bytes(FILE_DOMAIN_V1, bytes),
        }
    }

    fn metadata_only(&self) -> (u64, u64, u32, u32, u64, u64) {
        (
            self.device,
            self.inode,
            self.owner_uid,
            self.mode,
            self.link_count,
            self.size,
        )
    }

    fn validate_shape(&self) -> NamespaceResultV1<()> {
        if self.device == 0 || self.inode == 0 {
            return namespace_error(
                PocoNodeG2fNamespaceErrorCodeV1::IdentityChanged,
                "file device/inode must be nonzero",
            );
        }
        if self.mode != FILE_MODE_V1 {
            return namespace_error(
                PocoNodeG2fNamespaceErrorCodeV1::ModeMismatch,
                format!("file mode is {:o}, expected {:o}", self.mode, FILE_MODE_V1),
            );
        }
        if self.link_count != 1 {
            return namespace_error(
                PocoNodeG2fNamespaceErrorCodeV1::LinkCountMismatch,
                format!("file link count is {}, expected one", self.link_count),
            );
        }
        Ok(())
    }
}

/// Retained private directory descriptor and path identity.
///
/// The guard takes an exclusive advisory lock for cooperating owners.  The
/// lock is not treated as a security boundary: an uncooperative same-UID
/// process can still rename a path, so every operation compares the held
/// descriptor with the named path and effective UID.
#[derive(Debug)]
pub struct PocoNodeG2fNamespaceGuardV1 {
    root: PathBuf,
    directory: File,
    identity: PocoNodeG2fNamespaceIdentityV1,
}

impl PocoNodeG2fNamespaceGuardV1 {
    /// Open and retain an existing owner-private namespace directory.
    pub fn open_existing(root: impl AsRef<Path>) -> NamespaceResultV1<Self> {
        let root = root.as_ref().to_path_buf();
        validate_root_path(&root)?;
        let descriptor = open(
            &root,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|error| {
            PocoNodeG2fNamespaceErrorV1::new(
                classify_open_error(error),
                format!("open namespace with O_DIRECTORY|O_NOFOLLOW: {error}"),
            )
        })?;
        let directory: File = descriptor.into();
        let descriptor_metadata = directory.metadata().map_err(|error| {
            PocoNodeG2fNamespaceErrorV1::new(
                PocoNodeG2fNamespaceErrorCodeV1::Io,
                format!("stat retained namespace descriptor: {error}"),
            )
        })?;
        let identity = PocoNodeG2fNamespaceIdentityV1::from_metadata(&descriptor_metadata);
        validate_namespace_metadata(&identity, &descriptor_metadata)?;
        let named_metadata = fs::symlink_metadata(&root).map_err(|error| {
            PocoNodeG2fNamespaceErrorV1::new(
                PocoNodeG2fNamespaceErrorCodeV1::Io,
                format!("stat namespace path: {error}"),
            )
        })?;
        let named_identity = PocoNodeG2fNamespaceIdentityV1::from_metadata(&named_metadata);
        validate_namespace_metadata(&named_identity, &named_metadata)?;
        if named_identity != identity {
            return namespace_error(
                PocoNodeG2fNamespaceErrorCodeV1::IdentityChanged,
                "namespace descriptor/path device-inode-owner identity differs",
            );
        }
        ensure_canonical_path(&root)?;

        FileExt::try_lock_exclusive(&directory).map_err(|error| {
            PocoNodeG2fNamespaceErrorV1::new(
                PocoNodeG2fNamespaceErrorCodeV1::RootBusy,
                format!("exclusive namespace lock: {error}"),
            )
        })?;
        let guard = Self {
            root,
            directory,
            identity,
        };
        if let Err(error) = guard.revalidate() {
            let _ = FileExt::unlock(&guard.directory);
            return Err(error);
        }
        Ok(guard)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub const fn identity(&self) -> PocoNodeG2fNamespaceIdentityV1 {
        self.identity
    }

    /// Recheck the retained descriptor against the current path and euid.
    pub fn revalidate(&self) -> NamespaceResultV1<()> {
        let descriptor_metadata = self.directory.metadata().map_err(|error| {
            PocoNodeG2fNamespaceErrorV1::new(
                PocoNodeG2fNamespaceErrorCodeV1::Io,
                format!("stat retained namespace descriptor: {error}"),
            )
        })?;
        let descriptor_identity =
            PocoNodeG2fNamespaceIdentityV1::from_metadata(&descriptor_metadata);
        validate_namespace_metadata(&descriptor_identity, &descriptor_metadata)?;
        let named_metadata = fs::symlink_metadata(&self.root).map_err(|error| {
            PocoNodeG2fNamespaceErrorV1::new(
                PocoNodeG2fNamespaceErrorCodeV1::Io,
                format!("stat namespace path: {error}"),
            )
        })?;
        let named_identity = PocoNodeG2fNamespaceIdentityV1::from_metadata(&named_metadata);
        validate_namespace_metadata(&named_identity, &named_metadata)?;
        if descriptor_identity != self.identity || named_identity != self.identity {
            return namespace_error(
                PocoNodeG2fNamespaceErrorCodeV1::IdentityChanged,
                "retained namespace descriptor/path identity changed",
            );
        }
        ensure_canonical_path(&self.root)
    }

    /// Reject SQLite WAL/SHM/rollback-journal siblings for one base name.
    pub fn reject_sidecars(&self, base_name: &str) -> NamespaceResultV1<()> {
        validate_component(base_name)?;
        for suffix in ["-wal", "-shm", "-journal"] {
            let path = self.root.join(format!("{base_name}{suffix}"));
            match fs::symlink_metadata(&path) {
                Ok(_) => {
                    return namespace_error(
                        PocoNodeG2fNamespaceErrorCodeV1::SidecarPresent,
                        format!("SQLite sidecar/WAL exists: {}", path.display()),
                    )
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => {
                    return io_namespace(
                        PocoNodeG2fNamespaceErrorCodeV1::Io,
                        "inspect SQLite sidecar",
                        error,
                    )
                }
            }
        }
        Ok(())
    }

    /// Open a regular child relative to the retained descriptor (`openat`).
    /// The bytes and metadata are sampled twice; any torn/mutated sample is
    /// rejected before a handle is returned.
    pub fn openat_regular(
        &self,
        name: &str,
        max_bytes: u64,
    ) -> NamespaceResultV1<PocoNodeG2fFileHandleV1> {
        if max_bytes == 0 || max_bytes > DEFAULT_MAX_FILE_BYTES_V1 {
            return namespace_error(
                PocoNodeG2fNamespaceErrorCodeV1::TooLarge,
                format!("maximum file size must be in 1..={DEFAULT_MAX_FILE_BYTES_V1} bytes"),
            );
        }
        validate_component(name)?;
        self.revalidate()?;
        self.reject_sidecars(name)?;
        let descriptor = openat(
            &self.directory,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|error| {
            PocoNodeG2fNamespaceErrorV1::new(
                classify_open_error(error),
                format!("openat child {name}: {error}"),
            )
        })?;
        let file: File = descriptor.into();
        let identity = stable_file_snapshot(&file, max_bytes)?;
        let named_metadata = fs::symlink_metadata(self.root.join(name)).map_err(|error| {
            PocoNodeG2fNamespaceErrorV1::new(
                PocoNodeG2fNamespaceErrorCodeV1::Io,
                format!("stat opened child path {name}: {error}"),
            )
        })?;
        validate_file_metadata(&named_metadata)?;
        let named_identity = metadata_identity(&named_metadata);
        if named_identity != identity.metadata_only() {
            return namespace_error(
                PocoNodeG2fNamespaceErrorCodeV1::IdentityChanged,
                format!("openat child {name} was replaced before admission"),
            );
        }
        self.reject_sidecars(name)?;
        self.revalidate()?;
        let directory = self.directory.try_clone().map_err(|error| {
            PocoNodeG2fNamespaceErrorV1::new(
                PocoNodeG2fNamespaceErrorCodeV1::Io,
                format!("clone namespace descriptor for child {name}: {error}"),
            )
        })?;
        Ok(PocoNodeG2fFileHandleV1 {
            name: name.to_owned(),
            root: self.root.clone(),
            directory,
            namespace_identity: self.identity,
            file,
            identity,
            max_bytes,
        })
    }

    /// Open with the bounded default used by candidate evidence fixtures.
    pub fn openat_regular_default(&self, name: &str) -> NamespaceResultV1<PocoNodeG2fFileHandleV1> {
        self.openat_regular(name, DEFAULT_MAX_FILE_BYTES_V1)
    }
}

impl Drop for PocoNodeG2fNamespaceGuardV1 {
    fn drop(&mut self) {
        let _ = FileExt::unlock(&self.directory);
    }
}

/// Descriptor-bound child file.  The handle itself is not authority; callers
/// must call `revalidate`/`read_bytes` immediately before an authority step.
#[derive(Debug)]
pub struct PocoNodeG2fFileHandleV1 {
    name: String,
    root: PathBuf,
    directory: File,
    namespace_identity: PocoNodeG2fNamespaceIdentityV1,
    file: File,
    identity: PocoNodeG2fFileIdentityV1,
    max_bytes: u64,
}

impl PocoNodeG2fFileHandleV1 {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub const fn namespace_identity(&self) -> PocoNodeG2fNamespaceIdentityV1 {
        self.namespace_identity
    }

    pub const fn identity(&self) -> PocoNodeG2fFileIdentityV1 {
        self.identity
    }

    /// Revalidate namespace, path, sidecars and the retained file descriptor.
    pub fn revalidate(&self) -> NamespaceResultV1<()> {
        let directory_metadata = self.directory.metadata().map_err(|error| {
            PocoNodeG2fNamespaceErrorV1::new(
                PocoNodeG2fNamespaceErrorCodeV1::Io,
                format!("stat retained child namespace descriptor: {error}"),
            )
        })?;
        let directory_identity = PocoNodeG2fNamespaceIdentityV1::from_metadata(&directory_metadata);
        validate_namespace_metadata(&directory_identity, &directory_metadata)?;
        let named_namespace = fs::symlink_metadata(&self.root).map_err(|error| {
            PocoNodeG2fNamespaceErrorV1::new(
                PocoNodeG2fNamespaceErrorCodeV1::Io,
                format!("stat child namespace path: {error}"),
            )
        })?;
        let named_namespace_identity =
            PocoNodeG2fNamespaceIdentityV1::from_metadata(&named_namespace);
        validate_namespace_metadata(&named_namespace_identity, &named_namespace)?;
        if directory_identity != self.namespace_identity
            || named_namespace_identity != self.namespace_identity
        {
            return namespace_error(
                PocoNodeG2fNamespaceErrorCodeV1::IdentityChanged,
                "child namespace descriptor/path identity changed",
            );
        }
        ensure_canonical_path(&self.root)?;
        reject_sidecars_for_root(&self.root, &self.name)?;

        let current = stable_file_snapshot(&self.file, self.max_bytes)?;
        if current != self.identity {
            return namespace_error(
                PocoNodeG2fNamespaceErrorCodeV1::FileChanged,
                format!(
                    "child file {} changed after descriptor admission",
                    self.name
                ),
            );
        }
        let named_metadata = fs::symlink_metadata(self.root.join(&self.name)).map_err(|error| {
            PocoNodeG2fNamespaceErrorV1::new(
                PocoNodeG2fNamespaceErrorCodeV1::Io,
                format!("stat child file path {}: {error}", self.name),
            )
        })?;
        validate_file_metadata(&named_metadata)?;
        if metadata_identity(&named_metadata) != self.identity.metadata_only() {
            return namespace_error(
                PocoNodeG2fNamespaceErrorCodeV1::IdentityChanged,
                format!("child file path {} was copied or renamed", self.name),
            );
        }
        Ok(())
    }

    /// Read bytes only after a complete descriptor/path identity check, then
    /// recheck again.  A caller can hand these bytes to a candidate hash/join;
    /// this method never creates an authority capability.
    pub fn read_bytes(&self) -> NamespaceResultV1<Vec<u8>> {
        self.revalidate()?;
        let bytes = read_bounded_stable(&self.file, self.max_bytes)?;
        self.revalidate()?;
        Ok(bytes)
    }
}

/// Typed failures for the independent monotonic anchor contract.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum PocoNodeG2fAnchorErrorCodeV1 {
    InvalidField,
    WrongLength,
    WrongMagic,
    UnsupportedSchema,
    NonCanonical,
    ChecksumMismatch,
    ScopeMismatch,
    GenerationRollback,
    HeightRollback,
    EpochRollback,
    ValidatorSetMismatch,
    ManifestMismatch,
    NamespaceMismatch,
    FileMismatch,
    PredecessorMismatch,
    BackendUnavailable,
    CompareFailed,
    CommitUncertain,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PocoNodeG2fAnchorErrorV1 {
    code: PocoNodeG2fAnchorErrorCodeV1,
    detail: String,
}

impl PocoNodeG2fAnchorErrorV1 {
    fn new(code: PocoNodeG2fAnchorErrorCodeV1, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }

    pub const fn code(&self) -> PocoNodeG2fAnchorErrorCodeV1 {
        self.code
    }
}

impl fmt::Display for PocoNodeG2fAnchorErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "G2F external monotonic anchor rejected: {}",
            self.detail
        )
    }
}

impl Error for PocoNodeG2fAnchorErrorV1 {}

type AnchorResultV1<T> = Result<T, PocoNodeG2fAnchorErrorV1>;

fn anchor_error<T>(
    code: PocoNodeG2fAnchorErrorCodeV1,
    detail: impl Into<String>,
) -> AnchorResultV1<T> {
    Err(PocoNodeG2fAnchorErrorV1::new(code, detail))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
struct AnchorBodyV1 {
    magic: [u8; 8],
    schema_version: u16,
    scope: [u8; 32],
    generation: u64,
    height: u64,
    epoch: u64,
    validator_set_hash: [u8; 32],
    manifest_hash: [u8; 32],
    namespace_identity: PocoNodeG2fNamespaceIdentityV1,
    file_identity: PocoNodeG2fFileIdentityV1,
    predecessor_checksum: [u8; 32],
}

/// Canonical external anti-rollback record.  It is evidence/data, not a
/// signer or state-transition permit; only an independently administered
/// backend can make a compare-and-advance decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PocoNodeG2fAnchorRecordV1 {
    body: AnchorBodyV1,
    checksum: [u8; 32],
}

impl PocoNodeG2fAnchorRecordV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        scope: [u8; 32],
        generation: u64,
        height: u64,
        epoch: u64,
        validator_set_hash: [u8; 32],
        manifest_hash: [u8; 32],
        namespace_identity: PocoNodeG2fNamespaceIdentityV1,
        file_identity: PocoNodeG2fFileIdentityV1,
        predecessor_checksum: [u8; 32],
    ) -> AnchorResultV1<Self> {
        let record = Self {
            body: AnchorBodyV1 {
                magic: ANCHOR_MAGIC_V1,
                schema_version: ANCHOR_SCHEMA_V1,
                scope,
                generation,
                height,
                epoch,
                validator_set_hash,
                manifest_hash,
                namespace_identity,
                file_identity,
                predecessor_checksum,
            },
            checksum: [0; 32],
        };
        record.with_sealed_checksum()
    }

    pub fn initial(
        scope: [u8; 32],
        height: u64,
        epoch: u64,
        validator_set_hash: [u8; 32],
        manifest_hash: [u8; 32],
        namespace_identity: PocoNodeG2fNamespaceIdentityV1,
        file_identity: PocoNodeG2fFileIdentityV1,
    ) -> AnchorResultV1<Self> {
        Self::new(
            scope,
            0,
            height,
            epoch,
            validator_set_hash,
            manifest_hash,
            namespace_identity,
            file_identity,
            [0; 32],
        )
    }

    fn with_sealed_checksum(mut self) -> AnchorResultV1<Self> {
        self.validate_body()?;
        self.checksum = self.expected_checksum();
        Ok(self)
    }

    pub const fn scope(&self) -> [u8; 32] {
        self.body.scope
    }

    pub const fn generation(&self) -> u64 {
        self.body.generation
    }

    pub const fn height(&self) -> u64 {
        self.body.height
    }

    pub const fn epoch(&self) -> u64 {
        self.body.epoch
    }

    pub const fn validator_set_hash(&self) -> [u8; 32] {
        self.body.validator_set_hash
    }

    pub const fn manifest_hash(&self) -> [u8; 32] {
        self.body.manifest_hash
    }

    pub const fn namespace_identity(&self) -> PocoNodeG2fNamespaceIdentityV1 {
        self.body.namespace_identity
    }

    pub const fn file_identity(&self) -> PocoNodeG2fFileIdentityV1 {
        self.body.file_identity
    }

    pub const fn predecessor_checksum(&self) -> [u8; 32] {
        self.body.predecessor_checksum
    }

    pub const fn checksum(&self) -> [u8; 32] {
        self.checksum
    }

    pub fn encode_canonical(&self) -> Vec<u8> {
        let mut encoded = borsh::to_vec(&self.body).expect("fixed anchor encoding");
        encoded.extend_from_slice(&self.checksum);
        encoded
    }

    pub fn decode_canonical_exact(bytes: &[u8]) -> AnchorResultV1<Self> {
        if bytes.len() < 32 || bytes.len() > MAX_ANCHOR_BYTES_V1 {
            return anchor_error(
                PocoNodeG2fAnchorErrorCodeV1::WrongLength,
                format!(
                    "anchor bytes length {} is outside the bounded envelope",
                    bytes.len()
                ),
            );
        }
        let split = bytes.len() - 32;
        let body: AnchorBodyV1 =
            BorshDeserialize::try_from_slice(&bytes[..split]).map_err(|_| {
                PocoNodeG2fAnchorErrorV1::new(
                    PocoNodeG2fAnchorErrorCodeV1::NonCanonical,
                    "anchor body is not canonical Borsh",
                )
            })?;
        let canonical_body = borsh::to_vec(&body).expect("fixed anchor encoding");
        if canonical_body.as_slice() != &bytes[..split] {
            return anchor_error(
                PocoNodeG2fAnchorErrorCodeV1::NonCanonical,
                "anchor body has non-canonical trailing/encoding bytes",
            );
        }
        let checksum: [u8; 32] = bytes[split..].try_into().map_err(|_| {
            PocoNodeG2fAnchorErrorV1::new(
                PocoNodeG2fAnchorErrorCodeV1::WrongLength,
                "anchor checksum is not 32 bytes",
            )
        })?;
        let record = Self { body, checksum };
        record.validate_body()?;
        if record.expected_checksum() != checksum {
            return anchor_error(
                PocoNodeG2fAnchorErrorCodeV1::ChecksumMismatch,
                "anchor checksum does not match canonical body",
            );
        }
        Ok(record)
    }

    /// Validate a strict successor relation for an external CAS backend.
    ///
    /// Generation is strictly contiguous; finalized height cannot decrease;
    /// validator-set changes require an epoch advance; manifest, namespace and
    /// file identities remain pinned.  Identity rotation requires a future,
    /// separately reviewed state-sync contract and is intentionally rejected.
    pub fn validate_successor_of(&self, predecessor: &Self) -> AnchorResultV1<()> {
        if self.scope() != predecessor.scope() {
            return anchor_error(
                PocoNodeG2fAnchorErrorCodeV1::ScopeMismatch,
                "successor scope differs",
            );
        }
        if self.generation()
            != predecessor.generation().checked_add(1).ok_or_else(|| {
                PocoNodeG2fAnchorErrorV1::new(
                    PocoNodeG2fAnchorErrorCodeV1::GenerationRollback,
                    "successor generation overflows",
                )
            })?
        {
            return anchor_error(
                PocoNodeG2fAnchorErrorCodeV1::GenerationRollback,
                "anchor generation must advance exactly one",
            );
        }
        if self.predecessor_checksum() != predecessor.checksum() {
            return anchor_error(
                PocoNodeG2fAnchorErrorCodeV1::PredecessorMismatch,
                "successor does not name the exact predecessor checksum",
            );
        }
        if self.height() < predecessor.height() {
            return anchor_error(
                PocoNodeG2fAnchorErrorCodeV1::HeightRollback,
                "finalized height decreases",
            );
        }
        if self.epoch() < predecessor.epoch() {
            return anchor_error(
                PocoNodeG2fAnchorErrorCodeV1::EpochRollback,
                "epoch decreases",
            );
        }
        if self.epoch() == predecessor.epoch()
            && self.validator_set_hash() != predecessor.validator_set_hash()
        {
            return anchor_error(
                PocoNodeG2fAnchorErrorCodeV1::ValidatorSetMismatch,
                "validator-set hash changes without an epoch transition",
            );
        }
        if self.manifest_hash() != predecessor.manifest_hash() {
            return anchor_error(
                PocoNodeG2fAnchorErrorCodeV1::ManifestMismatch,
                "manifest identity changed without an explicit reviewed rotation",
            );
        }
        if self.namespace_identity() != predecessor.namespace_identity() {
            return anchor_error(
                PocoNodeG2fAnchorErrorCodeV1::NamespaceMismatch,
                "namespace identity changed without an explicit reviewed rotation",
            );
        }
        if self.file_identity() != predecessor.file_identity() {
            return anchor_error(
                PocoNodeG2fAnchorErrorCodeV1::FileMismatch,
                "file identity changed without an explicit reviewed rotation",
            );
        }
        Ok(())
    }

    fn validate_body(&self) -> AnchorResultV1<()> {
        if self.body.magic != ANCHOR_MAGIC_V1 {
            return anchor_error(
                PocoNodeG2fAnchorErrorCodeV1::WrongMagic,
                "anchor magic differs",
            );
        }
        if self.body.schema_version != ANCHOR_SCHEMA_V1 {
            return anchor_error(
                PocoNodeG2fAnchorErrorCodeV1::UnsupportedSchema,
                "anchor schema differs",
            );
        }
        if self.body.scope == [0; 32]
            || self.body.validator_set_hash == [0; 32]
            || self.body.manifest_hash == [0; 32]
        {
            return anchor_error(
                PocoNodeG2fAnchorErrorCodeV1::InvalidField,
                "anchor scope/validator-set/manifest hash must be nonzero",
            );
        }
        if self.body.generation == 0 {
            if self.body.predecessor_checksum != [0; 32] {
                return anchor_error(
                    PocoNodeG2fAnchorErrorCodeV1::PredecessorMismatch,
                    "initial anchor must have a zero predecessor",
                );
            }
        } else if self.body.predecessor_checksum == [0; 32] {
            return anchor_error(
                PocoNodeG2fAnchorErrorCodeV1::PredecessorMismatch,
                "successor anchor must carry a predecessor checksum",
            );
        }
        self.body
            .namespace_identity
            .validate_shape()
            .map_err(|error| {
                PocoNodeG2fAnchorErrorV1::new(
                    PocoNodeG2fAnchorErrorCodeV1::InvalidField,
                    error.to_string(),
                )
            })?;
        self.body.file_identity.validate_shape().map_err(|error| {
            PocoNodeG2fAnchorErrorV1::new(
                PocoNodeG2fAnchorErrorCodeV1::InvalidField,
                error.to_string(),
            )
        })?;
        Ok(())
    }

    fn expected_checksum(&self) -> [u8; 32] {
        digest_bytes(
            ANCHOR_DOMAIN_V1,
            &borsh::to_vec(&self.body).expect("fixed anchor encoding"),
        )
    }
}

/// Independently administered external monotonic anchor boundary.
///
/// Implementations must live outside every source-plane/whole-node SQLite
/// namespace (for example an HSM/KMS, remote operator quorum, or separately
/// locked authority daemon).  They must persist one value per scope and return
/// an uncertain/error result rather than claiming success when durability or
/// acknowledgement is ambiguous.
pub trait PocoNodeG2fExternalMonotonicAnchorV1 {
    fn load(&mut self, scope: [u8; 32]) -> AnchorResultV1<Option<PocoNodeG2fAnchorRecordV1>>;

    fn compare_and_advance(
        &mut self,
        expected: Option<PocoNodeG2fAnchorRecordV1>,
        target: PocoNodeG2fAnchorRecordV1,
    ) -> AnchorResultV1<()>;
}

/// Validate and execute one anchor CAS only while descriptor/file identities
/// are fresh.  If the backend reports success but the post-CAS revalidation
/// fails, the result is `CommitUncertain`; callers must reload the external
/// anchor and quarantine/reconcile before any authority use.
pub fn compare_and_advance_bound_v1<A: PocoNodeG2fExternalMonotonicAnchorV1>(
    backend: &mut A,
    expected: Option<PocoNodeG2fAnchorRecordV1>,
    target: PocoNodeG2fAnchorRecordV1,
    namespace: &PocoNodeG2fNamespaceGuardV1,
    file: &PocoNodeG2fFileHandleV1,
) -> AnchorResultV1<()> {
    namespace.revalidate().map_err(|error| {
        PocoNodeG2fAnchorErrorV1::new(
            PocoNodeG2fAnchorErrorCodeV1::NamespaceMismatch,
            error.to_string(),
        )
    })?;
    file.revalidate().map_err(|error| {
        PocoNodeG2fAnchorErrorV1::new(
            PocoNodeG2fAnchorErrorCodeV1::FileMismatch,
            error.to_string(),
        )
    })?;

    // A safe caller can only obtain a well-formed record through `new` or
    // `decode_canonical_exact`, but validate again at the authority boundary:
    // this is where an externally supplied/pre-decoded record becomes a CAS
    // request.  In particular, never let a target bind a different retained
    // namespace/file identity merely because its checksum is internally
    // consistent.
    validate_bound_anchor_record(&target, namespace, file)?;
    if let Some(predecessor) = expected {
        validate_bound_anchor_record(&predecessor, namespace, file)?;
    }
    match expected {
        None => {
            if target.generation() != 0 || target.predecessor_checksum() != [0; 32] {
                return anchor_error(
                    PocoNodeG2fAnchorErrorCodeV1::CompareFailed,
                    "initial external anchor target is not generation zero",
                );
            }
        }
        Some(predecessor) => target.validate_successor_of(&predecessor)?,
    }
    backend.compare_and_advance(expected, target)?;
    if namespace.revalidate().is_err() || file.revalidate().is_err() {
        return anchor_error(
            PocoNodeG2fAnchorErrorCodeV1::CommitUncertain,
            "namespace/file identity changed after external CAS acknowledgement",
        );
    }
    Ok(())
}

fn validate_bound_anchor_record(
    record: &PocoNodeG2fAnchorRecordV1,
    namespace: &PocoNodeG2fNamespaceGuardV1,
    file: &PocoNodeG2fFileHandleV1,
) -> AnchorResultV1<()> {
    record.validate_body()?;
    if record.expected_checksum() != record.checksum() {
        return anchor_error(
            PocoNodeG2fAnchorErrorCodeV1::ChecksumMismatch,
            "anchor checksum does not match its canonical body",
        );
    }
    if record.namespace_identity() != namespace.identity() {
        return anchor_error(
            PocoNodeG2fAnchorErrorCodeV1::NamespaceMismatch,
            "anchor namespace identity differs from retained descriptor",
        );
    }
    if record.file_identity() != file.identity() {
        return anchor_error(
            PocoNodeG2fAnchorErrorCodeV1::FileMismatch,
            "anchor file identity differs from retained descriptor",
        );
    }
    Ok(())
}

fn digest_bytes(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    hasher.finalize().into()
}

fn validate_root_path(path: &Path) -> NamespaceResultV1<()> {
    if !path.is_absolute()
        || path == Path::new("/")
        || path.components().count() < 3
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return namespace_error(
            PocoNodeG2fNamespaceErrorCodeV1::InvalidPath,
            "namespace root must be a narrow absolute path without dot components",
        );
    }
    Ok(())
}

fn validate_component(name: &str) -> NamespaceResultV1<()> {
    let path = Path::new(name);
    if name.is_empty()
        || name.as_bytes().contains(&0)
        || path.components().count() != 1
        || !matches!(path.components().next(), Some(Component::Normal(_)))
        || name == "."
        || name == ".."
        || name.ends_with("-wal")
        || name.ends_with("-shm")
        || name.ends_with("-journal")
    {
        return namespace_error(
            PocoNodeG2fNamespaceErrorCodeV1::InvalidComponent,
            "child name must be one normal component and not a SQLite sidecar",
        );
    }
    Ok(())
}

fn ensure_canonical_path(path: &Path) -> NamespaceResultV1<()> {
    let canonical = fs::canonicalize(path).map_err(|error| {
        PocoNodeG2fNamespaceErrorV1::new(
            PocoNodeG2fNamespaceErrorCodeV1::Io,
            format!("canonicalize namespace path: {error}"),
        )
    })?;
    if canonical != path {
        return namespace_error(
            PocoNodeG2fNamespaceErrorCodeV1::PathAlias,
            format!(
                "namespace path {} is a symlink/canonical alias",
                path.display()
            ),
        );
    }
    Ok(())
}

fn validate_namespace_metadata(
    identity: &PocoNodeG2fNamespaceIdentityV1,
    metadata: &fs::Metadata,
) -> NamespaceResultV1<()> {
    if metadata.file_type().is_symlink() {
        return namespace_error(
            PocoNodeG2fNamespaceErrorCodeV1::Symlink,
            "namespace must not be a symlink",
        );
    }
    if !metadata.is_dir() {
        return namespace_error(
            PocoNodeG2fNamespaceErrorCodeV1::NotDirectory,
            "namespace is not a directory",
        );
    }
    identity.validate_shape()?;
    let current_uid = geteuid().as_raw();
    if identity.owner_uid != current_uid {
        return namespace_error(
            PocoNodeG2fNamespaceErrorCodeV1::OwnerMismatch,
            format!(
                "namespace owner uid {} differs from effective uid {}",
                identity.owner_uid, current_uid
            ),
        );
    }
    Ok(())
}

fn validate_file_metadata(metadata: &fs::Metadata) -> NamespaceResultV1<()> {
    if metadata.file_type().is_symlink() {
        return namespace_error(
            PocoNodeG2fNamespaceErrorCodeV1::Symlink,
            "child file must not be a symlink",
        );
    }
    if !metadata.is_file() {
        return namespace_error(
            PocoNodeG2fNamespaceErrorCodeV1::NotRegularFile,
            "child is not a regular file",
        );
    }
    if metadata.permissions().mode() & 0o7777 != FILE_MODE_V1 {
        return namespace_error(
            PocoNodeG2fNamespaceErrorCodeV1::ModeMismatch,
            format!(
                "child file mode is {:o}, expected {:o}",
                metadata.permissions().mode() & 0o7777,
                FILE_MODE_V1
            ),
        );
    }
    if metadata.nlink() != 1 {
        return namespace_error(
            PocoNodeG2fNamespaceErrorCodeV1::LinkCountMismatch,
            "child file must have one hard link",
        );
    }
    if metadata.uid() != geteuid().as_raw() {
        return namespace_error(
            PocoNodeG2fNamespaceErrorCodeV1::OwnerMismatch,
            "child file owner differs from effective uid",
        );
    }
    Ok(())
}

fn metadata_identity(metadata: &fs::Metadata) -> (u64, u64, u32, u32, u64, u64) {
    (
        metadata.dev(),
        metadata.ino(),
        metadata.uid(),
        metadata.mode() & 0o7777,
        metadata.nlink(),
        metadata.len(),
    )
}

fn read_bounded_stable(file: &File, max_bytes: u64) -> NamespaceResultV1<Vec<u8>> {
    let metadata_before = file.metadata().map_err(|error| {
        PocoNodeG2fNamespaceErrorV1::new(
            PocoNodeG2fNamespaceErrorCodeV1::Io,
            format!("stat child descriptor before read: {error}"),
        )
    })?;
    validate_file_metadata(&metadata_before)?;
    if metadata_before.len() > max_bytes {
        return namespace_error(
            PocoNodeG2fNamespaceErrorCodeV1::TooLarge,
            format!(
                "child file is {} bytes, limit is {max_bytes}",
                metadata_before.len()
            ),
        );
    }
    let capacity = usize::try_from(metadata_before.len()).map_err(|_| {
        PocoNodeG2fNamespaceErrorV1::new(
            PocoNodeG2fNamespaceErrorCodeV1::TooLarge,
            "child size cannot be represented on this platform",
        )
    })?;
    let mut bytes = Vec::with_capacity(capacity);
    // `File::try_clone` shares the open-file-description offset.  Using
    // pread/read_at keeps the two stable samples independent and avoids a
    // false torn-read on the second sample (and avoids an offset race with a
    // cooperating reader).
    let mut offset = 0_u64;
    let mut buffer = [0_u8; 16 * 1024];
    while offset <= max_bytes {
        let remaining = max_bytes.saturating_add(1).saturating_sub(offset);
        if remaining == 0 {
            break;
        }
        let request = remaining.min(buffer.len() as u64) as usize;
        let count =
            UnixFileExt::read_at(file, &mut buffer[..request], offset).map_err(|error| {
                PocoNodeG2fNamespaceErrorV1::new(
                    PocoNodeG2fNamespaceErrorCodeV1::Io,
                    format!("read child descriptor with pread: {error}"),
                )
            })?;
        if count == 0 {
            break;
        }
        bytes.extend_from_slice(&buffer[..count]);
        offset = offset.saturating_add(count as u64);
        if count < request {
            break;
        }
    }
    if bytes.len() as u64 != metadata_before.len() || bytes.len() as u64 > max_bytes {
        return namespace_error(
            PocoNodeG2fNamespaceErrorCodeV1::TornRead,
            "child size changed or exceeded the bounded read during sampling",
        );
    }
    let metadata_after = file.metadata().map_err(|error| {
        PocoNodeG2fNamespaceErrorV1::new(
            PocoNodeG2fNamespaceErrorCodeV1::Io,
            format!("stat child descriptor after read: {error}"),
        )
    })?;
    validate_file_metadata(&metadata_after)?;
    if metadata_identity(&metadata_before) != metadata_identity(&metadata_after) {
        return namespace_error(
            PocoNodeG2fNamespaceErrorCodeV1::TornRead,
            "child metadata changed while reading",
        );
    }
    Ok(bytes)
}

fn stable_file_snapshot(
    file: &File,
    max_bytes: u64,
) -> NamespaceResultV1<PocoNodeG2fFileIdentityV1> {
    let first = read_bounded_stable(file, max_bytes)?;
    let second = read_bounded_stable(file, max_bytes)?;
    if first != second {
        return namespace_error(
            PocoNodeG2fNamespaceErrorCodeV1::TornRead,
            "child bytes changed between stable descriptor samples",
        );
    }
    let metadata = file.metadata().map_err(|error| {
        PocoNodeG2fNamespaceErrorV1::new(
            PocoNodeG2fNamespaceErrorCodeV1::Io,
            format!("stat child descriptor for identity: {error}"),
        )
    })?;
    validate_file_metadata(&metadata)?;
    Ok(PocoNodeG2fFileIdentityV1::from_metadata_and_bytes(
        &metadata, &first,
    ))
}

fn reject_sidecars_for_root(root: &Path, base_name: &str) -> NamespaceResultV1<()> {
    for suffix in ["-wal", "-shm", "-journal"] {
        let path = root.join(format!("{base_name}{suffix}"));
        match fs::symlink_metadata(&path) {
            Ok(_) => {
                return namespace_error(
                    PocoNodeG2fNamespaceErrorCodeV1::SidecarPresent,
                    format!("SQLite sidecar/WAL exists: {}", path.display()),
                )
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                return io_namespace(
                    PocoNodeG2fNamespaceErrorCodeV1::Io,
                    "inspect SQLite sidecar",
                    error,
                )
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        fs::OpenOptions,
        io::Write,
        os::unix::fs::{symlink, OpenOptionsExt, PermissionsExt},
    };

    fn secure_namespace() -> tempfile::TempDir {
        let parent = tempfile::tempdir().expect("temporary parent");
        fs::set_permissions(parent.path(), fs::Permissions::from_mode(0o700))
            .expect("private parent");
        parent
    }

    fn make_root(parent: &tempfile::TempDir) -> PathBuf {
        let root = parent.path().join("namespace");
        fs::create_dir(&root).expect("namespace");
        fs::set_permissions(&root, fs::Permissions::from_mode(NAMESPACE_MODE_V1 as u32))
            .expect("namespace mode");
        root
    }

    fn make_file(root: &Path, name: &str, bytes: &[u8]) -> PathBuf {
        let path = root.join(name);
        let mut options = OpenOptions::new();
        options
            .read(true)
            .write(true)
            .create_new(true)
            .mode(FILE_MODE_V1);
        let mut file = options.open(&path).expect("private child");
        file.write_all(bytes).expect("child bytes");
        file.sync_all().expect("child sync");
        path
    }

    fn anchor_pair(
        guard: &PocoNodeG2fNamespaceGuardV1,
        handle: &PocoNodeG2fFileHandleV1,
    ) -> (PocoNodeG2fAnchorRecordV1, PocoNodeG2fAnchorRecordV1) {
        let initial = PocoNodeG2fAnchorRecordV1::initial(
            [1; 32],
            7,
            0,
            [2; 32],
            [3; 32],
            guard.identity(),
            handle.identity(),
        )
        .expect("initial anchor");
        let successor = PocoNodeG2fAnchorRecordV1::new(
            [1; 32],
            1,
            8,
            0,
            [2; 32],
            [3; 32],
            guard.identity(),
            handle.identity(),
            initial.checksum(),
        )
        .expect("successor anchor");
        (initial, successor)
    }

    #[test]
    fn openat_guard_retains_descriptor_and_reads_private_child() {
        let parent = secure_namespace();
        let root = make_root(&parent);
        let path = make_file(&root, "state.db", b"candidate");
        let guard = PocoNodeG2fNamespaceGuardV1::open_existing(&root).expect("guard");
        let handle = guard
            .openat_regular_default("state.db")
            .expect("openat child");
        assert_eq!(handle.read_bytes().expect("read bytes"), b"candidate");
        assert_eq!(handle.identity().inode(), fs::metadata(path).unwrap().ino());
        assert_eq!(guard.identity().mode(), NAMESPACE_MODE_V1);
    }

    #[test]
    fn same_uid_namespace_rename_is_poisoned_by_retained_descriptor() {
        let parent = secure_namespace();
        let root = make_root(&parent);
        make_file(&root, "state.db", b"candidate");
        let guard = PocoNodeG2fNamespaceGuardV1::open_existing(&root).expect("guard");
        let moved = parent.path().join("moved");
        fs::rename(&root, &moved).expect("rename original namespace");
        fs::create_dir(&root).expect("replacement namespace");
        fs::set_permissions(&root, fs::Permissions::from_mode(NAMESPACE_MODE_V1 as u32))
            .expect("replacement mode");
        let error = guard
            .revalidate()
            .expect_err("same-uid rename must fail closed");
        assert_eq!(
            error.code(),
            PocoNodeG2fNamespaceErrorCodeV1::IdentityChanged
        );
    }

    #[test]
    fn copied_child_path_is_rejected_even_when_bytes_match() {
        let parent = secure_namespace();
        let root = make_root(&parent);
        let original = make_file(&root, "state.db", b"candidate");
        let guard = PocoNodeG2fNamespaceGuardV1::open_existing(&root).expect("guard");
        let handle = guard.openat_regular_default("state.db").expect("handle");
        let displaced = root.join("state.db.old");
        fs::rename(&original, &displaced).expect("displace original");
        make_file(&root, "state.db", b"candidate");
        let error = handle
            .revalidate()
            .expect_err("copied path must fail closed");
        assert_eq!(
            error.code(),
            PocoNodeG2fNamespaceErrorCodeV1::IdentityChanged
        );
    }

    #[test]
    fn same_inode_torn_rewrite_is_rejected_by_content_hash() {
        let parent = secure_namespace();
        let root = make_root(&parent);
        let path = make_file(&root, "state.db", b"candidate");
        let guard = PocoNodeG2fNamespaceGuardV1::open_existing(&root).expect("guard");
        let handle = guard.openat_regular_default("state.db").expect("handle");
        let mut writer = OpenOptions::new().write(true).open(&path).expect("writer");
        writer.write_all(b"mutated!").expect("same-inode rewrite");
        writer.sync_all().expect("rewrite sync");
        let error = handle
            .revalidate()
            .expect_err("same-inode rewrite must fail closed");
        assert!(matches!(
            error.code(),
            PocoNodeG2fNamespaceErrorCodeV1::FileChanged
                | PocoNodeG2fNamespaceErrorCodeV1::TornRead
        ));
    }

    #[test]
    fn sidecar_and_wal_mutants_fail_before_and_after_open() {
        let parent = secure_namespace();
        let root = make_root(&parent);
        make_file(&root, "state.db", b"candidate");
        fs::write(root.join("state.db-wal"), b"wal").expect("WAL mutant");
        let guard = PocoNodeG2fNamespaceGuardV1::open_existing(&root).expect("guard");
        let error = guard
            .openat_regular_default("state.db")
            .expect_err("WAL must fail closed");
        assert_eq!(
            error.code(),
            PocoNodeG2fNamespaceErrorCodeV1::SidecarPresent
        );

        fs::remove_file(root.join("state.db-wal")).expect("remove WAL mutant");
        let handle = guard.openat_regular_default("state.db").expect("handle");
        fs::write(root.join("state.db-shm"), b"shm").expect("SHM mutant");
        let error = handle.revalidate().expect_err("late SHM must fail closed");
        assert_eq!(
            error.code(),
            PocoNodeG2fNamespaceErrorCodeV1::SidecarPresent
        );
    }

    #[test]
    fn anchor_codec_and_successor_are_strict_and_monotonic() {
        let parent = secure_namespace();
        let root = make_root(&parent);
        make_file(&root, "state.db", b"candidate");
        let guard = PocoNodeG2fNamespaceGuardV1::open_existing(&root).expect("guard");
        let handle = guard.openat_regular_default("state.db").expect("handle");
        let (initial, successor) = anchor_pair(&guard, &handle);
        assert_eq!(
            PocoNodeG2fAnchorRecordV1::decode_canonical_exact(&initial.encode_canonical()),
            Ok(initial)
        );
        successor
            .validate_successor_of(&initial)
            .expect("successor");

        let mut rollback = successor;
        rollback.body.generation = 0;
        assert_eq!(
            rollback
                .validate_successor_of(&initial)
                .expect_err("generation rollback mutant")
                .code(),
            PocoNodeG2fAnchorErrorCodeV1::GenerationRollback
        );

        let mut tampered = initial.encode_canonical();
        tampered[24] ^= 1;
        assert_eq!(
            PocoNodeG2fAnchorRecordV1::decode_canonical_exact(&tampered)
                .expect_err("checksum mutant")
                .code(),
            PocoNodeG2fAnchorErrorCodeV1::ChecksumMismatch
        );
    }

    #[test]
    fn anchor_rejects_identity_rotation_and_validator_set_change_without_epoch() {
        let parent = secure_namespace();
        let root = make_root(&parent);
        make_file(&root, "state.db", b"candidate");
        let guard = PocoNodeG2fNamespaceGuardV1::open_existing(&root).expect("guard");
        let handle = guard.openat_regular_default("state.db").expect("handle");
        let (initial, successor) = anchor_pair(&guard, &handle);
        let mut validator_mutant = successor;
        validator_mutant.body.validator_set_hash = [9; 32];
        assert_eq!(
            validator_mutant
                .validate_successor_of(&initial)
                .expect_err("validator-set mutant")
                .code(),
            PocoNodeG2fAnchorErrorCodeV1::ValidatorSetMismatch
        );
        let mut file_mutant = successor;
        file_mutant.body.file_identity.content_hash[0] ^= 1;
        assert_eq!(
            file_mutant
                .validate_successor_of(&initial)
                .expect_err("file identity mutant")
                .code(),
            PocoNodeG2fAnchorErrorCodeV1::FileMismatch
        );
    }

    #[derive(Default)]
    struct MemoryAnchor {
        value: Option<PocoNodeG2fAnchorRecordV1>,
    }

    impl PocoNodeG2fExternalMonotonicAnchorV1 for MemoryAnchor {
        fn load(&mut self, scope: [u8; 32]) -> AnchorResultV1<Option<PocoNodeG2fAnchorRecordV1>> {
            if self.value.is_some_and(|value| value.scope() != scope) {
                return anchor_error(
                    PocoNodeG2fAnchorErrorCodeV1::ScopeMismatch,
                    "memory anchor scope mismatch",
                );
            }
            Ok(self.value)
        }

        fn compare_and_advance(
            &mut self,
            expected: Option<PocoNodeG2fAnchorRecordV1>,
            target: PocoNodeG2fAnchorRecordV1,
        ) -> AnchorResultV1<()> {
            if self.value != expected {
                return anchor_error(
                    PocoNodeG2fAnchorErrorCodeV1::CompareFailed,
                    "memory anchor compare failed",
                );
            }
            if let Some(current) = self.value {
                target.validate_successor_of(&current)?;
            } else if target.generation() != 0 {
                return anchor_error(
                    PocoNodeG2fAnchorErrorCodeV1::CompareFailed,
                    "memory anchor initial generation is not zero",
                );
            }
            self.value = Some(target);
            Ok(())
        }
    }

    #[test]
    fn bound_anchor_cas_requires_fresh_identity_and_external_successor() {
        let parent = secure_namespace();
        let root = make_root(&parent);
        make_file(&root, "state.db", b"candidate");
        let guard = PocoNodeG2fNamespaceGuardV1::open_existing(&root).expect("guard");
        let handle = guard.openat_regular_default("state.db").expect("handle");
        let (initial, successor) = anchor_pair(&guard, &handle);
        let mut backend = MemoryAnchor::default();
        compare_and_advance_bound_v1(&mut backend, None, initial, &guard, &handle)
            .expect("initial external CAS");
        compare_and_advance_bound_v1(&mut backend, Some(initial), successor, &guard, &handle)
            .expect("successor external CAS");
        assert_eq!(backend.load([1; 32]).unwrap(), Some(successor));
    }

    #[test]
    fn sidecar_name_and_symlink_mutants_are_rejected() {
        let parent = secure_namespace();
        let root = make_root(&parent);
        make_file(&root, "state.db", b"candidate");
        let outside = parent.path().join("outside");
        fs::write(&outside, b"outside").expect("outside");
        symlink(&outside, root.join("link.db")).expect("symlink mutant");
        let guard = PocoNodeG2fNamespaceGuardV1::open_existing(&root).expect("guard");
        let error = guard
            .openat_regular_default("link.db")
            .expect_err("symlink child must fail closed");
        assert_eq!(error.code(), PocoNodeG2fNamespaceErrorCodeV1::Symlink);
        let error = guard
            .openat_regular_default("state.db-wal")
            .expect_err("sidecar child name must fail closed");
        assert_eq!(
            error.code(),
            PocoNodeG2fNamespaceErrorCodeV1::InvalidComponent
        );
    }

    #[test]
    fn unbounded_file_size_mutant_is_rejected_before_openat() {
        let parent = secure_namespace();
        let root = make_root(&parent);
        make_file(&root, "state.db", b"candidate");
        let guard = PocoNodeG2fNamespaceGuardV1::open_existing(&root).expect("guard");
        let error = guard
            .openat_regular("state.db", DEFAULT_MAX_FILE_BYTES_V1 + 1)
            .expect_err("unbounded max_bytes must fail closed");
        assert_eq!(error.code(), PocoNodeG2fNamespaceErrorCodeV1::TooLarge);
    }
}
