#![cfg(target_os = "linux")]

use std::{
    ffi::OsString,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use fs2::FileExt;
use sha2::{Digest, Sha256};
use trnm_consensus_signer_journal::{
    ExternalMonotonicWatermarkV0, ExternalWatermarkErrorV0, SignerWatermarkV0,
};

const RECORD_MAGIC_V0: &[u8; 8] = b"TRNMWM0\0";
const RECORD_CHECKSUM_DOMAIN_V0: &[u8] = b"trnm.poco-node.recovery-process-watermark.record.v0";
const RECORD_BODY_BYTES_V0: usize = 8 + 32 + 32 + 8 + 32;
const RECORD_BYTES_V0: usize = RECORD_BODY_BYTES_V0 + 32;
const PRIVATE_DIRECTORY_MODE_V0: u32 = 0o700;
const PRIVATE_FILE_MODE_V0: u32 = 0o600;
const TEMPORARY_NAME_ATTEMPTS_V0: u64 = 128;

static NEXT_TEMPORARY_FILE_V0: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileIdentityV0 {
    device: u64,
    inode: u64,
    owner: u32,
    mode: u32,
    links: u64,
}

impl FileIdentityV0 {
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

/// Process-test-only durable adapter for the signer journal watermark trait.
///
/// The record lives in a private namespace separate from the signer journal.
/// Its stable lock sidecar is never replaced; record advances use a same-
/// directory temporary file, `fsync`, atomic rename, and parent-directory
/// `fsync`. This is enough to carry the exact watermark across the G1e child
/// process SIGKILL/restart tests. It is not an independently administered
/// production monotonic store and does not resist whole-namespace rollback,
/// cloning, hostile same-EUID replacement, device write-cache loss, or power
/// failure outside the local Linux filesystem contract.
pub(crate) struct RecoveryProcessFileWatermarkV0 {
    record_path: PathBuf,
    lock_path: PathBuf,
    directory_path: PathBuf,
    lock_file: File,
    directory_file: File,
    lock_identity: FileIdentityV0,
    directory_identity: FileIdentityV0,
    bound_scope: Option<[u8; 32]>,
    observed_claim: bool,
    owner_pid: u32,
}

impl RecoveryProcessFileWatermarkV0 {
    pub(crate) fn new(record_path: impl AsRef<Path>) -> Result<Self, ExternalWatermarkErrorV0> {
        let record_path = record_path.as_ref();
        if !record_path.is_absolute() || record_path.file_name().is_none() {
            return Err(ExternalWatermarkErrorV0::InvalidPersistedState);
        }
        let supplied_parent = record_path
            .parent()
            .ok_or(ExternalWatermarkErrorV0::InvalidPersistedState)?;
        let directory_path =
            fs::canonicalize(supplied_parent).map_err(|_| ExternalWatermarkErrorV0::Unavailable)?;
        let directory_metadata = fs::symlink_metadata(&directory_path)
            .map_err(|_| ExternalWatermarkErrorV0::Unavailable)?;
        validate_private_directory(&directory_metadata)?;
        let directory_file =
            File::open(&directory_path).map_err(|_| ExternalWatermarkErrorV0::Unavailable)?;
        let directory_handle_metadata = directory_file
            .metadata()
            .map_err(|_| ExternalWatermarkErrorV0::Unavailable)?;
        validate_private_directory(&directory_handle_metadata)?;
        let directory_identity = FileIdentityV0::from_metadata(&directory_handle_metadata);
        if FileIdentityV0::from_metadata(&directory_metadata) != directory_identity {
            return Err(ExternalWatermarkErrorV0::InvalidPersistedState);
        }

        let record_path = directory_path.join(
            record_path
                .file_name()
                .ok_or(ExternalWatermarkErrorV0::InvalidPersistedState)?,
        );
        let lock_path = path_with_suffix(&record_path, ".lock-v0")?;
        let (lock_file, created_lock) = open_or_create_lock_file(&lock_path)?;
        FileExt::try_lock_exclusive(&lock_file)
            .map_err(|_| ExternalWatermarkErrorV0::Unavailable)?;
        let lock_metadata = lock_file
            .metadata()
            .map_err(|_| ExternalWatermarkErrorV0::Unavailable)?;
        validate_private_regular_file(&lock_metadata, Some(0), directory_identity.owner)?;
        let lock_identity = FileIdentityV0::from_metadata(&lock_metadata);
        validate_path_matches_file(&lock_path, &lock_file, lock_identity, Some(0))?;
        if created_lock {
            lock_file
                .sync_all()
                .map_err(|_| ExternalWatermarkErrorV0::Unavailable)?;
            directory_file
                .sync_all()
                .map_err(|_| ExternalWatermarkErrorV0::Unavailable)?;
        }

        let initial = read_record_if_present(&record_path, directory_identity.owner)?;
        let mut store = Self {
            record_path,
            lock_path,
            directory_path,
            lock_file,
            directory_file,
            lock_identity,
            directory_identity,
            bound_scope: initial.map(|watermark| watermark.scope()),
            observed_claim: initial.is_some(),
            owner_pid: std::process::id(),
        };
        store.ensure_environment()?;
        Ok(store)
    }

    pub(crate) fn path(&self) -> &Path {
        self.record_path.as_path()
    }

    pub(crate) fn current_v0(
        &mut self,
    ) -> Result<Option<SignerWatermarkV0>, ExternalWatermarkErrorV0> {
        self.read_current()
    }

    fn ensure_environment(&mut self) -> Result<(), ExternalWatermarkErrorV0> {
        if self.owner_pid != std::process::id() {
            return Err(ExternalWatermarkErrorV0::InvalidPersistedState);
        }
        let directory_handle_metadata = self
            .directory_file
            .metadata()
            .map_err(|_| ExternalWatermarkErrorV0::Unavailable)?;
        validate_private_directory(&directory_handle_metadata)?;
        if FileIdentityV0::from_metadata(&directory_handle_metadata) != self.directory_identity {
            return Err(ExternalWatermarkErrorV0::InvalidPersistedState);
        }
        let directory_path_metadata = fs::symlink_metadata(&self.directory_path)
            .map_err(|_| ExternalWatermarkErrorV0::Unavailable)?;
        validate_private_directory(&directory_path_metadata)?;
        if FileIdentityV0::from_metadata(&directory_path_metadata) != self.directory_identity {
            return Err(ExternalWatermarkErrorV0::InvalidPersistedState);
        }
        validate_path_matches_file(
            &self.lock_path,
            &self.lock_file,
            self.lock_identity,
            Some(0),
        )
    }

    fn read_current(&mut self) -> Result<Option<SignerWatermarkV0>, ExternalWatermarkErrorV0> {
        self.ensure_environment()?;
        let current = read_record_if_present(&self.record_path, self.directory_identity.owner)?;
        if current.is_none() && self.observed_claim {
            return Err(ExternalWatermarkErrorV0::InvalidPersistedState);
        }
        if let Some(current) = current {
            if self
                .bound_scope
                .is_some_and(|scope| scope != current.scope())
            {
                return Err(ExternalWatermarkErrorV0::InvalidPersistedState);
            }
            self.bound_scope = Some(current.scope());
            self.observed_claim = true;
        }
        self.ensure_environment()?;
        Ok(current)
    }

    fn persist_target(
        &mut self,
        target: SignerWatermarkV0,
    ) -> Result<(), ExternalWatermarkErrorV0> {
        self.ensure_environment()?;
        let bytes = encode_record(target);
        let (temporary_path, mut temporary_file) =
            create_temporary_file(&self.record_path, self.directory_identity.owner)?;
        let write_result = (|| {
            temporary_file
                .write_all(&bytes)
                .map_err(|_| ExternalWatermarkErrorV0::Unavailable)?;
            temporary_file
                .sync_all()
                .map_err(|_| ExternalWatermarkErrorV0::Unavailable)?;
            let temporary_metadata = temporary_file
                .metadata()
                .map_err(|_| ExternalWatermarkErrorV0::Unavailable)?;
            validate_private_regular_file(
                &temporary_metadata,
                Some(RECORD_BYTES_V0 as u64),
                self.directory_identity.owner,
            )?;
            self.ensure_environment()?;
            fs::rename(&temporary_path, &self.record_path)
                .map_err(|_| ExternalWatermarkErrorV0::Unavailable)?;
            self.directory_file
                .sync_all()
                .map_err(|_| ExternalWatermarkErrorV0::Unavailable)?;
            let readback =
                read_record_if_present(&self.record_path, self.directory_identity.owner)?
                    .ok_or(ExternalWatermarkErrorV0::InvalidPersistedState)?;
            if readback != target {
                return Err(ExternalWatermarkErrorV0::InvalidPersistedState);
            }
            self.ensure_environment()?;
            Ok(())
        })();
        if write_result.is_err() {
            let _ = fs::remove_file(&temporary_path);
        }
        write_result
    }
}

impl ExternalMonotonicWatermarkV0 for RecoveryProcessFileWatermarkV0 {
    fn load(
        &mut self,
        scope: [u8; 32],
    ) -> Result<Option<SignerWatermarkV0>, ExternalWatermarkErrorV0> {
        if scope == [0; 32] || self.bound_scope.is_some_and(|bound| bound != scope) {
            return Err(ExternalWatermarkErrorV0::InvalidPersistedState);
        }
        let current = self.read_current()?;
        if current.is_some_and(|watermark| watermark.scope() != scope) {
            return Err(ExternalWatermarkErrorV0::InvalidPersistedState);
        }
        self.bound_scope = Some(scope);
        Ok(current)
    }

    fn compare_and_advance(
        &mut self,
        expected: Option<SignerWatermarkV0>,
        target: SignerWatermarkV0,
    ) -> Result<(), ExternalWatermarkErrorV0> {
        if self
            .bound_scope
            .is_some_and(|scope| scope != target.scope())
        {
            return Err(ExternalWatermarkErrorV0::InvalidPersistedState);
        }
        let current = self.read_current()?;
        if current != expected {
            return Err(ExternalWatermarkErrorV0::CompareFailed);
        }
        match expected {
            None if target.sequence() == 0 => {}
            Some(source)
                if source.scope() == target.scope()
                    && source.journal_id() == target.journal_id()
                    && source.sequence().checked_add(1) == Some(target.sequence()) => {}
            Some(source) if source.sequence() == u64::MAX => {
                return Err(ExternalWatermarkErrorV0::CapacityExhausted);
            }
            _ => return Err(ExternalWatermarkErrorV0::InvalidPersistedState),
        }
        self.bound_scope = Some(target.scope());
        self.persist_target(target)?;
        self.observed_claim = true;
        Ok(())
    }
}

fn open_or_create_lock_file(path: &Path) -> Result<(File, bool), ExternalWatermarkErrorV0> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .create_new(true)
        .mode(PRIVATE_FILE_MODE_V0);
    match options.open(path) {
        Ok(file) => {
            file.set_permissions(fs::Permissions::from_mode(PRIVATE_FILE_MODE_V0))
                .map_err(|_| ExternalWatermarkErrorV0::Unavailable)?;
            Ok((file, true))
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            let metadata =
                fs::symlink_metadata(path).map_err(|_| ExternalWatermarkErrorV0::Unavailable)?;
            if metadata.file_type().is_symlink() {
                return Err(ExternalWatermarkErrorV0::InvalidPersistedState);
            }
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .open(path)
                .map_err(|_| ExternalWatermarkErrorV0::Unavailable)?;
            Ok((file, false))
        }
        Err(_) => Err(ExternalWatermarkErrorV0::Unavailable),
    }
}

fn create_temporary_file(
    record_path: &Path,
    expected_owner: u32,
) -> Result<(PathBuf, File), ExternalWatermarkErrorV0> {
    for _ in 0..TEMPORARY_NAME_ATTEMPTS_V0 {
        let nonce = NEXT_TEMPORARY_FILE_V0.fetch_add(1, Ordering::Relaxed);
        let suffix = format!(".tmp-v0-{}-{nonce}", std::process::id());
        let path = path_with_suffix(record_path, &suffix)?;
        let mut options = OpenOptions::new();
        options
            .read(true)
            .write(true)
            .create_new(true)
            .mode(PRIVATE_FILE_MODE_V0);
        match options.open(&path) {
            Ok(file) => {
                file.set_permissions(fs::Permissions::from_mode(PRIVATE_FILE_MODE_V0))
                    .map_err(|_| ExternalWatermarkErrorV0::Unavailable)?;
                let metadata = file
                    .metadata()
                    .map_err(|_| ExternalWatermarkErrorV0::Unavailable)?;
                validate_private_regular_file(&metadata, Some(0), expected_owner)?;
                return Ok((path, file));
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(_) => return Err(ExternalWatermarkErrorV0::Unavailable),
        }
    }
    Err(ExternalWatermarkErrorV0::CapacityExhausted)
}

fn read_record_if_present(
    path: &Path,
    expected_owner: u32,
) -> Result<Option<SignerWatermarkV0>, ExternalWatermarkErrorV0> {
    let path_metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(ExternalWatermarkErrorV0::Unavailable),
    };
    if path_metadata.file_type().is_symlink() {
        return Err(ExternalWatermarkErrorV0::InvalidPersistedState);
    }
    validate_private_regular_file(&path_metadata, Some(RECORD_BYTES_V0 as u64), expected_owner)?;
    let mut file = File::open(path).map_err(|_| ExternalWatermarkErrorV0::Unavailable)?;
    let handle_metadata = file
        .metadata()
        .map_err(|_| ExternalWatermarkErrorV0::Unavailable)?;
    validate_private_regular_file(
        &handle_metadata,
        Some(RECORD_BYTES_V0 as u64),
        expected_owner,
    )?;
    let identity = FileIdentityV0::from_metadata(&handle_metadata);
    if FileIdentityV0::from_metadata(&path_metadata) != identity {
        return Err(ExternalWatermarkErrorV0::InvalidPersistedState);
    }
    let mut bytes = [0_u8; RECORD_BYTES_V0];
    file.read_exact(&mut bytes)
        .map_err(|_| ExternalWatermarkErrorV0::InvalidPersistedState)?;
    let mut trailing = [0_u8; 1];
    match file.read(&mut trailing) {
        Ok(0) => {}
        Ok(_) => return Err(ExternalWatermarkErrorV0::InvalidPersistedState),
        Err(_) => return Err(ExternalWatermarkErrorV0::Unavailable),
    }
    validate_path_matches_file(path, &file, identity, Some(RECORD_BYTES_V0 as u64))?;
    decode_record(&bytes).map(Some)
}

fn encode_record(watermark: SignerWatermarkV0) -> [u8; RECORD_BYTES_V0] {
    let mut bytes = [0_u8; RECORD_BYTES_V0];
    let mut cursor = 0;
    bytes[cursor..cursor + 8].copy_from_slice(RECORD_MAGIC_V0);
    cursor += 8;
    bytes[cursor..cursor + 32].copy_from_slice(&watermark.scope());
    cursor += 32;
    bytes[cursor..cursor + 32].copy_from_slice(&watermark.journal_id());
    cursor += 32;
    bytes[cursor..cursor + 8].copy_from_slice(&watermark.sequence().to_be_bytes());
    cursor += 8;
    bytes[cursor..cursor + 32].copy_from_slice(&watermark.chain_checksum());
    cursor += 32;
    debug_assert_eq!(cursor, RECORD_BODY_BYTES_V0);
    let checksum = record_checksum(&bytes[..RECORD_BODY_BYTES_V0]);
    bytes[RECORD_BODY_BYTES_V0..].copy_from_slice(&checksum);
    bytes
}

fn decode_record(
    bytes: &[u8; RECORD_BYTES_V0],
) -> Result<SignerWatermarkV0, ExternalWatermarkErrorV0> {
    if &bytes[..8] != RECORD_MAGIC_V0 {
        return Err(ExternalWatermarkErrorV0::InvalidPersistedState);
    }
    let expected_checksum = record_checksum(&bytes[..RECORD_BODY_BYTES_V0]);
    if bytes[RECORD_BODY_BYTES_V0..] != expected_checksum {
        return Err(ExternalWatermarkErrorV0::InvalidPersistedState);
    }
    let mut scope = [0_u8; 32];
    scope.copy_from_slice(&bytes[8..40]);
    let mut journal_id = [0_u8; 32];
    journal_id.copy_from_slice(&bytes[40..72]);
    let mut sequence_bytes = [0_u8; 8];
    sequence_bytes.copy_from_slice(&bytes[72..80]);
    let mut chain_checksum = [0_u8; 32];
    chain_checksum.copy_from_slice(&bytes[80..112]);
    SignerWatermarkV0::from_persisted_parts(
        scope,
        journal_id,
        u64::from_be_bytes(sequence_bytes),
        chain_checksum,
    )
}

fn record_checksum(body: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(RECORD_CHECKSUM_DOMAIN_V0);
    hasher.update((body.len() as u64).to_be_bytes());
    hasher.update(body);
    hasher.finalize().into()
}

fn validate_private_directory(metadata: &fs::Metadata) -> Result<(), ExternalWatermarkErrorV0> {
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.mode() & 0o777 != PRIVATE_DIRECTORY_MODE_V0
    {
        return Err(ExternalWatermarkErrorV0::InvalidPersistedState);
    }
    Ok(())
}

fn validate_private_regular_file(
    metadata: &fs::Metadata,
    expected_length: Option<u64>,
    expected_owner: u32,
) -> Result<(), ExternalWatermarkErrorV0> {
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != expected_owner
        || metadata.nlink() != 1
        || metadata.mode() & 0o777 != PRIVATE_FILE_MODE_V0
        || expected_length.is_some_and(|length| metadata.len() != length)
    {
        return Err(ExternalWatermarkErrorV0::InvalidPersistedState);
    }
    Ok(())
}

fn validate_path_matches_file(
    path: &Path,
    file: &File,
    expected_identity: FileIdentityV0,
    expected_length: Option<u64>,
) -> Result<(), ExternalWatermarkErrorV0> {
    let handle_metadata = file
        .metadata()
        .map_err(|_| ExternalWatermarkErrorV0::Unavailable)?;
    validate_private_regular_file(&handle_metadata, expected_length, expected_identity.owner)?;
    if FileIdentityV0::from_metadata(&handle_metadata) != expected_identity {
        return Err(ExternalWatermarkErrorV0::InvalidPersistedState);
    }
    let path_metadata =
        fs::symlink_metadata(path).map_err(|_| ExternalWatermarkErrorV0::Unavailable)?;
    if path_metadata.file_type().is_symlink() {
        return Err(ExternalWatermarkErrorV0::InvalidPersistedState);
    }
    validate_private_regular_file(&path_metadata, expected_length, expected_identity.owner)?;
    if FileIdentityV0::from_metadata(&path_metadata) != expected_identity {
        return Err(ExternalWatermarkErrorV0::InvalidPersistedState);
    }
    Ok(())
}

fn path_with_suffix(path: &Path, suffix: &str) -> Result<PathBuf, ExternalWatermarkErrorV0> {
    let file_name = path
        .file_name()
        .ok_or(ExternalWatermarkErrorV0::InvalidPersistedState)?;
    let mut suffixed = OsString::from(file_name);
    suffixed.push(suffix);
    Ok(path.with_file_name(suffixed))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    const SCOPE_V0: [u8; 32] = [0x11; 32];
    const JOURNAL_V0: [u8; 32] = [0x22; 32];

    fn protected_root_v0() -> TempDir {
        let root = TempDir::new().expect("create watermark test root");
        fs::set_permissions(
            root.path(),
            fs::Permissions::from_mode(PRIVATE_DIRECTORY_MODE_V0),
        )
        .expect("protect watermark test root");
        root
    }

    fn watermark_v0(sequence: u64) -> SignerWatermarkV0 {
        let checksum_byte = u8::try_from(sequence)
            .expect("test watermark sequence fits in one byte")
            .saturating_add(1);
        SignerWatermarkV0::from_persisted_parts(SCOPE_V0, JOURNAL_V0, sequence, [checksum_byte; 32])
            .expect("valid test watermark")
    }

    #[test]
    fn file_watermark_excludes_live_owner_and_enforces_exact_cas() {
        let root = protected_root_v0();
        let path = root.path().join("watermark.v0");
        let initial = watermark_v0(0);
        let successor = watermark_v0(1);
        let mut store = RecoveryProcessFileWatermarkV0::new(&path).expect("open new watermark");
        assert_eq!(store.load(SCOPE_V0).expect("load empty watermark"), None);
        store
            .compare_and_advance(None, initial)
            .expect("claim exact initial watermark");
        assert_eq!(
            store.load(SCOPE_V0).expect("load initial watermark"),
            Some(initial)
        );
        assert!(matches!(
            RecoveryProcessFileWatermarkV0::new(&path),
            Err(ExternalWatermarkErrorV0::Unavailable)
        ));
        drop(store);

        let mut reopened =
            RecoveryProcessFileWatermarkV0::new(&path).expect("reopen persisted watermark");
        assert_eq!(
            reopened
                .compare_and_advance(None, successor)
                .expect_err("stale expected head must fail"),
            ExternalWatermarkErrorV0::CompareFailed
        );
        reopened
            .compare_and_advance(Some(initial), successor)
            .expect("advance exact successor");
        assert_eq!(
            reopened.load(SCOPE_V0).expect("load successor watermark"),
            Some(successor)
        );

        let wrong_journal =
            SignerWatermarkV0::from_persisted_parts(SCOPE_V0, [0x33; 32], 2, [0x44; 32])
                .expect("structurally valid mismatched journal watermark");
        assert_eq!(
            reopened
                .compare_and_advance(Some(successor), wrong_journal)
                .expect_err("journal switch must fail"),
            ExternalWatermarkErrorV0::InvalidPersistedState
        );
    }

    #[test]
    fn file_watermark_rejects_checksum_corruption_and_trailing_bytes() {
        for mutation in ["checksum", "trailing"] {
            let root = protected_root_v0();
            let path = root.path().join("watermark.v0");
            let mut store = RecoveryProcessFileWatermarkV0::new(&path).expect("open new watermark");
            store
                .compare_and_advance(None, watermark_v0(0))
                .expect("persist initial watermark");
            drop(store);

            let mut bytes = fs::read(&path).expect("read persisted watermark bytes");
            match mutation {
                "checksum" => bytes[RECORD_BODY_BYTES_V0] ^= 0x80,
                "trailing" => bytes.push(0),
                _ => unreachable!("fixed mutation set"),
            }
            fs::write(&path, bytes).expect("write malformed watermark bytes");
            assert!(matches!(
                RecoveryProcessFileWatermarkV0::new(&path),
                Err(ExternalWatermarkErrorV0::InvalidPersistedState)
            ));
        }
    }
}
