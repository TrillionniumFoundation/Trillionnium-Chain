use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

use ed25519_dalek::{Signer, SigningKey};
use fs2::FileExt;
use sha2::{Digest, Sha256};
use trnm_consensus_signer_journal::{
    ExternalMonotonicWatermarkV0, ExternalWatermarkErrorV0, SignatureProducerErrorV0,
    SignatureProducerV0, SignatureRequestV0, SignerWatermarkV0,
};
use trnm_consensus_types::SignatureBytes;

const WATERMARK_MAGIC: &[u8; 8] = b"TRNMG3W1";
const WATERMARK_DOMAIN: &[u8] = b"trnm.poco-g3.lab-watermark.record.v1";
const WATERMARK_RECORD_BODY_BYTES: usize = 8 + 32 + 32 + 8 + 32;
const WATERMARK_RECORD_BYTES: usize = WATERMARK_RECORD_BODY_BYTES + 32;

/// Deterministic RFC 8032 producer owned by one laboratory validator process.
///
/// Ed25519 is deterministic, so exact replay of one fingerprint yields the
/// same signature. The producer has no API that accepts caller-selected bytes:
/// only the signer's journal-issued root can cross this boundary.
pub struct LabEd25519SignatureProducer {
    key: SigningKey,
}

impl LabEd25519SignatureProducer {
    pub fn new(key: SigningKey) -> Self {
        Self { key }
    }
}

impl SignatureProducerV0 for LabEd25519SignatureProducer {
    fn sign(
        &mut self,
        request: SignatureRequestV0<'_>,
    ) -> Result<SignatureBytes, SignatureProducerErrorV0> {
        let signature = self.key.sign(request.signing_root().as_bytes()).to_bytes();
        Ok(SignatureBytes::from_array(signature))
    }
}

/// Local-filesystem monotonic watermark for the single-LAN laboratory run.
///
/// The stable lock file and record live outside the signer SQLite namespace.
/// Updates use a same-directory `0600` temporary file, fsync, atomic rename,
/// and parent-directory fsync. This proves process restart/namespace behavior
/// on the measured Linux hosts, but is not an independently administered HSM,
/// TPM, remote CAS, or whole-machine rollback authority.
pub struct LabFileWatermark {
    directory_path: PathBuf,
    record_path: PathBuf,
    lock_path: PathBuf,
    directory: File,
    lock: File,
}

impl LabFileWatermark {
    pub fn open(record_path: impl AsRef<Path>) -> Result<Self, ExternalWatermarkErrorV0> {
        let supplied = record_path.as_ref();
        if !supplied.is_absolute() || supplied.file_name().is_none() {
            return Err(ExternalWatermarkErrorV0::InvalidPersistedState);
        }
        let parent = supplied
            .parent()
            .ok_or(ExternalWatermarkErrorV0::InvalidPersistedState)?;
        let parent = fs::canonicalize(parent).map_err(|_| ExternalWatermarkErrorV0::Unavailable)?;
        let metadata =
            fs::symlink_metadata(&parent).map_err(|_| ExternalWatermarkErrorV0::Unavailable)?;
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err(ExternalWatermarkErrorV0::InvalidPersistedState);
        }
        let record_path = parent.join(
            supplied
                .file_name()
                .ok_or(ExternalWatermarkErrorV0::InvalidPersistedState)?,
        );
        let lock_path = record_path.with_extension("lock-v1");
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&lock_path)
            .map_err(|_| ExternalWatermarkErrorV0::Unavailable)?;
        if lock
            .metadata()
            .map_err(|_| ExternalWatermarkErrorV0::Unavailable)?
            .permissions()
            .mode()
            & 0o777
            != 0o600
        {
            return Err(ExternalWatermarkErrorV0::InvalidPersistedState);
        }
        lock.try_lock_exclusive()
            .map_err(|_| ExternalWatermarkErrorV0::Unavailable)?;
        let directory = File::open(&parent).map_err(|_| ExternalWatermarkErrorV0::Unavailable)?;
        let value = Self {
            directory_path: parent,
            record_path,
            lock_path,
            directory,
            lock,
        };
        value.ensure_paths()?;
        let _ = value.read_record()?;
        Ok(value)
    }

    pub fn record_path(&self) -> &Path {
        &self.record_path
    }

    fn ensure_paths(&self) -> Result<(), ExternalWatermarkErrorV0> {
        let directory_path_metadata = fs::symlink_metadata(&self.directory_path)
            .map_err(|_| ExternalWatermarkErrorV0::Unavailable)?;
        let directory_handle_metadata = self
            .directory
            .metadata()
            .map_err(|_| ExternalWatermarkErrorV0::Unavailable)?;
        if directory_path_metadata.file_type().is_symlink()
            || !directory_path_metadata.is_dir()
            || directory_path_metadata.permissions().mode() & 0o077 != 0
            || directory_path_metadata.dev() != directory_handle_metadata.dev()
            || directory_path_metadata.ino() != directory_handle_metadata.ino()
        {
            return Err(ExternalWatermarkErrorV0::InvalidPersistedState);
        }
        let lock_metadata = fs::symlink_metadata(&self.lock_path)
            .map_err(|_| ExternalWatermarkErrorV0::Unavailable)?;
        if lock_metadata.file_type().is_symlink()
            || !lock_metadata.is_file()
            || lock_metadata.permissions().mode() & 0o777 != 0o600
            || lock_metadata.nlink() != 1
            || lock_metadata.uid() != directory_path_metadata.uid()
        {
            return Err(ExternalWatermarkErrorV0::InvalidPersistedState);
        }
        let handle_metadata = self
            .lock
            .metadata()
            .map_err(|_| ExternalWatermarkErrorV0::Unavailable)?;
        if handle_metadata.dev() != lock_metadata.dev()
            || handle_metadata.ino() != lock_metadata.ino()
            || handle_metadata.nlink() != 1
            || handle_metadata.uid() != directory_path_metadata.uid()
            || handle_metadata.len() != lock_metadata.len()
        {
            return Err(ExternalWatermarkErrorV0::InvalidPersistedState);
        }
        Ok(())
    }

    fn read_record(&self) -> Result<Option<SignerWatermarkV0>, ExternalWatermarkErrorV0> {
        self.ensure_paths()?;
        let metadata = match fs::symlink_metadata(&self.record_path) {
            Ok(value) => value,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(ExternalWatermarkErrorV0::Unavailable),
        };
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(ExternalWatermarkErrorV0::InvalidPersistedState);
        }
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&self.record_path)
            .map_err(|_| ExternalWatermarkErrorV0::Unavailable)?;
        let handle_metadata = file
            .metadata()
            .map_err(|_| ExternalWatermarkErrorV0::Unavailable)?;
        let directory_metadata = self
            .directory
            .metadata()
            .map_err(|_| ExternalWatermarkErrorV0::Unavailable)?;
        if metadata.permissions().mode() & 0o777 != 0o600
            || metadata.len() != WATERMARK_RECORD_BYTES as u64
            || metadata.nlink() != 1
            || metadata.uid() != directory_metadata.uid()
            || metadata.dev() != handle_metadata.dev()
            || metadata.ino() != handle_metadata.ino()
            || handle_metadata.nlink() != 1
        {
            return Err(ExternalWatermarkErrorV0::InvalidPersistedState);
        }
        let mut bytes = Vec::with_capacity(WATERMARK_RECORD_BYTES);
        file.read_to_end(&mut bytes)
            .map_err(|_| ExternalWatermarkErrorV0::Unavailable)?;
        decode_watermark(&bytes).map(Some)
    }

    fn write_record(&self, value: SignerWatermarkV0) -> Result<(), ExternalWatermarkErrorV0> {
        self.ensure_paths()?;
        let bytes = encode_watermark(value);
        let mut nonce = [0u8; 16];
        getrandom::getrandom(&mut nonce).map_err(|_| ExternalWatermarkErrorV0::Unavailable)?;
        let file_name = self
            .record_path
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or(ExternalWatermarkErrorV0::InvalidPersistedState)?;
        let temporary = self
            .record_path
            .parent()
            .ok_or(ExternalWatermarkErrorV0::InvalidPersistedState)?
            .join(format!(".{file_name}.{}.tmp", hex::encode(nonce)));
        let result = (|| {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
                .open(&temporary)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            fs::rename(&temporary, &self.record_path)?;
            self.directory.sync_all()?;
            Ok::<(), std::io::Error>(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
            return Err(ExternalWatermarkErrorV0::Unavailable);
        }
        if self.read_record()? != Some(value) {
            return Err(ExternalWatermarkErrorV0::CompareFailed);
        }
        Ok(())
    }
}

impl ExternalMonotonicWatermarkV0 for LabFileWatermark {
    fn load(
        &mut self,
        scope: [u8; 32],
    ) -> Result<Option<SignerWatermarkV0>, ExternalWatermarkErrorV0> {
        if scope == [0; 32] {
            return Err(ExternalWatermarkErrorV0::InvalidPersistedState);
        }
        let current = self.read_record()?;
        if current.is_some_and(|value| value.scope() != scope) {
            return Err(ExternalWatermarkErrorV0::CompareFailed);
        }
        Ok(current)
    }

    fn compare_and_advance(
        &mut self,
        expected: Option<SignerWatermarkV0>,
        target: SignerWatermarkV0,
    ) -> Result<(), ExternalWatermarkErrorV0> {
        let current = self.read_record()?;
        if current != expected {
            return Err(ExternalWatermarkErrorV0::CompareFailed);
        }
        match expected {
            None => {
                if target.sequence() != 0 {
                    return Err(ExternalWatermarkErrorV0::CompareFailed);
                }
            }
            Some(previous) => {
                if target.scope() != previous.scope()
                    || target.journal_id() != previous.journal_id()
                    || previous.sequence().checked_add(1) != Some(target.sequence())
                {
                    return Err(ExternalWatermarkErrorV0::CompareFailed);
                }
            }
        }
        self.write_record(target)
    }
}

fn encode_watermark(value: SignerWatermarkV0) -> [u8; WATERMARK_RECORD_BYTES] {
    let mut bytes = [0u8; WATERMARK_RECORD_BYTES];
    bytes[..8].copy_from_slice(WATERMARK_MAGIC);
    bytes[8..40].copy_from_slice(&value.scope());
    bytes[40..72].copy_from_slice(&value.journal_id());
    bytes[72..80].copy_from_slice(&value.sequence().to_be_bytes());
    bytes[80..112].copy_from_slice(&value.chain_checksum());
    let checksum = watermark_checksum(&bytes[..WATERMARK_RECORD_BODY_BYTES]);
    bytes[WATERMARK_RECORD_BODY_BYTES..].copy_from_slice(&checksum);
    bytes
}

fn decode_watermark(bytes: &[u8]) -> Result<SignerWatermarkV0, ExternalWatermarkErrorV0> {
    if bytes.len() != WATERMARK_RECORD_BYTES || &bytes[..8] != WATERMARK_MAGIC {
        return Err(ExternalWatermarkErrorV0::InvalidPersistedState);
    }
    let expected = watermark_checksum(&bytes[..WATERMARK_RECORD_BODY_BYTES]);
    if bytes[WATERMARK_RECORD_BODY_BYTES..] != expected {
        return Err(ExternalWatermarkErrorV0::InvalidPersistedState);
    }
    let scope = bytes[8..40]
        .try_into()
        .expect("fixed watermark scope range");
    let journal_id = bytes[40..72]
        .try_into()
        .expect("fixed watermark journal range");
    let sequence = u64::from_be_bytes(
        bytes[72..80]
            .try_into()
            .expect("fixed watermark sequence range"),
    );
    let chain_checksum = bytes[80..112]
        .try_into()
        .expect("fixed watermark checksum range");
    SignerWatermarkV0::from_persisted_parts(scope, journal_id, sequence, chain_checksum)
}

fn watermark_checksum(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(WATERMARK_DOMAIN);
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn private_temp() -> TempDir {
        let temporary = TempDir::new().expect("temporary directory");
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700))
            .expect("private temp mode");
        temporary
    }

    fn mark(sequence: u64, checksum: u8) -> SignerWatermarkV0 {
        SignerWatermarkV0::from_persisted_parts([0x11; 32], [0x22; 32], sequence, [checksum; 32])
            .expect("valid fixture watermark")
    }

    #[test]
    fn watermark_persists_exact_monotonic_head() {
        let temporary = private_temp();
        let path = temporary.path().join("watermark.bin");
        let mut store = LabFileWatermark::open(&path).expect("open fresh watermark");
        assert_eq!(store.load([0x11; 32]).unwrap(), None);
        store.compare_and_advance(None, mark(0, 0x31)).unwrap();
        store
            .compare_and_advance(Some(mark(0, 0x31)), mark(1, 0x32))
            .unwrap();
        drop(store);
        let mut reopened = LabFileWatermark::open(&path).expect("reopen watermark");
        assert_eq!(reopened.load([0x11; 32]).unwrap(), Some(mark(1, 0x32)));
        assert_eq!(
            reopened.compare_and_advance(Some(mark(0, 0x31)), mark(1, 0x32)),
            Err(ExternalWatermarkErrorV0::CompareFailed)
        );
    }

    #[test]
    fn watermark_tamper_and_foreign_scope_fail_closed() {
        let temporary = private_temp();
        let path = temporary.path().join("watermark.bin");
        let mut store = LabFileWatermark::open(&path).expect("open fresh watermark");
        store.compare_and_advance(None, mark(0, 0x31)).unwrap();
        assert_eq!(
            store.load([0x44; 32]),
            Err(ExternalWatermarkErrorV0::CompareFailed)
        );
        drop(store);
        let mut bytes = fs::read(&path).unwrap();
        bytes[32] ^= 1;
        fs::write(&path, bytes).unwrap();
        assert!(matches!(
            LabFileWatermark::open(&path),
            Err(ExternalWatermarkErrorV0::InvalidPersistedState)
        ));
    }
}
