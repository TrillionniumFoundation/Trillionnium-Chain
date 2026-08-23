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
    ExternalMonotonicWatermarkInjectionV0, ExternalMonotonicWatermarkV0, ExternalWatermarkErrorV0,
    ExternalWatermarkSemanticFactsV0, ProposalSignatureProducerV0, ProposalSignatureRequestV0,
    SignatureProducerErrorV0, SignatureProducerV0, SignatureRequestV0, SignerWatermarkV0,
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

/// Fixture-only proposal witness producer for the bounded continuous lane.
///
/// This adapter exists to exercise the proposal-signature injection seam while
/// the production remote protocol still deliberately admits only Vote and
/// TimeoutVote.  The caller remains responsible for strict verification of
/// the returned bytes against the request's expected public key and root.
pub struct LabEd25519ProposalSignatureProducerV0 {
    key: SigningKey,
}

impl LabEd25519ProposalSignatureProducerV0 {
    pub fn new(key: SigningKey) -> Self {
        Self { key }
    }
}

impl ProposalSignatureProducerV0 for LabEd25519ProposalSignatureProducerV0 {
    fn sign_proposal(
        &mut self,
        request: ProposalSignatureRequestV0,
    ) -> Result<SignatureBytes, SignatureProducerErrorV0> {
        if self.key.verifying_key().to_bytes() != request.expected_consensus_public_key() {
            return Err(SignatureProducerErrorV0::Rejected);
        }
        Ok(SignatureBytes::from_array(
            self.key.sign(request.signing_root().as_bytes()).to_bytes(),
        ))
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
    external: Option<Box<dyn ExternalMonotonicWatermarkV0 + Send>>,
    poisoned: bool,
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
            external: None,
            poisoned: false,
        };
        value.ensure_paths()?;
        let _ = value.read_record()?;
        Ok(value)
    }

    pub fn record_path(&self) -> &Path {
        &self.record_path
    }

    fn ensure_healthy(&self) -> Result<(), ExternalWatermarkErrorV0> {
        if self.poisoned {
            return Err(ExternalWatermarkErrorV0::Unavailable);
        }
        Ok(())
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
        self.ensure_healthy()?;
        if scope == [0; 32] {
            return Err(ExternalWatermarkErrorV0::InvalidPersistedState);
        }
        let current = self.read_record()?;
        if current.is_some_and(|value| value.scope() != scope) {
            return Err(ExternalWatermarkErrorV0::CompareFailed);
        }
        let Some(external) = self.external.as_mut() else {
            return Ok(current);
        };
        let observed = match external.load(scope) {
            Ok(value) => value,
            Err(error) => {
                self.poisoned = true;
                return Err(error);
            }
        };
        if observed.is_some_and(|value| value.scope() != scope) {
            self.poisoned = true;
            return Err(ExternalWatermarkErrorV0::CompareFailed);
        }
        Ok(observed)
    }

    fn compare_and_advance(
        &mut self,
        expected: Option<SignerWatermarkV0>,
        target: SignerWatermarkV0,
    ) -> Result<(), ExternalWatermarkErrorV0> {
        self.ensure_healthy()?;
        let current = self.read_record()?;
        let external_installed = self.external.is_some();
        // With an injected authority, a local head that is already `target`
        // is the recoverable inverse of the normal external-first ordering:
        // the process may have crashed after a remote CAS but before its
        // local atomic rename.  In that case the journal's one-event repair
        // path replays the same external CAS and only needs local readback.
        if (!external_installed && current != expected)
            || (external_installed && current != expected && current != Some(target))
        {
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
        if self.external.is_some() {
            let external_result = {
                let external = self
                    .external
                    .as_mut()
                    .expect("external watermark presence checked");
                let observed = external.load(target.scope()).map_err(|error| {
                    self.poisoned = true;
                    error
                })?;
                if observed != expected {
                    self.poisoned = true;
                    return Err(ExternalWatermarkErrorV0::CompareFailed);
                }
                external.compare_and_advance(expected, target)
            };
            if let Err(error) = external_result {
                self.poisoned = true;
                return Err(error);
            }
            if current == Some(target) {
                if self.read_record()? != Some(target) {
                    self.poisoned = true;
                    return Err(ExternalWatermarkErrorV0::CompareFailed);
                }
                return Ok(());
            }
            if let Err(error) = self.write_record(target) {
                // The external CAS may already have committed.  Retaining a
                // usable local owner here would permit a second authority to
                // sign against an uncertain head, so fail closed permanently.
                self.poisoned = true;
                return Err(error);
            }
            return Ok(());
        }
        self.write_record(target)
    }

    fn semantic_mode_v0(&self) -> bool {
        self.external
            .as_ref()
            .is_some_and(|external| external.semantic_mode_v0())
    }

    fn load_semantic_v0(
        &mut self,
        scope: [u8; 32],
        journal_id: [u8; 32],
    ) -> Result<
        Option<(SignerWatermarkV0, ExternalWatermarkSemanticFactsV0)>,
        ExternalWatermarkErrorV0,
    > {
        self.ensure_healthy()?;
        let current = self.read_record()?;
        if current.is_some_and(|value| value.scope() != scope) {
            return Err(ExternalWatermarkErrorV0::CompareFailed);
        }
        let Some(external) = self.external.as_mut() else {
            return Err(ExternalWatermarkErrorV0::Unavailable);
        };
        let result = external.load_semantic_v0(scope, journal_id);
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }

    fn compare_and_advance_semantic_v0(
        &mut self,
        expected: Option<SignerWatermarkV0>,
        target: SignerWatermarkV0,
        facts: ExternalWatermarkSemanticFactsV0,
    ) -> Result<(), ExternalWatermarkErrorV0> {
        self.ensure_healthy()?;
        let current = self.read_record()?;
        let Some(external) = self.external.as_mut() else {
            return Err(ExternalWatermarkErrorV0::Unavailable);
        };
        if current != expected && current != Some(target) {
            return Err(ExternalWatermarkErrorV0::CompareFailed);
        }
        match expected {
            None if target.sequence() != 0 => return Err(ExternalWatermarkErrorV0::CompareFailed),
            Some(previous)
                if target.scope() != previous.scope()
                    || target.journal_id() != previous.journal_id()
                    || previous.sequence().checked_add(1) != Some(target.sequence()) =>
            {
                return Err(ExternalWatermarkErrorV0::CompareFailed)
            }
            _ => {}
        }
        // A crash may have committed the external semantic CAS before the
        // local atomic watermark rename.  Re-read the semantic head and
        // repair only when both the value and exact facts already match; do
        // not issue a second CAS with the stale predecessor.
        if current == Some(target) {
            let observed = external
                .load_semantic_v0(target.scope(), target.journal_id())
                .map_err(|error| {
                    self.poisoned = true;
                    error
                })?;
            if observed == Some((target, facts)) {
                return Ok(());
            }
            self.poisoned = true;
            return Err(ExternalWatermarkErrorV0::CompareFailed);
        }
        let external_result = external.compare_and_advance_semantic_v0(expected, target, facts);
        let result = external_result.and_then(|()| self.write_record(target));
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }

    fn compare_and_advance_semantic_genesis_v0(
        &mut self,
        expected: Option<SignerWatermarkV0>,
        target: SignerWatermarkV0,
    ) -> Result<(), ExternalWatermarkErrorV0> {
        self.ensure_healthy()?;
        let current = self.read_record()?;
        let Some(external) = self.external.as_mut() else {
            return Err(ExternalWatermarkErrorV0::Unavailable);
        };
        if current != expected || target.sequence() != 0 {
            return Err(ExternalWatermarkErrorV0::CompareFailed);
        }
        if current == Some(target) {
            let observed = external
                .load_semantic_v0(target.scope(), target.journal_id())
                .map_err(|error| {
                    self.poisoned = true;
                    error
                })?;
            if observed.is_some_and(|(watermark, _)| watermark == target) {
                return Ok(());
            }
            self.poisoned = true;
            return Err(ExternalWatermarkErrorV0::CompareFailed);
        }
        let result = external
            .compare_and_advance_semantic_genesis_v0(expected, target)
            .and_then(|()| self.write_record(target));
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }
}

impl ExternalMonotonicWatermarkInjectionV0 for LabFileWatermark {
    fn install_external_monotonic_watermark_v0(
        &mut self,
        mut external: Box<dyn ExternalMonotonicWatermarkV0 + Send>,
    ) -> Result<(), ExternalWatermarkErrorV0> {
        self.ensure_healthy()?;
        if self.external.is_some() {
            self.poisoned = true;
            return Err(ExternalWatermarkErrorV0::CompareFailed);
        }
        let local = self.read_record()?;
        if let Some(local) = local {
            let observed = match if external.semantic_mode_v0() {
                external
                    .load_semantic_v0(local.scope(), local.journal_id())
                    .map(|value| value.map(|(watermark, _facts)| watermark))
            } else {
                external.load(local.scope())
            } {
                Ok(value) => value,
                Err(error) => {
                    self.poisoned = true;
                    return Err(error);
                }
            };
            match observed {
                None => {
                    // A fresh sequence-zero head has no prior signer event
                    // history and may be claimed by a newly started external
                    // authority.  Once any intent/signature event exists,
                    // silently claiming a missing external head would turn a
                    // local-only history into retroactive "evidence"; require
                    // the independently administered log to already contain
                    // the exact head instead.
                    if local.sequence() != 0 {
                        self.poisoned = true;
                        return Err(ExternalWatermarkErrorV0::CompareFailed);
                    }
                    let result = if external.semantic_mode_v0() {
                        external.compare_and_advance_semantic_genesis_v0(None, local)
                    } else {
                        external.compare_and_advance(None, local)
                    };
                    if let Err(error) = result {
                        self.poisoned = true;
                        return Err(error);
                    }
                }
                Some(value) if value == local => {}
                Some(_) => {
                    self.poisoned = true;
                    return Err(ExternalWatermarkErrorV0::CompareFailed);
                }
            }
        }
        self.external = Some(external);
        Ok(())
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
    use std::sync::{Arc, Mutex};
    use tempfile::TempDir;

    #[derive(Debug, Clone, Default)]
    struct MemoryExternalWatermark {
        state: Arc<Mutex<(Option<SignerWatermarkV0>, u64)>>,
        fail_compare: Arc<Mutex<bool>>,
    }

    impl MemoryExternalWatermark {
        fn observer(&self) -> Arc<Mutex<(Option<SignerWatermarkV0>, u64)>> {
            Arc::clone(&self.state)
        }

        fn set_fail_compare(&self, value: bool) {
            *self
                .fail_compare
                .lock()
                .expect("external watermark failure mutex") = value;
        }

        fn set_value(&self, value: Option<SignerWatermarkV0>) {
            self.state.lock().expect("external watermark mutex").0 = value;
        }
    }

    impl ExternalMonotonicWatermarkV0 for MemoryExternalWatermark {
        fn load(
            &mut self,
            scope: [u8; 32],
        ) -> Result<Option<SignerWatermarkV0>, ExternalWatermarkErrorV0> {
            let value = self.state.lock().expect("external watermark mutex").0;
            if value.is_some_and(|value| value.scope() != scope) {
                return Err(ExternalWatermarkErrorV0::CompareFailed);
            }
            Ok(value)
        }

        fn compare_and_advance(
            &mut self,
            expected: Option<SignerWatermarkV0>,
            target: SignerWatermarkV0,
        ) -> Result<(), ExternalWatermarkErrorV0> {
            let mut state = self.state.lock().expect("external watermark mutex");
            state.1 = state.1.saturating_add(1);
            if *self
                .fail_compare
                .lock()
                .expect("external watermark failure mutex")
            {
                return Err(ExternalWatermarkErrorV0::Unavailable);
            }
            if state.0 != expected {
                return Err(ExternalWatermarkErrorV0::CompareFailed);
            }
            state.0 = Some(target);
            Ok(())
        }
    }

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

    #[test]
    fn external_watermark_injection_fences_each_local_advance() {
        let temporary = private_temp();
        let path = temporary.path().join("watermark.bin");
        let mut store = LabFileWatermark::open(&path).expect("open fresh watermark");
        store.compare_and_advance(None, mark(0, 0x31)).unwrap();
        let external = MemoryExternalWatermark::default();
        let observer = external.observer();
        store
            .install_external_monotonic_watermark_v0(Box::new(external))
            .expect("claim the existing local head in the external register");
        store
            .compare_and_advance(Some(mark(0, 0x31)), mark(1, 0x32))
            .expect("advance external and local heads together");
        let state = observer.lock().expect("external watermark mutex");
        assert_eq!(state.0, Some(mark(1, 0x32)));
        assert_eq!(state.1, 2, "claim plus one journal event");
    }

    #[test]
    fn external_watermark_failure_poison_fails_closed() {
        let temporary = private_temp();
        let path = temporary.path().join("watermark.bin");
        let mut store = LabFileWatermark::open(&path).expect("open fresh watermark");
        store.compare_and_advance(None, mark(0, 0x31)).unwrap();
        let external = MemoryExternalWatermark::default();
        store
            .install_external_monotonic_watermark_v0(Box::new(external))
            .expect("installation itself claims the local head");
        // The delegate is owned by the local adapter after installation, but
        // this Arc-backed test double lets us inject a later CAS failure.
        let mut failing_store = LabFileWatermark::open(temporary.path().join("failing.bin"))
            .expect("open second watermark");
        failing_store
            .compare_and_advance(None, mark(0, 0x31))
            .unwrap();
        let failing_external = MemoryExternalWatermark::default();
        let failure_control = failing_external.clone();
        failing_store
            .install_external_monotonic_watermark_v0(Box::new(failing_external))
            .expect("installation itself claims the local head");
        failure_control.set_fail_compare(true);
        assert_eq!(
            failing_store.compare_and_advance(Some(mark(0, 0x31)), mark(1, 0x32)),
            Err(ExternalWatermarkErrorV0::Unavailable)
        );
        assert_eq!(
            failing_store.load([0x11; 32]),
            Err(ExternalWatermarkErrorV0::Unavailable),
            "an uncertain installation leaves the local owner poisoned"
        );
    }

    #[test]
    fn external_watermark_install_does_not_adopt_unfenced_history() {
        let temporary = private_temp();
        let path = temporary.path().join("watermark.bin");
        let mut store = LabFileWatermark::open(&path).expect("open fresh watermark");
        store.compare_and_advance(None, mark(0, 0x31)).unwrap();
        store
            .compare_and_advance(Some(mark(0, 0x31)), mark(1, 0x32))
            .unwrap();
        assert_eq!(
            store.install_external_monotonic_watermark_v0(Box::new(
                MemoryExternalWatermark::default(),
            )),
            Err(ExternalWatermarkErrorV0::CompareFailed),
            "a remote authority must already contain non-genesis history"
        );
        assert_eq!(
            store.load([0x11; 32]),
            Err(ExternalWatermarkErrorV0::Unavailable),
            "failed adoption poisons the local owner"
        );
    }

    #[test]
    fn external_watermark_repairs_one_event_remote_lag_without_local_rewrite() {
        let temporary = private_temp();
        let path = temporary.path().join("watermark.bin");
        let mut store = LabFileWatermark::open(&path).expect("open fresh watermark");
        store.compare_and_advance(None, mark(0, 0x31)).unwrap();
        let external = MemoryExternalWatermark::default();
        let control = external.clone();
        store
            .install_external_monotonic_watermark_v0(Box::new(external))
            .expect("claim genesis in the external register");
        store
            .compare_and_advance(Some(mark(0, 0x31)), mark(1, 0x32))
            .unwrap();
        control.set_value(Some(mark(0, 0x31)));
        store
            .compare_and_advance(Some(mark(0, 0x31)), mark(1, 0x32))
            .expect("repair one-event external lag without rewriting local head");
        assert_eq!(store.load([0x11; 32]).unwrap(), Some(mark(1, 0x32)));
    }
}
