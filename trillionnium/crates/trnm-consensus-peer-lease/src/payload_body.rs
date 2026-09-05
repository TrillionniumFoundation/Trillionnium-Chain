//! Candidate-only durable storage for authenticated replay frame bodies.
//!
//! [`PayloadReplayStoreV1`](crate::PayloadReplayStoreV1) deliberately stores
//! only the identity of an authenticated frame.  That is sufficient for a
//! replay fence, but it is not sufficient for a restart owner which has to
//! reconstruct the exact bytes that were authenticated before handing them to
//! a consensus parser.  This module is the narrow companion store for that
//! seam.  It appends the complete frame metadata *and* the exact body bytes to
//! one private, hash-chained file.
//!
//! The store is candidate-only.  It is not a transport, a signature verifier,
//! a Core/SafetyRules authority, or a cross-store transaction.  A future
//! effect-driver owner must coordinate this file with the metadata replay WAL
//! and a whole-node commit authority before treating a body as consensus
//! input.  In particular, a body append and a metadata append can still be
//! separated by a process crash; this module exposes that ambiguity instead
//! of pretending to close it.

use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

use fs2::FileExt;
use sha2::{Digest, Sha256};

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

use crate::payload::{
    decode_head, open_private_lock, persist_head, private_file_mode, private_parent,
    private_parent_mode, read_private_head, reject_stale_head_temps, set_private_mode,
    set_private_mode_options, sidecar_path, validate_private_file, PayloadReplayErrorV1,
    PayloadReplayFrameV1, PayloadReplayNamespaceV1, PAYLOAD_REPLAY_MAX_PAYLOAD_BYTES_V1,
    PAYLOAD_REPLAY_MAX_RECORDS_V1,
};
use crate::protocol::PeerLeaseDirectionV1;

/// Metadata truth: the body store may be exercised by candidate tests and
/// replay tooling, but it is not enabled in a production consensus runtime.
pub const PAYLOAD_REPLAY_BODY_STORE_CANDIDATE_V1: bool = true;
pub const PAYLOAD_REPLAY_BODY_STORE_PRODUCTION_ACTIVATION_V1: bool = false;

/// Bound the aggregate body journal independently from the per-frame bound.
/// This keeps restart parsing and disk consumption finite even when a caller
/// admits many maximum-sized payloads.
pub const PAYLOAD_REPLAY_MAX_BODY_STORE_BYTES_V1: u64 = 256 * 1024 * 1024;

const BODY_LOG_MAGIC_V1: [u8; 8] = *b"TRNBRW01";
const BODY_LOG_VERSION_V1: u8 = 1;
const BODY_LOG_GENESIS_KIND_V1: u8 = 0;
const BODY_LOG_FRAME_KIND_V1: u8 = 1;
const BODY_HEAD_SUFFIX_V1: &str = "head-v1";
const BODY_LOCK_SUFFIX_V1: &str = "lock-v1";
const BODY_DOMAIN_V1: &[u8] = b"trnm.poco-g3.payload-replay.body.v1";
const BODY_RECORD_DOMAIN_V1: &[u8] = b"trnm.poco-g3.payload-replay.body-record.v1";

// Header fields are fixed; body bytes follow immediately, then a 32-byte
// record digest.  The exact offsets are kept in one place so the parser never
// infers a length from an untrusted allocation.
// The frame fingerprint and body digest are intentionally separate fields.
// The former is supplied by the authenticated transport; the latter is
// recomputed from the retained bytes.  Keeping both makes a caller which
// accidentally binds a digest to the wrong frame observable on reopen.
const BODY_HEADER_BYTES_V1: usize = 384;
const BODY_RECORD_DIGEST_BYTES_V1: usize = 32;
const BODY_MIN_RECORD_BYTES_V1: usize = BODY_HEADER_BYTES_V1 + BODY_RECORD_DIGEST_BYTES_V1;
const BODY_HEAD_BYTES_V1: usize = 116;
const BODY_CHUNK_BYTES_V1: usize = 64 * 1024;

/// Descriptor/path identity retained for each body-store authority endpoint.
/// The journal and lock descriptors remain open for the lifetime of the
/// owner, but all mutable operations still use pathnames for the head sidecar
/// and therefore need an explicit replacement fence before and after I/O.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BodyAuthorityPathIdentityV1 {
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(unix)]
    uid: u32,
    #[cfg(unix)]
    mode: u32,
    #[cfg(unix)]
    nlink: u64,
    #[cfg(not(unix))]
    is_file: bool,
    #[cfg(not(unix))]
    is_directory: bool,
}

impl BodyAuthorityPathIdentityV1 {
    fn from_metadata(metadata: &fs::Metadata) -> Self {
        #[cfg(unix)]
        {
            Self {
                device: metadata.dev(),
                inode: metadata.ino(),
                uid: metadata.uid(),
                mode: metadata.mode(),
                nlink: metadata.nlink(),
            }
        }
        #[cfg(not(unix))]
        {
            Self {
                is_file: metadata.is_file(),
                is_directory: metadata.is_dir(),
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct BodyKeyV1 {
    remote_id: [u8; 32],
    direction: PeerLeaseDirectionV1,
    session_id: [u8; 32],
    generation: u64,
    sequence: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BodyLocationV1 {
    frame: PayloadReplayFrameV1,
    record_start: u64,
    body_start: u64,
    body_len: u32,
    body_digest: [u8; 32],
    record_index: u64,
    record_hash: [u8; 32],
}

/// Receipt for a durable body record.  `idempotent_replay` is true when an
/// exact existing `(frame metadata, body bytes)` record was found instead of
/// appended.  A conflicting body for the same frame identity is rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PayloadReplayBodyReceiptV1 {
    record_index: u64,
    record_hash: [u8; 32],
    body_digest: [u8; 32],
    idempotent_replay: bool,
}

impl PayloadReplayBodyReceiptV1 {
    pub const fn record_index(self) -> u64 {
        self.record_index
    }

    pub const fn record_hash(self) -> [u8; 32] {
        self.record_hash
    }

    pub const fn body_digest(self) -> [u8; 32] {
        self.body_digest
    }

    pub const fn idempotent_replay(self) -> bool {
        self.idempotent_replay
    }
}

/// Exact authenticated body returned by [`PayloadReplayBodyStoreV1::resolve`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayloadReplayAuthenticatedBodyV1 {
    frame: PayloadReplayFrameV1,
    body: Vec<u8>,
    receipt: PayloadReplayBodyReceiptV1,
}

impl PayloadReplayAuthenticatedBodyV1 {
    pub const fn frame(&self) -> PayloadReplayFrameV1 {
        self.frame
    }

    pub fn body(&self) -> &[u8] {
        &self.body
    }

    pub fn into_body(self) -> Vec<u8> {
        self.body
    }

    pub const fn receipt(&self) -> PayloadReplayBodyReceiptV1 {
        self.receipt
    }
}

/// A private append-only body journal companion to `PayloadReplayStoreV1`.
/// The journal and its sidecar head are authenticated independently and held
/// under an exclusive lock.  Reopen requires an exact head, never a merely
/// valid prefix.
#[derive(Debug)]
pub struct PayloadReplayBodyStoreV1 {
    path: PathBuf,
    head_path: PathBuf,
    directory: File,
    directory_identity: BodyAuthorityPathIdentityV1,
    file: File,
    file_identity: BodyAuthorityPathIdentityV1,
    lock_path: PathBuf,
    _lock: File,
    lock_identity: BodyAuthorityPathIdentityV1,
    head_identity: Option<BodyAuthorityPathIdentityV1>,
    namespace: PayloadReplayNamespaceV1,
    namespace_digest: [u8; 32],
    locations: BTreeMap<BodyKeyV1, BodyLocationV1>,
    last_hash: [u8; 32],
    record_count: u64,
    file_len: u64,
    poisoned: bool,
}

impl PayloadReplayBodyStoreV1 {
    /// Open and fully authenticate a body journal.  A missing journal starts
    /// with a synced genesis record and head; all other partial/corrupt states
    /// fail closed.
    pub fn open(
        path: impl AsRef<Path>,
        namespace: PayloadReplayNamespaceV1,
    ) -> Result<Self, PayloadReplayErrorV1> {
        let path = path.as_ref().to_path_buf();
        let (directory, parent) = private_parent(&path)?;
        let directory_identity = body_descriptor_identity(&directory)?;
        verify_body_directory_identity(&parent, &directory, directory_identity)?;
        let lock_path = sidecar_path(&path, BODY_LOCK_SUFFIX_V1)?;
        let head_path = sidecar_path(&path, BODY_HEAD_SUFFIX_V1)?;
        reject_stale_head_temps(&path)?;
        let lock = open_private_lock(&lock_path)?;
        let lock_identity = body_descriptor_identity(&lock)?;
        verify_body_file_identity(&lock_path, &lock, lock_identity)?;
        lock.try_lock_exclusive()
            .map_err(PayloadReplayErrorV1::Io)?;

        let existing = match fs::symlink_metadata(&path) {
            Ok(metadata) => {
                if !metadata.is_file() || !crate::payload::private_file_mode(&metadata) {
                    return Err(PayloadReplayErrorV1::InvalidRequest(
                        "payload replay body path is not a private regular file",
                    ));
                }
                true
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => false,
            Err(error) => return Err(PayloadReplayErrorV1::Io(error)),
        };
        let head_exists = match fs::symlink_metadata(&head_path) {
            Ok(_) => true,
            Err(error) if error.kind() == io::ErrorKind::NotFound => false,
            Err(error) => return Err(PayloadReplayErrorV1::Io(error)),
        };
        if !existing && head_exists {
            return Err(PayloadReplayErrorV1::InvalidRequest(
                "payload replay body head exists for a virgin journal",
            ));
        }

        let mut options = OpenOptions::new();
        options.read(true).write(true).append(true);
        // Existing files need the same no-follow protection as newly-created
        // files.  A metadata probe alone is not sufficient: a same-UID
        // pathname swap between the probe and `open` must not redirect the
        // body descriptor through a symlink.
        set_private_mode_options(&mut options);
        if existing {
            options.create(false);
        } else {
            options.create_new(true);
        }
        let file = options.open(&path).map_err(PayloadReplayErrorV1::Io)?;
        if !existing {
            set_private_mode(&file)?;
        }
        validate_private_file(&file)?;
        let file_identity = body_descriptor_identity(&file)?;
        verify_body_file_identity(&path, &file, file_identity)?;
        file.try_lock_exclusive()
            .map_err(PayloadReplayErrorV1::Io)?;

        let namespace_digest = namespace_digest_v1(namespace);
        let mut store = Self {
            path,
            head_path,
            directory,
            directory_identity,
            file,
            file_identity,
            lock_path,
            _lock: lock,
            lock_identity,
            head_identity: None,
            namespace,
            namespace_digest,
            locations: BTreeMap::new(),
            last_hash: [0; 32],
            record_count: 0,
            file_len: 0,
            poisoned: false,
        };
        if !existing {
            let genesis = encode_body_record_v1(None, namespace, namespace_digest, 0, [0; 32], &[]);
            store.file.write_all(&genesis)?;
            store.file.sync_all()?;
            store.directory.sync_all()?;
        }
        store.reload_from_disk_v1()?;
        store.reconcile_head_v1(!existing)?;
        let head_identity = body_path_identity(&store.head_path)?;
        verify_body_path_identity(&store.head_path, head_identity)?;
        store.head_identity = Some(head_identity);
        store.verify_bound_paths_v1()?;
        Ok(store)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn head_path(&self) -> &Path {
        &self.head_path
    }

    pub const fn namespace(&self) -> PayloadReplayNamespaceV1 {
        self.namespace
    }

    pub const fn record_count(&self) -> u64 {
        self.record_count
    }

    pub const fn accepted_body_count(&self) -> u64 {
        self.record_count.saturating_sub(1)
    }

    pub const fn last_hash(&self) -> [u8; 32] {
        self.last_hash
    }

    /// Revalidate the descriptor/path identity of the body journal, head,
    /// lock, and parent directory.  This is a candidate-only fail-closed
    /// fence for same-UID pathname replacement; it is not an openat/dirfd
    /// transaction or a whole-node anti-rollback authority.
    pub fn verify_bound_endpoint_identity(&self) -> Result<(), PayloadReplayErrorV1> {
        self.verify_bound_paths_v1()
    }

    /// Compute the body digest used by the journal.  This is public so an
    /// effect-driver seam can log the same digest without inventing a second
    /// body hash domain.
    pub fn body_digest(body: &[u8]) -> Result<[u8; 32], PayloadReplayErrorV1> {
        payload_replay_body_digest_v1(body)
    }

    /// Admit exact metadata and body bytes.  An exact duplicate is
    /// idempotent; a conflicting body or metadata for the same frame identity
    /// is a replay/conflict and never appends a second record.
    pub fn admit(
        &mut self,
        frame: &PayloadReplayFrameV1,
        body: &[u8],
    ) -> Result<PayloadReplayBodyReceiptV1, PayloadReplayErrorV1> {
        if self.poisoned {
            return Err(PayloadReplayErrorV1::Poisoned);
        }
        self.verify_or_poison_v1()?;
        self.validate_frame_context_v1(frame)?;
        let expected_len = frame.payload_len() as usize;
        if body.len() != expected_len {
            return Err(PayloadReplayErrorV1::InvalidRequest(
                "payload replay body length does not match frame metadata",
            ));
        }
        if body.len() > PAYLOAD_REPLAY_MAX_PAYLOAD_BYTES_V1 {
            return Err(PayloadReplayErrorV1::TooLarge);
        }
        let body_digest = body_digest_v1(body);
        let key = body_key_v1(*frame);
        if let Some(location) = self.locations.get(&key).copied() {
            if location.frame != *frame || location.body_digest != body_digest {
                return Err(PayloadReplayErrorV1::Replay);
            }
            let persisted = self.read_body_record_v1(location)?;
            if persisted != body {
                return Err(PayloadReplayErrorV1::Replay);
            }
            if let Err(error) = self.verify_bound_paths_v1() {
                self.poisoned = true;
                return Err(error);
            }
            return Ok(PayloadReplayBodyReceiptV1 {
                record_index: location.record_index,
                record_hash: location.record_hash,
                body_digest,
                idempotent_replay: true,
            });
        }
        if self.record_count >= PAYLOAD_REPLAY_MAX_RECORDS_V1 {
            return Err(PayloadReplayErrorV1::TooLarge);
        }
        let record_index = self.record_count;
        let record = encode_body_record_v1(
            Some(frame),
            self.namespace,
            self.namespace_digest,
            record_index,
            self.last_hash,
            body,
        );
        let new_file_len = self
            .file_len
            .checked_add(record.len() as u64)
            .ok_or(PayloadReplayErrorV1::TooLarge)?;
        if new_file_len > PAYLOAD_REPLAY_MAX_BODY_STORE_BYTES_V1 {
            return Err(PayloadReplayErrorV1::TooLarge);
        }
        if let Err(error) = self.file.write_all(&record) {
            self.poisoned = true;
            return Err(PayloadReplayErrorV1::CommitAmbiguous(Box::new(
                PayloadReplayErrorV1::Io(error),
            )));
        }
        if let Err(error) = self.file.sync_all().and_then(|_| self.directory.sync_all()) {
            self.poisoned = true;
            return Err(PayloadReplayErrorV1::CommitAmbiguous(Box::new(
                PayloadReplayErrorV1::Io(error),
            )));
        }
        let record_hash = body_record_digest_v1(&record[..BODY_HEADER_BYTES_V1], body);
        if let Err(error) = persist_head(
            &self.head_path,
            &self.directory,
            record_index
                .checked_add(1)
                .ok_or(PayloadReplayErrorV1::TooLarge)?,
            record_hash,
            self.namespace_digest,
        ) {
            self.poisoned = true;
            return Err(PayloadReplayErrorV1::CommitAmbiguous(Box::new(error)));
        }
        let body_start = self.file_len + BODY_HEADER_BYTES_V1 as u64;
        self.locations.insert(
            key,
            BodyLocationV1 {
                frame: *frame,
                record_start: self.file_len,
                body_start,
                body_len: body.len() as u32,
                body_digest,
                record_index,
                record_hash,
            },
        );
        self.last_hash = record_hash;
        self.record_count += 1;
        self.file_len = new_file_len;
        if let Err(error) = self.refresh_head_identity_v1() {
            self.poisoned = true;
            return Err(PayloadReplayErrorV1::CommitAmbiguous(Box::new(error)));
        }
        if let Err(error) = self.verify_bound_paths_v1() {
            self.poisoned = true;
            return Err(PayloadReplayErrorV1::CommitAmbiguous(Box::new(error)));
        }
        Ok(PayloadReplayBodyReceiptV1 {
            record_index,
            record_hash,
            body_digest,
            idempotent_replay: false,
        })
    }

    /// Resolve and re-authenticate the exact body selected by a receipt.
    /// Callers must supply the same frame metadata; a receipt cannot be used
    /// as a bearer capability for another frame.
    pub fn resolve(
        &mut self,
        frame: &PayloadReplayFrameV1,
        receipt: PayloadReplayBodyReceiptV1,
    ) -> Result<PayloadReplayAuthenticatedBodyV1, PayloadReplayErrorV1> {
        if self.poisoned {
            return Err(PayloadReplayErrorV1::Poisoned);
        }
        self.verify_or_poison_v1()?;
        self.validate_frame_context_v1(frame)?;
        let key = body_key_v1(*frame);
        let location =
            self.locations
                .get(&key)
                .copied()
                .ok_or(PayloadReplayErrorV1::InvalidRequest(
                    "payload replay body record is missing",
                ))?;
        if location.frame != *frame
            || location.record_index != receipt.record_index
            || location.record_hash != receipt.record_hash
            || location.body_digest != receipt.body_digest
        {
            return Err(PayloadReplayErrorV1::ContextMismatch);
        }
        let body = self.read_body_record_v1(location)?;
        if let Err(error) = self.verify_bound_paths_v1() {
            // The bytes were read from a descriptor that may no longer be
            // reachable through the authority pathname.  Even though the
            // caller receives no body, retain the failure as a permanent
            // fence until a fresh owner reopens and authenticates the pair.
            self.poisoned = true;
            return Err(error);
        }
        Ok(PayloadReplayAuthenticatedBodyV1 {
            frame: *frame,
            body,
            receipt: PayloadReplayBodyReceiptV1 {
                idempotent_replay: receipt.idempotent_replay,
                ..receipt
            },
        })
    }

    /// Verify the current on-disk head and refresh the in-memory location
    /// index.  This is intentionally explicit for a recovery owner that wants
    /// to check for same-UID replacement between two operations.
    pub fn refresh(&mut self) -> Result<(), PayloadReplayErrorV1> {
        if self.poisoned {
            return Err(PayloadReplayErrorV1::Poisoned);
        }
        self.verify_or_poison_v1()?;
        self.reload_from_disk_v1()?;
        if let Err(error) = self.verify_bound_paths_v1() {
            self.poisoned = true;
            return Err(error);
        }
        Ok(())
    }

    fn verify_or_poison_v1(&mut self) -> Result<(), PayloadReplayErrorV1> {
        if let Err(error) = self.verify_bound_paths_v1() {
            self.poisoned = true;
            return Err(error);
        }
        if let Err(error) = self.verify_live_head_v1() {
            self.poisoned = true;
            return Err(error);
        }
        if let Err(error) = self.verify_bound_paths_v1() {
            self.poisoned = true;
            return Err(error);
        }
        Ok(())
    }

    fn refresh_head_identity_v1(&mut self) -> Result<(), PayloadReplayErrorV1> {
        let identity = body_path_identity(&self.head_path)?;
        verify_body_path_identity(&self.head_path, identity)?;
        self.head_identity = Some(identity);
        Ok(())
    }

    fn verify_bound_paths_v1(&self) -> Result<(), PayloadReplayErrorV1> {
        let parent = self
            .path
            .parent()
            .ok_or(PayloadReplayErrorV1::InvalidRequest(
                "payload replay body path has no parent",
            ))?;
        verify_body_directory_identity(parent, &self.directory, self.directory_identity)?;
        verify_body_file_identity(&self.path, &self.file, self.file_identity)?;
        verify_body_file_identity(&self.lock_path, &self._lock, self.lock_identity)?;
        let head_identity = self.head_identity.ok_or(PayloadReplayErrorV1::Corrupt)?;
        verify_body_path_identity(&self.head_path, head_identity)?;
        Ok(())
    }

    fn validate_frame_context_v1(
        &self,
        frame: &PayloadReplayFrameV1,
    ) -> Result<(), PayloadReplayErrorV1> {
        let scope = frame.scope();
        if scope.local_id() != self.namespace.local_id()
            || scope.epoch() != self.namespace.epoch()
            || scope.validator_set_id() != self.namespace.validator_set_id()
            || frame.run_id_hash() != self.namespace.run_id_hash()
            || frame.network_context_hash() != self.namespace.network_context_hash()
        {
            return Err(PayloadReplayErrorV1::ContextMismatch);
        }
        if scope.remote_id() == [0; 32] || scope.remote_id() == scope.local_id() {
            return Err(PayloadReplayErrorV1::ContextMismatch);
        }
        Ok(())
    }

    fn verify_live_head_v1(&mut self) -> Result<(), PayloadReplayErrorV1> {
        let snapshot = parse_body_log_v1(&self.file, self.namespace, self.namespace_digest)?;
        if snapshot.records != self.record_count
            || snapshot.last_hash != self.last_hash
            || snapshot.file_len != self.file_len
        {
            return Err(PayloadReplayErrorV1::Corrupt);
        }
        // Comparing every location catches a same-length replacement whose
        // head/hash happens to be restored by a caller with filesystem access.
        if snapshot.locations != self.locations {
            return Err(PayloadReplayErrorV1::Corrupt);
        }
        let head_bytes = read_private_head(&self.head_path)?;
        if head_bytes.len() != BODY_HEAD_BYTES_V1 {
            return Err(PayloadReplayErrorV1::Corrupt);
        }
        let (head_count, head_hash, head_namespace) = decode_head(&head_bytes)?;
        if head_count != self.record_count
            || head_hash != self.last_hash
            || head_namespace != self.namespace_digest
        {
            return Err(PayloadReplayErrorV1::Corrupt);
        }
        self.verify_bound_paths_v1()?;
        Ok(())
    }

    fn reload_from_disk_v1(&mut self) -> Result<(), PayloadReplayErrorV1> {
        let snapshot = parse_body_log_v1(&self.file, self.namespace, self.namespace_digest)?;
        self.locations = snapshot.locations;
        self.last_hash = snapshot.last_hash;
        self.record_count = snapshot.records;
        self.file_len = snapshot.file_len;
        Ok(())
    }

    fn reconcile_head_v1(&self, virgin: bool) -> Result<(), PayloadReplayErrorV1> {
        let bytes = match read_private_head(&self.head_path) {
            Ok(bytes) => bytes,
            Err(PayloadReplayErrorV1::Io(error))
                if error.kind() == io::ErrorKind::NotFound && virgin =>
            {
                return persist_head(
                    &self.head_path,
                    &self.directory,
                    self.record_count,
                    self.last_hash,
                    self.namespace_digest,
                )
            }
            Err(error) => return Err(error),
        };
        if bytes.len() != BODY_HEAD_BYTES_V1 {
            return Err(PayloadReplayErrorV1::Corrupt);
        }
        let (count, hash, namespace_digest) = decode_head(&bytes)?;
        if namespace_digest != self.namespace_digest
            || count != self.record_count
            || hash != self.last_hash
        {
            return Err(PayloadReplayErrorV1::Corrupt);
        }
        Ok(())
    }

    fn read_body_record_v1(
        &self,
        location: BodyLocationV1,
    ) -> Result<Vec<u8>, PayloadReplayErrorV1> {
        let mut reader = self.file.try_clone()?;
        reader.seek(SeekFrom::Start(location.record_start))?;
        let mut header = [0u8; BODY_HEADER_BYTES_V1];
        reader.read_exact(&mut header)?;
        let decoded = decode_body_header_v1(
            &header,
            self.namespace,
            self.namespace_digest,
            location.record_index,
            location.record_start,
            location.record_hash,
        )?;
        if decoded.frame != Some(location.frame)
            || decoded.body_len != location.body_len
            || decoded.body_digest != location.body_digest
        {
            return Err(PayloadReplayErrorV1::Corrupt);
        }
        let mut body = vec![0u8; location.body_len as usize];
        reader.read_exact(&mut body)?;
        let mut stored_hash = [0u8; BODY_RECORD_DIGEST_BYTES_V1];
        reader.read_exact(&mut stored_hash)?;
        let expected_hash = body_record_digest_v1(&header, &body);
        if stored_hash != expected_hash || stored_hash != location.record_hash {
            return Err(PayloadReplayErrorV1::Corrupt);
        }
        if body_digest_v1(&body) != location.body_digest {
            return Err(PayloadReplayErrorV1::Corrupt);
        }
        Ok(body)
    }
}

/// Compute the canonical digest of an authenticated replay body.
pub fn payload_replay_body_digest_v1(body: &[u8]) -> Result<[u8; 32], PayloadReplayErrorV1> {
    if body.len() > PAYLOAD_REPLAY_MAX_PAYLOAD_BYTES_V1 {
        return Err(PayloadReplayErrorV1::TooLarge);
    }
    Ok(body_digest_v1(body))
}

fn body_descriptor_identity(
    file: &File,
) -> Result<BodyAuthorityPathIdentityV1, PayloadReplayErrorV1> {
    Ok(BodyAuthorityPathIdentityV1::from_metadata(
        &file.metadata()?,
    ))
}

fn body_path_identity(path: &Path) -> Result<BodyAuthorityPathIdentityV1, PayloadReplayErrorV1> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        return Err(PayloadReplayErrorV1::InvalidRequest(
            "payload replay body authority path is a symlink",
        ));
    }
    Ok(BodyAuthorityPathIdentityV1::from_metadata(&metadata))
}

fn verify_body_file_identity(
    path: &Path,
    file: &File,
    expected: BodyAuthorityPathIdentityV1,
) -> Result<(), PayloadReplayErrorV1> {
    validate_private_file(file)?;
    let descriptor_metadata = file.metadata()?;
    let named_metadata = fs::symlink_metadata(path)?;
    if named_metadata.file_type().is_symlink()
        || !descriptor_metadata.is_file()
        || !named_metadata.is_file()
        || !private_file_mode(&named_metadata)
        || BodyAuthorityPathIdentityV1::from_metadata(&descriptor_metadata) != expected
        || BodyAuthorityPathIdentityV1::from_metadata(&named_metadata) != expected
    {
        return Err(PayloadReplayErrorV1::InvalidRequest(
            "payload replay body authority file identity changed",
        ));
    }
    Ok(())
}

fn verify_body_path_identity(
    path: &Path,
    expected: BodyAuthorityPathIdentityV1,
) -> Result<(), PayloadReplayErrorV1> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || !private_file_mode(&metadata)
        || BodyAuthorityPathIdentityV1::from_metadata(&metadata) != expected
    {
        return Err(PayloadReplayErrorV1::InvalidRequest(
            "payload replay body authority path identity changed",
        ));
    }
    Ok(())
}

fn verify_body_directory_identity(
    path: &Path,
    directory: &File,
    expected: BodyAuthorityPathIdentityV1,
) -> Result<(), PayloadReplayErrorV1> {
    let descriptor_metadata = directory.metadata()?;
    let named_metadata = fs::symlink_metadata(path)?;
    if named_metadata.file_type().is_symlink()
        || !descriptor_metadata.is_dir()
        || !named_metadata.is_dir()
        || !private_parent_mode(&descriptor_metadata)
        || !private_parent_mode(&named_metadata)
        || BodyAuthorityPathIdentityV1::from_metadata(&descriptor_metadata) != expected
        || BodyAuthorityPathIdentityV1::from_metadata(&named_metadata) != expected
        || fs::canonicalize(path)? != path
    {
        return Err(PayloadReplayErrorV1::InvalidRequest(
            "payload replay body authority directory identity changed",
        ));
    }
    crate::store::ensure_private_directory(path).map_err(|error| match error {
        crate::PeerLeaseErrorV1::InvalidRequest(reason)
        | crate::PeerLeaseErrorV1::Protocol(reason) => PayloadReplayErrorV1::InvalidRequest(reason),
        crate::PeerLeaseErrorV1::Io(error) => PayloadReplayErrorV1::Io(error),
        crate::PeerLeaseErrorV1::Rejected(_) => PayloadReplayErrorV1::InvalidRequest(
            "payload replay body parent ancestry is not private",
        ),
    })?;
    Ok(())
}

#[derive(Debug)]
struct ParsedBodySnapshotV1 {
    locations: BTreeMap<BodyKeyV1, BodyLocationV1>,
    records: u64,
    last_hash: [u8; 32],
    file_len: u64,
}

fn parse_body_log_v1(
    file: &File,
    namespace: PayloadReplayNamespaceV1,
    namespace_digest: [u8; 32],
) -> Result<ParsedBodySnapshotV1, PayloadReplayErrorV1> {
    let file_len = file.metadata()?.len();
    if file_len > PAYLOAD_REPLAY_MAX_BODY_STORE_BYTES_V1 {
        return Err(PayloadReplayErrorV1::TooLarge);
    }
    if file_len < BODY_MIN_RECORD_BYTES_V1 as u64 {
        return Err(PayloadReplayErrorV1::Truncated);
    }
    let mut reader = file.try_clone()?;
    reader.seek(SeekFrom::Start(0))?;
    let mut offset = 0u64;
    let mut index = 0u64;
    let mut predecessor = [0u8; 32];
    let mut locations = BTreeMap::new();
    while offset < file_len {
        if index >= PAYLOAD_REPLAY_MAX_RECORDS_V1 {
            return Err(PayloadReplayErrorV1::TooLarge);
        }
        let record_start = offset;
        let mut header = [0u8; BODY_HEADER_BYTES_V1];
        reader
            .read_exact(&mut header)
            .map_err(|error| classify_read_error_v1(error, file_len, offset))?;
        offset = offset
            .checked_add(BODY_HEADER_BYTES_V1 as u64)
            .ok_or(PayloadReplayErrorV1::TooLarge)?;
        let decoded = decode_body_header_v1(
            &header,
            namespace,
            namespace_digest,
            index,
            record_start,
            [0; 32],
        )?;
        if decoded.predecessor != predecessor {
            return Err(PayloadReplayErrorV1::ContextMismatch);
        }
        let body_len = decoded.body_len as u64;
        let after_body = offset
            .checked_add(body_len)
            .and_then(|value| value.checked_add(BODY_RECORD_DIGEST_BYTES_V1 as u64))
            .ok_or(PayloadReplayErrorV1::TooLarge)?;
        if after_body > file_len {
            return Err(PayloadReplayErrorV1::Truncated);
        }
        let body_start = offset;
        let mut body_hasher = Sha256::new();
        body_hasher.update(BODY_DOMAIN_V1);
        body_hasher.update(body_len.to_be_bytes());
        let mut record_hasher = Sha256::new();
        record_hasher.update(BODY_RECORD_DOMAIN_V1);
        record_hasher.update((BODY_HEADER_BYTES_V1 as u64 + body_len).to_be_bytes());
        record_hasher.update(header);
        let mut remaining = body_len as usize;
        let mut chunk = [0u8; BODY_CHUNK_BYTES_V1];
        while remaining > 0 {
            let take = remaining.min(chunk.len());
            reader
                .read_exact(&mut chunk[..take])
                .map_err(|error| classify_read_error_v1(error, file_len, offset))?;
            body_hasher.update(&chunk[..take]);
            record_hasher.update(&chunk[..take]);
            remaining -= take;
            offset += take as u64;
        }
        let body_digest: [u8; 32] = body_hasher.finalize().into();
        let mut stored_hash = [0u8; BODY_RECORD_DIGEST_BYTES_V1];
        reader
            .read_exact(&mut stored_hash)
            .map_err(|error| classify_read_error_v1(error, file_len, offset))?;
        offset += BODY_RECORD_DIGEST_BYTES_V1 as u64;
        let expected_record_hash: [u8; 32] = record_hasher.finalize().into();
        if stored_hash != expected_record_hash {
            return Err(PayloadReplayErrorV1::Corrupt);
        }
        if index == 0 {
            if decoded.operation != BODY_LOG_GENESIS_KIND_V1
                || decoded.frame.is_some()
                || decoded.body_len != 0
                || decoded.body_digest != [0; 32]
                || body_digest != body_digest_v1(&[])
                || stored_hash == [0; 32]
            {
                return Err(PayloadReplayErrorV1::Corrupt);
            }
        } else {
            let frame = decoded.frame.ok_or(PayloadReplayErrorV1::Corrupt)?;
            if decoded.operation != BODY_LOG_FRAME_KIND_V1 {
                return Err(PayloadReplayErrorV1::Corrupt);
            }
            if body_digest != decoded.body_digest {
                return Err(PayloadReplayErrorV1::Corrupt);
            }
            let key = body_key_v1(frame);
            if locations
                .insert(
                    key,
                    BodyLocationV1 {
                        frame,
                        record_start,
                        body_start,
                        body_len: decoded.body_len,
                        body_digest,
                        record_index: index,
                        record_hash: stored_hash,
                    },
                )
                .is_some()
            {
                return Err(PayloadReplayErrorV1::Corrupt);
            }
        }
        predecessor = stored_hash;
        index += 1;
    }
    if offset != file_len || index == 0 {
        return Err(PayloadReplayErrorV1::Truncated);
    }
    Ok(ParsedBodySnapshotV1 {
        locations,
        records: index,
        last_hash: predecessor,
        file_len,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DecodedBodyHeaderV1 {
    operation: u8,
    index: u64,
    frame: Option<PayloadReplayFrameV1>,
    body_len: u32,
    body_digest: [u8; 32],
    predecessor: [u8; 32],
}

fn decode_body_header_v1(
    bytes: &[u8; BODY_HEADER_BYTES_V1],
    namespace: PayloadReplayNamespaceV1,
    namespace_digest: [u8; 32],
    expected_index: u64,
    _record_start: u64,
    _record_hash: [u8; 32],
) -> Result<DecodedBodyHeaderV1, PayloadReplayErrorV1> {
    if bytes[..8] != BODY_LOG_MAGIC_V1 || bytes[8] != BODY_LOG_VERSION_V1 {
        return Err(PayloadReplayErrorV1::Corrupt);
    }
    if bytes[10..12] != [0, 0]
        || bytes[117..124].iter().any(|byte| *byte != 0)
        || bytes[277..280].iter().any(|byte| *byte != 0)
    {
        return Err(PayloadReplayErrorV1::Corrupt);
    }
    let index = u64::from_be_bytes(bytes[12..20].try_into().expect("body record index"));
    if index != expected_index {
        return Err(PayloadReplayErrorV1::Corrupt);
    }
    let stored_namespace: [u8; 32] = bytes[20..52].try_into().expect("body namespace");
    if stored_namespace != namespace_digest || bytes[52..84] != namespace.local_id() {
        return Err(PayloadReplayErrorV1::ContextMismatch);
    }
    let remote_id: [u8; 32] = bytes[84..116].try_into().expect("body remote");
    let direction = match bytes[116] {
        0 => None,
        1 => Some(PeerLeaseDirectionV1::Outbound),
        2 => Some(PeerLeaseDirectionV1::Inbound),
        _ => return Err(PayloadReplayErrorV1::Corrupt),
    };
    let epoch = u64::from_be_bytes(bytes[124..132].try_into().expect("body epoch"));
    let validator_set_id: [u8; 32] = bytes[132..164].try_into().expect("body validator set");
    let run_id_hash: [u8; 32] = bytes[164..196].try_into().expect("body run id");
    let network_context_hash: [u8; 32] = bytes[196..228].try_into().expect("body context");
    let session_id: [u8; 32] = bytes[228..260].try_into().expect("body session");
    let generation = u64::from_be_bytes(bytes[260..268].try_into().expect("body generation"));
    let sequence = u64::from_be_bytes(bytes[268..276].try_into().expect("body sequence"));
    let frame_kind = bytes[276];
    let payload_len = u32::from_be_bytes(bytes[280..284].try_into().expect("body payload len"));
    let frame_fingerprint: [u8; 32] = bytes[284..316].try_into().expect("frame fingerprint");
    let body_digest: [u8; 32] = bytes[316..348].try_into().expect("body digest");
    let body_len = u32::from_be_bytes(bytes[348..352].try_into().expect("body len"));
    let predecessor: [u8; 32] = bytes[352..384].try_into().expect("body predecessor");
    if body_len as usize > PAYLOAD_REPLAY_MAX_PAYLOAD_BYTES_V1 {
        return Err(PayloadReplayErrorV1::TooLarge);
    }
    if epoch != namespace.epoch()
        || validator_set_id != namespace.validator_set_id()
        || run_id_hash != namespace.run_id_hash()
        || network_context_hash != namespace.network_context_hash()
    {
        return Err(PayloadReplayErrorV1::ContextMismatch);
    }
    if bytes[9] == BODY_LOG_GENESIS_KIND_V1 {
        if remote_id != [0; 32]
            || direction.is_some()
            || epoch != namespace.epoch()
            || validator_set_id != namespace.validator_set_id()
            || bytes[164..196] != namespace.run_id_hash()
            || bytes[196..228] != namespace.network_context_hash()
            || session_id != [0; 32]
            || generation != 0
            || sequence != 0
            || frame_kind != 0
            || payload_len != 0
            || body_len != 0
            || frame_fingerprint != [0; 32]
            || body_digest != [0; 32]
        {
            return Err(PayloadReplayErrorV1::Corrupt);
        }
        return Ok(DecodedBodyHeaderV1 {
            operation: bytes[9],
            index,
            frame: None,
            body_len,
            body_digest,
            predecessor,
        });
    }
    if bytes[9] != BODY_LOG_FRAME_KIND_V1
        || direction.is_none()
        || remote_id == [0; 32]
        || remote_id == namespace.local_id()
        || session_id == [0; 32]
        || generation == 0
        || frame_kind == 0
        || frame_fingerprint == [0; 32]
        || body_digest == [0; 32]
        || payload_len != body_len
    {
        return Err(PayloadReplayErrorV1::Corrupt);
    }
    let direction = direction.expect("checked direction");
    let scope = crate::protocol::PeerLeaseScopeV1::new(
        namespace.local_id(),
        remote_id,
        direction,
        epoch,
        validator_set_id,
    )
    .map_err(|_| PayloadReplayErrorV1::Corrupt)?;
    let frame = PayloadReplayFrameV1::new(
        scope,
        run_id_hash,
        network_context_hash,
        session_id,
        generation,
        sequence,
        frame_kind,
        payload_len as usize,
        frame_fingerprint,
    )
    .map_err(|_| PayloadReplayErrorV1::Corrupt)?;
    Ok(DecodedBodyHeaderV1 {
        operation: bytes[9],
        index,
        frame: Some(frame),
        body_len,
        body_digest,
        predecessor,
    })
}

fn encode_body_record_v1(
    frame: Option<&PayloadReplayFrameV1>,
    namespace: PayloadReplayNamespaceV1,
    namespace_digest: [u8; 32],
    index: u64,
    predecessor: [u8; 32],
    body: &[u8],
) -> Vec<u8> {
    let mut header = Vec::with_capacity(BODY_HEADER_BYTES_V1);
    header.extend_from_slice(&BODY_LOG_MAGIC_V1);
    header.push(BODY_LOG_VERSION_V1);
    header.push(if frame.is_some() {
        BODY_LOG_FRAME_KIND_V1
    } else {
        BODY_LOG_GENESIS_KIND_V1
    });
    header.extend_from_slice(&[0, 0]);
    header.extend_from_slice(&index.to_be_bytes());
    header.extend_from_slice(&namespace_digest);
    header.extend_from_slice(&namespace.local_id());
    if let Some(frame) = frame {
        let scope = frame.scope();
        header.extend_from_slice(&scope.remote_id());
        header.push(scope.direction() as u8);
        header.extend_from_slice(&[0; 7]);
        header.extend_from_slice(&scope.epoch().to_be_bytes());
        header.extend_from_slice(&scope.validator_set_id());
        header.extend_from_slice(&frame.run_id_hash());
        header.extend_from_slice(&frame.network_context_hash());
        header.extend_from_slice(&frame.session_id());
        header.extend_from_slice(&frame.generation().to_be_bytes());
        header.extend_from_slice(&frame.sequence().to_be_bytes());
        header.push(frame.frame_kind());
        header.extend_from_slice(&[0; 3]);
        header.extend_from_slice(&frame.payload_len().to_be_bytes());
        header.extend_from_slice(&frame.frame_fingerprint());
        header.extend_from_slice(&body_digest_v1(body));
        header.extend_from_slice(&(body.len() as u32).to_be_bytes());
    } else {
        header.extend_from_slice(&[0; 32]);
        header.push(0);
        header.extend_from_slice(&[0; 7]);
        header.extend_from_slice(&namespace.epoch().to_be_bytes());
        header.extend_from_slice(&namespace.validator_set_id());
        header.extend_from_slice(&namespace.run_id_hash());
        header.extend_from_slice(&namespace.network_context_hash());
        header.extend_from_slice(&[0; 32]);
        header.extend_from_slice(&0u64.to_be_bytes());
        header.extend_from_slice(&0u64.to_be_bytes());
        header.push(0);
        header.extend_from_slice(&[0; 3]);
        header.extend_from_slice(&0u32.to_be_bytes());
        header.extend_from_slice(&[0; 32]);
        header.extend_from_slice(&[0; 32]);
        header.extend_from_slice(&0u32.to_be_bytes());
    }
    header.extend_from_slice(&predecessor);
    debug_assert_eq!(header.len(), BODY_HEADER_BYTES_V1);
    let mut record = header.clone();
    record.extend_from_slice(body);
    record.extend_from_slice(&body_record_digest_v1(&header, body));
    record
}

fn namespace_digest_v1(namespace: PayloadReplayNamespaceV1) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"trnm.poco-g3.payload-replay.body-namespace.v1");
    hasher.update(namespace.local_id());
    hasher.update(namespace.epoch().to_be_bytes());
    hasher.update(namespace.validator_set_id());
    hasher.update(namespace.run_id_hash());
    hasher.update(namespace.network_context_hash());
    hasher.finalize().into()
}

fn body_digest_v1(body: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(BODY_DOMAIN_V1);
    hasher.update((body.len() as u64).to_be_bytes());
    hasher.update(body);
    hasher.finalize().into()
}

fn body_record_digest_v1(header: &[u8], body: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(BODY_RECORD_DOMAIN_V1);
    hasher.update(((header.len() + body.len()) as u64).to_be_bytes());
    hasher.update(header);
    hasher.update(body);
    hasher.finalize().into()
}

fn body_key_v1(frame: PayloadReplayFrameV1) -> BodyKeyV1 {
    let scope = frame.scope();
    BodyKeyV1 {
        remote_id: scope.remote_id(),
        direction: scope.direction(),
        session_id: frame.session_id(),
        generation: frame.generation(),
        sequence: frame.sequence(),
    }
}

fn classify_read_error_v1(error: io::Error, file_len: u64, offset: u64) -> PayloadReplayErrorV1 {
    if error.kind() == io::ErrorKind::UnexpectedEof || offset >= file_len {
        PayloadReplayErrorV1::Truncated
    } else {
        PayloadReplayErrorV1::Io(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use tempfile::TempDir;

    fn private_tempdir() -> TempDir {
        let directory = tempfile::Builder::new()
            .prefix("trnm-payload-body-")
            .tempdir()
            .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        }
        directory
    }

    fn namespace() -> PayloadReplayNamespaceV1 {
        PayloadReplayNamespaceV1::new([1; 32], 7, [2; 32], [3; 32], [4; 32]).unwrap()
    }

    fn frame(
        ns: PayloadReplayNamespaceV1,
        sequence: u64,
        fingerprint: [u8; 32],
    ) -> PayloadReplayFrameV1 {
        PayloadReplayFrameV1::new(
            ns.scope_for([9; 32], PeerLeaseDirectionV1::Inbound)
                .unwrap(),
            ns.run_id_hash(),
            ns.network_context_hash(),
            [5; 32],
            1,
            sequence,
            2,
            11,
            fingerprint,
        )
        .unwrap()
    }

    #[test]
    fn exact_body_roundtrip_reopen_and_idempotent_duplicate() {
        let dir = private_tempdir();
        let path = dir.path().join("bodies.wal");
        let ns = namespace();
        let body = b"exact-body!";
        let first_frame = frame(ns, 0, [10; 32]);
        let mut store = PayloadReplayBodyStoreV1::open(&path, ns).unwrap();
        let first = store.admit(&first_frame, body).unwrap();
        assert!(!first.idempotent_replay());
        let duplicate = store.admit(&first_frame, body).unwrap();
        assert!(duplicate.idempotent_replay());
        assert_eq!(duplicate.record_index(), first.record_index());
        let resolved = store.resolve(&first_frame, duplicate).unwrap();
        assert_eq!(resolved.body(), body);
        drop(store);

        let mut reopened = PayloadReplayBodyStoreV1::open(&path, ns).unwrap();
        let resolved = reopened.resolve(&first_frame, first).unwrap();
        assert_eq!(resolved.frame(), first_frame);
        assert_eq!(resolved.body(), body);
        assert_eq!(reopened.accepted_body_count(), 1);
    }

    #[test]
    fn conflicting_duplicate_body_or_metadata_is_rejected() {
        let dir = private_tempdir();
        let path = dir.path().join("bodies.wal");
        let ns = namespace();
        let first_frame = frame(ns, 0, [10; 32]);
        let mut store = PayloadReplayBodyStoreV1::open(&path, ns).unwrap();
        store.admit(&first_frame, b"exact-body!").unwrap();
        assert!(matches!(
            store.admit(&first_frame, b"other-body!"),
            Err(PayloadReplayErrorV1::Replay)
        ));
        let conflicting_frame = frame(ns, 0, [11; 32]);
        assert!(matches!(
            store.admit(&conflicting_frame, b"exact-body!"),
            Err(PayloadReplayErrorV1::Replay)
        ));
    }

    #[test]
    fn truncation_and_body_tamper_fail_closed_on_reopen() {
        let dir = private_tempdir();
        let path = dir.path().join("bodies.wal");
        let ns = namespace();
        let mut store = PayloadReplayBodyStoreV1::open(&path, ns).unwrap();
        store
            .admit(&frame(ns, 0, [10; 32]), b"exact-body!")
            .unwrap();
        drop(store);
        let original = fs::read(&path).unwrap();
        fs::write(&path, &original[..original.len() - 1]).unwrap();
        assert!(matches!(
            PayloadReplayBodyStoreV1::open(&path, ns),
            Err(PayloadReplayErrorV1::Truncated) | Err(PayloadReplayErrorV1::Corrupt)
        ));
        fs::write(&path, &original).unwrap();
        let mut mutated = original;
        mutated[BODY_HEADER_BYTES_V1] ^= 1;
        fs::write(&path, mutated).unwrap();
        assert!(matches!(
            PayloadReplayBodyStoreV1::open(&path, ns),
            Err(PayloadReplayErrorV1::Corrupt)
        ));
    }

    #[test]
    fn head_mutation_and_receipt_mismatch_fail_closed() {
        let dir = private_tempdir();
        let path = dir.path().join("bodies.wal");
        let ns = namespace();
        let frame = frame(ns, 0, [10; 32]);
        let mut store = PayloadReplayBodyStoreV1::open(&path, ns).unwrap();
        let receipt = store.admit(&frame, b"exact-body!").unwrap();
        let mut wrong = receipt;
        wrong.body_digest[0] ^= 1;
        assert!(matches!(
            store.resolve(&frame, wrong),
            Err(PayloadReplayErrorV1::ContextMismatch)
        ));
        drop(store);
        let head = sidecar_path(&path, BODY_HEAD_SUFFIX_V1).unwrap();
        let mut bytes = fs::read(&head).unwrap();
        bytes[20] ^= 1;
        fs::write(head, bytes).unwrap();
        assert!(matches!(
            PayloadReplayBodyStoreV1::open(&path, ns),
            Err(PayloadReplayErrorV1::Corrupt)
        ));
    }

    #[test]
    fn length_mismatch_is_rejected_before_append() {
        let dir = private_tempdir();
        let path = dir.path().join("bodies.wal");
        let ns = namespace();
        let frame = frame(ns, 0, [10; 32]);
        let mut store = PayloadReplayBodyStoreV1::open(&path, ns).unwrap();
        assert!(matches!(
            store.admit(&frame, b"short"),
            Err(PayloadReplayErrorV1::InvalidRequest(reason))
                if reason.contains("length")
        ));
        assert_eq!(store.accepted_body_count(), 0);
    }

    #[cfg(unix)]
    #[test]
    fn private_paths_and_retained_head_temporary_fail_closed() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let dir = private_tempdir();
        let path = dir.path().join("bodies.wal");
        fs::write(&path, b"not-private").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            PayloadReplayBodyStoreV1::open(&path, namespace()),
            Err(PayloadReplayErrorV1::InvalidRequest(reason))
                if reason.contains("private regular file")
        ));
        fs::remove_file(&path).unwrap();

        let real = dir.path().join("real");
        fs::create_dir(&real).unwrap();
        fs::set_permissions(&real, fs::Permissions::from_mode(0o700)).unwrap();
        let alias = dir.path().join("alias");
        symlink(&real, &alias).unwrap();
        assert!(matches!(
            PayloadReplayBodyStoreV1::open(alias.join("bodies.wal"), namespace()),
            Err(PayloadReplayErrorV1::InvalidRequest(reason))
                if reason.contains("symlink alias")
        ));

        // An existing journal pathname must also reject a symlink target;
        // this exercises the non-creation open path, which must carry
        // `O_NOFOLLOW` just like a virgin journal.
        let real_file = dir.path().join("real-bodies.wal");
        let mut real_store = PayloadReplayBodyStoreV1::open(&real_file, namespace()).unwrap();
        real_store
            .admit(&frame(namespace(), 0, [10; 32]), b"exact-body!")
            .unwrap();
        drop(real_store);
        let file_alias = dir.path().join("alias-bodies.wal");
        symlink(&real_file, &file_alias).unwrap();
        assert!(matches!(
            PayloadReplayBodyStoreV1::open(&file_alias, namespace()),
            Err(PayloadReplayErrorV1::InvalidRequest(reason))
                if reason.contains("private regular file")
        ));

        let temporary = dir.path().join("..bodies.wal.head-v1.tmp-retained");
        fs::write(&temporary, b"retained recovery evidence").unwrap();
        assert!(matches!(
            PayloadReplayBodyStoreV1::open(&path, namespace()),
            Err(PayloadReplayErrorV1::Corrupt)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn durable_publication_sidecars_are_private() {
        use std::os::unix::fs::PermissionsExt;

        let dir = private_tempdir();
        let path = dir.path().join("bodies.wal");
        let ns = namespace();
        let mut store = PayloadReplayBodyStoreV1::open(&path, ns).unwrap();
        store
            .admit(&frame(ns, 0, [10; 32]), b"exact-body!")
            .unwrap();
        let head = fs::symlink_metadata(store.head_path()).unwrap();
        assert_eq!(head.permissions().mode() & 0o7777, 0o600);
        let lock = fs::symlink_metadata(path.with_file_name(".bodies.wal.lock-v1")).unwrap();
        assert_eq!(lock.permissions().mode() & 0o7777, 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn endpoint_identity_rejects_body_wal_replacement_before_resolve() {
        let dir = private_tempdir();
        let path = dir.path().join("bodies.wal");
        let ns = namespace();
        let frame = frame(ns, 0, [10; 32]);
        let mut store = PayloadReplayBodyStoreV1::open(&path, ns).unwrap();
        let receipt = store.admit(&frame, b"exact-body!").unwrap();

        let original = dir.path().join("bodies.wal.original");
        fs::rename(&path, &original).unwrap();
        fs::copy(&original, &path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

        assert!(matches!(
            store.resolve(&frame, receipt),
            Err(PayloadReplayErrorV1::InvalidRequest(reason))
                if reason.contains("identity")
        ));
    }

    #[cfg(unix)]
    #[test]
    fn endpoint_identity_rejects_body_head_replacement_before_refresh() {
        let dir = private_tempdir();
        let path = dir.path().join("bodies.wal");
        let ns = namespace();
        let frame = frame(ns, 0, [10; 32]);
        let mut store = PayloadReplayBodyStoreV1::open(&path, ns).unwrap();
        store.admit(&frame, b"exact-body!").unwrap();
        let head = store.head_path().to_path_buf();

        let original = dir.path().join("bodies.head.original");
        fs::rename(&head, &original).unwrap();
        fs::copy(&original, &head).unwrap();
        fs::set_permissions(&head, fs::Permissions::from_mode(0o600)).unwrap();

        assert!(matches!(
            store.refresh(),
            Err(PayloadReplayErrorV1::InvalidRequest(reason))
                if reason.contains("identity")
        ));
    }

    #[cfg(unix)]
    #[test]
    fn endpoint_identity_rejects_body_lock_replacement_before_admit() {
        let dir = private_tempdir();
        let path = dir.path().join("bodies.wal");
        let ns = namespace();
        let frame = frame(ns, 0, [10; 32]);
        let mut store = PayloadReplayBodyStoreV1::open(&path, ns).unwrap();
        let lock = path.with_file_name(".bodies.wal.lock-v1");

        let original = dir.path().join("bodies.lock.original");
        fs::rename(&lock, &original).unwrap();
        fs::copy(&original, &lock).unwrap();
        fs::set_permissions(&lock, fs::Permissions::from_mode(0o600)).unwrap();

        assert!(matches!(
            store.admit(&frame, b"exact-body!"),
            Err(PayloadReplayErrorV1::InvalidRequest(reason))
                if reason.contains("identity")
        ));
    }
}
