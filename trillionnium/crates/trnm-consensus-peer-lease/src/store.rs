use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

use fs2::FileExt;
use sha2::{Digest, Sha256};

use crate::protocol::{
    LeaseOperationV1, LeaseRejectCodeV1, LeaseRequestV1, PeerLeaseDirectionV1, PeerLeaseScopeV1,
    PeerLeaseTokenV1,
};
use crate::PeerLeaseErrorV1;

const RECORD_MAGIC_V1: [u8; 4] = *b"TPLR";
const RECORD_VERSION_V1: u8 = 1;
const RECORD_PAYLOAD_BYTES_V1: usize = 1 + 32 + 32 + 1 + 8 + 32 + 32 + 8 + 8 + 8;
const RECORD_HEADER_BYTES_V1: usize = 4 + 1 + 1 + 4 + 32;
const RECORD_DIGEST_BYTES_V1: usize = 32;
const MIN_TTL_MS_V1: u64 = 1_000;
const MAX_TTL_MS_V1: u64 = 120_000;
const HEAD_MAGIC_V1: [u8; 4] = *b"TPLH";
const HEAD_VERSION_V1: u8 = 1;
const HEAD_BODY_BYTES_V1: usize = 4 + 1 + 3 + 8 + 32;
const HEAD_BYTES_V1: usize = HEAD_BODY_BYTES_V1 + 32;

/// Durable append-only authority state.  Only the daemon owns an instance;
/// clients never open this file.  A hash chain and strict replay validation
/// make truncation, byte edits, record reordering and database rollback fail
/// closed at daemon startup.
#[derive(Debug)]
pub struct PeerLeaseStoreV1 {
    path: PathBuf,
    anchor_path: PathBuf,
    directory: File,
    file: File,
    _lock_file: File,
    entries: BTreeMap<PeerLeaseScopeV1, LeaseStateV1>,
    generations: BTreeMap<PeerLeaseScopeV1, u64>,
    seen_sessions: BTreeSet<(PeerLeaseScopeV1, [u8; 32])>,
    last_hash: [u8; 32],
    record_count: u64,
    last_now_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LeaseStateV1 {
    session_id: [u8; 32],
    generation: u64,
    expires_at_ms: u64,
    record_hash: [u8; 32],
}

impl PeerLeaseStoreV1 {
    /// Open and fully verify an authority journal.  No repair/truncation is
    /// attempted: a partial final record is an explicit fail-stop condition.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, PeerLeaseErrorV1> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
            ensure_private_directory(parent)?;
        }
        let anchor_path = anchor_path_for(&path);
        let directory = File::open(
            path.parent()
                .ok_or(PeerLeaseErrorV1::InvalidRequest("journal parent"))?,
        )?;
        let lock_file = open_lock_file(&path)?;
        lock_file
            .try_lock_exclusive()
            .map_err(PeerLeaseErrorV1::Io)?;
        let mut file = open_append_file(&path)?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        let mut store = Self {
            path,
            anchor_path,
            directory,
            file,
            _lock_file: lock_file,
            entries: BTreeMap::new(),
            generations: BTreeMap::new(),
            seen_sessions: BTreeSet::new(),
            last_hash: [0; 32],
            record_count: 0,
            last_now_ms: 0,
        };
        store.replay(&bytes)?;
        store.file.seek(SeekFrom::End(0))?;
        store.reconcile_anchor()?;
        Ok(store)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub const fn last_hash(&self) -> [u8; 32] {
        self.last_hash
    }

    pub const fn last_now_ms(&self) -> u64 {
        self.last_now_ms
    }

    pub fn active_lease(&self, scope: PeerLeaseScopeV1) -> Option<PeerLeaseTokenV1> {
        self.entries.get(&scope).map(|state| {
            PeerLeaseTokenV1::new(
                scope,
                state.session_id,
                state.generation,
                state.expires_at_ms,
                state.record_hash,
            )
        })
    }

    pub fn latest_generation(&self, scope: PeerLeaseScopeV1) -> u64 {
        self.generations.get(&scope).copied().unwrap_or(0)
    }

    /// Apply one authority operation and durably append its record.  The
    /// caller supplies the observed clock so tests and a daemon can make the
    /// clock-rollback policy explicit.
    pub(crate) fn apply(
        &mut self,
        request: LeaseRequestV1,
        now_ms: u64,
    ) -> Result<PeerLeaseTokenV1, PeerLeaseErrorV1> {
        if now_ms < self.last_now_ms {
            return Err(PeerLeaseErrorV1::Rejected(LeaseRejectCodeV1::ClockRollback));
        }
        validate_request(request)?;
        let scope = request.scope;
        let current = self.entries.get(&scope).copied();
        let latest_generation = self.latest_generation(scope);
        let new_state = match request.operation {
            LeaseOperationV1::Acquire => {
                if self.seen_sessions.contains(&(scope, request.session_id)) {
                    return Err(PeerLeaseErrorV1::Rejected(
                        LeaseRejectCodeV1::StaleGeneration,
                    ));
                }
                if current.is_some_and(|state| now_ms < state.expires_at_ms) {
                    return Err(PeerLeaseErrorV1::Rejected(LeaseRejectCodeV1::AlreadyLeased));
                }
                let expected_generation =
                    latest_generation
                        .checked_add(1)
                        .ok_or(PeerLeaseErrorV1::Rejected(
                            LeaseRejectCodeV1::StaleGeneration,
                        ))?;
                if request.generation != expected_generation {
                    return Err(PeerLeaseErrorV1::Rejected(
                        LeaseRejectCodeV1::StaleGeneration,
                    ));
                }
                let generation = request.generation;
                let expires_at_ms = now_ms
                    .checked_add(request.ttl_ms)
                    .ok_or(PeerLeaseErrorV1::InvalidRequest("lease TTL overflow"))?;
                LeaseStateV1 {
                    session_id: request.session_id,
                    generation,
                    expires_at_ms,
                    record_hash: [0; 32],
                }
            }
            LeaseOperationV1::Renew => {
                let state =
                    current.ok_or(PeerLeaseErrorV1::Rejected(LeaseRejectCodeV1::LeaseNotFound))?;
                ensure_token_matches(request, state)?;
                if now_ms >= state.expires_at_ms {
                    return Err(PeerLeaseErrorV1::Rejected(LeaseRejectCodeV1::LeaseExpired));
                }
                let expires_at_ms = now_ms
                    .checked_add(request.ttl_ms)
                    .ok_or(PeerLeaseErrorV1::InvalidRequest("lease TTL overflow"))?;
                LeaseStateV1 {
                    expires_at_ms,
                    record_hash: [0; 32],
                    ..state
                }
            }
            LeaseOperationV1::Revalidate => {
                let state =
                    current.ok_or(PeerLeaseErrorV1::Rejected(LeaseRejectCodeV1::LeaseNotFound))?;
                ensure_token_matches(request, state)?;
                if now_ms >= state.expires_at_ms {
                    return Err(PeerLeaseErrorV1::Rejected(LeaseRejectCodeV1::LeaseExpired));
                }
                return Ok(PeerLeaseTokenV1::new(
                    scope,
                    state.session_id,
                    state.generation,
                    state.expires_at_ms,
                    state.record_hash,
                ));
            }
            LeaseOperationV1::Release => {
                let state =
                    current.ok_or(PeerLeaseErrorV1::Rejected(LeaseRejectCodeV1::LeaseNotFound))?;
                ensure_token_matches(request, state)?;
                if now_ms >= state.expires_at_ms {
                    return Err(PeerLeaseErrorV1::Rejected(LeaseRejectCodeV1::LeaseExpired));
                }
                // A released lease remains represented by `generations` and
                // `seen_sessions`; replaying it can never regain authority.
                LeaseStateV1 {
                    session_id: [0; 32],
                    generation: state.generation,
                    expires_at_ms: 0,
                    record_hash: [0; 32],
                }
            }
        };

        let record = encode_record(
            request.operation,
            scope,
            request.session_id,
            new_state.generation,
            new_state.expires_at_ms,
            now_ms,
            self.last_hash,
        );
        let record_hash = record.digest;
        self.file.write_all(&record.bytes)?;
        self.file.sync_all()?;
        sync_parent_dir(&self.path)?;
        self.last_hash = record_hash;
        self.record_count = self
            .record_count
            .checked_add(1)
            .ok_or(PeerLeaseErrorV1::Rejected(
                LeaseRejectCodeV1::AuthorityCorrupt,
            ))?;
        self.last_now_ms = now_ms;

        match request.operation {
            LeaseOperationV1::Acquire => {
                self.generations.insert(scope, new_state.generation);
                self.seen_sessions.insert((scope, request.session_id));
                self.entries.insert(
                    scope,
                    LeaseStateV1 {
                        record_hash,
                        ..new_state
                    },
                );
            }
            LeaseOperationV1::Renew => {
                self.entries.insert(
                    scope,
                    LeaseStateV1 {
                        record_hash,
                        ..new_state
                    },
                );
            }
            LeaseOperationV1::Release => {
                self.entries.remove(&scope);
                self.generations.insert(scope, new_state.generation);
            }
            LeaseOperationV1::Revalidate => unreachable!("revalidate returns above"),
        }

        self.persist_anchor()?;

        if request.operation == LeaseOperationV1::Release {
            Ok(PeerLeaseTokenV1::new(
                scope,
                request.session_id,
                new_state.generation,
                0,
                record_hash,
            ))
        } else {
            Ok(PeerLeaseTokenV1::new(
                scope,
                request.session_id,
                new_state.generation,
                new_state.expires_at_ms,
                record_hash,
            ))
        }
    }

    fn replay(&mut self, bytes: &[u8]) -> Result<(), PeerLeaseErrorV1> {
        let mut offset = 0usize;
        while offset < bytes.len() {
            let remaining = bytes.len() - offset;
            if remaining < RECORD_HEADER_BYTES_V1 + RECORD_DIGEST_BYTES_V1 {
                return Err(PeerLeaseErrorV1::Rejected(
                    LeaseRejectCodeV1::AuthorityCorrupt,
                ));
            }
            let magic = bytes
                .get(offset..offset + 4)
                .ok_or(PeerLeaseErrorV1::Protocol("journal header truncated"))?;
            if magic != RECORD_MAGIC_V1 {
                return Err(PeerLeaseErrorV1::Rejected(
                    LeaseRejectCodeV1::AuthorityCorrupt,
                ));
            }
            let version = bytes[offset + 4];
            let op_tag = bytes[offset + 5];
            let payload_len = u32::from_le_bytes(
                bytes[offset + 6..offset + 10]
                    .try_into()
                    .expect("fixed journal header"),
            ) as usize;
            if version != RECORD_VERSION_V1 || payload_len != RECORD_PAYLOAD_BYTES_V1 {
                return Err(PeerLeaseErrorV1::Rejected(
                    LeaseRejectCodeV1::AuthorityCorrupt,
                ));
            }
            let total = RECORD_HEADER_BYTES_V1
                .checked_add(payload_len)
                .and_then(|value| value.checked_add(RECORD_DIGEST_BYTES_V1))
                .ok_or(PeerLeaseErrorV1::Rejected(
                    LeaseRejectCodeV1::AuthorityCorrupt,
                ))?;
            if remaining < total {
                return Err(PeerLeaseErrorV1::Rejected(
                    LeaseRejectCodeV1::AuthorityCorrupt,
                ));
            }
            let prev_hash: [u8; 32] = bytes[offset + 10..offset + 42]
                .try_into()
                .expect("fixed journal header");
            if prev_hash != self.last_hash {
                return Err(PeerLeaseErrorV1::Rejected(
                    LeaseRejectCodeV1::AuthorityCorrupt,
                ));
            }
            let payload_start = offset + RECORD_HEADER_BYTES_V1;
            let payload_end = payload_start + payload_len;
            let payload = &bytes[payload_start..payload_end];
            let stored_digest: [u8; 32] = bytes[payload_end..payload_end + 32]
                .try_into()
                .expect("fixed journal digest");
            let expected_digest =
                digest_record(version, op_tag, payload_len as u32, prev_hash, payload);
            if stored_digest != expected_digest {
                return Err(PeerLeaseErrorV1::Rejected(
                    LeaseRejectCodeV1::AuthorityCorrupt,
                ));
            }
            let operation = LeaseOperationV1::from_tag(op_tag).ok_or(
                PeerLeaseErrorV1::Rejected(LeaseRejectCodeV1::AuthorityCorrupt),
            )?;
            let decoded = decode_record_payload(payload)
                .map_err(|_| PeerLeaseErrorV1::Rejected(LeaseRejectCodeV1::AuthorityCorrupt))?;
            self.apply_replayed(operation, decoded, stored_digest)?;
            self.last_hash = stored_digest;
            self.record_count =
                self.record_count
                    .checked_add(1)
                    .ok_or(PeerLeaseErrorV1::Rejected(
                        LeaseRejectCodeV1::AuthorityCorrupt,
                    ))?;
            self.last_now_ms = self.last_now_ms.max(decoded.observed_now_ms);
            offset += total;
        }
        Ok(())
    }

    fn reconcile_anchor(&mut self) -> Result<(), PeerLeaseErrorV1> {
        let bytes = match fs::read(&self.anchor_path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                if self.record_count != 0 {
                    return Err(PeerLeaseErrorV1::Rejected(
                        LeaseRejectCodeV1::AuthorityCorrupt,
                    ));
                }
                self.persist_anchor()?;
                return Ok(());
            }
            Err(error) => return Err(PeerLeaseErrorV1::Io(error)),
        };
        let (anchored_count, anchored_hash) = decode_head(&bytes)?;
        if anchored_count > self.record_count {
            return Err(PeerLeaseErrorV1::Rejected(
                LeaseRejectCodeV1::AuthorityCorrupt,
            ));
        }
        if anchored_count == self.record_count && anchored_hash != self.last_hash {
            return Err(PeerLeaseErrorV1::Rejected(
                LeaseRejectCodeV1::AuthorityCorrupt,
            ));
        }
        // A crash after the journal fsync but before the head publication is
        // safe to recover: the authenticated journal is ahead and the anchor
        // is advanced to that exact head. The inverse (anchor ahead of log)
        // is always a hard failure above.
        if anchored_count < self.record_count {
            self.persist_anchor()?;
        }
        Ok(())
    }

    fn persist_anchor(&self) -> Result<(), PeerLeaseErrorV1> {
        let name = self
            .anchor_path
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or(PeerLeaseErrorV1::InvalidRequest("journal anchor filename"))?;
        let temporary = self.anchor_path.with_file_name(format!(
            ".{name}.tmp-{}-{}",
            std::process::id(),
            self.record_count
        ));
        let bytes = encode_head(self.record_count, self.last_hash);
        let result = (|| {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
                .open(&temporary)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            fs::rename(&temporary, &self.anchor_path)?;
            self.directory.sync_all()?;
            Ok::<(), std::io::Error>(())
        })();
        if let Err(error) = result {
            let _ = fs::remove_file(&temporary);
            return Err(PeerLeaseErrorV1::Io(error));
        }
        Ok(())
    }

    fn apply_replayed(
        &mut self,
        operation: LeaseOperationV1,
        record: DecodedRecordV1,
        record_hash: [u8; 32],
    ) -> Result<(), PeerLeaseErrorV1> {
        let current = self.entries.get(&record.scope).copied();
        let latest = self.latest_generation(record.scope);
        match operation {
            LeaseOperationV1::Acquire => {
                if record.generation != latest.saturating_add(1)
                    || self
                        .seen_sessions
                        .contains(&(record.scope, record.session_id))
                    || current.is_some_and(|state| record.observed_now_ms < state.expires_at_ms)
                    || record.expires_at_ms <= record.observed_now_ms
                {
                    return Err(PeerLeaseErrorV1::Rejected(
                        LeaseRejectCodeV1::AuthorityCorrupt,
                    ));
                }
                self.generations.insert(record.scope, record.generation);
                self.seen_sessions.insert((record.scope, record.session_id));
                self.entries.insert(
                    record.scope,
                    LeaseStateV1 {
                        session_id: record.session_id,
                        generation: record.generation,
                        expires_at_ms: record.expires_at_ms,
                        record_hash,
                    },
                );
            }
            LeaseOperationV1::Renew => {
                let state = current.ok_or(PeerLeaseErrorV1::Rejected(
                    LeaseRejectCodeV1::AuthorityCorrupt,
                ))?;
                if state.session_id != record.session_id
                    || state.generation != record.generation
                    || record.observed_now_ms >= state.expires_at_ms
                    || record.expires_at_ms <= record.observed_now_ms
                {
                    return Err(PeerLeaseErrorV1::Rejected(
                        LeaseRejectCodeV1::AuthorityCorrupt,
                    ));
                }
                self.entries.insert(
                    record.scope,
                    LeaseStateV1 {
                        session_id: record.session_id,
                        generation: record.generation,
                        expires_at_ms: record.expires_at_ms,
                        record_hash,
                    },
                );
            }
            LeaseOperationV1::Release => {
                let state = current.ok_or(PeerLeaseErrorV1::Rejected(
                    LeaseRejectCodeV1::AuthorityCorrupt,
                ))?;
                if state.session_id != record.session_id
                    || state.generation != record.generation
                    || state.expires_at_ms == 0
                    || record.expires_at_ms != 0
                {
                    return Err(PeerLeaseErrorV1::Rejected(
                        LeaseRejectCodeV1::AuthorityCorrupt,
                    ));
                }
                self.entries.remove(&record.scope);
            }
            LeaseOperationV1::Revalidate => {
                return Err(PeerLeaseErrorV1::Rejected(
                    LeaseRejectCodeV1::AuthorityCorrupt,
                ));
            }
        }
        Ok(())
    }
}

fn validate_request(request: LeaseRequestV1) -> Result<(), PeerLeaseErrorV1> {
    if request.scope.local_id() == [0; 32]
        || request.scope.remote_id() == [0; 32]
        || request.scope.validator_set_id() == [0; 32]
        || request.scope.local_id() == request.scope.remote_id()
        || request.session_id == [0; 32]
    {
        return Err(PeerLeaseErrorV1::InvalidRequest("invalid lease identity"));
    }
    match request.operation {
        LeaseOperationV1::Acquire | LeaseOperationV1::Renew => {
            if request.generation == 0 {
                return Err(PeerLeaseErrorV1::InvalidRequest(
                    "lease generation must be positive",
                ));
            }
            if !(MIN_TTL_MS_V1..=MAX_TTL_MS_V1).contains(&request.ttl_ms) {
                return Err(PeerLeaseErrorV1::InvalidRequest(
                    "lease TTL is outside the bounded profile",
                ));
            }
        }
        LeaseOperationV1::Revalidate | LeaseOperationV1::Release => {}
    }
    Ok(())
}

fn ensure_token_matches(
    request: LeaseRequestV1,
    state: LeaseStateV1,
) -> Result<(), PeerLeaseErrorV1> {
    if request.session_id != state.session_id || request.generation != state.generation {
        return Err(PeerLeaseErrorV1::Rejected(LeaseRejectCodeV1::Fenced));
    }
    if request.expires_at_ms != state.expires_at_ms || request.record_hash != state.record_hash {
        return Err(PeerLeaseErrorV1::Rejected(LeaseRejectCodeV1::Fenced));
    }
    Ok(())
}

#[derive(Debug, Clone, Copy)]
struct DecodedRecordV1 {
    scope: PeerLeaseScopeV1,
    session_id: [u8; 32],
    generation: u64,
    expires_at_ms: u64,
    observed_now_ms: u64,
}

struct EncodedRecordV1 {
    bytes: Vec<u8>,
    digest: [u8; 32],
}

fn head_checksum(body: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(HEAD_MAGIC_V1);
    hasher.update((body.len() as u64).to_le_bytes());
    hasher.update(body);
    hasher.finalize().into()
}

fn encode_head(record_count: u64, head_hash: [u8; 32]) -> [u8; HEAD_BYTES_V1] {
    let mut bytes = [0u8; HEAD_BYTES_V1];
    bytes[..4].copy_from_slice(&HEAD_MAGIC_V1);
    bytes[4] = HEAD_VERSION_V1;
    bytes[5..8].copy_from_slice(&[0, 0, 0]);
    bytes[8..16].copy_from_slice(&record_count.to_le_bytes());
    bytes[16..48].copy_from_slice(&head_hash);
    let checksum = head_checksum(&bytes[..HEAD_BODY_BYTES_V1]);
    bytes[HEAD_BODY_BYTES_V1..].copy_from_slice(&checksum);
    bytes
}

fn decode_head(bytes: &[u8]) -> Result<(u64, [u8; 32]), PeerLeaseErrorV1> {
    if bytes.len() != HEAD_BYTES_V1
        || bytes[..4] != HEAD_MAGIC_V1
        || bytes[4] != HEAD_VERSION_V1
        || bytes[5..8] != [0, 0, 0]
    {
        return Err(PeerLeaseErrorV1::Rejected(
            LeaseRejectCodeV1::AuthorityCorrupt,
        ));
    }
    if bytes[HEAD_BODY_BYTES_V1..] != head_checksum(&bytes[..HEAD_BODY_BYTES_V1]) {
        return Err(PeerLeaseErrorV1::Rejected(
            LeaseRejectCodeV1::AuthorityCorrupt,
        ));
    }
    let count = u64::from_le_bytes(bytes[8..16].try_into().expect("head count"));
    let head = bytes[16..48].try_into().expect("head hash");
    if (count == 0) != (head == [0; 32]) {
        return Err(PeerLeaseErrorV1::Rejected(
            LeaseRejectCodeV1::AuthorityCorrupt,
        ));
    }
    Ok((count, head))
}

fn encode_record(
    operation: LeaseOperationV1,
    scope: PeerLeaseScopeV1,
    session_id: [u8; 32],
    generation: u64,
    expires_at_ms: u64,
    observed_now_ms: u64,
    prev_hash: [u8; 32],
) -> EncodedRecordV1 {
    let mut payload = Vec::with_capacity(RECORD_PAYLOAD_BYTES_V1);
    payload.push(operation.tag());
    payload.extend_from_slice(&scope.local_id());
    payload.extend_from_slice(&scope.remote_id());
    payload.push(scope.direction() as u8);
    payload.extend_from_slice(&scope.epoch().to_le_bytes());
    payload.extend_from_slice(&scope.validator_set_id());
    payload.extend_from_slice(&session_id);
    payload.extend_from_slice(&generation.to_le_bytes());
    payload.extend_from_slice(&expires_at_ms.to_le_bytes());
    payload.extend_from_slice(&observed_now_ms.to_le_bytes());
    let digest = digest_record(
        RECORD_VERSION_V1,
        operation.tag(),
        payload.len() as u32,
        prev_hash,
        &payload,
    );
    let mut bytes = Vec::with_capacity(RECORD_HEADER_BYTES_V1 + payload.len() + 32);
    bytes.extend_from_slice(&RECORD_MAGIC_V1);
    bytes.push(RECORD_VERSION_V1);
    bytes.push(operation.tag());
    bytes.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&prev_hash);
    bytes.extend_from_slice(&payload);
    bytes.extend_from_slice(&digest);
    EncodedRecordV1 { bytes, digest }
}

fn decode_record_payload(payload: &[u8]) -> Result<DecodedRecordV1, ()> {
    if payload.len() != RECORD_PAYLOAD_BYTES_V1 {
        return Err(());
    }
    let operation_tag = payload[0];
    if LeaseOperationV1::from_tag(operation_tag).is_none() {
        return Err(());
    }
    let local_id: [u8; 32] = payload[1..33].try_into().map_err(|_| ())?;
    let remote_id: [u8; 32] = payload[33..65].try_into().map_err(|_| ())?;
    let direction = PeerLeaseDirectionV1::from_u8(payload[65]).ok_or(())?;
    let epoch = u64::from_le_bytes(payload[66..74].try_into().map_err(|_| ())?);
    let set_id: [u8; 32] = payload[74..106].try_into().map_err(|_| ())?;
    let session_id: [u8; 32] = payload[106..138].try_into().map_err(|_| ())?;
    let generation = u64::from_le_bytes(payload[138..146].try_into().map_err(|_| ())?);
    let expires_at_ms = u64::from_le_bytes(payload[146..154].try_into().map_err(|_| ())?);
    let observed_now_ms = u64::from_le_bytes(payload[154..162].try_into().map_err(|_| ())?);
    Ok(DecodedRecordV1 {
        scope: PeerLeaseScopeV1::new(local_id, remote_id, direction, epoch, set_id)
            .map_err(|_| ())?,
        session_id,
        generation,
        expires_at_ms,
        observed_now_ms,
    })
}

fn digest_record(
    version: u8,
    operation: u8,
    payload_len: u32,
    prev_hash: [u8; 32],
    payload: &[u8],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(RECORD_MAGIC_V1);
    hasher.update([version, operation]);
    hasher.update(payload_len.to_le_bytes());
    hasher.update(prev_hash);
    hasher.update(payload);
    hasher.finalize().into()
}

fn open_append_file(path: &Path) -> Result<File, PeerLeaseErrorV1> {
    let mut options = OpenOptions::new();
    options.create(true).read(true).append(true);
    #[cfg(unix)]
    {
        options
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    let file = options.open(path)?;
    ensure_private_regular_file(&file)?;
    Ok(file)
}

fn open_lock_file(path: &Path) -> Result<File, PeerLeaseErrorV1> {
    let lock_path = path.with_extension("lease-lock");
    let mut options = OpenOptions::new();
    options.create(true).read(true).write(true);
    #[cfg(unix)]
    {
        options
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    let file = options.open(lock_path)?;
    ensure_private_regular_file(&file)?;
    Ok(file)
}

fn anchor_path_for(path: &Path) -> PathBuf {
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("lease");
    path.with_file_name(format!(".{name}.head-v1"))
}

fn ensure_private_directory(path: &Path) -> Result<(), PeerLeaseErrorV1> {
    let metadata = fs::symlink_metadata(path)?;
    #[cfg(unix)]
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(PeerLeaseErrorV1::InvalidRequest(
            "journal parent must be a directory",
        ));
    }
    #[cfg(not(unix))]
    if !metadata.is_dir() {
        return Err(PeerLeaseErrorV1::InvalidRequest(
            "journal parent must be a directory",
        ));
    }
    Ok(())
}

fn ensure_private_regular_file(file: &File) -> Result<(), PeerLeaseErrorV1> {
    let metadata = file.metadata()?;
    #[cfg(unix)]
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(PeerLeaseErrorV1::InvalidRequest(
            "journal authority file must be a private regular file",
        ));
    }
    #[cfg(not(unix))]
    if !metadata.is_file() {
        return Err(PeerLeaseErrorV1::InvalidRequest(
            "journal authority file must be a regular file",
        ));
    }
    Ok(())
}

fn sync_parent_dir(path: &Path) -> Result<(), PeerLeaseErrorV1> {
    if let Some(parent) = path.parent() {
        let directory = File::open(parent)?;
        directory.sync_all()?;
    }
    Ok(())
}

pub(crate) fn now_ms() -> Result<u64, PeerLeaseErrorV1> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| PeerLeaseErrorV1::InvalidRequest("system clock predates Unix epoch"))
        .and_then(|duration| {
            u64::try_from(duration.as_millis())
                .map_err(|_| PeerLeaseErrorV1::InvalidRequest("system clock overflow"))
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{LeaseOperationV1, LeaseRequestV1, PeerLeaseScopeV1};
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    fn private_tempdir() -> tempfile::TempDir {
        let directory = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        directory
    }

    fn scope() -> PeerLeaseScopeV1 {
        PeerLeaseScopeV1::new([1; 32], [2; 32], PeerLeaseDirectionV1::Outbound, 3, [4; 32]).unwrap()
    }

    fn acquire(session: [u8; 32], generation: u64) -> LeaseRequestV1 {
        LeaseRequestV1 {
            operation: LeaseOperationV1::Acquire,
            scope: scope(),
            session_id: session,
            generation,
            expires_at_ms: 0,
            ttl_ms: 10_000,
            record_hash: [0; 32],
        }
    }

    #[test]
    fn journal_restarts_and_fences_stale_generation() {
        let directory = private_tempdir();
        let path = directory.path().join("leases.log");
        let mut store = PeerLeaseStoreV1::open(&path).unwrap();
        let first = store.apply(acquire([5; 32], 1), 1_000).unwrap();
        let release = LeaseRequestV1 {
            operation: LeaseOperationV1::Release,
            scope: first.scope(),
            session_id: first.session_id(),
            generation: first.generation(),
            expires_at_ms: first.expires_at_ms(),
            ttl_ms: 0,
            record_hash: first.record_hash(),
        };
        store.apply(release, 2_000).unwrap();
        drop(store);
        let mut restarted = PeerLeaseStoreV1::open(&path).unwrap();
        let second = restarted.apply(acquire([6; 32], 2), 3_000).unwrap();
        assert_eq!(second.generation(), first.generation() + 1);
        assert_eq!(restarted.latest_generation(scope()), 2);
        assert_eq!(restarted.last_now_ms(), 3_000);
    }

    #[test]
    fn byte_tamper_and_partial_record_are_fail_stop() {
        let directory = private_tempdir();
        let path = directory.path().join("leases.log");
        let mut store = PeerLeaseStoreV1::open(&path).unwrap();
        store.apply(acquire([5; 32], 1), 1_000).unwrap();
        drop(store);
        let mut bytes = std::fs::read(&path).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x80;
        std::fs::write(&path, &bytes).unwrap();
        assert!(matches!(
            PeerLeaseStoreV1::open(&path),
            Err(PeerLeaseErrorV1::Rejected(
                LeaseRejectCodeV1::AuthorityCorrupt
            ))
        ));

        let partial_path = directory.path().join("partial.log");
        let mut partial = PeerLeaseStoreV1::open(&partial_path).unwrap();
        partial.apply(acquire([7; 32], 1), 1_000).unwrap();
        drop(partial);
        let mut partial_bytes = std::fs::read(&partial_path).unwrap();
        partial_bytes.truncate(partial_bytes.len() - 3);
        std::fs::write(&partial_path, partial_bytes).unwrap();
        assert!(matches!(
            PeerLeaseStoreV1::open(&partial_path),
            Err(PeerLeaseErrorV1::Rejected(
                LeaseRejectCodeV1::AuthorityCorrupt
            ))
        ));

        // A complete-record rollback is indistinguishable from a valid
        // prefix to a bare hash chain. The independent head anchor must make
        // that rollback fail closed as well.
        let rollback_path = directory.path().join("rollback.log");
        let mut rollback = PeerLeaseStoreV1::open(&rollback_path).unwrap();
        rollback.apply(acquire([9; 32], 1), 1_000).unwrap();
        drop(rollback);
        let bytes = std::fs::read(&rollback_path).unwrap();
        let record_bytes =
            RECORD_HEADER_BYTES_V1 + RECORD_PAYLOAD_BYTES_V1 + RECORD_DIGEST_BYTES_V1;
        std::fs::write(&rollback_path, &bytes[..bytes.len() - record_bytes]).unwrap();
        assert!(matches!(
            PeerLeaseStoreV1::open(&rollback_path),
            Err(PeerLeaseErrorV1::Rejected(
                LeaseRejectCodeV1::AuthorityCorrupt
            ))
        ));
    }

    #[test]
    fn clock_rollback_and_second_store_open_fail_closed() {
        let directory = private_tempdir();
        let path = directory.path().join("leases.log");
        let mut store = PeerLeaseStoreV1::open(&path).unwrap();
        store.apply(acquire([8; 32], 1), 2_000).unwrap();
        assert!(matches!(
            store.apply(acquire([9; 32], 1), 1_999),
            Err(PeerLeaseErrorV1::Rejected(LeaseRejectCodeV1::ClockRollback))
        ));
        assert!(matches!(
            PeerLeaseStoreV1::open(&path),
            Err(PeerLeaseErrorV1::Io(_))
        ));
    }
}
