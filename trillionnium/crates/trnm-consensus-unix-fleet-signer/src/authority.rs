#![forbid(unsafe_code)]

//! Durable, cross-process fleet-root signing authority.
//!
//! The authority owns only a private namespace lock and an append-only
//! request/response hash chain.  A caller supplies a signer implementation;
//! the default crate has no private-key type.  The test-only fixture supplies
//! a deterministic signer behind the explicit `test-fixture` feature.

use std::{
    collections::BTreeMap,
    error::Error,
    fmt,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

use fs2::FileExt;
use sha2::{Digest, Sha256};

use crate::{FleetRootRequestV1, FleetSignerProtocolErrorV1};
use trnm_consensus_crypto::StrictEd25519Verifier;
use trnm_consensus_types::{
    ConsensusPublicKey, SignatureBytes, SignatureVerifier, SigningRoot, Validator, ValidatorId,
    VotingPower,
};

const LOG_MAGIC_V1: &[u8; 8] = b"TRNMFH01";
const LOG_DOMAIN_V1: &[u8] = b"trnm.consensus.unix-fleet-root.authority-record.v1\0";
const ANCHOR_MAGIC_V1: &[u8; 8] = b"TRNMFA01";
const CHECKSUM_DOMAIN_V1: &[u8] = b"trnm.consensus.unix-fleet-root.authority-anchor.v1\0";
const SCHEMA_V1: u8 = 1;
const MAX_LOG_BYTES_V1: u64 = 64 * 1024 * 1024;
const MAX_ORIGIN_BYTES_V1: usize = 128;
// magic + schema/reserved + sequence + purpose/reserved + origin length +
// fixed origin + set/root/nonce/fingerprint + signature + predecessor/hash.
const RECORD_BYTES_V1: usize = 8 + 4 + 8 + 4 + 2 + MAX_ORIGIN_BYTES_V1 + 32 * 4 + 64 + 32 + 32;
// magic + schema/reserved + sequence + origin length + fixed origin + set id + head.
const ANCHOR_BODY_BYTES_V1: usize = 8 + 4 + 8 + 2 + MAX_ORIGIN_BYTES_V1 + 32 + 32;
const ANCHOR_BYTES_V1: usize = ANCHOR_BODY_BYTES_V1 + 32;

/// Fail-closed authority failures. A poisoned authority never signs another
/// request in its process lifetime.
#[derive(Debug)]
pub enum FleetRootAuthorityErrorV1 {
    InvalidConfig(&'static str),
    InvalidLog(&'static str),
    Io {
        stage: &'static str,
        source: io::Error,
    },
    Conflict(&'static str),
    BindingMismatch(&'static str),
    ReplayConflict,
    SignatureInvalid,
    Poisoned,
    Protocol(FleetSignerProtocolErrorV1),
}

impl fmt::Display for FleetRootAuthorityErrorV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(reason) => write!(f, "invalid fleet authority config: {reason}"),
            Self::InvalidLog(reason) => write!(f, "fleet authority log rejected: {reason}"),
            Self::Io { stage, source } => write!(f, "fleet authority I/O at {stage}: {source}"),
            Self::Conflict(reason) => write!(f, "fleet authority conflict: {reason}"),
            Self::BindingMismatch(reason) => {
                write!(f, "fleet authority binding mismatch: {reason}")
            }
            Self::ReplayConflict => f.write_str("fleet authority nonce replay conflicts"),
            Self::SignatureInvalid => {
                f.write_str("fleet authority signer returned invalid signature")
            }
            Self::Poisoned => f.write_str("fleet authority is poisoned"),
            Self::Protocol(error) => write!(f, "fleet authority request protocol: {error}"),
        }
    }
}

impl Error for FleetRootAuthorityErrorV1 {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Protocol(error) => Some(error),
            _ => None,
        }
    }
}

impl From<FleetSignerProtocolErrorV1> for FleetRootAuthorityErrorV1 {
    fn from(value: FleetSignerProtocolErrorV1) -> Self {
        Self::Protocol(value)
    }
}

/// Private-key provider boundary. Implementors live outside the default
/// library; the authority only receives an exact typed request and signature.
pub trait FleetRootAuthoritySignerV1: Send {
    fn sign_fleet_root_authority_v1(
        &mut self,
        request: &FleetRootRequestV1,
    ) -> Result<[u8; 64], FleetRootAuthorityErrorV1>;
}

#[derive(Debug, Clone, Copy)]
struct AuthorityRecordV1 {
    sequence: u64,
    request: FleetRootRequestV1,
    fingerprint: [u8; 32],
    signature: [u8; 64],
    previous_hash: [u8; 32],
    record_hash: [u8; 32],
}

/// One process-owned durable authority namespace. Opening a second process on
/// the same log fails at the exclusive lock boundary.
pub struct DurableFleetRootSignerAuthorityV1<S> {
    log_path: PathBuf,
    anchor_path: PathBuf,
    directory: File,
    log: File,
    _lock: File,
    origin: ValidatorId,
    validator_set_id: [u8; 32],
    verifying_key: [u8; 32],
    signer: S,
    by_fingerprint: BTreeMap<[u8; 32], ([u8; 32], [u8; 64])>,
    by_nonce: BTreeMap<[u8; 32], [u8; 32]>,
    head_hash: [u8; 32],
    sequence: u64,
    poisoned: bool,
}

impl<S: FleetRootAuthoritySignerV1> DurableFleetRootSignerAuthorityV1<S> {
    /// Opens and authenticates a namespace. Existing logs must have a valid
    /// complete chain and anchor; no partial tail or missing anchor is
    /// tolerated. `verifying_key` is public verification material only.
    pub fn open(
        log_path: impl AsRef<Path>,
        origin: ValidatorId,
        validator_set_id: [u8; 32],
        verifying_key: [u8; 32],
        signer: S,
    ) -> Result<Self, FleetRootAuthorityErrorV1> {
        if origin.is_zero() {
            return Err(FleetRootAuthorityErrorV1::InvalidConfig(
                "authority origin is zero",
            ));
        }
        if validator_set_id == [0; 32] {
            return Err(FleetRootAuthorityErrorV1::InvalidConfig(
                "authority validator-set id is zero",
            ));
        }
        if verifying_key == [0; 32] {
            return Err(FleetRootAuthorityErrorV1::InvalidConfig(
                "verifying key is zero",
            ));
        }
        let log_path = log_path.as_ref();
        if !log_path.is_absolute() {
            return Err(FleetRootAuthorityErrorV1::InvalidConfig(
                "authority log path must be absolute",
            ));
        }
        let parent = log_path
            .parent()
            .ok_or(FleetRootAuthorityErrorV1::InvalidConfig(
                "log has no parent",
            ))?;
        fs::create_dir_all(parent).map_err(|source| FleetRootAuthorityErrorV1::Io {
            stage: "create authority directory",
            source,
        })?;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).map_err(|source| {
            FleetRootAuthorityErrorV1::Io {
                stage: "set authority directory mode",
                source,
            }
        })?;
        let directory = File::open(parent).map_err(|source| FleetRootAuthorityErrorV1::Io {
            stage: "open authority directory",
            source,
        })?;
        ensure_private_directory(parent)?;
        let file_name = log_path.file_name().and_then(|name| name.to_str()).ok_or(
            FleetRootAuthorityErrorV1::InvalidConfig("invalid authority log name"),
        )?;
        let lock_path = parent.join(format!(".{file_name}.lock"));
        let anchor_path = parent.join(format!(".{file_name}.anchor"));
        let lock = open_private_file(&lock_path, true, false).map_err(|source| {
            FleetRootAuthorityErrorV1::Io {
                stage: "open authority namespace lock",
                source,
            }
        })?;
        ensure_private_regular(&lock, "authority namespace lock")?;
        lock.try_lock_exclusive()
            .map_err(|source| FleetRootAuthorityErrorV1::Io {
                stage: "lock authority namespace",
                source,
            })?;
        let log = open_private_file(log_path, true, true).map_err(|source| {
            FleetRootAuthorityErrorV1::Io {
                stage: "open authority append-only log",
                source,
            }
        })?;
        ensure_private_regular(&log, "authority log")?;
        let mut authority = Self {
            log_path: log_path.to_path_buf(),
            anchor_path,
            directory,
            log,
            _lock: lock,
            origin,
            validator_set_id,
            verifying_key,
            signer,
            by_fingerprint: BTreeMap::new(),
            by_nonce: BTreeMap::new(),
            head_hash: [0; 32],
            sequence: 0,
            poisoned: false,
        };
        authority.replay_log()?;
        authority.reconcile_anchor()?;
        Ok(authority)
    }

    pub fn log_path(&self) -> &Path {
        &self.log_path
    }

    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    pub const fn poisoned(&self) -> bool {
        self.poisoned
    }

    /// Exact duplicate requests return the persisted signature without
    /// touching the signer. A nonce reused by a different intent is rejected.
    pub fn sign_fleet_root_v1(
        &mut self,
        request: &FleetRootRequestV1,
    ) -> Result<[u8; 64], FleetRootAuthorityErrorV1> {
        if self.poisoned {
            return Err(FleetRootAuthorityErrorV1::Poisoned);
        }
        request.validate()?;
        if request.origin() != self.origin {
            return Err(FleetRootAuthorityErrorV1::BindingMismatch(
                "request origin differs from authority namespace",
            ));
        }
        if request.validator_set_id() != self.validator_set_id {
            return Err(FleetRootAuthorityErrorV1::BindingMismatch(
                "request validator-set differs from authority namespace",
            ));
        }
        let fingerprint = request.fingerprint()?;
        if let Some((bound_root, signature)) = self.by_fingerprint.get(&fingerprint).copied() {
            if bound_root != request.signing_root() {
                self.poisoned = true;
                return Err(FleetRootAuthorityErrorV1::Conflict(
                    "fingerprint is bound to a different root",
                ));
            }
            return Ok(signature);
        }
        if let Some(previous) = self.by_nonce.get(&request.nonce()) {
            if previous != &fingerprint {
                return Err(FleetRootAuthorityErrorV1::ReplayConflict);
            }
        }
        let signature = self.signer.sign_fleet_root_authority_v1(request)?;
        self.verify_signature(request, signature)?;
        self.append_record(*request, fingerprint, signature)?;
        Ok(signature)
    }

    fn verify_signature(
        &self,
        request: &FleetRootRequestV1,
        signature: [u8; 64],
    ) -> Result<(), FleetRootAuthorityErrorV1> {
        let validator = Validator::new(
            self.origin,
            ConsensusPublicKey::new(self.verifying_key),
            VotingPower::new(1).map_err(|_| FleetRootAuthorityErrorV1::InvalidConfig("power"))?,
        )
        .map_err(|_| FleetRootAuthorityErrorV1::InvalidConfig("verifying key shape"))?;
        let root = SigningRoot::new(request.signing_root());
        let bytes = SignatureBytes::from_array(signature);
        if StrictEd25519Verifier.verify(&validator, &root, &bytes) {
            Ok(())
        } else {
            Err(FleetRootAuthorityErrorV1::SignatureInvalid)
        }
    }

    fn append_record(
        &mut self,
        request: FleetRootRequestV1,
        fingerprint: [u8; 32],
        signature: [u8; 64],
    ) -> Result<(), FleetRootAuthorityErrorV1> {
        let sequence = self
            .sequence
            .checked_add(1)
            .ok_or(FleetRootAuthorityErrorV1::InvalidLog("sequence exhausted"))?;
        let previous_hash = self.head_hash;
        let mut record = AuthorityRecordV1 {
            sequence,
            request,
            fingerprint,
            signature,
            previous_hash,
            record_hash: [0; 32],
        };
        let preimage = encode_record_without_hash(&record)?;
        record.record_hash = hash_record(&preimage);
        let encoded = encode_record(&record)?;
        let current_len = self
            .log
            .metadata()
            .map_err(|source| FleetRootAuthorityErrorV1::Io {
                stage: "stat authority log before append",
                source,
            })?
            .len();
        if current_len != self.sequence.saturating_mul(RECORD_BYTES_V1 as u64) {
            self.poisoned = true;
            return Err(FleetRootAuthorityErrorV1::InvalidLog(
                "authority log length changed while open",
            ));
        }
        if current_len.saturating_add(encoded.len() as u64) > MAX_LOG_BYTES_V1 {
            return Err(FleetRootAuthorityErrorV1::InvalidLog(
                "authority log capacity exhausted",
            ));
        }
        if let Err(source) = self.log.write_all(&encoded) {
            self.poisoned = true;
            return Err(FleetRootAuthorityErrorV1::Io {
                stage: "append authority record",
                source,
            });
        }
        if let Err(source) = self.log.sync_data() {
            self.poisoned = true;
            return Err(FleetRootAuthorityErrorV1::Io {
                stage: "sync authority record",
                source,
            });
        }
        if let Err(source) = self.directory.sync_data() {
            self.poisoned = true;
            return Err(FleetRootAuthorityErrorV1::Io {
                stage: "sync authority directory",
                source,
            });
        }
        self.sequence = sequence;
        self.head_hash = record.record_hash;
        self.by_fingerprint
            .insert(fingerprint, (request.signing_root(), signature));
        self.by_nonce.insert(request.nonce(), fingerprint);
        if let Err(error) = self.persist_anchor() {
            self.poisoned = true;
            return Err(error);
        }
        Ok(())
    }

    fn replay_log(&mut self) -> Result<(), FleetRootAuthorityErrorV1> {
        let metadata = self
            .log
            .metadata()
            .map_err(|source| FleetRootAuthorityErrorV1::Io {
                stage: "stat authority log",
                source,
            })?;
        if metadata.len() > MAX_LOG_BYTES_V1 {
            return Err(FleetRootAuthorityErrorV1::InvalidLog(
                "authority log too large",
            ));
        }
        let mut bytes = Vec::new();
        self.log
            .try_clone()
            .map_err(|source| FleetRootAuthorityErrorV1::Io {
                stage: "clone authority log",
                source,
            })?
            .take(MAX_LOG_BYTES_V1 + 1)
            .read_to_end(&mut bytes)
            .map_err(|source| FleetRootAuthorityErrorV1::Io {
                stage: "read authority log",
                source,
            })?;
        if bytes.len() as u64 > MAX_LOG_BYTES_V1 || bytes.len() % RECORD_BYTES_V1 != 0 {
            return Err(FleetRootAuthorityErrorV1::InvalidLog(
                "authority log has partial or oversized tail",
            ));
        }
        for chunk in bytes.chunks_exact(RECORD_BYTES_V1) {
            let record = decode_record(chunk)?;
            let expected = self
                .sequence
                .checked_add(1)
                .ok_or(FleetRootAuthorityErrorV1::InvalidLog("sequence exhausted"))?;
            if record.sequence != expected || record.previous_hash != self.head_hash {
                return Err(FleetRootAuthorityErrorV1::InvalidLog(
                    "authority sequence or predecessor differs",
                ));
            }
            let preimage = encode_record_without_hash(&record)?;
            if record.record_hash != hash_record(&preimage) {
                return Err(FleetRootAuthorityErrorV1::InvalidLog(
                    "authority record hash differs",
                ));
            }
            let expected_fingerprint = record.request.fingerprint()?;
            if expected_fingerprint != record.fingerprint {
                return Err(FleetRootAuthorityErrorV1::InvalidLog(
                    "authority request fingerprint differs",
                ));
            }
            if record.request.origin() != self.origin {
                return Err(FleetRootAuthorityErrorV1::InvalidLog(
                    "authority record origin differs from namespace",
                ));
            }
            if record.request.validator_set_id() != self.validator_set_id {
                return Err(FleetRootAuthorityErrorV1::InvalidLog(
                    "authority record validator-set differs from namespace",
                ));
            }
            self.verify_signature(&record.request, record.signature)?;
            if self.by_fingerprint.contains_key(&record.fingerprint)
                || self.by_nonce.contains_key(&record.request.nonce())
            {
                return Err(FleetRootAuthorityErrorV1::InvalidLog(
                    "duplicate authority request identity",
                ));
            }
            self.by_fingerprint.insert(
                record.fingerprint,
                (record.request.signing_root(), record.signature),
            );
            self.by_nonce
                .insert(record.request.nonce(), record.fingerprint);
            self.sequence = record.sequence;
            self.head_hash = record.record_hash;
        }
        Ok(())
    }

    fn reconcile_anchor(&mut self) -> Result<(), FleetRootAuthorityErrorV1> {
        match fs::symlink_metadata(&self.anchor_path) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink()
                    || !metadata.is_file()
                    || metadata.permissions().mode() & 0o7777 != 0o600
                {
                    return Err(FleetRootAuthorityErrorV1::InvalidConfig(
                        "authority anchor must be a 0600 regular file",
                    ));
                }
                let bytes = fs::read(&self.anchor_path).map_err(|source| {
                    FleetRootAuthorityErrorV1::Io {
                        stage: "read authority anchor",
                        source,
                    }
                })?;
                if bytes.len() != ANCHOR_BYTES_V1
                    || &bytes[..8] != ANCHOR_MAGIC_V1
                    || bytes[8] != SCHEMA_V1
                    || bytes[9..12] != [0, 0, 0]
                {
                    return Err(FleetRootAuthorityErrorV1::InvalidLog(
                        "authority anchor envelope differs",
                    ));
                }
                let sequence = u64::from_be_bytes(bytes[12..20].try_into().unwrap());
                let origin_length = u16::from_be_bytes(bytes[20..22].try_into().unwrap()) as usize;
                if origin_length == 0 || origin_length > MAX_ORIGIN_BYTES_V1 {
                    return Err(FleetRootAuthorityErrorV1::InvalidLog(
                        "authority anchor origin length differs",
                    ));
                }
                let origin_bytes = &bytes[22..22 + MAX_ORIGIN_BYTES_V1];
                if origin_bytes[origin_length..].iter().any(|byte| *byte != 0) {
                    return Err(FleetRootAuthorityErrorV1::InvalidLog(
                        "authority anchor origin padding differs",
                    ));
                }
                let anchor_origin = ValidatorId::from_bytes(&origin_bytes[..origin_length])
                    .map_err(|_| {
                        FleetRootAuthorityErrorV1::InvalidLog("authority anchor origin")
                    })?;
                let set_start = 22 + MAX_ORIGIN_BYTES_V1;
                let anchor_set: [u8; 32] = bytes[set_start..set_start + 32].try_into().unwrap();
                let head_start = set_start + 32;
                let head: [u8; 32] = bytes[head_start..head_start + 32].try_into().unwrap();
                if checksum_anchor(&bytes[..ANCHOR_BODY_BYTES_V1]) != bytes[ANCHOR_BODY_BYTES_V1..]
                    || sequence != self.sequence
                    || anchor_origin != self.origin
                    || anchor_set != self.validator_set_id
                    || head != self.head_hash
                {
                    return Err(FleetRootAuthorityErrorV1::InvalidLog(
                        "authority anchor does not match log head",
                    ));
                }
                Ok(())
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                if self.sequence != 0 {
                    return Err(FleetRootAuthorityErrorV1::InvalidLog(
                        "non-empty authority log has no anchor",
                    ));
                }
                self.persist_anchor()
            }
            Err(source) => Err(FleetRootAuthorityErrorV1::Io {
                stage: "inspect authority anchor",
                source,
            }),
        }
    }

    fn persist_anchor(&self) -> Result<(), FleetRootAuthorityErrorV1> {
        let mut body = Vec::with_capacity(ANCHOR_BYTES_V1);
        body.extend_from_slice(ANCHOR_MAGIC_V1);
        body.extend_from_slice(&[SCHEMA_V1, 0, 0, 0]);
        body.extend_from_slice(&self.sequence.to_be_bytes());
        let origin = self.origin.as_bytes();
        body.extend_from_slice(&(origin.len() as u16).to_be_bytes());
        body.extend_from_slice(origin);
        body.resize(body.len() + (MAX_ORIGIN_BYTES_V1 - origin.len()), 0);
        body.extend_from_slice(&self.validator_set_id);
        body.extend_from_slice(&self.head_hash);
        body.extend_from_slice(&checksum_anchor(&body));
        let temporary = self
            .anchor_path
            .with_extension(format!("anchor.tmp-{}", std::process::id()));
        if temporary.exists() {
            let metadata = fs::symlink_metadata(&temporary).map_err(|source| {
                FleetRootAuthorityErrorV1::Io {
                    stage: "inspect authority anchor temporary",
                    source,
                }
            })?;
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(FleetRootAuthorityErrorV1::InvalidConfig(
                    "authority anchor temporary is not regular",
                ));
            }
            fs::remove_file(&temporary).map_err(|source| FleetRootAuthorityErrorV1::Io {
                stage: "remove authority anchor temporary",
                source,
            })?;
        }
        let result = (|| {
            let mut file = open_private_new(&temporary)?;
            file.write_all(&body)
                .map_err(|source| FleetRootAuthorityErrorV1::Io {
                    stage: "write authority anchor",
                    source,
                })?;
            file.sync_all()
                .map_err(|source| FleetRootAuthorityErrorV1::Io {
                    stage: "sync authority anchor",
                    source,
                })?;
            fs::rename(&temporary, &self.anchor_path).map_err(|source| {
                FleetRootAuthorityErrorV1::Io {
                    stage: "publish authority anchor",
                    source,
                }
            })?;
            self.directory
                .sync_data()
                .map_err(|source| FleetRootAuthorityErrorV1::Io {
                    stage: "sync authority anchor directory",
                    source,
                })
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }
}

fn ensure_private_directory(path: &Path) -> Result<(), FleetRootAuthorityErrorV1> {
    let metadata = fs::symlink_metadata(path).map_err(|source| FleetRootAuthorityErrorV1::Io {
        stage: "stat authority directory",
        source,
    })?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.permissions().mode() & 0o7777 != 0o700
    {
        return Err(FleetRootAuthorityErrorV1::InvalidConfig(
            "authority directory must be a 0700 regular directory",
        ));
    }
    Ok(())
}

fn ensure_private_regular(
    file: &File,
    name: &'static str,
) -> Result<(), FleetRootAuthorityErrorV1> {
    let metadata = file
        .metadata()
        .map_err(|source| FleetRootAuthorityErrorV1::Io {
            stage: "stat authority file",
            source,
        })?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.permissions().mode() & 0o7777 != 0o600
    {
        return Err(FleetRootAuthorityErrorV1::InvalidConfig(name));
    }
    Ok(())
}

fn open_private_file(path: &Path, create: bool, append: bool) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create(create)
        .append(append)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
}

fn open_private_new(path: &Path) -> Result<File, FleetRootAuthorityErrorV1> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|source| FleetRootAuthorityErrorV1::Io {
            stage: "create authority anchor temporary",
            source,
        })
}

fn encode_record_without_hash(
    record: &AuthorityRecordV1,
) -> Result<Vec<u8>, FleetRootAuthorityErrorV1> {
    let origin_id = record.request.origin();
    let origin = origin_id.as_bytes();
    if origin.is_empty() || origin.len() > MAX_ORIGIN_BYTES_V1 {
        return Err(FleetRootAuthorityErrorV1::InvalidLog("origin length"));
    }
    let mut bytes = Vec::with_capacity(RECORD_BYTES_V1 - 32);
    bytes.extend_from_slice(LOG_MAGIC_V1);
    bytes.extend_from_slice(&[SCHEMA_V1, 0, 0, 0]);
    bytes.extend_from_slice(&record.sequence.to_be_bytes());
    bytes.push(record.request.purpose().as_byte());
    bytes.extend_from_slice(&[0, 0, 0]);
    bytes.extend_from_slice(&(origin.len() as u16).to_be_bytes());
    bytes.extend_from_slice(origin);
    bytes.resize(bytes.len() + (MAX_ORIGIN_BYTES_V1 - origin.len()), 0);
    bytes.extend_from_slice(&record.request.validator_set_id());
    bytes.extend_from_slice(&record.request.signing_root());
    bytes.extend_from_slice(&record.request.nonce());
    bytes.extend_from_slice(&record.fingerprint);
    bytes.extend_from_slice(&record.signature);
    bytes.extend_from_slice(&record.previous_hash);
    Ok(bytes)
}

fn encode_record(record: &AuthorityRecordV1) -> Result<Vec<u8>, FleetRootAuthorityErrorV1> {
    let mut bytes = encode_record_without_hash(record)?;
    bytes.extend_from_slice(&record.record_hash);
    if bytes.len() != RECORD_BYTES_V1 {
        return Err(FleetRootAuthorityErrorV1::InvalidLog("record size"));
    }
    Ok(bytes)
}

fn decode_record(bytes: &[u8]) -> Result<AuthorityRecordV1, FleetRootAuthorityErrorV1> {
    if bytes.len() != RECORD_BYTES_V1
        || &bytes[..8] != LOG_MAGIC_V1
        || bytes[8] != SCHEMA_V1
        || bytes[9..12] != [0, 0, 0]
    {
        return Err(FleetRootAuthorityErrorV1::InvalidLog("record envelope"));
    }
    let sequence = u64::from_be_bytes(bytes[12..20].try_into().unwrap());
    let purpose = crate::FleetRootPurposeV1::from_byte(bytes[20])?;
    if bytes[21..24] != [0, 0, 0] {
        return Err(FleetRootAuthorityErrorV1::InvalidLog(
            "record reserved bytes",
        ));
    }
    let origin_length = u16::from_be_bytes(bytes[24..26].try_into().unwrap()) as usize;
    if origin_length == 0 || origin_length > MAX_ORIGIN_BYTES_V1 {
        return Err(FleetRootAuthorityErrorV1::InvalidLog(
            "record origin length",
        ));
    }
    let origin_bytes = &bytes[26..26 + MAX_ORIGIN_BYTES_V1];
    if origin_bytes[origin_length..].iter().any(|byte| *byte != 0) {
        return Err(FleetRootAuthorityErrorV1::InvalidLog(
            "record origin padding",
        ));
    }
    let origin = ValidatorId::from_bytes(&origin_bytes[..origin_length])
        .map_err(|_| FleetRootAuthorityErrorV1::InvalidLog("record origin"))?;
    let mut offset = 26 + MAX_ORIGIN_BYTES_V1;
    let set_id: [u8; 32] = bytes[offset..offset + 32].try_into().unwrap();
    offset += 32;
    let root: [u8; 32] = bytes[offset..offset + 32].try_into().unwrap();
    offset += 32;
    let nonce: [u8; 32] = bytes[offset..offset + 32].try_into().unwrap();
    offset += 32;
    let fingerprint: [u8; 32] = bytes[offset..offset + 32].try_into().unwrap();
    offset += 32;
    let signature: [u8; 64] = bytes[offset..offset + 64].try_into().unwrap();
    offset += 64;
    let previous_hash: [u8; 32] = bytes[offset..offset + 32].try_into().unwrap();
    offset += 32;
    let record_hash: [u8; 32] = bytes[offset..offset + 32].try_into().unwrap();
    let request = FleetRootRequestV1::new(purpose, origin, set_id, root, nonce)?;
    Ok(AuthorityRecordV1 {
        sequence,
        request,
        fingerprint,
        signature,
        previous_hash,
        record_hash,
    })
}

fn hash_record(bytes: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(LOG_DOMAIN_V1);
    hash.update(bytes);
    hash.finalize().into()
}

fn checksum_anchor(bytes: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(CHECKSUM_DOMAIN_V1);
    hash.update(bytes);
    hash.finalize().into()
}

#[cfg(all(test, feature = "test-fixture"))]
mod tests {
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    use ed25519_dalek::{Signer, SigningKey};
    use tempfile::tempdir;
    use trnm_consensus_types::ValidatorId;

    use super::*;

    struct CountingSigner {
        key: SigningKey,
        calls: Arc<AtomicUsize>,
    }

    impl FleetRootAuthoritySignerV1 for CountingSigner {
        fn sign_fleet_root_authority_v1(
            &mut self,
            request: &FleetRootRequestV1,
        ) -> Result<[u8; 64], FleetRootAuthorityErrorV1> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.key.sign(&request.signing_root()).to_bytes())
        }
    }

    fn authority(
        path: &Path,
        calls: Arc<AtomicUsize>,
    ) -> DurableFleetRootSignerAuthorityV1<CountingSigner> {
        let key = SigningKey::from_bytes(&[0x4a; 32]);
        DurableFleetRootSignerAuthorityV1::open(
            path,
            ValidatorId::from_bytes(b"authority-test-origin").expect("origin"),
            [0x71; 32],
            key.verifying_key().to_bytes(),
            CountingSigner { key, calls },
        )
        .expect("open authority")
    }

    #[test]
    fn exact_duplicate_replays_without_second_signer_call() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("authority.log");
        let calls = Arc::new(AtomicUsize::new(0));
        let mut authority = authority(&path, Arc::clone(&calls));
        let origin = ValidatorId::from_bytes(b"authority-test-origin").expect("origin");
        let request = FleetRootRequestV1::new(
            crate::FleetRootPurposeV1::Ready,
            origin,
            [0x71; 32],
            [0x81; 32],
            [0x91; 32],
        )
        .expect("request");
        let first = authority
            .sign_fleet_root_v1(&request)
            .expect("first signature");
        let replay = authority
            .sign_fleet_root_v1(&request)
            .expect("replay signature");
        assert_eq!(first, replay);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(authority.sequence(), 1);
    }

    #[test]
    fn origin_and_set_are_checked_before_signer() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("authority.log");
        let calls = Arc::new(AtomicUsize::new(0));
        let mut authority = authority(&path, Arc::clone(&calls));
        let wrong_origin = ValidatorId::from_bytes(b"other-authority-origin").expect("origin");
        let request = FleetRootRequestV1::new(
            crate::FleetRootPurposeV1::Ready,
            wrong_origin,
            [0x71; 32],
            [0x82; 32],
            [0x92; 32],
        )
        .expect("request");
        assert!(matches!(
            authority.sign_fleet_root_v1(&request),
            Err(FleetRootAuthorityErrorV1::BindingMismatch(_))
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }
}
