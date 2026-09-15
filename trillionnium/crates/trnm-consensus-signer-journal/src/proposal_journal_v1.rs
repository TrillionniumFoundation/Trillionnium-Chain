//! Candidate, fixed-epoch proposal-witness journal. This is local persistence,
//! not a new consensus wire/signing domain or a Core/Safety authorization.
//!
//! The caller must first validate the complete proposal using its real owner.
//! A separately commissioned, opaque monotonic anchor is mandatory. The log
//! stores one Prepared/Signed pair per strictly increasing view; exact replays
//! return the stored signature. Heights are context, not a cross-view ordering
//! rule: Core owns fork/parent validity. It never stores keys or signs votes.
//! Linux only; owner-controlled canonical ancestors and one cooperating owner
//! are required. Complete history is audited on every operation (bounded by
//! 4096 requests); this is not pruning, physical durability or HSM qualification.

use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Component, Path, PathBuf},
};

use fs2::FileExt;
use trnm_consensus_crypto::{validate_validator_set_strict_ed25519_v0, StrictEd25519Verifier};
use trnm_consensus_types::{
    BlockId, ConsensusParametersV0, Epoch, Height, SignatureBytes, SignatureVerifier, SigningRoot,
    ValidatorId, ValidatorSet, View,
};

use crate::{
    hash::hash_domain, ExternalMonotonicWatermarkV0, ProposalSignatureProducerV0,
    ProposalSignatureRequestV0, SignatureProducerErrorV0, SignerWatermarkV0,
};

const MAGIC: &[u8; 8] = b"TRNMPJ01";
const HEADER_BYTES: usize = 104;
const REQUEST_BYTES: usize = 120;
const RECORD_BYTES: usize = 8 + 1 + REQUEST_BYTES + 64 + 32 + 32;
const MAX_REQUESTS: usize = 4096;

/// A commissioned, candidate-only fixed-epoch signer context. Namespace and
/// external scope must not be reused across a different set, key or epoch.
#[derive(Clone)]
pub struct ProposalJournalProfileV1 {
    set: ValidatorSet,
    author: ValidatorId,
    signer_profile: [u8; 32],
    scope: [u8; 32],
    maximum_requests: usize,
    digest: [u8; 32],
}

impl ProposalJournalProfileV1 {
    pub fn new(
        set: ValidatorSet,
        parameters: ConsensusParametersV0,
        author: ValidatorId,
        signer_profile: [u8; 32],
        external_scope: [u8; 32],
        maximum_requests: usize,
    ) -> Result<Self, ProposalJournalErrorV1> {
        if set.protocol_version() != trnm_consensus_types::ProtocolVersion::V0
            || parameters.production_activation()
            || signer_profile == [0; 32]
            || external_scope == [0; 32]
            || !(1..=MAX_REQUESTS).contains(&maximum_requests)
            || set.validator(author).is_none()
        {
            return Err(ProposalJournalErrorV1::InvalidProfile);
        }
        set.validate_against_parameters(&parameters)
            .map_err(|_| ProposalJournalErrorV1::InvalidProfile)?;
        validate_validator_set_strict_ed25519_v0(&set)
            .map_err(|_| ProposalJournalErrorV1::InvalidProfile)?;
        let encoded = set
            .try_cev0_bytes()
            .map_err(|_| ProposalJournalErrorV1::InvalidProfile)?;
        let digest = hash_domain(
            "trnm.proposal-journal.profile.v1",
            &[
                &encoded,
                &parameters.canonical_bytes(),
                author.as_bytes(),
                &signer_profile,
                &external_scope,
                &(maximum_requests as u64).to_be_bytes(),
            ],
        );
        Ok(Self {
            set,
            author,
            signer_profile,
            scope: external_scope,
            maximum_requests,
            digest,
        })
    }

    fn maximum_bytes(&self) -> usize {
        HEADER_BYTES + self.maximum_requests * 2 * RECORD_BYTES
    }

    fn validate_request(
        &self,
        request: &ProposalSignatureRequestV0,
    ) -> Result<(), ProposalJournalErrorV1> {
        if request.validator_set_id() != self.set.id()
            || request.epoch() != self.set.epoch()
            || request.author() != self.author
            || request.signer_profile_ref() != self.signer_profile
            || request.expected_consensus_public_key()
                != self
                    .set
                    .validator(self.author)
                    .ok_or(ProposalJournalErrorV1::InvalidProfile)?
                    .consensus_key()
                    .into_bytes()
        {
            return Err(ProposalJournalErrorV1::InvalidRequest);
        }
        Ok(())
    }

    fn verify_signature(
        &self,
        request: &ProposalSignatureRequestV0,
        signature: SignatureBytes,
    ) -> bool {
        self.set.validator(self.author).is_some_and(|validator| {
            StrictEd25519Verifier.verify(validator, &request.signing_root(), &signature)
        })
    }
}

#[derive(Debug)]
pub enum ProposalJournalErrorV1 {
    InvalidProfile,
    InvalidRequest,
    Conflict,
    Capacity,
    Corrupt,
    Namespace,
    Locked,
    Anchor,
    NotReady,
    InvalidSignature,
    Producer(SignatureProducerErrorV0),
    Io(std::io::Error),
}

impl std::fmt::Display for ProposalJournalErrorV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "proposal journal: {self:?}")
    }
}
impl std::error::Error for ProposalJournalErrorV1 {}
impl From<std::io::Error> for ProposalJournalErrorV1 {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct Identity {
    device: u64,
    inode: u64,
}
impl Identity {
    fn of(metadata: &fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }
}

struct Namespace {
    path: PathBuf,
    parent: PathBuf,
    directory: File,
    file: File,
    directory_identity: Identity,
    file_identity: Identity,
    process: u32,
}

impl Namespace {
    fn open(path: &Path, fresh: bool) -> Result<Self, ProposalJournalErrorV1> {
        if !path.is_absolute()
            || path
                .components()
                .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
        {
            return Err(ProposalJournalErrorV1::Namespace);
        }
        let parent = path.parent().ok_or(ProposalJournalErrorV1::Namespace)?;
        if fs::canonicalize(parent)? != parent {
            return Err(ProposalJournalErrorV1::Namespace);
        }
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(parent)?;
        let meta = directory.metadata()?;
        // Safe ownership check without adding an unsafe syscall boundary.
        let process_uid = fs::metadata("/proc/self")?.uid();
        if !meta.is_dir() || meta.uid() != process_uid || meta.mode() & 0o077 != 0 {
            return Err(ProposalJournalErrorV1::Namespace);
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(fresh)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        FileExt::try_lock_exclusive(&file).map_err(|_| ProposalJournalErrorV1::Locked)?;
        let file_meta = file.metadata()?;
        let result = Self {
            path: path.to_path_buf(),
            parent: parent.to_path_buf(),
            directory_identity: Identity::of(&meta),
            file_identity: Identity::of(&file_meta),
            directory,
            file,
            process: std::process::id(),
        };
        result.check()?;
        Ok(result)
    }

    fn check(&self) -> Result<(), ProposalJournalErrorV1> {
        let directory = fs::symlink_metadata(&self.parent)?;
        let file = fs::symlink_metadata(&self.path)?;
        let opened_dir = self.directory.metadata()?;
        let opened_file = self.file.metadata()?;
        let uid = fs::metadata("/proc/self")?.uid();
        if std::process::id() != self.process
            || fs::canonicalize(&self.parent)? != self.parent
            || !directory.is_dir()
            || directory.file_type().is_symlink()
            || directory.uid() != uid
            || directory.mode() & 0o077 != 0
            || Identity::of(&directory) != self.directory_identity
            || Identity::of(&opened_dir) != self.directory_identity
            || !file.is_file()
            || file.file_type().is_symlink()
            || file.nlink() != 1
            || file.uid() != uid
            || file.mode() & 0o777 != 0o600
            || opened_file.nlink() != 1
            || opened_file.mode() & 0o777 != 0o600
            || Identity::of(&file) != self.file_identity
            || Identity::of(&opened_file) != self.file_identity
        {
            return Err(ProposalJournalErrorV1::Namespace);
        }
        Ok(())
    }

    fn sync(&self) -> Result<(), ProposalJournalErrorV1> {
        self.file.sync_all()?;
        self.directory.sync_all()?;
        self.check()
    }
}

struct Entry {
    request: ProposalSignatureRequestV0,
    signature: Option<SignatureBytes>,
}
struct Audit {
    journal_id: [u8; 32],
    head: SignerWatermarkV0,
    predecessor: Option<SignerWatermarkV0>,
    entries: Vec<Entry>,
    length: usize,
}

/// No Clone, live database/page cache, signer key, voting authority or activation
/// flag. Errors after a possible append/CAS/custody call leave this owner closed.
/// Drop and open_existing to re-audit. No record is truncated or deleted.
pub struct ProposalJournalV1<W> {
    namespace: Namespace,
    profile: ProposalJournalProfileV1,
    external: W,
    ready: bool,
    #[cfg(test)]
    fault: Option<(u64, &'static str)>,
    #[cfg(test)]
    fault_exit: bool,
}

impl<W: ExternalMonotonicWatermarkV0> ProposalJournalV1<W> {
    pub fn create_new(
        path: impl AsRef<Path>,
        profile: ProposalJournalProfileV1,
        external: W,
    ) -> Result<Self, ProposalJournalErrorV1> {
        if external.semantic_mode_v0() {
            return Err(ProposalJournalErrorV1::InvalidProfile);
        }
        let namespace = Namespace::open(path.as_ref(), true)?;
        let mut random = [0u8; 32];
        getrandom::getrandom(&mut random).map_err(|_| ProposalJournalErrorV1::InvalidProfile)?;
        let journal_id = hash_domain(
            "trnm.proposal-journal.instance.v1",
            &[&profile.digest, &random],
        );
        let mut header = Vec::with_capacity(HEADER_BYTES);
        header.extend_from_slice(MAGIC);
        header.extend_from_slice(&profile.digest);
        header.extend_from_slice(&journal_id);
        let checksum = hash_domain("trnm.proposal-journal.header.v1", &[&header]);
        header.extend_from_slice(&checksum);
        let mut result = Self {
            namespace,
            profile,
            external,
            ready: false,
            #[cfg(test)]
            fault: None,
            #[cfg(test)]
            fault_exit: false,
        };
        result.namespace.file.write_all(&header)?;
        result.namespace.sync()?;
        let audit = result.audit()?;
        // A previously used scope may NEVER be reused for a fresh local log.
        if result
            .external
            .load(result.profile.scope)
            .map_err(|_| ProposalJournalErrorV1::Anchor)?
            .is_some()
        {
            return Err(ProposalJournalErrorV1::Anchor);
        }
        result
            .external
            .compare_and_advance(None, audit.head)
            .map_err(|_| ProposalJournalErrorV1::Anchor)?;
        result.require_anchor(&audit)?;
        result.ready = true;
        Ok(result)
    }

    pub fn open_existing(
        path: impl AsRef<Path>,
        profile: ProposalJournalProfileV1,
        external: W,
    ) -> Result<Self, ProposalJournalErrorV1> {
        if external.semantic_mode_v0() {
            return Err(ProposalJournalErrorV1::InvalidProfile);
        }
        let mut result = Self {
            namespace: Namespace::open(path.as_ref(), false)?,
            profile,
            external,
            ready: false,
            #[cfg(test)]
            fault: None,
            #[cfg(test)]
            fault_exit: false,
        };
        let audit = result.audit()?;
        let external_head = result
            .external
            .load(result.profile.scope)
            .map_err(|_| ProposalJournalErrorV1::Anchor)?;
        if external_head != Some(audit.head) {
            // Only the exact immediately preceding independently anchored event
            // permits repairing a response-lost/local-one-record append.
            if external_head.is_none() || external_head != audit.predecessor {
                return Err(ProposalJournalErrorV1::Anchor);
            }
            result.namespace.sync()?;
            result
                .external
                .compare_and_advance(external_head, audit.head)
                .map_err(|_| ProposalJournalErrorV1::Anchor)?;
        }
        result.require_anchor(&audit)?;
        result.ready = true;
        Ok(result)
    }

    /// Bind a composition to the same fixed context before replacing its
    /// proposal signer. This check grants no proposal, voting or epoch authority.
    pub fn require_context(
        &self,
        set: &ValidatorSet,
        author: ValidatorId,
        signer_profile: [u8; 32],
    ) -> Result<(), ProposalJournalErrorV1> {
        if !self.ready {
            return Err(ProposalJournalErrorV1::NotReady);
        }
        if &self.profile.set != set
            || self.profile.author != author
            || self.profile.signer_profile != signer_profile
        {
            return Err(ProposalJournalErrorV1::InvalidProfile);
        }
        Ok(())
    }

    pub const fn is_ready(&self) -> bool {
        self.ready
    }

    pub fn sign_exact<P: ProposalSignatureProducerV0 + ?Sized>(
        &mut self,
        request: ProposalSignatureRequestV0,
        producer: &mut P,
    ) -> Result<SignatureBytes, ProposalJournalErrorV1> {
        let audit = self.admit(request)?;
        if let Some(signature) = exact_signature(&audit, request) {
            return Ok(signature);
        }
        self.ready = false;
        let result = self.sign_pending(audit, request, producer);
        if result.is_ok() {
            self.ready = true;
        }
        result
    }

    fn sign_pending<P: ProposalSignatureProducerV0 + ?Sized>(
        &mut self,
        mut audit: Audit,
        request: ProposalSignatureRequestV0,
        producer: &mut P,
    ) -> Result<SignatureBytes, ProposalJournalErrorV1> {
        if audit
            .entries
            .last()
            .is_none_or(|entry| entry.signature.is_some())
        {
            audit = self.append(&audit, request, None)?;
        }
        self.require_anchor(&audit)?;
        let signature = producer
            .sign_proposal(request)
            .map_err(ProposalJournalErrorV1::Producer)?;
        self.test_cut(audit.head.sequence(), "custody")?;
        if !self.profile.verify_signature(&request, signature) {
            return Err(ProposalJournalErrorV1::InvalidSignature);
        }
        self.require_anchor(&audit)?;
        self.append(&audit, request, Some(signature))?;
        Ok(signature)
    }

    /// Resolve an already observed signature against the exact anchored pending
    /// request. No producer is accepted or called here. A malicious supplied
    /// signature cannot create an intent, rewrite the tail or advance the anchor.
    pub fn recover_observed_signature(
        &mut self,
        request: ProposalSignatureRequestV0,
        signature: SignatureBytes,
    ) -> Result<SignatureBytes, ProposalJournalErrorV1> {
        let audit = self.admit(request)?;
        if !self.profile.verify_signature(&request, signature) {
            return Err(ProposalJournalErrorV1::InvalidSignature);
        }
        if let Some(stored) = exact_signature(&audit, request) {
            return if stored == signature {
                Ok(stored)
            } else {
                Err(ProposalJournalErrorV1::Conflict)
            };
        }
        if !audit
            .entries
            .last()
            .is_some_and(|entry| entry.request == request && entry.signature.is_none())
        {
            return Err(ProposalJournalErrorV1::Conflict);
        }
        self.ready = false;
        self.append(&audit, request, Some(signature))?;
        self.ready = true;
        Ok(signature)
    }

    fn admit(
        &mut self,
        request: ProposalSignatureRequestV0,
    ) -> Result<Audit, ProposalJournalErrorV1> {
        if !self.ready {
            return Err(ProposalJournalErrorV1::NotReady);
        }
        self.profile.validate_request(&request)?;
        self.ready = false;
        let audit = self.audit()?;
        self.require_anchor(&audit)?;
        self.ready = true;
        if let Some(entry) = audit
            .entries
            .iter()
            .find(|e| e.request.view() == request.view())
        {
            return if entry.request == request {
                Ok(audit)
            } else {
                Err(ProposalJournalErrorV1::Conflict)
            };
        }
        if audit.entries.last().is_some_and(|entry| {
            entry.signature.is_none() || request.view() <= entry.request.view()
        }) {
            return Err(ProposalJournalErrorV1::Conflict);
        }
        if audit.entries.len() >= self.profile.maximum_requests {
            return Err(ProposalJournalErrorV1::Capacity);
        }
        Ok(audit)
    }

    fn append(
        &mut self,
        audit: &Audit,
        request: ProposalSignatureRequestV0,
        signature: Option<SignatureBytes>,
    ) -> Result<Audit, ProposalJournalErrorV1> {
        self.require_anchor(audit)?;
        let sequence = audit
            .head
            .sequence()
            .checked_add(1)
            .ok_or(ProposalJournalErrorV1::Capacity)?;
        let mut bytes = Vec::with_capacity(RECORD_BYTES);
        bytes.extend_from_slice(&sequence.to_be_bytes());
        bytes.push(u8::from(signature.is_some()));
        bytes.extend_from_slice(&encode_request(request));
        bytes.extend_from_slice(signature.as_ref().map_or(&[0; 64], |s| s.as_bytes()));
        bytes.extend_from_slice(&audit.head.chain_checksum());
        let checksum = hash_domain(
            "trnm.proposal-journal.record.v1",
            &[&self.profile.digest, &audit.journal_id, &bytes],
        );
        bytes.extend_from_slice(&checksum);
        self.namespace.file.seek(SeekFrom::End(0))?;
        self.namespace.file.write_all(&bytes)?;
        self.namespace.sync()?;
        self.test_cut(sequence, "sync")?;
        let target = self.audit()?;
        if target.head.sequence() != sequence
            || target.predecessor != Some(audit.head)
            || target.length != audit.length + RECORD_BYTES
            || target.head.chain_checksum() != checksum
        {
            return Err(ProposalJournalErrorV1::Corrupt);
        }
        self.external
            .compare_and_advance(Some(audit.head), target.head)
            .map_err(|_| ProposalJournalErrorV1::Anchor)?;
        self.test_cut(sequence, "anchor")?;
        self.require_anchor(&target)?;
        Ok(target)
    }

    fn require_anchor(&mut self, expected: &Audit) -> Result<(), ProposalJournalErrorV1> {
        let fresh = self.audit()?;
        if fresh.head != expected.head
            || fresh.journal_id != expected.journal_id
            || fresh.length != expected.length
        {
            return Err(ProposalJournalErrorV1::Corrupt);
        }
        if self
            .external
            .load(self.profile.scope)
            .map_err(|_| ProposalJournalErrorV1::Anchor)?
            != Some(fresh.head)
        {
            return Err(ProposalJournalErrorV1::Anchor);
        }
        self.namespace.check()?;
        Ok(())
    }

    fn audit(&mut self) -> Result<Audit, ProposalJournalErrorV1> {
        self.namespace.check()?;
        let length = usize::try_from(self.namespace.file.metadata()?.len())
            .map_err(|_| ProposalJournalErrorV1::Capacity)?;
        if length < HEADER_BYTES
            || length > self.profile.maximum_bytes()
            || !(length - HEADER_BYTES).is_multiple_of(RECORD_BYTES)
        {
            return Err(ProposalJournalErrorV1::Corrupt);
        }
        self.namespace.file.seek(SeekFrom::Start(0))?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(length)
            .map_err(|_| ProposalJournalErrorV1::Capacity)?;
        Read::by_ref(&mut self.namespace.file)
            .take(length as u64 + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() != length
            || &bytes[..8] != MAGIC
            || bytes[8..40] != self.profile.digest
            || hash_domain("trnm.proposal-journal.header.v1", &[&bytes[..72]]) != bytes[72..104]
        {
            return Err(ProposalJournalErrorV1::Corrupt);
        }
        let journal_id = bytes[40..72]
            .try_into()
            .map_err(|_| ProposalJournalErrorV1::Corrupt)?;
        let mut head = SignerWatermarkV0::from_persisted_parts(
            self.profile.scope,
            journal_id,
            0,
            bytes[72..104]
                .try_into()
                .map_err(|_| ProposalJournalErrorV1::Corrupt)?,
        )
        .map_err(|_| ProposalJournalErrorV1::Corrupt)?;
        let mut predecessor = None;
        let mut entries: Vec<Entry> = Vec::new();
        for record in bytes[HEADER_BYTES..].chunks_exact(RECORD_BYTES) {
            let sequence = u64::from_be_bytes(
                record[..8]
                    .try_into()
                    .map_err(|_| ProposalJournalErrorV1::Corrupt)?,
            );
            let checksum = hash_domain(
                "trnm.proposal-journal.record.v1",
                &[
                    &self.profile.digest,
                    &journal_id,
                    &record[..RECORD_BYTES - 32],
                ],
            );
            if sequence != head.sequence() + 1
                || record[RECORD_BYTES - 64..RECORD_BYTES - 32] != head.chain_checksum()
                || record[RECORD_BYTES - 32..] != checksum
            {
                return Err(ProposalJournalErrorV1::Corrupt);
            }
            let request = decode_request(&record[9..9 + REQUEST_BYTES], &self.profile)?;
            let signature_bytes: [u8; 64] = record[9 + REQUEST_BYTES..9 + REQUEST_BYTES + 64]
                .try_into()
                .map_err(|_| ProposalJournalErrorV1::Corrupt)?;
            match record[8] {
                0 => {
                    if signature_bytes != [0; 64]
                        || entries.len() >= self.profile.maximum_requests
                        || entries.last().is_some_and(|entry| {
                            entry.signature.is_none() || request.view() <= entry.request.view()
                        })
                    {
                        return Err(ProposalJournalErrorV1::Corrupt);
                    }
                    entries.push(Entry {
                        request,
                        signature: None,
                    });
                }
                1 => {
                    let last = entries.last_mut().ok_or(ProposalJournalErrorV1::Corrupt)?;
                    let signature = SignatureBytes::from_array(signature_bytes);
                    if last.signature.is_some()
                        || last.request != request
                        || !self.profile.verify_signature(&request, signature)
                    {
                        return Err(ProposalJournalErrorV1::Corrupt);
                    }
                    last.signature = Some(signature);
                }
                _ => return Err(ProposalJournalErrorV1::Corrupt),
            }
            predecessor = Some(head);
            head = SignerWatermarkV0::from_persisted_parts(
                self.profile.scope,
                journal_id,
                sequence,
                checksum,
            )
            .map_err(|_| ProposalJournalErrorV1::Corrupt)?;
        }
        self.namespace.check()?;
        Ok(Audit {
            journal_id,
            head,
            predecessor,
            entries,
            length,
        })
    }

    fn test_cut(&self, sequence: u64, stage: &'static str) -> Result<(), ProposalJournalErrorV1> {
        #[cfg(test)]
        if self.fault == Some((sequence, stage)) {
            if self.fault_exit {
                std::process::exit(73);
            }
            return Err(ProposalJournalErrorV1::Io(std::io::Error::other(
                "injected proposal journal cut",
            )));
        }
        let _ = (sequence, stage);
        Ok(())
    }
}

fn exact_signature(audit: &Audit, request: ProposalSignatureRequestV0) -> Option<SignatureBytes> {
    audit
        .entries
        .iter()
        .find(|entry| entry.request == request)
        .and_then(|entry| entry.signature)
}
fn encode_request(request: ProposalSignatureRequestV0) -> [u8; REQUEST_BYTES] {
    let mut result = [0; REQUEST_BYTES];
    result[..32].copy_from_slice(request.proposal_id().as_bytes());
    result[32..64].copy_from_slice(request.parent_id().as_bytes());
    result[64..72].copy_from_slice(&request.epoch().get().to_be_bytes());
    result[72..80].copy_from_slice(&request.view().get().to_be_bytes());
    result[80..88].copy_from_slice(&request.height().get().to_be_bytes());
    result[88..120].copy_from_slice(request.signing_root().as_bytes());
    result
}
fn decode_request(
    bytes: &[u8],
    profile: &ProposalJournalProfileV1,
) -> Result<ProposalSignatureRequestV0, ProposalJournalErrorV1> {
    if bytes.len() != REQUEST_BYTES {
        return Err(ProposalJournalErrorV1::Corrupt);
    }
    let hash = |start| -> Result<[u8; 32], ProposalJournalErrorV1> {
        bytes[start..start + 32]
            .try_into()
            .map_err(|_| ProposalJournalErrorV1::Corrupt)
    };
    let number = |start| -> Result<u64, ProposalJournalErrorV1> {
        Ok(u64::from_be_bytes(
            bytes[start..start + 8]
                .try_into()
                .map_err(|_| ProposalJournalErrorV1::Corrupt)?,
        ))
    };
    let key = profile
        .set
        .validator(profile.author)
        .ok_or(ProposalJournalErrorV1::Corrupt)?
        .consensus_key()
        .into_bytes();
    let request = ProposalSignatureRequestV0::new(
        BlockId::new(hash(0)?),
        BlockId::new(hash(32)?),
        profile.set.id(),
        profile.author,
        Epoch::new(number(64)?),
        View::new(number(72)?),
        Height::new(number(80)?),
        SigningRoot::new(hash(88)?),
        key,
        profile.signer_profile,
    )
    .ok_or(ProposalJournalErrorV1::Corrupt)?;
    profile
        .validate_request(&request)
        .map_err(|_| ProposalJournalErrorV1::Corrupt)?;
    Ok(request)
}

/// Actual adapter for the existing proposal-signature port. It journals before
/// invoking the injected custody producer. Errors never become a signature.
pub struct JournaledProposalProducerV1<W, P> {
    journal: ProposalJournalV1<W>,
    producer: P,
}
impl<W, P> JournaledProposalProducerV1<W, P> {
    pub fn new(journal: ProposalJournalV1<W>, producer: P) -> Self {
        Self { journal, producer }
    }
}
impl<W: ExternalMonotonicWatermarkV0, P: ProposalSignatureProducerV0> ProposalSignatureProducerV0
    for JournaledProposalProducerV1<W, P>
{
    fn sign_proposal(
        &mut self,
        request: ProposalSignatureRequestV0,
    ) -> Result<SignatureBytes, SignatureProducerErrorV0> {
        self.journal
            .sign_exact(request, &mut self.producer)
            .map_err(|error| match error {
                ProposalJournalErrorV1::InvalidRequest
                | ProposalJournalErrorV1::Conflict
                | ProposalJournalErrorV1::Capacity => SignatureProducerErrorV0::Rejected,
                _ => SignatureProducerErrorV0::Unavailable,
            })
    }
}

#[cfg(test)]
#[path = "proposal_journal_tests_v1.rs"]
mod tests;
