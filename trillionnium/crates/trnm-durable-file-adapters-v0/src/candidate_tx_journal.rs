//! M05 candidate transaction journal. Linux, local private filesystem only.
//!
//! A published frame is one indivisible mutation, including both replacement
//! records. Publication uses renameat2(NOREPLACE) after file sync; the retained
//! directory is synced before success. Unpublished staging bytes are never
//! replayed. The log is bounded and never compacted: collection removes a
//! record from the latest view, not from historical evidence. Checksums detect
//! corruption and interior deletion, not coherent rollback by a storage owner.

use fs2::FileExt;
use rustix::fs::{self as rfs, AtFlags, Dir, Mode, OFlags, RenameFlags};
use std::{
    collections::BTreeMap,
    error::Error,
    ffi::OsString,
    fmt,
    fs::File,
    io::{self, Read, Write},
    os::unix::fs::MetadataExt,
    path::Path,
};
use trnm_tx_lifecycle_v0::{
    Digest32V0, DurableTxJournalV0, DurableTxRecordV0, DurableTxReplacementV0, RecoveredTxRecordV0,
    ReplayFloorWitnessV0, TombstoneReasonV0, TxIdV0, TxPhaseV0, TxRecordV0,
    MAX_TX_RECORD_ENCODED_BYTES_V0,
};

pub const CANDIDATE_TX_JOURNAL_PRODUCTION_ACTIVATION_V0: bool = false;
pub const CANDIDATE_TX_JOURNAL_EXTERNAL_ROLLBACK_PROTECTION_V0: bool = false;
pub const CANDIDATE_TX_JOURNAL_WIRE_VERSION_V0: u16 = 0;
pub const CANDIDATE_TX_JOURNAL_MAXIMUM_FRAMES_V0: u64 = 100_000;
pub const CANDIDATE_TX_JOURNAL_MAXIMUM_LOG_BYTES_V0: u64 = 1024 * 1024 * 1024;
pub const CANDIDATE_TX_JOURNAL_MAXIMUM_LATEST_RECORDS_V0: u64 = 10_000;
const ZERO: Digest32V0 = Digest32V0([0; 32]);
const FRAME_MAGIC: &[u8; 8] = b"TRNMTXF0";
const IDENTITY_MAGIC: &[u8; 8] = b"TRNMTXJ0";
const LOCK: &str = "owner.lock";
const IDENTITY: &str = "identity.v0";
const STAGE: &str = "pending.frame";
const IDENTITY_STAGE: &str = "pending.identity";
const MAX_FRAME_BYTES: usize = 2 * MAX_TX_RECORD_ENCODED_BYTES_V0 + 256;
const IDENTITY_BYTES: usize = 8 + 2 + 32 + 32 + 24 + 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CandidateTxJournalIdentityV0 {
    pub chain_id: Digest32V0,
    /// Deployment-supplied nonzero local journal identity, not an authority.
    pub journal_id: Digest32V0,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CandidateTxJournalLimitsV0 {
    /// Includes collected history. Reaching a cap fails closed; no eviction.
    pub maximum_frames: u64,
    pub maximum_log_bytes: u64,
    pub maximum_latest_records: u64,
}

impl Default for CandidateTxJournalLimitsV0 {
    fn default() -> Self {
        Self {
            maximum_frames: CANDIDATE_TX_JOURNAL_MAXIMUM_FRAMES_V0,
            maximum_log_bytes: CANDIDATE_TX_JOURNAL_MAXIMUM_LOG_BYTES_V0,
            maximum_latest_records: CANDIDATE_TX_JOURNAL_MAXIMUM_LATEST_RECORDS_V0,
        }
    }
}

#[derive(Debug)]
pub enum CandidateTxJournalErrorV0 {
    Io(io::Error),
    Locked,
    Poisoned,
    Namespace,
    Identity,
    Corrupt(&'static str),
    InvalidRecord,
    CompareFailed,
    CollectionDenied,
    Capacity,
}
impl fmt::Display for CandidateTxJournalErrorV0 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "candidate tx journal I/O: {error}"),
            Self::Locked => f.write_str("candidate tx journal already has an owner"),
            Self::Poisoned => {
                f.write_str("candidate tx journal requires reopen after uncertain I/O")
            }
            Self::Namespace => {
                f.write_str("candidate tx journal private namespace changed or is unsafe")
            }
            Self::Identity => f.write_str("candidate tx journal identity or limits mismatch"),
            Self::Corrupt(reason) => write!(f, "candidate tx journal corruption: {reason}"),
            Self::InvalidRecord => f.write_str("invalid candidate tx journal record transition"),
            Self::CompareFailed => {
                f.write_str("candidate tx journal exact predecessor compare failed")
            }
            Self::CollectionDenied => {
                f.write_str("candidate tx collection is not authorized by retained state")
            }
            Self::Capacity => f.write_str("candidate tx journal hard capacity reached"),
        }
    }
}
impl Error for CandidateTxJournalErrorV0 {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        if let Self::Io(error) = self {
            Some(error)
        } else {
            None
        }
    }
}
impl From<io::Error> for CandidateTxJournalErrorV0 {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}
impl From<rustix::io::Errno> for CandidateTxJournalErrorV0 {
    fn from(error: rustix::io::Errno) -> Self {
        Self::Io(error.into())
    }
}
type Result<T> = std::result::Result<T, CandidateTxJournalErrorV0>;

#[derive(Debug)]
enum Mutation {
    Append {
        previous: Digest32V0,
        record: Box<TxRecordV0>,
    },
    Replace {
        previous: Digest32V0,
        replaced: Box<TxRecordV0>,
        admitted: Box<TxRecordV0>,
    },
    Collect {
        tx_id: TxIdV0,
        previous: Digest32V0,
        floor: ReplayFloorWitnessV0,
    },
}

#[derive(Default)]
struct State {
    sequence: u64,
    head: Option<Digest32V0>,
    frame_digests: Vec<Digest32V0>,
    bytes: u64,
    records: BTreeMap<TxIdV0, RecoveredTxRecordV0>,
    active: BTreeMap<(Digest32V0, u64), TxIdV0>,
    replay_floor: BTreeMap<Digest32V0, u64>,
    finalized_nonce: BTreeMap<Digest32V0, u64>,
    collected: BTreeMap<TxIdV0, Collection>,
}

#[derive(Clone, Copy)]
struct Collection {
    previous: Digest32V0,
    floor: ReplayFloorWitnessV0,
    receipt: Digest32V0,
    sequence: u64,
}

/// One owner holds the namespace and lock descriptors for its entire lifetime.
/// All names below that directory are resolved relative to the retained fd.
/// The supplied directory must already exist, be canonical, and have mode0700.
/// Files must be owned by the caller, regular, mode0600, and singly linked.
/// Neither this constructor nor collection deletes historical frame files.
/// The parent descriptor is pinned; its own ancestors are a trusted deployment
/// namespace and must not be renamed/replaced while an owner is active.
pub struct CandidateTxFileJournalV0 {
    parent: File,
    directory: File,
    directory_name: OsString,
    lock: File,
    identity: CandidateTxJournalIdentityV0,
    limits: CandidateTxJournalLimitsV0,
    identity_digest: Digest32V0,
    state: State,
    poisoned: bool,
    #[cfg(test)]
    fault: Option<tests::Fault>,
}

impl CandidateTxFileJournalV0 {
    pub fn open(
        directory: &Path,
        identity: CandidateTxJournalIdentityV0,
        limits: CandidateTxJournalLimitsV0,
    ) -> Result<Self> {
        if identity.chain_id == ZERO
            || identity.journal_id == ZERO
            || limits.maximum_frames == 0
            || limits.maximum_log_bytes == 0
            || limits.maximum_latest_records == 0
            || limits.maximum_frames > CANDIDATE_TX_JOURNAL_MAXIMUM_FRAMES_V0
            || limits.maximum_log_bytes > CANDIDATE_TX_JOURNAL_MAXIMUM_LOG_BYTES_V0
            || limits.maximum_latest_records > CANDIDATE_TX_JOURNAL_MAXIMUM_LATEST_RECORDS_V0
        {
            return Err(CandidateTxJournalErrorV0::Identity);
        }
        if !directory.is_absolute() || directory.canonicalize()? != directory {
            return Err(CandidateTxJournalErrorV0::Namespace);
        }
        let directory_name = directory
            .file_name()
            .ok_or(CandidateTxJournalErrorV0::Namespace)?
            .to_owned();
        let parent_path = directory
            .parent()
            .ok_or(CandidateTxJournalErrorV0::Namespace)?;
        let parent: File = rfs::open(
            parent_path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?
        .into();
        let directory: File = rfs::openat(
            &parent,
            &directory_name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?
        .into();
        validate_directory(&directory)?;
        let lock: File = rfs::openat(
            &directory,
            LOCK,
            OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )?
        .into();
        validate_file(&lock)?;
        lock.try_lock_exclusive().map_err(|error| {
            if error.kind() == io::ErrorKind::WouldBlock {
                CandidateTxJournalErrorV0::Locked
            } else {
                CandidateTxJournalErrorV0::Io(error)
            }
        })?;
        let identity_bytes = encode_identity(identity, limits);
        let identity_digest = digest(b"trnm.candidate-tx-journal.identity.v0", &identity_bytes);
        let mut owner = Self {
            parent,
            directory,
            directory_name,
            lock,
            identity,
            limits,
            identity_digest,
            state: State::default(),
            poisoned: false,
            #[cfg(test)]
            fault: None,
        };
        owner.check_namespace()?;
        let names = owner.names()?;
        if names.iter().any(|name| name == IDENTITY) {
            if owner.read_file(IDENTITY, IDENTITY_BYTES)? != identity_bytes {
                return Err(CandidateTxJournalErrorV0::Identity);
            }
        } else {
            if names
                .iter()
                .any(|name| name != LOCK && name != IDENTITY_STAGE)
            {
                return Err(CandidateTxJournalErrorV0::Corrupt(
                    "missing identity with retained history",
                ));
            }
            owner.discard_stage(IDENTITY_STAGE)?;
            owner.publish_bytes(IDENTITY_STAGE, IDENTITY, &identity_bytes, false)?;
        }
        owner.state = owner.replay()?;
        // Only these fixed, unpublished names are disposable. No committed
        // transaction record can be removed through this recovery path.
        owner.discard_stage(STAGE)?;
        owner.discard_stage(IDENTITY_STAGE)?;
        owner.directory.sync_all()?;
        owner.parent.sync_all()?;
        Ok(owner)
    }

    pub const fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    fn check_namespace(&self) -> Result<()> {
        validate_directory(&self.directory)?;
        let named: File = rfs::openat(
            &self.parent,
            &self.directory_name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?
        .into();
        if !same_inode(&named, &self.directory)? {
            return Err(CandidateTxJournalErrorV0::Namespace);
        }
        validate_file(&self.lock)?;
        let named_lock = self.open_file(LOCK)?;
        if !same_inode(&named_lock, &self.lock)? {
            return Err(CandidateTxJournalErrorV0::Namespace);
        }
        Ok(())
    }

    fn ensure_healthy(&mut self) -> Result<()> {
        if self.poisoned {
            return Err(CandidateTxJournalErrorV0::Poisoned);
        }
        let check = (|| {
            self.check_namespace()?;
            if self.read_file(IDENTITY, IDENTITY_BYTES)?
                != encode_identity(self.identity, self.limits)
            {
                return Err(CandidateTxJournalErrorV0::Identity);
            }
            if self.state.sequence > 0 {
                self.verify_frame(self.state.sequence)?;
            }
            Ok(())
        })();
        if let Err(error) = check {
            self.poisoned = true;
            return Err(error);
        }
        Ok(())
    }

    fn verify_frame(&self, sequence: u64) -> Result<()> {
        let index = usize::try_from(sequence)
            .ok()
            .and_then(|n| n.checked_sub(1))
            .ok_or(CandidateTxJournalErrorV0::Corrupt(
                "invalid retained sequence",
            ))?;
        let expected =
            self.state
                .frame_digests
                .get(index)
                .ok_or(CandidateTxJournalErrorV0::Corrupt(
                    "missing retained frame digest",
                ))?;
        let previous = if index == 0 {
            self.identity_digest
        } else {
            self.state.frame_digests[index - 1]
        };
        let bytes = self.read_file(&frame_name(sequence), MAX_FRAME_BYTES)?;
        let (_, found) = decode_frame(&bytes, self.identity_digest, sequence, previous)?;
        if found != *expected {
            return Err(CandidateTxJournalErrorV0::Corrupt(
                "published frame changed",
            ));
        }
        Ok(())
    }

    fn require_published_frame(&mut self, sequence: u64) -> Result<()> {
        if let Err(error) = self.verify_frame(sequence) {
            self.poisoned = true;
            return Err(error);
        }
        Ok(())
    }

    fn open_file(&self, name: &str) -> Result<File> {
        let file: File = rfs::openat(
            &self.directory,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )?
        .into();
        validate_file(&file)?;
        Ok(file)
    }

    fn read_file(&self, name: &str, maximum: usize) -> Result<Vec<u8>> {
        let mut file = self.open_file(name)?;
        let size = file.metadata()?.len();
        if size > maximum as u64 {
            return Err(CandidateTxJournalErrorV0::Capacity);
        }
        let mut bytes = Vec::with_capacity(size as usize);
        (&mut file)
            .take(maximum as u64 + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 != size {
            return Err(CandidateTxJournalErrorV0::Corrupt(
                "file changed during read",
            ));
        }
        Ok(bytes)
    }

    fn names(&self) -> Result<Vec<String>> {
        let mut names = Vec::new();
        for entry in Dir::read_from(&self.directory)? {
            let entry = entry?;
            let name = entry.file_name().to_bytes();
            if name == b"." || name == b".." {
                continue;
            }
            if names.len() as u64 >= self.limits.maximum_frames.saturating_add(4) {
                return Err(CandidateTxJournalErrorV0::Capacity);
            }
            let name =
                std::str::from_utf8(name).map_err(|_| CandidateTxJournalErrorV0::Namespace)?;
            if name != LOCK
                && name != IDENTITY
                && name != STAGE
                && name != IDENTITY_STAGE
                && parse_frame_name(name).is_none()
            {
                return Err(CandidateTxJournalErrorV0::Namespace);
            }
            names.push(name.to_owned());
        }
        names.sort();
        Ok(names)
    }

    fn discard_stage(&self, name: &str) -> Result<()> {
        match self.open_file(name) {
            Ok(_) => {
                rfs::unlinkat(&self.directory, name, AtFlags::empty())?;
                Ok(())
            }
            Err(CandidateTxJournalErrorV0::Io(error))
                if error.kind() == io::ErrorKind::NotFound =>
            {
                Ok(())
            }
            Err(error) => Err(error),
        }
    }

    fn replay(&self) -> Result<State> {
        self.check_namespace()?;
        if self.read_file(IDENTITY, IDENTITY_BYTES)? != encode_identity(self.identity, self.limits)
        {
            return Err(CandidateTxJournalErrorV0::Identity);
        }
        let mut state = State::default();
        for name in self.names()? {
            let Some(sequence) = parse_frame_name(&name) else {
                continue;
            };
            if sequence
                != state
                    .sequence
                    .checked_add(1)
                    .ok_or(CandidateTxJournalErrorV0::Capacity)?
            {
                return Err(CandidateTxJournalErrorV0::Corrupt("frame sequence gap"));
            }
            let bytes = self.read_file(&name, MAX_FRAME_BYTES)?;
            let next_bytes = state
                .bytes
                .checked_add(bytes.len() as u64)
                .ok_or(CandidateTxJournalErrorV0::Capacity)?;
            if next_bytes > self.limits.maximum_log_bytes || sequence > self.limits.maximum_frames {
                return Err(CandidateTxJournalErrorV0::Capacity);
            }
            let (mutation, frame_digest) = decode_frame(
                &bytes,
                self.identity_digest,
                sequence,
                state.head.unwrap_or(self.identity_digest),
            )?;
            self.validate_mutation(&state, &mutation)?;
            apply_mutation(&mut state, mutation, sequence, frame_digest);
            state.bytes = next_bytes;
        }
        self.check_namespace()?;
        Ok(state)
    }

    fn validate_new(&self, state: &State, record: &TxRecordV0) -> Result<()> {
        if record.phase != TxPhaseV0::Admitted
            || state.records.contains_key(&record.tx_id)
            || state
                .replay_floor
                .get(&record.intent.sender)
                .is_some_and(|floor| record.intent.nonce < *floor)
            || state
                .finalized_nonce
                .get(&record.intent.sender)
                .is_some_and(|nonce| record.intent.nonce <= *nonce)
        {
            return Err(CandidateTxJournalErrorV0::CompareFailed);
        }
        if state.records.len() as u64 >= self.limits.maximum_latest_records {
            return Err(CandidateTxJournalErrorV0::Capacity);
        }
        Ok(())
    }

    fn validate_mutation(&self, state: &State, mutation: &Mutation) -> Result<()> {
        match mutation {
            Mutation::Append { previous, record } => {
                record
                    .validate_persisted_v0(self.identity.chain_id)
                    .map_err(|_| CandidateTxJournalErrorV0::InvalidRecord)?;
                match state.records.get(&record.tx_id) {
                    Some(old) => {
                        if old.durable.record_digest != *previous {
                            return Err(CandidateTxJournalErrorV0::CompareFailed);
                        }
                        if old.record.phase == TxPhaseV0::Admitted
                            && record.phase == TxPhaseV0::WalPersisted
                            && record.wal_sequence != Some(old.durable.journal_sequence)
                        {
                            return Err(CandidateTxJournalErrorV0::InvalidRecord);
                        }
                        validate_successor(&old.record, record)?;
                    }
                    None => {
                        if *previous != ZERO {
                            return Err(CandidateTxJournalErrorV0::CompareFailed);
                        }
                        self.validate_new(state, record)?;
                        if state
                            .active
                            .contains_key(&(record.intent.sender, record.intent.nonce))
                        {
                            return Err(CandidateTxJournalErrorV0::CompareFailed);
                        }
                    }
                }
            }
            Mutation::Replace {
                previous,
                replaced,
                admitted,
            } => {
                replaced
                    .validate_persisted_v0(self.identity.chain_id)
                    .map_err(|_| CandidateTxJournalErrorV0::InvalidRecord)?;
                admitted
                    .validate_persisted_v0(self.identity.chain_id)
                    .map_err(|_| CandidateTxJournalErrorV0::InvalidRecord)?;
                let old = state
                    .records
                    .get(&replaced.tx_id)
                    .ok_or(CandidateTxJournalErrorV0::CompareFailed)?;
                if old.durable.record_digest != *previous {
                    return Err(CandidateTxJournalErrorV0::CompareFailed);
                }
                self.validate_new(state, admitted)?;
                let dummy = DurableTxReplacementV0 {
                    replaced: receipt(replaced, *previous, 1, self.identity_digest),
                    admitted: receipt(admitted, ZERO, 1, self.identity_digest),
                };
                dummy
                    .validate(&old.record, replaced, admitted)
                    .map_err(|_| CandidateTxJournalErrorV0::InvalidRecord)?;
                if state
                    .active
                    .get(&(admitted.intent.sender, admitted.intent.nonce))
                    != Some(&old.record.tx_id)
                {
                    return Err(CandidateTxJournalErrorV0::CompareFailed);
                }
            }
            Mutation::Collect {
                tx_id,
                previous,
                floor,
            } => {
                let old = state
                    .records
                    .get(tx_id)
                    .ok_or(CandidateTxJournalErrorV0::CompareFailed)?;
                if old.durable.record_digest != *previous {
                    return Err(CandidateTxJournalErrorV0::CompareFailed);
                }
                if old.record.phase != TxPhaseV0::Tombstoned
                    || floor.account != old.record.intent.sender
                    || floor.minimum_replayable_nonce <= old.record.intent.nonce
                    || floor.finalized_height < old.record.finality.map_or(0, |value| value.height)
                    || floor.authority_digest == ZERO
                {
                    return Err(CandidateTxJournalErrorV0::CollectionDenied);
                }
            }
        }
        Ok(())
    }

    fn publish_bytes(
        &mut self,
        staging: &str,
        target: &str,
        bytes: &[u8],
        instrument: bool,
    ) -> Result<()> {
        let outcome = (|| {
            self.check_namespace()?;
            #[cfg(test)]
            if instrument {
                self.at_fault(tests::Point::BeforeStage)?;
            }
            let mut file: File = rfs::openat(
                &self.directory,
                staging,
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::from_raw_mode(0o600),
            )?
            .into();
            validate_file(&file)?;
            let midpoint = bytes.len() / 2;
            file.write_all(&bytes[..midpoint])?;
            #[cfg(test)]
            if instrument {
                self.at_fault(tests::Point::PartialStage)?;
            }
            file.write_all(&bytes[midpoint..])?;
            #[cfg(test)]
            if instrument {
                self.at_fault(tests::Point::BeforeFileSync)?;
            }
            file.sync_all()?;
            #[cfg(test)]
            if instrument {
                self.at_fault(tests::Point::FileSynced)?;
            }
            self.check_namespace()?;
            rfs::renameat_with(
                &self.directory,
                staging,
                &self.directory,
                target,
                RenameFlags::NOREPLACE,
            )?;
            #[cfg(test)]
            if instrument {
                self.at_fault(tests::Point::Published)?;
            }
            self.directory.sync_all()?;
            #[cfg(test)]
            if instrument {
                self.at_fault(tests::Point::DirectorySynced)?;
            }
            self.check_namespace()?;
            #[cfg(not(test))]
            let _ = instrument;
            Ok(())
        })();
        if outcome.is_err() {
            self.poisoned = true;
        }
        outcome
    }

    fn commit(&mut self, mutation: Mutation) -> Result<Digest32V0> {
        self.ensure_healthy()?;
        self.validate_mutation(&self.state, &mutation)?;
        let tx_id = match &mutation {
            Mutation::Append { record, .. } => record.tx_id,
            Mutation::Replace { replaced, .. } => replaced.tx_id,
            Mutation::Collect { tx_id, .. } => *tx_id,
        };
        if let Some(previous) = self.state.records.get(&tx_id) {
            self.require_published_frame(previous.durable.journal_sequence)?;
        }
        let sequence = self
            .state
            .sequence
            .checked_add(1)
            .ok_or(CandidateTxJournalErrorV0::Capacity)?;
        let bytes = encode_frame(
            &mutation,
            self.identity_digest,
            sequence,
            self.state.head.unwrap_or(self.identity_digest),
        )?;
        let total = self
            .state
            .bytes
            .checked_add(bytes.len() as u64)
            .ok_or(CandidateTxJournalErrorV0::Capacity)?;
        if sequence > self.limits.maximum_frames || total > self.limits.maximum_log_bytes {
            return Err(CandidateTxJournalErrorV0::Capacity);
        }
        let frame_digest = Digest32V0(
            bytes[bytes.len() - 32..]
                .try_into()
                .expect("encoded frame digest"),
        );
        self.publish_bytes(STAGE, &frame_name(sequence), &bytes, true)?;
        apply_mutation(&mut self.state, mutation, sequence, frame_digest);
        self.state.bytes = total;
        #[cfg(test)]
        if let Err(error) = self.at_fault(tests::Point::ResponseLost) {
            self.poisoned = true;
            return Err(error);
        }
        Ok(frame_digest)
    }
}

impl DurableTxJournalV0 for CandidateTxFileJournalV0 {
    type Error = CandidateTxJournalErrorV0;

    fn load_latest(&mut self, chain_id: Digest32V0) -> Result<Vec<RecoveredTxRecordV0>> {
        self.ensure_healthy()?;
        if chain_id != self.identity.chain_id {
            return Err(CandidateTxJournalErrorV0::Identity);
        }
        let recovered = match self.replay() {
            Ok(recovered) => recovered,
            Err(error) => {
                self.poisoned = true;
                return Err(error);
            }
        };
        // Even a coherent suffix deletion cannot be adopted by a live owner.
        // A new process has no external head anchor and cannot make that claim.
        if recovered.sequence != self.state.sequence || recovered.head != self.state.head {
            self.poisoned = true;
            return Err(CandidateTxJournalErrorV0::Corrupt(
                "live journal head changed",
            ));
        }
        self.state = recovered;
        Ok(self.state.records.values().cloned().collect())
    }

    fn compare_and_append(
        &mut self,
        expected: Option<Digest32V0>,
        record: &TxRecordV0,
    ) -> Result<DurableTxRecordV0> {
        record
            .validate_persisted_v0(self.identity.chain_id)
            .map_err(|_| CandidateTxJournalErrorV0::InvalidRecord)?;
        self.ensure_healthy()?;
        let previous = expected.unwrap_or(ZERO);
        if let Some(retained) = self.state.records.get(&record.tx_id) {
            if retained.record == *record && retained.durable.previous_record_digest == previous {
                let receipt = retained.durable;
                self.require_published_frame(receipt.journal_sequence)?;
                return Ok(receipt);
            }
        }
        self.commit(Mutation::Append {
            previous,
            record: Box::new(record.clone()),
        })?;
        Ok(self.state.records[&record.tx_id].durable)
    }

    fn compare_and_replace(
        &mut self,
        expected: Digest32V0,
        replaced: &TxRecordV0,
        admitted: &TxRecordV0,
    ) -> Result<DurableTxReplacementV0> {
        replaced
            .validate_persisted_v0(self.identity.chain_id)
            .map_err(|_| CandidateTxJournalErrorV0::InvalidRecord)?;
        admitted
            .validate_persisted_v0(self.identity.chain_id)
            .map_err(|_| CandidateTxJournalErrorV0::InvalidRecord)?;
        self.ensure_healthy()?;
        if let (Some(old), Some(new)) = (
            self.state.records.get(&replaced.tx_id),
            self.state.records.get(&admitted.tx_id),
        ) {
            if old.record == *replaced
                && new.record == *admitted
                && old.durable.previous_record_digest == expected
                && new.durable.previous_record_digest == ZERO
                && old.durable.journal_sequence == new.durable.journal_sequence
            {
                let receipt = DurableTxReplacementV0 {
                    replaced: old.durable,
                    admitted: new.durable,
                };
                self.require_published_frame(receipt.replaced.journal_sequence)?;
                return Ok(receipt);
            }
        }
        self.commit(Mutation::Replace {
            previous: expected,
            replaced: Box::new(replaced.clone()),
            admitted: Box::new(admitted.clone()),
        })?;
        Ok(DurableTxReplacementV0 {
            replaced: self.state.records[&replaced.tx_id].durable,
            admitted: self.state.records[&admitted.tx_id].durable,
        })
    }

    fn delete_collected(
        &mut self,
        tx_id: TxIdV0,
        final_record_digest: Digest32V0,
        replay_floor: ReplayFloorWitnessV0,
    ) -> Result<Digest32V0> {
        self.ensure_healthy()?;
        if let Some(collection) = self.state.collected.get(&tx_id).copied() {
            return if collection.previous == final_record_digest && collection.floor == replay_floor
            {
                self.require_published_frame(collection.sequence)?;
                Ok(collection.receipt)
            } else {
                Err(CandidateTxJournalErrorV0::CompareFailed)
            };
        }
        self.commit(Mutation::Collect {
            tx_id,
            previous: final_record_digest,
            floor: replay_floor,
        })
    }
}

fn same_inode(left: &File, right: &File) -> Result<bool> {
    let left = left.metadata()?;
    let right = right.metadata()?;
    Ok(left.dev() == right.dev() && left.ino() == right.ino())
}
fn validate_directory(file: &File) -> Result<()> {
    let metadata = file.metadata()?;
    if !metadata.is_dir()
        || metadata.mode() & 0o7777 != 0o700
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.nlink() == 0
    {
        return Err(CandidateTxJournalErrorV0::Namespace);
    }
    Ok(())
}
fn validate_file(file: &File) -> Result<()> {
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.mode() & 0o7777 != 0o600
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.nlink() != 1
    {
        return Err(CandidateTxJournalErrorV0::Namespace);
    }
    Ok(())
}
fn digest(domain: &[u8], bytes: &[u8]) -> Digest32V0 {
    Digest32V0::hash(domain, &[bytes])
}
fn frame_name(sequence: u64) -> String {
    format!("{sequence:020}.txf")
}
fn parse_frame_name(name: &str) -> Option<u64> {
    let digits = name.strip_suffix(".txf")?;
    if digits.len() != 20 || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let sequence = digits.parse::<u64>().ok()?;
    (sequence > 0).then_some(sequence)
}
fn encode_identity(
    identity: CandidateTxJournalIdentityV0,
    limits: CandidateTxJournalLimitsV0,
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(IDENTITY_BYTES);
    bytes.extend_from_slice(IDENTITY_MAGIC);
    bytes.extend_from_slice(&CANDIDATE_TX_JOURNAL_WIRE_VERSION_V0.to_be_bytes());
    bytes.extend_from_slice(&identity.chain_id.0);
    bytes.extend_from_slice(&identity.journal_id.0);
    bytes.extend_from_slice(&limits.maximum_frames.to_be_bytes());
    bytes.extend_from_slice(&limits.maximum_log_bytes.to_be_bytes());
    bytes.extend_from_slice(&limits.maximum_latest_records.to_be_bytes());
    bytes.extend_from_slice(&digest(b"trnm.candidate-tx-journal.identity-checksum.v0", &bytes).0);
    bytes
}
fn receipt(
    record: &TxRecordV0,
    previous: Digest32V0,
    sequence: u64,
    frame_digest: Digest32V0,
) -> DurableTxRecordV0 {
    let record_digest = record.canonical_record_digest_v0();
    DurableTxRecordV0 {
        tx_id: record.tx_id,
        previous_record_digest: previous,
        record_digest,
        journal_sequence: sequence,
        durable_receipt_digest: Digest32V0::hash(
            b"trnm.candidate-tx-journal.receipt.v0",
            &[
                &frame_digest.0,
                &sequence.to_be_bytes(),
                &record.tx_id.0,
                &previous.0,
                &record_digest.0,
            ],
        ),
    }
}
fn active(record: &TxRecordV0) -> bool {
    !matches!(record.phase, TxPhaseV0::Finalized | TxPhaseV0::Tombstoned)
}
fn install_record(
    state: &mut State,
    record: TxRecordV0,
    previous: Digest32V0,
    sequence: u64,
    frame_digest: Digest32V0,
) {
    if let Some(old) = state.records.get(&record.tx_id) {
        if active(&old.record) {
            state
                .active
                .remove(&(old.record.intent.sender, old.record.intent.nonce));
        }
    }
    if active(&record) {
        state
            .active
            .insert((record.intent.sender, record.intent.nonce), record.tx_id);
    }
    if record.finality.is_some() {
        state
            .finalized_nonce
            .entry(record.intent.sender)
            .and_modify(|value| *value = (*value).max(record.intent.nonce))
            .or_insert(record.intent.nonce);
    }
    let durable = receipt(&record, previous, sequence, frame_digest);
    state
        .records
        .insert(record.tx_id, RecoveredTxRecordV0 { record, durable });
}
fn apply_mutation(state: &mut State, mutation: Mutation, sequence: u64, frame_digest: Digest32V0) {
    match mutation {
        Mutation::Append { previous, record } => {
            install_record(state, *record, previous, sequence, frame_digest)
        }
        Mutation::Replace {
            previous,
            replaced,
            admitted,
        } => {
            install_record(state, *replaced, previous, sequence, frame_digest);
            install_record(state, *admitted, ZERO, sequence, frame_digest);
        }
        Mutation::Collect {
            tx_id,
            previous,
            floor,
        } => {
            state.records.remove(&tx_id);
            state
                .replay_floor
                .entry(floor.account)
                .and_modify(|value| *value = (*value).max(floor.minimum_replayable_nonce))
                .or_insert(floor.minimum_replayable_nonce);
            state.collected.insert(
                tx_id,
                Collection {
                    previous,
                    floor,
                    receipt: frame_digest,
                    sequence,
                },
            );
        }
    }
    state.sequence = sequence;
    state.head = Some(frame_digest);
    state.frame_digests.push(frame_digest);
}

// Exactly one lifecycle mutation or one broadcast receipt may be persisted at
// a time. Existing commitments are immutable; replacing an old transaction is
// deliberately absent here and must use the atomic two-record method.
fn validate_successor(previous: &TxRecordV0, record: &TxRecordV0) -> Result<()> {
    let mut expected = previous.clone();
    if previous.phase == record.phase {
        if previous.broadcast_intent.is_none()
            && record.broadcast_intent.is_some()
            && previous.broadcast_receipt == record.broadcast_receipt
            && !matches!(previous.phase, TxPhaseV0::Admitted | TxPhaseV0::Tombstoned)
        {
            expected.broadcast_intent = record.broadcast_intent;
        } else if previous.broadcast_receipt.is_none()
            && record.broadcast_receipt.is_some()
            && previous.broadcast_intent.is_some()
        {
            expected.broadcast_receipt = record.broadcast_receipt;
        } else {
            return Err(CandidateTxJournalErrorV0::InvalidRecord);
        }
    } else {
        expected.lifecycle_sequence = previous
            .lifecycle_sequence
            .checked_add(1)
            .ok_or(CandidateTxJournalErrorV0::InvalidRecord)?;
        expected.phase = record.phase;
        match (previous.phase, record.phase) {
            (TxPhaseV0::Admitted, TxPhaseV0::WalPersisted) => {
                expected.wal_sequence = record.wal_sequence
            }
            (TxPhaseV0::WalPersisted, TxPhaseV0::Proposed) => expected.proposal = record.proposal,
            (TxPhaseV0::Proposed, TxPhaseV0::Ordered) => expected.ordered = record.ordered,
            (TxPhaseV0::Ordered, TxPhaseV0::Executed) => expected.execution = record.execution,
            (TxPhaseV0::Executed, TxPhaseV0::Finalized) => expected.finality = record.finality,
            (TxPhaseV0::Finalized, TxPhaseV0::Tombstoned)
                if record.tombstone == Some(TombstoneReasonV0::Finalized) =>
            {
                expected.tombstone = record.tombstone
            }
            // These reasons exist in the core schema; their authority still
            // belongs to the host. They cannot authorize deleting live state.
            (TxPhaseV0::Admitted | TxPhaseV0::WalPersisted, TxPhaseV0::Tombstoned)
                if matches!(
                    record.tombstone,
                    Some(TombstoneReasonV0::Expired | TombstoneReasonV0::Rejected)
                ) =>
            {
                expected.tombstone = record.tombstone
            }
            _ => return Err(CandidateTxJournalErrorV0::InvalidRecord),
        }
    }
    if expected != *record {
        return Err(CandidateTxJournalErrorV0::InvalidRecord);
    }
    Ok(())
}

fn encode_frame(
    mutation: &Mutation,
    identity: Digest32V0,
    sequence: u64,
    previous: Digest32V0,
) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(FRAME_MAGIC);
    bytes.extend_from_slice(&CANDIDATE_TX_JOURNAL_WIRE_VERSION_V0.to_be_bytes());
    bytes.extend_from_slice(&identity.0);
    bytes.extend_from_slice(&sequence.to_be_bytes());
    bytes.extend_from_slice(&previous.0);
    match mutation {
        Mutation::Append { previous, record } => {
            bytes.push(0);
            bytes.extend_from_slice(&previous.0);
            encode_record(&mut bytes, record)?;
        }
        Mutation::Replace {
            previous,
            replaced,
            admitted,
        } => {
            bytes.push(1);
            bytes.extend_from_slice(&previous.0);
            encode_record(&mut bytes, replaced)?;
            encode_record(&mut bytes, admitted)?;
        }
        Mutation::Collect {
            tx_id,
            previous,
            floor,
        } => {
            bytes.push(2);
            bytes.extend_from_slice(&tx_id.0);
            bytes.extend_from_slice(&previous.0);
            bytes.extend_from_slice(&floor.account.0);
            bytes.extend_from_slice(&floor.minimum_replayable_nonce.to_be_bytes());
            bytes.extend_from_slice(&floor.finalized_height.to_be_bytes());
            bytes.extend_from_slice(&floor.authority_digest.0);
        }
    }
    let checksum = digest(b"trnm.candidate-tx-journal.frame.v0", &bytes);
    bytes.extend_from_slice(&checksum.0);
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(CandidateTxJournalErrorV0::Capacity);
    }
    Ok(bytes)
}
fn encode_record(bytes: &mut Vec<u8>, record: &TxRecordV0) -> Result<()> {
    let encoded = record
        .encode_canonical_v0()
        .map_err(|_| CandidateTxJournalErrorV0::InvalidRecord)?;
    bytes.extend_from_slice(&(encoded.len() as u32).to_be_bytes());
    bytes.extend_from_slice(&encoded);
    Ok(())
}
struct Decoder<'a>(&'a [u8]);
impl<'a> Decoder<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8]> {
        let bytes = self
            .0
            .get(..count)
            .ok_or(CandidateTxJournalErrorV0::Corrupt("truncated frame"))?;
        self.0 = &self.0[count..];
        Ok(bytes)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        Ok(self.take(N)?.try_into().expect("bounded frame field"))
    }
    fn digest(&mut self) -> Result<Digest32V0> {
        Ok(Digest32V0(self.array()?))
    }
    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.array()?))
    }
    fn record(&mut self) -> Result<Box<TxRecordV0>> {
        let length = u32::from_be_bytes(self.array()?) as usize;
        if length > MAX_TX_RECORD_ENCODED_BYTES_V0 {
            return Err(CandidateTxJournalErrorV0::Capacity);
        }
        TxRecordV0::decode_canonical_v0(self.take(length)?)
            .map(Box::new)
            .map_err(|_| CandidateTxJournalErrorV0::InvalidRecord)
    }
}
fn decode_frame(
    bytes: &[u8],
    identity: Digest32V0,
    sequence: u64,
    previous: Digest32V0,
) -> Result<(Mutation, Digest32V0)> {
    let body_length = bytes
        .len()
        .checked_sub(32)
        .ok_or(CandidateTxJournalErrorV0::Corrupt("missing checksum"))?;
    let (body, checksum) = bytes.split_at(body_length);
    let frame_digest = digest(b"trnm.candidate-tx-journal.frame.v0", body);
    if frame_digest.0 != checksum {
        return Err(CandidateTxJournalErrorV0::Corrupt(
            "frame checksum mismatch",
        ));
    }
    let mut decoder = Decoder(body);
    if decoder.take(8)? != FRAME_MAGIC
        || u16::from_be_bytes(decoder.array()?) != CANDIDATE_TX_JOURNAL_WIRE_VERSION_V0
        || decoder.digest()? != identity
        || decoder.u64()? != sequence
        || decoder.digest()? != previous
    {
        return Err(CandidateTxJournalErrorV0::Corrupt(
            "frame identity or predecessor mismatch",
        ));
    }
    let mutation = match decoder.take(1)?[0] {
        0 => Mutation::Append {
            previous: decoder.digest()?,
            record: decoder.record()?,
        },
        1 => Mutation::Replace {
            previous: decoder.digest()?,
            replaced: decoder.record()?,
            admitted: decoder.record()?,
        },
        2 => Mutation::Collect {
            tx_id: decoder.digest()?,
            previous: decoder.digest()?,
            floor: ReplayFloorWitnessV0 {
                account: decoder.digest()?,
                minimum_replayable_nonce: decoder.u64()?,
                finalized_height: decoder.u64()?,
                authority_digest: decoder.digest()?,
            },
        },
        _ => {
            return Err(CandidateTxJournalErrorV0::Corrupt(
                "unknown frame operation",
            ))
        }
    };
    if !decoder.0.is_empty() {
        return Err(CandidateTxJournalErrorV0::Corrupt("trailing frame bytes"));
    }
    Ok((mutation, frame_digest))
}

#[cfg(test)]
mod tests;
