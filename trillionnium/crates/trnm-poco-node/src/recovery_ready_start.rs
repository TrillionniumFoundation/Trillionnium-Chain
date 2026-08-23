//! Durable process-2 `RecoveryReady` -> `RecoveryStart` orchestration.
//!
//! The existing process-2 owner deliberately stops behind Core's replay fence
//! and keeps the startup timer private.  This module supplies the next,
//! narrower boundary: it records the two authenticated recovery certificates
//! in an independently durable journal and can be replayed after a process
//! loss.  It does *not* consume the owner, clear Core's fence, activate a
//! signer, arm a timer, or open ingress.
//!
//! The journal is an actual SQLite CAS journal, rather than a marker file:
//! every transition is written in an `IMMEDIATE` transaction with
//! `synchronous=FULL`, linked to its predecessor by a SHA-256 hash chain, and
//! re-audited on every open/advance.  A caller may therefore retry an
//! interrupted transition and gets either the exact already-committed row or
//! a fail-closed error.  The owner adapter (compiled when the laboratory
//! runtime is present) calls the caught-up owner's fresh revalidation before
//! it can append either row.

use std::{
    error::Error,
    fmt,
    fs::{self, OpenOptions},
    path::{Component, Path, PathBuf},
};

use rusqlite::{params, Connection, TransactionBehavior};
use sha2::{Digest, Sha256};
use trnm_consensus_types::{
    Epoch, RecoveryReadySetV1, RecoveryStartCertificateV1, SignatureVerifier, ValidatorId,
    ValidatorSet, ValidatorSetId,
};

use crate::external_node_checkpoint::ExternalNodeCheckpointV0;

#[cfg(feature = "lab-validator-runtime")]
use crate::deployed_lab_process2_recovery::PocoNodeDeployedLabProcess2CaughtUpOwnerV1;
#[cfg(feature = "lab-validator-runtime")]
use trnm_consensus_signer_journal::ExternalMonotonicWatermarkV0;

const JOURNAL_MAGIC_V1: &[u8; 8] = b"TRNMPRJ1";
const JOURNAL_SCHEMA_V1: u16 = 1;
const JOURNAL_DOMAIN_V1: &[u8] = b"trnm.poco-node.process2-recovery-transition.v1";
const JOURNAL_APP_ID_V1: i64 = 0x5452_524a; // TRRJ
const JOURNAL_USER_VERSION_V1: i64 = 1;
const JOURNAL_BUSY_TIMEOUT_MS_V1: u64 = 5_000;
// magic + schema + phase + sequence + predecessor, eleven fixed 32-byte
// binding/digest fields, generation, and the record checksum.
const JOURNAL_RECORD_BYTES_V1: usize = 8 + 2 + 1 + 8 + 32 + (32 * 11) + (8 * 3) + 32;

/// This journal is a real durable boundary.  It is not an activation claim.
pub const PROCESS2_RECOVERY_TRANSITION_JOURNAL_V1: bool = true;
pub const PROCESS2_RECOVERY_READY_START_COORDINATOR_V1: bool = true;
pub const PROCESS2_RECOVERY_RUNTIME_WIRING_V1: bool = false;
pub const PROCESS2_RECOVERY_START_ACTIVATION_V1: bool = false;

const CREATE_METADATA_V1: &str = concat!(
    "CREATE TABLE process2_recovery_transition_metadata_v1 (",
    "singleton INTEGER PRIMARY KEY CHECK(singleton = 1),",
    "journal_id BLOB NOT NULL CHECK(typeof(journal_id) = 'blob' AND length(journal_id) = 32),",
    "scope BLOB NOT NULL CHECK(typeof(scope) = 'blob' AND length(scope) = 32),",
    "head_sequence INTEGER NOT NULL CHECK(head_sequence >= -1),",
    "head_phase INTEGER NOT NULL CHECK(head_phase IN (0, 1, 2)),",
    "head_checksum BLOB NOT NULL CHECK(typeof(head_checksum) = 'blob' AND length(head_checksum) = 32),",
    "fenced INTEGER NOT NULL CHECK(fenced IN (0, 1))",
    ") STRICT, WITHOUT ROWID;"
);
const CREATE_EVENTS_V1: &str = concat!(
    "CREATE TABLE process2_recovery_transition_events_v1 (",
    "sequence INTEGER PRIMARY KEY CHECK(sequence >= 0),",
    "phase INTEGER NOT NULL CHECK(phase IN (1, 2)),",
    "predecessor_checksum BLOB NOT NULL CHECK(typeof(predecessor_checksum) = 'blob' AND length(predecessor_checksum) = 32),",
    "checksum BLOB NOT NULL CHECK(typeof(checksum) = 'blob' AND length(checksum) = 32),",
    "record BLOB NOT NULL CHECK(typeof(record) = 'blob' AND length(record) = 459)",
    ") STRICT, WITHOUT ROWID;"
);

/// The two durable stages.  `Empty` is represented by a journal with no
/// event rows; it is included in the public projection for explicit ordering
/// checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Process2RecoveryTransitionPhaseV1 {
    Empty = 0,
    RecoveryReady = 1,
    RecoveryStart = 2,
}

impl TryFrom<u8> for Process2RecoveryTransitionPhaseV1 {
    type Error = RecoveryTransitionJournalErrorV1;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Empty),
            1 => Ok(Self::RecoveryReady),
            2 => Ok(Self::RecoveryStart),
            _ => Err(RecoveryTransitionJournalErrorV1::Tamper(
                "unknown transition phase",
            )),
        }
    }
}

/// Exact prerequisite cut consumed by the coordinator.
///
/// The checkpoint is the independently administered whole-node fence.  Its
/// scope, generation, checksum, and canonical bytes are all copied into the
/// binding, so a certificate for an older node image cannot be replayed on a
/// newer process (or vice versa).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Process2RecoveryTransitionBindingV1 {
    session_id: [u8; 32],
    caught_up_cut_digest: [u8; 32],
    node_facts_digest: [u8; 32],
    validator_set_id: ValidatorSetId,
    target_validator: ValidatorId,
    epoch: Epoch,
    process_generation: u64,
    checkpoint_scope: [u8; 32],
    checkpoint_generation: u64,
    checkpoint_checksum: [u8; 32],
    checkpoint_canonical_sha256: [u8; 32],
    fence_token_digest: [u8; 32],
}

impl Process2RecoveryTransitionBindingV1 {
    /// Construct a binding from exact, already-audited process-2 facts and a
    /// whole-node checkpoint.  The fence token is supplied by the external
    /// owner process; it is intentionally opaque to this crate.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        session_id: [u8; 32],
        caught_up_cut_digest: [u8; 32],
        node_facts_digest: [u8; 32],
        validator_set_id: ValidatorSetId,
        target_validator: ValidatorId,
        epoch: Epoch,
        process_generation: u64,
        checkpoint: ExternalNodeCheckpointV0,
        fence_token_digest: [u8; 32],
    ) -> Result<Self, RecoveryTransitionJournalErrorV1> {
        if session_id == [0; 32]
            || caught_up_cut_digest == [0; 32]
            || node_facts_digest == [0; 32]
            || validator_set_id.as_bytes() == &[0; 32]
            || target_validator.is_zero()
            || process_generation == 0
            || checkpoint.scope() == [0; 32]
            || checkpoint.generation() == 0
            || checkpoint.generation() != process_generation
            || checkpoint.checkpoint_checksum() == [0; 32]
            || fence_token_digest == [0; 32]
        {
            return Err(RecoveryTransitionJournalErrorV1::InvalidBinding(
                "recovery transition binding contains a zero prerequisite",
            ));
        }
        Ok(Self {
            session_id,
            caught_up_cut_digest,
            node_facts_digest,
            validator_set_id,
            target_validator,
            epoch,
            process_generation,
            checkpoint_scope: checkpoint.scope(),
            checkpoint_generation: checkpoint.generation(),
            checkpoint_checksum: checkpoint.checkpoint_checksum(),
            checkpoint_canonical_sha256: Sha256::digest(checkpoint.encode_canonical()).into(),
            fence_token_digest,
        })
    }

    pub const fn session_id_v1(self) -> [u8; 32] {
        self.session_id
    }

    pub const fn caught_up_cut_digest_v1(self) -> [u8; 32] {
        self.caught_up_cut_digest
    }

    pub const fn node_facts_digest_v1(self) -> [u8; 32] {
        self.node_facts_digest
    }

    pub const fn validator_set_id_v1(self) -> ValidatorSetId {
        self.validator_set_id
    }

    pub const fn target_validator_v1(self) -> ValidatorId {
        self.target_validator
    }

    pub const fn epoch_v1(self) -> Epoch {
        self.epoch
    }

    pub const fn process_generation_v1(self) -> u64 {
        self.process_generation
    }

    pub const fn checkpoint_scope_v1(self) -> [u8; 32] {
        self.checkpoint_scope
    }

    pub const fn checkpoint_generation_v1(self) -> u64 {
        self.checkpoint_generation
    }

    pub const fn checkpoint_checksum_v1(self) -> [u8; 32] {
        self.checkpoint_checksum
    }

    pub const fn checkpoint_canonical_sha256_v1(self) -> [u8; 32] {
        self.checkpoint_canonical_sha256
    }

    pub const fn fence_token_digest_v1(self) -> [u8; 32] {
        self.fence_token_digest
    }

    fn digest_v1(self) -> [u8; 32] {
        let mut bytes = Vec::with_capacity(32 * 9 + 8 + 8);
        bytes.extend_from_slice(JOURNAL_DOMAIN_V1);
        bytes.extend_from_slice(&self.session_id);
        bytes.extend_from_slice(&self.caught_up_cut_digest);
        bytes.extend_from_slice(&self.node_facts_digest);
        bytes.extend_from_slice(self.validator_set_id.as_bytes());
        bytes.extend_from_slice(self.target_validator.as_bytes());
        bytes.extend_from_slice(&self.epoch.get().to_be_bytes());
        bytes.extend_from_slice(&self.process_generation.to_be_bytes());
        bytes.extend_from_slice(&self.checkpoint_scope);
        bytes.extend_from_slice(&self.checkpoint_generation.to_be_bytes());
        bytes.extend_from_slice(&self.checkpoint_checksum);
        bytes.extend_from_slice(&self.checkpoint_canonical_sha256);
        bytes.extend_from_slice(&self.fence_token_digest);
        Sha256::digest(bytes).into()
    }
}

/// Cloneable read-only head facts.  It carries no owner or activation handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Process2RecoveryTransitionFactsV1 {
    phase: Process2RecoveryTransitionPhaseV1,
    sequence: u64,
    binding_digest: [u8; 32],
    ready_set_digest: [u8; 32],
    start_certificate_digest: [u8; 32],
    event_checksum: [u8; 32],
}

impl Process2RecoveryTransitionFactsV1 {
    pub const fn phase_v1(self) -> Process2RecoveryTransitionPhaseV1 {
        self.phase
    }
    pub const fn sequence_v1(self) -> u64 {
        self.sequence
    }
    pub const fn binding_digest_v1(self) -> [u8; 32] {
        self.binding_digest
    }
    pub const fn ready_set_digest_v1(self) -> [u8; 32] {
        self.ready_set_digest
    }
    pub const fn start_certificate_digest_v1(self) -> [u8; 32] {
        self.start_certificate_digest
    }
    pub const fn event_checksum_v1(self) -> [u8; 32] {
        self.event_checksum
    }
}

/// Closed failures.  `Tamper` and `ThirdState` are terminal until an
/// operator quarantines the namespace; callers must not retry them as if they
/// were network delay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryTransitionJournalErrorV1 {
    Unavailable(&'static str),
    InvalidPath,
    InvalidBinding(&'static str),
    WrongOrder(&'static str),
    Stale(&'static str),
    Conflict(&'static str),
    Verification(&'static str),
    Tamper(&'static str),
    ThirdState(&'static str),
}

impl fmt::Display for RecoveryTransitionJournalErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "process2 recovery transition error: {self:?}")
    }
}

impl Error for RecoveryTransitionJournalErrorV1 {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TransitionRecordV1 {
    phase: Process2RecoveryTransitionPhaseV1,
    sequence: u64,
    predecessor_checksum: [u8; 32],
    binding: Process2RecoveryTransitionBindingV1,
    ready_set_digest: [u8; 32],
    start_certificate_digest: [u8; 32],
    checksum: [u8; 32],
}

impl TransitionRecordV1 {
    fn new(
        phase: Process2RecoveryTransitionPhaseV1,
        sequence: u64,
        predecessor_checksum: [u8; 32],
        binding: Process2RecoveryTransitionBindingV1,
        ready_set_digest: [u8; 32],
        start_certificate_digest: [u8; 32],
    ) -> Result<Self, RecoveryTransitionJournalErrorV1> {
        if !matches!(
            phase,
            Process2RecoveryTransitionPhaseV1::RecoveryReady
                | Process2RecoveryTransitionPhaseV1::RecoveryStart
        ) || ready_set_digest == [0; 32]
            || (phase == Process2RecoveryTransitionPhaseV1::RecoveryStart
                && start_certificate_digest == [0; 32])
            || (phase == Process2RecoveryTransitionPhaseV1::RecoveryReady
                && start_certificate_digest != [0; 32])
        {
            return Err(RecoveryTransitionJournalErrorV1::InvalidBinding(
                "transition record phase/digest shape is invalid",
            ));
        }
        let mut value = Self {
            phase,
            sequence,
            predecessor_checksum,
            binding,
            ready_set_digest,
            start_certificate_digest,
            checksum: [0; 32],
        };
        value.checksum = value.compute_checksum_v1();
        Ok(value)
    }

    fn compute_checksum_v1(&self) -> [u8; 32] {
        Sha256::digest(self.encode_prefix_v1()).into()
    }

    fn encode_prefix_v1(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(JOURNAL_RECORD_BYTES_V1 - 32);
        bytes.extend_from_slice(JOURNAL_MAGIC_V1);
        bytes.extend_from_slice(&JOURNAL_SCHEMA_V1.to_be_bytes());
        bytes.push(self.phase as u8);
        bytes.extend_from_slice(&self.sequence.to_be_bytes());
        bytes.extend_from_slice(&self.predecessor_checksum);
        bytes.extend_from_slice(&self.binding.session_id);
        bytes.extend_from_slice(&self.binding.caught_up_cut_digest);
        bytes.extend_from_slice(&self.binding.node_facts_digest);
        bytes.extend_from_slice(self.binding.validator_set_id.as_bytes());
        bytes.extend_from_slice(self.binding.target_validator.as_bytes());
        bytes.extend_from_slice(&self.binding.epoch.get().to_be_bytes());
        bytes.extend_from_slice(&self.binding.process_generation.to_be_bytes());
        bytes.extend_from_slice(&self.binding.checkpoint_scope);
        bytes.extend_from_slice(&self.binding.checkpoint_generation.to_be_bytes());
        bytes.extend_from_slice(&self.binding.checkpoint_checksum);
        bytes.extend_from_slice(&self.binding.checkpoint_canonical_sha256);
        bytes.extend_from_slice(&self.binding.fence_token_digest);
        bytes.extend_from_slice(&self.ready_set_digest);
        bytes.extend_from_slice(&self.start_certificate_digest);
        bytes
    }

    fn encode_v1(&self) -> Vec<u8> {
        let mut bytes = self.encode_prefix_v1();
        bytes.extend_from_slice(&self.checksum);
        bytes
    }

    fn decode_v1(bytes: &[u8]) -> Result<Self, RecoveryTransitionJournalErrorV1> {
        if bytes.len() != JOURNAL_RECORD_BYTES_V1 {
            return Err(RecoveryTransitionJournalErrorV1::Tamper(
                "transition record length differs",
            ));
        }
        if &bytes[..8] != JOURNAL_MAGIC_V1
            || u16::from_be_bytes([bytes[8], bytes[9]]) != JOURNAL_SCHEMA_V1
        {
            return Err(RecoveryTransitionJournalErrorV1::Tamper(
                "transition record magic/schema differs",
            ));
        }
        let mut offset = 10;
        let phase = Process2RecoveryTransitionPhaseV1::try_from(bytes[offset])?;
        offset += 1;
        let sequence = read_u64_v1(bytes, &mut offset)?;
        let predecessor_checksum = read_array_v1(bytes, &mut offset)?;
        let session_id = read_array_v1(bytes, &mut offset)?;
        let caught_up_cut_digest = read_array_v1(bytes, &mut offset)?;
        let node_facts_digest = read_array_v1(bytes, &mut offset)?;
        let validator_set_id = ValidatorSetId::new(read_array_v1(bytes, &mut offset)?);
        let target_validator = ValidatorId::new(read_array_v1(bytes, &mut offset)?);
        let epoch = Epoch::new(read_u64_v1(bytes, &mut offset)?);
        let process_generation = read_u64_v1(bytes, &mut offset)?;
        let checkpoint_scope = read_array_v1(bytes, &mut offset)?;
        let checkpoint_generation = read_u64_v1(bytes, &mut offset)?;
        let checkpoint_checksum = read_array_v1(bytes, &mut offset)?;
        let checkpoint_canonical_sha256 = read_array_v1(bytes, &mut offset)?;
        let fence_token_digest = read_array_v1(bytes, &mut offset)?;
        let ready_set_digest = read_array_v1(bytes, &mut offset)?;
        let start_certificate_digest = read_array_v1(bytes, &mut offset)?;
        let checksum = read_array_v1(bytes, &mut offset)?;
        if offset != bytes.len() {
            return Err(RecoveryTransitionJournalErrorV1::Tamper(
                "transition record has trailing bytes",
            ));
        }
        let binding = Process2RecoveryTransitionBindingV1 {
            session_id,
            caught_up_cut_digest,
            node_facts_digest,
            validator_set_id,
            target_validator,
            epoch,
            process_generation,
            checkpoint_scope,
            checkpoint_generation,
            checkpoint_checksum,
            checkpoint_canonical_sha256,
            fence_token_digest,
        };
        let value = Self::new(
            phase,
            sequence,
            predecessor_checksum,
            binding,
            ready_set_digest,
            start_certificate_digest,
        )?;
        if value.checksum != checksum {
            return Err(RecoveryTransitionJournalErrorV1::Tamper(
                "transition record checksum differs",
            ));
        }
        Ok(value)
    }

    fn facts_v1(&self) -> Process2RecoveryTransitionFactsV1 {
        Process2RecoveryTransitionFactsV1 {
            phase: self.phase,
            sequence: self.sequence,
            binding_digest: self.binding.digest_v1(),
            ready_set_digest: self.ready_set_digest,
            start_certificate_digest: self.start_certificate_digest,
            event_checksum: self.checksum,
        }
    }
}

/// Independently durable process-2 transition journal.
#[derive(Debug, Clone)]
pub struct Process2RecoveryTransitionJournalV1 {
    path: PathBuf,
}

impl Process2RecoveryTransitionJournalV1 {
    pub fn initialize_new(
        path: impl AsRef<Path>,
    ) -> Result<Self, RecoveryTransitionJournalErrorV1> {
        let path = validate_journal_path_v1(path.as_ref())?;
        let mut options = OpenOptions::new();
        options.read(true).write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        let file = options.open(&path).map_err(|_| {
            RecoveryTransitionJournalErrorV1::Unavailable("cannot create transition journal")
        })?;
        file.sync_all().map_err(|_| {
            RecoveryTransitionJournalErrorV1::Unavailable("cannot sync transition journal")
        })?;
        drop(file);
        let connection = open_connection_v1(&path, true)?;
        initialize_schema_v1(&connection)?;
        drop(connection);
        Ok(Self { path })
    }

    pub fn open_existing(path: impl AsRef<Path>) -> Result<Self, RecoveryTransitionJournalErrorV1> {
        let path = validate_journal_path_v1(path.as_ref())?;
        if !path.is_file() {
            return Err(RecoveryTransitionJournalErrorV1::Unavailable(
                "transition journal does not exist",
            ));
        }
        let connection = open_connection_v1(&path, false)?;
        validate_schema_v1(&connection)?;
        let journal = Self { path };
        journal.audit_connection_v1(&connection)?;
        Ok(journal)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn head_v1(
        &self,
    ) -> Result<Option<Process2RecoveryTransitionFactsV1>, RecoveryTransitionJournalErrorV1> {
        let connection = open_connection_v1(&self.path, false)?;
        validate_schema_v1(&connection)?;
        Ok(self
            .audit_connection_v1(&connection)?
            .map(|record| record.facts_v1()))
    }

    fn audit_connection_v1(
        &self,
        connection: &Connection,
    ) -> Result<Option<TransitionRecordV1>, RecoveryTransitionJournalErrorV1> {
        let metadata = connection
            .query_row(
                "SELECT journal_id, scope, head_sequence, head_phase, head_checksum, fenced FROM process2_recovery_transition_metadata_v1 WHERE singleton = 1",
                [],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, Vec<u8>>(4)?,
                        row.get::<_, i64>(5)?,
                    ))
                },
            )
            .map_err(|_| RecoveryTransitionJournalErrorV1::Tamper("metadata row missing"))?;
        if metadata.0.len() != 32
            || metadata.1.len() != 32
            || metadata.4.len() != 32
            || metadata.5 != 0
            || metadata.2 < -1
            || !(0..=2).contains(&metadata.3)
        {
            return Err(RecoveryTransitionJournalErrorV1::Tamper(
                "metadata shape is invalid",
            ));
        }
        let mut statement = connection
            .prepare(
                "SELECT sequence, phase, predecessor_checksum, checksum, record FROM process2_recovery_transition_events_v1 ORDER BY sequence ASC",
            )
            .map_err(|_| RecoveryTransitionJournalErrorV1::Unavailable("cannot read transition events"))?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                ))
            })
            .map_err(|_| {
                RecoveryTransitionJournalErrorV1::Unavailable("cannot scan transition events")
            })?;
        let mut expected_sequence = 0_u64;
        let mut predecessor = [0_u8; 32];
        let mut head = None;
        for row in rows {
            let (sequence, phase, predecessor_bytes, checksum_bytes, record_bytes) = row
                .map_err(|_| RecoveryTransitionJournalErrorV1::Tamper("cannot decode event row"))?;
            let sequence = u64::try_from(sequence).map_err(|_| {
                RecoveryTransitionJournalErrorV1::Tamper("event sequence is negative")
            })?;
            if sequence != expected_sequence
                || predecessor_bytes.as_slice() != predecessor
                || checksum_bytes.len() != 32
                || record_bytes.len() != JOURNAL_RECORD_BYTES_V1
            {
                return Err(RecoveryTransitionJournalErrorV1::Tamper(
                    "event sequence/hash chain is not contiguous",
                ));
            }
            let record = TransitionRecordV1::decode_v1(&record_bytes)?;
            if record.sequence != sequence
                || record.phase as i64 != phase
                || record.predecessor_checksum != predecessor
                || record.checksum.as_slice() != checksum_bytes.as_slice()
            {
                return Err(RecoveryTransitionJournalErrorV1::Tamper(
                    "event row columns differ from canonical record",
                ));
            }
            if sequence == 0 && record.phase != Process2RecoveryTransitionPhaseV1::RecoveryReady
                || sequence == 1 && record.phase != Process2RecoveryTransitionPhaseV1::RecoveryStart
                || sequence > 1
            {
                return Err(RecoveryTransitionJournalErrorV1::Tamper(
                    "transition phase ordering is invalid",
                ));
            }
            if record.phase == Process2RecoveryTransitionPhaseV1::RecoveryStart
                && head.as_ref().is_none_or(|previous: &TransitionRecordV1| {
                    previous.phase != Process2RecoveryTransitionPhaseV1::RecoveryReady
                        || previous.binding != record.binding
                        || previous.ready_set_digest != record.ready_set_digest
                })
            {
                return Err(RecoveryTransitionJournalErrorV1::Tamper(
                    "RecoveryStart does not follow the exact RecoveryReady",
                ));
            }
            predecessor = record.checksum;
            expected_sequence = expected_sequence.checked_add(1).ok_or(
                RecoveryTransitionJournalErrorV1::Tamper("event sequence overflow"),
            )?;
            head = Some(record);
        }
        let expected_head_sequence = i64::try_from(expected_sequence)
            .ok()
            .and_then(|v| v.checked_sub(1));
        if Some(metadata.2) != expected_head_sequence
            || metadata.3 != head.map(|value| value.phase as i64).unwrap_or(0)
            || metadata.4.as_slice() != head.map(|value| value.checksum).unwrap_or([0; 32])
            || match head {
                Some(value) => {
                    metadata.0.as_slice() != value.binding.digest_v1()
                        || metadata.1.as_slice() != value.binding.checkpoint_scope
                }
                None => metadata.0.as_slice() != [0; 32] || metadata.1.as_slice() != [0; 32],
            }
        {
            return Err(RecoveryTransitionJournalErrorV1::Tamper(
                "metadata head differs from event history",
            ));
        }
        Ok(head)
    }

    fn append_v1(
        &self,
        expected: Option<&TransitionRecordV1>,
        target: TransitionRecordV1,
    ) -> Result<TransitionRecordV1, RecoveryTransitionJournalErrorV1> {
        let mut connection = open_connection_v1(&self.path, false)?;
        validate_schema_v1(&connection)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| {
                RecoveryTransitionJournalErrorV1::Unavailable("cannot start journal transaction")
            })?;
        let observed = self.audit_connection_v1(&transaction)?;
        if observed.as_ref() == Some(&target) {
            return Ok(target);
        }
        if observed.as_ref() != expected {
            return Err(RecoveryTransitionJournalErrorV1::Conflict(
                "journal head is neither exact expected nor exact target",
            ));
        }
        if let Some(previous) = expected {
            if target.sequence != previous.sequence.saturating_add(1)
                || target.predecessor_checksum != previous.checksum
            {
                return Err(RecoveryTransitionJournalErrorV1::WrongOrder(
                    "transition does not name the exact predecessor",
                ));
            }
        } else if target.sequence != 0 || target.predecessor_checksum != [0; 32] {
            return Err(RecoveryTransitionJournalErrorV1::WrongOrder(
                "first transition must be sequence zero",
            ));
        }
        let record = target.encode_v1();
        debug_assert_eq!(record.len(), JOURNAL_RECORD_BYTES_V1);
        let changed = transaction
            .execute(
                "INSERT INTO process2_recovery_transition_events_v1(sequence, phase, predecessor_checksum, checksum, record) VALUES(?1, ?2, ?3, ?4, ?5)",
                params![
                    i64::try_from(target.sequence).map_err(|_| RecoveryTransitionJournalErrorV1::WrongOrder("sequence overflows SQLite"))?,
                    i64::from(target.phase as u8),
                    &target.predecessor_checksum[..],
                    &target.checksum[..],
                    &record[..],
                ],
            )
            .map_err(|_| RecoveryTransitionJournalErrorV1::Unavailable("cannot append transition event"))?;
        if changed != 1 {
            return Err(RecoveryTransitionJournalErrorV1::Conflict(
                "transition event insert changed no row",
            ));
        }
        let binding_digest = target.binding.digest_v1();
        let changed = transaction
            .execute(
                "UPDATE process2_recovery_transition_metadata_v1 SET journal_id = ?1, scope = ?2, head_sequence = ?3, head_phase = ?4, head_checksum = ?5 WHERE singleton = 1 AND fenced = 0 AND head_sequence = ?6 AND head_phase = ?7 AND head_checksum = ?8",
                params![
                    &binding_digest[..],
                    &target.binding.checkpoint_scope[..],
                    i64::try_from(target.sequence).map_err(|_| RecoveryTransitionJournalErrorV1::WrongOrder("sequence overflows SQLite"))?,
                    i64::from(target.phase as u8),
                    &target.checksum[..],
                    expected.map(|record| i64::try_from(record.sequence).unwrap_or(-2)).unwrap_or(-1),
                    expected.map(|record| i64::from(record.phase as u8)).unwrap_or(0),
                    &expected.map(|record| record.checksum).unwrap_or([0; 32])[..],
                ],
            )
            .map_err(|_| RecoveryTransitionJournalErrorV1::Unavailable("cannot advance transition metadata"))?;
        if changed != 1 {
            return Err(RecoveryTransitionJournalErrorV1::Conflict(
                "transition metadata CAS changed no row",
            ));
        }
        transaction.commit().map_err(|_| {
            RecoveryTransitionJournalErrorV1::Unavailable(
                "transition commit acknowledgement was lost",
            )
        })?;
        let reopened = open_connection_v1(&self.path, false)?;
        validate_schema_v1(&reopened)?;
        let observed = self.audit_connection_v1(&reopened)?;
        if observed != Some(target) {
            return Err(RecoveryTransitionJournalErrorV1::ThirdState(
                "transition commit readback is neither expected nor target",
            ));
        }
        Ok(target)
    }

    fn append_ready_v1(
        &self,
        binding: Process2RecoveryTransitionBindingV1,
        ready_set_digest: [u8; 32],
    ) -> Result<Process2RecoveryTransitionFactsV1, RecoveryTransitionJournalErrorV1> {
        let target = TransitionRecordV1::new(
            Process2RecoveryTransitionPhaseV1::RecoveryReady,
            0,
            [0; 32],
            binding,
            ready_set_digest,
            [0; 32],
        )?;
        Ok(self.append_v1(None, target)?.facts_v1())
    }

    fn append_start_v1(
        &self,
        binding: Process2RecoveryTransitionBindingV1,
        ready_set_digest: [u8; 32],
        start_certificate_digest: [u8; 32],
    ) -> Result<Process2RecoveryTransitionFactsV1, RecoveryTransitionJournalErrorV1> {
        let head = self.head_record_v1()?;
        if let Some(previous) = head.as_ref() {
            if previous.binding != binding || previous.ready_set_digest != ready_set_digest {
                return Err(RecoveryTransitionJournalErrorV1::Stale(
                    "RecoveryStart does not match the exact Ready predecessor",
                ));
            }
            if previous.phase == Process2RecoveryTransitionPhaseV1::RecoveryStart {
                if previous.start_certificate_digest == start_certificate_digest {
                    return Ok(previous.facts_v1());
                }
                return Err(RecoveryTransitionJournalErrorV1::Conflict(
                    "RecoveryStart certificate differs from the committed certificate",
                ));
            }
        }
        let target = TransitionRecordV1::new(
            Process2RecoveryTransitionPhaseV1::RecoveryStart,
            1,
            head.map(|value| value.checksum).unwrap_or([0; 32]),
            binding,
            ready_set_digest,
            start_certificate_digest,
        )?;
        Ok(self.append_v1(head.as_ref(), target)?.facts_v1())
    }

    fn head_record_v1(
        &self,
    ) -> Result<Option<TransitionRecordV1>, RecoveryTransitionJournalErrorV1> {
        let connection = open_connection_v1(&self.path, false)?;
        validate_schema_v1(&connection)?;
        self.audit_connection_v1(&connection)
    }
}

/// Coordinator that verifies direct-7 certificates and persists their exact
/// ordering.  It is intentionally not an activation owner.
#[derive(Debug, Clone)]
pub struct Process2RecoveryReadyStartCoordinatorV1 {
    journal: Process2RecoveryTransitionJournalV1,
}

impl Process2RecoveryReadyStartCoordinatorV1 {
    pub fn initialize_new(
        path: impl AsRef<Path>,
    ) -> Result<Self, RecoveryTransitionJournalErrorV1> {
        Ok(Self {
            journal: Process2RecoveryTransitionJournalV1::initialize_new(path)?,
        })
    }

    pub fn open_existing(path: impl AsRef<Path>) -> Result<Self, RecoveryTransitionJournalErrorV1> {
        Ok(Self {
            journal: Process2RecoveryTransitionJournalV1::open_existing(path)?,
        })
    }

    pub const fn journal(&self) -> &Process2RecoveryTransitionJournalV1 {
        &self.journal
    }

    pub fn head_v1(
        &self,
    ) -> Result<Option<Process2RecoveryTransitionFactsV1>, RecoveryTransitionJournalErrorV1> {
        self.journal.head_v1()
    }

    /// Persist an authenticated Ready barrier after checking the exact
    /// process-2 binding.  This method does not expose or consume owner parts.
    pub fn record_recovery_ready_v1(
        &mut self,
        binding: Process2RecoveryTransitionBindingV1,
        ready_set: &RecoveryReadySetV1,
        validator_set: &ValidatorSet,
        verifier: &impl SignatureVerifier,
    ) -> Result<Process2RecoveryTransitionFactsV1, RecoveryTransitionJournalErrorV1> {
        ready_set.verify(validator_set, verifier).map_err(|_| {
            RecoveryTransitionJournalErrorV1::Verification("RecoveryReady verification failed")
        })?;
        validate_ready_binding_v1(&binding, ready_set, validator_set)?;
        let digest = ready_set.digest();
        if let Some(head) = self.journal.head_record_v1()? {
            if head.binding != binding {
                return Err(RecoveryTransitionJournalErrorV1::Stale(
                    "RecoveryReady belongs to a stale or foreign process2 cut",
                ));
            }
            if head.phase == Process2RecoveryTransitionPhaseV1::RecoveryReady
                && head.ready_set_digest == digest
            {
                return Ok(head.facts_v1());
            }
            if head.phase == Process2RecoveryTransitionPhaseV1::RecoveryStart
                && head.ready_set_digest == digest
            {
                return Ok(head.facts_v1());
            }
            return Err(RecoveryTransitionJournalErrorV1::Conflict(
                "RecoveryReady is a replay or an equivocation",
            ));
        }
        self.journal.append_ready_v1(binding, digest)
    }

    /// Persist an authenticated Start certificate only after the exact Ready
    /// row is present.  Replaying the same certificate is idempotent; changing
    /// any context, ReadySet, or certificate digest fails closed.
    pub fn record_recovery_start_v1(
        &mut self,
        binding: Process2RecoveryTransitionBindingV1,
        start_certificate: &RecoveryStartCertificateV1,
        validator_set: &ValidatorSet,
        verifier: &impl SignatureVerifier,
    ) -> Result<Process2RecoveryTransitionFactsV1, RecoveryTransitionJournalErrorV1> {
        start_certificate
            .verify(validator_set, verifier)
            .map_err(|_| {
                RecoveryTransitionJournalErrorV1::Verification("RecoveryStart verification failed")
            })?;
        validate_start_binding_v1(&binding, start_certificate, validator_set)?;
        let ready_digest = start_certificate.ready_set().digest();
        let certificate_digest = start_certificate.digest();
        let head =
            self.journal
                .head_record_v1()?
                .ok_or(RecoveryTransitionJournalErrorV1::WrongOrder(
                    "RecoveryStart cannot be persisted before RecoveryReady",
                ))?;
        if head.binding != binding || head.ready_set_digest != ready_digest {
            return Err(RecoveryTransitionJournalErrorV1::Stale(
                "RecoveryStart does not match the exact Ready cut",
            ));
        }
        match head.phase {
            Process2RecoveryTransitionPhaseV1::RecoveryReady => {
                self.journal
                    .append_start_v1(binding, ready_digest, certificate_digest)
            }
            Process2RecoveryTransitionPhaseV1::RecoveryStart
                if head.start_certificate_digest == certificate_digest =>
            {
                Ok(head.facts_v1())
            }
            Process2RecoveryTransitionPhaseV1::RecoveryStart => {
                Err(RecoveryTransitionJournalErrorV1::Conflict(
                    "RecoveryStart certificate differs from the committed certificate",
                ))
            }
            Process2RecoveryTransitionPhaseV1::Empty => {
                Err(RecoveryTransitionJournalErrorV1::WrongOrder(
                    "RecoveryStart cannot follow an empty journal",
                ))
            }
        }
    }

    /// Owner-aware Ready gate.  The fresh revalidation is the important
    /// runtime seam: copied facts or a stale SQLite row cannot mint a Ready
    /// event.  The owner remains borrowed and non-cloneable.
    #[cfg(feature = "lab-validator-runtime")]
    pub fn record_recovery_ready_for_caught_up_owner_v1<W: ExternalMonotonicWatermarkV0>(
        &mut self,
        owner: &mut PocoNodeDeployedLabProcess2CaughtUpOwnerV1<W>,
        checkpoint: ExternalNodeCheckpointV0,
        fence_token_digest: [u8; 32],
        ready_set: &RecoveryReadySetV1,
        validator_set: &ValidatorSet,
        verifier: &impl SignatureVerifier,
    ) -> Result<Process2RecoveryTransitionFactsV1, RecoveryTransitionJournalErrorV1> {
        owner.revalidate_zero_delta_caught_up_v1().map_err(|_| {
            RecoveryTransitionJournalErrorV1::Stale("caught-up owner revalidation failed")
        })?;
        let binding = binding_from_caught_up_owner_v1(owner, checkpoint, fence_token_digest)?;
        self.record_recovery_ready_v1(binding, ready_set, validator_set, verifier)
    }

    #[cfg(feature = "lab-validator-runtime")]
    pub fn record_recovery_start_for_caught_up_owner_v1<W: ExternalMonotonicWatermarkV0>(
        &mut self,
        owner: &mut PocoNodeDeployedLabProcess2CaughtUpOwnerV1<W>,
        checkpoint: ExternalNodeCheckpointV0,
        fence_token_digest: [u8; 32],
        start_certificate: &RecoveryStartCertificateV1,
        validator_set: &ValidatorSet,
        verifier: &impl SignatureVerifier,
    ) -> Result<Process2RecoveryTransitionFactsV1, RecoveryTransitionJournalErrorV1> {
        owner.revalidate_zero_delta_caught_up_v1().map_err(|_| {
            RecoveryTransitionJournalErrorV1::Stale("caught-up owner revalidation failed")
        })?;
        let binding = binding_from_caught_up_owner_v1(owner, checkpoint, fence_token_digest)?;
        self.record_recovery_start_v1(binding, start_certificate, validator_set, verifier)
    }
}

fn validate_ready_binding_v1(
    binding: &Process2RecoveryTransitionBindingV1,
    ready_set: &RecoveryReadySetV1,
    validator_set: &ValidatorSet,
) -> Result<(), RecoveryTransitionJournalErrorV1> {
    let context = ready_set.context();
    if context.validator_set_id() != binding.validator_set_id
        || context.target_validator() != binding.target_validator
        || context.fields().caught_up_cut_artifact_sha256 != binding.caught_up_cut_digest
        || context.node_facts_sha256() != binding.node_facts_digest
        || context.validator_set_id() != validator_set.id()
        || context.fields().restart_cut_epoch != binding.epoch
        || context.fields().terminal_epoch != binding.epoch
        || validator_set.epoch() != binding.epoch
    {
        return Err(RecoveryTransitionJournalErrorV1::Stale(
            "RecoveryReady context does not bind the exact process2 cut",
        ));
    }
    Ok(())
}

fn validate_start_binding_v1(
    binding: &Process2RecoveryTransitionBindingV1,
    certificate: &RecoveryStartCertificateV1,
    validator_set: &ValidatorSet,
) -> Result<(), RecoveryTransitionJournalErrorV1> {
    validate_ready_binding_v1(binding, certificate.ready_set(), validator_set)
}

#[cfg(feature = "lab-validator-runtime")]
fn binding_from_caught_up_owner_v1<W: ExternalMonotonicWatermarkV0>(
    owner: &PocoNodeDeployedLabProcess2CaughtUpOwnerV1<W>,
    checkpoint: ExternalNodeCheckpointV0,
    fence_token_digest: [u8; 32],
) -> Result<Process2RecoveryTransitionBindingV1, RecoveryTransitionJournalErrorV1> {
    let facts = owner.facts_v1();
    let cut = facts.restart_cut_v1().fields_v1();
    let process2 = facts.process2_v1();
    if checkpoint.generation() != process2.final_checkpoint_generation_v0()
        || checkpoint.checkpoint_checksum() != process2.final_checkpoint_checksum_v0()
        || Sha256::digest(checkpoint.encode_canonical()).as_slice()
            != facts.process2_checkpoint_canonical_sha256_v1()
    {
        return Err(RecoveryTransitionJournalErrorV1::Stale(
            "external checkpoint is not the exact caught-up checkpoint",
        ));
    }
    Process2RecoveryTransitionBindingV1::new(
        process2.session_id_v0(),
        facts.artifact_sha256_v1(),
        facts.node_facts_sha256_v1(),
        cut.validator_set_id,
        cut.local_validator,
        cut.epoch,
        process2.final_checkpoint_generation_v0(),
        checkpoint,
        fence_token_digest,
    )
}

fn validate_journal_path_v1(path: &Path) -> Result<PathBuf, RecoveryTransitionJournalErrorV1> {
    if !path.is_absolute()
        || path.file_name().is_none()
        || path.parent().is_none()
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(RecoveryTransitionJournalErrorV1::InvalidPath);
    }
    let parent = path
        .parent()
        .ok_or(RecoveryTransitionJournalErrorV1::InvalidPath)?;
    if !parent.is_dir() {
        return Err(RecoveryTransitionJournalErrorV1::InvalidPath);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let metadata =
            fs::metadata(parent).map_err(|_| RecoveryTransitionJournalErrorV1::InvalidPath)?;
        if metadata.mode() & 0o077 != 0 {
            return Err(RecoveryTransitionJournalErrorV1::InvalidPath);
        }
    }
    Ok(path.to_path_buf())
}

fn open_connection_v1(
    path: &Path,
    initialize: bool,
) -> Result<Connection, RecoveryTransitionJournalErrorV1> {
    let connection = Connection::open(path).map_err(|_| {
        RecoveryTransitionJournalErrorV1::Unavailable("cannot open transition journal")
    })?;
    connection
        .busy_timeout(std::time::Duration::from_millis(JOURNAL_BUSY_TIMEOUT_MS_V1))
        .map_err(|_| RecoveryTransitionJournalErrorV1::Unavailable("cannot set busy timeout"))?;
    connection
        .pragma_update(None, "journal_mode", "DELETE")
        .map_err(|_| RecoveryTransitionJournalErrorV1::Unavailable("cannot set journal mode"))?;
    connection
        .pragma_update(None, "synchronous", "FULL")
        .map_err(|_| RecoveryTransitionJournalErrorV1::Unavailable("cannot set sync mode"))?;
    if initialize {
        connection
            .pragma_update(None, "application_id", JOURNAL_APP_ID_V1)
            .map_err(|_| {
                RecoveryTransitionJournalErrorV1::Unavailable("cannot set application id")
            })?;
        connection
            .pragma_update(None, "user_version", JOURNAL_USER_VERSION_V1)
            .map_err(|_| {
                RecoveryTransitionJournalErrorV1::Unavailable("cannot set schema version")
            })?;
    }
    Ok(connection)
}

fn initialize_schema_v1(connection: &Connection) -> Result<(), RecoveryTransitionJournalErrorV1> {
    let transaction = connection.unchecked_transaction().map_err(|_| {
        RecoveryTransitionJournalErrorV1::Unavailable("cannot initialize transition schema")
    })?;
    transaction
        .execute_batch(CREATE_METADATA_V1)
        .and_then(|_| transaction.execute_batch(CREATE_EVENTS_V1))
        .and_then(|_| {
            transaction.execute(
                "INSERT INTO process2_recovery_transition_metadata_v1(singleton, journal_id, scope, head_sequence, head_phase, head_checksum, fenced) VALUES(1, ?1, ?2, -1, 0, ?3, 0)",
                params![&[0_u8; 32][..], &[0_u8; 32][..], &[0_u8; 32][..]],
            )
        })
        .map_err(|_| RecoveryTransitionJournalErrorV1::Unavailable("cannot write transition schema"))?;
    transaction.commit().map_err(|_| {
        RecoveryTransitionJournalErrorV1::Unavailable("cannot commit transition schema")
    })
}

fn validate_schema_v1(connection: &Connection) -> Result<(), RecoveryTransitionJournalErrorV1> {
    let app_id: i64 = connection
        .pragma_query_value(None, "application_id", |row| row.get(0))
        .map_err(|_| {
            RecoveryTransitionJournalErrorV1::Tamper("cannot read transition application id")
        })?;
    let version: i64 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|_| {
            RecoveryTransitionJournalErrorV1::Tamper("cannot read transition schema version")
        })?;
    if app_id != JOURNAL_APP_ID_V1 || version != JOURNAL_USER_VERSION_V1 {
        return Err(RecoveryTransitionJournalErrorV1::Tamper(
            "transition journal application/schema differs",
        ));
    }
    Ok(())
}

fn read_u64_v1(bytes: &[u8], offset: &mut usize) -> Result<u64, RecoveryTransitionJournalErrorV1> {
    let end = offset
        .checked_add(8)
        .ok_or(RecoveryTransitionJournalErrorV1::Tamper(
            "record offset overflow",
        ))?;
    let value = bytes
        .get(*offset..end)
        .ok_or(RecoveryTransitionJournalErrorV1::Tamper(
            "record ended before u64",
        ))?;
    *offset = end;
    Ok(u64::from_be_bytes(
        value.try_into().expect("fixed u64 slice"),
    ))
}

fn read_array_v1<const N: usize>(
    bytes: &[u8],
    offset: &mut usize,
) -> Result<[u8; N], RecoveryTransitionJournalErrorV1> {
    let end = offset
        .checked_add(N)
        .ok_or(RecoveryTransitionJournalErrorV1::Tamper(
            "record offset overflow",
        ))?;
    let value = bytes
        .get(*offset..end)
        .ok_or(RecoveryTransitionJournalErrorV1::Tamper(
            "record ended before fixed field",
        ))?;
    *offset = end;
    Ok(value.try_into().expect("fixed array slice"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::tempdir;
    use trnm_consensus_types::{
        ChainId, ConsensusParametersHash, ConsensusPublicKey, GenesisHash, Height, ProtocolVersion,
        RecoveryContextV1, RecoveryContextV1Fields, RecoveryModeV1, Signature64, SignatureBytes,
        SigningRoot, Validator, VotingPower, SIGNATURE_BYTES,
    };

    #[derive(Debug, Clone, Copy)]
    struct BoundVerifier;

    impl SignatureVerifier for BoundVerifier {
        fn verify(
            &self,
            validator: &Validator,
            signing_root: &SigningRoot,
            signature: &SignatureBytes,
        ) -> bool {
            signature.as_bytes()[..32] == signing_root.as_bytes()[..]
                && signature.as_bytes()[32..] == validator.consensus_key().as_bytes()[..]
        }
    }

    fn validator_set() -> ValidatorSet {
        let validators = (1..=7)
            .map(|index| {
                let byte = u8::try_from(index).expect("validator index");
                Validator::new(
                    ValidatorId::new([byte; 32]),
                    ConsensusPublicKey::new([byte.wrapping_add(0x20); 32]),
                    VotingPower::new(1).expect("power"),
                )
                .expect("validator")
            })
            .collect();
        ValidatorSet::new(
            GenesisHash::new([0x11; 32]),
            ChainId::from_static("trnm-recovery-transition-test"),
            ProtocolVersion::V0,
            trnm_consensus_types::Epoch::new(4),
            ConsensusParametersHash::new([0x22; 32]),
            validators,
        )
        .expect("validator set")
    }

    fn recovery_context(set: &ValidatorSet) -> RecoveryContextV1 {
        RecoveryContextV1::new_direct7(
            RecoveryContextV1Fields {
                mode: RecoveryModeV1::ZeroDelta,
                campaign_context_sha256: [0x31; 32],
                fleet_start_certificate_sha256: [0x32; 32],
                validator_set_id: set.id(),
                validator_set_artifact_sha256: [0x33; 32],
                restart_cut_artifact_sha256: [0x34; 32],
                restart_park_artifact_sha256: [0x35; 32],
                restart_parked_ack_artifact_sha256: [0x36; 32],
                restart_parked_ack_admission_set_sha256: [0x37; 32],
                caught_up_cut_artifact_sha256: [0xA1; 32],
                target_validator: set.validators()[0].id(),
                process_instance: trnm_consensus_types::RECOVERY_PROCESS_INSTANCE_V1,
                recovery_nonce: [0x38; 32],
                restart_cut_epoch: set.epoch(),
                restart_cut_height: Height::new(50),
                restart_cut_block_id: trnm_consensus_types::BlockId::new([0x41; 32]),
                restart_cut_state_root: trnm_consensus_types::StateRoot::new([0x42; 32]),
                restart_cut_chain_root: [0x43; 32],
                terminal_epoch: set.epoch(),
                terminal_height: Height::new(50),
                terminal_block_id: trnm_consensus_types::BlockId::new([0x41; 32]),
                terminal_state_root: trnm_consensus_types::StateRoot::new([0x42; 32]),
                terminal_chain_root: [0x43; 32],
                node_facts_sha256: [0xA2; 32],
            },
            set,
        )
        .expect("recovery context")
    }

    fn signature_for(set: &ValidatorSet, origin: ValidatorId, root: SigningRoot) -> Signature64 {
        let validator = set.validator(origin).expect("origin");
        let mut bytes = [0_u8; SIGNATURE_BYTES];
        bytes[..32].copy_from_slice(root.as_bytes());
        bytes[32..].copy_from_slice(validator.consensus_key().as_bytes());
        Signature64::from_array(bytes)
    }

    fn authenticated_ready_set(set: &ValidatorSet) -> RecoveryReadySetV1 {
        let context = recovery_context(set);
        let statements = set
            .validators()
            .iter()
            .map(|validator| {
                let origin = validator.id();
                let root =
                    trnm_consensus_types::SignedRecoveryReadyV1::signing_root_for(&context, origin);
                trnm_consensus_types::SignedRecoveryReadyV1::from_signature(
                    context,
                    origin,
                    signature_for(set, origin, root),
                    set,
                    &BoundVerifier,
                )
                .expect("ready statement")
            })
            .collect();
        RecoveryReadySetV1::new(context, statements, set, &BoundVerifier).expect("ready set")
    }

    fn authenticated_start_certificate(
        set: &ValidatorSet,
        ready_set: RecoveryReadySetV1,
    ) -> RecoveryStartCertificateV1 {
        let statements = set
            .validators()
            .iter()
            .map(|validator| {
                let origin = validator.id();
                let root = trnm_consensus_types::SignedRecoveryStartV1::signing_root_for(
                    &ready_set, origin,
                );
                trnm_consensus_types::SignedRecoveryStartV1::from_signature(
                    &ready_set,
                    origin,
                    signature_for(set, origin, root),
                    set,
                    &BoundVerifier,
                )
                .expect("start statement")
            })
            .collect();
        RecoveryStartCertificateV1::new(ready_set, statements, set, &BoundVerifier)
            .expect("start certificate")
    }

    fn private_dir() -> tempfile::TempDir {
        let dir = tempdir().expect("tempdir");
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).expect("private dir");
        dir
    }

    fn checkpoint(seed: u8) -> ExternalNodeCheckpointV0 {
        // Tests exercise the journal's prerequisite binding, not Core's
        // checkpoint field derivation.  The canonical checkpoint constructor
        // is intentionally fed a non-zero, self-consistent shape here.
        let watermark = trnm_consensus_signer_journal::SignerWatermarkV0::from_persisted_parts(
            [seed; 32],
            [seed.wrapping_add(1); 32],
            2,
            [seed.wrapping_add(2); 32],
        )
        .expect("watermark");
        ExternalNodeCheckpointV0::new(crate::ExternalNodeCheckpointFieldsV0 {
            scope: [seed; 32],
            generation: 3,
            predecessor_checksum: [seed.wrapping_add(3); 32],
            safety_journal_id: [seed.wrapping_add(4); 32],
            safety_verifier_profile_ref: [seed.wrapping_add(5); 32],
            safety_revision: 3,
            safety_state_record_checksum: [seed.wrapping_add(6); 32],
            safety_record_chain_checksum: [seed.wrapping_add(7); 32],
            application_host_config_ref: [seed.wrapping_add(8); 32],
            application_projection_profile_ref: [seed.wrapping_add(9); 32],
            application_safety_binding_manifest_checksum: [seed.wrapping_add(10); 32],
            application_committed_head_row_checksum: [seed.wrapping_add(11); 32],
            application_recovery_closure_checksum: [seed.wrapping_add(12); 32],
            application_block_id: trnm_consensus_types::BlockId::new([seed.wrapping_add(13); 32]),
            application_height: 3,
            application_state_root: trnm_consensus_types::StateRoot::new(
                [seed.wrapping_add(14); 32],
            ),
            application_view: 2,
            application_timestamp_ms: 1,
            signer_journal_id: [seed.wrapping_add(1); 32],
            signer_profile_checksum: [seed.wrapping_add(16); 32],
            signer_exact_watermark: watermark,
        })
        .expect("checkpoint")
    }

    fn binding(seed: u8) -> Process2RecoveryTransitionBindingV1 {
        Process2RecoveryTransitionBindingV1::new(
            [seed; 32],
            [seed.wrapping_add(1); 32],
            [seed.wrapping_add(2); 32],
            ValidatorSetId::new([seed.wrapping_add(3); 32]),
            ValidatorId::new([seed.wrapping_add(4); 32]),
            Epoch::new(4),
            3,
            checkpoint(seed),
            [seed.wrapping_add(5); 32],
        )
        .expect("binding")
    }

    #[test]
    fn coordinator_verifies_authenticated_ready_start_and_replays_exactly() {
        let dir = private_dir();
        let path = dir.path().join("recovery.sqlite");
        let mut coordinator =
            Process2RecoveryReadyStartCoordinatorV1::initialize_new(&path).expect("coordinator");
        let set = validator_set();
        let ready_set = authenticated_ready_set(&set);
        let ready = coordinator
            .record_recovery_ready_v1(
                Process2RecoveryTransitionBindingV1::new(
                    [0x01; 32],
                    [0xA1; 32],
                    [0xA2; 32],
                    set.id(),
                    set.validators()[0].id(),
                    set.epoch(),
                    3,
                    checkpoint(1),
                    [0xA3; 32],
                )
                .expect("binding"),
                &ready_set,
                &set,
                &BoundVerifier,
            )
            .expect("authenticated ready");
        assert_eq!(
            ready.phase_v1(),
            Process2RecoveryTransitionPhaseV1::RecoveryReady
        );
        let certificate = authenticated_start_certificate(&set, ready_set.clone());
        let start = coordinator
            .record_recovery_start_v1(
                Process2RecoveryTransitionBindingV1::new(
                    [0x01; 32],
                    [0xA1; 32],
                    [0xA2; 32],
                    set.id(),
                    set.validators()[0].id(),
                    set.epoch(),
                    3,
                    checkpoint(1),
                    [0xA3; 32],
                )
                .expect("binding"),
                &certificate,
                &set,
                &BoundVerifier,
            )
            .expect("authenticated start");
        assert_eq!(
            start.phase_v1(),
            Process2RecoveryTransitionPhaseV1::RecoveryStart
        );
        assert_eq!(coordinator.head_v1().expect("head"), Some(start));
    }

    #[test]
    fn journal_persists_ready_then_start_and_reopens_exactly() {
        let dir = private_dir();
        let path = dir.path().join("recovery.sqlite");
        let journal = Process2RecoveryTransitionJournalV1::initialize_new(&path).expect("init");
        let ready = journal
            .append_ready_v1(binding(1), [0x61; 32])
            .expect("ready");
        assert_eq!(
            ready.phase_v1(),
            Process2RecoveryTransitionPhaseV1::RecoveryReady
        );
        let start = journal
            .append_start_v1(binding(1), [0x61; 32], [0x62; 32])
            .expect("start");
        assert_eq!(start.sequence_v1(), 1);
        drop(journal);
        let reopened = Process2RecoveryTransitionJournalV1::open_existing(&path).expect("reopen");
        assert_eq!(reopened.head_v1().expect("head"), Some(start));
    }

    #[test]
    fn journal_rejects_wrong_order_stale_and_third_certificate() {
        let dir = private_dir();
        let path = dir.path().join("recovery.sqlite");
        let journal = Process2RecoveryTransitionJournalV1::initialize_new(&path).expect("init");
        let error = journal
            .append_start_v1(binding(1), [0x61; 32], [0x62; 32])
            .expect_err("start before ready");
        assert!(matches!(
            error,
            RecoveryTransitionJournalErrorV1::WrongOrder(_)
        ));
        journal
            .append_ready_v1(binding(1), [0x61; 32])
            .expect("ready");
        let stale = journal
            .append_start_v1(binding(2), [0x61; 32], [0x62; 32])
            .expect_err("foreign start");
        assert!(matches!(stale, RecoveryTransitionJournalErrorV1::Stale(_)));
        let start = journal
            .append_start_v1(binding(1), [0x61; 32], [0x62; 32])
            .expect("start");
        let retry = journal
            .append_start_v1(binding(1), [0x61; 32], [0x62; 32])
            .expect("exact retry");
        assert_eq!(retry, start);
        let third = journal
            .append_start_v1(binding(1), [0x61; 32], [0x63; 32])
            .expect_err("different certificate");
        assert!(matches!(
            third,
            RecoveryTransitionJournalErrorV1::Conflict(_)
        ));
    }

    #[test]
    fn journal_detects_record_tamper_on_reopen() {
        let dir = private_dir();
        let path = dir.path().join("recovery.sqlite");
        let journal = Process2RecoveryTransitionJournalV1::initialize_new(&path).expect("init");
        journal
            .append_ready_v1(binding(1), [0x61; 32])
            .expect("ready");
        drop(journal);
        let connection = Connection::open(&path).expect("open for tamper");
        connection
            .execute(
                "UPDATE process2_recovery_transition_events_v1 SET record = ?1 WHERE sequence = 0",
                params![vec![0xA5_u8; JOURNAL_RECORD_BYTES_V1]],
            )
            .expect("tamper row");
        let error = Process2RecoveryTransitionJournalV1::open_existing(&path)
            .expect_err("tamper must fail closed");
        assert!(matches!(error, RecoveryTransitionJournalErrorV1::Tamper(_)));
    }
}
