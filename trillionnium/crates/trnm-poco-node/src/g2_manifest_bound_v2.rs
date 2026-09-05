//! Node-private durable sink for one exact manifest-bound candidate-local join.
//!
//! The only authority-bearing ingress consumes
//! [`G2CandidateLocalFinalizeJoinV2`]. The SQLite journal stores canonical data
//! only: decoding a record, reopening the journal, or reconstructing an
//! external pin cannot recreate the non-Clone owner. After process loss the
//! caller must reproduce the exact typed join; its canonical snapshot must be
//! byte-identical to the durable target before the owner can exist again.
//!
//! This is an inert candidate-local persistence boundary. It does not write a
//! source plane or global store and has no finality, voting, signing, Core,
//! network, or production authority. Path/hash rechecks around separate SQLite
//! opens narrow replacement exposure but are not descriptor-bound `openat`
//! identity and do not close a malicious same-UID rename race.

use std::{
    error::Error,
    ffi::OsString,
    fmt,
    fs::{self, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    time::Duration,
};

#[cfg(unix)]
use std::{
    fs::{File, Metadata},
    io::Read,
};

use borsh::{object_length, to_writer, BorshSerialize};
use rusqlite::{params, Connection, OpenFlags, TransactionBehavior};
use sha2::{Digest, Sha256};
use trnm_poco_global_execution_v1::G2CandidateLocalFinalizeJoinV2;

const JOURNAL_SCHEMA_V2: u16 = 1;
const SNAPSHOT_MAGIC_V2: [u8; 8] = *b"TRNMG2J2";
const RECORD_MAGIC_V2: [u8; 8] = *b"TRNMG2D1";
const JOURNAL_FILE_NAME_V2: &str = "g2-manifest-bound-v2.sqlite";
const SQLITE_APPLICATION_ID_V2: i64 = 0x5452_4d32;
const SQLITE_USER_VERSION_V2: i64 = 1;
const MAX_PLANE_ROOTS_BYTES_V2: usize = 4 * 1024;
const MAX_RECEIPTS_V2: usize = 4 * 256;
const MAX_JOIN_SNAPSHOT_BYTES_V2: usize = 64 * 1024 * 1024 - 4096;
const MAX_JOURNAL_RECORD_BYTES_V2: usize = 64 * 1024 * 1024;
const MAX_JOURNAL_DATABASE_BYTES_V2: u64 = 256 * 1024 * 1024;
// Snapshot bytes excluding the variable Borsh plane-root and receipt bodies:
// magic/schema, request identity, eight roots, two request digests, two byte
// lengths, receipt count, and the preview/join digests.
const SNAPSHOT_FIXED_OVERHEAD_BYTES_V2: usize =
    8 + 2 + 32 + 8 + 32 + (8 * 32) + 32 + 32 + 4 + 4 + 4 + 32 + 32;
const SNAPSHOT_DOMAIN_V2: &str = "trnm.poco-ai.node-g2-manifest-bound-join-snapshot.v2";
const RECORD_DOMAIN_V2: &str = "trnm.poco-ai.node-g2-manifest-bound-journal-record.v2";
const META_SQL_V2: &str = concat!(
    "CREATE TABLE g2_manifest_bound_metadata_v2 (",
    "singleton INTEGER PRIMARY KEY CHECK(singleton=1),",
    "journal_id BLOB NOT NULL CHECK(typeof(journal_id)='blob' AND length(journal_id)=32),",
    "scope BLOB NOT NULL CHECK(typeof(scope)='blob' AND length(scope)=32),",
    "head_generation BLOB NOT NULL CHECK(typeof(head_generation)='blob' AND length(head_generation)=8),",
    "head_phase INTEGER NOT NULL CHECK(head_phase IN(0,1)),",
    "head_checksum BLOB NOT NULL CHECK(typeof(head_checksum)='blob' AND length(head_checksum)=32),",
    "fenced INTEGER NOT NULL CHECK(fenced IN(0,1))",
    ") STRICT"
);
const HISTORY_SQL_V2: &str = concat!(
    "CREATE TABLE g2_manifest_bound_history_v2 (",
    "generation BLOB PRIMARY KEY CHECK(typeof(generation)='blob' AND length(generation)=8),",
    "phase INTEGER NOT NULL CHECK(phase IN(0,1)),",
    "predecessor_checksum BLOB NOT NULL CHECK(typeof(predecessor_checksum)='blob' AND length(predecessor_checksum)=32),",
    "join_commitment BLOB CHECK((phase=0 AND join_commitment IS NULL) OR (phase=1 AND typeof(join_commitment)='blob' AND length(join_commitment)=32)),",
    "checksum BLOB NOT NULL UNIQUE CHECK(typeof(checksum)='blob' AND length(checksum)=32),",
    "record BLOB NOT NULL CHECK(typeof(record)='blob' AND length(record)>0 AND length(record)<=67108864)",
    ") STRICT, WITHOUT ROWID"
);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PocoNodeG2ManifestBoundErrorCodeV2 {
    InvalidNamespace,
    JournalUnavailable,
    JournalSchemaMismatch,
    JournalTamper,
    JournalRollback,
    JournalFork,
    CompareNotApplied,
    ThirdJournalState,
    ExactJoinMismatch,
    SnapshotTooLarge,
}

#[derive(Debug)]
pub(crate) struct PocoNodeG2ManifestBoundErrorV2 {
    code: PocoNodeG2ManifestBoundErrorCodeV2,
    detail: String,
}

impl PocoNodeG2ManifestBoundErrorV2 {
    pub(crate) const fn code_v2(&self) -> PocoNodeG2ManifestBoundErrorCodeV2 {
        self.code
    }
}

impl fmt::Display for PocoNodeG2ManifestBoundErrorV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "G2 manifest-bound candidate journal rejected: {}",
            self.detail
        )
    }
}

impl Error for PocoNodeG2ManifestBoundErrorV2 {}

type ResultV2<T> = Result<T, PocoNodeG2ManifestBoundErrorV2>;

fn reject<T>(code: PocoNodeG2ManifestBoundErrorCodeV2, detail: impl Into<String>) -> ResultV2<T> {
    Err(PocoNodeG2ManifestBoundErrorV2 {
        code,
        detail: detail.into(),
    })
}

fn require(
    condition: bool,
    code: PocoNodeG2ManifestBoundErrorCodeV2,
    detail: impl Into<String>,
) -> ResultV2<()> {
    if condition {
        Ok(())
    } else {
        reject(code, detail)
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub(crate) enum PocoNodeG2ManifestBoundJournalPhaseV2 {
    Anchor = 0,
    Persisted = 1,
}

impl PocoNodeG2ManifestBoundJournalPhaseV2 {
    const fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Anchor),
            1 => Some(Self::Persisted),
            _ => None,
        }
    }
}

/// Cloneable rollback-detection data. It selects a complete journal audit but
/// cannot recreate the exact join or the owner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PocoNodeG2ManifestBoundJournalPinV2 {
    journal_id: [u8; 32],
    scope: [u8; 32],
    generation: u64,
    phase: PocoNodeG2ManifestBoundJournalPhaseV2,
    checksum: [u8; 32],
}

impl PocoNodeG2ManifestBoundJournalPinV2 {
    /// Reconstitute pin data that a future external process owner must
    /// authenticate. This function performs no process-owner authentication;
    /// the result is data only and is never an owner issuer.
    pub(crate) fn from_external_trusted_parts_v2(
        journal_id: [u8; 32],
        scope: [u8; 32],
        generation: u64,
        phase: PocoNodeG2ManifestBoundJournalPhaseV2,
        checksum: [u8; 32],
    ) -> ResultV2<Self> {
        let pin = Self {
            journal_id,
            scope,
            generation,
            phase,
            checksum,
        };
        pin.validate_v2()?;
        Ok(pin)
    }

    pub(crate) const fn journal_id_v2(&self) -> [u8; 32] {
        self.journal_id
    }

    pub(crate) const fn scope_v2(&self) -> [u8; 32] {
        self.scope
    }

    pub(crate) const fn generation_v2(&self) -> u64 {
        self.generation
    }

    pub(crate) const fn phase_v2(&self) -> PocoNodeG2ManifestBoundJournalPhaseV2 {
        self.phase
    }

    pub(crate) const fn checksum_v2(&self) -> [u8; 32] {
        self.checksum
    }

    fn validate_v2(&self) -> ResultV2<()> {
        require(
            self.journal_id != [0; 32]
                && self.scope != [0; 32]
                && self.checksum != [0; 32]
                && self.generation == u64::from(self.phase as u8),
            PocoNodeG2ManifestBoundErrorCodeV2::JournalTamper,
            "external journal pin is zero or phase-inconsistent",
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CanonicalJoinSnapshotV2 {
    raw: Vec<u8>,
    commitment: [u8; 32],
}

fn checked_receipt_count_v2(count: usize) -> ResultV2<u32> {
    require(
        count > 0 && count <= MAX_RECEIPTS_V2,
        PocoNodeG2ManifestBoundErrorCodeV2::SnapshotTooLarge,
        "typed join receipt inventory is empty or exceeds the Node count bound",
    )?;
    u32::try_from(count).map_err(|_| PocoNodeG2ManifestBoundErrorV2 {
        code: PocoNodeG2ManifestBoundErrorCodeV2::SnapshotTooLarge,
        detail: "receipt count exceeds u32".to_owned(),
    })
}

struct HardLimitedBorshWriterV2 {
    bytes: Vec<u8>,
    maximum: usize,
}

impl HardLimitedBorshWriterV2 {
    fn with_exact_capacity_v2(capacity: usize, maximum: usize) -> ResultV2<Self> {
        require(
            capacity <= maximum,
            PocoNodeG2ManifestBoundErrorCodeV2::SnapshotTooLarge,
            "bounded Borsh capacity exceeds its hard maximum",
        )?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(capacity)
            .map_err(|cause| unavailable(format!("cannot reserve bounded Borsh bytes: {cause}")))?;
        Ok(Self { bytes, maximum })
    }

    fn finish_exact_v2(self, expected_length: usize, label: &str) -> ResultV2<Vec<u8>> {
        require(
            self.bytes.len() == expected_length,
            PocoNodeG2ManifestBoundErrorCodeV2::JournalTamper,
            format!("{label} Borsh length changed between counting and encoding"),
        )?;
        Ok(self.bytes)
    }
}

impl Write for HardLimitedBorshWriterV2 {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let next = self
            .bytes
            .len()
            .checked_add(bytes.len())
            .ok_or_else(|| io::Error::from(io::ErrorKind::OutOfMemory))?;
        if next > self.maximum {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Borsh encoding exceeds the hard snapshot field bound",
            ));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn encode_borsh_bounded_v2<T: BorshSerialize + ?Sized>(
    value: &T,
    maximum: usize,
    label: &str,
) -> ResultV2<Vec<u8>> {
    // object_length uses Borsh's allocation-free counting writer. The count
    // gate is deliberately before both reservation and the real serializer.
    let encoded_length = object_length(value).map_err(|cause| PocoNodeG2ManifestBoundErrorV2 {
        code: PocoNodeG2ManifestBoundErrorCodeV2::SnapshotTooLarge,
        detail: format!("cannot count bounded {label} Borsh bytes: {cause}"),
    })?;
    require(
        encoded_length > 0 && encoded_length <= maximum,
        PocoNodeG2ManifestBoundErrorCodeV2::SnapshotTooLarge,
        format!("{label} Borsh bytes exceed the hard snapshot field bound"),
    )?;
    let mut writer = HardLimitedBorshWriterV2::with_exact_capacity_v2(encoded_length, maximum)?;
    to_writer(&mut writer, value).map_err(|cause| PocoNodeG2ManifestBoundErrorV2 {
        code: PocoNodeG2ManifestBoundErrorCodeV2::SnapshotTooLarge,
        detail: format!("cannot encode bounded {label} Borsh bytes: {cause}"),
    })?;
    writer.finish_exact_v2(encoded_length, label)
}

impl CanonicalJoinSnapshotV2 {
    fn from_exact_join_v2(exact_join: &G2CandidateLocalFinalizeJoinV2) -> ResultV2<Self> {
        // Count is checked before walking or reserving the potentially large
        // nested receipt bodies.
        let receipt_count = checked_receipt_count_v2(exact_join.receipts().len())?;
        let plane_roots = encode_borsh_bounded_v2(
            exact_join.plane_roots(),
            MAX_PLANE_ROOTS_BYTES_V2,
            "exact plane roots",
        )?;
        require(
            !plane_roots.is_empty() && plane_roots.len() <= MAX_PLANE_ROOTS_BYTES_V2,
            PocoNodeG2ManifestBoundErrorCodeV2::SnapshotTooLarge,
            "typed join plane-root inventory exceeds the Node bound",
        )?;
        let receipts_maximum = MAX_JOIN_SNAPSHOT_BYTES_V2
            .checked_sub(SNAPSHOT_FIXED_OVERHEAD_BYTES_V2)
            .and_then(|remaining| remaining.checked_sub(plane_roots.len()))
            .ok_or_else(|| PocoNodeG2ManifestBoundErrorV2 {
                code: PocoNodeG2ManifestBoundErrorCodeV2::SnapshotTooLarge,
                detail: "fixed snapshot fields exhaust the 64 MiB record budget".to_owned(),
            })?;
        let receipts =
            encode_borsh_bounded_v2(exact_join.receipts(), receipts_maximum, "exact receipts")?;

        let snapshot_length = SNAPSHOT_FIXED_OVERHEAD_BYTES_V2
            .checked_add(plane_roots.len())
            .and_then(|length| length.checked_add(receipts.len()))
            .ok_or_else(|| PocoNodeG2ManifestBoundErrorV2 {
                code: PocoNodeG2ManifestBoundErrorCodeV2::SnapshotTooLarge,
                detail: "join snapshot length overflows".to_owned(),
            })?;
        require(
            snapshot_length <= MAX_JOIN_SNAPSHOT_BYTES_V2,
            PocoNodeG2ManifestBoundErrorCodeV2::SnapshotTooLarge,
            "join snapshot exceeds its 64 MiB record budget",
        )?;
        let mut raw = Vec::new();
        raw.try_reserve_exact(snapshot_length)
            .map_err(|cause| unavailable(format!("cannot reserve exact join snapshot: {cause}")))?;
        raw.extend_from_slice(&SNAPSHOT_MAGIC_V2);
        raw.extend_from_slice(&JOURNAL_SCHEMA_V2.to_le_bytes());
        raw.extend_from_slice(exact_join.input_id().as_bytes());
        raw.extend_from_slice(&exact_join.candidate_height().to_le_bytes());
        raw.extend_from_slice(exact_join.candidate_block_id().as_bytes());
        for root in exact_join.ordered_roots() {
            raw.extend_from_slice(&root);
        }
        raw.extend_from_slice(exact_join.plan_digest().as_bytes());
        raw.extend_from_slice(&exact_join.binding_digest());
        put_bytes_v2(&mut raw, &plane_roots)?;
        raw.extend_from_slice(&receipt_count.to_le_bytes());
        put_bytes_v2(&mut raw, &receipts)?;
        raw.extend_from_slice(&exact_join.preview_digest().0);
        raw.extend_from_slice(&exact_join.join_digest().0);
        require(
            raw.len() == snapshot_length,
            PocoNodeG2ManifestBoundErrorCodeV2::JournalTamper,
            "join snapshot fixed-overhead calculation differs",
        )?;
        Self::from_raw_v2(raw)
    }

    fn from_raw_v2(raw: Vec<u8>) -> ResultV2<Self> {
        validate_snapshot_structure_v2(&raw)?;
        let commitment = digest_v2(SNAPSHOT_DOMAIN_V2, &raw);
        Ok(Self { raw, commitment })
    }

    fn validate_v2(&self) -> ResultV2<()> {
        validate_snapshot_structure_v2(&self.raw)?;
        require(
            self.commitment == digest_v2(SNAPSHOT_DOMAIN_V2, &self.raw),
            PocoNodeG2ManifestBoundErrorCodeV2::JournalTamper,
            "join snapshot commitment differs",
        )
    }
}

fn validate_snapshot_structure_v2(raw: &[u8]) -> ResultV2<()> {
    require(
        raw.len() <= MAX_JOIN_SNAPSHOT_BYTES_V2
            && raw.len() >= SNAPSHOT_FIXED_OVERHEAD_BYTES_V2 + 490 + 4,
        PocoNodeG2ManifestBoundErrorCodeV2::SnapshotTooLarge,
        "join snapshot length is outside the exact Node bound",
    )?;
    let mut cursor = CursorV2::new(raw);
    require(
        cursor.array::<8>()? == SNAPSHOT_MAGIC_V2 && cursor.u16()? == JOURNAL_SCHEMA_V2,
        PocoNodeG2ManifestBoundErrorCodeV2::JournalTamper,
        "join snapshot magic or schema differs",
    )?;
    let input_id = cursor.array::<32>()?;
    let candidate_height = cursor.u64()?;
    let candidate_block_id = cursor.array::<32>()?;
    let mut ordered_roots = [[0_u8; 32]; 8];
    for root in &mut ordered_roots {
        *root = cursor.array()?;
    }
    let plan_digest = cursor.array::<32>()?;
    let binding_digest = cursor.array::<32>()?;
    let plane_roots = cursor.length_prefixed(MAX_PLANE_ROOTS_BYTES_V2)?;
    let receipt_count =
        usize::try_from(cursor.u32()?).map_err(|_| PocoNodeG2ManifestBoundErrorV2 {
            code: PocoNodeG2ManifestBoundErrorCodeV2::SnapshotTooLarge,
            detail: "join receipt count does not fit usize".to_owned(),
        })?;
    let receipts = cursor.length_prefixed(MAX_JOIN_SNAPSHOT_BYTES_V2)?;
    let preview_digest = cursor.array::<32>()?;
    let join_digest = cursor.array::<32>()?;
    require(
        cursor.remaining() == 0,
        PocoNodeG2ManifestBoundErrorCodeV2::JournalTamper,
        "join snapshot contains trailing bytes",
    )?;
    require(
        input_id != [0; 32]
            && candidate_height > 0
            && candidate_block_id != [0; 32]
            && ordered_roots.iter().all(|root| *root != [0; 32])
            && plan_digest != [0; 32]
            && binding_digest != [0; 32]
            && preview_digest != [0; 32]
            && join_digest != [0; 32]
            && receipt_count > 0
            && receipt_count <= MAX_RECEIPTS_V2,
        PocoNodeG2ManifestBoundErrorCodeV2::JournalTamper,
        "join snapshot contains a zero or out-of-bound identity",
    )?;
    // Plane roots are a fixed Borsh struct: schema, candidate-local ID,
    // candidate height, and fourteen hashes. Treat the receipt body bytes as
    // opaque here; only a fresh typed join can authenticate their canonical
    // nested Borsh encoding without allocating from attacker-controlled sizes.
    require(
        plane_roots.len() == 490
            && plane_roots[..2] == 2_u16.to_le_bytes()
            && plane_roots[2..34] != [0_u8; 32]
            && plane_roots[34..42] == candidate_height.to_le_bytes()
            && plane_roots[42..]
                .chunks_exact(32)
                .all(|digest| digest != [0_u8; 32]),
        PocoNodeG2ManifestBoundErrorCodeV2::JournalTamper,
        "join plane-root encoding differs from the fixed v2 shape",
    )?;
    require(
        receipts.len() >= 4 && receipts[..4] == u32::try_from(receipt_count).unwrap().to_le_bytes(),
        PocoNodeG2ManifestBoundErrorCodeV2::JournalTamper,
        "join receipt count differs from its bounded Borsh inventory",
    )
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct JournalRecordV2 {
    journal_id: [u8; 32],
    scope: [u8; 32],
    generation: u64,
    phase: PocoNodeG2ManifestBoundJournalPhaseV2,
    predecessor_checksum: [u8; 32],
    snapshot: Option<CanonicalJoinSnapshotV2>,
    checksum: [u8; 32],
}

impl JournalRecordV2 {
    fn anchor_v2(journal_id: [u8; 32], scope: [u8; 32]) -> ResultV2<Self> {
        let mut record = Self {
            journal_id,
            scope,
            generation: 0,
            phase: PocoNodeG2ManifestBoundJournalPhaseV2::Anchor,
            predecessor_checksum: [0; 32],
            snapshot: None,
            checksum: [0; 32],
        };
        record.reseal_v2()?;
        record.validate_v2()?;
        Ok(record)
    }

    fn persisted_successor_v2(&self, snapshot: CanonicalJoinSnapshotV2) -> ResultV2<Self> {
        self.validate_v2()?;
        require(
            self.phase == PocoNodeG2ManifestBoundJournalPhaseV2::Anchor,
            PocoNodeG2ManifestBoundErrorCodeV2::JournalFork,
            "persisted join requires the exact anchor predecessor",
        )?;
        let mut target = Self {
            journal_id: self.journal_id,
            scope: self.scope,
            generation: 1,
            phase: PocoNodeG2ManifestBoundJournalPhaseV2::Persisted,
            predecessor_checksum: self.checksum,
            snapshot: Some(snapshot),
            checksum: [0; 32],
        };
        target.reseal_v2()?;
        self.validate_successor_v2(&target)?;
        Ok(target)
    }

    fn pin_v2(&self) -> PocoNodeG2ManifestBoundJournalPinV2 {
        PocoNodeG2ManifestBoundJournalPinV2 {
            journal_id: self.journal_id,
            scope: self.scope,
            generation: self.generation,
            phase: self.phase,
            checksum: self.checksum,
        }
    }

    fn join_commitment_v2(&self) -> Option<[u8; 32]> {
        self.snapshot.as_ref().map(|value| value.commitment)
    }

    fn reseal_v2(&mut self) -> ResultV2<()> {
        self.checksum = digest_v2(RECORD_DOMAIN_V2, &self.encode_prefix_v2()?);
        Ok(())
    }

    fn validate_v2(&self) -> ResultV2<()> {
        require(
            self.journal_id != [0; 32]
                && self.scope != [0; 32]
                && self.generation == u64::from(self.phase as u8),
            PocoNodeG2ManifestBoundErrorCodeV2::JournalTamper,
            "journal record identity or phase differs",
        )?;
        match self.phase {
            PocoNodeG2ManifestBoundJournalPhaseV2::Anchor => require(
                self.predecessor_checksum == [0; 32] && self.snapshot.is_none(),
                PocoNodeG2ManifestBoundErrorCodeV2::JournalTamper,
                "anchor record contains successor facts",
            )?,
            PocoNodeG2ManifestBoundJournalPhaseV2::Persisted => {
                require(
                    self.predecessor_checksum != [0; 32] && self.snapshot.is_some(),
                    PocoNodeG2ManifestBoundErrorCodeV2::JournalTamper,
                    "persisted record lacks its predecessor or exact join snapshot",
                )?;
                self.snapshot
                    .as_ref()
                    .expect("checked snapshot")
                    .validate_v2()?;
            }
        }
        require(
            self.checksum == digest_v2(RECORD_DOMAIN_V2, &self.encode_prefix_v2()?),
            PocoNodeG2ManifestBoundErrorCodeV2::JournalTamper,
            "journal record checksum differs",
        )
    }

    fn validate_successor_v2(&self, target: &Self) -> ResultV2<()> {
        self.validate_v2()?;
        target.validate_v2()?;
        require(
            self.phase == PocoNodeG2ManifestBoundJournalPhaseV2::Anchor
                && target.phase == PocoNodeG2ManifestBoundJournalPhaseV2::Persisted
                && self.generation.checked_add(1) == Some(target.generation)
                && target.predecessor_checksum == self.checksum
                && target.journal_id == self.journal_id
                && target.scope == self.scope,
            PocoNodeG2ManifestBoundErrorCodeV2::JournalFork,
            "journal target is not the exact immutable successor",
        )
    }

    fn encode_prefix_v2(&self) -> ResultV2<Vec<u8>> {
        let snapshot_size = self.snapshot.as_ref().map_or(0, |value| value.raw.len());
        let mut out = Vec::with_capacity(124_usize.saturating_add(snapshot_size));
        out.extend_from_slice(&RECORD_MAGIC_V2);
        out.extend_from_slice(&JOURNAL_SCHEMA_V2.to_le_bytes());
        out.extend_from_slice(&self.journal_id);
        out.extend_from_slice(&self.scope);
        out.extend_from_slice(&self.generation.to_le_bytes());
        out.push(self.phase as u8);
        out.extend_from_slice(&self.predecessor_checksum);
        match &self.snapshot {
            None => out.push(0),
            Some(snapshot) => {
                out.push(1);
                put_bytes_v2(&mut out, &snapshot.raw)?;
                out.extend_from_slice(&snapshot.commitment);
            }
        }
        require(
            out.len().saturating_add(32) <= MAX_JOURNAL_RECORD_BYTES_V2,
            PocoNodeG2ManifestBoundErrorCodeV2::SnapshotTooLarge,
            "journal record exceeds its exact byte bound",
        )?;
        Ok(out)
    }

    fn encode_v2(&self) -> ResultV2<Vec<u8>> {
        let mut out = self.encode_prefix_v2()?;
        out.extend_from_slice(&self.checksum);
        Ok(out)
    }

    fn decode_exact_v2(raw: &[u8]) -> ResultV2<Self> {
        require(
            raw.len() >= 116 && raw.len() <= MAX_JOURNAL_RECORD_BYTES_V2,
            PocoNodeG2ManifestBoundErrorCodeV2::JournalTamper,
            "journal record length differs",
        )?;
        let mut cursor = CursorV2::new(raw);
        require(
            cursor.array::<8>()? == RECORD_MAGIC_V2 && cursor.u16()? == JOURNAL_SCHEMA_V2,
            PocoNodeG2ManifestBoundErrorCodeV2::JournalTamper,
            "journal record magic or schema differs",
        )?;
        let journal_id = cursor.array()?;
        let scope = cursor.array()?;
        let generation = cursor.u64()?;
        let phase =
            PocoNodeG2ManifestBoundJournalPhaseV2::from_u8(cursor.u8()?).ok_or_else(|| {
                PocoNodeG2ManifestBoundErrorV2 {
                    code: PocoNodeG2ManifestBoundErrorCodeV2::JournalTamper,
                    detail: "journal phase is unsupported".to_owned(),
                }
            })?;
        let predecessor_checksum = cursor.array()?;
        let snapshot = match cursor.u8()? {
            0 => None,
            1 => {
                let bytes = cursor.length_prefixed(MAX_JOIN_SNAPSHOT_BYTES_V2)?.to_vec();
                let commitment = cursor.array()?;
                let value = CanonicalJoinSnapshotV2 {
                    raw: bytes,
                    commitment,
                };
                value.validate_v2()?;
                Some(value)
            }
            _ => {
                return reject(
                    PocoNodeG2ManifestBoundErrorCodeV2::JournalTamper,
                    "journal snapshot option tag differs",
                )
            }
        };
        let checksum = cursor.array()?;
        require(
            cursor.remaining() == 0,
            PocoNodeG2ManifestBoundErrorCodeV2::JournalTamper,
            "journal record contains trailing bytes",
        )?;
        let record = Self {
            journal_id,
            scope,
            generation,
            phase,
            predecessor_checksum,
            snapshot,
            checksum,
        };
        require(
            record.encode_v2()? == raw,
            PocoNodeG2ManifestBoundErrorCodeV2::JournalTamper,
            "journal record does not round-trip exactly",
        )?;
        record.validate_v2()?;
        Ok(record)
    }
}

/// One canonical private directory owned by the future process commissioner.
#[derive(Clone, Debug)]
pub(crate) struct PocoNodeG2ManifestBoundJournalNamespaceV2 {
    directory: PathBuf,
}

impl PocoNodeG2ManifestBoundJournalNamespaceV2 {
    pub(crate) fn new_v2(directory: impl Into<PathBuf>) -> ResultV2<Self> {
        Ok(Self {
            directory: canonical_private_directory_v2(&directory.into())?,
        })
    }

    pub(crate) fn journal_path_v2(&self) -> PathBuf {
        self.directory.join(JOURNAL_FILE_NAME_V2)
    }

    fn revalidate_v2(&self) -> ResultV2<()> {
        require(
            canonical_private_directory_v2(&self.directory)? == self.directory,
            PocoNodeG2ManifestBoundErrorCodeV2::InvalidNamespace,
            "journal namespace identity changed",
        )
    }
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct JournalFileStatV2 {
    device: u64,
    inode: u64,
    owner: u32,
    links: u64,
    mode: u32,
    size: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct JournalFileIdentityV2 {
    stat: JournalFileStatV2,
    content_sha256: [u8; 32],
}

#[derive(Debug)]
struct SqliteG2ManifestBoundJournalV2 {
    path: PathBuf,
    journal_id: [u8; 32],
    scope: [u8; 32],
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum JournalFaultV2 {
    BeforeCommit,
    AfterCommitBeforeReturn,
}

impl SqliteG2ManifestBoundJournalV2 {
    fn initialize_new_v2(
        namespace: &PocoNodeG2ManifestBoundJournalNamespaceV2,
        journal_id: [u8; 32],
        scope: [u8; 32],
    ) -> ResultV2<(Self, JournalRecordV2)> {
        namespace.revalidate_v2()?;
        let anchor = JournalRecordV2::anchor_v2(journal_id, scope)?;
        let path = namespace.journal_path_v2();
        validate_journal_path_v2(&path, false)?;
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|cause| unavailable(format!("cannot create journal: {cause}")))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
                .map_err(|cause| unavailable(format!("cannot set journal permissions: {cause}")))?;
        }
        drop(file);
        let mut connection = open_rw_raw_v2(&path)?;
        configure_rw_v2(&connection)?;
        connection
            .pragma_update(None, "application_id", SQLITE_APPLICATION_ID_V2)
            .map_err(sqlite_unavailable_v2)?;
        connection
            .pragma_update(None, "user_version", SQLITE_USER_VERSION_V2)
            .map_err(sqlite_unavailable_v2)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_unavailable_v2)?;
        transaction
            .execute_batch(META_SQL_V2)
            .map_err(sqlite_unavailable_v2)?;
        transaction
            .execute_batch(HISTORY_SQL_V2)
            .map_err(sqlite_unavailable_v2)?;
        transaction
            .execute(
                "INSERT INTO g2_manifest_bound_history_v2(generation,phase,predecessor_checksum,join_commitment,checksum,record) VALUES(?1,0,?2,NULL,?3,?4)",
                params![
                    &anchor.generation.to_be_bytes()[..],
                    &anchor.predecessor_checksum[..],
                    &anchor.checksum[..],
                    anchor.encode_v2()?,
                ],
            )
            .map_err(sqlite_unavailable_v2)?;
        transaction
            .execute(
                "INSERT INTO g2_manifest_bound_metadata_v2(singleton,journal_id,scope,head_generation,head_phase,head_checksum,fenced) VALUES(1,?1,?2,?3,0,?4,0)",
                params![
                    &anchor.journal_id[..],
                    &anchor.scope[..],
                    &anchor.generation.to_be_bytes()[..],
                    &anchor.checksum[..],
                ],
            )
            .map_err(sqlite_unavailable_v2)?;
        transaction.commit().map_err(sqlite_unavailable_v2)?;
        drop(connection);
        #[cfg(unix)]
        File::open(&namespace.directory)
            .and_then(|directory| directory.sync_all())
            .map_err(|cause| unavailable(format!("cannot fsync journal namespace: {cause}")))?;
        reject_sidecars_v2(&path)?;
        let journal = Self {
            path,
            journal_id,
            scope,
        };
        let records = journal.audit_fresh_v2()?;
        require(
            records.as_slice() == [anchor.clone()],
            PocoNodeG2ManifestBoundErrorCodeV2::JournalTamper,
            "fresh anchor readback differs",
        )?;
        Ok((journal, anchor))
    }

    fn open_existing_v2(
        namespace: &PocoNodeG2ManifestBoundJournalNamespaceV2,
        trusted_pin: &PocoNodeG2ManifestBoundJournalPinV2,
    ) -> ResultV2<Self> {
        namespace.revalidate_v2()?;
        trusted_pin.validate_v2()?;
        let path = namespace.journal_path_v2();
        validate_journal_path_v2(&path, true)?;
        let journal = Self {
            path,
            journal_id: trusted_pin.journal_id,
            scope: trusted_pin.scope,
        };
        let records = journal.audit_fresh_v2()?;
        require_trusted_prefix_v2(&records, trusted_pin)?;
        Ok(journal)
    }

    fn advance_v2(
        &self,
        expected: &JournalRecordV2,
        target: &JournalRecordV2,
    ) -> ResultV2<JournalRecordV2> {
        self.advance_inner_v2(expected, target, None)
    }

    #[cfg(test)]
    fn advance_with_fault_v2(
        &self,
        expected: &JournalRecordV2,
        target: &JournalRecordV2,
        fault: JournalFaultV2,
    ) -> ResultV2<JournalRecordV2> {
        self.advance_inner_v2(expected, target, Some(fault))
    }

    fn advance_inner_v2(
        &self,
        expected: &JournalRecordV2,
        target: &JournalRecordV2,
        #[cfg_attr(not(test), allow(unused_variables))] fault: Option<JournalFaultV2>,
    ) -> ResultV2<JournalRecordV2> {
        expected.validate_successor_v2(target)?;
        let (read_only, identity) = open_existing_ro_preflight_v2(&self.path)?;
        let preflight = audit_connection_v2(&read_only, self.journal_id, self.scope)?;
        drop(read_only);
        require_journal_file_identity_v2(&self.path, identity)?;
        let preflight_head = preflight.last().expect("audited history is nonempty");
        if preflight_head == target {
            return self.require_fresh_target_v2(target);
        }
        if preflight_head != expected {
            let _ = self.fence_v2();
            return reject(
                PocoNodeG2ManifestBoundErrorCodeV2::ThirdJournalState,
                "pre-CAS journal head is neither exact source nor target",
            );
        }

        let mut connection = open_rw_matching_preflight_v2(&self.path, identity)?;
        let result = (|| -> ResultV2<()> {
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(sqlite_unavailable_v2)?;
            let observed = audit_connection_v2(&transaction, self.journal_id, self.scope)?;
            let observed_head = observed.last().expect("audited history is nonempty");
            if observed_head == target {
                drop(transaction);
                return Ok(());
            }
            require(
                observed_head == expected,
                PocoNodeG2ManifestBoundErrorCodeV2::JournalFork,
                "journal CAS source is neither exact expected nor target",
            )?;
            transaction
                .execute(
                    "INSERT INTO g2_manifest_bound_history_v2(generation,phase,predecessor_checksum,join_commitment,checksum,record) VALUES(?1,1,?2,?3,?4,?5)",
                    params![
                        &target.generation.to_be_bytes()[..],
                        &target.predecessor_checksum[..],
                        &target.join_commitment_v2().expect("persisted target has commitment")[..],
                        &target.checksum[..],
                        target.encode_v2()?,
                    ],
                )
                .map_err(sqlite_unavailable_v2)?;
            let changed = transaction
                .execute(
                    "UPDATE g2_manifest_bound_metadata_v2 SET head_generation=?1,head_phase=1,head_checksum=?2 WHERE singleton=1 AND fenced=0 AND journal_id=?3 AND scope=?4 AND head_generation=?5 AND head_phase=0 AND head_checksum=?6",
                    params![
                        &target.generation.to_be_bytes()[..],
                        &target.checksum[..],
                        &target.journal_id[..],
                        &target.scope[..],
                        &expected.generation.to_be_bytes()[..],
                        &expected.checksum[..],
                    ],
                )
                .map_err(sqlite_unavailable_v2)?;
            require(
                changed == 1,
                PocoNodeG2ManifestBoundErrorCodeV2::JournalFork,
                "journal metadata CAS changed no row",
            )?;
            #[cfg(test)]
            if matches!(fault, Some(JournalFaultV2::BeforeCommit)) {
                drop(transaction);
                return reject(
                    PocoNodeG2ManifestBoundErrorCodeV2::JournalUnavailable,
                    "injected loss before commit",
                );
            }
            let commit = transaction.commit().map_err(sqlite_unavailable_v2);
            #[cfg(test)]
            if matches!(fault, Some(JournalFaultV2::AfterCommitBeforeReturn)) {
                return reject(
                    PocoNodeG2ManifestBoundErrorCodeV2::JournalUnavailable,
                    "injected response loss after commit",
                );
            }
            commit
        })();
        drop(connection);

        // The SQLite result is never authority. Resolve every attempted CAS by
        // immutable fresh readback of the complete journal.
        let observed = self.audit_fresh_v2();
        match observed {
            Ok(records) if records.last() == Some(target) => Ok(target.clone()),
            Ok(records) if records.last() == Some(expected) => {
                let _ = result;
                reject(
                    PocoNodeG2ManifestBoundErrorCodeV2::CompareNotApplied,
                    "journal CAS was proven not applied",
                )
            }
            _ => {
                let _ = self.fence_v2();
                reject(
                    PocoNodeG2ManifestBoundErrorCodeV2::ThirdJournalState,
                    "fresh journal state is neither exact source nor target",
                )
            }
        }
    }

    fn require_fresh_target_v2(&self, target: &JournalRecordV2) -> ResultV2<JournalRecordV2> {
        let records = self.audit_fresh_v2()?;
        require(
            records.last() == Some(target),
            PocoNodeG2ManifestBoundErrorCodeV2::ThirdJournalState,
            "mandatory target readback differs",
        )?;
        Ok(target.clone())
    }

    fn audit_fresh_v2(&self) -> ResultV2<Vec<JournalRecordV2>> {
        let (connection, identity) = open_existing_ro_preflight_v2(&self.path)?;
        let records = audit_connection_v2(&connection, self.journal_id, self.scope)?;
        drop(connection);
        reject_sidecars_v2(&self.path)?;
        require_journal_file_identity_v2(&self.path, identity)?;
        Ok(records)
    }

    fn fence_v2(&self) -> ResultV2<()> {
        let connection = open_existing_rw_after_immutable_preflight_v2(&self.path)?;
        connection
            .execute(
                "UPDATE g2_manifest_bound_metadata_v2 SET fenced=1 WHERE singleton=1",
                [],
            )
            .map_err(sqlite_unavailable_v2)?;
        drop(connection);
        reject_sidecars_v2(&self.path)
    }
}

/// Data-only store handle. Reopen never returns the exact owner.
#[derive(Debug)]
#[must_use = "the candidate-local store must consume a fresh exact join or remain inert"]
pub(crate) struct PocoNodeG2ManifestBoundCandidateLocalStoreV2 {
    journal: SqliteG2ManifestBoundJournalV2,
    trusted_pin: PocoNodeG2ManifestBoundJournalPinV2,
}

impl PocoNodeG2ManifestBoundCandidateLocalStoreV2 {
    /// Derive the deterministic data-only anchor expected for one journal
    /// namespace. This does not open, create, or authorize a journal and
    /// cannot issue the exact candidate-local owner.
    pub(crate) fn expected_anchor_pin_v2(
        journal_id: [u8; 32],
        scope: [u8; 32],
    ) -> ResultV2<PocoNodeG2ManifestBoundJournalPinV2> {
        Ok(JournalRecordV2::anchor_v2(journal_id, scope)?.pin_v2())
    }

    pub(crate) fn initialize_new_v2(
        namespace: &PocoNodeG2ManifestBoundJournalNamespaceV2,
        journal_id: [u8; 32],
        scope: [u8; 32],
    ) -> ResultV2<(Self, PocoNodeG2ManifestBoundJournalPinV2)> {
        let (journal, anchor) =
            SqliteG2ManifestBoundJournalV2::initialize_new_v2(namespace, journal_id, scope)?;
        let pin = anchor.pin_v2();
        Ok((
            Self {
                journal,
                trusted_pin: pin.clone(),
            },
            pin,
        ))
    }

    pub(crate) fn open_existing_v2(
        namespace: &PocoNodeG2ManifestBoundJournalNamespaceV2,
        trusted_pin: &PocoNodeG2ManifestBoundJournalPinV2,
    ) -> ResultV2<Self> {
        let journal = SqliteG2ManifestBoundJournalV2::open_existing_v2(namespace, trusted_pin)?;
        Ok(Self {
            journal,
            trusted_pin: trusted_pin.clone(),
        })
    }

    /// Prepare-only crash reconciliation accepts exactly the deterministic
    /// generation-zero anchor and no already-persisted target. Reopening with
    /// a trusted anchor through the general recovery path is intentionally
    /// broader because it also permits one exact response-loss successor.
    pub(crate) fn revalidate_fresh_anchor_only_v2(&self) -> ResultV2<()> {
        require(
            self.trusted_pin.phase == PocoNodeG2ManifestBoundJournalPhaseV2::Anchor
                && self.trusted_pin.generation == 0,
            PocoNodeG2ManifestBoundErrorCodeV2::ThirdJournalState,
            "prepare does not retain an exact generation-zero T0-D anchor",
        )?;
        let records = self.journal.audit_fresh_v2()?;
        require(
            records.len() == 1
                && records
                    .last()
                    .is_some_and(|record| record.pin_v2() == self.trusted_pin),
            PocoNodeG2ManifestBoundErrorCodeV2::ThirdJournalState,
            "prepare found a T0-D target or non-exact anchor history",
        )
    }

    /// Sole authority-bearing ingress. At an anchor it performs the one exact
    /// successor CAS; at the durable target it requires a freshly reproduced,
    /// byte-identical typed join. No decoded snapshot or caller-supplied root
    /// can enter this path.
    pub(crate) fn consume_exact_finalize_join_v2(
        self,
        exact_join: G2CandidateLocalFinalizeJoinV2,
    ) -> ResultV2<PocoNodeG2ManifestBoundCandidateLocalOwnerV2> {
        let candidate = CanonicalJoinSnapshotV2::from_exact_join_v2(&exact_join)?;
        let records_before = self.journal.audit_fresh_v2()?;
        require_trusted_prefix_v2(&records_before, &self.trusted_pin)?;
        let head = records_before
            .last()
            .expect("audited journal history is nonempty");
        let durable = match head.phase {
            PocoNodeG2ManifestBoundJournalPhaseV2::Anchor => {
                let target = head.persisted_successor_v2(candidate.clone())?;
                self.journal.advance_v2(head, &target)?
            }
            PocoNodeG2ManifestBoundJournalPhaseV2::Persisted => {
                require_exact_snapshot_v2(head, &candidate)?;
                // Narrow the encode/history-read race before recreating the
                // in-memory owner. This does not close the separate same-UID
                // path-rename race between rusqlite connections. The trusted
                // pin may be the anchor only for the unique
                // applied-but-response-lost successor.
                let records_after = self.journal.audit_fresh_v2()?;
                require_trusted_prefix_v2(&records_after, &self.trusted_pin)?;
                require(
                    records_after.last() == Some(head),
                    PocoNodeG2ManifestBoundErrorCodeV2::ThirdJournalState,
                    "journal changed across exact recovery comparison",
                )?;
                head.clone()
            }
        };
        require_exact_snapshot_v2(&durable, &candidate)?;
        let owner = PocoNodeG2ManifestBoundCandidateLocalOwnerV2 {
            exact_join,
            journal: self.journal,
            journal_pin: durable.pin_v2(),
        };
        owner.revalidate_fresh_exact_v2()?;
        Ok(owner)
    }
}

/// Canonical commitment to every public fact in one exact typed join. The
/// returned hash is comparison data only; only consuming the typed join at
/// [`PocoNodeG2ManifestBoundCandidateLocalStoreV2`] can issue the inert owner.
pub(crate) fn exact_finalize_join_commitment_v2(
    exact_join: &G2CandidateLocalFinalizeJoinV2,
) -> ResultV2<[u8; 32]> {
    Ok(CanonicalJoinSnapshotV2::from_exact_join_v2(exact_join)?.commitment)
}

/// Non-Clone, crate-private owner retaining the exact typed join and the live
/// journal revalidation capability. The cloneable durable pin remains
/// rollback-detection data only and cannot recreate this owner.
#[must_use = "retain the inert candidate-local owner for a later bounded tranche"]
#[derive(Debug)]
pub(crate) struct PocoNodeG2ManifestBoundCandidateLocalOwnerV2 {
    exact_join: G2CandidateLocalFinalizeJoinV2,
    journal: SqliteG2ManifestBoundJournalV2,
    journal_pin: PocoNodeG2ManifestBoundJournalPinV2,
}

impl PocoNodeG2ManifestBoundCandidateLocalOwnerV2 {
    pub(crate) fn journal_pin_v2(&self) -> PocoNodeG2ManifestBoundJournalPinV2 {
        self.journal_pin.clone()
    }

    /// Re-derive the complete canonical snapshot from the retained typed join
    /// and compare it with two complete fresh journal audits. This is an inert
    /// owner-liveness check only; neither the journal nor decoded records can
    /// escape through this interface.
    pub(crate) fn revalidate_fresh_exact_v2(&self) -> ResultV2<()> {
        let candidate = CanonicalJoinSnapshotV2::from_exact_join_v2(&self.exact_join)?;
        let before = self.journal.audit_fresh_v2()?;
        let before_head = before.last().expect("audited journal history is nonempty");
        require(
            before_head.pin_v2() == self.journal_pin,
            PocoNodeG2ManifestBoundErrorCodeV2::JournalRollback,
            "live owner journal head differs from its retained exact pin",
        )?;
        require_exact_snapshot_v2(before_head, &candidate)?;

        let after = self.journal.audit_fresh_v2()?;
        require(
            after == before,
            PocoNodeG2ManifestBoundErrorCodeV2::ThirdJournalState,
            "live owner journal changed across mandatory fresh exact revalidation",
        )?;
        let after_head = after.last().expect("audited journal history is nonempty");
        require(
            after_head.pin_v2() == self.journal_pin,
            PocoNodeG2ManifestBoundErrorCodeV2::JournalRollback,
            "live owner journal target no longer matches its retained exact pin",
        )?;
        require_exact_snapshot_v2(after_head, &candidate)
    }
}

fn require_exact_snapshot_v2(
    record: &JournalRecordV2,
    candidate: &CanonicalJoinSnapshotV2,
) -> ResultV2<()> {
    require(
        record.phase == PocoNodeG2ManifestBoundJournalPhaseV2::Persisted
            && record.snapshot.as_ref() == Some(candidate),
        PocoNodeG2ManifestBoundErrorCodeV2::ExactJoinMismatch,
        "fresh exact join differs from the durable candidate-local snapshot",
    )
}

fn require_trusted_prefix_v2(
    records: &[JournalRecordV2],
    trusted_pin: &PocoNodeG2ManifestBoundJournalPinV2,
) -> ResultV2<()> {
    trusted_pin.validate_v2()?;
    let position = records
        .iter()
        .position(|record| record.pin_v2() == *trusted_pin)
        .ok_or_else(|| PocoNodeG2ManifestBoundErrorV2 {
            code: PocoNodeG2ManifestBoundErrorCodeV2::JournalRollback,
            detail: "external trusted pin is absent from the complete journal".to_owned(),
        })?;
    require(
        position + 1 == records.len()
            || (trusted_pin.phase == PocoNodeG2ManifestBoundJournalPhaseV2::Anchor
                && position == 0
                && records.len() == 2
                && records[1].phase == PocoNodeG2ManifestBoundJournalPhaseV2::Persisted),
        PocoNodeG2ManifestBoundErrorCodeV2::JournalRollback,
        "journal advanced beyond the only response-loss successor",
    )
}

fn audit_connection_v2(
    connection: &Connection,
    expected_journal_id: [u8; 32],
    expected_scope: [u8; 32],
) -> ResultV2<Vec<JournalRecordV2>> {
    validate_schema_v2(connection)?;
    let metadata = connection
        .query_row(
            "SELECT journal_id,scope,head_generation,head_phase,head_checksum,fenced FROM g2_manifest_bound_metadata_v2 WHERE singleton=1",
            [],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, i64>(5)?,
                ))
            },
        )
        .map_err(sqlite_unavailable_v2)?;
    let journal_id = exact_hash_v2(&metadata.0, "metadata journal ID")?;
    let scope = exact_hash_v2(&metadata.1, "metadata scope")?;
    let head_generation = exact_u64_v2(&metadata.2, "metadata generation")?;
    let head_phase = u8::try_from(metadata.3)
        .ok()
        .and_then(PocoNodeG2ManifestBoundJournalPhaseV2::from_u8)
        .ok_or_else(|| PocoNodeG2ManifestBoundErrorV2 {
            code: PocoNodeG2ManifestBoundErrorCodeV2::JournalTamper,
            detail: "metadata phase is invalid".to_owned(),
        })?;
    let head_checksum = exact_hash_v2(&metadata.4, "metadata checksum")?;
    require(
        journal_id == expected_journal_id
            && scope == expected_scope
            && journal_id != [0; 32]
            && scope != [0; 32]
            && metadata.5 == 0,
        PocoNodeG2ManifestBoundErrorCodeV2::JournalTamper,
        "metadata identity differs or journal is fenced",
    )?;

    let mut statement = connection
        .prepare(
            "SELECT generation,phase,predecessor_checksum,join_commitment,checksum,record FROM g2_manifest_bound_history_v2 ORDER BY generation",
        )
        .map_err(sqlite_unavailable_v2)?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, Option<Vec<u8>>>(3)?,
                row.get::<_, Vec<u8>>(4)?,
                row.get::<_, Vec<u8>>(5)?,
            ))
        })
        .map_err(sqlite_unavailable_v2)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(sqlite_unavailable_v2)?;
    require(
        !rows.is_empty() && rows.len() <= 2,
        PocoNodeG2ManifestBoundErrorCodeV2::JournalTamper,
        "journal history count differs from anchor/target bound",
    )?;
    let mut records: Vec<JournalRecordV2> = Vec::with_capacity(rows.len());
    for row in rows {
        let generation = exact_u64_v2(&row.0, "history generation")?;
        let phase = u8::try_from(row.1)
            .ok()
            .and_then(PocoNodeG2ManifestBoundJournalPhaseV2::from_u8)
            .ok_or_else(|| PocoNodeG2ManifestBoundErrorV2 {
                code: PocoNodeG2ManifestBoundErrorCodeV2::JournalTamper,
                detail: "history phase is invalid".to_owned(),
            })?;
        let predecessor = exact_hash_v2(&row.2, "history predecessor")?;
        let join_commitment = row
            .3
            .as_deref()
            .map(|raw| exact_hash_v2(raw, "history join commitment"))
            .transpose()?;
        let checksum = exact_hash_v2(&row.4, "history checksum")?;
        let record = JournalRecordV2::decode_exact_v2(&row.5)?;
        require(
            generation == record.generation
                && phase == record.phase
                && predecessor == record.predecessor_checksum
                && join_commitment == record.join_commitment_v2()
                && checksum == record.checksum
                && record.journal_id == journal_id
                && record.scope == scope,
            PocoNodeG2ManifestBoundErrorCodeV2::JournalTamper,
            "history columns differ from the exact record",
        )?;
        if let Some(previous) = records.last() {
            previous.validate_successor_v2(&record)?;
        } else {
            require(
                record.phase == PocoNodeG2ManifestBoundJournalPhaseV2::Anchor,
                PocoNodeG2ManifestBoundErrorCodeV2::JournalTamper,
                "journal history does not begin at the anchor",
            )?;
        }
        records.push(record);
    }
    let head = records.last().expect("nonempty history checked");
    require(
        head.generation == head_generation
            && head.phase == head_phase
            && head.checksum == head_checksum,
        PocoNodeG2ManifestBoundErrorCodeV2::JournalTamper,
        "metadata head differs from complete history tail",
    )?;
    Ok(records)
}

fn canonical_private_directory_v2(path: &Path) -> ResultV2<PathBuf> {
    require(
        path.is_absolute() && !path.as_os_str().is_empty(),
        PocoNodeG2ManifestBoundErrorCodeV2::InvalidNamespace,
        "journal directory must be nonempty and absolute",
    )?;
    let metadata = fs::symlink_metadata(path)
        .map_err(|cause| unavailable(format!("journal directory unavailable: {cause}")))?;
    require(
        metadata.is_dir() && !metadata.file_type().is_symlink(),
        PocoNodeG2ManifestBoundErrorCodeV2::InvalidNamespace,
        "journal namespace must be a direct directory",
    )?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        require(
            metadata.permissions().mode() & 0o777 == 0o700,
            PocoNodeG2ManifestBoundErrorCodeV2::InvalidNamespace,
            "journal namespace mode must be exactly 0700",
        )?;
    }
    let canonical = fs::canonicalize(path)
        .map_err(|cause| unavailable(format!("journal directory cannot canonicalize: {cause}")))?;
    require(
        canonical == path,
        PocoNodeG2ManifestBoundErrorCodeV2::InvalidNamespace,
        "journal namespace path must already be canonical",
    )?;
    Ok(canonical)
}

fn validate_journal_path_v2(path: &Path, must_exist: bool) -> ResultV2<()> {
    let parent = path
        .parent()
        .ok_or_else(|| PocoNodeG2ManifestBoundErrorV2 {
            code: PocoNodeG2ManifestBoundErrorCodeV2::InvalidNamespace,
            detail: "journal path has no parent".to_owned(),
        })?;
    canonical_private_directory_v2(parent)?;
    require(
        path.file_name().and_then(|name| name.to_str()) == Some(JOURNAL_FILE_NAME_V2),
        PocoNodeG2ManifestBoundErrorCodeV2::InvalidNamespace,
        "journal filename differs",
    )?;
    match fs::symlink_metadata(path) {
        Ok(metadata) => require(
            must_exist && metadata.is_file() && !metadata.file_type().is_symlink(),
            PocoNodeG2ManifestBoundErrorCodeV2::InvalidNamespace,
            "journal path type or expected existence differs",
        ),
        Err(cause) if cause.kind() == std::io::ErrorKind::NotFound => require(
            !must_exist,
            PocoNodeG2ManifestBoundErrorCodeV2::InvalidNamespace,
            "journal file is missing",
        ),
        Err(cause) => reject(
            PocoNodeG2ManifestBoundErrorCodeV2::JournalUnavailable,
            format!("journal path metadata unavailable: {cause}"),
        ),
    }
}

fn reject_sidecars_v2(path: &Path) -> ResultV2<()> {
    for suffix in ["-wal", "-shm", "-journal"] {
        let mut sidecar = OsString::from(path.as_os_str());
        sidecar.push(suffix);
        match fs::symlink_metadata(PathBuf::from(sidecar)) {
            Ok(_) => {
                return reject(
                    PocoNodeG2ManifestBoundErrorCodeV2::JournalUnavailable,
                    format!("forbidden SQLite sidecar exists: {suffix}"),
                )
            }
            Err(cause) if cause.kind() == std::io::ErrorKind::NotFound => {}
            Err(cause) => {
                return reject(
                    PocoNodeG2ManifestBoundErrorCodeV2::JournalUnavailable,
                    format!("SQLite sidecar metadata unavailable: {cause}"),
                )
            }
        }
    }
    Ok(())
}

fn open_rw_raw_v2(path: &Path) -> ResultV2<Connection> {
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(sqlite_unavailable_v2)?;
    connection
        .busy_timeout(Duration::from_secs(2))
        .map_err(sqlite_unavailable_v2)?;
    Ok(connection)
}

fn open_ro_immutable_v2(path: &Path) -> ResultV2<Connection> {
    let mut uri = String::from("file:");
    for byte in path.as_os_str().as_encoded_bytes() {
        if byte.is_ascii_alphanumeric() || matches!(*byte, b'/' | b'.' | b'_' | b'-' | b'~') {
            uri.push(char::from(*byte));
        } else {
            use std::fmt::Write as _;
            write!(&mut uri, "%{byte:02X}")
                .map_err(|_| unavailable("cannot encode immutable journal URI"))?;
        }
    }
    uri.push_str("?mode=ro&immutable=1");
    let connection = Connection::open_with_flags(
        uri,
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_URI,
    )
    .map_err(sqlite_unavailable_v2)?;
    connection
        .busy_timeout(Duration::from_secs(2))
        .map_err(sqlite_unavailable_v2)?;
    Ok(connection)
}

fn configure_rw_v2(connection: &Connection) -> ResultV2<()> {
    connection
        .execute_batch(
            "PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON; PRAGMA trusted_schema=OFF;",
        )
        .map_err(sqlite_unavailable_v2)
}

fn validate_schema_v2(connection: &Connection) -> ResultV2<()> {
    let application_id = connection
        .query_row("PRAGMA application_id", [], |row| row.get::<_, i64>(0))
        .map_err(sqlite_unavailable_v2)?;
    let user_version = connection
        .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
        .map_err(sqlite_unavailable_v2)?;
    require(
        application_id == SQLITE_APPLICATION_ID_V2 && user_version == SQLITE_USER_VERSION_V2,
        PocoNodeG2ManifestBoundErrorCodeV2::JournalSchemaMismatch,
        "journal SQLite identity or schema version differs",
    )?;
    let quick_check = connection
        .query_row("PRAGMA quick_check", [], |row| row.get::<_, String>(0))
        .map_err(sqlite_unavailable_v2)?;
    require(
        quick_check == "ok",
        PocoNodeG2ManifestBoundErrorCodeV2::JournalTamper,
        "journal SQLite quick_check failed",
    )?;
    let mut statement = connection
        .prepare("SELECT name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY name")
        .map_err(sqlite_unavailable_v2)?;
    let actual = statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(sqlite_unavailable_v2)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(sqlite_unavailable_v2)?;
    let expected = vec![
        (
            "g2_manifest_bound_history_v2".to_owned(),
            HISTORY_SQL_V2.to_owned(),
        ),
        (
            "g2_manifest_bound_metadata_v2".to_owned(),
            META_SQL_V2.to_owned(),
        ),
    ];
    require(
        actual == expected,
        PocoNodeG2ManifestBoundErrorCodeV2::JournalSchemaMismatch,
        "journal SQLite schema inventory differs",
    )
}

#[cfg(unix)]
fn journal_file_stat_v2(metadata: &Metadata) -> JournalFileStatV2 {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    JournalFileStatV2 {
        device: metadata.dev(),
        inode: metadata.ino(),
        owner: metadata.uid(),
        links: metadata.nlink(),
        mode: metadata.permissions().mode() & 0o777,
        size: metadata.len(),
        modified_seconds: metadata.mtime(),
        modified_nanoseconds: metadata.mtime_nsec(),
        changed_seconds: metadata.ctime(),
        changed_nanoseconds: metadata.ctime_nsec(),
    }
}

#[cfg(unix)]
fn require_safe_journal_metadata_v2(metadata: &Metadata) -> ResultV2<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    require(
        metadata.is_file()
            && !metadata.file_type().is_symlink()
            && metadata.nlink() == 1
            && metadata.permissions().mode() & 0o777 == 0o600
            && metadata.len() >= 100
            && metadata.len() <= MAX_JOURNAL_DATABASE_BYTES_V2,
        PocoNodeG2ManifestBoundErrorCodeV2::JournalUnavailable,
        "journal file type/link-count/mode/size is unsafe",
    )
}

#[cfg(unix)]
fn journal_file_identity_v2(path: &Path) -> ResultV2<JournalFileIdentityV2> {
    let path_before = fs::symlink_metadata(path)
        .map_err(|cause| unavailable(format!("journal identity unavailable: {cause}")))?;
    require_safe_journal_metadata_v2(&path_before)?;
    let mut file = File::open(path)
        .map_err(|cause| unavailable(format!("journal bytes unavailable: {cause}")))?;
    let file_before = file
        .metadata()
        .map_err(|cause| unavailable(format!("opened journal identity unavailable: {cause}")))?;
    require_safe_journal_metadata_v2(&file_before)?;
    require(
        journal_file_stat_v2(&path_before) == journal_file_stat_v2(&file_before),
        PocoNodeG2ManifestBoundErrorCodeV2::JournalUnavailable,
        "journal path changed while opening immutable identity",
    )?;
    let mut header = [0_u8; 100];
    file.read_exact(&mut header)
        .map_err(|cause| unavailable(format!("cannot read SQLite header: {cause}")))?;
    require(
        &header[..16] == b"SQLite format 3\0" && header[18] == 1 && header[19] == 1,
        PocoNodeG2ManifestBoundErrorCodeV2::JournalUnavailable,
        "journal SQLite header or rollback-journal mode differs",
    )?;
    let mut hasher = Sha256::new();
    hasher.update(header);
    let mut total = 100_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|cause| unavailable(format!("cannot hash journal bytes: {cause}")))?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(u64::try_from(read).expect("buffer length fits u64"))
            .ok_or_else(|| unavailable("journal byte count overflows"))?;
        hasher.update(&buffer[..read]);
    }
    let file_after = file
        .metadata()
        .map_err(|cause| unavailable(format!("cannot re-read journal identity: {cause}")))?;
    let path_after = fs::symlink_metadata(path)
        .map_err(|cause| unavailable(format!("cannot re-read journal path: {cause}")))?;
    require_safe_journal_metadata_v2(&file_after)?;
    require_safe_journal_metadata_v2(&path_after)?;
    let stat = journal_file_stat_v2(&file_before);
    require(
        stat == journal_file_stat_v2(&file_after)
            && stat == journal_file_stat_v2(&path_after)
            && total == stat.size,
        PocoNodeG2ManifestBoundErrorCodeV2::JournalUnavailable,
        "journal file changed while hashing immutable identity",
    )?;
    Ok(JournalFileIdentityV2 {
        stat,
        content_sha256: hasher.finalize().into(),
    })
}

#[cfg(not(unix))]
fn journal_file_identity_v2(_: &Path) -> ResultV2<()> {
    reject(
        PocoNodeG2ManifestBoundErrorCodeV2::JournalUnavailable,
        "journal immutable identity requires Unix metadata",
    )
}

#[cfg(unix)]
fn require_journal_file_identity_v2(path: &Path, expected: JournalFileIdentityV2) -> ResultV2<()> {
    require(
        journal_file_identity_v2(path)? == expected,
        PocoNodeG2ManifestBoundErrorCodeV2::JournalUnavailable,
        "journal dev/ino/uid/nlink/mode/size/time/content identity changed",
    )
}

#[cfg(not(unix))]
fn require_journal_file_identity_v2(_: &Path, _: ()) -> ResultV2<()> {
    reject(
        PocoNodeG2ManifestBoundErrorCodeV2::JournalUnavailable,
        "journal immutable identity requires Unix metadata",
    )
}

#[cfg(unix)]
fn open_existing_ro_preflight_v2(path: &Path) -> ResultV2<(Connection, JournalFileIdentityV2)> {
    reject_sidecars_v2(path)?;
    let identity = journal_file_identity_v2(path)?;
    let connection = open_ro_immutable_v2(path)?;
    require_journal_file_identity_v2(path, identity)?;
    validate_schema_v2(&connection)?;
    require_journal_file_identity_v2(path, identity)?;
    reject_sidecars_v2(path)?;
    Ok((connection, identity))
}

#[cfg(not(unix))]
fn open_existing_ro_preflight_v2(_: &Path) -> ResultV2<(Connection, ())> {
    reject(
        PocoNodeG2ManifestBoundErrorCodeV2::JournalUnavailable,
        "journal immutable preflight requires Unix metadata",
    )
}

#[cfg(unix)]
fn open_rw_matching_preflight_v2(
    path: &Path,
    expected: JournalFileIdentityV2,
) -> ResultV2<Connection> {
    reject_sidecars_v2(path)?;
    require_journal_file_identity_v2(path, expected)?;
    let connection = open_rw_raw_v2(path)?;
    reject_sidecars_v2(path)?;
    require_journal_file_identity_v2(path, expected)?;
    validate_schema_v2(&connection)?;
    reject_sidecars_v2(path)?;
    require_journal_file_identity_v2(path, expected)?;
    configure_rw_v2(&connection)?;
    Ok(connection)
}

#[cfg(not(unix))]
fn open_rw_matching_preflight_v2(_: &Path, _: ()) -> ResultV2<Connection> {
    reject(
        PocoNodeG2ManifestBoundErrorCodeV2::JournalUnavailable,
        "journal read-write preflight requires Unix metadata",
    )
}

fn open_existing_rw_after_immutable_preflight_v2(path: &Path) -> ResultV2<Connection> {
    let (read_only, identity) = open_existing_ro_preflight_v2(path)?;
    drop(read_only);
    reject_sidecars_v2(path)?;
    require_journal_file_identity_v2(path, identity)?;
    open_rw_matching_preflight_v2(path, identity)
}

fn sqlite_unavailable_v2(cause: rusqlite::Error) -> PocoNodeG2ManifestBoundErrorV2 {
    unavailable(format!("journal SQLite unavailable: {cause}"))
}

fn unavailable(detail: impl Into<String>) -> PocoNodeG2ManifestBoundErrorV2 {
    PocoNodeG2ManifestBoundErrorV2 {
        code: PocoNodeG2ManifestBoundErrorCodeV2::JournalUnavailable,
        detail: detail.into(),
    }
}

fn exact_hash_v2(raw: &[u8], label: &str) -> ResultV2<[u8; 32]> {
    raw.try_into().map_err(|_| PocoNodeG2ManifestBoundErrorV2 {
        code: PocoNodeG2ManifestBoundErrorCodeV2::JournalTamper,
        detail: format!("{label} is not exactly 32 bytes"),
    })
}

fn exact_u64_v2(raw: &[u8], label: &str) -> ResultV2<u64> {
    let bytes: [u8; 8] = raw.try_into().map_err(|_| PocoNodeG2ManifestBoundErrorV2 {
        code: PocoNodeG2ManifestBoundErrorCodeV2::JournalTamper,
        detail: format!("{label} is not exactly 8 bytes"),
    })?;
    Ok(u64::from_be_bytes(bytes))
}

fn digest_v2(domain: &str, bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(
        u32::try_from(domain.len())
            .expect("static journal domain length fits u32")
            .to_le_bytes(),
    );
    hasher.update(domain.as_bytes());
    hasher.update(bytes);
    hasher.finalize().into()
}

fn put_bytes_v2(out: &mut Vec<u8>, bytes: &[u8]) -> ResultV2<()> {
    let length = u32::try_from(bytes.len()).map_err(|_| PocoNodeG2ManifestBoundErrorV2 {
        code: PocoNodeG2ManifestBoundErrorCodeV2::SnapshotTooLarge,
        detail: "snapshot byte field exceeds u32".to_owned(),
    })?;
    out.extend_from_slice(&length.to_le_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

struct CursorV2<'a> {
    raw: &'a [u8],
    offset: usize,
}

impl<'a> CursorV2<'a> {
    const fn new(raw: &'a [u8]) -> Self {
        Self { raw, offset: 0 }
    }

    fn take(&mut self, length: usize) -> ResultV2<&'a [u8]> {
        let end =
            self.offset
                .checked_add(length)
                .ok_or_else(|| PocoNodeG2ManifestBoundErrorV2 {
                    code: PocoNodeG2ManifestBoundErrorCodeV2::JournalTamper,
                    detail: "journal cursor overflows".to_owned(),
                })?;
        let value =
            self.raw
                .get(self.offset..end)
                .ok_or_else(|| PocoNodeG2ManifestBoundErrorV2 {
                    code: PocoNodeG2ManifestBoundErrorCodeV2::JournalTamper,
                    detail: "journal record is truncated".to_owned(),
                })?;
        self.offset = end;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> ResultV2<[u8; N]> {
        self.take(N)?
            .try_into()
            .map_err(|_| PocoNodeG2ManifestBoundErrorV2 {
                code: PocoNodeG2ManifestBoundErrorCodeV2::JournalTamper,
                detail: "fixed journal field length differs".to_owned(),
            })
    }

    fn u8(&mut self) -> ResultV2<u8> {
        Ok(self.array::<1>()?[0])
    }

    fn u16(&mut self) -> ResultV2<u16> {
        Ok(u16::from_le_bytes(self.array()?))
    }

    fn u32(&mut self) -> ResultV2<u32> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    fn u64(&mut self) -> ResultV2<u64> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    fn length_prefixed(&mut self, maximum: usize) -> ResultV2<&'a [u8]> {
        let length = usize::try_from(self.u32()?).map_err(|_| PocoNodeG2ManifestBoundErrorV2 {
            code: PocoNodeG2ManifestBoundErrorCodeV2::SnapshotTooLarge,
            detail: "length-prefixed journal field does not fit usize".to_owned(),
        })?;
        require(
            length > 0 && length <= maximum,
            PocoNodeG2ManifestBoundErrorCodeV2::SnapshotTooLarge,
            "length-prefixed journal field exceeds its bound",
        )?;
        self.take(length)
    }

    fn remaining(&self) -> usize {
        self.raw.len().saturating_sub(self.offset)
    }
}

#[cfg(test)]
mod tests {
    use std::{cell::Cell, fs, io::Write as _, os::unix::fs::PermissionsExt};

    use tempfile::TempDir;
    use trnm_poco_global_execution_v1::ManifestBoundGlobalExecutionInputV2;
    use trnm_poco_order_application_v1::{
        seal_manifest_bound_g2_order_block_v2, EmptyOrderStateAnchorV1, OrderApplicationParentV1,
    };

    use super::*;
    use crate::g2_order_commit_v1::real_e2e_tests::RealG2RigV1;

    const JOURNAL_ID: [u8; 32] = [0x41; 32];
    const SCOPE: [u8; 32] = [0x52; 32];

    fn namespace_v2() -> (TempDir, PocoNodeG2ManifestBoundJournalNamespaceV2) {
        let root = TempDir::new().expect("temp journal namespace");
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700))
            .expect("private namespace mode");
        let canonical = fs::canonicalize(root.path()).expect("canonical namespace");
        let namespace = PocoNodeG2ManifestBoundJournalNamespaceV2::new_v2(canonical)
            .expect("valid private namespace");
        (root, namespace)
    }

    fn synthetic_snapshot_v2(seed: u8) -> CanonicalJoinSnapshotV2 {
        let height = 7_u64;
        let mut plane_roots = vec![seed; 490];
        plane_roots[..2].copy_from_slice(&2_u16.to_le_bytes());
        plane_roots[2..34].fill(seed.max(1));
        plane_roots[34..42].copy_from_slice(&height.to_le_bytes());
        plane_roots[42..].fill(seed.max(1));
        let receipts = [1_u32.to_le_bytes().as_slice(), &[seed.max(1); 32]].concat();
        let mut raw = Vec::new();
        raw.extend_from_slice(&SNAPSHOT_MAGIC_V2);
        raw.extend_from_slice(&JOURNAL_SCHEMA_V2.to_le_bytes());
        raw.extend_from_slice(&[seed.max(1); 32]);
        raw.extend_from_slice(&height.to_le_bytes());
        raw.extend_from_slice(&[seed.wrapping_add(1).max(1); 32]);
        for index in 0..8_u8 {
            raw.extend_from_slice(&[seed.wrapping_add(index).max(1); 32]);
        }
        raw.extend_from_slice(&[seed.wrapping_add(9).max(1); 32]);
        raw.extend_from_slice(&[seed.wrapping_add(10).max(1); 32]);
        put_bytes_v2(&mut raw, &plane_roots).expect("plane roots fit");
        raw.extend_from_slice(&1_u32.to_le_bytes());
        put_bytes_v2(&mut raw, &receipts).expect("receipts fit");
        raw.extend_from_slice(&[seed.wrapping_add(11).max(1); 32]);
        raw.extend_from_slice(&[seed.wrapping_add(12).max(1); 32]);
        CanonicalJoinSnapshotV2::from_raw_v2(raw).expect("synthetic snapshot")
    }

    struct VirtualBorshBodyV2<'a> {
        passes: &'a Cell<usize>,
        chunks: usize,
    }

    impl BorshSerialize for VirtualBorshBodyV2<'_> {
        fn serialize<W: borsh::io::Write>(&self, writer: &mut W) -> borsh::io::Result<()> {
            self.passes.set(self.passes.get() + 1);
            for _ in 0..self.chunks {
                writer.write_all(&[0x5a; 32])?;
            }
            Ok(())
        }
    }

    #[test]
    fn exact_join_receipt_bounds_fail_before_large_allocation() {
        assert_eq!(
            checked_receipt_count_v2(MAX_RECEIPTS_V2 + 1)
                .expect_err("over-count inventory rejects before encoding")
                .code_v2(),
            PocoNodeG2ManifestBoundErrorCodeV2::SnapshotTooLarge,
        );

        // A virtual serializer proves an over-byte object receives only the
        // allocation-free object_length pass. Its real writer pass, reserve,
        // and large backing allocation are never reached.
        let oversize_passes = Cell::new(0);
        let virtual_oversize = VirtualBorshBodyV2 {
            passes: &oversize_passes,
            chunks: 2,
        };
        assert_eq!(
            encode_borsh_bounded_v2(&virtual_oversize, 63, "virtual receipts")
                .expect_err("64 encoded bytes exceed the 63-byte test cap")
                .code_v2(),
            PocoNodeG2ManifestBoundErrorCodeV2::SnapshotTooLarge,
        );
        assert_eq!(oversize_passes.get(), 1);

        let bounded_passes = Cell::new(0);
        let virtual_bounded = VirtualBorshBodyV2 {
            passes: &bounded_passes,
            chunks: 2,
        };
        assert_eq!(
            encode_borsh_bounded_v2(&virtual_bounded, 64, "virtual receipts")
                .expect("hard-limited writer accepts the exact bound")
                .len(),
            64,
        );
        assert_eq!(bounded_passes.get(), 2);
    }

    #[test]
    fn real_public_path_exact_join_reopens_recovers_and_source_change_rejects() {
        let mut rig = RealG2RigV1::new();
        let batch = rig.manifest_bound_batch_v2(0xb1);
        let (batch_id, certificate_id) = rig.certify_manifest_bound_batch_v2(&batch, 2);

        // First join: fresh cut sampling, real four-plane preview, public Order
        // sealing, and the public binding join. No test-only join constructor
        // or raw snapshot path participates.
        let first_input = {
            let mut sources = rig.manifest_bound_sources_v2();
            ManifestBoundGlobalExecutionInputV2::from_certified_batch_and_fresh_sources_v2(
                batch.clone(),
                batch_id,
                certificate_id,
                &mut sources,
            )
            .expect("fresh typed manifest input")
        };
        let first_preview = {
            let mut sources = rig.manifest_bound_sources_v2();
            first_input
                .preview_five_plane_inert_v2(&mut sources)
                .expect("first real fresh public preview")
        };
        let (first_order_input, first_plan, first_binding) = first_preview.into_order_material_v2();
        let first_anchor = EmptyOrderStateAnchorV1::new(1, rig.manifest_bound_parent_block_id_v2())
            .expect("real public-path empty parent");
        let first_request = seal_manifest_bound_g2_order_block_v2(
            OrderApplicationParentV1::EmptyAnchor(&first_anchor),
            rig.manifest_bound_order_template_v2(),
            first_order_input,
            first_plan,
        )
        .expect("seal first real public-path Order block")
        .into_finalize_binding_request_v2()
        .expect("derive first public finalize request");
        let first_join = first_binding
            .join_finalize_request_v2(first_request)
            .expect("first real public-path exact join");
        let expected_input_id = first_join.input_id();
        let expected_join_digest = first_join.join_digest();
        let expected_roots = first_join.ordered_roots();

        let (_root, namespace) = namespace_v2();
        let (store, _anchor_pin) = PocoNodeG2ManifestBoundCandidateLocalStoreV2::initialize_new_v2(
            &namespace, JOURNAL_ID, SCOPE,
        )
        .expect("initialize public-path anchor store");
        let anchor_copy = namespace.directory.join("owner-anchor-copy.sqlite");
        fs::copy(namespace.journal_path_v2(), &anchor_copy)
            .expect("save coherent anchor before owner CAS");
        let owner = store
            .consume_exact_finalize_join_v2(first_join)
            .expect("anchor consumes real public-path exact join");
        let target_pin = owner.journal_pin_v2();
        assert_eq!(
            target_pin.phase_v2(),
            PocoNodeG2ManifestBoundJournalPhaseV2::Persisted,
        );
        owner
            .revalidate_fresh_exact_v2()
            .expect("live owner freshly revalidates exact typed join and target journal");
        let target_copy = namespace.directory.join("owner-target-copy.sqlite");
        fs::copy(namespace.journal_path_v2(), &target_copy)
            .expect("save exact owner target before rollback mutant");
        fs::copy(&anchor_copy, namespace.journal_path_v2())
            .expect("inject coherent database-only owner rollback");
        assert_eq!(
            owner
                .revalidate_fresh_exact_v2()
                .expect_err("live owner pin rejects coherent journal rollback")
                .code_v2(),
            PocoNodeG2ManifestBoundErrorCodeV2::JournalRollback,
        );
        fs::copy(&target_copy, namespace.journal_path_v2())
            .expect("restore exact owner target after rollback control");
        owner
            .revalidate_fresh_exact_v2()
            .expect("restored target again matches retained live owner");
        drop(owner);

        // Simulate an independently authenticated process envelope while
        // keeping the reconstruction data-only.
        let external_target_pin =
            PocoNodeG2ManifestBoundJournalPinV2::from_external_trusted_parts_v2(
                target_pin.journal_id_v2(),
                target_pin.scope_v2(),
                target_pin.generation_v2(),
                target_pin.phase_v2(),
                target_pin.checksum_v2(),
            )
            .expect("reconstruct external target pin data");

        // Independently sample the unchanged stores and repeat the complete
        // public path. This fresh non-Clone join must be byte-exact to recover.
        let retry_input = {
            let mut sources = rig.manifest_bound_sources_v2();
            ManifestBoundGlobalExecutionInputV2::from_certified_batch_and_fresh_sources_v2(
                batch.clone(),
                batch_id,
                certificate_id,
                &mut sources,
            )
            .expect("independently resample exact typed input")
        };
        let retry_preview = {
            let mut sources = rig.manifest_bound_sources_v2();
            retry_input
                .preview_five_plane_inert_v2(&mut sources)
                .expect("independent real fresh retry preview")
        };
        let (retry_order_input, retry_plan, retry_binding) = retry_preview.into_order_material_v2();
        let retry_anchor = EmptyOrderStateAnchorV1::new(1, rig.manifest_bound_parent_block_id_v2())
            .expect("retry public-path empty parent");
        let retry_request = seal_manifest_bound_g2_order_block_v2(
            OrderApplicationParentV1::EmptyAnchor(&retry_anchor),
            rig.manifest_bound_order_template_v2(),
            retry_order_input,
            retry_plan,
        )
        .expect("seal independent retry Order block")
        .into_finalize_binding_request_v2()
        .expect("derive independent retry finalize request");
        let retry_join = retry_binding
            .join_finalize_request_v2(retry_request)
            .expect("independent real public-path exact join");
        assert_eq!(retry_join.input_id(), expected_input_id);
        assert_eq!(retry_join.join_digest(), expected_join_digest);
        assert_eq!(retry_join.ordered_roots(), expected_roots);

        let reopened = PocoNodeG2ManifestBoundCandidateLocalStoreV2::open_existing_v2(
            &namespace,
            &external_target_pin,
        )
        .expect("external target pin reopens data-only store");
        let recovered = reopened
            .consume_exact_finalize_join_v2(retry_join)
            .expect("fresh exact retry recovers owner");
        assert_eq!(recovered.journal_pin_v2(), external_target_pin);
        drop(recovered);

        // Certifying unrelated typed data advances the DA source while the
        // original manifest batch/certificate remain fixed. The formerly
        // fresh input now rejects before preview facts or a join can exist.
        let source_advance_batch = rig.manifest_bound_batch_v2(0xc1);
        rig.certify_manifest_bound_batch_v2(&source_advance_batch, 3);
        let stale_error = {
            let mut sources = rig.manifest_bound_sources_v2();
            retry_input
                .preview_five_plane_inert_v2(&mut sources)
                .expect_err("stale source cut cannot reproduce a preview")
        };
        assert_eq!(
            stale_error.code(),
            trnm_poco_global_execution_v1::GlobalExecutionErrorCodeV1::SourceCutMismatch,
        );

        // Freshly bind the *same* original typed batch and certificate to the
        // changed stores. If the historical certificate remains retrievable,
        // the real public path produces a source-distinct inert join, which
        // cannot recover the durable target selected before the source change.
        let source_changed_input = {
            let mut sources = rig.manifest_bound_sources_v2();
            ManifestBoundGlobalExecutionInputV2::from_certified_batch_and_fresh_sources_v2(
                batch,
                batch_id,
                certificate_id,
                &mut sources,
            )
            .expect("freshly rebind original input after source change")
        };
        let source_changed_preview = {
            let mut sources = rig.manifest_bound_sources_v2();
            source_changed_input
                .preview_five_plane_inert_v2(&mut sources)
                .expect("source-changed public preview of original batch")
        };
        let (source_changed_order_input, source_changed_plan, source_changed_binding) =
            source_changed_preview.into_order_material_v2();
        let source_changed_anchor =
            EmptyOrderStateAnchorV1::new(1, rig.manifest_bound_parent_block_id_v2())
                .expect("changed-source public-path empty parent");
        let source_changed_request = seal_manifest_bound_g2_order_block_v2(
            OrderApplicationParentV1::EmptyAnchor(&source_changed_anchor),
            rig.manifest_bound_order_template_v2(),
            source_changed_order_input,
            source_changed_plan,
        )
        .expect("seal changed-source Order block")
        .into_finalize_binding_request_v2()
        .expect("derive changed-source finalize request");
        let source_changed_join = source_changed_binding
            .join_finalize_request_v2(source_changed_request)
            .expect("changed-source public join remains inert data");
        assert_ne!(source_changed_join.input_id(), expected_input_id);
        let changed_reopen = PocoNodeG2ManifestBoundCandidateLocalStoreV2::open_existing_v2(
            &namespace,
            &external_target_pin,
        )
        .expect("target still reopens before mismatched recovery");
        assert_eq!(
            changed_reopen
                .consume_exact_finalize_join_v2(source_changed_join)
                .expect_err("source-changed join cannot recover exact owner")
                .code_v2(),
            PocoNodeG2ManifestBoundErrorCodeV2::ExactJoinMismatch,
        );
    }

    #[test]
    fn exact_join_anchor_cas_reopen_and_recovery_are_linear() {
        let (_root, namespace) = namespace_v2();
        let (journal, anchor) =
            SqliteG2ManifestBoundJournalV2::initialize_new_v2(&namespace, JOURNAL_ID, SCOPE)
                .expect("initialize anchor");
        let target = anchor
            .persisted_successor_v2(synthetic_snapshot_v2(0x21))
            .expect("exact target");
        assert_eq!(journal.advance_v2(&anchor, &target).expect("CAS"), target);
        assert_eq!(
            journal.audit_fresh_v2().expect("fresh history"),
            vec![anchor.clone(), target.clone()]
        );

        let target_pin = target.pin_v2();
        let reopened = SqliteG2ManifestBoundJournalV2::open_existing_v2(&namespace, &target_pin)
            .expect("target pin reopen");
        assert_eq!(
            reopened.audit_fresh_v2().expect("reopened target").last(),
            Some(&target)
        );
        SqliteG2ManifestBoundJournalV2::open_existing_v2(&namespace, &anchor.pin_v2())
            .expect("anchor trusted-prefix accepts sole response-loss successor");
        assert_eq!(
            journal.advance_v2(&anchor, &target).expect("exact retry"),
            target
        );
    }

    #[test]
    fn exact_join_cas_response_loss_resolves_only_source_or_target() {
        let (_root_before, namespace_before) = namespace_v2();
        let (journal_before, anchor_before) =
            SqliteG2ManifestBoundJournalV2::initialize_new_v2(&namespace_before, JOURNAL_ID, SCOPE)
                .expect("before-commit anchor");
        let target_before = anchor_before
            .persisted_successor_v2(synthetic_snapshot_v2(0x31))
            .expect("before target");
        let error = journal_before
            .advance_with_fault_v2(&anchor_before, &target_before, JournalFaultV2::BeforeCommit)
            .expect_err("precommit loss cannot mint target");
        assert_eq!(
            error.code_v2(),
            PocoNodeG2ManifestBoundErrorCodeV2::CompareNotApplied
        );
        assert_eq!(
            journal_before.audit_fresh_v2().expect("fresh source"),
            vec![anchor_before]
        );

        let (_root_after, namespace_after) = namespace_v2();
        let (journal_after, anchor_after) = SqliteG2ManifestBoundJournalV2::initialize_new_v2(
            &namespace_after,
            [0x61; 32],
            [0x62; 32],
        )
        .expect("after-commit anchor");
        let target_after = anchor_after
            .persisted_successor_v2(synthetic_snapshot_v2(0x32))
            .expect("after target");
        assert_eq!(
            journal_after
                .advance_with_fault_v2(
                    &anchor_after,
                    &target_after,
                    JournalFaultV2::AfterCommitBeforeReturn,
                )
                .expect("target readback resolves lost response"),
            target_after
        );
    }

    #[test]
    fn exact_join_foreign_mutants_and_third_state_never_mint_owner() {
        let (_root, namespace) = namespace_v2();
        let (journal, anchor) =
            SqliteG2ManifestBoundJournalV2::initialize_new_v2(&namespace, JOURNAL_ID, SCOPE)
                .expect("initialize anchor");
        let exact = synthetic_snapshot_v2(0x41);
        let foreign = synthetic_snapshot_v2(0x42);
        let target = anchor
            .persisted_successor_v2(exact.clone())
            .expect("exact target");
        journal.advance_v2(&anchor, &target).expect("persist exact");
        assert_eq!(
            require_exact_snapshot_v2(&target, &foreign)
                .expect_err("foreign snapshot rejects")
                .code_v2(),
            PocoNodeG2ManifestBoundErrorCodeV2::ExactJoinMismatch
        );
        require_exact_snapshot_v2(&target, &exact).expect("exact snapshot recovers");
        // Every fixed request/root/plane/receipt/final digest region remains
        // part of the raw exact comparison even if an attacker can recompute a
        // self-consistent data-only snapshot commitment.
        for offset in [10_usize, 50, 82, 338, 370, 448, 908, 940, 972] {
            let mut raw = exact.raw.clone();
            raw[offset] ^= 1;
            let mutant = CanonicalJoinSnapshotV2::from_raw_v2(raw)
                .expect("nonzero self-consistent data mutant");
            assert_eq!(
                require_exact_snapshot_v2(&target, &mutant)
                    .expect_err("field substitution rejects")
                    .code_v2(),
                PocoNodeG2ManifestBoundErrorCodeV2::ExactJoinMismatch
            );
        }
        assert_eq!(
            journal.audit_fresh_v2().expect("mutants do not mutate"),
            vec![anchor.clone(), target.clone()]
        );

        let competing = anchor
            .persisted_successor_v2(synthetic_snapshot_v2(0x43))
            .expect("competing target");
        let error = journal
            .advance_v2(&anchor, &competing)
            .expect_err("third state rejects");
        assert_eq!(
            error.code_v2(),
            PocoNodeG2ManifestBoundErrorCodeV2::ThirdJournalState
        );
    }

    #[test]
    fn exact_join_torn_schema_identity_and_sidecars_fail_closed() {
        let (_root, namespace) = namespace_v2();
        let (journal, anchor) =
            SqliteG2ManifestBoundJournalV2::initialize_new_v2(&namespace, JOURNAL_ID, SCOPE)
                .expect("initialize anchor");
        let target = anchor
            .persisted_successor_v2(synthetic_snapshot_v2(0x51))
            .expect("target");
        let connection = open_rw_raw_v2(&journal.path).expect("raw test connection");
        connection
            .execute(
                "INSERT INTO g2_manifest_bound_history_v2(generation,phase,predecessor_checksum,join_commitment,checksum,record) VALUES(?1,1,?2,?3,?4,?5)",
                params![
                    &target.generation.to_be_bytes()[..],
                    &target.predecessor_checksum[..],
                    &target.join_commitment_v2().expect("commitment")[..],
                    &target.checksum[..],
                    target.encode_v2().expect("record"),
                ],
            )
            .expect("inject history-only tear");
        drop(connection);
        assert_eq!(
            journal
                .audit_fresh_v2()
                .expect_err("metadata/history tear rejects")
                .code_v2(),
            PocoNodeG2ManifestBoundErrorCodeV2::JournalTamper
        );

        let (_schema_root, schema_namespace) = namespace_v2();
        let (schema_journal, _) = SqliteG2ManifestBoundJournalV2::initialize_new_v2(
            &schema_namespace,
            [0x71; 32],
            [0x72; 32],
        )
        .expect("schema anchor");
        let connection = open_rw_raw_v2(&schema_journal.path).expect("schema connection");
        connection
            .execute("CREATE TABLE foreign_schema(value INTEGER)", [])
            .expect("inject extra schema");
        drop(connection);
        assert_eq!(
            schema_journal
                .audit_fresh_v2()
                .expect_err("extra schema rejects")
                .code_v2(),
            PocoNodeG2ManifestBoundErrorCodeV2::JournalSchemaMismatch
        );

        let (_sidecar_root, sidecar_namespace) = namespace_v2();
        let (sidecar_journal, _) = SqliteG2ManifestBoundJournalV2::initialize_new_v2(
            &sidecar_namespace,
            [0x73; 32],
            [0x74; 32],
        )
        .expect("sidecar anchor");
        let mut sidecar_path = OsString::from(sidecar_journal.path.as_os_str());
        sidecar_path.push("-wal");
        let mut sidecar = fs::File::create(PathBuf::from(sidecar_path)).expect("create sidecar");
        sidecar.write_all(b"forbidden").expect("write sidecar");
        drop(sidecar);
        assert_eq!(
            sidecar_journal
                .audit_fresh_v2()
                .expect_err("sidecar rejects")
                .code_v2(),
            PocoNodeG2ManifestBoundErrorCodeV2::JournalUnavailable
        );
    }

    #[test]
    fn exact_join_external_pin_rejects_database_only_rollback() {
        let (_root, namespace) = namespace_v2();
        let (journal, anchor) =
            SqliteG2ManifestBoundJournalV2::initialize_new_v2(&namespace, JOURNAL_ID, SCOPE)
                .expect("initialize anchor");
        let anchor_copy = namespace.directory.join("anchor-copy.sqlite");
        fs::copy(&journal.path, &anchor_copy).expect("copy coherent anchor");
        fs::set_permissions(&anchor_copy, fs::Permissions::from_mode(0o600)).expect("copy mode");
        let target = anchor
            .persisted_successor_v2(synthetic_snapshot_v2(0x61))
            .expect("target");
        journal
            .advance_v2(&anchor, &target)
            .expect("persist target");
        let target_pin = target.pin_v2();
        fs::copy(&anchor_copy, &journal.path).expect("whole-database rollback");
        let error = SqliteG2ManifestBoundJournalV2::open_existing_v2(&namespace, &target_pin)
            .expect_err("target pin rejects anchor rollback");
        assert_eq!(
            error.code_v2(),
            PocoNodeG2ManifestBoundErrorCodeV2::JournalRollback
        );
    }

    #[test]
    fn exact_join_immutable_preflight_rejects_file_replacement() {
        let (_root, namespace) = namespace_v2();
        let (journal, _) =
            SqliteG2ManifestBoundJournalV2::initialize_new_v2(&namespace, JOURNAL_ID, SCOPE)
                .expect("initialize original");
        let (read_only, identity) =
            open_existing_ro_preflight_v2(&journal.path).expect("immutable preflight");
        drop(read_only);

        let (_replacement_root, replacement_namespace) = namespace_v2();
        let (replacement, _) = SqliteG2ManifestBoundJournalV2::initialize_new_v2(
            &replacement_namespace,
            [0x75; 32],
            [0x76; 32],
        )
        .expect("initialize replacement");
        let displaced = namespace.directory.join("displaced.sqlite");
        fs::rename(&journal.path, &displaced).expect("displace original inode");
        fs::rename(&replacement.path, &journal.path).expect("replace journal inode");
        let error = open_rw_matching_preflight_v2(&journal.path, identity)
            .expect_err("read-write open rejects preflight replacement");
        assert_eq!(
            error.code_v2(),
            PocoNodeG2ManifestBoundErrorCodeV2::JournalUnavailable
        );
    }

    #[test]
    fn exact_join_raw_record_pin_and_preview_have_no_owner_ingress() {
        type ExactIngressV2 = fn(
            PocoNodeG2ManifestBoundCandidateLocalStoreV2,
            G2CandidateLocalFinalizeJoinV2,
        ) -> ResultV2<PocoNodeG2ManifestBoundCandidateLocalOwnerV2>;
        fn require_exact_ingress(_: ExactIngressV2) {}
        require_exact_ingress(
            PocoNodeG2ManifestBoundCandidateLocalStoreV2::consume_exact_finalize_join_v2,
        );

        let module = include_str!("g2_manifest_bound_v2.rs");
        let production = module
            .split_once("#[cfg(test)]\nmod tests")
            .expect("focused tests remain separated")
            .0;
        assert_eq!(
            production
                .matches("exact_join: G2CandidateLocalFinalizeJoinV2")
                .count(),
            2,
            "one owner field plus one typed consuming ingress"
        );
        assert!(production.contains("journal: SqliteG2ManifestBoundJournalV2"));
        assert_eq!(
            production.matches("fn revalidate_fresh_exact_v2(").count(),
            1
        );
        let owner_impl = production
            .split_once("impl PocoNodeG2ManifestBoundCandidateLocalOwnerV2")
            .expect("owner implementation remains explicit")
            .1
            .split_once("fn require_exact_snapshot_v2")
            .expect("owner implementation remains bounded")
            .0;
        for forbidden_escape in [
            "into_journal",
            "journal_mut",
            "journal_v2(&self)",
            "snapshot_v2(&self)",
            "record_v2(&self)",
            "exact_join_v2(&self)",
        ] {
            assert!(
                !owner_impl.contains(forbidden_escape),
                "owner escape surface: {forbidden_escape}"
            );
        }
        for forbidden in [
            "ManifestBoundGlobalExecutionInputV2",
            "G2CandidateLocalPreviewBindingV2",
            "G2FinalizeBindingRequestV2",
            "G2InertExecutionPlanV2",
            "PreVoteExecutionReadyV1",
            "WholeNodeFinalizationOwnerV1",
            "VerifiedOrderFinalityV1",
            "trnm_consensus_core",
            "trnm_consensus_signer_journal",
            "broadcast",
            "OutboundMessage",
            "Core<",
        ] {
            assert!(
                !production.contains(forbidden),
                "foreign authority ingress: {forbidden}"
            );
        }
        assert!(!production.contains("impl Clone for PocoNodeG2ManifestBoundCandidateLocalOwnerV2"));
        assert!(!production.contains("BorshDeserialize"));
    }
}
