//! Durable append-only epoch-transition journal.
//!
//! The journal is the first persistent boundary after strict checkpoint/seal/
//! handoff verification. It stores canonical `EpochPreparationRecordV1` bytes
//! and immutable checkpoint coordinates, but never turns a record into Core or
//! signing authority. Reopening therefore still requires strict recovery with
//! an independently trusted old validator set and parameter set for each
//! transition.
//!
//! Earlier candidate builds used a two-slot SQLite table because the P0
//! acceptance target required two consecutive transitions. That acceptance
//! minimum is not a runtime lifetime limit: this implementation migrates those
//! rows into an append-only stream and permits an arbitrary contiguous sequence
//! bounded by SQLite's signed integer key space.

use std::{
    error::Error,
    fmt,
    path::{Path, PathBuf},
};

use rusqlite::{params, Connection};
use trnm_consensus_core::{recover_epoch_preparation_v1, EpochPreparationV1};
use trnm_consensus_types::{Cev0AdmissionBudgetV0, ConsensusParametersV0, ValidatorSet};

const LEGACY_TABLE: &str = "trnm_epoch_transition_journal_v1";
const STREAM_SCHEMA: &str = "CREATE TABLE IF NOT EXISTS trnm_epoch_transition_stream_v1 (\
 sequence INTEGER PRIMARY KEY CHECK(sequence >= 0),\
 old_epoch INTEGER NOT NULL CHECK(old_epoch >= 0),\
 new_epoch INTEGER NOT NULL CHECK(new_epoch >= 0),\
 checkpoint_generation INTEGER NOT NULL CHECK(checkpoint_generation > 0),\
 checkpoint_checksum BLOB NOT NULL CHECK(length(checkpoint_checksum)=32),\
 binding_ref BLOB NOT NULL CHECK(length(binding_ref)=32),\
 preparation BLOB NOT NULL);";

#[derive(Debug)]
pub enum EpochTransitionJournalErrorV1 {
    Io(rusqlite::Error),
    Invalid(&'static str),
    SlotAlreadyWritten(u64),
    SlotOrder { expected: u64, received: u64 },
    EpochDiscontinuity { expected: u64, received: u64 },
    CheckpointGenerationRegression,
    BindingMismatch,
    Recovery(trnm_consensus_core::EpochPreparationErrorV1),
}

impl fmt::Display for EpochTransitionJournalErrorV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "epoch journal sqlite: {error}"),
            Self::Invalid(message) => write!(f, "epoch journal invalid: {message}"),
            Self::SlotAlreadyWritten(slot) => {
                write!(f, "epoch journal sequence {slot} already written")
            }
            Self::SlotOrder { expected, received } => write!(
                f,
                "epoch journal expected sequence {expected}, received {received}"
            ),
            Self::EpochDiscontinuity { expected, received } => write!(
                f,
                "epoch journal expected old epoch {expected}, received {received}"
            ),
            Self::CheckpointGenerationRegression => {
                f.write_str("epoch journal checkpoint generation regressed")
            }
            Self::BindingMismatch => f.write_str(
                "epoch journal binding/checkpoint coordinates are zero or inconsistent",
            ),
            Self::Recovery(error) => write!(f, "epoch journal strict recovery: {error}"),
        }
    }
}

impl Error for EpochTransitionJournalErrorV1 {}

impl From<rusqlite::Error> for EpochTransitionJournalErrorV1 {
    fn from(error: rusqlite::Error) -> Self {
        Self::Io(error)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpochTransitionJournalEntryV1 {
    /// Zero-based durable append sequence. The historical `slot` name is kept
    /// for API compatibility; it is no longer limited to 0 or 1.
    pub slot: u64,
    pub old_epoch: u64,
    pub new_epoch: u64,
    pub checkpoint_generation: u64,
    pub checkpoint_checksum: [u8; 32],
    pub binding_ref: [u8; 32],
    pub preparation: Vec<u8>,
}

pub struct EpochTransitionJournalV1 {
    path: PathBuf,
    conn: Connection,
}

impl fmt::Debug for EpochTransitionJournalV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EpochTransitionJournalV1")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl EpochTransitionJournalV1 {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, EpochTransitionJournalErrorV1> {
        let path = path.as_ref().to_path_buf();
        let conn = Connection::open(&path)?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;")?;
        conn.execute_batch(STREAM_SCHEMA)?;
        migrate_legacy_two_slot_rows(&conn)?;
        let journal = Self { path, conn };
        journal.entries()?;
        Ok(journal)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn entries(
        &self,
    ) -> Result<Vec<EpochTransitionJournalEntryV1>, EpochTransitionJournalErrorV1> {
        let mut statement = self.conn.prepare(
            "SELECT sequence,old_epoch,new_epoch,checkpoint_generation,\
             checkpoint_checksum,binding_ref,preparation \
             FROM trnm_epoch_transition_stream_v1 ORDER BY sequence",
        )?;
        let rows = statement.query_map([], |row| {
            let sequence: i64 = row.get(0)?;
            let checksum: Vec<u8> = row.get(4)?;
            let binding: Vec<u8> = row.get(5)?;
            let preparation: Vec<u8> = row.get(6)?;
            Ok((
                sequence,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
                checksum,
                binding,
                preparation,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (sequence, old, new, generation, checksum, binding, preparation) = row?;
            if sequence < 0
                || old < 0
                || new < 0
                || generation <= 0
                || checksum.len() != 32
                || binding.len() != 32
            {
                return Err(EpochTransitionJournalErrorV1::Invalid(
                    "row shape or integer range",
                ));
            }
            let mut checkpoint_checksum = [0; 32];
            checkpoint_checksum.copy_from_slice(&checksum);
            let mut binding_ref = [0; 32];
            binding_ref.copy_from_slice(&binding);
            out.push(EpochTransitionJournalEntryV1 {
                slot: sequence as u64,
                old_epoch: old as u64,
                new_epoch: new as u64,
                checkpoint_generation: generation as u64,
                checkpoint_checksum,
                binding_ref,
                preparation,
            });
        }
        validate_entries(&out)?;
        Ok(out)
    }

    /// Append one strictly verified preparation. The stream requires exact
    /// epoch continuity and monotonically increasing checkpoint generations.
    pub fn append_verified(
        &mut self,
        preparation: &EpochPreparationV1,
        checkpoint_generation: u64,
        checkpoint_checksum: [u8; 32],
    ) -> Result<u64, EpochTransitionJournalErrorV1> {
        if checkpoint_generation == 0 || checkpoint_checksum == [0; 32] {
            return Err(EpochTransitionJournalErrorV1::BindingMismatch);
        }
        let entries = self.entries()?;
        let sequence = entries.len() as u64;
        if sequence > i64::MAX as u64
            || checkpoint_generation > i64::MAX as u64
        {
            return Err(EpochTransitionJournalErrorV1::Invalid(
                "journal coordinate exceeds sqlite integer range",
            ));
        }

        let authority = preparation.authority_v1();
        let old = authority.joint_handoff().old_epoch().get();
        let new = authority.joint_handoff().new_epoch().get();
        if old > i64::MAX as u64 || new > i64::MAX as u64 {
            return Err(EpochTransitionJournalErrorV1::Invalid(
                "epoch exceeds sqlite integer range",
            ));
        }
        if new != old.saturating_add(1) {
            return Err(EpochTransitionJournalErrorV1::EpochDiscontinuity {
                expected: old.saturating_add(1),
                received: new,
            });
        }
        if let Some(previous) = entries.last() {
            if old != previous.new_epoch {
                return Err(EpochTransitionJournalErrorV1::EpochDiscontinuity {
                    expected: previous.new_epoch,
                    received: old,
                });
            }
            if checkpoint_generation <= previous.checkpoint_generation {
                return Err(EpochTransitionJournalErrorV1::CheckpointGenerationRegression);
            }
        }

        let bytes = preparation
            .record_v1()
            .encode_v1()
            .map_err(|_| EpochTransitionJournalErrorV1::Invalid("noncanonical preparation record"))?;
        let binding = preparation.record_v1().binding_ref_v1();
        if binding == [0; 32] {
            return Err(EpochTransitionJournalErrorV1::BindingMismatch);
        }
        let transaction = self.conn.transaction()?;
        transaction.execute(
            "INSERT INTO trnm_epoch_transition_stream_v1 \
             (sequence,old_epoch,new_epoch,checkpoint_generation,checkpoint_checksum,binding_ref,preparation) \
             VALUES (?1,?2,?3,?4,?5,?6,?7)",
            params![
                sequence as i64,
                old as i64,
                new as i64,
                checkpoint_generation as i64,
                checkpoint_checksum.as_slice(),
                binding.as_slice(),
                bytes
            ],
        )?;
        transaction.commit()?;
        Ok(sequence)
    }

    /// Strictly recover one transition after a process restart. Persisted bytes
    /// never suffice to activate a validator set.
    pub fn recover_entry(
        &self,
        slot: u64,
        trusted_old_set: &ValidatorSet,
        trusted_old_parameters: &ConsensusParametersV0,
        budget: &mut Cev0AdmissionBudgetV0,
    ) -> Result<EpochPreparationV1, EpochTransitionJournalErrorV1> {
        let entry = self
            .entries()?
            .into_iter()
            .find(|entry| entry.slot == slot)
            .ok_or(EpochTransitionJournalErrorV1::Invalid(
                "requested sequence is absent",
            ))?;
        recover_epoch_preparation_v1(
            &entry.preparation,
            trusted_old_set,
            trusted_old_parameters,
            entry.binding_ref,
            budget,
        )
        .map_err(EpochTransitionJournalErrorV1::Recovery)
    }

    /// P0 requires at least two consecutive transitions; reaching that minimum
    /// must not make the runtime unable to append epoch 3 and beyond.
    pub fn has_minimum_two_transitions(
        &self,
    ) -> Result<bool, EpochTransitionJournalErrorV1> {
        Ok(self.entries()?.len() >= 2)
    }

    /// Backward-compatible name for the old P0 acceptance query.
    pub fn is_complete(&self) -> Result<bool, EpochTransitionJournalErrorV1> {
        self.has_minimum_two_transitions()
    }
}

fn table_exists(conn: &Connection, table: &str) -> Result<bool, rusqlite::Error> {
    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1",
        params![table],
        |row| row.get(0),
    )?;
    Ok(count == 1)
}

fn migrate_legacy_two_slot_rows(
    conn: &Connection,
) -> Result<(), EpochTransitionJournalErrorV1> {
    if !table_exists(conn, LEGACY_TABLE)? {
        return Ok(());
    }
    let stream_count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM trnm_epoch_transition_stream_v1",
        [],
        |row| row.get(0),
    )?;
    if stream_count != 0 {
        return Ok(());
    }
    conn.execute(
        "INSERT INTO trnm_epoch_transition_stream_v1 \
         (sequence,old_epoch,new_epoch,checkpoint_generation,checkpoint_checksum,binding_ref,preparation) \
         SELECT slot,old_epoch,new_epoch,checkpoint_generation,checkpoint_checksum,binding_ref,preparation \
         FROM trnm_epoch_transition_journal_v1 ORDER BY slot",
        [],
    )?;
    Ok(())
}

fn validate_entries(
    entries: &[EpochTransitionJournalEntryV1],
) -> Result<(), EpochTransitionJournalErrorV1> {
    for (index, entry) in entries.iter().enumerate() {
        let expected = index as u64;
        if entry.slot != expected {
            return Err(EpochTransitionJournalErrorV1::SlotOrder {
                expected,
                received: entry.slot,
            });
        }
        if entry.binding_ref == [0; 32]
            || entry.checkpoint_checksum == [0; 32]
            || entry.checkpoint_generation == 0
        {
            return Err(EpochTransitionJournalErrorV1::BindingMismatch);
        }
        if entry.new_epoch != entry.old_epoch.saturating_add(1) {
            return Err(EpochTransitionJournalErrorV1::EpochDiscontinuity {
                expected: entry.old_epoch.saturating_add(1),
                received: entry.new_epoch,
            });
        }
        if index > 0 {
            let previous = &entries[index - 1];
            if entry.old_epoch != previous.new_epoch {
                return Err(EpochTransitionJournalErrorV1::EpochDiscontinuity {
                    expected: previous.new_epoch,
                    received: entry.old_epoch,
                });
            }
            if entry.checkpoint_generation <= previous.checkpoint_generation {
                return Err(EpochTransitionJournalErrorV1::CheckpointGenerationRegression);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn empty_journal_reopens_and_is_incomplete() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("epoch.sqlite");
        let journal = EpochTransitionJournalV1::open(&path).unwrap();
        assert!(journal.entries().unwrap().is_empty());
        assert!(!journal.is_complete().unwrap());
        drop(journal);
        let reopened = EpochTransitionJournalV1::open(&path).unwrap();
        assert!(reopened.entries().unwrap().is_empty());
    }

    #[test]
    fn tampered_epoch_coordinate_is_rejected_on_reopen() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("epoch.sqlite");
        let journal = EpochTransitionJournalV1::open(&path).unwrap();
        drop(journal);
        let conn = Connection::open(&path).unwrap();
        conn.execute(
            "INSERT INTO trnm_epoch_transition_stream_v1 \
             (sequence,old_epoch,new_epoch,checkpoint_generation,checkpoint_checksum,binding_ref,preparation) \
             VALUES (0,0,2,1,?1,?2,?3)",
            params![[1u8; 32], [2u8; 32], vec![0u8; 1]],
        )
        .unwrap();
        drop(conn);
        assert!(matches!(
            EpochTransitionJournalV1::open(&path),
            Err(EpochTransitionJournalErrorV1::EpochDiscontinuity { .. })
        ));
    }

    #[test]
    fn legacy_two_slot_rows_migrate_without_becoming_a_runtime_cap() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("epoch.sqlite");
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE trnm_epoch_transition_journal_v1 (\
             slot INTEGER PRIMARY KEY CHECK(slot IN (0,1)),\
             old_epoch INTEGER NOT NULL CHECK(old_epoch >= 0),\
             new_epoch INTEGER NOT NULL CHECK(new_epoch >= 0),\
             checkpoint_generation INTEGER NOT NULL CHECK(checkpoint_generation > 0),\
             checkpoint_checksum BLOB NOT NULL CHECK(length(checkpoint_checksum)=32),\
             binding_ref BLOB NOT NULL CHECK(length(binding_ref)=32),\
             preparation BLOB NOT NULL);",
        )
        .unwrap();
        for slot in 0..2_i64 {
            conn.execute(
                "INSERT INTO trnm_epoch_transition_journal_v1 \
                 (slot,old_epoch,new_epoch,checkpoint_generation,checkpoint_checksum,binding_ref,preparation) \
                 VALUES (?1,?2,?3,?4,?5,?6,?7)",
                params![
                    slot,
                    slot,
                    slot + 1,
                    slot + 1,
                    [1u8; 32],
                    [2u8; 32],
                    vec![slot as u8]
                ],
            )
            .unwrap();
        }
        drop(conn);

        let journal = EpochTransitionJournalV1::open(&path).unwrap();
        assert_eq!(journal.entries().unwrap().len(), 2);
        assert!(journal.has_minimum_two_transitions().unwrap());
        drop(journal);

        let conn = Connection::open(&path).unwrap();
        conn.execute(
            "INSERT INTO trnm_epoch_transition_stream_v1 \
             (sequence,old_epoch,new_epoch,checkpoint_generation,checkpoint_checksum,binding_ref,preparation) \
             VALUES (2,2,3,3,?1,?2,?3)",
            params![[1u8; 32], [2u8; 32], vec![2u8]],
        )
        .unwrap();
        drop(conn);
        let reopened = EpochTransitionJournalV1::open(&path).unwrap();
        assert_eq!(reopened.entries().unwrap().len(), 3);
    }

    #[test]
    fn p0_two_transition_minimum_does_not_cap_later_epochs() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("epoch.sqlite");
        let journal = EpochTransitionJournalV1::open(&path).unwrap();
        drop(journal);
        let conn = Connection::open(&path).unwrap();
        for sequence in 0..3_i64 {
            conn.execute(
                "INSERT INTO trnm_epoch_transition_stream_v1 \
                 (sequence,old_epoch,new_epoch,checkpoint_generation,checkpoint_checksum,binding_ref,preparation) \
                 VALUES (?1,?2,?3,?4,?5,?6,?7)",
                params![
                    sequence,
                    sequence,
                    sequence + 1,
                    sequence + 1,
                    [1u8; 32],
                    [2u8; 32],
                    vec![sequence as u8]
                ],
            )
            .unwrap();
        }
        drop(conn);
        let reopened = EpochTransitionJournalV1::open(&path).unwrap();
        assert_eq!(reopened.entries().unwrap().len(), 3);
        assert!(reopened.has_minimum_two_transitions().unwrap());
    }
}
