//! Durable append-only epoch-transition journal.
//!
//! The former v1 table was deliberately capped at two rows because the first
//! acceptance campaign required two transitions.  That was an acceptance
//! minimum, not a valid runtime capacity limit.  This implementation migrates
//! those rows into an append-only table and preserves strict, consecutive epoch
//! and checkpoint-generation ordering for every later transition.
//!
//! Journal bytes are recovery inputs only.  They never mint Core, SafetyRules,
//! validator-set, or signing authority without strict re-verification against
//! independently trusted old-epoch context.

use std::{
    error::Error,
    fmt,
    path::{Path, PathBuf},
};

use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use trnm_consensus_core::{recover_epoch_preparation_v1, EpochPreparationV1};
use trnm_consensus_types::{Cev0AdmissionBudgetV0, ConsensusParametersV0, ValidatorSet};

const LEGACY_TABLE: &str = "trnm_epoch_transition_journal_v1";
const ACTIVE_TABLE: &str = "trnm_epoch_transition_journal_v2";
const ACTIVE_SCHEMA: &str = "CREATE TABLE IF NOT EXISTS trnm_epoch_transition_journal_v2 (\
 transition_index INTEGER PRIMARY KEY CHECK(transition_index >= 0),\
 old_epoch INTEGER NOT NULL CHECK(old_epoch >= 0),\
 new_epoch INTEGER NOT NULL CHECK(new_epoch >= 0),\
 checkpoint_generation INTEGER NOT NULL CHECK(checkpoint_generation > 0),\
 checkpoint_checksum BLOB NOT NULL CHECK(length(checkpoint_checksum)=32),\
 binding_ref BLOB NOT NULL CHECK(length(binding_ref)=32),\
 preparation BLOB NOT NULL,\
 UNIQUE(old_epoch),\
 UNIQUE(new_epoch));";

#[derive(Debug)]
pub enum EpochTransitionJournalErrorV1 {
    Sqlite(rusqlite::Error),
    Invalid(&'static str),
    TransitionOrder { expected: u64, received: u64 },
    EpochDiscontinuity { expected: u64, received: u64 },
    CheckpointGenerationRegression,
    BindingMismatch,
    IntegerRange(&'static str),
    LegacyConflict,
    Recovery(trnm_consensus_core::EpochPreparationErrorV1),
}

impl fmt::Display for EpochTransitionJournalErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sqlite(error) => write!(formatter, "epoch journal sqlite: {error}"),
            Self::Invalid(reason) => write!(formatter, "epoch journal invalid: {reason}"),
            Self::TransitionOrder { expected, received } => write!(
                formatter,
                "epoch journal expected transition {expected}, received {received}",
            ),
            Self::EpochDiscontinuity { expected, received } => write!(
                formatter,
                "epoch journal expected epoch coordinate {expected}, received {received}",
            ),
            Self::CheckpointGenerationRegression => {
                formatter.write_str("epoch journal checkpoint generation regressed")
            }
            Self::BindingMismatch => formatter
                .write_str("epoch journal binding/checkpoint coordinates are zero or inconsistent"),
            Self::IntegerRange(field) => {
                write!(formatter, "epoch journal {field} exceeds SQLite INTEGER")
            }
            Self::LegacyConflict => formatter
                .write_str("epoch journal v1/v2 histories disagree; refusing automatic migration"),
            Self::Recovery(error) => write!(formatter, "epoch journal strict recovery: {error}"),
        }
    }
}

impl Error for EpochTransitionJournalErrorV1 {}

impl From<rusqlite::Error> for EpochTransitionJournalErrorV1 {
    fn from(error: rusqlite::Error) -> Self {
        Self::Sqlite(error)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpochTransitionJournalEntryV1 {
    pub transition_index: u64,
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
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EpochTransitionJournalV1")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl EpochTransitionJournalV1 {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, EpochTransitionJournalErrorV1> {
        let path = path.as_ref().to_path_buf();
        let mut conn = Connection::open(&path)?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;")?;
        conn.execute_batch(ACTIVE_SCHEMA)?;
        migrate_legacy_if_present(&mut conn)?;
        validate_entries(&read_entries(&conn, ACTIVE_TABLE, "transition_index")?)?;
        Ok(Self { path, conn })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn entries(
        &self,
    ) -> Result<Vec<EpochTransitionJournalEntryV1>, EpochTransitionJournalErrorV1> {
        read_entries(&self.conn, ACTIVE_TABLE, "transition_index")
    }

    pub fn latest_entry(
        &self,
    ) -> Result<Option<EpochTransitionJournalEntryV1>, EpochTransitionJournalErrorV1> {
        Ok(self.entries()?.pop())
    }

    /// Append one strictly verified preparation.  The two-transition P0
    /// criterion is only a minimum acceptance prefix; it never closes history.
    pub fn append_verified(
        &mut self,
        preparation: &EpochPreparationV1,
        checkpoint_generation: u64,
        checkpoint_checksum: [u8; 32],
    ) -> Result<u64, EpochTransitionJournalErrorV1> {
        if checkpoint_generation == 0 || checkpoint_checksum == [0; 32] {
            return Err(EpochTransitionJournalErrorV1::BindingMismatch);
        }
        let previous = self.latest_entry()?;
        let transition_index = match previous.as_ref() {
            Some(entry) => entry.transition_index.checked_add(1).ok_or(
                EpochTransitionJournalErrorV1::IntegerRange("transition index"),
            )?,
            None => 0,
        };

        let handoff = preparation.authority_v1().joint_handoff();
        let old_epoch = handoff.old_epoch().get();
        let new_epoch = handoff.new_epoch().get();
        let expected_new = old_epoch
            .checked_add(1)
            .ok_or(EpochTransitionJournalErrorV1::IntegerRange("epoch"))?;
        if new_epoch != expected_new {
            return Err(EpochTransitionJournalErrorV1::EpochDiscontinuity {
                expected: expected_new,
                received: new_epoch,
            });
        }
        if let Some(previous) = previous.as_ref() {
            if old_epoch != previous.new_epoch {
                return Err(EpochTransitionJournalErrorV1::EpochDiscontinuity {
                    expected: previous.new_epoch,
                    received: old_epoch,
                });
            }
            if checkpoint_generation <= previous.checkpoint_generation {
                return Err(EpochTransitionJournalErrorV1::CheckpointGenerationRegression);
            }
        }

        let record = preparation.record_v1();
        let binding_ref = record.binding_ref_v1();
        if binding_ref == [0; 32] {
            return Err(EpochTransitionJournalErrorV1::BindingMismatch);
        }
        let bytes = record.encode_v1().map_err(|_| {
            EpochTransitionJournalErrorV1::Invalid("noncanonical preparation record")
        })?;
        let transaction = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute(
            "INSERT INTO trnm_epoch_transition_journal_v2 (transition_index,old_epoch,new_epoch,checkpoint_generation,checkpoint_checksum,binding_ref,preparation) VALUES (?1,?2,?3,?4,?5,?6,?7)",
            params![
                sql_integer(transition_index, "transition index")?,
                sql_integer(old_epoch, "old epoch")?,
                sql_integer(new_epoch, "new epoch")?,
                sql_integer(checkpoint_generation, "checkpoint generation")?,
                checkpoint_checksum.as_slice(),
                binding_ref.as_slice(),
                bytes,
            ],
        )?;
        transaction.commit()?;
        Ok(transition_index)
    }

    pub fn recover_entry(
        &self,
        transition_index: u64,
        trusted_old_set: &ValidatorSet,
        trusted_old_parameters: &ConsensusParametersV0,
        budget: &mut Cev0AdmissionBudgetV0,
    ) -> Result<EpochPreparationV1, EpochTransitionJournalErrorV1> {
        let entry = self
            .entries()?
            .into_iter()
            .find(|entry| entry.transition_index == transition_index)
            .ok_or(EpochTransitionJournalErrorV1::Invalid(
                "requested transition is absent",
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

    pub fn has_minimum_acceptance_prefix(
        &self,
        minimum_transitions: usize,
    ) -> Result<bool, EpochTransitionJournalErrorV1> {
        if minimum_transitions == 0 {
            return Err(EpochTransitionJournalErrorV1::Invalid(
                "acceptance minimum must be positive",
            ));
        }
        Ok(self.entries()?.len() >= minimum_transitions)
    }

    /// Compatibility name for the historical P0 milestone.  Completion here
    /// means “at least two validated transitions”, never “journal is full”.
    pub fn is_complete(&self) -> Result<bool, EpochTransitionJournalErrorV1> {
        self.has_minimum_acceptance_prefix(2)
    }
}

type RawEntry = (i64, i64, i64, i64, Vec<u8>, Vec<u8>, Vec<u8>);

fn decode_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawEntry> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
    ))
}

fn decode_entry(
    raw: RawEntry,
) -> Result<EpochTransitionJournalEntryV1, EpochTransitionJournalErrorV1> {
    let (index, old, new, generation, checksum, binding, preparation) = raw;
    if index < 0
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
    let mut checkpoint_checksum = [0_u8; 32];
    checkpoint_checksum.copy_from_slice(&checksum);
    let mut binding_ref = [0_u8; 32];
    binding_ref.copy_from_slice(&binding);
    Ok(EpochTransitionJournalEntryV1 {
        transition_index: index as u64,
        old_epoch: old as u64,
        new_epoch: new as u64,
        checkpoint_generation: generation as u64,
        checkpoint_checksum,
        binding_ref,
        preparation,
    })
}

fn read_entries(
    conn: &Connection,
    table: &str,
    index_column: &str,
) -> Result<Vec<EpochTransitionJournalEntryV1>, EpochTransitionJournalErrorV1> {
    let sql = format!(
        "SELECT {index_column},old_epoch,new_epoch,checkpoint_generation,checkpoint_checksum,binding_ref,preparation FROM {table} ORDER BY {index_column}"
    );
    let mut statement = conn.prepare(&sql)?;
    let rows = statement.query_map([], decode_row)?;
    let mut entries = Vec::new();
    for row in rows {
        entries.push(decode_entry(row?)?);
    }
    validate_entries(&entries)?;
    Ok(entries)
}

fn validate_entries(
    entries: &[EpochTransitionJournalEntryV1],
) -> Result<(), EpochTransitionJournalErrorV1> {
    for (position, entry) in entries.iter().enumerate() {
        let expected_index = u64::try_from(position)
            .map_err(|_| EpochTransitionJournalErrorV1::IntegerRange("transition index"))?;
        if entry.transition_index != expected_index {
            return Err(EpochTransitionJournalErrorV1::TransitionOrder {
                expected: expected_index,
                received: entry.transition_index,
            });
        }
        if entry.binding_ref == [0; 32] || entry.checkpoint_checksum == [0; 32] {
            return Err(EpochTransitionJournalErrorV1::BindingMismatch);
        }
        let expected_new = entry
            .old_epoch
            .checked_add(1)
            .ok_or(EpochTransitionJournalErrorV1::IntegerRange("epoch"))?;
        if entry.new_epoch != expected_new {
            return Err(EpochTransitionJournalErrorV1::EpochDiscontinuity {
                expected: expected_new,
                received: entry.new_epoch,
            });
        }
        if let Some(previous) = position.checked_sub(1).and_then(|index| entries.get(index)) {
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

fn sql_integer(value: u64, field: &'static str) -> Result<i64, EpochTransitionJournalErrorV1> {
    i64::try_from(value).map_err(|_| EpochTransitionJournalErrorV1::IntegerRange(field))
}

fn table_exists(conn: &Connection, name: &str) -> Result<bool, EpochTransitionJournalErrorV1> {
    Ok(conn
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1",
            [name],
            |row| row.get::<_, i64>(0),
        )
        .optional()?
        .is_some())
}

fn migrate_legacy_if_present(conn: &mut Connection) -> Result<(), EpochTransitionJournalErrorV1> {
    if !table_exists(conn, LEGACY_TABLE)? {
        return Ok(());
    }
    let legacy = read_entries(conn, LEGACY_TABLE, "slot")?;
    if legacy.is_empty() {
        return Ok(());
    }
    let current = read_entries(conn, ACTIVE_TABLE, "transition_index")?;
    if !current.is_empty() {
        if current.len() < legacy.len() || current[..legacy.len()] != legacy[..] {
            return Err(EpochTransitionJournalErrorV1::LegacyConflict);
        }
        return Ok(());
    }

    let transaction = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    for entry in legacy {
        transaction.execute(
            "INSERT INTO trnm_epoch_transition_journal_v2 (transition_index,old_epoch,new_epoch,checkpoint_generation,checkpoint_checksum,binding_ref,preparation) VALUES (?1,?2,?3,?4,?5,?6,?7)",
            params![
                sql_integer(entry.transition_index, "transition index")?,
                sql_integer(entry.old_epoch, "old epoch")?,
                sql_integer(entry.new_epoch, "new epoch")?,
                sql_integer(entry.checkpoint_generation, "checkpoint generation")?,
                entry.checkpoint_checksum.as_slice(),
                entry.binding_ref.as_slice(),
                entry.preparation,
            ],
        )?;
    }
    transaction.commit()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn insert_active(conn: &Connection, index: i64, old: i64, new: i64, generation: i64) {
        conn.execute(
            "INSERT INTO trnm_epoch_transition_journal_v2 (transition_index,old_epoch,new_epoch,checkpoint_generation,checkpoint_checksum,binding_ref,preparation) VALUES (?1,?2,?3,?4,?5,?6,?7)",
            params![index, old, new, generation, [1_u8; 32], [2_u8; 32], vec![1_u8]],
        )
        .unwrap();
    }

    #[test]
    fn empty_journal_reopens_and_is_incomplete() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("epoch.sqlite");
        let journal = EpochTransitionJournalV1::open(&path).unwrap();
        assert!(journal.entries().unwrap().is_empty());
        assert!(!journal.is_complete().unwrap());
        drop(journal);
        assert!(EpochTransitionJournalV1::open(&path).is_ok());
    }

    #[test]
    fn more_than_two_transitions_are_valid_history() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("epoch.sqlite");
        let journal = EpochTransitionJournalV1::open(&path).unwrap();
        for index in 0_i64..4_i64 {
            insert_active(&journal.conn, index, index, index + 1, index + 1);
        }
        assert_eq!(journal.entries().unwrap().len(), 4);
        assert!(journal.is_complete().unwrap());
    }

    #[test]
    fn discontinuous_epoch_is_rejected_on_reopen() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("epoch.sqlite");
        let journal = EpochTransitionJournalV1::open(&path).unwrap();
        insert_active(&journal.conn, 0, 0, 2, 1);
        drop(journal);
        assert!(matches!(
            EpochTransitionJournalV1::open(&path),
            Err(EpochTransitionJournalErrorV1::EpochDiscontinuity { .. })
        ));
    }

    #[test]
    fn legacy_two_rows_migrate_without_capping_future_history() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("epoch.sqlite");
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE trnm_epoch_transition_journal_v1 (\
             slot INTEGER PRIMARY KEY CHECK(slot >= 0 AND slot <= 1),\
             old_epoch INTEGER NOT NULL, new_epoch INTEGER NOT NULL,\
             checkpoint_generation INTEGER NOT NULL,\
             checkpoint_checksum BLOB NOT NULL CHECK(length(checkpoint_checksum)=32),\
             binding_ref BLOB NOT NULL CHECK(length(binding_ref)=32),\
             preparation BLOB NOT NULL);",
        )
        .unwrap();
        for index in 0_i64..2_i64 {
            conn.execute(
                "INSERT INTO trnm_epoch_transition_journal_v1 (slot,old_epoch,new_epoch,checkpoint_generation,checkpoint_checksum,binding_ref,preparation) VALUES (?1,?2,?3,?4,?5,?6,?7)",
                params![index, index, index + 1, index + 1, [1_u8; 32], [2_u8; 32], vec![1_u8]],
            )
            .unwrap();
        }
        drop(conn);

        let journal = EpochTransitionJournalV1::open(&path).unwrap();
        assert_eq!(journal.entries().unwrap().len(), 2);
        insert_active(&journal.conn, 2, 2, 3, 3);
        assert_eq!(journal.entries().unwrap().len(), 3);
    }
}
