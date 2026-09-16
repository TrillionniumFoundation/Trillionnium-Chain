//! Durable two-slot epoch-transition journal.
//!
//! The journal is the first persistent boundary after strict checkpoint/seal/
//! handoff verification.  It deliberately stores only the canonical
//! `EpochPreparationRecordV1` bytes and immutable checkpoint coordinates; it
//! never turns a record into Core or signing authority.  Reopening the file
//! therefore requires the caller to run the strict recovery function with the
//! trusted validator set and parameters for each slot.

use std::{path::{Path, PathBuf}, error::Error, fmt};
use rusqlite::{params, Connection};
use trnm_consensus_core::{EpochPreparationV1, recover_epoch_preparation_v1};
use trnm_consensus_types::{Cev0AdmissionBudgetV0, ConsensusParametersV0, ValidatorSet};

const SCHEMA: &str = "CREATE TABLE IF NOT EXISTS trnm_epoch_transition_journal_v1 (\
 slot INTEGER PRIMARY KEY CHECK(slot >= 0 AND slot <= 1),\
 old_epoch INTEGER NOT NULL,\
 new_epoch INTEGER NOT NULL,\
 checkpoint_generation INTEGER NOT NULL,\
 checkpoint_checksum BLOB NOT NULL CHECK(length(checkpoint_checksum)=32),\
 binding_ref BLOB NOT NULL CHECK(length(binding_ref)=32),\
 preparation BLOB NOT NULL);";

#[derive(Debug)]
pub enum EpochTransitionJournalErrorV1 {
    Io(rusqlite::Error),
    Invalid(&'static str),
    SlotAlreadyWritten(u8),
    SlotOrder { expected: u8, received: u8 },
    EpochDiscontinuity { expected: u64, received: u64 },
    CheckpointGenerationRegression,
    BindingMismatch,
    Recovery(trnm_consensus_core::EpochPreparationErrorV1),
}
impl fmt::Display for EpochTransitionJournalErrorV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "epoch journal sqlite: {e}"),
            Self::Invalid(s) => write!(f, "epoch journal invalid: {s}"),
            Self::SlotAlreadyWritten(s) => write!(f, "epoch journal slot {s} already written"),
            Self::SlotOrder { expected, received } => write!(f, "epoch journal expected slot {expected}, received {received}"),
            Self::EpochDiscontinuity { expected, received } => write!(f, "epoch journal expected old epoch {expected}, received {received}"),
            Self::CheckpointGenerationRegression => f.write_str("epoch journal checkpoint generation regressed"),
            Self::BindingMismatch => f.write_str("epoch journal binding/checkpoint coordinates are zero or inconsistent"),
            Self::Recovery(e) => write!(f, "epoch journal strict recovery: {e}"),
        }
    }
}
impl Error for EpochTransitionJournalErrorV1 {}
impl From<rusqlite::Error> for EpochTransitionJournalErrorV1 { fn from(e: rusqlite::Error) -> Self { Self::Io(e) } }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpochTransitionJournalEntryV1 {
    pub slot: u8,
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
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.debug_struct("EpochTransitionJournalV1").field("path", &self.path).finish_non_exhaustive() }
}
impl EpochTransitionJournalV1 {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, EpochTransitionJournalErrorV1> {
        let path = path.as_ref().to_path_buf();
        let conn = Connection::open(&path)?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;")?;
        conn.execute_batch(SCHEMA)?;
        Ok(Self { path, conn })
    }
    pub fn path(&self) -> &Path { &self.path }
    pub fn entries(&self) -> Result<Vec<EpochTransitionJournalEntryV1>, EpochTransitionJournalErrorV1> {
        let mut stmt = self.conn.prepare("SELECT slot,old_epoch,new_epoch,checkpoint_generation,checkpoint_checksum,binding_ref,preparation FROM trnm_epoch_transition_journal_v1 ORDER BY slot")?;
        let rows = stmt.query_map([], |row| {
            let slot: i64 = row.get(0)?;
            let checksum: Vec<u8> = row.get(4)?;
            let binding: Vec<u8> = row.get(5)?;
            let preparation: Vec<u8> = row.get(6)?;
            Ok((slot, row.get::<_, i64>(1)?, row.get::<_, i64>(2)?, row.get::<_, i64>(3)?, checksum, binding, preparation))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (slot, old, new, generation, checksum, binding, preparation) = row?;
            if !(0..=1).contains(&slot) || checksum.len() != 32 || binding.len() != 32 || old < 0 || new < 0 || generation < 0 {
                return Err(EpochTransitionJournalErrorV1::Invalid("row shape or integer range"));
            }
            let mut c = [0; 32]; c.copy_from_slice(&checksum);
            let mut b = [0; 32]; b.copy_from_slice(&binding);
            out.push(EpochTransitionJournalEntryV1 { slot: slot as u8, old_epoch: old as u64, new_epoch: new as u64, checkpoint_generation: generation as u64, checkpoint_checksum: c, binding_ref: b, preparation });
        }
        validate_entries(&out)?;
        Ok(out)
    }
    /// Append one strictly verified preparation.  Exactly two contiguous
    /// transitions are accepted; duplicate/out-of-order writes fail closed.
    pub fn append_verified(&mut self, preparation: &EpochPreparationV1, checkpoint_generation: u64, checkpoint_checksum: [u8; 32]) -> Result<u8, EpochTransitionJournalErrorV1> {
        if checkpoint_generation == 0 || checkpoint_checksum == [0; 32] { return Err(EpochTransitionJournalErrorV1::BindingMismatch); }
        let entries = self.entries()?;
        let slot = entries.len() as u8;
        if slot > 1 { return Err(EpochTransitionJournalErrorV1::Invalid("two-slot journal is full")); }
        let authority = preparation.authority_v1();
        let old = authority.joint_handoff().old_epoch().get();
        let new = authority.joint_handoff().new_epoch().get();
        if new != old.saturating_add(1) { return Err(EpochTransitionJournalErrorV1::EpochDiscontinuity { expected: old.saturating_add(1), received: new }); }
        if let Some(previous) = entries.last() {
            if old != previous.new_epoch { return Err(EpochTransitionJournalErrorV1::EpochDiscontinuity { expected: previous.new_epoch, received: old }); }
            if checkpoint_generation <= previous.checkpoint_generation { return Err(EpochTransitionJournalErrorV1::CheckpointGenerationRegression); }
        }
        let bytes = preparation.record_v1().encode_v1().map_err(|_| EpochTransitionJournalErrorV1::Invalid("noncanonical preparation record"))?;
        let binding = preparation.record_v1().binding_ref_v1();
        if binding == [0; 32] { return Err(EpochTransitionJournalErrorV1::BindingMismatch); }
        let tx = self.conn.transaction()?;
        tx.execute("INSERT INTO trnm_epoch_transition_journal_v1 (slot,old_epoch,new_epoch,checkpoint_generation,checkpoint_checksum,binding_ref,preparation) VALUES (?1,?2,?3,?4,?5,?6,?7)", params![slot as i64, old as i64, new as i64, checkpoint_generation as i64, checkpoint_checksum.as_slice(), binding.as_slice(), bytes])?;
        tx.commit()?;
        Ok(slot)
    }
    /// Strictly recover one slot after a process restart.  The caller supplies
    /// the independently trusted old context; persisted bytes are never enough
    /// to activate a validator set.
    pub fn recover_entry(&self, slot: u8, trusted_old_set: &ValidatorSet, trusted_old_parameters: &ConsensusParametersV0, budget: &mut Cev0AdmissionBudgetV0) -> Result<EpochPreparationV1, EpochTransitionJournalErrorV1> {
        let entry = self.entries()?.into_iter().find(|e| e.slot == slot).ok_or(EpochTransitionJournalErrorV1::Invalid("requested slot is absent"))?;
        recover_epoch_preparation_v1(&entry.preparation, trusted_old_set, trusted_old_parameters, entry.binding_ref, budget).map_err(EpochTransitionJournalErrorV1::Recovery)
    }
    pub fn is_complete(&self) -> Result<bool, EpochTransitionJournalErrorV1> { Ok(self.entries()?.len() == 2) }
}

fn validate_entries(entries: &[EpochTransitionJournalEntryV1]) -> Result<(), EpochTransitionJournalErrorV1> {
    if entries.len() > 2 { return Err(EpochTransitionJournalErrorV1::Invalid("more than two transition rows")); }
    for (index, entry) in entries.iter().enumerate() {
        if entry.slot as usize != index { return Err(EpochTransitionJournalErrorV1::SlotOrder { expected: index as u8, received: entry.slot }); }
        if entry.binding_ref == [0; 32] || entry.checkpoint_checksum == [0; 32] || entry.checkpoint_generation == 0 { return Err(EpochTransitionJournalErrorV1::BindingMismatch); }
        if entry.new_epoch != entry.old_epoch.saturating_add(1) { return Err(EpochTransitionJournalErrorV1::EpochDiscontinuity { expected: entry.old_epoch.saturating_add(1), received: entry.new_epoch }); }
        if index > 0 {
            let previous = &entries[index - 1];
            if entry.old_epoch != previous.new_epoch { return Err(EpochTransitionJournalErrorV1::EpochDiscontinuity { expected: previous.new_epoch, received: entry.old_epoch }); }
            if entry.checkpoint_generation <= previous.checkpoint_generation { return Err(EpochTransitionJournalErrorV1::CheckpointGenerationRegression); }
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
        let dir = tempdir().unwrap();
        let path = dir.path().join("epoch.sqlite");
        let journal = EpochTransitionJournalV1::open(&path).unwrap();
        assert!(journal.entries().unwrap().is_empty());
        assert!(!journal.is_complete().unwrap());
        drop(journal);
        let reopened = EpochTransitionJournalV1::open(&path).unwrap();
        assert!(reopened.entries().unwrap().is_empty());
    }

    #[test]
    fn tampered_epoch_coordinate_is_rejected_on_reopen() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("epoch.sqlite");
        let journal = EpochTransitionJournalV1::open(&path).unwrap();
        drop(journal);
        let conn = Connection::open(&path).unwrap();
        conn.execute("INSERT INTO trnm_epoch_transition_journal_v1 (slot,old_epoch,new_epoch,checkpoint_generation,checkpoint_checksum,binding_ref,preparation) VALUES (0,0,2,1,?1,?2,?3)", params![[1u8;32], [2u8;32], vec![0u8; 1]]).unwrap();
        drop(conn);
        let reopened = EpochTransitionJournalV1::open(&path).unwrap();
        assert!(matches!(reopened.entries(), Err(EpochTransitionJournalErrorV1::EpochDiscontinuity { .. })));
    }
}
