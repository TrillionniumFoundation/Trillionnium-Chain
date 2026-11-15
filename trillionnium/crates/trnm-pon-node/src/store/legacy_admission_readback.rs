//! A private, single-use common prefix inside one Legacy admission writer.
//!
//! The parent is reconstructed from the original SQL snapshot/delta path AFTER
//! all intended writes. Its complete State and every intermediate root still
//! pass the original checks. Only the subsequent child read may consume it,
//! while the original connection, explicit transaction, no-write epoch and
//! closed ordinary-table schema remain current. Nothing survives this call.
//! An active parent's KV read is a DIFFERENT source from its child's historical
//! snapshot/deltas, so an active parent can never issue this prefix.
//!
//! This is not an incremental state commitment, a cross-request validation
//! cache, a filesystem immutability proof, or authority for another connection.
//! The existing PostWriteReadback constructor supplies the original schema
//! normalization and transaction observation; its authenticated graph cache is
//! not used by this classical-only path. Blob/backup/UDF/virtual-table graphs
//! remain outside that admitted SQL contract.
use super::{ensure, Error, Hash, Node, Result, State, StateBackend};
use super::{growth_profile_v2, native_authenticated, pq_accounts_v2};
use rusqlite::Connection;
use std::collections::BTreeMap;

/// There is no caller-supplied State constructor. The only constructor below
/// first runs the original complete parent readback and equality comparison.
/// A child snapshot takes the original path and need not consume this loan.
pub(super) struct Parent<'scope, 'db> {
    child: Hash,
    parent: Hash,
    state: Option<State>,
    scope: &'scope mut native_authenticated::PostWriteReadback<'db>,
}

impl Parent<'_, '_> {
    pub(super) fn take_if_current(
        &mut self,
        db: &Connection,
        child: Hash,
        current: Hash,
    ) -> Result<Option<State>> {
        ensure(child == self.child, "STORAGE_WRITE").map_err(Error::local_integrity)?;
        if current != self.parent {
            return Ok(None);
        }
        // The ancestor walk still reads and validates the actual child's
        // parent/height link before reaching this exact fully checked parent.
        // A write/no-row write/DDL or transaction ABA cannot borrow its State.
        self.scope.require_unchanged_after_last_write(db)?;
        Ok(self.state.take())
    }
}

impl Node {
    pub(super) fn legacy_admission_readback_schema(&self) -> Option<&BTreeMap<String, String>> {
        (self.state_backend == StateBackend::Legacy
            && !pq_accounts_v2::enabled(&self.settings.app)
            && !growth_profile_v2::enabled(&self.settings.app))
        .then_some(self.legacy_admission_schema.as_ref())
        .flatten()
    }

    pub(super) fn check_legacy_admission_states(
        &self,
        (parent, child): (Hash, Hash),
        (expected_parent, expected_child): (&State, &State),
        progress: &mut dyn FnMut() -> Result<()>,
        scope: &mut native_authenticated::PostWriteReadback<'_>,
    ) -> Result<()> {
        ensure(
            self.legacy_admission_readback_schema().is_some(),
            "STORAGE_WRITE",
        )
        .map_err(Error::local_integrity)?;
        scope.require_unchanged_after_last_write(&self.db)?;
        ensure(parent != self.active()?.0, "STORAGE_WRITE").map_err(Error::local_integrity)?;
        let actual = self.state_at_with_progress(parent, progress)?;
        ensure(&actual == expected_parent, "STORAGE_WRITE").map_err(Error::local_integrity)?;
        scope.require_unchanged_after_last_write(&self.db)?;
        let mut prefix = Parent {
            child,
            parent,
            state: Some(actual),
            scope,
        };
        let actual = self.state_at_with_replay_prefix(child, progress, None, Some(&mut prefix))?;
        ensure(&actual == expected_child, "STORAGE_WRITE").map_err(Error::local_integrity)?;
        // This also fences a callback after the last State/root comparison.
        // The admission owner checks again after its later active/tail checks.
        scope.require_unchanged_after_last_write(&self.db)
    }
}

#[cfg(test)]
pub(super) fn test_progress(db: &Connection, point: super::ExecutionProgress) -> Result<()> {
    tests::progress(db, point)
}

#[cfg(test)]
mod tests;
