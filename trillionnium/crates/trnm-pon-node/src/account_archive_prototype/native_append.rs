//! Private write facts from this one actual native apply. No caller supplies a
//! write allowance, replacement scope or completed graph.
use super::{apply_bounded, Root};
use crate::store::native_authenticated::GraphScope;
use crate::Result;
use rusqlite::Connection;
use trnm_protocol::pon_wire::Hash;

pub(super) struct InsertCount(u64);

impl InsertCount {
    // Called only after the unchanged save_node INSERT and any exact conflict
    // readback succeeded. Failed applies return no receipt at all.
    pub(super) fn record(&mut self) -> Result<()> {
        self.0 = self.0.checked_add(1).ok_or("NATIVE_APPEND_COUNT")?;
        Ok(())
    }
}

/// This owned fact cannot authorize another scope, parent or apply result.
/// Its scope token keeps the original allocation alive and cannot suffer ABA.
pub(crate) struct AppliedNodes {
    scope: GraphScope,
    parent_record: Hash,
    parent: Root,
    result: Root,
    inserts: u64,
}

impl AppliedNodes {
    pub(crate) fn is_for(
        &self,
        scope: &GraphScope,
        parent_record: Hash,
        parent: &Root,
        result: &Root,
    ) -> bool {
        self.scope.same_scope(scope)
            && self.parent_record == parent_record
            && self.parent == *parent
            && self.result == *result
    }

    pub(crate) fn inserts(&self) -> u64 {
        self.inserts
    }
}

/// The sole constructor executes the original native apply with its original
/// callbacks, reads and writes. Its internal counter is updated only at the
/// two existing successful save_node sites, never by progress callbacks.
pub(crate) fn apply(
    db: &Connection,
    parent_record: Hash,
    parent: &Root,
    deltas: &[crate::store::Delta],
    progress: &mut dyn FnMut() -> Result<()>,
    scope: GraphScope,
) -> Result<(Root, AppliedNodes)> {
    let mut inserts = InsertCount(0);
    let result = apply_bounded(db, parent, deltas, progress, 65_536, Some(&mut inserts))?;
    let receipt = AppliedNodes {
        scope,
        parent_record,
        parent: parent.clone(),
        result: result.clone(),
        inserts: inserts.0,
    };
    // No change to the original Root or error/cancellation result.
    Ok((result, receipt))
}
