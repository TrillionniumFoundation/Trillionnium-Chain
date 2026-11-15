//! Complete account-root arithmetic without constructing storage records.
//!
//! A root needs the same path, depth and digest at every Patricia subtree.
//! Stored node IDs bind encoded child pointers but are not inputs to these
//! mathematical values. This type deliberately has no record ID, child pointer,
//! encoder or database access. The independent record-building reference and
//! every actual SQL graph verification remain in the parent/native modules.
use super::{
    bit, branch, common, empty_hashes, leaf, native_store::LiftCache, ordered_accounts, Account,
    ArchiveError, Hash, Result,
};
use std::collections::BTreeMap;

struct RootDigest {
    path: Hash,
    depth: usize,
    digest: Hash,
}

impl RootDigest {
    fn lift(&self, depth: usize, lifts: &LiftCache) -> Hash {
        lifts.lift_parts(self.path, self.digest, self.depth, depth)
    }

    fn fork(depth: usize, left: &Self, right: &Self, lifts: &LiftCache) -> Result<Self> {
        // Preserve the original Node::fork_with_lift shape checks and their
        // order before evaluating either child lift.
        if depth >= left.depth
            || depth >= right.depth
            || common(&left.path, &right.path) != depth
            || bit(&left.path, depth)
            || !bit(&right.path, depth)
        {
            return Err(ArchiveError::CorruptRecord);
        }
        let left_hash = left.lift(depth + 1, lifts);
        let right_hash = right.lift(depth + 1, lifts);
        Ok(Self {
            path: left.path,
            depth,
            digest: branch(left_hash, right_hash),
        })
    }
}

fn build(
    rows: &[(Hash, Hash, Account)],
    progress: &mut dyn FnMut() -> Result<()>,
    lifts: &LiftCache,
) -> Result<Option<RootDigest>> {
    if rows.is_empty() {
        return Ok(None);
    }
    progress()?;
    let node = if rows.len() == 1 {
        RootDigest {
            // ordered_accounts computed this exact owner's path in this call.
            path: rows[0].0,
            depth: 256,
            digest: leaf(rows[0].1, rows[0].2),
        }
    } else {
        let depth = common(&rows[0].0, &rows[rows.len() - 1].0);
        if depth == 256 {
            return Err(ArchiveError::KeyCollision);
        }
        let split = rows.partition_point(|row| !bit(&row.0, depth));
        if split == 0 || split == rows.len() {
            return Err(ArchiveError::CorruptRecord);
        }
        let left = build(&rows[..split], progress, lifts)?.ok_or(ArchiveError::CorruptRecord)?;
        let right = build(&rows[split..], progress, lifts)?.ok_or(ArchiveError::CorruptRecord)?;
        RootDigest::fork(depth, &left, &right, lifts)?
    };
    Ok(Some(node))
}

pub(super) fn root(values: &BTreeMap<Hash, Account>, lifts: &LiftCache) -> Result<Hash> {
    // Still visit, hash, order and rebuild ALL current accounts. The original
    // commitment-only entry has the same no-op callback; this grants no new
    // progress, current-State, storage, signature or source authority.
    Ok(build(&ordered_accounts(values)?, &mut || Ok(()), lifts)?
        .map_or_else(|| empty_hashes()[0], |node| node.lift(0, lifts)))
}

#[cfg(test)]
#[path = "native_root_digest_tests.rs"]
mod tests;
