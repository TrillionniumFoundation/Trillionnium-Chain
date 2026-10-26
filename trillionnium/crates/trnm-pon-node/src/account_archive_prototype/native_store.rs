//! Transaction-local Patricia storage for the explicitly selected native backend.
//!
//! This reuses the established node bytes and hashes, but never opens a sidecar
//! or commits a transaction. The native owner supplies its own SQLite connection
//! and commits account nodes with the actual block, deltas and state commitment.
use super::{Account, ArchiveError, Kind, Node};
use crate::{Error, Result};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use trnm_mvcc_fee::pon_executor::State;
use trnm_protocol::pon_wire::Hash;

#[path = "native_node_decode.rs"]
mod node_decode;
#[path = "native_node_reader.rs"]
mod node_reader;
use node_reader::NodeReader;

/// Exact mathematical inputs only. Every stored node is still read from SQL.
/// Node decoding can reuse only the complete actual bytes and expected ID;
/// compressed-path hashes bind all their original inputs separately. No row,
/// graph, state, ancestry or commit verdict survives a call.
type LiftInput = (Hash, Hash, usize, usize);
#[derive(Default)]
pub(crate) struct LiftCache(
    RefCell<BTreeMap<LiftInput, Hash>>,
    node_decode::NodeDecodeArithmetic,
);
impl LiftCache {
    const MAX_ENTRIES: usize = 8192;

    pub(crate) fn decode_observation(&self) -> serde_json::Value {
        self.1.observation()
    }

    pub(super) fn lift(&self, node: &Node, depth: usize) -> Hash {
        let key = (node.path, node.digest, node.depth, depth);
        if let Ok(entries) = self.0.try_borrow() {
            if let Some(value) = entries.get(&key) {
                return *value;
            }
        }
        // The omitted empty table is the immutable compiled grammar, never an
        // input supplied by a caller, database, record or selected block.
        let value = node.lift(depth, &empty_hashes());
        if let Ok(mut entries) = self.0.try_borrow_mut() {
            if entries.len() == Self::MAX_ENTRIES {
                entries.clear();
            }
            entries.insert(key, value);
        }
        value
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Root {
    pub node: Option<Hash>,
    pub digest: Hash,
    pub count: u64,
    pub balance: u64,
}

fn storage(error: ArchiveError) -> Error {
    Error::from(format!("NATIVE_ACCOUNT_STORE:{error:?}")).local_integrity()
}

fn controlled<T>(
    progress: &mut dyn FnMut() -> Result<()>,
    run: impl FnOnce(&mut dyn FnMut() -> super::Result<()>) -> super::Result<T>,
) -> Result<T> {
    let mut cancelled = None;
    let result = run(&mut || {
        progress().map_err(|error| {
            cancelled = Some(error);
            ArchiveError::Cancelled
        })
    });
    if let Some(error) = cancelled {
        return Err(error);
    }
    result.map_err(storage)
}

fn load_root(db: &Connection, root: &Root, empty: &[Hash; 257]) -> Result<Option<Node>> {
    load_root_bounded(db, root, empty, 65_536)
}
fn load_root_bounded(
    db: &Connection,
    root: &Root,
    empty: &[Hash; 257],
    maximum: u64,
) -> Result<Option<Node>> {
    let node = root
        .node
        .map(|id| super::load_node(db, id))
        .transpose()
        .map_err(storage)?;
    crate::ensure(
        root.count <= maximum
            && root.node.is_none() == (root.count == 0)
            && node.as_ref().map_or(empty[0], |node| node.lift(0, empty)) == root.digest,
        "NATIVE_ACCOUNT_ROOT",
    )
    .map_err(Error::local_integrity)?;
    Ok(node)
}

pub(crate) fn seed(
    db: &Connection,
    state: &State,
    progress: &mut dyn FnMut() -> Result<()>,
) -> Result<Root> {
    let accounts = super::accounts(state).map_err(storage)?;
    let ordered = super::ordered_accounts(&accounts).map_err(storage)?;
    let empty = empty_hashes();
    let node = controlled(progress, |checkpoint| {
        super::build(Some(db), &ordered, &empty, checkpoint)
    })?;
    let balance = accounts.values().try_fold(0u64, |sum, account| {
        sum.checked_add(account.balance)
            .ok_or("NATIVE_ACCOUNT_BALANCE")
    })?;
    let root = Root {
        node: node.as_ref().map(|node| node.id),
        digest: node.as_ref().map_or(empty[0], |node| node.lift(0, &empty)),
        count: accounts.len() as u64,
        balance,
    };
    verify(db, &root, state, progress)?;
    Ok(root)
}

fn lookup(
    db: &Connection,
    root: Option<Node>,
    owner: Hash,
    empty: &[Hash; 257],
) -> Result<Option<Account>> {
    let key = super::path(owner);
    let mut current = root;
    for _ in 0..257 {
        let Some(node) = current else { return Ok(None) };
        if super::common(&key, &node.path) < node.depth {
            return Ok(None);
        }
        match node.kind {
            Kind::Leaf(stored, account) => {
                crate::ensure(stored == owner, "NATIVE_ACCOUNT_COLLISION")
                    .map_err(Error::local_integrity)?;
                return Ok(Some(account));
            }
            Kind::Fork { .. } => {
                current = Some(
                    super::child(db, &node, super::bit(&key, node.depth), empty)
                        .map_err(storage)?,
                );
            }
        }
    }
    Err(Error::from("NATIVE_ACCOUNT_PATH").local_integrity())
}

fn account(key: &str, bytes: &[u8]) -> Result<(Hash, Account)> {
    let value =
        serde_json::from_slice(bytes).map_err(|error| Error::from(error).local_integrity())?;
    let state = State::from([(key.to_owned(), value)]);
    let mut values = super::accounts(&state).map_err(storage)?;
    crate::ensure(values.len() == 1, "NATIVE_ACCOUNT_ROW").map_err(Error::local_integrity)?;
    values
        .pop_first()
        .ok_or_else(|| Error::from("NATIVE_ACCOUNT_ROW").local_integrity())
}

/// Merge sorted changed leaves into the compressed parent tree. Every persisted
/// node belongs to the completed successor: intermediate per-account roots are
/// never written. Unchanged subtrees and all prior versions remain untouched.
fn apply_batch(
    db: &Connection,
    existing: Option<Node>,
    updates: &[Node],
    empty: &[Hash; 257],
    progress: &mut dyn FnMut() -> Result<()>,
) -> Result<Option<Node>> {
    progress()?;
    let Some(first) = updates.first() else {
        return Ok(existing);
    };
    let last = updates.last().ok_or("NATIVE_ACCOUNT_DELTA")?;
    let changed_depth = super::common(&first.path, &last.path);
    let depth = existing.as_ref().map_or(changed_depth, |node| {
        changed_depth
            .min(node.depth)
            .min(super::common(&node.path, &first.path))
    });
    if depth == 256 {
        crate::ensure(updates.len() == 1, "NATIVE_ACCOUNT_DELTA")
            .map_err(Error::local_integrity)?;
        // The original-parent lookup already checked identity and nonce. Keep
        // this structural guard so the merge cannot replace another owner.
        if let Some(node) = existing {
            crate::ensure(
                matches!((node.kind, first.kind), (Kind::Leaf(old, _), Kind::Leaf(new, _)) if old == new),
                "NATIVE_ACCOUNT_COLLISION",
            )
            .map_err(Error::local_integrity)?;
        }
        super::save_node(db, first).map_err(storage)?;
        return Ok(Some(first.clone()));
    }
    let split = updates.partition_point(|node| !super::bit(&node.path, depth));
    let (left_updates, right_updates) = updates.split_at(split);
    let (left, right) = match existing {
        None => (None, None),
        Some(node) if depth < node.depth => {
            if super::bit(&node.path, depth) {
                (None, Some(node))
            } else {
                (Some(node), None)
            }
        }
        Some(node) => {
            crate::ensure(
                depth == node.depth && matches!(node.kind, Kind::Fork { .. }),
                "NATIVE_ACCOUNT_GRAPH",
            )
            .map_err(Error::local_integrity)?;
            (
                Some(super::child(db, &node, false, empty).map_err(storage)?),
                Some(super::child(db, &node, true, empty).map_err(storage)?),
            )
        }
    };
    let left = apply_batch(db, left, left_updates, empty, progress)?
        .ok_or_else(|| Error::from("NATIVE_ACCOUNT_GRAPH").local_integrity())?;
    let right = apply_batch(db, right, right_updates, empty, progress)?
        .ok_or_else(|| Error::from("NATIVE_ACCOUNT_GRAPH").local_integrity())?;
    let next = Node::fork(depth, &left, &right, empty).map_err(storage)?;
    super::save_node(db, &next).map_err(storage)?;
    Ok(Some(next))
}

/// Apply actual ordered native deltas. Accounts retain both nonce and existence;
/// an absent persisted child is never interpreted as a never-created account.
pub(crate) fn apply(
    db: &Connection,
    parent: &Root,
    deltas: &[crate::store::Delta],
    progress: &mut dyn FnMut() -> Result<()>,
) -> Result<Root> {
    apply_bounded(db, parent, deltas, progress, 65_536)
}

/// Only the explicitly selected growth owner calls this versioned bound.
pub(crate) fn apply_growth(
    db: &Connection,
    parent: &Root,
    deltas: &[crate::store::Delta],
    progress: &mut dyn FnMut() -> Result<()>,
) -> Result<Root> {
    apply_bounded(
        db,
        parent,
        deltas,
        progress,
        trnm_mvcc_fee::pon_executor::growth::MAX_ACCOUNTS,
    )
}
fn apply_bounded(
    db: &Connection,
    parent: &Root,
    deltas: &[crate::store::Delta],
    progress: &mut dyn FnMut() -> Result<()>,
    maximum: u64,
) -> Result<Root> {
    let empty = empty_hashes();
    let original = load_root_bounded(db, parent, &empty, maximum)?;
    let mut updates = Vec::new();
    let mut count = parent.count;
    // Canonical key order can visit a credit before its matching debit. Keep a
    // signed wide delta accumulator so an intermediate order cannot reject a
    // conserved u64 total near its boundary.
    let mut balance = i128::from(parent.balance);
    for (key, before, after) in deltas {
        progress()?;
        if !key.starts_with("account:") {
            continue;
        }
        let after = after
            .as_ref()
            .ok_or_else(|| Error::from("NATIVE_ACCOUNT_DELETION").local_integrity())?;
        let (owner, next) = account(key, after)?;
        let prior = before
            .as_ref()
            .map(|bytes| account(key, bytes).map(|row| row.1))
            .transpose()?;
        crate::ensure(
            lookup(db, original.clone(), owner, &empty)? == prior
                && prior.is_none_or(|prior| next.nonce >= prior.nonce),
            "NATIVE_ACCOUNT_DELTA",
        )
        .map_err(Error::local_integrity)?;
        count = count
            .checked_add(u64::from(prior.is_none()))
            .ok_or("NATIVE_ACCOUNT_COUNT")?;
        balance = balance
            .checked_sub(i128::from(prior.map_or(0, |prior| prior.balance)))
            .and_then(|value| value.checked_add(i128::from(next.balance)))
            .ok_or("NATIVE_ACCOUNT_BALANCE")?;
        updates.push(Node::account(owner, next));
    }
    crate::ensure(count <= maximum, "NATIVE_ACCOUNT_COUNT").map_err(Error::local_integrity)?;
    let balance = u64::try_from(balance)
        .map_err(|_| Error::from("NATIVE_ACCOUNT_BALANCE").local_integrity())?;
    updates.sort_unstable_by_key(|node| node.path);
    crate::ensure(
        updates.windows(2).all(|pair| pair[0].path != pair[1].path),
        "NATIVE_ACCOUNT_DELTA",
    )
    .map_err(Error::local_integrity)?;
    let root = apply_batch(db, original, &updates, &empty, progress)?;
    Ok(Root {
        node: root.as_ref().map(|node| node.id),
        digest: root.as_ref().map_or(empty[0], |node| node.lift(0, &empty)),
        count,
        balance,
    })
}

#[cfg(test)]
#[path = "native_store_batch_tests.rs"]
mod batch_tests;

// Only the compiled account-archive hash grammar determines these 8,224 bytes.
// No database, block, clock, network context or successful validation is cached.
// Return an owned copy so callers cannot modify the shared mathematical constants.
fn empty_hashes() -> [Hash; 257] {
    static EMPTY: std::sync::OnceLock<[Hash; 257]> = std::sync::OnceLock::new();
    *EMPTY.get_or_init(super::empty_hashes)
}

/// Read every required node and leaf, including unchanged subtrees, and compare
/// their real bytes with the independently checked complete native State.
/// This explicit reference check remains linear in account count.
pub(crate) fn verify(
    db: &Connection,
    root: &Root,
    state: &State,
    progress: &mut dyn FnMut() -> Result<()>,
) -> Result<()> {
    verify_with_lifts(db, root, state, progress, None)
}

pub(crate) fn verify_with_lifts(
    db: &Connection,
    root: &Root,
    state: &State,
    progress: &mut dyn FnMut() -> Result<()>,
    lifts: Option<&LiftCache>,
) -> Result<()> {
    let empty = empty_hashes();
    let actual = super::accounts(state).map_err(storage)?;
    let mut reader = NodeReader::new(db);
    let node = root
        .node
        .map(|id| reader.load(id, lifts))
        .transpose()
        .map_err(storage)?;
    crate::ensure(
        root.count <= 65_536
            && root.node.is_none() == (root.count == 0)
            && node.as_ref().map_or(empty[0], |node| {
                lifts.map_or_else(|| node.lift(0, &empty), |cache| cache.lift(node, 0))
            }) == root.digest,
        "NATIVE_ACCOUNT_ROOT",
    )
    .map_err(Error::local_integrity)?;
    let mut stack = node.into_iter().collect::<Vec<_>>();
    let mut seen = BTreeSet::new();
    let mut retained = BTreeMap::new();
    let mut balance = 0u64;
    while let Some(node) = stack.pop() {
        progress()?;
        crate::ensure(
            seen.insert(node.id) && seen.len() <= 131_071,
            "NATIVE_ACCOUNT_GRAPH",
        )
        .map_err(Error::local_integrity)?;
        match node.kind {
            Kind::Leaf(owner, value) => {
                crate::ensure(
                    retained.insert(owner, value).is_none(),
                    "NATIVE_ACCOUNT_DUPLICATE",
                )
                .map_err(Error::local_integrity)?;
                balance = balance
                    .checked_add(value.balance)
                    .ok_or("NATIVE_ACCOUNT_BALANCE")?;
            }
            Kind::Fork { .. } => {
                stack.push(
                    child_with_lifts(&mut reader, &node, true, &empty, lifts).map_err(storage)?,
                );
                stack.push(
                    child_with_lifts(&mut reader, &node, false, &empty, lifts).map_err(storage)?,
                );
            }
        }
    }
    crate::ensure(
        retained == actual && retained.len() as u64 == root.count && balance == root.balance,
        "NATIVE_ACCOUNT_STATE",
    )
    .map_err(Error::local_integrity)
}

fn child_with_lifts(
    reader: &mut NodeReader<'_>,
    parent: &Node,
    right_side: bool,
    empty: &[Hash; 257],
    lifts: Option<&LiftCache>,
) -> super::Result<Node> {
    let Kind::Fork {
        left,
        right,
        left_hash,
        right_hash,
    } = parent.kind
    else {
        return Err(ArchiveError::CorruptRecord);
    };
    // Preserve the actual SQL read, exact-input decode, path/depth and parent
    // hash comparisons. Only arithmetic on the just-read bytes can be reused.
    let out = reader.load(if right_side { right } else { left }, lifts)?;
    if out.depth <= parent.depth
        || super::common(&out.path, &parent.path) < parent.depth
        || super::bit(&out.path, parent.depth) != right_side
        || lifts.map_or_else(
            || out.lift(parent.depth + 1, empty),
            |cache| cache.lift(&out, parent.depth + 1),
        ) != if right_side { right_hash } else { left_hash }
    {
        return Err(ArchiveError::CorruptRecord);
    }
    Ok(out)
}

/// Recover every actual account from one retained root. The result is local to
/// this read operation: neither a caller digest nor a previous successful audit
/// can stand in for the current SQL bytes and complete graph traversal.
pub(crate) fn materialize_accounts(
    db: &Connection,
    root: &Root,
    progress: &mut dyn FnMut() -> Result<()>,
    lifts: Option<&LiftCache>,
) -> Result<BTreeMap<Hash, Account>> {
    let empty = empty_hashes();
    let mut reader = NodeReader::new(db);
    let node = root
        .node
        .map(|id| reader.load(id, lifts))
        .transpose()
        .map_err(storage)?;
    crate::ensure(
        root.count <= 65_536
            && root.node.is_none() == (root.count == 0)
            && node.as_ref().map_or(empty[0], |node| {
                lifts.map_or_else(|| node.lift(0, &empty), |cache| cache.lift(node, 0))
            }) == root.digest,
        "NATIVE_ACCOUNT_ROOT",
    )
    .map_err(Error::local_integrity)?;
    let mut stack = node.into_iter().collect::<Vec<_>>();
    let mut seen = BTreeSet::new();
    let mut retained = BTreeMap::new();
    let mut balance = 0u64;
    while let Some(node) = stack.pop() {
        progress()?;
        crate::ensure(
            seen.insert(node.id) && seen.len() <= 131_071,
            "NATIVE_ACCOUNT_GRAPH",
        )
        .map_err(Error::local_integrity)?;
        match node.kind {
            Kind::Leaf(owner, value) => {
                crate::ensure(
                    retained.insert(owner, value).is_none(),
                    "NATIVE_ACCOUNT_DUPLICATE",
                )
                .map_err(Error::local_integrity)?;
                balance = balance
                    .checked_add(value.balance)
                    .ok_or_else(|| Error::from("NATIVE_ACCOUNT_BALANCE").local_integrity())?;
            }
            Kind::Fork { .. } => {
                stack.push(
                    child_with_lifts(&mut reader, &node, true, &empty, lifts).map_err(storage)?,
                );
                stack.push(
                    child_with_lifts(&mut reader, &node, false, &empty, lifts).map_err(storage)?,
                );
            }
        }
    }
    crate::ensure(
        retained.len() as u64 == root.count && balance == root.balance,
        "NATIVE_ACCOUNT_STATE",
    )
    .map_err(Error::local_integrity)?;
    progress()?;
    Ok(retained)
}

/// An opaque point-query binding to one actual native block. It makes no claim
/// of a separately persisted AccountArchive checkpoint or archive ancestry.
pub(crate) fn query_checkpoint(
    db: &Connection,
    context: super::Context,
    block: Hash,
    height: u64,
    state_root: Hash,
    root: &Root,
) -> Result<super::Checkpoint> {
    let empty = empty_hashes();
    let node = load_root(db, root, &empty)?;
    Ok(super::make_checkpoint(
        context,
        block,
        None,
        height,
        Some(state_root),
        node.as_ref(),
        root.count,
    ))
}

/// Cold audit: authenticate every reachable node and independently recover count
/// and balance. It is intentionally linear and never called by the growth hot path.
pub(crate) fn audit_growth(db: &Connection, root: &Root) -> Result<()> {
    let empty = empty_hashes();
    let maximum = trnm_mvcc_fee::pon_executor::growth::MAX_ACCOUNTS;
    let mut stack: Vec<_> = load_root_bounded(db, root, &empty, maximum)?
        .into_iter()
        .collect();
    let mut seen = BTreeSet::new();
    let mut owners = BTreeSet::new();
    let mut balance = 0u64;
    while let Some(node) = stack.pop() {
        crate::ensure(
            seen.insert(node.id) && (seen.len() as u64) < maximum * 2,
            "NATIVE_ACCOUNT_GRAPH",
        )
        .map_err(Error::local_integrity)?;
        match node.kind {
            Kind::Leaf(owner, account) => {
                crate::ensure(owners.insert(owner), "NATIVE_ACCOUNT_DUPLICATE")
                    .map_err(Error::local_integrity)?;
                balance = balance
                    .checked_add(account.balance)
                    .ok_or("NATIVE_ACCOUNT_BALANCE")?;
            }
            Kind::Fork { .. } => {
                stack.push(super::child(db, &node, false, &empty).map_err(storage)?);
                stack.push(super::child(db, &node, true, &empty).map_err(storage)?);
            }
        }
    }
    crate::ensure(
        owners.len() as u64 == root.count && balance == root.balance,
        "NATIVE_ACCOUNT_AGGREGATE",
    )
    .map_err(Error::local_integrity)
}

/// One frozen cold snapshot may share checked immutable node aggregates across
/// retained roots. This cache never escapes the audit or survives SQL writes.
pub(crate) fn audit_growth_roots(db: &Connection, roots: &[Root]) -> Result<()> {
    let empty = empty_hashes();
    let maximum = trnm_mvcc_fee::pon_executor::growth::MAX_ACCOUNTS;
    let mut memo: BTreeMap<Hash, (u64, u64)> = BTreeMap::new();
    for root in roots {
        let first = load_root_bounded(db, root, &empty, maximum)?;
        let Some(first) = first else {
            crate::ensure(root.balance == 0, "NATIVE_ACCOUNT_AGGREGATE")?;
            continue;
        };
        let root_id = first.id;
        let mut stack = vec![(first, false)];
        while let Some((node, visited)) = stack.pop() {
            if memo.contains_key(&node.id) {
                continue;
            }
            match node.kind {
                Kind::Leaf(_, account) => {
                    memo.insert(node.id, (1, account.balance));
                }
                Kind::Fork { left, right, .. } if visited => {
                    let l = memo.get(&left).ok_or("NATIVE_ACCOUNT_GRAPH")?;
                    let r = memo.get(&right).ok_or("NATIVE_ACCOUNT_GRAPH")?;
                    let count = l.0.checked_add(r.0).ok_or("NATIVE_ACCOUNT_COUNT")?;
                    let balance = l.1.checked_add(r.1).ok_or("NATIVE_ACCOUNT_BALANCE")?;
                    crate::ensure(count <= maximum, "NATIVE_ACCOUNT_COUNT")?;
                    memo.insert(node.id, (count, balance));
                }
                Kind::Fork { .. } => {
                    let left = super::child(db, &node, false, &empty).map_err(storage)?;
                    let right = super::child(db, &node, true, &empty).map_err(storage)?;
                    stack.push((node, true));
                    stack.push((right, false));
                    stack.push((left, false));
                }
            }
        }
        crate::ensure(
            memo.get(&root_id) == Some(&(root.count, root.balance)),
            "NATIVE_ACCOUNT_AGGREGATE",
        )?;
    }
    let stored: usize = db.query_row("SELECT count(*) FROM archive_nodes", [], |r| r.get(0))?;
    crate::ensure(stored == memo.len(), "NATIVE_ACCOUNT_ORPHAN")?;
    Ok(())
}

pub(crate) fn seed_growth(db: &Connection, state: &State) -> Result<Root> {
    let values = super::accounts(state).map_err(storage)?;
    crate::ensure(
        values.len() as u64 <= trnm_mvcc_fee::pon_executor::growth::MAX_ACCOUNTS,
        "NATIVE_ACCOUNT_COUNT",
    )?;
    let ordered = super::ordered_accounts(&values).map_err(storage)?;
    let empty = empty_hashes();
    let node = super::build(Some(db), &ordered, &empty, &mut || Ok(())).map_err(storage)?;
    let root = Root {
        node: node.as_ref().map(|n| n.id),
        digest: node.as_ref().map_or(empty[0], |n| n.lift(0, &empty)),
        count: values.len() as u64,
        balance: values.values().try_fold(0u64, |sum, a| {
            sum.checked_add(a.balance).ok_or("NATIVE_ACCOUNT_BALANCE")
        })?,
    };
    audit_growth(db, &root)?;
    Ok(root)
}

pub(crate) fn query_growth_checkpoint(
    db: &Connection,
    context: super::Context,
    block: Hash,
    height: u64,
    state_root: Hash,
    root: &Root,
) -> Result<super::Checkpoint> {
    let empty = empty_hashes();
    let node = load_root_bounded(
        db,
        root,
        &empty,
        trnm_mvcc_fee::pon_executor::growth::MAX_ACCOUNTS,
    )?;
    Ok(super::make_checkpoint(
        context,
        block,
        None,
        height,
        Some(state_root),
        node.as_ref(),
        root.count,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use trnm_protocol::pon_wire::hash;

    #[test]
    fn native_lift_arithmetic_cache_binds_every_input_and_keeps_fixed_capacity() {
        let cache = LiftCache::default();
        let mut node = Node::account(
            [7; 32],
            Account {
                balance: 19,
                nonce: 3,
            },
        );
        let empty = empty_hashes();
        for depth in [0, 1, 7, 63, 128, 255, 256] {
            assert_eq!(cache.lift(&node, depth), node.lift(depth, &empty));
            assert_eq!(cache.lift(&node, depth), node.lift(depth, &empty));
        }
        for mutation in 0..3 {
            match mutation {
                0 => node.path[0] ^= 1,
                1 => node.digest[0] ^= 1,
                _ => node.depth -= 1,
            }
            assert_eq!(cache.lift(&node, 0), node.lift(0, &empty));
        }
        for index in 0..=LiftCache::MAX_ENTRIES {
            node.digest[..8].copy_from_slice(&(index as u64).to_le_bytes());
            assert_eq!(cache.lift(&node, node.depth), node.digest);
            assert!(cache.0.borrow().len() <= LiftCache::MAX_ENTRIES);
        }
    }

    #[test]
    fn native_complete_account_root_arithmetic_cache_matches_uncached_growth_and_removal() {
        let cache = LiftCache::default();
        let mut values = BTreeMap::new();
        for count in [0, 1, 2, 3, 17, 65] {
            while values.len() < count {
                let index = values.len() as u64;
                let owner = hash(b"native-arithmetic-account", &[&index.to_le_bytes()]);
                values.insert(
                    owner,
                    Account {
                        balance: index * 13,
                        nonce: index,
                    },
                );
            }
            let expected = super::super::account_root(&values).unwrap();
            assert_eq!(
                super::super::account_root_with_lifts(&values, &cache).unwrap(),
                expected
            );
            assert_eq!(
                super::super::account_root_with_lifts(&values, &cache).unwrap(),
                expected
            );
        }
        for value in values.values_mut().step_by(3) {
            value.balance += 1;
            value.nonce += 1;
        }
        assert_eq!(
            super::super::account_root_with_lifts(&values, &cache).unwrap(),
            super::super::account_root(&values).unwrap()
        );
        while !values.is_empty() {
            values.pop_first();
            assert_eq!(
                super::super::account_root_with_lifts(&values, &cache).unwrap(),
                super::super::account_root(&values).unwrap()
            );
        }
    }

    #[test]
    fn native_account_delta_credit_before_debit_preserves_maximum_aggregate() {
        // Arithmetic/storage boundary only, not a claim that a live installed
        // genesis issues u64::MAX. The lower key credits before the higher debit.
        let db = Connection::open_in_memory().unwrap();
        db.execute_batch(crate::store::native_authenticated::DDL)
            .unwrap();
        let recipient = format!("account:{}", hex::encode([0; 32]));
        let sender = format!("account:{}", hex::encode([255; 32]));
        let before = State::from([
            (recipient.clone(), json!({"balance":0,"nonce":0})),
            (sender.clone(), json!({"balance":u64::MAX,"nonce":0})),
        ]);
        let after = State::from([
            (recipient.clone(), json!({"balance":7,"nonce":0})),
            (sender.clone(), json!({"balance":u64::MAX - 7,"nonce":1})),
        ]);
        let rows: Vec<_> = [recipient, sender]
            .into_iter()
            .map(|key| {
                (
                    key.clone(),
                    Some(serde_json::to_vec(&before[&key]).unwrap()),
                    Some(serde_json::to_vec(&after[&key]).unwrap()),
                )
            })
            .collect();
        let parent = seed(&db, &before, &mut || Ok(())).unwrap();
        let next = apply(&db, &parent, &rows, &mut || Ok(())).unwrap();
        assert_eq!(next.balance, u64::MAX);
        assert_eq!(next.count, 2);
        verify(&db, &parent, &before, &mut || Ok(())).unwrap();
        verify(&db, &next, &after, &mut || Ok(())).unwrap();
    }

    #[test]
    fn native_empty_constants_match_wire_and_keep_owned_copy_isolation() {
        let mut reference = [[0; 32]; 257];
        reference[256] = hash(b"account-archive-empty-v1", &[]);
        for depth in (0..256).rev() {
            reference[depth] = hash(
                b"account-archive-branch-v1",
                &[&reference[depth + 1], &reference[depth + 1]],
            );
        }
        assert_eq!(empty_hashes(), reference);
        for depth in 0..=256 {
            let mut owned = empty_hashes();
            owned[depth][depth % 32] ^= 0xff;
            assert_ne!(owned, reference);
            assert_eq!(empty_hashes(), reference);
        }
    }

    #[test]
    fn native_empty_constants_parallel_callers_keep_independent_values() {
        let reference = super::super::empty_hashes();
        let barrier = std::sync::Barrier::new(8);
        std::thread::scope(|scope| {
            let mut workers = Vec::new();
            for worker in 0..8 {
                let barrier = &barrier;
                let reference = &reference;
                workers.push(scope.spawn(move || {
                    barrier.wait();
                    for iteration in 0..32 {
                        let mut owned = empty_hashes();
                        assert_eq!(&owned, reference);
                        owned[worker * 32 + iteration] = [worker as u8; 32];
                        std::hint::black_box(owned);
                    }
                    assert_eq!(&empty_hashes(), reference);
                }));
            }
            for worker in workers {
                worker.join().unwrap();
            }
        });
    }

    #[test]
    #[ignore = "explicit constant-table observation; not full-node performance"]
    fn native_empty_constants_paired_cost_observation() {
        if cfg!(debug_assertions) {
            panic!("release comparison required");
        }
        assert_eq!(empty_hashes(), super::super::empty_hashes());
        let implementations: [fn() -> [Hash; 257]; 2] = [super::super::empty_hashes, empty_hashes];
        for pair in 0..8 {
            let mut checksums = [[0u8; 32]; 2];
            for arm in if pair % 2 == 0 { [0, 1] } else { [1, 0] } {
                let mut checksum = [0u8; 32];
                let start = std::time::Instant::now();
                for iteration in 0..1024 {
                    let table = std::hint::black_box(implementations[arm])();
                    let value = std::hint::black_box(table)[iteration % 257];
                    for (out, byte) in checksum.iter_mut().zip(value) {
                        *out ^= byte;
                    }
                }
                let elapsed_ns = start.elapsed().as_nanos();
                checksums[arm] = checksum;
                eprintln!(
                    "pon_native_empty_table_cost_v1 {}",
                    json!({
                        "pair":pair,"arm":if arm == 0 {"original"} else {"immutable-copy"},
                        "calls":1024,"elapsed_ns":elapsed_ns,"checksum":hex::encode(checksum),
                        "retained_constant_bytes":257*32,"warm_constant":true,
                        "whole_node_performance_qualified":false
                    })
                );
            }
            assert_eq!(checksums[0], checksums[1]);
        }
    }
}
