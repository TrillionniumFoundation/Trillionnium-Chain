//! Transaction-local Patricia storage for the explicitly selected native backend.
//!
//! This reuses the established node bytes and hashes, but never opens a sidecar
//! or commits a transaction. The native owner supplies its own SQLite connection
//! and commits account nodes with the actual block, deltas and state commitment.
use super::{Account, ArchiveError, Kind, Node};
use crate::{Error, Result};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use trnm_mvcc_fee::pon_executor::State;
use trnm_protocol::pon_wire::Hash;

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
    let node = root
        .node
        .map(|id| super::load_node(db, id))
        .transpose()
        .map_err(storage)?;
    crate::ensure(
        root.count <= 65_536
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
    let empty = super::empty_hashes();
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
    let empty = super::empty_hashes();
    let original = load_root(db, parent, &empty)?;
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
    crate::ensure(count <= 65_536, "NATIVE_ACCOUNT_COUNT").map_err(Error::local_integrity)?;
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

/// Read every required node and leaf, including unchanged subtrees, and compare
/// their real bytes with the independently checked complete native State.
/// This explicit reference check remains linear in account count.
pub(crate) fn verify(
    db: &Connection,
    root: &Root,
    state: &State,
    progress: &mut dyn FnMut() -> Result<()>,
) -> Result<()> {
    let empty = super::empty_hashes();
    let actual = super::accounts(state).map_err(storage)?;
    let mut stack = load_root(db, root, &empty)?.into_iter().collect::<Vec<_>>();
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
                stack.push(super::child(db, &node, true, &empty).map_err(storage)?);
                stack.push(super::child(db, &node, false, &empty).map_err(storage)?);
            }
        }
    }
    crate::ensure(
        retained == actual && retained.len() as u64 == root.count && balance == root.balance,
        "NATIVE_ACCOUNT_STATE",
    )
    .map_err(Error::local_integrity)
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
    let empty = super::empty_hashes();
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

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
}
