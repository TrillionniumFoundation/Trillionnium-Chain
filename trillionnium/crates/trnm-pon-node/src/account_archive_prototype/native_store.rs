//! Transaction-local Patricia storage for the explicitly selected native backend.
//!
//! This reuses the established node bytes and hashes, but never opens a sidecar
//! or commits a transaction. The native owner supplies its own SQLite connection
//! and commits account nodes with the actual block, deltas and state commitment.
use super::{Account, ArchiveError, Kind, Node};
use crate::account_archive_execution::state_witness::CurrentAccounts;
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
#[path = "native_scoped_readback.rs"]
pub(crate) mod scoped_readback;

/// Exact mathematical inputs only. Every stored node is still read from SQL.
/// Node decoding can reuse only the complete actual bytes and expected ID;
/// compressed-path hashes bind all their original inputs separately. No row,
/// graph, state, ancestry or commit verdict survives a call.
type LiftInput = (Hash, Hash, usize, usize);
// Fixed eight-way buckets keep scans larger than the cache from discarding
// every established input at once, while still admitting a new working set.
// The index is only a bounded lookup hint. All fields of LiftInput must match.
const LIFT_WAYS: usize = 8;
const LIFT_BUCKETS: usize = LiftCache::MAX_ENTRIES / LIFT_WAYS;
type LiftEntry = (LiftInput, Hash);
type LiftPage = [Option<LiftEntry>; LIFT_WAYS];
type LiftPageDirectory = Box<[Option<Box<LiftPage>>]>;
#[derive(Default)]
struct LiftEntries {
    // A missing page is an empty eight-way bucket. Neither the directory nor
    // a page exists until an insertion needs it; lookup never allocates.
    pages: Option<LiftPageDirectory>,
    retained: usize,
    replacement: u64,
}
const LIFT_MAX_SLOT_BYTES: usize = LIFT_BUCKETS * std::mem::size_of::<LiftPage>();
const LIFT_MAX_DIRECTORY_BYTES: usize = LIFT_BUCKETS * std::mem::size_of::<Option<Box<LiftPage>>>();
// Charge every allocated page, the directory and its RefCell owner. The full
// table adds one pointer per bucket over eager storage; the 1 MiB ceiling is
// unchanged. This is not an RSS bound: allocator metadata, temporary allocations,
// stacks, SQLite, the compiled empty table and the decoder/other caches are excluded.
const LIFT_SOFTWARE_CHARGE: usize =
    LIFT_MAX_SLOT_BYTES + LIFT_MAX_DIRECTORY_BYTES + std::mem::size_of::<RefCell<LiftEntries>>();
const _: () = assert!(LIFT_SOFTWARE_CHARGE <= 1024 * 1024);
const _: () = assert!(LiftCache::MAX_ENTRIES.is_multiple_of(LIFT_WAYS));

impl LiftEntries {
    fn bucket(key: &LiftInput) -> usize {
        let lane = u16::from_le_bytes([key.0[0], key.0[1]])
            ^ u16::from_le_bytes([key.1[0], key.1[1]])
            ^ (key.2 as u16).rotate_left(3)
            ^ (key.3 as u16).rotate_left(7);
        (usize::from(lane) % (LiftCache::MAX_ENTRIES / LIFT_WAYS)) * LIFT_WAYS
    }

    fn get(&self, key: &LiftInput) -> Option<&Hash> {
        let start = Self::bucket(key);
        self.pages.as_ref()?[start / LIFT_WAYS]
            .as_ref()?
            .iter()
            .flatten()
            .find_map(|(input, value)| (input == key).then_some(value))
    }

    fn insert(&mut self, key: LiftInput, value: Hash) {
        let start = Self::bucket(&key);
        let pages = self
            .pages
            .get_or_insert_with(|| vec![None; LIFT_BUCKETS].into_boxed_slice());
        let page = pages[start / LIFT_WAYS].get_or_insert_with(|| Box::new([None; LIFT_WAYS]));
        for entry in page.iter_mut() {
            match entry {
                Some((input, output)) if *input == key => {
                    *output = value;
                    return;
                }
                None => {
                    *entry = Some((key, value));
                    self.retained += 1;
                    return;
                }
                _ => (),
            }
        }
        // This deterministic sampler controls only which exact arithmetic is
        // retained. It is not a security random source. A FIFO hand makes a
        // cyclic scan of nine inputs miss forever in an eight-way bucket;
        // sampling a slot avoids that systematic eviction order. A collision
        // always falls back to the original lift, never to another key's value.
        self.replacement = self
            .replacement
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        let victim = (self.replacement >> 32) as usize % LIFT_WAYS;
        page[victim] = Some((key, value));
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.retained
    }

    #[cfg(test)]
    fn allocated_pages(&self) -> usize {
        self.pages
            .as_ref()
            .map_or(0, |pages| pages.iter().flatten().count())
    }

    #[cfg(test)]
    fn directory_bytes(&self) -> usize {
        self.pages.as_ref().map_or(0, |pages| {
            pages.len() * std::mem::size_of::<Option<Box<LiftPage>>>()
        })
    }

    #[cfg(test)]
    fn software_charge(&self) -> usize {
        self.directory_bytes()
            + self.allocated_pages() * std::mem::size_of::<LiftPage>()
            + std::mem::size_of::<RefCell<Self>>()
    }
}

#[derive(Default)]
pub(crate) struct LiftCache(RefCell<LiftEntries>, node_decode::NodeDecodeArithmetic);
impl LiftCache {
    const MAX_ENTRIES: usize = 8192;

    pub(crate) fn decode_observation(&self) -> serde_json::Value {
        self.1.observation()
    }

    pub(super) fn lift(&self, node: &Node, depth: usize) -> Hash {
        self.lift_parts(node.path, node.digest, node.depth, depth)
    }

    // These are exactly the original mathematical inputs. A commitment-only
    // subtree has no stored record or ID; neither enters a lift computation.
    pub(super) fn lift_parts(
        &self,
        path: Hash,
        digest: Hash,
        source_depth: usize,
        depth: usize,
    ) -> Hash {
        // The original lift performs no branch hashes at this exact depth.
        // Do not occupy or evict arithmetic entries for an identity result.
        if depth == source_depth {
            return digest;
        }
        let key = (path, digest, source_depth, depth);
        if let Ok(entries) = self.0.try_borrow() {
            if let Some(value) = entries.get(&key) {
                return *value;
            }
        }
        // The omitted empty table is the immutable compiled grammar, never an
        // input supplied by a caller, database, record or selected block.
        let value = super::lift_digest(&path, digest, source_depth, depth, &empty_hashes());
        if let Ok(mut entries) = self.0.try_borrow_mut() {
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
    // Preserve the old empty-prefix result for callers outside apply_bounded.
    crate::ensure(key.starts_with("account:"), "NATIVE_ACCOUNT_ROW")
        .map_err(Error::local_integrity)?;
    super::account_row(key, &value).map_err(storage)
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

#[cfg(test)]
#[path = "native_apply_reader_tests.rs"]
mod apply_reader_tests;

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
    verify_account_values(db, root, &actual, progress, lifts, &empty)
}

/// Reuse parsing from the complete commitment made in this same operation.
/// The projection must borrow this exact State; a foreign State falls back to
/// the original parser. No SQL row, graph result or progress check is reused.
pub(crate) fn verify_with_current_accounts(
    db: &Connection,
    root: &Root,
    state: &State,
    progress: &mut dyn FnMut() -> Result<()>,
    lifts: Option<&LiftCache>,
    current_accounts: &CurrentAccounts<'_>,
) -> Result<()> {
    match current_accounts.values_for(state) {
        Some(actual) => {
            let empty = empty_hashes();
            verify_account_values(db, root, actual, progress, lifts, &empty)
        }
        None => verify_with_lifts(db, root, state, progress, lifts),
    }
}

fn verify_account_values(
    db: &Connection,
    root: &Root,
    actual: &BTreeMap<Hash, Account>,
    progress: &mut dyn FnMut() -> Result<()>,
    lifts: Option<&LiftCache>,
    empty: &[Hash; 257],
) -> Result<()> {
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
                lifts.map_or_else(|| node.lift(0, empty), |cache| cache.lift(node, 0))
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
                    child_with_lifts(&mut reader, &node, true, empty, lifts).map_err(storage)?,
                );
                stack.push(
                    child_with_lifts(&mut reader, &node, false, empty, lifts).map_err(storage)?,
                );
            }
        }
    }
    crate::ensure(
        retained == *actual && retained.len() as u64 == root.count && balance == root.balance,
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

    // Frozen eager algorithm from 36c8effa32f004fdde30c139eab206af7f4fad8f.
    // Keep addressing, scan order and replacement independent of paged helpers.
    #[derive(Default)]
    struct EagerLiftOracle {
        slots: Option<Box<[Option<LiftEntry>]>>,
        retained: usize,
        replacement: u64,
    }

    impl EagerLiftOracle {
        fn bucket(key: &LiftInput) -> usize {
            let lane = u16::from_le_bytes([key.0[0], key.0[1]])
                ^ u16::from_le_bytes([key.1[0], key.1[1]])
                ^ (key.2 as u16).rotate_left(3)
                ^ (key.3 as u16).rotate_left(7);
            (usize::from(lane) % (8192 / 8)) * 8
        }

        fn get(&self, key: &LiftInput) -> Option<&Hash> {
            let slots = self.slots.as_ref()?;
            let start = Self::bucket(key);
            slots[start..start + 8]
                .iter()
                .flatten()
                .find_map(|(input, value)| (input == key).then_some(value))
        }

        fn insert(&mut self, key: LiftInput, value: Hash) {
            let start = Self::bucket(&key);
            let slots = self
                .slots
                .get_or_insert_with(|| vec![None; 8192].into_boxed_slice());
            for entry in &mut slots[start..start + 8] {
                match entry {
                    Some((input, output)) if *input == key => {
                        *output = value;
                        return;
                    }
                    None => {
                        *entry = Some((key, value));
                        self.retained += 1;
                        return;
                    }
                    _ => (),
                }
            }
            self.replacement = self
                .replacement
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let victim = (self.replacement >> 32) as usize % 8;
            slots[start + victim] = Some((key, value));
        }
    }

    fn lift_page_key(bucket: usize, index: u64) -> LiftInput {
        let mut path = [0; 32];
        path[..2].copy_from_slice(&(bucket as u16).to_le_bytes());
        path[24..].copy_from_slice(&index.to_le_bytes());
        (path, [0; 32], 256, 0)
    }

    fn assert_lift_bucket_matches(actual: &LiftEntries, eager: &EagerLiftOracle, key: &LiftInput) {
        let start = EagerLiftOracle::bucket(key);
        assert_eq!(LiftEntries::bucket(key), start);
        assert_eq!(actual.get(key), eager.get(key));
        assert_eq!(actual.len(), eager.retained);
        assert_eq!(actual.replacement, eager.replacement);
        for way in 0..8 {
            let actual_slot = actual
                .pages
                .as_ref()
                .and_then(|pages| pages[start / 8].as_ref())
                .and_then(|page| page[way].as_ref());
            let eager_slot = eager
                .slots
                .as_ref()
                .and_then(|slots| slots[start + way].as_ref());
            assert_eq!(actual_slot, eager_slot, "logical slot {}", start + way);
        }
    }

    #[test]
    fn native_lift_pages_exact_inputs_and_scan_order_match_frozen_eager() {
        let mut actual = LiftEntries::default();
        let mut eager = EagerLiftOracle::default();
        let base = lift_page_key(0, 0);
        let mut keys = [base; 7];
        keys[1].0[31] = 1;
        keys[2].1[31] = 1;
        keys[3].2 = 128;
        keys[4].3 = 8;
        keys[5].2 += 1 << 16;
        keys[6].3 += 1 << 16;
        for (index, key) in keys.iter().enumerate() {
            assert_eq!(LiftEntries::bucket(key), LiftEntries::bucket(&base));
            assert_eq!(actual.get(key), None);
            assert_lift_bucket_matches(&actual, &eager, key);
            let value = [index as u8; 32];
            actual.insert(*key, value);
            eager.insert(*key, value);
            assert_lift_bucket_matches(&actual, &eager, key);
        }
        // Overwrite every exact input before the vacant last slot, without
        // changing occupancy, allocating another page or advancing the sampler.
        for key in &keys {
            actual.insert(*key, [0xfe; 32]);
            eager.insert(*key, [0xfe; 32]);
            assert_lift_bucket_matches(&actual, &eager, key);
        }
        assert_eq!(actual.allocated_pages(), 1);
        assert_eq!(actual.len(), keys.len());
        assert_eq!(actual.replacement, 0);

        // A synthetic hole before a later exact match checks the original
        // vacancy-before-overwrite order as well as first-match lookup order.
        actual.pages.as_mut().unwrap()[0].as_mut().unwrap()[0] = None;
        eager.slots.as_mut().unwrap()[0] = None;
        actual.retained -= 1;
        eager.retained -= 1;
        actual.insert(keys[5], [0xff; 32]);
        eager.insert(keys[5], [0xff; 32]);
        assert_lift_bucket_matches(&actual, &eager, &keys[5]);
        assert_eq!(actual.get(&keys[5]), Some(&[0xff; 32]));
        assert_eq!(actual.len(), keys.len());
        assert_eq!(actual.replacement, 0);
    }

    #[test]
    fn native_lift_pages_collision_victims_and_wrapping_match_frozen_eager() {
        let mut actual = LiftEntries::default();
        let mut eager = EagerLiftOracle::default();
        for bucket in [0, 1023] {
            for index in 0..8 {
                let key = lift_page_key(bucket, index);
                actual.insert(key, [index as u8; 32]);
                eager.insert(key, [index as u8; 32]);
                assert_lift_bucket_matches(&actual, &eager, &key);
            }
        }
        let victims = [
            6, 1, 2, 1, 2, 6, 0, 6, 1, 7, 6, 4, 5, 2, 0, 4, 3, 4, 7, 7, 5, 2, 7, 5, 2, 6, 2, 6, 7,
            4, 2, 0,
        ];
        for (index, victim) in victims.into_iter().enumerate() {
            let bucket = if index % 2 == 0 { 0 } else { 1023 };
            let key = lift_page_key(bucket, index as u64 + 8);
            let value = [index as u8 + 8; 32];
            let before = *actual.pages.as_ref().unwrap()[bucket].as_deref().unwrap();
            actual.insert(key, value);
            eager.insert(key, value);
            assert_lift_bucket_matches(&actual, &eager, &key);
            let after = actual.pages.as_ref().unwrap()[bucket].as_deref().unwrap();
            for way in 0..8 {
                assert_eq!(
                    after[way],
                    if way == victim {
                        Some((key, value))
                    } else {
                        before[way]
                    }
                );
                if let Some((previous_key, _)) = before[way] {
                    assert_eq!(actual.get(&previous_key), eager.get(&previous_key));
                }
            }
        }
        // Exercise the wrapping state boundary explicitly, then mixed hits,
        // overwrites and replacements across both independently allocated pages.
        actual.replacement = u64::MAX;
        eager.replacement = u64::MAX;
        for index in 0..4096u64 {
            let bucket = if index % 3 == 0 { 0 } else { 1023 };
            let key = lift_page_key(bucket, (index * 17) % 43);
            assert_eq!(actual.get(&key), eager.get(&key));
            actual.insert(key, [index as u8; 32]);
            eager.insert(key, [index as u8; 32]);
            assert_lift_bucket_matches(&actual, &eager, &key);
        }
        assert_eq!(actual.allocated_pages(), 2);
        assert_eq!(actual.len(), 16);
    }

    #[test]
    fn native_lift_pages_sparse_full_storage_and_charge_are_bounded() {
        let mut actual = LiftEntries::default();
        let mut eager = EagerLiftOracle::default();
        let owner_bytes = std::mem::size_of::<RefCell<LiftEntries>>();
        assert_eq!(actual.software_charge(), owner_bytes);
        for bucket in 0..LIFT_BUCKETS {
            let key = lift_page_key(bucket, 0);
            assert_lift_bucket_matches(&actual, &eager, &key);
        }
        assert!(actual.pages.is_none());
        assert_eq!(actual.allocated_pages(), 0);
        assert_eq!(actual.directory_bytes(), 0);

        for index in 0..LIFT_WAYS {
            // First allocate one slot per bucket, then fill all eight ways.
            // Unoccupied slots in an allocated page count fully; missing pages
            // count zero.
            for bucket in 0..LIFT_BUCKETS {
                let key = lift_page_key(bucket, index as u64);
                actual.insert(key, [index as u8; 32]);
                eager.insert(key, [index as u8; 32]);
                assert_lift_bucket_matches(&actual, &eager, &key);
                let pages = if index == 0 { bucket + 1 } else { LIFT_BUCKETS };
                assert_eq!(actual.allocated_pages(), pages);
                assert_eq!(actual.directory_bytes(), LIFT_MAX_DIRECTORY_BYTES);
                assert_eq!(
                    actual.software_charge(),
                    owner_bytes
                        + LIFT_MAX_DIRECTORY_BYTES
                        + pages * std::mem::size_of::<LiftPage>()
                );
                assert!(actual.software_charge() <= LIFT_SOFTWARE_CHARGE);
                if index == 0 && bucket == 0 {
                    let charge = actual.software_charge();
                    assert_eq!(actual.get(&lift_page_key(1023, 0)), None);
                    assert_eq!(actual.software_charge(), charge);
                    if cfg!(target_pointer_width = "64") {
                        assert_eq!(charge, 9192);
                    }
                }
            }
        }
        assert_eq!(actual.len(), LiftCache::MAX_ENTRIES);
        assert_eq!(actual.software_charge(), LIFT_SOFTWARE_CHARGE);
        assert_eq!(actual.replacement, 0);
        let eager_charge = 8192 * std::mem::size_of::<Option<LiftEntry>>()
            + std::mem::size_of::<RefCell<EagerLiftOracle>>();
        assert_eq!(
            LIFT_SOFTWARE_CHARGE,
            eager_charge + LIFT_MAX_DIRECTORY_BYTES
        );
        if cfg!(target_pointer_width = "64") {
            assert_eq!(eager_charge, 983080);
            assert_eq!(LIFT_SOFTWARE_CHARGE, 991272);
        }
        // Fully populated replacement/overwrite never changes allocation.
        for bucket in 0..LIFT_BUCKETS {
            let key = lift_page_key(bucket, 8);
            for value in [[8; 32], [9; 32]] {
                actual.insert(key, value);
                eager.insert(key, value);
                assert_lift_bucket_matches(&actual, &eager, &key);
                assert_eq!(actual.software_charge(), LIFT_SOFTWARE_CHARGE);
            }
        }
        eprintln!(
            "pon_native_lift_page_charge {}",
            json!({
                "storage": "lazy-eight-way-bucket-pages",
                "allocated_pages": actual.allocated_pages(),
                "allocated_slots": actual.allocated_pages() * LIFT_WAYS,
                "occupied_slots": actual.len(),
                "allocated_slot_bytes": actual.allocated_pages() * std::mem::size_of::<LiftPage>(),
                "allocated_directory_bytes": actual.directory_bytes(),
                "owner_size_bytes": owner_bytes,
                "retained_software_charge_bytes": actual.software_charge(),
                "maximum_software_charge_bytes": LIFT_SOFTWARE_CHARGE,
                "hard_software_charge_ceiling_bytes": 1024 * 1024,
                "charge_is_process_rss_bound": false,
                "excluded": "allocator metadata, temporary allocations, stacks, SQLite, compiled empty table, decoder and other caches",
                "has_consensus_authority": false,
            })
        );
    }

    #[test]
    fn native_lift_pages_identity_and_borrow_fallback_do_not_allocate() {
        let cache = LiftCache::default();
        let node = Node::account(
            [0x39; 32],
            Account {
                balance: 23,
                nonce: 5,
            },
        );
        let empty = empty_hashes();
        let owner_bytes = cache.0.borrow().software_charge();
        for depth in [0, 1, 128, 256] {
            assert_eq!(
                cache.lift_parts(node.path, node.digest, depth, depth),
                node.digest
            );
        }
        assert_eq!(cache.lift(&node, node.depth), node.digest);
        {
            let entries = cache.0.borrow();
            assert_eq!(cache.lift(&node, 255), node.lift(255, &empty));
            assert_eq!(entries.software_charge(), owner_bytes);
            assert!(entries.pages.is_none());
        }
        {
            let entries = cache.0.borrow_mut();
            assert_eq!(cache.lift(&node, 0), node.lift(0, &empty));
            assert_eq!(cache.lift(&node, node.depth), node.digest);
            assert_eq!(entries.software_charge(), owner_bytes);
            assert!(entries.pages.is_none());
            assert_eq!((entries.len(), entries.replacement), (0, 0));
        }
        assert_eq!(cache.lift(&node, 255), node.lift(255, &empty));
        let charge = cache.0.borrow().software_charge();
        {
            let entries = cache.0.borrow();
            assert_eq!(cache.lift(&node, 255), node.lift(255, &empty));
            assert_eq!(cache.lift(&node, 254), node.lift(254, &empty));
            assert_eq!(entries.software_charge(), charge);
            assert_eq!((entries.len(), entries.replacement), (1, 0));
        }
        {
            let entries = cache.0.borrow_mut();
            assert_eq!(cache.lift(&node, 255), node.lift(255, &empty));
            assert_eq!(cache.lift(&node, 254), node.lift(254, &empty));
            assert_eq!(entries.software_charge(), charge);
            assert_eq!((entries.len(), entries.replacement), (1, 0));
        }
        assert_eq!(cache.1.observation()["retained"]["allocated_pages"], 0);
    }

    #[test]
    fn native_delta_row_decode_matches_complete_parser_without_temporary_state() {
        fn previous(key: &str, bytes: &[u8]) -> Result<(Hash, Account)> {
            let value = serde_json::from_slice(bytes)
                .map_err(|error| Error::from(error).local_integrity())?;
            let state = State::from([(key.to_owned(), value)]);
            let mut values = super::super::accounts(&state).map_err(storage)?;
            crate::ensure(values.len() == 1, "NATIVE_ACCOUNT_ROW")
                .map_err(Error::local_integrity)?;
            values
                .pop_first()
                .ok_or_else(|| Error::from("NATIVE_ACCOUNT_ROW").local_integrity())
        }
        let mut keys = vec![
            String::new(),
            "account;".into(),
            "account:".into(),
            format!("account:{}", "0".repeat(63)),
            format!("account:{}", "f".repeat(65)),
            format!("account:{}", "A".repeat(64)),
            format!("account:{}", "é".repeat(32)),
            format!("account:{}", "0".repeat(64)),
            format!("account:{}", "f".repeat(64)),
        ];
        for byte in 0u8..=127 {
            keys.push(format!("account:{}{}", char::from(byte), "0".repeat(63)));
        }
        let mut values = vec![
            b"{".to_vec(),
            b"null".to_vec(),
            b"[]".to_vec(),
            b"{}".to_vec(),
            br#"{"balance":0}"#.to_vec(),
            br#"{"balance":0,"nonce":0,"extra":true}"#.to_vec(),
            br#"{"balance":-1,"nonce":0}"#.to_vec(),
            br#"{"balance":0.0,"nonce":0}"#.to_vec(),
            br#"{"balance":0,"nonce":null}"#.to_vec(),
            br#"{"balance":0,"nonce":18446744073709551616}"#.to_vec(),
        ];
        for balance in [0, 1, u64::MAX] {
            for nonce in [0, 1, u64::MAX] {
                values.push(
                    serde_json::to_vec(&json!({"balance": balance, "nonce": nonce})).unwrap(),
                );
            }
        }
        for key in keys {
            for bytes in &values {
                let expected = previous(&key, bytes).map_err(|error| error.to_string());
                super::super::take_account_parse_observation();
                assert_eq!(
                    account(&key, bytes).map_err(|error| error.to_string()),
                    expected,
                    "key={key:?}, bytes={bytes:?}"
                );
                assert_eq!(super::super::take_account_parse_observation(), (0, 0));
            }
        }
    }

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
            assert_eq!(
                cache.lift_parts(node.path, node.digest, node.depth, depth),
                node.lift(depth, &empty)
            );
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
        let identity_entries = cache.0.borrow().len();
        for index in 0..=LiftCache::MAX_ENTRIES {
            node.digest[..8].copy_from_slice(&(index as u64).to_le_bytes());
            assert_eq!(cache.lift(&node, node.depth), node.digest);
            assert!(cache.0.borrow().len() <= LiftCache::MAX_ENTRIES);
        }
        assert_eq!(cache.0.borrow().len(), identity_entries);

        // Preserve the original identity controls above. These distinct inputs
        // perform one real branch hash, so the fixed-capacity boundary is still
        // exercised after identity lifts stop entering the cache.
        let capacity_cache = LiftCache::default();
        let lifted_depth = node.depth - 1;
        for index in 0..=LiftCache::MAX_ENTRIES {
            node.digest[..8].copy_from_slice(&(index as u64).to_le_bytes());
            let actual = capacity_cache.lift(&node, lifted_depth);
            assert_eq!(actual, node.lift(lifted_depth, &empty));
            assert!(capacity_cache.0.borrow().len() <= LiftCache::MAX_ENTRIES);
            if index + 1 == LiftCache::MAX_ENTRIES {
                assert_eq!(capacity_cache.0.borrow().len(), LiftCache::MAX_ENTRIES);
            }
        }
        assert_eq!(capacity_cache.0.borrow().len(), LiftCache::MAX_ENTRIES);
    }

    #[test]
    fn native_lift_cache_collisions_keep_exact_math_and_bounded_replacement() {
        let cache = LiftCache::default();
        let empty = empty_hashes();
        let base = Node::account(
            [0x51; 32],
            Account {
                balance: 19,
                nonce: 3,
            },
        );
        let key = |node: &Node| (node.path, node.digest, node.depth, 255);
        let mut colliding = Vec::new();
        for index in 0..=LIFT_WAYS {
            let mut node = base.clone();
            node.digest[24..].copy_from_slice(&(index as u64).to_le_bytes());
            assert_eq!(
                LiftEntries::bucket(&key(&node)),
                LiftEntries::bucket(&key(&base))
            );
            assert_eq!(cache.lift(&node, 255), node.lift(255, &empty));
            colliding.push(node);
        }
        assert_eq!(cache.0.borrow().len(), LIFT_WAYS);
        let mut other = base.clone();
        other.path[0] ^= 1;
        let other_value = cache.lift(&other, 255);
        assert_ne!(
            LiftEntries::bucket(&key(&other)),
            LiftEntries::bucket(&key(&base))
        );
        let mut exact_hits = 0;
        for _ in 0..16 {
            for node in &colliding {
                if cache.0.borrow().get(&key(node)).is_some() {
                    exact_hits += 1;
                }
                assert_eq!(cache.lift(node, 255), node.lift(255, &empty));
                assert_eq!(cache.0.borrow().len(), LIFT_WAYS + 1);
                assert_eq!(cache.0.borrow().get(&key(&other)), Some(&other_value));
            }
        }
        assert!(
            exact_hits > 0,
            "a cyclic over-capacity bucket must not deterministically miss on every key"
        );
        let locked = cache.0.borrow_mut();
        assert_eq!(cache.lift(&other, 255), other.lift(255, &empty));
        assert_eq!(
            cache.lift_parts(other.path, other.digest, other.depth, 255),
            other.lift(255, &empty)
        );
        assert_eq!(
            cache.lift_parts(other.path, other.digest, other.depth, other.depth),
            other.digest
        );
        assert_eq!(locked.len(), LIFT_WAYS + 1);
        drop(locked);
        let independent = LiftCache::default();
        assert_eq!(independent.0.borrow().len(), 0);
        assert!(independent.0.borrow().pages.is_none());
        assert_eq!(
            independent.lift_parts(other.path, other.digest, other.depth, other.depth),
            other.digest
        );
        assert!(independent.0.borrow().pages.is_none());
        assert_eq!(independent.lift(&other, other.depth), other.digest);
        assert!(independent.0.borrow().pages.is_none());
    }

    #[test]
    #[ignore = "explicit bounded-cache complete-graph diagnostic; not a business SLO"]
    fn native_lift_cache_complete_graph_cost_observation() {
        use rusqlite::StatementStatus;
        use sha2::{Digest, Sha256};
        use std::io::Write;
        use std::time::Instant;

        let path = std::env::var("TRNM_NATIVE_LIFT_COST_OUTPUT")
            .expect("fresh diagnostic output filename required");
        let mut out = std::fs::File::create_new(path).unwrap();
        let write = |out: &mut std::fs::File, value: serde_json::Value| {
            serde_json::to_writer(&mut *out, &value).unwrap();
            writeln!(out).unwrap();
            out.flush().unwrap();
        };
        write(
            &mut out,
            json!({
                "schema":"pon-native-lift-cache-full-graph-cost-v1",
                "kind":"source",
                "native_store_sha256":hex::encode(Sha256::digest(include_bytes!("native_store.rs"))),
                "account_archive_sha256":hex::encode(Sha256::digest(include_bytes!("../account_archive_prototype.rs"))),
                "debug_assertions":cfg!(debug_assertions),
                "cache_limit_per_instance":LiftCache::MAX_ENTRIES,
                "lift_software_charge_per_instance_bytes":LIFT_SOFTWARE_CHARGE,
                "simultaneously_live_cache_instances":2,
                "scope":"real native complete account graph including fresh SQL reads, actual account parsing and every original progress checkpoint; excludes Host checks, PQ authorization, complete State commitment, business confirmation and network",
                "samples":"two independent cold caches and 100 warm traversals per size; p99 uses nearest rank and is descriptive only"
            }),
        );
        for (count, prefilled) in [
            (1024usize, false),
            (9216, false),
            (32768, false),
            (1024, true),
            (9216, true),
        ] {
            let db = Connection::open_in_memory().unwrap();
            db.execute_batch(crate::store::native_authenticated::DDL)
                .unwrap();
            let state: State = (0..count as u64)
                .map(|index| {
                    let owner = hash(
                        b"native-lift-cache-full-graph-cost-v1",
                        &[&index.to_le_bytes()],
                    );
                    (
                        format!("account:{}", hex::encode(owner)),
                        json!({"balance":index * 7,"nonce":index}),
                    )
                })
                .collect();
            let root = seed(&db, &state, &mut || Ok(())).unwrap();
            let nodes: usize = db
                .query_row("SELECT count(*) FROM archive_nodes", [], |row| row.get(0))
                .unwrap();
            assert_eq!(nodes, count * 2 - 1);
            let caches = [LiftCache::default(), LiftCache::default()];
            if prefilled {
                let mut unrelated = Node::account(
                    [0xa9; 32],
                    Account {
                        balance: 17,
                        nonce: 6,
                    },
                );
                for cache in &caches {
                    for index in 0..LiftCache::MAX_ENTRIES {
                        unrelated.digest[..8].copy_from_slice(&(index as u64).to_le_bytes());
                        assert_eq!(
                            cache.lift(&unrelated, 255),
                            unrelated.lift(255, &empty_hashes())
                        );
                    }
                    assert_eq!(cache.0.borrow().len(), LiftCache::MAX_ENTRIES);
                }
            }
            let mut oracle_visits = 0usize;
            verify(&db, &root, &state, &mut || {
                oracle_visits += 1;
                Ok(())
            })
            .unwrap();
            assert_eq!(oracle_visits, nodes);
            let mut cold_ns = Vec::new();
            let mut warm_ns = Vec::new();
            db.flush_prepared_statement_cache();
            for pass in 0..51 {
                for instance in if pass % 2 == 0 { [0, 1] } else { [1, 0] } {
                    let cache = &caches[instance];
                    let selected_runs = || {
                        db.prepare_cached(super::super::NODE_SELECT)
                            .unwrap()
                            .get_status(StatementStatus::Run)
                    };
                    let reads_before = selected_runs();
                    let decodes_before = super::super::NODE_DECODE_CALLS.with(std::cell::Cell::get);
                    let mut visits = 0usize;
                    let start = Instant::now();
                    verify_with_lifts(
                        &db,
                        &root,
                        &state,
                        &mut || {
                            visits += 1;
                            Ok(())
                        },
                        Some(cache),
                    )
                    .unwrap();
                    let elapsed_ns = start.elapsed().as_nanos();
                    let sql_reads = selected_runs() - reads_before;
                    let original_decodes =
                        super::super::NODE_DECODE_CALLS.with(std::cell::Cell::get) - decodes_before;
                    assert_eq!(sql_reads as usize, nodes);
                    assert_eq!(visits, nodes);
                    let retained = cache.0.borrow().len();
                    assert!(retained <= LiftCache::MAX_ENTRIES);
                    if pass == 0 {
                        cold_ns.push(elapsed_ns);
                    } else {
                        warm_ns.push(elapsed_ns);
                    }
                    write(
                        &mut out,
                        json!({
                            "kind":"traversal", "accounts":count, "unrelated_prefill":prefilled,
                            "root":hex::encode(root.digest), "instance":instance,
                            "pass":pass, "temperature":if pass == 0 {"cold"} else {"warm"},
                            "elapsed_ns":elapsed_ns, "sql_reads":sql_reads,
                            "progress_checks":visits, "original_node_decodes":original_decodes,
                            "retained_lift_entries":retained,
                            "retained_lift_payload_bytes":retained * std::mem::size_of::<(LiftInput, Hash)>()
                        }),
                    );
                }
            }
            warm_ns.sort_unstable();
            assert_eq!(warm_ns.len(), 100);
            let proc_memory = std::fs::read_to_string("/proc/self/status")
                .ok()
                .map(|text| {
                    text.lines()
                        .filter(|line| line.starts_with("VmRSS:") || line.starts_with("VmHWM:"))
                        .map(str::to_owned)
                        .collect::<Vec<_>>()
                });
            write(
                &mut out,
                json!({
                    "kind":"summary", "accounts":count, "unrelated_prefill":prefilled, "cold_elapsed_ns":cold_ns,
                    "warm_samples":warm_ns.len(), "warm_p50_ns":warm_ns[49],
                    "warm_p99_ns":warm_ns[98], "warm_max_ns":warm_ns[99],
                    "live_lift_entries_total":caches.iter().map(|cache| cache.0.borrow().len()).sum::<usize>(),
                    "proc_memory":proc_memory,
                    "memory_scope":"retained payload excludes unoccupied slots and allocator bookkeeping; VmRSS/VmHWM cover this whole test process, not a cache-only charge"
                }),
            );
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
