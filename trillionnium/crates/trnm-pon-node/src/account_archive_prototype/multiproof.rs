//! Canonical compact account queries for the complete-State execution relation.
//!
//! AAM1 is separate from AAW1. Queried leaves and the nonempty boundary of their
//! sparse trie occur once. Empty siblings and unary paths are implicit. Verified
//! bytes retain a compressed immutable tree; updates hash only changed edges.
//! Neither this query type nor its count is a State or admission authority.
use super::{
    bit, branch, checked_root, child, common, empty_hashes, leaf, path, Account, AccountArchive,
    ArchiveError, Checkpoint, Context, Kind, Node, Reader, ResearchUpdate, Result,
};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use trnm_protocol::pon_wire::Hash;

pub const SCHEMA: &str = "pon-account-multiproof-v1";
pub const MAX_ACCOUNTS: usize = 66_049;
pub const MAX_FRONTIER_NODES: usize = 65_536;
pub const HEADER_BYTES: usize = 44;
pub const MAX_ACCOUNT_BYTES: usize = 49;
pub const FRONTIER_BYTES: usize = 66;
pub const MAX_ENCODED_BYTES: usize =
    HEADER_BYTES + MAX_ACCOUNT_BYTES * MAX_ACCOUNTS + FRONTIER_BYTES * MAX_FRONTIER_NODES;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProofAccount {
    pub owner: Hash,
    pub account: Option<Account>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FrontierNode {
    /// Depth in the original 256-bit sparse tree, never zero.
    pub depth: u16,
    /// Bits after depth are exactly zero; this is not an arbitrary representative.
    pub prefix: Hash,
    pub digest: Hash,
}

/// Deserialized values are untrusted. Only CheckedMultiproof verifies the root.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Multiproof {
    pub checkpoint: Hash,
    /// Strict hash-path order, independently of owner-byte order.
    pub accounts: Vec<ProofAccount>,
    /// Strict prefix order; only exact nonempty query-trie boundary slots.
    pub frontier: Vec<FrontierNode>,
}

fn prefix(mut key: Hash, depth: usize) -> Hash {
    if depth < 256 {
        let complete = depth / 8;
        let tail = depth % 8;
        if tail == 0 {
            key[complete..].fill(0);
        } else {
            key[complete] &= 0xff << (8 - tail);
            key[complete + 1..].fill(0);
        }
    }
    key
}

fn nearest_common(paths: &[Hash], key: Hash) -> Option<usize> {
    let next = paths.partition_point(|path| path < &key);
    paths
        .get(next)
        .into_iter()
        .chain(next.checked_sub(1).and_then(|index| paths.get(index)))
        .map(|path| common(path, &key))
        .max()
}

impl Multiproof {
    /// Borrowed dimensions are bounded before path allocations or hash work.
    pub fn encoded_len(&self) -> Result<usize> {
        if self.accounts.len() > MAX_ACCOUNTS || self.frontier.len() > MAX_FRONTIER_NODES {
            return Err(ArchiveError::Budget);
        }
        Ok(HEADER_BYTES
            + self
                .accounts
                .iter()
                .map(|account| 33 + 16 * usize::from(account.account.is_some()))
                .sum::<usize>()
            + FRONTIER_BYTES * self.frontier.len())
    }

    fn structure(&self, empty: &[Hash; 257]) -> Result<Vec<Hash>> {
        self.encoded_len()?;
        let paths: Vec<_> = self
            .accounts
            .iter()
            .map(|account| path(account.owner))
            .collect();
        if paths.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(ArchiveError::InvalidWitness);
        }
        let mut previous = None;
        for node in &self.frontier {
            let depth = usize::from(node.depth);
            if !(1..=256).contains(&depth)
                || prefix(node.prefix, depth) != node.prefix
                || previous.is_some_and(|value| value >= node.prefix)
                || node.digest == empty[depth]
                // An exact boundary shares depth-1 bits with its nearest query,
                // and contains no queried leaf. Nonmaximal/overlapping nodes
                // cannot pass this equality, even when their digests are valid.
                || nearest_common(&paths, node.prefix) != Some(depth - 1)
            {
                return Err(ArchiveError::InvalidWitness);
            }
            previous = Some(node.prefix);
        }
        Ok(paths)
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        let length = self.encoded_len()?;
        self.structure(&empty_hashes())?;
        let mut out = Vec::with_capacity(length);
        out.extend(b"AAM1");
        out.extend(self.checkpoint);
        out.extend((self.accounts.len() as u32).to_le_bytes());
        out.extend((self.frontier.len() as u32).to_le_bytes());
        for account in &self.accounts {
            out.extend(account.owner);
            out.push(u8::from(account.account.is_some()));
            if let Some(value) = account.account {
                out.extend(value.balance.to_le_bytes());
                out.extend(value.nonce.to_le_bytes());
            }
        }
        for node in &self.frontier {
            out.extend(node.depth.to_le_bytes());
            out.extend(node.prefix);
            out.extend(node.digest);
        }
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_ENCODED_BYTES {
            return Err(ArchiveError::Budget);
        }
        let decode = || -> Result<Self> {
            let mut reader = Reader(bytes);
            if reader.take::<4>()? != *b"AAM1" {
                return Err(ArchiveError::InvalidWitness);
            }
            let checkpoint = reader.take()?;
            let account_count = u32::from_le_bytes(reader.take()?) as usize;
            let frontier_count = u32::from_le_bytes(reader.take()?) as usize;
            if account_count > MAX_ACCOUNTS || frontier_count > MAX_FRONTIER_NODES {
                return Err(ArchiveError::Budget);
            }
            // Reject truncated counts before allocating either attacker-sized Vec.
            if reader.0.len() < 33 * account_count + FRONTIER_BYTES * frontier_count {
                return Err(ArchiveError::InvalidWitness);
            }
            let mut accounts = Vec::with_capacity(account_count);
            for _ in 0..account_count {
                let owner = reader.take()?;
                let account = match reader.take::<1>()?[0] {
                    0 => None,
                    1 => Some(Account {
                        balance: u64::from_le_bytes(reader.take()?),
                        nonce: u64::from_le_bytes(reader.take()?),
                    }),
                    _ => return Err(ArchiveError::InvalidWitness),
                };
                accounts.push(ProofAccount { owner, account });
            }
            let mut frontier = Vec::with_capacity(frontier_count);
            for _ in 0..frontier_count {
                frontier.push(FrontierNode {
                    depth: u16::from_le_bytes(reader.take()?),
                    prefix: reader.take()?,
                    digest: reader.take()?,
                });
            }
            if !reader.0.is_empty() {
                return Err(ArchiveError::InvalidWitness);
            }
            let result = Self {
                checkpoint,
                accounts,
                frontier,
            };
            result.structure(&empty_hashes())?;
            Ok(result)
        };
        decode().map_err(|error| match error {
            ArchiveError::Budget => error,
            _ => ArchiveError::InvalidWitness,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MultiproofProgress {
    BeforeVerification,
    Account { index: usize },
    Frontier { index: usize },
    Hash { index: usize },
    Update { index: usize },
    ArchiveRead { index: usize },
    BeforeOutput,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct MultiproofObservation {
    pub schema: &'static str,
    pub accounts: usize,
    pub frontier_nodes: usize,
    pub encoded_bytes: usize,
    pub retained_tree_nodes: usize,
    /// Actual sparse branch hashes, including the final lift, excluding the
    /// fixed empty-hash table and leaf/key hashing. Not a time measurement.
    pub verification_branch_hashes: usize,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct UpdateObservation {
    pub changed_accounts: usize,
    pub changed_forks: usize,
    pub branch_hashes: usize,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ConstructionObservation {
    /// Actual archive_nodes reads; checkpoint/context lookups are not included.
    pub archive_point_reads: usize,
    pub proof: MultiproofObservation,
    pub expanded_witnesses_allocated: usize,
}

#[derive(Debug)]
enum CheckedKind {
    Account,
    Frontier,
    Fork {
        left: usize,
        right: usize,
        left_hash: Hash,
        right_hash: Hash,
    },
}
#[derive(Debug)]
struct CheckedNode {
    prefix: Hash,
    depth: usize,
    digest: Hash,
    parent: Option<usize>,
    kind: CheckedKind,
}
#[derive(Debug)]
struct Entry {
    prefix: Hash,
    depth: usize,
    digest: Hash,
    account: Option<(Hash, Option<Account>)>,
}

fn lift(node: &CheckedNode, to: usize, empty: &[Hash; 257], hashes: &mut usize) -> Hash {
    let mut digest = node.digest;
    for depth in (to..node.depth).rev() {
        digest = if bit(&node.prefix, depth) {
            branch(empty[depth + 1], digest)
        } else {
            branch(digest, empty[depth + 1])
        };
        *hashes += 1;
    }
    digest
}

/// Opaque checked query material. It is deliberately not Deserialize. An empty
/// query checks context/checkpoint and has no access authority; it does not prove
/// a nonempty tree from zero bytes. Its only accepted update is the empty update,
/// which returns the separately supplied checkpoint root without re-proving it.
#[derive(Debug)]
pub struct CheckedMultiproof {
    checkpoint: Hash,
    root: Hash,
    accounts: BTreeMap<Hash, (Option<Account>, usize)>,
    nodes: Vec<CheckedNode>,
    root_index: Option<usize>,
    observation: MultiproofObservation,
}
impl CheckedMultiproof {
    pub fn verify(context: Context, checkpoint: &Checkpoint, proof: &Multiproof) -> Result<Self> {
        Self::verify_with_progress(context, checkpoint, proof, &|_| Ok::<_, ArchiveError>(()))
    }

    pub fn verify_with_progress<E: From<ArchiveError>>(
        context: Context,
        checkpoint: &Checkpoint,
        proof: &Multiproof,
        progress: &(impl Fn(MultiproofProgress) -> std::result::Result<(), E> + ?Sized),
    ) -> std::result::Result<Self, E> {
        let encoded_bytes = proof.encoded_len()?;
        if context != checkpoint.context {
            return Err(ArchiveError::Context.into());
        }
        if proof.checkpoint != checkpoint.id
            || proof.frontier.len() as u64 > checkpoint.account_count
        {
            return Err(ArchiveError::InvalidWitness.into());
        }
        progress(MultiproofProgress::BeforeVerification)?;
        let empty = empty_hashes();
        let paths = proof.structure(&empty)?;
        let mut entries = Vec::with_capacity(paths.len() + proof.frontier.len());
        for (index, (account, key)) in proof.accounts.iter().zip(paths).enumerate() {
            progress(MultiproofProgress::Account { index })?;
            entries.push(Entry {
                prefix: key,
                depth: 256,
                digest: account
                    .account
                    .map_or(empty[256], |value| leaf(account.owner, value)),
                account: Some((account.owner, account.account)),
            });
        }
        for (index, node) in proof.frontier.iter().enumerate() {
            progress(MultiproofProgress::Frontier { index })?;
            entries.push(Entry {
                prefix: node.prefix,
                depth: usize::from(node.depth),
                digest: node.digest,
                account: None,
            });
        }
        entries.sort_unstable_by_key(|entry| entry.prefix);
        if entries.windows(2).any(|pair| {
            common(&pair[0].prefix, &pair[1].prefix) >= pair[0].depth.min(pair[1].depth)
        }) {
            return Err(ArchiveError::InvalidWitness.into());
        }
        let mut result = Self {
            checkpoint: checkpoint.id,
            root: checkpoint.account_root,
            accounts: BTreeMap::new(),
            nodes: Vec::with_capacity(entries.len().saturating_mul(2).saturating_sub(1)),
            root_index: None,
            observation: MultiproofObservation {
                schema: SCHEMA,
                accounts: proof.accounts.len(),
                frontier_nodes: proof.frontier.len(),
                encoded_bytes,
                retained_tree_nodes: 0,
                verification_branch_hashes: 0,
            },
        };
        if !entries.is_empty() {
            let index = result.build(&entries, &empty, progress)?;
            progress(MultiproofProgress::Hash { index })?;
            let root = lift(
                &result.nodes[index],
                0,
                &empty,
                &mut result.observation.verification_branch_hashes,
            );
            if root != checkpoint.account_root {
                return Err(ArchiveError::InvalidWitness.into());
            }
            result.root_index = Some(index);
        }
        result.observation.retained_tree_nodes = result.nodes.len();
        progress(MultiproofProgress::BeforeOutput)?;
        Ok(result)
    }

    fn build<E: From<ArchiveError>>(
        &mut self,
        entries: &[Entry],
        empty: &[Hash; 257],
        progress: &(impl Fn(MultiproofProgress) -> std::result::Result<(), E> + ?Sized),
    ) -> std::result::Result<usize, E> {
        let first = entries.first().ok_or(ArchiveError::InvalidWitness)?;
        if entries.len() == 1 {
            let index = self.nodes.len();
            self.nodes.push(CheckedNode {
                prefix: first.prefix,
                depth: first.depth,
                digest: first.digest,
                parent: None,
                kind: if first.account.is_some() {
                    CheckedKind::Account
                } else {
                    CheckedKind::Frontier
                },
            });
            if let Some((owner, account)) = first.account {
                if self.accounts.insert(owner, (account, index)).is_some() {
                    return Err(ArchiveError::InvalidWitness.into());
                }
            }
            return Ok(index);
        }
        let last = entries.last().ok_or(ArchiveError::InvalidWitness)?;
        let depth = common(&first.prefix, &last.prefix);
        if depth >= first.depth.min(last.depth) {
            return Err(ArchiveError::InvalidWitness.into());
        }
        let split = entries.partition_point(|entry| !bit(&entry.prefix, depth));
        if split == 0 || split == entries.len() {
            return Err(ArchiveError::InvalidWitness.into());
        }
        let left = self.build(&entries[..split], empty, progress)?;
        let right = self.build(&entries[split..], empty, progress)?;
        let index = self.nodes.len();
        progress(MultiproofProgress::Hash { index })?;
        let left_hash = lift(
            &self.nodes[left],
            depth + 1,
            empty,
            &mut self.observation.verification_branch_hashes,
        );
        let right_hash = lift(
            &self.nodes[right],
            depth + 1,
            empty,
            &mut self.observation.verification_branch_hashes,
        );
        self.observation.verification_branch_hashes += 1;
        self.nodes.push(CheckedNode {
            prefix: prefix(first.prefix, depth),
            depth,
            digest: branch(left_hash, right_hash),
            parent: None,
            kind: CheckedKind::Fork {
                left,
                right,
                left_hash,
                right_hash,
            },
        });
        self.nodes[left].parent = Some(index);
        self.nodes[right].parent = Some(index);
        Ok(index)
    }

    pub fn checkpoint(&self) -> Hash {
        self.checkpoint
    }
    pub fn len(&self) -> usize {
        self.accounts.len()
    }
    pub fn is_empty(&self) -> bool {
        self.accounts.is_empty()
    }
    pub fn account(&self, owner: Hash) -> Result<Option<Account>> {
        self.accounts
            .get(&owner)
            .map(|(account, _)| *account)
            .ok_or(ArchiveError::MissingWitness)
    }
    pub fn values(&self) -> impl Iterator<Item = (Hash, Option<Account>)> + '_ {
        self.accounts
            .iter()
            .map(|(&owner, &(account, _))| (owner, account))
    }
    pub fn observation(&self) -> &MultiproofObservation {
        &self.observation
    }

    /// Original-parent changes in strict owner order. Accounts cannot be deleted,
    /// present zero balances remain leaves, and nonce rollback is rejected.
    pub fn root_for_updates<E: From<ArchiveError>>(
        &self,
        updates: &[ResearchUpdate],
        progress: &(impl Fn(MultiproofProgress) -> std::result::Result<(), E> + ?Sized),
    ) -> std::result::Result<(Hash, UpdateObservation), E> {
        if updates.len() > self.accounts.len() {
            return Err(ArchiveError::Budget.into());
        }
        let mut digests = BTreeMap::new();
        let mut dirty = BTreeSet::new();
        let mut previous = None;
        for (index, update) in updates.iter().enumerate() {
            progress(MultiproofProgress::Update { index })?;
            let &(before, node) = self
                .accounts
                .get(&update.owner)
                .ok_or(ArchiveError::MissingWitness)?;
            if previous.is_some_and(|owner| owner >= update.owner)
                || before != update.before
                || before == Some(update.after)
                || before.is_some_and(|value| value.nonce > update.after.nonce)
            {
                return Err(ArchiveError::InvalidTransition.into());
            }
            previous = Some(update.owner);
            digests.insert(node, leaf(update.owner, update.after));
            let mut parent = self.nodes[node].parent;
            while let Some(index) = parent {
                if !dirty.insert(index) {
                    break;
                }
                parent = self.nodes[index].parent;
            }
        }
        let mut observation = UpdateObservation {
            changed_accounts: updates.len(),
            changed_forks: dirty.len(),
            branch_hashes: 0,
        };
        if updates.is_empty() {
            progress(MultiproofProgress::BeforeOutput)?;
            return Ok((self.root, observation));
        }
        let empty = empty_hashes();
        for index in dirty {
            progress(MultiproofProgress::Hash { index })?;
            let node = &self.nodes[index];
            let CheckedKind::Fork {
                left,
                right,
                left_hash,
                right_hash,
            } = node.kind
            else {
                return Err(ArchiveError::InvalidWitness.into());
            };
            let lifted = |child: usize, unchanged: Hash, hashes: &mut usize| {
                let original = &self.nodes[child];
                if let Some(&digest) = digests.get(&child) {
                    lift(
                        &CheckedNode {
                            prefix: original.prefix,
                            depth: original.depth,
                            digest,
                            parent: None,
                            kind: CheckedKind::Frontier,
                        },
                        node.depth + 1,
                        &empty,
                        hashes,
                    )
                } else {
                    unchanged
                }
            };
            let left_hash = lifted(left, left_hash, &mut observation.branch_hashes);
            let right_hash = lifted(right, right_hash, &mut observation.branch_hashes);
            observation.branch_hashes += 1;
            digests.insert(index, branch(left_hash, right_hash));
        }
        let index = self.root_index.ok_or(ArchiveError::InvalidWitness)?;
        let original = &self.nodes[index];
        let digest = *digests.get(&index).ok_or(ArchiveError::InvalidWitness)?;
        progress(MultiproofProgress::Hash { index })?;
        let root = lift(
            &CheckedNode {
                prefix: original.prefix,
                depth: original.depth,
                digest,
                parent: None,
                kind: CheckedKind::Frontier,
            },
            0,
            &empty,
            &mut observation.branch_hashes,
        );
        progress(MultiproofProgress::BeforeOutput)?;
        Ok((root, observation))
    }
}

struct Query {
    path: Hash,
    account: ProofAccount,
}
struct Collector<'a> {
    db: &'a Connection,
    empty: &'a [Hash; 257],
    frontier: Vec<FrontierNode>,
    reads: usize,
}
impl Collector<'_> {
    fn boundary(&mut self, depth: usize, key: Hash, digest: Hash) -> Result<()> {
        if self.frontier.len() >= MAX_FRONTIER_NODES {
            return Err(ArchiveError::Budget);
        }
        self.frontier.push(FrontierNode {
            depth: depth as u16,
            prefix: prefix(key, depth),
            digest,
        });
        Ok(())
    }

    fn visit<E: From<ArchiveError>>(
        &mut self,
        node: Node,
        queries: &mut [Query],
        progress: &(impl Fn(MultiproofProgress) -> std::result::Result<(), E> + ?Sized),
    ) -> std::result::Result<(), E> {
        let lower = prefix(node.path, node.depth);
        let start = queries.partition_point(|query| query.path < lower);
        let end = start
            + queries[start..]
                .partition_point(|query| common(&query.path, &node.path) >= node.depth);
        if start == end {
            // The single retained subtree lies outside every query. Its exact
            // boundary is one bit below the longest common queried prefix.
            let at = queries.partition_point(|query| query.path < node.path);
            let shared = queries
                .get(at)
                .into_iter()
                .chain(at.checked_sub(1).and_then(|index| queries.get(index)))
                .map(|query| common(&query.path, &node.path))
                .max()
                .ok_or(ArchiveError::InvalidWitness)?;
            self.boundary(shared + 1, node.path, node.lift(shared + 1, self.empty))?;
            return Ok(());
        }
        let matching = &mut queries[start..end];
        match node.kind {
            Kind::Leaf(owner, account) => {
                if matching.len() != 1 || matching[0].account.owner != owner {
                    return Err(ArchiveError::KeyCollision.into());
                }
                matching[0].account.account = Some(account);
            }
            Kind::Fork {
                left_hash,
                right_hash,
                ..
            } => {
                let split = matching.partition_point(|query| !bit(&query.path, node.depth));
                let (left_queries, right_queries) = matching.split_at_mut(split);
                for (right_side, queries, digest) in [
                    (false, left_queries, left_hash),
                    (true, right_queries, right_hash),
                ] {
                    if queries.is_empty() {
                        let mut key = node.path;
                        if right_side {
                            key[node.depth / 8] |= 0x80 >> (node.depth % 8);
                        } else {
                            key[node.depth / 8] &= !(0x80 >> (node.depth % 8));
                        }
                        self.boundary(node.depth + 1, key, digest)?;
                    } else {
                        progress(MultiproofProgress::ArchiveRead { index: self.reads })?;
                        let child = child(self.db, &node, right_side, self.empty)?;
                        self.reads += 1;
                        self.visit(child, queries, progress)?;
                    }
                }
            }
        }
        Ok(())
    }
}

impl AccountArchive {
    pub fn multiproof(
        &self,
        checkpoint: Hash,
        requested: &[Hash],
    ) -> Result<(Multiproof, ConstructionObservation)> {
        self.multiproof_with_progress(checkpoint, requested, &|_| Ok::<_, ArchiveError>(()))
    }

    /// Direct compressed-trie traversal. No AAW1 proof or 256-sibling vector is
    /// allocated. Missing required records still fail; excluded subtrees use the
    /// authenticated parent edge and need not fetch unrelated descendant bytes.
    pub fn multiproof_with_progress<E: From<ArchiveError>>(
        &self,
        checkpoint: Hash,
        requested: &[Hash],
        progress: &(impl Fn(MultiproofProgress) -> std::result::Result<(), E> + ?Sized),
    ) -> std::result::Result<(Multiproof, ConstructionObservation), E> {
        if requested.len() > MAX_ACCOUNTS {
            return Err(ArchiveError::Budget.into());
        }
        let checkpoint = self.checkpoint(checkpoint)?;
        from_database_with_progress(&self.db, &checkpoint, requested, progress)
    }
}

/// Crate-only adapter for the explicitly selected native authenticated backend.
/// Its caller must derive the opaque checkpoint from checked native block/state
/// and durable account nodes. No serialized report or raw root is accepted here.
pub(crate) fn from_native_database(
    db: &Connection,
    checkpoint: &Checkpoint,
    requested: &[Hash],
) -> Result<(Multiproof, ConstructionObservation)> {
    from_database_with_progress(db, checkpoint, requested, &|_| Ok::<_, ArchiveError>(()))
}

fn from_database_with_progress<E: From<ArchiveError>>(
    db: &Connection,
    checkpoint: &Checkpoint,
    requested: &[Hash],
    progress: &(impl Fn(MultiproofProgress) -> std::result::Result<(), E> + ?Sized),
) -> std::result::Result<(Multiproof, ConstructionObservation), E> {
    if requested.len() > MAX_ACCOUNTS {
        return Err(ArchiveError::Budget.into());
    }
    let mut queries: Vec<_> = requested
        .iter()
        .map(|&owner| Query {
            path: path(owner),
            account: ProofAccount {
                owner,
                account: None,
            },
        })
        .collect();
    queries.sort_unstable_by_key(|query| query.path);
    if queries.windows(2).any(|pair| pair[0].path == pair[1].path) {
        return Err(ArchiveError::InvalidWitness.into());
    }
    let empty = empty_hashes();
    let mut collector = Collector {
        db,
        empty: &empty,
        frontier: Vec::new(),
        reads: 0,
    };
    if !queries.is_empty() {
        progress(MultiproofProgress::ArchiveRead { index: 0 })?;
        if let Some(root) = checked_root(db, checkpoint, &empty)? {
            collector.reads = 1;
            collector.visit(root, &mut queries, progress)?;
        }
    }
    collector.frontier.sort_unstable_by_key(|node| node.prefix);
    let proof = Multiproof {
        checkpoint: checkpoint.id,
        accounts: queries.into_iter().map(|query| query.account).collect(),
        frontier: collector.frontier,
    };
    let checked =
        CheckedMultiproof::verify_with_progress(checkpoint.context, checkpoint, &proof, progress)?;
    Ok((
        proof,
        ConstructionObservation {
            archive_point_reads: collector.reads,
            proof: checked.observation,
            expanded_witnesses_allocated: 0,
        },
    ))
}

#[cfg(test)]
#[path = "multiproof_tests.rs"]
mod tests;
