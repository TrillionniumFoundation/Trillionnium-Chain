//! Bounded graph results inside the original Node WRITE transaction only.
//! The ordinary no-scope verifier remains independent and unchanged.
use super::{child_with_lifts, empty_hashes, storage, Kind, LiftCache, Node, NodeReader, Root};
use crate::account_archive_execution::state_witness::CurrentAccounts;
use crate::store::native_authenticated::GraphAccess;
use crate::{ensure, Error, Result};
use std::collections::{BTreeMap, BTreeSet};
use trnm_protocol::pon_wire::Hash;

// The first four path bits partition leaves into at most sixteen disjoint
// subtrees. This is a fixed software bound, not a balance assumption: chosen
// owners can occupy one bucket and obtain no partial-readback improvement.
const FRONTIER_DEPTH: usize = 4;
const FRONTIER_SLOTS: usize = 1 << FRONTIER_DEPTH;
const MAX_GRAPH_NODES: u64 = 131_071;

struct Subtree {
    id: Hash,
    path: Hash,
    depth: usize,
    digest: Hash,
    nodes: u64,
    accounts: u64,
    balance: u64,
}

/// Private evidence produced by a complete successful real graph traversal.
/// It is pending until PostWriteReadback seals it after the ORIGINAL final
/// callback and no-write check. Only that owner can issue a GraphAccess loan.
/// No serialization, cloning, standalone lookup or cross-transaction owner.
pub(crate) struct Frontier {
    source_record: Hash,
    source_root: Root,
    slots: [Option<Subtree>; FRONTIER_SLOTS],
}

impl Frontier {
    pub(crate) fn source_record(&self) -> Hash {
        self.source_record
    }

    pub(crate) fn is_for(&self, record: Hash, root: &Root) -> bool {
        self.source_record == record && self.source_root == *root
    }

    #[cfg(test)]
    pub(crate) fn occupied_slots(&self) -> usize {
        self.slots.iter().flatten().count()
    }

    fn find(&self, node: &Node) -> Option<&Subtree> {
        self.slots[bucket(node)].as_ref().filter(|proof| {
            // ID binds ALL actual encoded child pointers, not just the lifted
            // account digest. A re-encoded fork can retain its digest while
            // naming a missing child, and must still enter the real traversal.
            proof.id == node.id
                && proof.path == node.path
                && proof.depth == node.depth
                && proof.digest == node.digest
                && proof.nodes > 1
        })
    }
}

fn bucket(node: &Node) -> usize {
    usize::from(node.path[0] >> (8 - FRONTIER_DEPTH))
}

struct PendingFrontier {
    frontier: Frontier,
    upper_nodes: u64,
}

impl PendingFrontier {
    fn new(source_record: Hash, source_root: &Root) -> Self {
        Self {
            frontier: Frontier {
                source_record,
                source_root: source_root.clone(),
                slots: std::array::from_fn(|_| None),
            },
            upper_nodes: 0,
        }
    }

    fn observe(&mut self, node: &Node) -> Result<()> {
        if node.depth < FRONTIER_DEPTH {
            self.upper_nodes = self
                .upper_nodes
                .checked_add(1)
                .ok_or("NATIVE_ACCOUNT_GRAPH")?;
            return Ok(());
        }
        // Original preorder DFS first encounters the highest node in this
        // four-bit region. Valid prefix/side edges put all later nodes of the
        // same bucket inside that one subtree; top-level forks are excluded.
        let proof = self.frontier.slots[bucket(node)].get_or_insert(Subtree {
            id: node.id,
            path: node.path,
            depth: node.depth,
            digest: node.digest,
            nodes: 0,
            accounts: 0,
            balance: 0,
        });
        proof.nodes = proof.nodes.checked_add(1).ok_or("NATIVE_ACCOUNT_GRAPH")?;
        if let Kind::Leaf(_, account) = node.kind {
            proof.accounts = proof
                .accounts
                .checked_add(1)
                .ok_or("NATIVE_ACCOUNT_GRAPH")?;
            // Called AFTER the original global checked balance addition. A
            // bucket overflow therefore cannot preempt an original error.
            proof.balance = proof
                .balance
                .checked_add(account.balance)
                .ok_or("NATIVE_ACCOUNT_BALANCE")?;
        }
        Ok(())
    }

    fn finish(self, nodes: usize) -> Result<Frontier> {
        let mut accounts = 0u64;
        let mut balance = 0u64;
        let mut total_nodes = self.upper_nodes;
        for proof in self.frontier.slots.iter().flatten() {
            ensure(
                proof.depth >= FRONTIER_DEPTH
                    && proof.accounts > 0
                    && proof.accounts.checked_mul(2).and_then(|n| n.checked_sub(1))
                        == Some(proof.nodes),
                "NATIVE_ACCOUNT_FRONTIER",
            )
            .map_err(Error::local_integrity)?;
            // All terms were counted in the original <=131071-node graph and
            // its checked balance, before this optional evidence is created.
            accounts = accounts
                .checked_add(proof.accounts)
                .ok_or("NATIVE_ACCOUNT_GRAPH")?;
            total_nodes = total_nodes
                .checked_add(proof.nodes)
                .ok_or("NATIVE_ACCOUNT_GRAPH")?;
            balance = balance
                .checked_add(proof.balance)
                .ok_or("NATIVE_ACCOUNT_BALANCE")?;
        }
        ensure(
            self.upper_nodes < FRONTIER_SLOTS as u64
                && total_nodes == nodes as u64
                && total_nodes <= MAX_GRAPH_NODES
                && accounts == self.frontier.source_root.count
                && balance == self.frontier.source_root.balance,
            "NATIVE_ACCOUNT_FRONTIER",
        )
        .map_err(Error::local_integrity)?;
        Ok(self.frontier)
    }
}

pub(crate) struct VerifiedGraph {
    pending: Option<Frontier>,
    source_used: Option<Hash>,
    #[cfg(test)]
    hits: usize,
}

impl VerifiedGraph {
    pub(crate) fn source_used(&self) -> Option<Hash> {
        self.source_used
    }

    pub(crate) fn into_pending(self) -> Option<Frontier> {
        self.pending
    }

    #[cfg(test)]
    pub(crate) fn hits(&self) -> usize {
        self.hits
    }
}

/// GraphAccess contains the actual immutably borrowed State/Record whose
/// COMPLETE commitment was just compared, plus at most one owner-sealed
/// frontier. There is deliberately no separately supplied raw State or Root.
pub(crate) fn verify(
    access: GraphAccess<'_, '_>,
    progress: &mut dyn FnMut() -> Result<()>,
    lifts: Option<&LiftCache>,
    current_accounts: Option<&CurrentAccounts<'_>>,
) -> Result<VerifiedGraph> {
    let db = access.connection();
    let root = access.root();
    let empty = empty_hashes();
    // Reuse only parsing from this exact immutable State. Foreign or absent
    // projections take the original parser; current SQL/graph checks follow.
    let projected = current_accounts.and_then(|current| current.values_for(access.state()));
    let parsed;
    let actual = match projected {
        Some(values) => values,
        None => {
            parsed = super::super::accounts(access.state()).map_err(storage)?;
            &parsed
        }
    };
    let mut reader = NodeReader::new(db);
    // Preserve the original load BEFORE root count/empty/digest checks. A
    // missing or wrongly typed root row retains its original error priority.
    let node = root
        .node
        .map(|id| reader.load(id, lifts))
        .transpose()
        .map_err(storage)?;
    ensure(
        root.count <= 65_536
            && root.node.is_none() == (root.count == 0)
            && node.as_ref().map_or(empty[0], |node| {
                lifts.map_or_else(|| node.lift(0, &empty), |cache| cache.lift(node, 0))
            }) == root.digest,
        "NATIVE_ACCOUNT_ROOT",
    )
    .map_err(Error::local_integrity)?;
    let mut pending = access
        .frontier()
        .is_none()
        .then(|| PendingFrontier::new(access.record_id(), root));
    let mut stack = node.into_iter().collect::<Vec<_>>();
    let mut seen = BTreeSet::new();
    let mut retained = BTreeMap::new();
    let mut balance = 0u64;
    let mut logical_nodes = 0u64;
    let mut covered_accounts = 0u64;
    let mut source_used = None;
    #[cfg(test)]
    let mut hits = 0usize;
    while let Some(node) = stack.pop() {
        // Every actually visited node retains its ORIGINAL checkpoint. The
        // certified descendants do no native traversal or synthetic progress.
        progress()?;
        logical_nodes = logical_nodes.checked_add(1).ok_or("NATIVE_ACCOUNT_GRAPH")?;
        ensure(
            seen.insert(node.id) && logical_nodes <= MAX_GRAPH_NODES,
            "NATIVE_ACCOUNT_GRAPH",
        )
        .map_err(Error::local_integrity)?;
        if let Some(frontier) = access.frontier() {
            if let Some(proof) = frontier.find(&node) {
                let nodes = logical_nodes.checked_add(proof.nodes - 1);
                let accounts = covered_accounts.checked_add(proof.accounts);
                let aggregate = balance.checked_add(proof.balance);
                if let (Some(nodes), Some(accounts), Some(aggregate)) = (nodes, accounts, aggregate)
                {
                    if nodes <= MAX_GRAPH_NODES {
                        logical_nodes = nodes;
                        covered_accounts = accounts;
                        balance = aggregate;
                        source_used = Some(frontier.source_record);
                        #[cfg(test)]
                        {
                            hits += 1;
                        }
                        continue;
                    }
                }
                // A node-limit/balance failure inside this subtree must keep
                // the original DFS error order. Do its real traversal instead
                // of reporting an aggregate error at this earlier boundary.
            }
        }
        match node.kind {
            Kind::Leaf(owner, value) => {
                ensure(
                    retained.insert(owner, value).is_none(),
                    "NATIVE_ACCOUNT_DUPLICATE",
                )
                .map_err(Error::local_integrity)?;
                balance = balance
                    .checked_add(value.balance)
                    .ok_or("NATIVE_ACCOUNT_BALANCE")?;
            }
            Kind::Fork { .. } => {
                // Current SQL rows and ALL original depth/prefix/side/lift
                // checks remain on each exposed edge, right then left.
                stack.push(
                    child_with_lifts(&mut reader, &node, true, &empty, lifts).map_err(storage)?,
                );
                stack.push(
                    child_with_lifts(&mut reader, &node, false, &empty, lifts).map_err(storage)?,
                );
            }
        }
        if let Some(pending) = pending.as_mut() {
            pending.observe(&node)?;
        }
    }
    let same_accounts = if source_used.is_none() {
        // The first graph and every no-hit traversal retain the original full
        // map comparison. No partial result is promoted to a source frontier.
        retained == *actual && retained.len() as u64 == root.count
    } else {
        // Each exposed leaf still equals the actual State. Hidden leaves are
        // covered by successful exact-ID subtrees in this unchanged writer.
        // Prefix/side edges make these regions disjoint: a repeated node/owner
        // in two branches would require its path bit to be both zero and one.
        // GraphAccess's private COMPLETE-State binding independently commits
        // ALL actual accounts (including nonce/existence) to this graph digest;
        // count and balance alone would not justify this scoped comparison.
        retained
            .iter()
            .all(|(owner, value)| actual.get(owner) == Some(value))
            && (retained.len() as u64).checked_add(covered_accounts) == Some(root.count)
            && actual.len() as u64 == root.count
    };
    ensure(
        same_accounts && balance == root.balance,
        "NATIVE_ACCOUNT_STATE",
    )
    .map_err(Error::local_integrity)?;
    Ok(VerifiedGraph {
        pending: pending
            .map(|pending| pending.finish(seen.len()))
            .transpose()?,
        source_used,
        #[cfg(test)]
        hits,
    })
}
