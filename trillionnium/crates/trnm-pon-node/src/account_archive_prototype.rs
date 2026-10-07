//! Explicit research sidecar for retained account bytes and bounded read witnesses.
//!
//! The AccountArchive connection remains a separate sidecar and is never used
//! as a partial State by M05/M06, mining, fork choice or admission. Its shared
//! Patricia primitives are also used by the explicitly selected native_store
//! backend in the Node's own transaction. The separate checked execution wrapper
//! gates semantic account accesses while retaining the complete native State.
//! A checked projection binds supplied complete State bytes; it does not establish
//! that the supplied transition was signed or admitted. Accounts are not deleted.
//! Only a verified nonmembership witness can represent a never-created account.
//! Persistent nodes and old branches grow; a bounded view is not bounded storage.
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use trnm_mvcc_fee::pon_executor::{self, State};
use trnm_protocol::pon_wire::{hash, Hash};

pub mod multiproof;
#[cfg(test)]
mod native_primitive_tests;
pub(crate) mod native_store;

pub const SCHEMA: &str = "pon-account-archive-prototype-v1";
pub const MAX_VIEW_ACCOUNTS: usize = 32;
pub const WITNESS_SIBLINGS: usize = 256;
pub const MAX_WITNESS_BYTES: usize = 4 + 32 + 32 + 1 + 16 + 256 * 32;
pub const MAX_PROJECTION_CHANGES: usize = 4096;
const MAX_NODE_BYTES: usize = 163;
const NODE_SELECT: &str = "SELECT substr(data,1,164) FROM archive_nodes WHERE id=?";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ArchiveError {
    Context,
    InvalidState,
    InvalidTransition,
    SourceRoot,
    MissingCheckpoint,
    DataUnavailable,
    CorruptRecord,
    KeyCollision,
    Conflict,
    Budget,
    InvalidWitness,
    MissingWitness,
    Nonce,
    StaleActive,
    Cancelled,
    Storage(String),
}
impl std::fmt::Display for ArchiveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for ArchiveError {}
impl From<rusqlite::Error> for ArchiveError {
    fn from(value: rusqlite::Error) -> Self {
        Self::Storage(value.to_string())
    }
}
pub type Result<T> = std::result::Result<T, ArchiveError>;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Context {
    pub network: Hash,
    pub parameters: Hash,
    pub genesis: Hash,
}
impl Context {
    fn bytes(self) -> Vec<u8> {
        [self.network, self.parameters, self.genesis].concat()
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Account {
    pub balance: u64,
    pub nonce: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct Limits {
    pub max_accounts: u64,
    pub max_node_rows: u64,
    pub max_checkpoints: u64,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_accounts: 1_000_000,
            max_node_rows: 2_000_000,
            max_checkpoints: 2048,
        }
    }
}

/// Opaque source binding. Serialize is observation, not a decoding authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Checkpoint {
    id: Hash,
    context: Context,
    branch: Hash,
    parent: Option<Hash>,
    height: u64,
    source_state_root: Option<Hash>,
    account_root: Hash,
    root_node: Option<Hash>,
    account_count: u64,
}
impl Checkpoint {
    pub fn id(&self) -> Hash {
        self.id
    }
    pub fn branch(&self) -> Hash {
        self.branch
    }
    pub fn height(&self) -> u64 {
        self.height
    }
    pub fn account_root(&self) -> Hash {
        self.account_root
    }
    pub fn account_count(&self) -> u64 {
        self.account_count
    }
    pub fn source_state_root(&self) -> Option<Hash> {
        self.source_state_root
    }
    fn unsigned(&self) -> Vec<u8> {
        let mut out = self.context.bytes();
        out.extend(self.branch);
        optional(&mut out, self.parent);
        out.extend(self.height.to_le_bytes());
        optional(&mut out, self.source_state_root);
        out.extend(self.account_root);
        optional(&mut out, self.root_node);
        out.extend(self.account_count.to_le_bytes());
        out
    }
    fn encode(&self) -> Vec<u8> {
        let mut out = b"AAC1".to_vec();
        out.extend(self.id);
        out.extend(self.unsigned());
        out
    }
    fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader(bytes);
        if r.take::<4>()? != *b"AAC1" {
            return Err(ArchiveError::CorruptRecord);
        }
        let result = Self {
            id: r.take()?,
            context: Context {
                network: r.take()?,
                parameters: r.take()?,
                genesis: r.take()?,
            },
            branch: r.take()?,
            parent: r.optional()?,
            height: u64::from_le_bytes(r.take()?),
            source_state_root: r.optional()?,
            account_root: r.take()?,
            root_node: r.optional()?,
            account_count: u64::from_le_bytes(r.take()?),
        };
        if !r.0.is_empty()
            || result.id != hash(b"account-archive-checkpoint-v1", &[&result.unsigned()])
            || result.root_node.is_none() != (result.account_count == 0)
            || (result.root_node.is_none() && result.account_root != empty_hashes()[0])
        {
            return Err(ArchiveError::CorruptRecord);
        }
        Ok(result)
    }
}
fn optional(out: &mut Vec<u8>, value: Option<Hash>) {
    out.push(u8::from(value.is_some()));
    out.extend(value.unwrap_or([0; 32]));
}
struct Reader<'a>(&'a [u8]);
impl Reader<'_> {
    fn take<const N: usize>(&mut self) -> Result<[u8; N]> {
        let out = self
            .0
            .get(..N)
            .ok_or(ArchiveError::CorruptRecord)?
            .try_into()
            .map_err(|_| ArchiveError::CorruptRecord)?;
        self.0 = &self.0[N..];
        Ok(out)
    }
    fn optional(&mut self) -> Result<Option<Hash>> {
        let flag = self.take::<1>()?[0];
        let value = self.take()?;
        match flag {
            0 if value == [0; 32] => Ok(None),
            1 => Ok(Some(value)),
            _ => Err(ArchiveError::CorruptRecord),
        }
    }
}

fn path(owner: Hash) -> Hash {
    hash(b"account-archive-key-v1", &[&owner])
}
fn bit(path: &Hash, depth: usize) -> bool {
    path[depth / 8] & (128 >> (depth % 8)) != 0
}
fn common(a: &Hash, b: &Hash) -> usize {
    for (i, (&x, &y)) in a.iter().zip(b).enumerate() {
        if x != y {
            return i * 8 + (x ^ y).leading_zeros() as usize;
        }
    }
    256
}
fn leaf(owner: Hash, account: Account) -> Hash {
    hash(
        b"account-archive-leaf-v1",
        &[
            &owner,
            &account.balance.to_le_bytes(),
            &account.nonce.to_le_bytes(),
        ],
    )
}
fn branch(left: Hash, right: Hash) -> Hash {
    hash(b"account-archive-branch-v1", &[&left, &right])
}
fn empty_hashes() -> [Hash; 257] {
    let mut out = [[0; 32]; 257];
    out[256] = hash(b"account-archive-empty-v1", &[]);
    for d in (0..256).rev() {
        out[d] = branch(out[d + 1], out[d + 1]);
    }
    out
}

#[derive(Clone, Copy)]
enum Kind {
    Leaf(Hash, Account),
    Fork {
        left: Hash,
        right: Hash,
        left_hash: Hash,
        right_hash: Hash,
    },
}
#[derive(Clone)]
struct Node {
    id: Hash,
    path: Hash,
    depth: usize,
    digest: Hash,
    kind: Kind,
}
impl Node {
    fn account(owner: Hash, value: Account) -> Self {
        let mut result = Self {
            id: [0; 32],
            path: path(owner),
            depth: 256,
            digest: leaf(owner, value),
            kind: Kind::Leaf(owner, value),
        };
        result.id = hash(b"account-archive-node-record-v1", &[&result.encode()]);
        result
    }
    fn fork(depth: usize, left: &Self, right: &Self, empty: &[Hash; 257]) -> Result<Self> {
        if depth >= left.depth
            || depth >= right.depth
            || common(&left.path, &right.path) != depth
            || bit(&left.path, depth)
            || !bit(&right.path, depth)
        {
            return Err(ArchiveError::CorruptRecord);
        }
        let left_hash = left.lift(depth + 1, empty);
        let right_hash = right.lift(depth + 1, empty);
        let mut result = Self {
            id: [0; 32],
            path: left.path,
            depth,
            digest: branch(left_hash, right_hash),
            kind: Kind::Fork {
                left: left.id,
                right: right.id,
                left_hash,
                right_hash,
            },
        };
        result.id = hash(b"account-archive-node-record-v1", &[&result.encode()]);
        Ok(result)
    }
    fn lift(&self, depth: usize, empty: &[Hash; 257]) -> Hash {
        let mut value = self.digest;
        for d in (depth..self.depth).rev() {
            value = if bit(&self.path, d) {
                branch(empty[d + 1], value)
            } else {
                branch(value, empty[d + 1])
            };
        }
        value
    }
    fn encode(&self) -> Vec<u8> {
        match self.kind {
            Kind::Leaf(owner, account) => {
                let mut out = vec![0];
                out.extend(owner);
                out.extend(account.balance.to_le_bytes());
                out.extend(account.nonce.to_le_bytes());
                out
            }
            Kind::Fork {
                left,
                right,
                left_hash,
                right_hash,
            } => {
                let mut out = vec![1];
                out.extend((self.depth as u16).to_le_bytes());
                out.extend(self.path);
                for value in [left, right, left_hash, right_hash] {
                    out.extend(value);
                }
                out
            }
        }
    }
    fn decode(id: Hash, bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_NODE_BYTES || id != hash(b"account-archive-node-record-v1", &[bytes]) {
            return Err(ArchiveError::CorruptRecord);
        }
        let mut r = Reader(bytes);
        let result = match r.take::<1>()?[0] {
            0 => {
                let owner = r.take()?;
                let value = Account {
                    balance: u64::from_le_bytes(r.take()?),
                    nonce: u64::from_le_bytes(r.take()?),
                };
                // The exact stored bytes already passed the content hash above.
                // Fixed-width decoding plus the final no-trailing-bytes check
                // gives the same canonical leaf without encoding/hash work twice.
                Self {
                    id,
                    path: path(owner),
                    depth: 256,
                    digest: leaf(owner, value),
                    kind: Kind::Leaf(owner, value),
                }
            }
            1 => {
                let depth = u16::from_le_bytes(r.take()?) as usize;
                if depth >= 256 {
                    return Err(ArchiveError::CorruptRecord);
                }
                let path = r.take()?;
                let left = r.take()?;
                let right = r.take()?;
                let left_hash = r.take()?;
                let right_hash = r.take()?;
                Self {
                    id,
                    path,
                    depth,
                    digest: branch(left_hash, right_hash),
                    kind: Kind::Fork {
                        left,
                        right,
                        left_hash,
                        right_hash,
                    },
                }
            }
            _ => return Err(ArchiveError::CorruptRecord),
        };
        if !r.0.is_empty() || result.id != id {
            return Err(ArchiveError::CorruptRecord);
        }
        Ok(result)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Witness {
    pub checkpoint: Hash,
    pub owner: Hash,
    pub account: Option<Account>,
    /// Complete, depth-indexed siblings. Compression is only an archive detail.
    pub siblings: Vec<Hash>,
}
impl Witness {
    /// Exact bounded research bytes. JSON observations have a different size.
    pub fn encode(&self) -> Result<Vec<u8>> {
        if self.siblings.len() != WITNESS_SIBLINGS {
            return Err(ArchiveError::InvalidWitness);
        }
        let mut out = b"AAW1".to_vec();
        out.extend(self.checkpoint);
        out.extend(self.owner);
        out.push(u8::from(self.account.is_some()));
        if let Some(account) = self.account {
            out.extend(account.balance.to_le_bytes());
            out.extend(account.nonce.to_le_bytes());
        }
        for sibling in &self.siblings {
            out.extend(sibling);
        }
        Ok(out)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_WITNESS_BYTES {
            return Err(ArchiveError::InvalidWitness);
        }
        let decode = || -> Result<Self> {
            let mut r = Reader(bytes);
            if r.take::<4>()? != *b"AAW1" {
                return Err(ArchiveError::InvalidWitness);
            }
            let checkpoint = r.take()?;
            let owner = r.take()?;
            let account = match r.take::<1>()?[0] {
                0 => None,
                1 => Some(Account {
                    balance: u64::from_le_bytes(r.take()?),
                    nonce: u64::from_le_bytes(r.take()?),
                }),
                _ => return Err(ArchiveError::InvalidWitness),
            };
            let siblings = (0..256).map(|_| r.take()).collect::<Result<Vec<_>>>()?;
            if !r.0.is_empty() {
                return Err(ArchiveError::InvalidWitness);
            }
            Ok(Self {
                checkpoint,
                owner,
                account,
                siblings,
            })
        };
        decode().map_err(|_| ArchiveError::InvalidWitness)
    }
}
/// Verified query bytes, not transaction, signature, balance or fork authority.
#[derive(Debug)]
pub struct CheckedAccounts {
    checkpoint: Hash,
    accounts: BTreeMap<Hash, Option<Account>>,
}
impl CheckedAccounts {
    pub fn verify(
        context: Context,
        checkpoint: &Checkpoint,
        requested: &[Hash],
        witnesses: &[Witness],
    ) -> Result<Self> {
        if context != checkpoint.context {
            return Err(ArchiveError::Context);
        }
        if requested.len() > MAX_VIEW_ACCOUNTS || requested.len() != witnesses.len() {
            return Err(ArchiveError::Budget);
        }
        let wanted: BTreeSet<_> = requested.iter().copied().collect();
        if wanted.len() != requested.len() {
            return Err(ArchiveError::InvalidWitness);
        }
        let empty = empty_hashes();
        let mut accounts = BTreeMap::new();
        for witness in witnesses {
            if witness.checkpoint != checkpoint.id
                || !wanted.contains(&witness.owner)
                || witness.siblings.len() != WITNESS_SIBLINGS
                || accounts.contains_key(&witness.owner)
            {
                return Err(ArchiveError::InvalidWitness);
            }
            let key = path(witness.owner);
            let mut digest = witness
                .account
                .map_or(empty[256], |a| leaf(witness.owner, a));
            for d in (0..256).rev() {
                digest = if bit(&key, d) {
                    branch(witness.siblings[d], digest)
                } else {
                    branch(digest, witness.siblings[d])
                };
            }
            if digest != checkpoint.account_root {
                return Err(ArchiveError::InvalidWitness);
            }
            accounts.insert(witness.owner, witness.account);
        }
        Ok(Self {
            checkpoint: checkpoint.id,
            accounts,
        })
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
            .copied()
            .ok_or(ArchiveError::MissingWitness)
    }
    /// A local query on verified bytes. No signature, funds or M06 authorization.
    pub fn check_next_nonce(&self, owner: Hash, nonce: u64) -> Result<()> {
        let previous = self.account(owner)?.map_or(0, |a| a.nonce);
        if previous.checked_add(1) == Some(nonce) {
            Ok(())
        } else {
            Err(ArchiveError::Nonce)
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct ActiveCheckpoint {
    pub checkpoint: Hash,
    pub generation: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct StorageObservation {
    pub node_rows: u64,
    pub node_payload_bytes: u64,
    pub checkpoint_rows: u64,
}

/// Verified aggregate of one retained permanent-account checkpoint. Private
/// fields prevent caller-supplied deserialization from becoming authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct AccountAggregateObservation {
    checkpoint: Hash,
    account_root: Hash,
    account_count: u64,
    account_balance: u64,
    node_rows_read: u64,
}
impl AccountAggregateObservation {
    pub fn checkpoint(&self) -> Hash {
        self.checkpoint
    }
    pub fn account_root(&self) -> Hash {
        self.account_root
    }
    pub fn account_count(&self) -> u64 {
        self.account_count
    }
    pub fn account_balance(&self) -> u64 {
        self.account_balance
    }
    pub fn node_rows_read(&self) -> u64 {
        self.node_rows_read
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct ResearchUpdate {
    pub owner: Hash,
    pub before: Option<Account>,
    pub after: Account,
}
/// One disposable research database. No production Node lifecycle calls this API.
pub struct AccountArchive {
    db: Connection,
    context: Context,
    limits: Limits,
    empty: [Hash; 257],
}
impl AccountArchive {
    pub fn open(path: &Path, context: Context, limits: Limits) -> Result<Self> {
        if limits.max_accounts == 0 || limits.max_node_rows == 0 || limits.max_checkpoints == 0 {
            return Err(ArchiveError::Budget);
        }
        let mut db = Connection::open(path)?;
        let names: Vec<String> = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")?
            .query_map([], |r| r.get(0))?.collect::<std::result::Result<_, _>>()?;
        let expected = [
            "archive_active",
            "archive_checkpoints",
            "archive_meta",
            "archive_nodes",
        ];
        if !names.is_empty() && names.iter().map(String::as_str).collect::<Vec<_>>() != expected {
            return Err(ArchiveError::Context);
        }
        if names.is_empty() {
            let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
            tx.execute_batch("CREATE TABLE archive_meta(key TEXT PRIMARY KEY,value BLOB NOT NULL); CREATE TABLE archive_nodes(id BLOB PRIMARY KEY,data BLOB NOT NULL); CREATE TABLE archive_checkpoints(id BLOB PRIMARY KEY,branch BLOB UNIQUE NOT NULL,data BLOB NOT NULL); CREATE TABLE archive_active(singleton INTEGER PRIMARY KEY CHECK(singleton=1),checkpoint BLOB NOT NULL,generation INTEGER NOT NULL);")?;
            tx.execute(
                "INSERT INTO archive_meta(key,value) VALUES('schema',?),('context',?)",
                params![SCHEMA.as_bytes(), context.bytes()],
            )?;
            tx.commit()?;
        }
        let schema: Vec<u8> = db.query_row(
            "SELECT substr(value,1,?) FROM archive_meta WHERE key='schema'",
            [SCHEMA.len() + 1],
            |r| r.get(0),
        )?;
        let stored: Vec<u8> = db.query_row(
            "SELECT substr(value,1,97) FROM archive_meta WHERE key='context'",
            [],
            |r| r.get(0),
        )?;
        if schema != SCHEMA.as_bytes() || stored != context.bytes() {
            return Err(ArchiveError::Context);
        }
        db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;")?;
        let result = Self {
            db,
            context,
            limits,
            empty: empty_hashes(),
        };
        check_budget(&result.db, limits)?;
        {
            let mut statement = result.db.prepare("SELECT substr(id,1,33),substr(branch,1,33),substr(data,1,312) FROM archive_checkpoints")?;
            let mut rows = statement.query([])?;
            while let Some(row) = rows.next()? {
                let id: Vec<u8> = row.get(0)?;
                let branch: Vec<u8> = row.get(1)?;
                let data: Vec<u8> = row.get(2)?;
                let checkpoint = Checkpoint::decode(&data)?;
                if id != checkpoint.id
                    || branch != checkpoint.branch
                    || checkpoint.context != context
                {
                    return Err(ArchiveError::CorruptRecord);
                }
                if checkpoint.account_count > limits.max_accounts {
                    return Err(ArchiveError::Budget);
                }
            }
        }
        if let Some(active) = result.active()? {
            let checkpoint = result.checkpoint(active.checkpoint)?;
            checked_root(&result.db, &checkpoint, &result.empty)?;
        }
        Ok(result)
    }
    pub fn checkpoint(&self, id: Hash) -> Result<Checkpoint> {
        load_checkpoint(&self.db, self.context, id)
    }
    pub fn active(&self) -> Result<Option<ActiveCheckpoint>> {
        active(&self.db)
    }
    pub fn observation(&self) -> Result<StorageObservation> {
        observation(&self.db)
    }

    /// Recompute count and balance from every authenticated leaf reachable from
    /// one retained checkpoint. This is a storage/commitment observation only;
    /// it does not authorize execution, chain selection or ledger growth.
    pub fn aggregate_observation(
        &self,
        checkpoint_id: Hash,
        progress: &mut dyn FnMut() -> Result<()>,
    ) -> Result<AccountAggregateObservation> {
        let checkpoint = self.checkpoint(checkpoint_id)?;
        if checkpoint.account_count > self.limits.max_accounts {
            return Err(ArchiveError::Budget);
        }
        let mut stack = checked_root(&self.db, &checkpoint, &self.empty)?
            .into_iter()
            .collect::<Vec<_>>();
        let mut seen = BTreeSet::new();
        let mut account_count = 0u64;
        let mut account_balance = 0u64;
        while let Some(node) = stack.pop() {
            progress()?;
            if !seen.insert(node.id) || seen.len() as u64 > self.limits.max_node_rows {
                return Err(ArchiveError::CorruptRecord);
            }
            match node.kind {
                Kind::Leaf(_, account) => {
                    account_count = account_count
                        .checked_add(1)
                        .ok_or(ArchiveError::Budget)?;
                    account_balance = account_balance
                        .checked_add(account.balance)
                        .ok_or(ArchiveError::InvalidState)?;
                }
                Kind::Fork { .. } => {
                    stack.push(child(&self.db, &node, true, &self.empty)?);
                    stack.push(child(&self.db, &node, false, &self.empty)?);
                }
            }
        }
        progress()?;
        if account_count != checkpoint.account_count {
            return Err(ArchiveError::CorruptRecord);
        }
        Ok(AccountAggregateObservation {
            checkpoint: checkpoint.id,
            account_root: checkpoint.account_root,
            account_count,
            account_balance,
            node_rows_read: seen.len() as u64,
        })
    }
    /// Records supplied complete initial bytes after the existing full-root check.
    /// The caller, not this sidecar, establishes native genesis/admission provenance.
    pub fn project_initial(&mut self, state: &State, expected_root: Hash) -> Result<Checkpoint> {
        let actual = pon_executor::root(state).map_err(|_| ArchiveError::InvalidState)?;
        if actual != expected_root {
            return Err(ArchiveError::SourceRoot);
        }
        let values = accounts(state)?;
        self.seed(self.context.genesis, Some(actual), &values, &mut || Ok(()))
    }
    /// Explicit synthetic account-space experiment, without a source ledger root.
    /// This path can exceed the current ledger's 65,536 *total state key* limit.
    pub fn seed_research_accounts(
        &mut self,
        label: Hash,
        values: &BTreeMap<Hash, Account>,
        progress: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Checkpoint> {
        self.seed(label, None, values, progress)
    }
    fn seed(
        &mut self,
        label: Hash,
        source: Option<Hash>,
        values: &BTreeMap<Hash, Account>,
        progress: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Checkpoint> {
        if values.len() as u64 > self.limits.max_accounts {
            return Err(ArchiveError::Budget);
        }
        let ordered = ordered_accounts(values)?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        progress()?;
        let root = build(Some(&tx), &ordered, &self.empty, progress)?;
        let checkpoint = make_checkpoint(
            self.context,
            label,
            None,
            0,
            source,
            root.as_ref(),
            values.len() as u64,
        );
        save_checkpoint(&tx, &checkpoint)?;
        check_budget(&tx, self.limits)?;
        progress()?;
        tx.commit()?;
        Ok(checkpoint)
    }
    /// Full before/after scans are deliberate. This is not a stateless executor.
    /// Inactive checkpoints may persist; activation is a separate explicit CAS.
    pub fn project_successor(
        &mut self,
        parent_id: Hash,
        before: &State,
        after: &State,
        branch_id: Hash,
        height: u64,
        progress: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Checkpoint> {
        let before_root = pon_executor::root(before).map_err(|_| ArchiveError::InvalidState)?;
        let after_root = pon_executor::root(after).map_err(|_| ArchiveError::InvalidState)?;
        let old = accounts(before)?;
        let new = accounts(after)?;
        if new.len() as u64 > self.limits.max_accounts {
            return Err(ArchiveError::Budget);
        }
        let old_root = account_root(&old)?;
        let new_root = account_root(&new)?;
        let mut changed = Vec::new();
        for (owner, value) in &old {
            if new.get(owner).is_none_or(|next| next.nonce < value.nonce) {
                return Err(ArchiveError::InvalidTransition);
            }
        }
        for (&owner, &value) in &new {
            if old.get(&owner) != Some(&value) {
                changed.push((owner, value));
            }
        }
        if changed.len() > MAX_PROJECTION_CHANGES {
            return Err(ArchiveError::Budget);
        }
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let parent = load_checkpoint(&tx, self.context, parent_id)?;
        if parent.source_state_root != Some(before_root)
            || parent.account_count != old.len() as u64
            || parent.account_root != old_root
        {
            return Err(ArchiveError::SourceRoot);
        }
        if parent.height.checked_add(1) != Some(height) {
            return Err(ArchiveError::InvalidTransition);
        }
        let mut root = checked_root(&tx, &parent, &self.empty)?;
        progress()?;
        for (owner, value) in changed {
            // The witness authenticates the old leaf against this source parent.
            let witnessed = witness_from_root(&tx, &parent, owner, &self.empty)?.0;
            if witnessed.account != old.get(&owner).copied() {
                return Err(ArchiveError::SourceRoot);
            }
            let next = Node::account(owner, value);
            save_node(&tx, &next)?;
            root = Some(insert(&tx, root.as_ref(), next, &self.empty, progress)?);
        }
        let checkpoint = make_checkpoint(
            self.context,
            branch_id,
            Some(parent.id),
            height,
            Some(after_root),
            root.as_ref(),
            new.len() as u64,
        );
        if checkpoint.account_root != new_root {
            return Err(ArchiveError::SourceRoot);
        }
        save_checkpoint(&tx, &checkpoint)?;
        check_budget(&tx, self.limits)?;
        progress()?;
        tx.commit()?;
        Ok(checkpoint)
    }
    /// Explicit synthetic-space COW updates. Neither parent nor child has a ledger
    /// source root. Input old leaves are authenticated; deletion is not offered.
    pub fn research_successor(
        &mut self,
        parent_id: Hash,
        branch_id: Hash,
        updates: &[ResearchUpdate],
        progress: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Checkpoint> {
        if updates.len() > MAX_VIEW_ACCOUNTS {
            return Err(ArchiveError::Budget);
        }
        let distinct: BTreeSet<_> = updates.iter().map(|u| u.owner).collect();
        if distinct.len() != updates.len() {
            return Err(ArchiveError::InvalidTransition);
        }
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let parent = load_checkpoint(&tx, self.context, parent_id)?;
        if parent.source_state_root.is_some() {
            return Err(ArchiveError::InvalidTransition);
        }
        let mut root = checked_root(&tx, &parent, &self.empty)?;
        let mut count = parent.account_count;
        for update in updates {
            progress()?;
            let witness = witness_from_root(&tx, &parent, update.owner, &self.empty)?.0;
            if witness.account != update.before {
                return Err(ArchiveError::SourceRoot);
            }
            if update
                .before
                .is_some_and(|before| update.after.nonce < before.nonce)
            {
                return Err(ArchiveError::InvalidTransition);
            }
            count = count
                .checked_add(u64::from(update.before.is_none()))
                .ok_or(ArchiveError::Budget)?;
            if count > self.limits.max_accounts {
                return Err(ArchiveError::Budget);
            }
            let leaf = Node::account(update.owner, update.after);
            save_node(&tx, &leaf)?;
            root = Some(insert(&tx, root.as_ref(), leaf, &self.empty, progress)?);
        }
        let height = parent.height.checked_add(1).ok_or(ArchiveError::Budget)?;
        let checkpoint = make_checkpoint(
            self.context,
            branch_id,
            Some(parent.id),
            height,
            None,
            root.as_ref(),
            count,
        );
        save_checkpoint(&tx, &checkpoint)?;
        check_budget(&tx, self.limits)?;
        progress()?;
        tx.commit()?;
        Ok(checkpoint)
    }
    /// No chainwork or admission check is implied. Caller chooses the observed branch.
    pub fn activate(
        &mut self,
        expected: Option<ActiveCheckpoint>,
        checkpoint: Hash,
        progress: &mut dyn FnMut() -> Result<()>,
    ) -> Result<ActiveCheckpoint> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if active(&tx)? != expected {
            return Err(ArchiveError::StaleActive);
        }
        let selected = load_checkpoint(&tx, self.context, checkpoint)?;
        checked_root(&tx, &selected, &self.empty)?;
        let generation = expected
            .map_or(Some(1), |a| a.generation.checked_add(1))
            .ok_or(ArchiveError::Budget)?;
        let generation_i64 = i64::try_from(generation).map_err(|_| ArchiveError::Budget)?;
        tx.execute("INSERT INTO archive_active(singleton,checkpoint,generation) VALUES(1,?,?) ON CONFLICT(singleton) DO UPDATE SET checkpoint=excluded.checkpoint,generation=excluded.generation", params![checkpoint.as_slice(), generation_i64])?;
        progress()?;
        tx.commit()?;
        Ok(ActiveCheckpoint {
            checkpoint,
            generation,
        })
    }
    /// Returns proof plus actual point-read count, never a missing-as-empty fallback.
    pub fn witness(&self, checkpoint: Hash, owner: Hash) -> Result<(Witness, usize)> {
        let checkpoint = self.checkpoint(checkpoint)?;
        witness_from_root(&self.db, &checkpoint, owner, &self.empty)
    }
}

pub(crate) fn accounts(state: &State) -> Result<BTreeMap<Hash, Account>> {
    let mut out = BTreeMap::new();
    for (key, value) in state {
        let Some(owner) = key.strip_prefix("account:") else {
            continue;
        };
        if owner.len() != 64
            || !owner
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(ArchiveError::InvalidState);
        }
        let mut address = [0; 32];
        hex::decode_to_slice(owner, &mut address).map_err(|_| ArchiveError::InvalidState)?;
        let account = Account::deserialize(value).map_err(|_| ArchiveError::InvalidState)?;
        if out.insert(address, account).is_some() {
            return Err(ArchiveError::InvalidState);
        }
    }
    Ok(out)
}
fn ordered_accounts(values: &BTreeMap<Hash, Account>) -> Result<Vec<(Hash, Hash, Account)>> {
    let mut ordered: Vec<_> = values
        .iter()
        .map(|(&owner, &value)| (path(owner), owner, value))
        .collect();
    ordered.sort_unstable_by_key(|row| row.0);
    if ordered.windows(2).any(|w| w[0].0 == w[1].0) {
        return Err(ArchiveError::KeyCollision);
    }
    Ok(ordered)
}
/// Complete independent-of-storage rebuild. It neither authorizes a source State
/// nor bounds global account growth. Callers bound their supplied collection.
pub fn account_root(values: &BTreeMap<Hash, Account>) -> Result<Hash> {
    let empty = empty_hashes();
    Ok(
        build(None, &ordered_accounts(values)?, &empty, &mut || Ok(()))?
            .map_or(empty[0], |n| n.lift(0, &empty)),
    )
}
fn make_checkpoint(
    context: Context,
    branch: Hash,
    parent: Option<Hash>,
    height: u64,
    source_state_root: Option<Hash>,
    root: Option<&Node>,
    count: u64,
) -> Checkpoint {
    let empty = empty_hashes();
    let mut out = Checkpoint {
        id: [0; 32],
        context,
        branch,
        parent,
        height,
        source_state_root,
        account_root: root.map_or(empty[0], |n| n.lift(0, &empty)),
        root_node: root.map(|n| n.id),
        account_count: count,
    };
    out.id = hash(b"account-archive-checkpoint-v1", &[&out.unsigned()]);
    out
}
fn save_node(db: &Connection, node: &Node) -> Result<()> {
    let bytes = node.encode();
    let changed = db
        .prepare_cached(
            "INSERT INTO archive_nodes(id,data) VALUES(?,?) ON CONFLICT(id) DO NOTHING",
        )?
        .execute(params![node.id.as_slice(), &bytes])?;
    if changed == 0 {
        let existing: Vec<u8> = db
            .prepare_cached(NODE_SELECT)?
            .query_row([node.id.as_slice()], |r| r.get(0))?;
        if existing != bytes {
            return Err(ArchiveError::CorruptRecord);
        }
    }
    Ok(())
}
fn load_node(db: &Connection, id: Hash) -> Result<Node> {
    let bytes: Option<Vec<u8>> = db
        .prepare_cached(NODE_SELECT)?
        .query_row([id.as_slice()], |r| r.get(0))
        .optional()?;
    Node::decode(id, &bytes.ok_or(ArchiveError::DataUnavailable)?)
}
fn load_checkpoint(db: &Connection, context: Context, id: Hash) -> Result<Checkpoint> {
    let row: Option<(Vec<u8>, Vec<u8>)> = db
        .query_row(
            "SELECT substr(branch,1,33),substr(data,1,312) FROM archive_checkpoints WHERE id=?",
            [id.as_slice()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let (branch, bytes) = row.ok_or(ArchiveError::MissingCheckpoint)?;
    let result = Checkpoint::decode(&bytes)?;
    if result.id != id || result.context != context || branch != result.branch {
        return Err(ArchiveError::CorruptRecord);
    }
    Ok(result)
}
fn save_checkpoint(db: &Connection, checkpoint: &Checkpoint) -> Result<()> {
    let existing: Option<(Vec<u8>, Vec<u8>)> = db
        .query_row(
            "SELECT substr(id,1,33),substr(data,1,312) FROM archive_checkpoints WHERE branch=?",
            [checkpoint.branch.as_slice()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    if let Some((id, bytes)) = existing {
        let stored = Checkpoint::decode(&bytes)?;
        if id != stored.id
            || stored.context != checkpoint.context
            || stored.branch != checkpoint.branch
        {
            return Err(ArchiveError::CorruptRecord);
        }
        return if bytes == checkpoint.encode() {
            Ok(())
        } else {
            Err(ArchiveError::Conflict)
        };
    }
    db.execute(
        "INSERT INTO archive_checkpoints(id,branch,data) VALUES(?,?,?)",
        params![
            checkpoint.id.as_slice(),
            checkpoint.branch.as_slice(),
            checkpoint.encode()
        ],
    )?;
    Ok(())
}
fn checked_root(
    db: &Connection,
    checkpoint: &Checkpoint,
    empty: &[Hash; 257],
) -> Result<Option<Node>> {
    let result = checkpoint
        .root_node
        .map(|id| load_node(db, id))
        .transpose()?;
    if result.as_ref().map_or(empty[0], |n| n.lift(0, empty)) != checkpoint.account_root {
        return Err(ArchiveError::CorruptRecord);
    }
    Ok(result)
}
fn child(db: &Connection, parent: &Node, right_side: bool, empty: &[Hash; 257]) -> Result<Node> {
    let Kind::Fork {
        left,
        right,
        left_hash,
        right_hash,
    } = parent.kind
    else {
        return Err(ArchiveError::CorruptRecord);
    };
    let out = load_node(db, if right_side { right } else { left })?;
    if out.depth <= parent.depth
        || common(&out.path, &parent.path) < parent.depth
        || bit(&out.path, parent.depth) != right_side
        || out.lift(parent.depth + 1, empty) != if right_side { right_hash } else { left_hash }
    {
        return Err(ArchiveError::CorruptRecord);
    }
    Ok(out)
}
fn build(
    db: Option<&Connection>,
    rows: &[(Hash, Hash, Account)],
    empty: &[Hash; 257],
    progress: &mut dyn FnMut() -> Result<()>,
) -> Result<Option<Node>> {
    if rows.is_empty() {
        return Ok(None);
    }
    progress()?;
    let node = if rows.len() == 1 {
        Node::account(rows[0].1, rows[0].2)
    } else {
        let depth = common(&rows[0].0, &rows[rows.len() - 1].0);
        if depth == 256 {
            return Err(ArchiveError::KeyCollision);
        }
        let split = rows.partition_point(|row| !bit(&row.0, depth));
        if split == 0 || split == rows.len() {
            return Err(ArchiveError::CorruptRecord);
        }
        let left =
            build(db, &rows[..split], empty, progress)?.ok_or(ArchiveError::CorruptRecord)?;
        let right =
            build(db, &rows[split..], empty, progress)?.ok_or(ArchiveError::CorruptRecord)?;
        Node::fork(depth, &left, &right, empty)?
    };
    if let Some(db) = db {
        save_node(db, &node)?;
    }
    Ok(Some(node))
}
fn insert(
    db: &Connection,
    existing: Option<&Node>,
    leaf: Node,
    empty: &[Hash; 257],
    progress: &mut dyn FnMut() -> Result<()>,
) -> Result<Node> {
    progress()?;
    let Some(node) = existing else {
        return Ok(leaf);
    };
    let depth = common(&node.path, &leaf.path);
    let next = if depth < node.depth {
        if bit(&leaf.path, depth) {
            Node::fork(depth, node, &leaf, empty)?
        } else {
            Node::fork(depth, &leaf, node, empty)?
        }
    } else {
        match node.kind {
            Kind::Leaf(owner, _) => {
                let Kind::Leaf(new_owner, _) = leaf.kind else {
                    return Err(ArchiveError::CorruptRecord);
                };
                if owner != new_owner {
                    return Err(ArchiveError::KeyCollision);
                }
                leaf
            }
            Kind::Fork { .. } => {
                let left = child(db, node, false, empty)?;
                let right = child(db, node, true, empty)?;
                if bit(&leaf.path, node.depth) {
                    Node::fork(
                        node.depth,
                        &left,
                        &insert(db, Some(&right), leaf, empty, progress)?,
                        empty,
                    )?
                } else {
                    Node::fork(
                        node.depth,
                        &insert(db, Some(&left), leaf, empty, progress)?,
                        &right,
                        empty,
                    )?
                }
            }
        }
    };
    save_node(db, &next)?;
    Ok(next)
}
fn witness_from_root(
    db: &Connection,
    checkpoint: &Checkpoint,
    owner: Hash,
    empty: &[Hash; 257],
) -> Result<(Witness, usize)> {
    let key = path(owner);
    let mut witness = Witness {
        checkpoint: checkpoint.id,
        owner,
        account: None,
        siblings: empty[1..].to_vec(),
    };
    let mut current = checked_root(db, checkpoint, empty)?;
    let mut reads = usize::from(current.is_some());
    while let Some(node) = current {
        if reads > 257 {
            return Err(ArchiveError::CorruptRecord);
        }
        let shared = common(&key, &node.path);
        if shared < node.depth {
            witness.siblings[shared] = node.lift(shared + 1, empty);
            break;
        }
        match node.kind {
            Kind::Leaf(stored_owner, account) => {
                if owner != stored_owner {
                    return Err(ArchiveError::KeyCollision);
                }
                witness.account = Some(account);
                break;
            }
            Kind::Fork {
                left_hash,
                right_hash,
                ..
            } => {
                let right_side = bit(&key, node.depth);
                witness.siblings[node.depth] = if right_side { left_hash } else { right_hash };
                current = Some(child(db, &node, right_side, empty)?);
                reads += 1;
            }
        }
    }
    // Validate nonmembership exclusion and compressed-path expansion before export.
    CheckedAccounts::verify(
        checkpoint.context,
        checkpoint,
        &[owner],
        std::slice::from_ref(&witness),
    )?;
    Ok((witness, reads))
}
fn active(db: &Connection) -> Result<Option<ActiveCheckpoint>> {
    let row: Option<(Vec<u8>, i64)> = db
        .query_row(
            "SELECT substr(checkpoint,1,33),generation FROM archive_active WHERE singleton=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    row.map(|(checkpoint, generation)| {
        if generation <= 0 {
            return Err(ArchiveError::CorruptRecord);
        }
        Ok(ActiveCheckpoint {
            checkpoint: checkpoint
                .try_into()
                .map_err(|_| ArchiveError::CorruptRecord)?,
            generation: generation as u64,
        })
    })
    .transpose()
}
fn observation(db: &Connection) -> Result<StorageObservation> {
    let (nodes, payload): (u64, u64) = db.query_row(
        "SELECT count(*),coalesce(sum(length(data)),0) FROM archive_nodes",
        [],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    let checkpoints = db.query_row("SELECT count(*) FROM archive_checkpoints", [], |r| r.get(0))?;
    Ok(StorageObservation {
        node_rows: nodes,
        node_payload_bytes: payload,
        checkpoint_rows: checkpoints,
    })
}
fn check_budget(db: &Connection, limits: Limits) -> Result<()> {
    let observed = observation(db)?;
    if observed.node_rows > limits.max_node_rows
        || observed.checkpoint_rows > limits.max_checkpoints
    {
        Err(ArchiveError::Budget)
    } else {
        Ok(())
    }
}
