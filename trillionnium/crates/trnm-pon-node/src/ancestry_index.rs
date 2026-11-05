//! Local derived binary-lifting index. Seals detect inconsistent local data,
//! not a malicious owner who can rewrite the database and recompute hashes.
use crate::{ensure, Error, Result};
use rusqlite::{params, Connection, OptionalExtension};
#[cfg(test)]
use std::collections::BTreeMap;
use trnm_crypto_primitives::pon_work;
use trnm_protocol::pon_wire::{hash, Hash, Header, HEADER_BYTES};

pub(crate) const LEVELS: u8 = 63;
pub(crate) const READ_SQL_BUDGET: u64 = 1024;
const WRITE_SQL_BUDGET: u64 = 4096;
const MAX_PACKET: usize = 1_048_576;
pub(crate) const DDL:&str="CREATE TABLE ancestry_jump(block BLOB NOT NULL CHECK(length(block)=32),level INTEGER NOT NULL CHECK(level>=0 AND level<63),ancestor BLOB NOT NULL CHECK(length(ancestor)=32),ancestor_height INTEGER NOT NULL CHECK(ancestor_height>=0),left_seal BLOB NOT NULL CHECK(length(left_seal)=32),right_seal BLOB NOT NULL CHECK(length(right_seal)=32),seal BLOB NOT NULL CHECK(length(seal)=32),PRIMARY KEY(block,level),FOREIGN KEY(block) REFERENCES blocks(id),FOREIGN KEY(ancestor) REFERENCES blocks(id)) WITHOUT ROWID;";
type StoredShape = (u64, Option<usize>, usize, Option<usize>);
type HeaderProjection = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);
type JumpProjection = (Vec<u8>, u64, Vec<u8>, Vec<u8>, Vec<u8>);
#[derive(Clone, Copy)]
pub(crate) struct Context {
    pub network: Hash,
    pub parameters: Hash,
    pub genesis: Hash,
}
#[derive(Clone, Copy)]
struct Metadata {
    parent: Option<Hash>,
    height: u64,
}
#[derive(Clone, Copy, PartialEq, Eq)]
struct Row {
    block: Hash,
    level: u8,
    ancestor: Hash,
    ancestor_height: u64,
    left_seal: Hash,
    right_seal: Hash,
    seal: Hash,
}
/// Expected bytes are operation-local and can only be made by the checked
/// insertion below. Later writes in the same transaction must preserve them.
pub(crate) struct Inserted {
    block: Hash,
    rows: Vec<Row>,
}
struct Budget<'a> {
    used: u64,
    maximum: u64,
    progress: &'a mut dyn FnMut(u64) -> Result<()>,
    origin: BudgetOrigin,
    #[cfg(test)]
    reads: Option<&'a mut ReadSet>,
}
#[derive(Clone, Copy)]
enum BudgetOrigin {
    Owner,
    PublicHistoryRequest,
}
struct ReadMode<'a> {
    origin: BudgetOrigin,
    #[cfg(test)]
    reads: Option<&'a mut ReadSet>,
    _scope: std::marker::PhantomData<&'a ()>,
}
impl Budget<'_> {
    fn charge(&mut self) -> Result<()> {
        if self.used == self.maximum {
            // Only exhaustion here selects a request origin. Trusted maximum
            // validation, stored corruption and progress callback errors do not.
            return Err(match self.origin {
                BudgetOrigin::PublicHistoryRequest => Error::public_history_budget(),
                BudgetOrigin::Owner => Error::from("ANCESTRY_INDEX_BUDGET"),
            });
        }
        self.used += 1;
        (self.progress)(self.used)
    }
    #[cfg(test)]
    fn observe(&mut self, key: ReadKey, digest: impl FnOnce() -> Hash) -> Result<()> {
        if let Some(reads) = self.reads.as_deref_mut() {
            reads.observe(key, digest())?;
        }
        Ok(())
    }
}

#[cfg(test)]
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum ReadKey {
    Shape(Hash),
    Header(Hash),
    Jump(Hash, u8),
}

/// Exact query facts for one readonly snapshot. No successful ancestry verdict
/// is stored or retained across operations. First-read order is preserved.
#[cfg(test)]
#[derive(Default)]
pub(crate) struct ReadSet {
    positions: BTreeMap<ReadKey, usize>,
    entries: Vec<(ReadKey, Hash)>,
}
#[cfg(test)]
impl ReadSet {
    fn observe(&mut self, key: ReadKey, digest: Hash) -> Result<()> {
        if let Some(index) = self.positions.get(&key) {
            return ensure(self.entries[*index].1 == digest, "ANCESTRY_INDEX_STRUCTURE");
        }
        ensure(
            self.entries.len() < READ_SQL_BUDGET as usize,
            "ANCESTRY_INDEX_BUDGET",
        )?;
        self.positions.insert(key, self.entries.len());
        self.entries.push((key, digest));
        Ok(())
    }
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }
    pub(crate) fn revalidate(
        &self,
        db: &Connection,
        progress: &mut dyn FnMut(u64) -> Result<()>,
    ) -> Result<()> {
        for (index, (key, expected)) in self.entries.iter().enumerate() {
            progress(index as u64)?;
            let actual = (|| -> Result<Hash> {
                Ok(match *key {
                    ReadKey::Shape(id) => shape_digest(&read_shape(db, id)?),
                    ReadKey::Header(id) => header_digest(&read_header(db, id)?),
                    ReadKey::Jump(id, level) => jump_digest(&read_jump(db, id, level)?),
                })
            })()
            .map_err(Error::local_integrity)?;
            ensure(actual == *expected, "ANCESTRY_INDEX_STRUCTURE")
                .map_err(Error::local_integrity)?;
        }
        progress(self.entries.len() as u64)
    }
}

fn read_shape(db: &Connection, id: Hash) -> rusqlite::Result<Option<StoredShape>> {
    db.query_row(
        "SELECT height,length(parent),length(state_root),length(packet) FROM blocks WHERE id=?",
        [id.as_slice()],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
    )
    .optional()
}
fn read_header(db: &Connection, id: Hash) -> rusqlite::Result<Option<HeaderProjection>> {
    db.query_row("SELECT parent,state_root,substr(packet,1,?),substr(packet,-32) FROM blocks WHERE id=? AND length(parent)=32 AND length(state_root)=32 AND length(packet)<=?",
        params![HEADER_BYTES,id.as_slice(),MAX_PACKET], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).optional()
}
fn read_jump(db: &Connection, id: Hash, level: u8) -> rusqlite::Result<Option<JumpProjection>> {
    db.query_row("SELECT ancestor,ancestor_height,left_seal,right_seal,seal FROM ancestry_jump WHERE block=? AND level=? AND length(ancestor)=32 AND length(left_seal)=32 AND length(right_seal)=32 AND length(seal)=32",
        params![id.as_slice(),level], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?))).optional()
}
#[cfg(test)]
fn shape_digest(value: &Option<StoredShape>) -> Hash {
    match value {
        None => hash(b"native-history-read-shape-v1", &[&[0]]),
        Some((height, parent, root, packet)) => {
            let optional = |v: Option<usize>| {
                let mut bytes = [0; 9];
                bytes[0] = u8::from(v.is_some());
                bytes[1..].copy_from_slice(&(v.unwrap_or(0) as u64).to_le_bytes());
                bytes
            };
            hash(
                b"native-history-read-shape-v1",
                &[
                    &[1],
                    &height.to_le_bytes(),
                    &optional(*parent),
                    &(*root as u64).to_le_bytes(),
                    &optional(*packet),
                ],
            )
        }
    }
}
#[cfg(test)]
fn header_digest(value: &Option<HeaderProjection>) -> Hash {
    match value {
        None => hash(b"native-history-read-header-v1", &[&[0]]),
        Some((parent, root, prefix, trace)) => hash(
            b"native-history-read-header-v1",
            &[&[1], parent, root, prefix, trace],
        ),
    }
}
#[cfg(test)]
fn jump_digest(value: &Option<JumpProjection>) -> Hash {
    match value {
        None => hash(b"native-history-read-jump-v1", &[&[0]]),
        Some((ancestor, height, left, right, seal)) => hash(
            b"native-history-read-jump-v1",
            &[&[1], ancestor, &height.to_le_bytes(), left, right, seal],
        ),
    }
}
fn bytes32(bytes: Vec<u8>) -> Result<Hash> {
    bytes.try_into().map_err(|_| "ANCESTRY_INDEX_HASH".into())
}
fn seal(ctx: Context, row: &Row, metadata: Metadata) -> Hash {
    hash(
        b"native-derived-ancestry-row-v1",
        &[
            &ctx.network,
            &ctx.parameters,
            &ctx.genesis,
            &row.block,
            &metadata.parent.unwrap_or([0; 32]),
            &metadata.height.to_le_bytes(),
            &[row.level],
            &row.ancestor,
            &row.ancestor_height.to_le_bytes(),
            &row.left_seal,
            &row.right_seal,
        ],
    )
}
fn metadata(db: &Connection, ctx: Context, id: Hash, budget: &mut Budget<'_>) -> Result<Metadata> {
    budget.charge()?;
    let shape = read_shape(db, id)?;
    #[cfg(test)]
    budget.observe(ReadKey::Shape(id), || shape_digest(&shape))?;
    let (height, parent_len, root_len, packet_len) = shape.ok_or("ANCESTRY_INDEX_UNKNOWN_BLOCK")?;
    ensure(
        root_len == 32 && height <= i64::MAX as u64,
        "ANCESTRY_INDEX_METADATA",
    )?;
    if id == ctx.genesis {
        ensure(
            height == 0 && parent_len.is_none() && packet_len.is_none(),
            "ANCESTRY_INDEX_GENESIS",
        )?;
        return Ok(Metadata {
            parent: None,
            height: 0,
        });
    }
    ensure(
        height > 0
            && parent_len == Some(32)
            && packet_len.is_some_and(|n| {
                (HEADER_BYTES + 2 + pon_work::PROOF_BYTES..=MAX_PACKET).contains(&n)
            }),
        "ANCESTRY_INDEX_PACKET_BYTES",
    )?;
    budget.charge()?;
    // Predicates precede prefix/trace extraction: even corrupt oversized BLOBs
    // never enter the projection or Rust Vec allocation.
    let row = read_header(db, id)?;
    #[cfg(test)]
    budget.observe(ReadKey::Header(id), || header_digest(&row))?;
    let (parent, root, prefix, trace) = row.ok_or("ANCESTRY_INDEX_METADATA")?;
    let parent = bytes32(parent)?;
    let root = bytes32(root)?;
    let trace = bytes32(trace)?;
    let header = Header::decode(&prefix).map_err(|_| Error::from("ANCESTRY_INDEX_HEADER"))?;
    ensure(
        header.block_id(trace) == id
            && header.network == ctx.network
            && header.parameters == ctx.parameters
            && header.parent == parent
            && header.height == height
            && header.state == root,
        "ANCESTRY_INDEX_HEADER",
    )?;
    Ok(Metadata {
        parent: Some(parent),
        height,
    })
}
fn basic(
    db: &Connection,
    ctx: Context,
    block: Hash,
    level: u8,
    budget: &mut Budget<'_>,
) -> Result<Row> {
    ensure(level < LEVELS, "ANCESTRY_INDEX_LEVEL")?;
    budget.charge()?;
    let values = read_jump(db, block, level)?;
    #[cfg(test)]
    budget.observe(ReadKey::Jump(block, level), || jump_digest(&values))?;
    let (ancestor, ancestor_height, left_seal, right_seal, row_seal) =
        values.ok_or("ANCESTRY_INDEX_MISSING")?;
    let row = Row {
        block,
        level,
        ancestor: bytes32(ancestor)?,
        ancestor_height,
        left_seal: bytes32(left_seal)?,
        right_seal: bytes32(right_seal)?,
        seal: bytes32(row_seal)?,
    };
    let origin = metadata(db, ctx, block, budget)?;
    let destination = metadata(db, ctx, row.ancestor, budget)?;
    ensure(
        origin.height.checked_sub(1_u64 << level) == Some(row.ancestor_height)
            && destination.height == row.ancestor_height
            && row.seal == seal(ctx, &row, origin),
        "ANCESTRY_INDEX_SEAL",
    )?;
    if level == 0 {
        ensure(
            row.ancestor == origin.parent.ok_or("ANCESTRY_INDEX_PARENT")?
                && row.left_seal == [0; 32]
                && row.right_seal == [0; 32],
            "ANCESTRY_INDEX_PARENT",
        )?;
    }
    Ok(row)
}
fn checked(
    db: &Connection,
    ctx: Context,
    block: Hash,
    level: u8,
    budget: &mut Budget<'_>,
) -> Result<Row> {
    let row = basic(db, ctx, block, level, budget)?;
    if level > 0 {
        let left = basic(db, ctx, block, level - 1, budget)?;
        let right = basic(db, ctx, left.ancestor, level - 1, budget)?;
        ensure(
            row.ancestor == right.ancestor
                && row.ancestor_height == right.ancestor_height
                && row.left_seal == left.seal
                && row.right_seal == right.seal,
            "ANCESTRY_INDEX_STRUCTURE",
        )?;
    }
    Ok(row)
}
/// Must execute in the same transaction as the already verified block INSERT.
/// This does not admit a block or create consensus authority from a SQL row.
pub(crate) fn insert(db: &Connection, ctx: Context, block: Hash) -> Result<Inserted> {
    let mut progress = |_| Ok(());
    let mut budget = Budget {
        used: 0,
        maximum: WRITE_SQL_BUDGET,
        progress: &mut progress,
        origin: BudgetOrigin::Owner,
        #[cfg(test)]
        reads: None,
    };
    let origin = metadata(db, ctx, block, &mut budget)?;
    ensure(block != ctx.genesis, "ANCESTRY_INDEX_GENESIS")?;
    let parent = origin.parent.ok_or("ANCESTRY_INDEX_PARENT")?;
    let parent_metadata = metadata(db, ctx, parent, &mut budget)?;
    ensure(
        parent_metadata.height.checked_add(1) == Some(origin.height),
        "ANCESTRY_INDEX_PARENT",
    )?;
    let mut row = Row {
        block,
        level: 0,
        ancestor: parent,
        ancestor_height: parent_metadata.height,
        left_seal: [0; 32],
        right_seal: [0; 32],
        seal: [0; 32],
    };
    let mut inserted = Inserted {
        block,
        rows: Vec::new(),
    };
    for level in 0..LEVELS {
        if (1_u64 << level) > origin.height {
            break;
        }
        row.level = level;
        if level > 0 {
            let left = checked(db, ctx, block, level - 1, &mut budget)?;
            let right = checked(db, ctx, left.ancestor, level - 1, &mut budget)?;
            row.ancestor = right.ancestor;
            row.ancestor_height = right.ancestor_height;
            row.left_seal = left.seal;
            row.right_seal = right.seal;
        }
        row.seal = seal(ctx, &row, origin);
        budget.charge()?;
        let written = db.execute(
            "INSERT INTO ancestry_jump VALUES(?,?,?,?,?,?,?)",
            params![
                block.as_slice(),
                level,
                row.ancestor.as_slice(),
                row.ancestor_height,
                row.left_seal.as_slice(),
                row.right_seal.as_slice(),
                row.seal.as_slice()
            ],
        )?;
        ensure(written == 1, "STORAGE_WRITE").map_err(Error::local_integrity)?;
        inserted.rows.push(row);
    }
    Ok(inserted)
}

/// Read back the entire new block's exact row set after all transaction writes.
/// The visible two-half checks also remain live; this is bounded by 63 levels,
/// and does not purport to audit every retained block on every admission.
pub(crate) fn verify_inserted(db: &Connection, ctx: Context, inserted: &Inserted) -> Result<()> {
    let mut progress = |_| Ok(());
    let mut budget = Budget {
        used: 0,
        maximum: READ_SQL_BUDGET,
        progress: &mut progress,
        origin: BudgetOrigin::Owner,
        #[cfg(test)]
        reads: None,
    };
    exact_row_count(db, inserted.block, inserted.rows.len(), &mut budget)?;
    for expected in &inserted.rows {
        let actual = checked(db, ctx, inserted.block, expected.level, &mut budget)?;
        ensure(actual == *expected, "ANCESTRY_INDEX_STRUCTURE")?;
    }
    Ok(())
}

fn exact_row_count(
    db: &Connection,
    block: Hash,
    expected: usize,
    budget: &mut Budget<'_>,
) -> Result<()> {
    budget.charge()?;
    let count: usize = db.query_row(
        "SELECT COUNT(*) FROM ancestry_jump WHERE block=?",
        [block.as_slice()],
        |row| row.get(0),
    )?;
    ensure(count == expected, "ANCESTRY_INDEX_STRUCTURE")
}
#[derive(Debug)]
pub(crate) struct Lookup {
    pub next: Option<Hash>,
    pub height: u64,
    pub sql_lookups: u64,
}
fn ascend(
    db: &Connection,
    ctx: Context,
    tip: Hash,
    difference: u64,
    budget: &mut Budget<'_>,
) -> Result<Hash> {
    let mut current = tip;
    for level in (0..LEVELS).rev() {
        if difference & (1_u64 << level) != 0 {
            current = checked(db, ctx, current, level, budget)?.ancestor;
        }
    }
    Ok(current)
}
/// Bounded local observation that `candidate` is on `tip`'s retained
/// ancestry. This is not finality or a global inclusion proof. It validates the
/// same sealed binary-lifting rows used by history paging and returns false for
/// a well-formed retained fork rather than converting that fork into an error.
pub(crate) fn contains(
    db: &Connection,
    ctx: Context,
    tip: Hash,
    candidate: Hash,
    maximum_sql: u64,
    progress: &mut dyn FnMut(u64) -> Result<()>,
) -> Result<bool> {
    ensure(
        (2..=READ_SQL_BUDGET).contains(&maximum_sql),
        "ANCESTRY_INDEX_BUDGET",
    )?;
    let mut budget = Budget {
        used: 0,
        maximum: maximum_sql,
        progress,
        origin: BudgetOrigin::Owner,
        #[cfg(test)]
        reads: None,
    };
    let tip_metadata = metadata(db, ctx, tip, &mut budget)?;
    let candidate_metadata = metadata(db, ctx, candidate, &mut budget)?;
    let Some(difference) = tip_metadata.height.checked_sub(candidate_metadata.height) else {
        return Ok(false);
    };
    if difference == 0 {
        return Ok(tip == candidate);
    }
    Ok(ascend(db, ctx, tip, difference, &mut budget)? == candidate)
}

/// Index integrity is local, not an independent proof of the entire path.
/// Leaves two SQL slots for the caller's length check and packet-body load.
pub(crate) fn next(
    db: &Connection,
    ctx: Context,
    tip: Hash,
    after: Hash,
    maximum_sql: u64,
    progress: &mut dyn FnMut(u64) -> Result<()>,
) -> Result<Lookup> {
    next_with_mode(
        db,
        ctx,
        tip,
        after,
        maximum_sql,
        progress,
        ReadMode {
            origin: BudgetOrigin::Owner,
            #[cfg(test)]
            reads: None,
            _scope: std::marker::PhantomData,
        },
    )
}
pub(crate) fn next_public_request(
    db: &Connection,
    ctx: Context,
    tip: Hash,
    after: Hash,
    maximum_sql: u64,
    progress: &mut dyn FnMut(u64) -> Result<()>,
) -> Result<Lookup> {
    next_with_mode(
        db,
        ctx,
        tip,
        after,
        maximum_sql,
        progress,
        ReadMode {
            origin: BudgetOrigin::PublicHistoryRequest,
            #[cfg(test)]
            reads: None,
            _scope: std::marker::PhantomData,
        },
    )
}
#[cfg(test)]
pub(crate) fn next_recording(
    db: &Connection,
    ctx: Context,
    tip: Hash,
    after: Hash,
    maximum_sql: u64,
    progress: &mut dyn FnMut(u64) -> Result<()>,
    reads: &mut ReadSet,
) -> Result<Lookup> {
    next_with_mode(
        db,
        ctx,
        tip,
        after,
        maximum_sql,
        progress,
        ReadMode {
            origin: BudgetOrigin::PublicHistoryRequest,
            reads: Some(reads),
            _scope: std::marker::PhantomData,
        },
    )
}
fn next_with_mode(
    db: &Connection,
    ctx: Context,
    tip: Hash,
    after: Hash,
    maximum_sql: u64,
    progress: &mut dyn FnMut(u64) -> Result<()>,
    mode: ReadMode<'_>,
) -> Result<Lookup> {
    ensure(
        (3..=READ_SQL_BUDGET).contains(&maximum_sql),
        "ANCESTRY_INDEX_BUDGET",
    )?;
    let mut budget = Budget {
        used: 0,
        maximum: maximum_sql - 2,
        progress,
        origin: mode.origin,
        #[cfg(test)]
        reads: mode.reads,
    };
    let target = metadata(db, ctx, tip, &mut budget)?;
    let cursor = metadata(db, ctx, after, &mut budget)?;
    if tip == after {
        return Ok(Lookup {
            next: None,
            height: cursor.height,
            sql_lookups: budget.used,
        });
    }
    let difference = target
        .height
        .checked_sub(cursor.height)
        .filter(|n| *n > 0)
        .ok_or("CURSOR")?;
    let candidate = ascend(db, ctx, tip, difference - 1, &mut budget)?;
    let candidate_metadata = metadata(db, ctx, candidate, &mut budget)?;
    ensure(
        candidate_metadata.height == cursor.height + 1 && candidate_metadata.parent == Some(after),
        "CURSOR",
    )?;
    Ok(Lookup {
        next: Some(candidate),
        height: candidate_metadata.height,
        sql_lookups: budget.used,
    })
}
/// Bounded restart check of active-tip entries and their visible two-half links.
/// Unvisited rows are not globally audited and are checked lazily when used.
pub(crate) fn validate_tip(db: &Connection, ctx: Context, tip: Hash) -> Result<()> {
    let mut progress = |_| Ok(());
    let mut budget = Budget {
        used: 0,
        maximum: READ_SQL_BUDGET,
        progress: &mut progress,
        origin: BudgetOrigin::Owner,
        #[cfg(test)]
        reads: None,
    };
    let origin = metadata(db, ctx, tip, &mut budget)?;
    for level in 0..LEVELS {
        if (1_u64 << level) > origin.height {
            break;
        }
        checked(db, ctx, tip, level, &mut budget)?;
    }
    // Preserve the original missing/seal/structure error precedence, then
    // reject any additional level (including every row attached to genesis).
    exact_row_count(
        db,
        tip,
        (u64::BITS - origin.height.leading_zeros()) as usize,
        &mut budget,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (Connection, Context) {
        let db = Connection::open_in_memory().unwrap();
        db.execute_batch("PRAGMA foreign_keys=ON;CREATE TABLE blocks(id BLOB PRIMARY KEY,parent BLOB,height INTEGER NOT NULL,chainwork BLOB NOT NULL,packet BLOB,state_root BLOB NOT NULL);").unwrap();
        db.execute_batch(DDL).unwrap();
        let ctx = Context {
            network: [1; 32],
            parameters: [2; 32],
            genesis: [3; 32],
        };
        db.execute(
            "INSERT INTO blocks VALUES(?,NULL,0,?,NULL,?)",
            params![
                ctx.genesis.as_slice(),
                [0_u8; 64].as_slice(),
                [0_u8; 32].as_slice()
            ],
        )
        .unwrap();
        (db, ctx)
    }
    // Pure index fixtures commit header/id/parent bytes but have no valid PNW1
    // proof. Production insert is reachable only after Node's actual verifier.
    fn block(db: &Connection, ctx: Context, parent: Hash, height: u64, salt: u64) -> Hash {
        let header = Header {
            network: ctx.network,
            parameters: ctx.parameters,
            parent,
            height,
            timestamp: height * 10,
            target: [0xff; 32],
            miner: [0; 32],
            transactions: [0; 32],
            state: [0; 32],
            receipts: [0; 32],
            work_task: [0; 32],
            nonce: salt,
        };
        let trace = hash(
            b"index-only-fixture",
            &[&parent, &height.to_le_bytes(), &salt.to_le_bytes()],
        );
        let id = header.block_id(trace);
        let mut raw = header.encode();
        raw.extend(0_u16.to_le_bytes());
        raw.extend(vec![0; pon_work::PROOF_BYTES - 32]);
        raw.extend(trace);
        db.execute(
            "INSERT INTO blocks VALUES(?,?,?,?,?,?)",
            params![
                id.as_slice(),
                parent.as_slice(),
                height,
                [0_u8; 64].as_slice(),
                raw,
                [0_u8; 32].as_slice()
            ],
        )
        .unwrap();
        id
    }
    fn chain(db: &Connection, ctx: Context, count: u64) -> Vec<Hash> {
        let mut ids = vec![ctx.genesis];
        for height in 1..=count {
            let id = block(db, ctx, *ids.last().unwrap(), height, 0);
            insert(db, ctx, id).unwrap();
            ids.push(id);
        }
        ids
    }
    #[test]
    fn forks_use_derived_parent_paths_and_lookup_is_bounded_nonrecursive() {
        let (db, ctx) = fixture();
        let ids = chain(&db, ctx, 65);
        let fork1 = block(&db, ctx, ids[32], 33, 1);
        insert(&db, ctx, fork1).unwrap();
        let fork2 = block(&db, ctx, fork1, 34, 1);
        insert(&db, ctx, fork2).unwrap();
        let mut observed = Vec::new();
        let lookup = next(&db, ctx, ids[65], ctx.genesis, READ_SQL_BUDGET, &mut |n| {
            observed.push(n);
            Ok(())
        })
        .unwrap();
        assert_eq!(lookup.next, Some(ids[1]));
        assert!(lookup.sql_lookups < 150);
        assert_eq!(observed.last(), Some(&lookup.sql_lookups));
        let lookup = next(&db, ctx, fork2, ids[32], READ_SQL_BUDGET, &mut |_| Ok(())).unwrap();
        assert_eq!(lookup.next, Some(fork1));
        assert!(contains(&db, ctx, ids[65], ids[32], READ_SQL_BUDGET, &mut |_| Ok(())).unwrap());
        assert!(contains(&db, ctx, ids[65], ids[65], READ_SQL_BUDGET, &mut |_| Ok(())).unwrap());
        assert!(!contains(&db, ctx, ids[32], ids[65], READ_SQL_BUDGET, &mut |_| Ok(())).unwrap());
        assert!(!contains(&db, ctx, ids[65], fork1, READ_SQL_BUDGET, &mut |_| Ok(())).unwrap());
        assert_eq!(
            next(&db, ctx, ids[65], fork1, READ_SQL_BUDGET, &mut |_| Ok(()))
                .unwrap_err()
                .to_string(),
            "CURSOR"
        );
        assert!(next(&db, ctx, ids[65], ctx.genesis, 3, &mut |_| Ok(())).is_err());
        assert!(
            next(&db, ctx, ids[65], ctx.genesis, READ_SQL_BUDGET, &mut |_| {
                Err("CANCELLED".into())
            })
            .is_err()
        );
        validate_tip(&db, ctx, ids[65]).unwrap();
    }
    #[test]
    fn public_request_budget_origin_preserves_invalid_limit_corruption_and_callback() {
        let (db, ctx) = fixture();
        let ids = chain(&db, ctx, 9);
        let request =
            next_public_request(&db, ctx, ids[9], ctx.genesis, 3, &mut |_| Ok(())).unwrap_err();
        assert_eq!(request.to_string(), "ANCESTRY_INDEX_BUDGET");
        assert!(!request.requires_owner_stop());
        let owner = next(&db, ctx, ids[9], ctx.genesis, 3, &mut |_| Ok(())).unwrap_err();
        assert!(owner.requires_owner_stop());
        let invalid =
            next_public_request(&db, ctx, ids[9], ctx.genesis, 2, &mut |_| Ok(())).unwrap_err();
        assert!(invalid.requires_owner_stop());
        let callback =
            next_public_request(&db, ctx, ids[9], ctx.genesis, READ_SQL_BUDGET, &mut |_| {
                Err("ANCESTRY_INDEX_BUDGET".into())
            })
            .unwrap_err();
        assert!(callback.requires_owner_stop());
        db.execute(
            "UPDATE ancestry_jump SET seal=? WHERE block=? AND level=3",
            params![[0_u8; 32].as_slice(), ids[9].as_slice()],
        )
        .unwrap();
        let corrupt =
            next_public_request(&db, ctx, ids[9], ctx.genesis, READ_SQL_BUDGET, &mut |_| {
                Ok(())
            })
            .unwrap_err();
        assert_eq!(corrupt.to_string(), "ANCESTRY_INDEX_SEAL");
        assert!(corrupt.requires_owner_stop());
    }
    #[test]
    fn random_row_corruption_and_visible_resealed_structure_are_refused() {
        for mode in ["seal", "missing", "structure", "parent"] {
            let (db, ctx) = fixture();
            let ids = chain(&db, ctx, 9);
            match mode {
                "seal" => {
                    db.execute(
                        "UPDATE ancestry_jump SET seal=? WHERE block=? AND level=3",
                        params![[0_u8; 32].as_slice(), ids[9].as_slice()],
                    )
                    .unwrap();
                }
                "missing" => {
                    db.execute(
                        "DELETE FROM ancestry_jump WHERE block=? AND level=3",
                        [ids[9].as_slice()],
                    )
                    .unwrap();
                }
                "structure" => {
                    let mut progress = |_| Ok(());
                    let mut b = Budget {
                        used: 0,
                        maximum: READ_SQL_BUDGET,
                        progress: &mut progress,
                        origin: BudgetOrigin::Owner,
                        reads: None,
                    };
                    let mut row = basic(&db, ctx, ids[9], 3, &mut b).unwrap();
                    row.left_seal = [0; 32];
                    let metadata = metadata(&db, ctx, ids[9], &mut b).unwrap();
                    row.seal = seal(ctx, &row, metadata);
                    db.execute(
                        "UPDATE ancestry_jump SET left_seal=?,seal=? WHERE block=? AND level=3",
                        params![
                            row.left_seal.as_slice(),
                            row.seal.as_slice(),
                            ids[9].as_slice()
                        ],
                    )
                    .unwrap();
                }
                "parent" => {
                    db.execute(
                        "UPDATE blocks SET parent=? WHERE id=?",
                        params![ctx.genesis.as_slice(), ids[9].as_slice()],
                    )
                    .unwrap();
                }
                _ => unreachable!(),
            }
            assert!(
                next(&db, ctx, ids[9], ctx.genesis, READ_SQL_BUDGET, &mut |_| Ok(
                    ()
                ))
                .is_err(),
                "{mode}"
            );
            assert!(validate_tip(&db, ctx, ids[9]).is_err(), "{mode}");
        }
    }
    #[test]
    fn index_failure_rolls_back_block_and_partial_index_in_same_transaction() {
        let (mut db, ctx) = fixture();
        let ids = chain(&db, ctx, 3);
        db.execute_batch("CREATE TRIGGER fail_index BEFORE INSERT ON ancestry_jump WHEN NEW.level=2 BEGIN SELECT RAISE(ABORT,'index fault');END;").unwrap();
        let id;
        {
            let tx = db.transaction().unwrap();
            id = block(&tx, ctx, ids[3], 4, 0);
            assert!(insert(&tx, ctx, id).is_err());
        }
        let blocks: u64 = db
            .query_row(
                "SELECT COUNT(*) FROM blocks WHERE id=?",
                [id.as_slice()],
                |r| r.get(0),
            )
            .unwrap();
        let indexes: u64 = db
            .query_row(
                "SELECT COUNT(*) FROM ancestry_jump WHERE block=?",
                [id.as_slice()],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!((blocks, indexes), (0, 0));
    }
}
