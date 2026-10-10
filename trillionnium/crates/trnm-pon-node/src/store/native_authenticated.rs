//! Mandatory integrated state storage for an explicitly selected Node namespace.
//!
//! The native transaction owns every write. Account paths are copied on write
//! from the actual canonical deltas; their root and aggregates are independently
//! compared with the complete final M06 state, including recorded task output.
//! Complete state reads and reference root construction remain linear.
use super::{bytes32, bytes64, canonical, Delta};
use crate::account_archive_execution::state_witness::{
    commitment_from_complete_state, StateCommitment,
};
use crate::account_archive_prototype::native_store::{self, Root};
use crate::{consensus, ensure, sequence_root, Error, Packet, Result, Settings};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use trnm_mvcc_fee::pon_executor::{root, State};
use trnm_protocol::pon_wire::{hash, Hash};

pub(crate) const DDL: &str = "CREATE TABLE archive_nodes(id BLOB PRIMARY KEY,data BLOB NOT NULL);\nCREATE TABLE native_state_commitments(block BLOB PRIMARY KEY,data BLOB NOT NULL);";
pub(crate) const RECORD_SCHEMA: &str = "pon-native-authenticated-state-record-v1";
const MAX_RECORD_BYTES: usize = 16 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Record {
    pub schema: String,
    pub id: Hash,
    pub block: Hash,
    pub parent: Option<Hash>,
    pub parent_commitment: Option<Hash>,
    pub height: u64,
    pub packet_digest: Option<Hash>,
    pub state: StateCommitment,
    pub accounts: Root,
    pub delta_count: u64,
    pub delta_root: Hash,
}
impl Record {
    fn digest(&self) -> Result<Hash> {
        Ok(hash(
            b"native-authenticated-state-record-v1",
            &[&canonical(&(
                &self.schema,
                self.block,
                self.parent,
                self.parent_commitment,
                self.height,
                self.packet_digest,
                &self.state,
                &self.accounts,
                self.delta_count,
                self.delta_root,
            ))?],
        ))
    }
}

struct NativeBlock {
    parent: Option<Hash>,
    height: u64,
    root: Hash,
    packet_digest: Option<Hash>,
}
type StoredBlockRow = (Option<Vec<u8>>, u64, Vec<u8>, Option<Vec<u8>>, Vec<u8>);

// Reuse only SQLite statement bytecode in the connection's existing bounded
// cache. Every invocation rebinds parameters and rereads the current rows;
// none of the record, packet, delta, ancestry or state verdicts is cached.

fn local<T>(result: Result<T>) -> Result<T> {
    result.map_err(Error::local_integrity)
}
fn complete(settings: &Settings, state: &State) -> Result<StateCommitment> {
    commitment_from_complete_state(settings, state).map_err(|error| {
        Error::from(format!("NATIVE_STATE_COMMITMENT:{error:?}")).local_integrity()
    })
}

fn native_block(db: &Connection, settings: &Settings, id: Hash) -> Result<NativeBlock> {
    local((|| {
        let (parent, height, work, packet, state): StoredBlockRow = db
            .prepare_cached(
                "SELECT parent,height,chainwork,CASE WHEN typeof(packet)='blob' THEN substr(packet,1,1048577) ELSE packet END AS packet,state_root FROM blocks WHERE id=?",
            )?
            .query_row([id.as_slice()], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            })?;
        let parent = parent.map(bytes32).transpose()?;
        let state = bytes32(state)?;
        let work = consensus::Work::from_bytes(bytes64(work)?);
        if id == settings.genesis() {
            ensure(
                parent.is_none()
                    && height == 0
                    && packet.is_none()
                    && work == consensus::Work::from_bytes([0; 64])
                    && state == root(&settings.initial)?,
                "NATIVE_STATE_GENESIS",
            )?;
            return Ok(NativeBlock {
                parent,
                height,
                root: state,
                packet_digest: None,
            });
        }
        let raw = packet.ok_or("NATIVE_STATE_PACKET")?;
        let packet = Packet::decode(&raw)?;
        let h = &packet.header;
        ensure(
            packet.id()? == id
                && h.network == settings.network()
                && h.parameters == settings.parameters()
                && Some(h.parent) == parent
                && h.height == height
                && h.state == state
                && h.transactions == sequence_root("transactions", &packet.transactions),
            "NATIVE_STATE_PACKET",
        )?;
        let (parent_height, parent_work): (u64, Vec<u8>) = db
            .prepare_cached("SELECT height,chainwork FROM blocks WHERE id=?")?
            .query_row([h.parent.as_slice()], |row| Ok((row.get(0)?, row.get(1)?)))?;
        ensure(
            parent_height.checked_add(1) == Some(height)
                && consensus::Work::from_bytes(bytes64(parent_work)?)
                    .checked_add(consensus::required_work(h.target)?)?
                    == work,
            "NATIVE_STATE_PARENT",
        )?;
        Ok(NativeBlock {
            parent,
            height,
            root: state,
            packet_digest: Some(hash(b"native-authenticated-packet-v1", &[&raw])),
        })
    })())
}

// Match the existing state-root grammar: 160 key bytes and 4096 canonical
// value bytes. SQL projects at most one extra byte, so corrupt retained rows
// cannot allocate their entire payload in Rust before the limit is checked.
// CASE preserves SQLite types: a TEXT "before" is still not a BLOB.
const DELTA_ROWS_SQL: &str = "SELECT
 CASE WHEN typeof(key)='text' THEN CAST(substr(CAST(key AS BLOB),1,161) AS TEXT) ELSE key END AS key,
 CASE WHEN typeof(before)='blob' THEN substr(before,1,4097) ELSE before END AS before,
 CASE WHEN typeof(after)='blob' THEN substr(after,1,4097) ELSE after END AS after,
 length(CAST(key AS BLOB)),length(CAST(before AS BLOB)),length(CAST(after AS BLOB))
 FROM deltas WHERE block=? ORDER BY deltas.key";

// Read each actual retained row once. Stored-data errors carry local origin;
// caller cancellation is propagated unchanged and never returns a partial list.
fn visit_deltas(
    db: &Connection,
    id: Hash,
    progress: &mut dyn FnMut() -> Result<()>,
    mut visit: impl FnMut(Delta) -> Result<()>,
) -> Result<usize> {
    progress()?;
    let mut statement = local(db.prepare_cached(DELTA_ROWS_SQL).map_err(Error::from))?;
    let mut rows = local(statement.query([id.as_slice()]).map_err(Error::from))?;
    let mut previous: Option<String> = None;
    let mut count = 0usize;
    while let Some(row) = local(rows.next().map_err(Error::from))? {
        let row: Delta = local((|| {
            for (column, bound) in [(3, 160), (4, 4096), (5, 4096)] {
                let length: Option<i64> = row.get(column)?;
                ensure(
                    length.is_none_or(|n| (0..=bound).contains(&n)),
                    "NATIVE_STATE_DELTA_LIMIT",
                )?;
            }
            let row: Delta = (row.get(0)?, row.get(1)?, row.get(2)?);
            ensure(
                previous.as_ref().is_none_or(|key| key < &row.0)
                    && row.1 != row.2
                    && count < 131_072,
                "NATIVE_STATE_DELTA",
            )?;
            for bytes in [&row.1, &row.2].into_iter().flatten() {
                let value: Value = serde_json::from_slice(bytes)?;
                ensure(canonical(&value)? == *bytes, "NATIVE_STATE_DELTA_BYTES")?;
            }
            Ok(row)
        })())?;
        previous = Some(row.0.clone());
        visit(row)?;
        count += 1;
        if count.is_multiple_of(256) {
            progress()?;
        }
    }
    progress()?;
    Ok(count)
}

pub(crate) fn deltas(db: &Connection, id: Hash) -> Result<Vec<Delta>> {
    deltas_with_progress(db, id, &mut || Ok(()))
}

pub(super) fn deltas_with_progress(
    db: &Connection,
    id: Hash,
    progress: &mut dyn FnMut() -> Result<()>,
) -> Result<Vec<Delta>> {
    let mut out = Vec::new();
    visit_deltas(db, id, progress, |row| {
        out.push(row);
        Ok(())
    })?;
    Ok(out)
}

// Verification needs the commitment and count, not a second complete payload
// list. Account updates still use the actual full deltas through the owner API.
fn stored_delta_root(
    db: &Connection,
    id: Hash,
    progress: &mut dyn FnMut() -> Result<()>,
) -> Result<(usize, Hash)> {
    let mut tree = DeltaRootBuilder::default();
    let count = visit_deltas(db, id, progress, |row| tree.push(&row))?;
    let root = tree.finish();
    progress()?;
    Ok((count, root))
}

fn delta_root(rows: &[Delta]) -> Result<Hash> {
    delta_root_with_progress(rows, &mut || Ok(()))
}

/// The original indexed, duplicate-last sequence root, computed one encoded row
/// at a time. This is operation-local hashing, never a stored validity cache.
/// An occupied frontier slot at level k is a complete 2^k-leaf left subtree.
fn delta_root_with_progress(
    rows: &[Delta],
    progress: &mut dyn FnMut() -> Result<()>,
) -> Result<Hash> {
    progress()?;
    let mut tree = DeltaRootBuilder::default();
    for (index, row) in rows.iter().enumerate() {
        tree.push(row)?;
        if (index + 1).is_multiple_of(256) {
            progress()?;
        }
    }
    let root = tree.finish();
    progress()?;
    Ok(root)
}

/// Only untrusted intermediate hashes for this call; no cached validity fact.
#[derive(Default)]
struct DeltaRootBuilder {
    frontier: Vec<Option<Hash>>,
    count: usize,
}
impl DeltaRootBuilder {
    fn push(&mut self, row: &Delta) -> Result<()> {
        let encoded = canonical(row)?;
        let mut node = hash(
            b"native-authenticated-deltas-v1-leaf",
            &[&(self.count as u64).to_le_bytes(), &encoded],
        );
        // Do not retain every canonical row while constructing the Merkle tree.
        drop(encoded);
        let mut level = 0;
        loop {
            if level == self.frontier.len() {
                self.frontier.push(Some(node));
                break;
            }
            match self.frontier[level].take() {
                Some(left) => {
                    node = hash(b"native-authenticated-deltas-v1-node", &[&left, &node]);
                    level += 1;
                }
                None => {
                    self.frontier[level] = Some(node);
                    break;
                }
            }
        }
        self.count += 1;
        Ok(())
    }
    fn finish(self) -> Hash {
        // Fold the suffix from low to high. Only the rightmost partial subtree is
        // duplicated to the next occupied level; padding leaves to a power of two
        // instead would change the original root for some non-power-of-two counts.
        let mut suffix: Option<(Hash, usize)> = None;
        for (level, left) in self.frontier.into_iter().enumerate() {
            let Some(left) = left else {
                continue;
            };
            suffix = Some(match suffix {
                None => (left, level),
                Some((mut right, mut right_level)) => {
                    while right_level < level {
                        right = hash(b"native-authenticated-deltas-v1-node", &[&right, &right]);
                        right_level += 1;
                    }
                    (
                        hash(b"native-authenticated-deltas-v1-node", &[&left, &right]),
                        level + 1,
                    )
                }
            });
        }
        suffix.map_or_else(
            || hash(b"native-authenticated-deltas-v1-empty", &[]),
            |(root, _)| root,
        )
    }
}
// Operation-local traversal: no persistent verdict or extra full-delta copy.
fn visit_difference(
    before: &State,
    after: &State,
    progress: &mut dyn FnMut() -> Result<()>,
    mut visit: impl FnMut(&str, Option<Vec<u8>>, Option<Vec<u8>>),
) -> Result<()> {
    progress()?;
    let mut inspected = 0usize;
    // Walk the two existing sorted maps without a third full-key tree or a
    // repeated lookup per key. Still encode EVERY value, before then after:
    // Value equality is not a substitute for canonical byte equality (signed
    // floating zero, integer/float representations, present null and absence).
    let mut left = before.iter();
    let mut right = after.iter();
    let mut a = left.next();
    let mut b = right.next();
    loop {
        let (key, prior, next) = match (a, b) {
            (Some((ka, va)), Some((kb, vb))) => match ka.cmp(kb) {
                std::cmp::Ordering::Less => {
                    a = left.next();
                    (ka, Some(va), None)
                }
                std::cmp::Ordering::Equal => {
                    a = left.next();
                    b = right.next();
                    (ka, Some(va), Some(vb))
                }
                std::cmp::Ordering::Greater => {
                    b = right.next();
                    (kb, None, Some(vb))
                }
            },
            (Some((key, value)), None) => {
                a = left.next();
                (key, Some(value), None)
            }
            (None, Some((key, value))) => {
                b = right.next();
                (key, None, Some(value))
            }
            (None, None) => break,
        };
        let prior = prior.map(canonical).transpose()?;
        let next = next.map(canonical).transpose()?;
        if prior != next {
            visit(key, prior, next);
        }
        inspected += 1;
        if inspected.is_multiple_of(256) {
            progress()?;
        }
    }
    progress()
}

fn matches_difference(
    before: &State,
    after: &State,
    rows: &[Delta],
    progress: &mut dyn FnMut() -> Result<()>,
) -> Result<bool> {
    let mut position = 0usize;
    let mut equal = true;
    visit_difference(before, after, progress, |key, prior, next| {
        equal &= rows
            .get(position)
            .is_some_and(|row| row.0 == key && row.1 == prior && row.2 == next);
        position += 1;
    })?;
    // Do not short-circuit on a mismatch: all canonical values and the final
    // cancellation fence must be checked, as when materializing the old list.
    Ok(equal && position == rows.len())
}

#[cfg(test)]
fn difference(before: &State, after: &State) -> Result<Vec<Delta>> {
    let mut rows = Vec::new();
    visit_difference(before, after, &mut || Ok(()), |key, prior, next| {
        rows.push((key.to_owned(), prior, next));
    })?;
    Ok(rows)
}

fn save(db: &Connection, record: &mut Record) -> Result<()> {
    record.id = record.digest()?;
    let data = canonical(record)?;
    ensure(data.len() <= MAX_RECORD_BYTES, "NATIVE_STATE_RECORD_LIMIT")?;
    local(ensure(
        db.execute(
            "INSERT INTO native_state_commitments(block,data) VALUES(?,?)",
            params![record.block.as_slice(), data],
        )? == 1,
        "NATIVE_STATE_WRITE",
    ))?;
    local(ensure(
        load(db, record.block)? == *record,
        "NATIVE_STATE_WRITE",
    ))
}

pub(crate) fn load(db: &Connection, id: Hash) -> Result<Record> {
    local((|| {
        let bytes: Vec<u8> = db
            .prepare_cached("SELECT substr(data,1,?) FROM native_state_commitments WHERE block=?")?
            .query_row(params![MAX_RECORD_BYTES + 1, id.as_slice()], |row| {
                row.get(0)
            })
            .optional()?
            .ok_or("NATIVE_STATE_MISSING")?;
        ensure(bytes.len() <= MAX_RECORD_BYTES, "NATIVE_STATE_RECORD_LIMIT")?;
        let record: Record = serde_json::from_slice(&bytes)?;
        ensure(
            canonical(&record)? == bytes
                && record.schema == RECORD_SCHEMA
                && record.block == id
                && record.id == record.digest()?
                && record.state.account_root == record.accounts.digest
                && record.state.account_count == record.accounts.count
                && record.state.account_balance == record.accounts.balance,
            "NATIVE_STATE_RECORD",
        )?;
        Ok(record)
    })())
}

fn verify_record(
    db: &Connection,
    settings: &Settings,
    record: &Record,
    progress: &mut dyn FnMut() -> Result<()>,
) -> Result<()> {
    let native = native_block(db, settings, record.block)?;
    let (delta_count, delta_root) = stored_delta_root(db, record.block, progress)?;
    local(ensure(
        record.parent == native.parent
            && record.height == native.height
            && record.packet_digest == native.packet_digest
            && record.state.network == settings.network()
            && record.state.parameters == settings.parameters()
            && record.state.genesis == settings.genesis()
            && record.state.state_root == native.root
            && record.delta_count == delta_count as u64
            && record.delta_root == delta_root,
        "NATIVE_STATE_BINDING",
    ))?;
    match record.parent {
        None => local(ensure(
            record.block == settings.genesis()
                && record.parent_commitment.is_none()
                && delta_count == 0,
            "NATIVE_STATE_GENESIS",
        )),
        Some(parent) => {
            let parent = load(db, parent)?;
            local(ensure(
                record.parent_commitment == Some(parent.id)
                    && parent.height.checked_add(1) == Some(record.height),
                "NATIVE_STATE_PARENT",
            ))
        }
    }
}

pub(crate) fn verify_state(
    db: &Connection,
    settings: &Settings,
    block: Hash,
    state: &State,
    progress: &mut dyn FnMut() -> Result<()>,
) -> Result<()> {
    progress()?;
    let record = load(db, block)?;
    verify_record(db, settings, &record, progress)?;
    local(ensure(
        record.state == complete(settings, state)?,
        "NATIVE_STATE_ROOT",
    ))?;
    native_store::verify(db, &record.accounts, state, progress)?;
    progress()
}

/// Seal and verify every delta record needed to reconstruct a retained branch.
/// Non-genesis snapshots remain optional accelerators; genesis is the anchor.
pub(crate) fn verify_history(
    db: &Connection,
    settings: &Settings,
    block: Hash,
    progress: &mut dyn FnMut() -> Result<()>,
) -> Result<()> {
    let mut current = block;
    let mut expected_height = None;
    loop {
        progress()?;
        let record = load(db, current)?;
        verify_record(db, settings, &record, progress)?;
        local(ensure(
            expected_height.is_none_or(|height| record.height == height),
            "NATIVE_STATE_HISTORY",
        ))?;
        match record.parent {
            Some(parent) => {
                expected_height = Some(record.height.checked_sub(1).ok_or("NATIVE_STATE_HISTORY")?);
                current = parent;
            }
            None => {
                let bytes: Vec<u8> = db
                    .prepare_cached("SELECT state FROM snapshots WHERE block=?")
                    .map_err(|error| Error::from(error).local_integrity())?
                    .query_row([current.as_slice()], |row| row.get(0))
                    .map_err(|error| Error::from(error).local_integrity())?;
                let state: State = serde_json::from_slice(&bytes)
                    .map_err(|error| Error::from(error).local_integrity())?;
                local(ensure(
                    canonical(&state)? == bytes && state == settings.initial,
                    "NATIVE_STATE_GENESIS",
                ))?;
                return verify_state(db, settings, current, &state, progress);
            }
        }
    }
}

pub(crate) fn seed(db: &Connection, settings: &Settings) -> Result<()> {
    let accounts = native_store::seed(db, &settings.initial, &mut || Ok(()))?;
    let mut record = Record {
        schema: RECORD_SCHEMA.into(),
        id: [0; 32],
        block: settings.genesis(),
        parent: None,
        parent_commitment: None,
        height: 0,
        packet_digest: None,
        state: complete(settings, &settings.initial)?,
        accounts,
        delta_count: 0,
        delta_root: delta_root(&[])?,
    };
    save(db, &mut record)?;
    verify_state(
        db,
        settings,
        settings.genesis(),
        &settings.initial,
        &mut || Ok(()),
    )
}

/// Called only inside the native owner's block transaction, after the actual
/// block and canonical deltas are written and before the final commit fence.
pub(crate) fn publish(
    db: &Connection,
    settings: &Settings,
    parent: Hash,
    block: Hash,
    before: &State,
    after: &State,
    progress: &mut dyn FnMut() -> Result<()>,
) -> Result<()> {
    verify_state(db, settings, parent, before, progress)?;
    let parent_record = load(db, parent)?;
    let native = native_block(db, settings, block)?;
    local(ensure(
        native.parent == Some(parent) && parent_record.height.checked_add(1) == Some(native.height),
        "NATIVE_STATE_PARENT",
    ))?;
    let rows = deltas_with_progress(db, block, progress)?;
    let matches = matches_difference(before, after, &rows, progress)?;
    local(ensure(matches, "NATIVE_STATE_DELTA"))?;
    let accounts = native_store::apply(db, &parent_record.accounts, &rows, progress)?;
    let state = complete(settings, after)?;
    local(ensure(
        accounts.digest == state.account_root
            && accounts.count == state.account_count
            && accounts.balance == state.account_balance,
        "NATIVE_STATE_ACCOUNT_ROOT",
    ))?;
    let mut record = Record {
        schema: RECORD_SCHEMA.into(),
        id: [0; 32],
        block,
        parent: Some(parent),
        parent_commitment: Some(parent_record.id),
        height: native.height,
        packet_digest: native.packet_digest,
        state,
        accounts,
        delta_count: rows.len() as u64,
        delta_root: delta_root_with_progress(&rows, progress)?,
    };
    save(db, &mut record)?;
    verify_state(db, settings, block, after, progress)?;
    verify_history(db, settings, block, progress)
}

#[cfg(test)]
mod difference_tests {
    use super::*;
    use serde_json::json;
    use std::collections::BTreeSet;

    // Retain the original algorithm, including independent key union, lookups
    // and byte encoding. This reference shares no traversal with production.
    fn reference(before: &State, after: &State) -> Result<Vec<Delta>> {
        let mut keys: BTreeSet<_> = before.keys().collect();
        keys.extend(after.keys());
        let mut rows = Vec::new();
        for key in keys {
            let prior = before.get(key).map(canonical).transpose()?;
            let next = after.get(key).map(canonical).transpose()?;
            if prior != next {
                rows.push((key.clone(), prior, next));
            }
        }
        Ok(rows)
    }

    fn compare(before: &State, after: &State) {
        let initial = (canonical(before).unwrap(), canonical(after).unwrap());
        for (source, target) in [(before, after), (after, before)] {
            let expected = reference(source, target).unwrap();
            let actual = difference(source, target).unwrap();
            assert!(matches_difference(source, target, &expected, &mut || Ok(())).unwrap());
            assert_eq!(actual, expected);
            assert_eq!(canonical(&actual).unwrap(), canonical(&expected).unwrap());
            assert_eq!(delta_root(&actual).unwrap(), delta_root(&expected).unwrap());
        }
        assert_eq!(
            initial,
            (canonical(before).unwrap(), canonical(after).unwrap())
        );
    }

    #[test]
    fn sorted_difference_preserves_null_absence_signed_zero_and_numeric_bytes() {
        let values = [
            Value::Null,
            json!(false),
            json!(0),
            json!(0.0),
            json!(-0.0),
            json!(u64::MAX),
            json!([null, false, 0, -0.0]),
            json!({"nested": ["", "\u{0000}", "λ"]}),
        ];
        let keys = ["", "a", "a\0", "z", "λ", "\u{ffff}", "😀"];
        for key in keys {
            for source in &values {
                let before = State::from([(key.to_string(), source.clone())]);
                compare(&before, &State::new());
                for target in &values {
                    compare(&before, &State::from([(key.to_string(), target.clone())]));
                }
            }
        }
        let minus = State::from([("zero".into(), json!(-0.0))]);
        let plus = State::from([("zero".into(), json!(0.0))]);
        let rows = difference(&minus, &plus).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].1.as_deref(), Some(b"-0.0".as_slice()));
        assert_eq!(rows[0].2.as_deref(), Some(b"0.0".as_slice()));
        compare(&State::new(), &State::new());
    }

    #[test]
    fn sorted_difference_matches_independent_union_for_interleaved_branch_edits() {
        for seed in 0..64u64 {
            let mut before = State::new();
            let mut after = State::new();
            for index in 0..32u64 {
                let key = format!("key-{index:02}");
                if (index + seed) % 3 != 0 {
                    before.insert(key.clone(), json!([index, seed, null]));
                }
                if (index * 7 + seed) % 5 != 0 {
                    after.insert(key, json!([index, seed + index % 2, null]));
                }
            }
            compare(&before, &after);
            compare(&before, &before);
        }
    }

    #[test]
    fn sorted_difference_full_key_walk_keeps_late_changes_and_original_state() {
        // Traversal boundary, not ledger admission or a public capacity claim.
        let before: State = (0..65_536u64)
            .map(|i| (format!("key-{i:05}"), json!(i)))
            .collect();
        let mut after = before.clone();
        after.insert("key-00000".into(), Value::Null);
        after.remove("key-32768");
        after.insert("key-65535".into(), json!(-0.0));
        after.insert("!first".into(), json!(false));
        after.insert("λ-last".into(), json!([]));
        let rows = difference(&before, &after).unwrap();
        assert_eq!(rows.len(), 5);
        assert_eq!(rows.first().unwrap().0, "!first");
        assert_eq!(rows.last().unwrap().0, "λ-last");
        compare(&before, &after);
        compare(&before, &before);
    }
}

#[cfg(test)]
mod difference_stream_tests {
    use super::*;
    use serde_json::json;

    fn states(n: usize) -> (State, State) {
        let before: State = (0..n).map(|i| (format!("key-{i:06}"), json!(i))).collect();
        let after: State = (0..n)
            .map(|i| (format!("key-{i:06}"), json!([i, null])))
            .collect();
        (before, after)
    }

    #[test]
    fn stream_match_refuses_missing_extra_reordered_and_changed_rows() {
        let (before, after) = states(513);
        let rows = difference(&before, &after).unwrap();
        assert!(matches_difference(&before, &after, &rows, &mut || Ok(())).unwrap());
        for position in [0, 256, 512] {
            let mut missing = rows.clone();
            missing.remove(position);
            assert!(!matches_difference(&before, &after, &missing, &mut || Ok(())).unwrap());
            let mut changed = rows.clone();
            changed[position].2 = Some(b"null".to_vec());
            assert!(!matches_difference(&before, &after, &changed, &mut || Ok(())).unwrap());
            let mut wrong_key = rows.clone();
            wrong_key[position].0.push('!');
            assert!(!matches_difference(&before, &after, &wrong_key, &mut || Ok(())).unwrap());
        }
        let mut extra = rows.clone();
        extra.push(rows[0].clone());
        assert!(!matches_difference(&before, &after, &extra, &mut || Ok(())).unwrap());
        let mut swapped = rows;
        swapped.swap(0, 512);
        assert!(!matches_difference(&before, &after, &swapped, &mut || Ok(())).unwrap());
    }

    #[test]
    fn stream_match_visits_equal_keys_and_complete_mismatch_before_result() {
        for n in [0, 1, 255, 256, 257, 512, 65_536] {
            let (before, after) = states(n);
            for target in [&before, &after] {
                let rows = difference(&before, target).unwrap();
                let mut calls = 0;
                assert!(matches_difference(&before, target, &rows, &mut || {
                    calls += 1;
                    Ok(())
                })
                .unwrap());
                assert_eq!(calls, 2 + n / 256);
                let mut calls = 0;
                let result = matches_difference(&before, target, &[], &mut || {
                    calls += 1;
                    Ok(())
                })
                .unwrap();
                assert_eq!(result, rows.is_empty());
                assert_eq!(calls, 2 + n / 256);
            }
        }
    }

    #[test]
    fn stream_match_cancellation_returns_no_result_and_keeps_inputs_retryable() {
        let (before, after) = states(513);
        let rows = difference(&before, &after).unwrap();
        let original = (
            canonical(&before).unwrap(),
            canonical(&after).unwrap(),
            rows.clone(),
        );
        for cut in 0..4 {
            let mut calls = 0;
            let result = matches_difference(&before, &after, &rows, &mut || {
                let current = calls;
                calls += 1;
                if current == cut {
                    Err("STREAM_TEST_CANCELLED".into())
                } else {
                    Ok(())
                }
            });
            assert_eq!(result.err().unwrap().to_string(), "STREAM_TEST_CANCELLED");
            assert_eq!(calls, cut + 1);
            assert_eq!(original.0, canonical(&before).unwrap());
            assert_eq!(original.1, canonical(&after).unwrap());
            assert_eq!(original.2, rows);
            assert!(matches_difference(&before, &after, &rows, &mut || Ok(())).unwrap());
        }
        // Even after an observed mismatch, final cancellation cannot become an
        // ordinary false result (which publish would label storage corruption).
        let mut calls = 0;
        let result = matches_difference(&before, &after, &[], &mut || {
            calls += 1;
            if calls == 4 {
                Err("FINAL_CANCELLED".into())
            } else {
                Ok(())
            }
        });
        assert_eq!(result.err().unwrap().to_string(), "FINAL_CANCELLED");
    }

    #[test]
    fn stream_match_uses_original_byte_rules_for_null_absence_and_signed_zero() {
        let before = State::from([
            ("a".into(), Value::Null),
            ("b".into(), json!(-0.0)),
            ("d".into(), json!({"x": [1, "λ"]})),
        ]);
        let after = State::from([
            ("b".into(), json!(0.0)),
            ("c".into(), Value::Null),
            ("d".into(), json!({"x": [1, "λ"]})),
        ]);
        for (left, right) in [(&before, &after), (&after, &before)] {
            let rows = difference(left, right).unwrap();
            assert_eq!(rows.len(), 3);
            assert!(matches_difference(left, right, &rows, &mut || Ok(())).unwrap());
            let mut fabricated_absence = rows.clone();
            fabricated_absence[0].1 = None;
            fabricated_absence[0].2 = None;
            assert!(!matches_difference(left, right, &fabricated_absence, &mut || Ok(())).unwrap());
        }
    }
}

#[cfg(test)]
mod delta_root_stream_tests {
    use super::*;

    // The existing general sequence_root retains its independent all-leaves
    // implementation. Do not use the streaming routine to derive expectations.
    fn reference(rows: &[Delta]) -> Hash {
        let encoded = rows
            .iter()
            .map(canonical)
            .collect::<Result<Vec<_>>>()
            .unwrap();
        sequence_root("native-authenticated-deltas-v1", &encoded)
    }

    fn rows(count: usize) -> Vec<Delta> {
        (0..count)
            .map(|i| {
                (
                    format!("key-{i:06}"),
                    Some((i as u64).to_le_bytes().to_vec()),
                    Some(vec![(i % 251) as u8]),
                )
            })
            .collect()
    }

    #[test]
    fn streaming_delta_root_matches_every_small_padding_shape() {
        let rows = rows(1025);
        for count in 0..=129 {
            assert_eq!(
                delta_root(&rows[..count]).unwrap(),
                reference(&rows[..count])
            );
        }
        for count in [255, 256, 257, 511, 512, 513, 1023, 1024, 1025] {
            assert_eq!(
                delta_root(&rows[..count]).unwrap(),
                reference(&rows[..count])
            );
        }
    }

    #[test]
    fn streaming_delta_root_keeps_order_bytes_and_absence_distinct() {
        let original = rows(513);
        let expected = reference(&original);
        assert_eq!(delta_root(&original).unwrap(), expected);
        for index in [0, 256, 512] {
            let mut changed = original.clone();
            changed[index].0.push('!');
            assert_ne!(delta_root(&changed).unwrap(), expected);
            assert_eq!(delta_root(&changed).unwrap(), reference(&changed));
            let mut missing = original.clone();
            missing.remove(index);
            assert_ne!(delta_root(&missing).unwrap(), expected);
            assert_eq!(delta_root(&missing).unwrap(), reference(&missing));
        }
        let mut reordered = original.clone();
        reordered.swap(0, 512);
        assert_ne!(delta_root(&reordered).unwrap(), expected);
        assert_eq!(delta_root(&reordered).unwrap(), reference(&reordered));
        let mut extended = original.clone();
        extended.push(original.last().unwrap().clone());
        assert_ne!(delta_root(&extended).unwrap(), expected);
        assert_eq!(delta_root(&extended).unwrap(), reference(&extended));
        let options = [
            None,
            Some(Vec::new()),
            Some(b"null".to_vec()),
            Some(b"-0.0".to_vec()),
            Some(b"0.0".to_vec()),
            Some(vec![255; 4096]),
        ];
        let mut roots = Vec::new();
        for before in &options {
            for after in &options {
                let row = vec![("λ\u{0000}😀".to_owned(), before.clone(), after.clone())];
                let actual = delta_root(&row).unwrap();
                assert_eq!(actual, reference(&row));
                assert!(!roots.contains(&actual));
                roots.push(actual);
            }
        }
        assert_eq!(original, rows(513));
    }

    #[test]
    fn streaming_delta_root_checks_empty_batch_and_final_cancellation() {
        for count in [0, 1, 255, 256, 257, 512, 513] {
            let rows = rows(count);
            let original = rows.clone();
            let expected = reference(&rows);
            let checkpoints = 2 + count / 256;
            let mut calls = 0;
            let actual = delta_root_with_progress(&rows, &mut || {
                calls += 1;
                Ok(())
            })
            .unwrap();
            assert_eq!(actual, expected);
            assert_eq!(calls, checkpoints);
            for cut in 0..checkpoints {
                let mut calls = 0;
                let result = delta_root_with_progress(&rows, &mut || {
                    let current = calls;
                    calls += 1;
                    if current == cut {
                        Err("DELTA_ROOT_CANCELLED".into())
                    } else {
                        Ok(())
                    }
                });
                assert_eq!(result.unwrap_err().to_string(), "DELTA_ROOT_CANCELLED");
                assert_eq!(calls, cut + 1);
                assert_eq!(rows, original);
                assert_eq!(delta_root(&rows).unwrap(), expected);
            }
        }
    }

    #[test]
    fn streaming_delta_root_matches_full_delta_boundary_without_state_admission_claim() {
        // 131072 is the retained-delta read bound, not a new ledger key limit,
        // organic account growth, physical memory observation or throughput test.
        let rows = rows(131_072);
        for count in [65_535, 65_536, 65_537, 131_071, 131_072] {
            let mut calls = 0;
            let actual = delta_root_with_progress(&rows[..count], &mut || {
                calls += 1;
                Ok(())
            })
            .unwrap();
            assert_eq!(actual, reference(&rows[..count]));
            assert_eq!(calls, 2 + count / 256);
        }
    }

    #[test]
    fn streaming_delta_root_matches_independent_python_vectors() {
        let rows = rows(11);
        let vectors = [
            (
                0,
                "0442a6d63fa68366d6d02b3bfa078c969ab5be9a7560f25007b59023304f857e",
            ),
            (
                1,
                "15d5f9cb3988fe9bf9f7113d5fe81fdc10892ed60c2597a824acad42125a4048",
            ),
            (
                3,
                "b742441bf83f119eda56090faefd99301d84337b90a01aac80818daf9c979f20",
            ),
            (
                6,
                "a93b3e405ebd597cb81544d7ea6f9422a82fe4c92acc5a6a177664e21b0792b7",
            ),
            (
                11,
                "9f97caa00f34e9988ec322937d7d5264b6a47cfdf2ef2f64716a09b4634603b2",
            ),
        ];
        for (count, expected) in vectors {
            let root = delta_root(&rows[..count]).unwrap();
            assert_eq!(hex::encode(root), expected);
            assert_eq!(root, reference(&rows[..count]));
        }
    }
}

#[cfg(test)]
mod stored_delta_stream_tests {
    use super::*;
    use crate::ErrorCode;

    fn database(count: usize, width: usize) -> Connection {
        let db = Connection::open_in_memory().unwrap();
        db.execute_batch(super::super::BASE_DDL).unwrap();
        db.execute_batch("BEGIN").unwrap();
        let mut insert = db
            .prepare("INSERT INTO deltas(block,key,before,after) VALUES(?,?,?,?)")
            .unwrap();
        for i in 0..count {
            let before = canonical(&format!("{}a", "x".repeat(width))).unwrap();
            let after = canonical(&format!("{}b", "x".repeat(width))).unwrap();
            insert
                .execute(params![
                    [7u8; 32].as_slice(),
                    format!("key-{i:06}"),
                    before,
                    after
                ])
                .unwrap();
        }
        drop(insert);
        db.execute_batch("COMMIT").unwrap();
        db
    }

    #[test]
    fn cached_delta_reads_rebind_and_observe_committed_mutations() {
        let db = database(3, 0);
        let original = reference(&db).unwrap();
        assert_eq!(
            stored_delta_root(&db, [7; 32], &mut || Ok(())).unwrap(),
            original
        );
        assert_eq!(
            stored_delta_root(&db, [8; 32], &mut || Ok(())).unwrap(),
            (0, delta_root(&[]).unwrap())
        );
        db.execute(
            "UPDATE deltas SET after=? WHERE key='key-000000'",
            [b"null".as_slice()],
        )
        .unwrap();
        let changed = stored_delta_root(&db, [7; 32], &mut || Ok(())).unwrap();
        assert_ne!(changed, original);
        assert_eq!(changed, reference(&db).unwrap());
        assert_eq!(
            stored_delta_root(&db, [8; 32], &mut || Ok(())).unwrap().0,
            0
        );
    }

    #[test]
    fn cached_delta_failure_then_rollback_does_not_reuse_a_verdict() {
        let db = database(1, 0);
        let original = stored_delta_root(&db, [7; 32], &mut || Ok(())).unwrap();
        db.execute_batch("SAVEPOINT corrupt; UPDATE deltas SET before='null'")
            .unwrap();
        let error = stored_delta_root(&db, [7; 32], &mut || Ok(())).unwrap_err();
        assert!(error.requires_owner_stop());
        db.execute_batch("ROLLBACK TO corrupt; RELEASE corrupt")
            .unwrap();
        assert_eq!(
            stored_delta_root(&db, [7; 32], &mut || Ok(())).unwrap(),
            original
        );
        db.execute("UPDATE deltas SET after=?", [vec![b'x'; 4097]])
            .unwrap();
        let error = stored_delta_root(&db, [7; 32], &mut || Ok(())).unwrap_err();
        assert_eq!(error.to_string(), "NATIVE_STATE_DELTA_LIMIT");
        assert!(error.requires_owner_stop());
    }

    #[test]
    fn cached_delta_cursor_is_released_after_cancellation() {
        let db = database(513, 0);
        let expected = reference(&db).unwrap();
        let mut calls = 0;
        let error = stored_delta_root(&db, [7; 32], &mut || {
            calls += 1;
            if calls == 2 {
                Err("CACHED_DELTA_CANCELLED".into())
            } else {
                Ok(())
            }
        })
        .unwrap_err();
        assert_eq!(error.to_string(), "CACHED_DELTA_CANCELLED");
        assert!(!error.requires_owner_stop());
        assert_eq!(
            stored_delta_root(&db, [7; 32], &mut || Ok(())).unwrap(),
            expected
        );
        db.execute(
            "UPDATE deltas SET after=? WHERE key='key-000000'",
            [b"0".as_slice()],
        )
        .unwrap();
        assert_eq!(
            stored_delta_root(&db, [7; 32], &mut || Ok(())).unwrap(),
            reference(&db).unwrap()
        );
    }

    #[test]
    fn cached_delta_eviction_or_disabled_cache_keeps_original_results() {
        let db = database(257, 0);
        let expected = reference(&db).unwrap();
        for capacity in [0, 1, 16] {
            db.set_prepared_statement_cache_capacity(capacity);
            for _ in 0..3 {
                assert_eq!(
                    stored_delta_root(&db, [7; 32], &mut || Ok(())).unwrap(),
                    expected
                );
                db.prepare_cached("SELECT 1")
                    .unwrap()
                    .query_row([], |row| row.get::<_, i64>(0))
                    .unwrap();
                assert_eq!(
                    stored_delta_root(&db, [8; 32], &mut || Ok(())).unwrap().0,
                    0
                );
            }
        }
    }

    #[test]
    fn cached_delta_complete_call_observation_keeps_checks_and_results() {
        // Warm both modes before timing. Cache capacity zero is the same
        // candidate with statement reuse disabled, not a different validator.
        // No speed threshold, whole-node TPS or hardware independence claim.
        for count in [1, 257, 4096] {
            let db = database(count, 12);
            let expected = reference(&db).unwrap();
            let repetitions = 50;
            for (round, capacity) in [0, 16, 16, 0].into_iter().enumerate() {
                db.set_prepared_statement_cache_capacity(capacity);
                db.flush_prepared_statement_cache();
                assert_eq!(
                    stored_delta_root(&db, [7; 32], &mut || Ok(())).unwrap(),
                    expected
                );
                let mut progress_calls = 0;
                let started = std::time::Instant::now();
                for _ in 0..repetitions {
                    let actual = stored_delta_root(&db, [7; 32], &mut || {
                        progress_calls += 1;
                        Ok(())
                    })
                    .unwrap();
                    assert_eq!(actual, expected);
                }
                let elapsed_ns = started.elapsed().as_nanos();
                assert_eq!(progress_calls, repetitions * (3 + count / 256));
                assert_eq!(reference(&db).unwrap(), expected);
                eprintln!(
                    "native_statement_cache_observation_v1 {}",
                    serde_json::json!({
                        "rows": count,
                        "width": 12,
                        "repetitions": repetitions,
                        "round": round,
                        "statement_cache_capacity": capacity,
                        "elapsed_ns": elapsed_ns,
                        "progress_calls": progress_calls,
                        "delta_root": hex::encode(expected.1),
                        "full_checks_preserved": true,
                        "whole_node_throughput_measured": false,
                        "independent_operator": false
                    })
                );
            }
        }
    }

    // Original full-list reader and original all-leaves root algorithm remain
    // independent of the streamed reader/builder, including invalid-data order.
    fn reference(db: &Connection) -> Result<(usize, Hash)> {
        local((|| {
            let mut statement =
                db.prepare("SELECT key,before,after FROM deltas WHERE block=? ORDER BY key")?;
            let rows = statement.query_map([[7u8; 32].as_slice()], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })?;
            let mut out: Vec<Delta> = Vec::new();
            for row in rows {
                let row: Delta = row?;
                ensure(
                    out.last().is_none_or(|prior| prior.0 < row.0)
                        && row.1 != row.2
                        && out.len() < 131_072,
                    "NATIVE_STATE_DELTA",
                )?;
                for bytes in [&row.1, &row.2].into_iter().flatten() {
                    let value: Value = serde_json::from_slice(bytes)?;
                    ensure(canonical(&value)? == *bytes, "NATIVE_STATE_DELTA_BYTES")?;
                }
                out.push(row);
            }
            let encoded = out.iter().map(canonical).collect::<Result<Vec<_>>>()?;
            Ok((
                out.len(),
                sequence_root("native-authenticated-deltas-v1", &encoded),
            ))
        })())
    }

    #[test]
    fn stored_root_stream_matches_all_original_padding_shapes_and_rows() {
        for count in [0, 1, 3, 6, 11, 255, 256, 257, 513, 1025] {
            let db = database(count, 12);
            let expected = reference(&db).unwrap();
            assert_eq!(
                stored_delta_root(&db, [7; 32], &mut || Ok(())).unwrap(),
                expected
            );
            let rows = deltas(&db, [7; 32]).unwrap();
            assert_eq!(rows.len(), count);
            assert_eq!(delta_root(&rows).unwrap(), expected.1);
        }
    }

    #[test]
    fn stored_root_stream_preserves_corrupt_row_error_identity_and_order() {
        let attacks = [
            "UPDATE deltas SET after=before WHERE key='key-000256'",
            "UPDATE deltas SET before=X'2030' WHERE key='key-000256'",
            "UPDATE deltas SET before=X'7b' WHERE key='key-000256'",
            "UPDATE deltas SET after='not-a-blob' WHERE key='key-000256'",
            "UPDATE deltas SET before=NULL,after=NULL WHERE key='key-000256'",
        ];
        for sql in attacks {
            let db = database(513, 12);
            db.execute_batch(sql).unwrap();
            let expected = reference(&db).unwrap_err();
            let actual = stored_delta_root(&db, [7; 32], &mut || Ok(())).unwrap_err();
            assert_eq!(actual.to_string(), expected.to_string());
            assert_eq!(actual.kind(), expected.kind());
            assert_eq!(actual.requires_owner_stop(), expected.requires_owner_stop());
        }
    }

    #[test]
    fn stored_root_stream_cancellation_returns_no_result_and_keeps_original_error() {
        for count in [0, 1, 255, 256, 257, 513] {
            let db = database(count, 8);
            let before = reference(&db).unwrap();
            let mut calls = 0;
            let actual = stored_delta_root(&db, [7; 32], &mut || {
                calls += 1;
                Ok(())
            })
            .unwrap();
            assert_eq!(actual, before);
            assert_eq!(calls, 3 + count / 256);
            for cut in 0..calls {
                let mut observed = 0;
                let result = stored_delta_root(&db, [7; 32], &mut || {
                    let current = observed;
                    observed += 1;
                    if current == cut {
                        Err("FRAME_DEADLINE".into())
                    } else {
                        Ok(())
                    }
                });
                let error = result.unwrap_err();
                assert!(error.is(ErrorCode::FrameDeadline));
                assert!(!error.requires_owner_stop());
                assert_eq!(observed, cut + 1);
                assert_eq!(reference(&db).unwrap(), before);
                assert_eq!(
                    stored_delta_root(&db, [7; 32], &mut || Ok(())).unwrap(),
                    before
                );
            }
        }
    }

    #[test]
    fn stored_delta_list_cancellation_does_not_return_a_prefix() {
        let db = database(513, 8);
        let expected = deltas(&db, [7; 32]).unwrap();
        for cut in 0..4 {
            let mut calls = 0;
            let result = deltas_with_progress(&db, [7; 32], &mut || {
                let current = calls;
                calls += 1;
                if current == cut {
                    Err("FRAME_DEADLINE".into())
                } else {
                    Ok(())
                }
            });
            assert!(result.unwrap_err().is(ErrorCode::FrameDeadline));
            assert_eq!(calls, cut + 1);
            assert_eq!(deltas(&db, [7; 32]).unwrap(), expected);
        }
    }

    #[test]
    fn stored_root_stream_preserves_full_delta_read_limit_and_rejects_next_row() {
        // Actual SQLite rows at the existing mechanism bound, not native ledger
        // admission, organic account growth, or permanent storage qualification.
        let db = database(131_072, 0);
        let expected = reference(&db).unwrap();
        let mut calls = 0;
        assert_eq!(
            stored_delta_root(&db, [7; 32], &mut || {
                calls += 1;
                Ok(())
            })
            .unwrap(),
            expected
        );
        assert_eq!(calls, 515);
        db.execute(
            "INSERT INTO deltas VALUES(?,?,?,?)",
            params![
                [7u8; 32].as_slice(),
                "last",
                b"0".as_slice(),
                b"1".as_slice()
            ],
        )
        .unwrap();
        let expected = reference(&db).unwrap_err();
        let error = stored_delta_root(&db, [7; 32], &mut || Ok(())).unwrap_err();
        assert_eq!(error.to_string(), expected.to_string());
        assert!(error.requires_owner_stop());
    }

    #[test]
    fn stored_rows_bound_bytes_before_decode_and_keep_unicode_nul_and_sql_types() {
        let db = database(1, 4093); // exactly 4096 bytes including JSON quotes.
        db.execute("UPDATE deltas SET key=?", ["λ".repeat(80)])
            .unwrap();
        assert_eq!(
            stored_delta_root(&db, [7; 32], &mut || Ok(())).unwrap(),
            reference(&db).unwrap()
        );
        db.execute(
            "UPDATE deltas SET key=?",
            [format!("{}\0z", "x".repeat(159))],
        )
        .unwrap();
        let error = stored_delta_root(&db, [7; 32], &mut || Ok(())).unwrap_err();
        assert_eq!(error.to_string(), "NATIVE_STATE_DELTA_LIMIT");
        assert!(error.requires_owner_stop());
        db.execute(
            "UPDATE deltas SET key='key-000000',before=?",
            [vec![b'x'; 1024 * 1024]],
        )
        .unwrap();
        // Inspect the actual bounded SQL projection; full SQLite page traffic
        // and allocator/RSS accounting are outside this Rust-payload assertion.
        let (returned, original): (usize, usize) = db
            .prepare(DELTA_ROWS_SQL)
            .unwrap()
            .query_row([[7u8; 32].as_slice()], |row| {
                let raw: Vec<u8> = row.get(1)?;
                Ok((raw.len(), row.get(4)?))
            })
            .unwrap();
        assert_eq!((returned, original), (4097, 1024 * 1024));
        let error = stored_delta_root(&db, [7; 32], &mut || Ok(())).unwrap_err();
        assert_eq!(error.to_string(), "NATIVE_STATE_DELTA_LIMIT");
        db.execute(
            "UPDATE deltas SET before=NULL,after=?",
            [b"null".as_slice()],
        )
        .unwrap();
        assert_eq!(
            stored_delta_root(&db, [7; 32], &mut || Ok(())).unwrap(),
            reference(&db).unwrap()
        );
        db.execute("UPDATE deltas SET before=?", [b"null".as_slice()])
            .unwrap();
        assert_eq!(
            stored_delta_root(&db, [7; 32], &mut || Ok(()))
                .unwrap_err()
                .to_string(),
            "NATIVE_STATE_DELTA"
        );
    }

    fn baseline_226_root_with_progress(
        rows: &[Delta],
        progress: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Hash> {
        progress()?;
        let mut frontier: Vec<Option<Hash>> = Vec::new();
        for (index, row) in rows.iter().enumerate() {
            let encoded = canonical(row)?;
            let mut node = hash(
                b"native-authenticated-deltas-v1-leaf",
                &[&(index as u64).to_le_bytes(), &encoded],
            );
            // Do not retain every canonical row while constructing the Merkle tree.
            drop(encoded);
            let mut level = 0;
            loop {
                if level == frontier.len() {
                    frontier.push(Some(node));
                    break;
                }
                match frontier[level].take() {
                    Some(left) => {
                        node = hash(b"native-authenticated-deltas-v1-node", &[&left, &node]);
                        level += 1;
                    }
                    None => {
                        frontier[level] = Some(node);
                        break;
                    }
                }
            }
            if (index + 1).is_multiple_of(256) {
                progress()?;
            }
        }
        // Fold the suffix from low to high. Only the rightmost partial subtree is
        // duplicated to the next occupied level; padding leaves to a power of two
        // instead would change the original root for some non-power-of-two counts.
        let mut suffix: Option<(Hash, usize)> = None;
        for (level, left) in frontier.into_iter().enumerate() {
            let Some(left) = left else {
                continue;
            };
            suffix = Some(match suffix {
                None => (left, level),
                Some((mut right, mut right_level)) => {
                    while right_level < level {
                        right = hash(b"native-authenticated-deltas-v1-node", &[&right, &right]);
                        right_level += 1;
                    }
                    (
                        hash(b"native-authenticated-deltas-v1-node", &[&left, &right]),
                        level + 1,
                    )
                }
            });
        }
        let root = suffix.map_or_else(
            || hash(b"native-authenticated-deltas-v1-empty", &[]),
            |(root, _)| root,
        );
        // A fully computed root still cannot escape an operation cancelled here.
        progress()?;
        Ok(root)
    }

    fn baseline_226_cost(db: &Connection) -> Result<(usize, Hash)> {
        local((|| {
            let mut statement =
                db.prepare("SELECT key,before,after FROM deltas WHERE block=? ORDER BY key")?;
            let rows = statement.query_map([[7u8; 32].as_slice()], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })?;
            let mut out: Vec<Delta> = Vec::new();
            for row in rows {
                let row: Delta = row?;
                ensure(
                    out.last().is_none_or(|prior| prior.0 < row.0)
                        && row.1 != row.2
                        && out.len() < 131_072,
                    "NATIVE_STATE_DELTA",
                )?;
                for bytes in [&row.1, &row.2].into_iter().flatten() {
                    let value: Value = serde_json::from_slice(bytes)?;
                    ensure(canonical(&value)? == *bytes, "NATIVE_STATE_DELTA_BYTES")?;
                }
                out.push(row);
            }
            Ok((
                out.len(),
                baseline_226_root_with_progress(&out, &mut || Ok(()))?,
            ))
        })())
    }

    #[test]
    #[ignore = "explicit release-only retained-delta cost observation; not a throughput gate"]
    fn retained_delta_stream_cost_preserves_all_paired_observations() {
        use std::io::Write;
        let path = std::env::var_os("TRNM_RETAINED_DELTA_COST_PATH")
            .expect("explicit create-new output path is required");
        let mut output = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .unwrap();
        writeln!(output, "{}", serde_json::json!({
            "schema": "pon-native-retained-delta-cost-v1",
            "scope": "actual in-memory SQLite ordered read, canonical validation and complete delta root; not Node/state/history/physical I/O/RSS/TPS",
            "comparison": "exact eee8db8 full-list reader and streaming root versus current bounded streamed reader/root",
            "synthetic_sqlite_rows": true, "speed_threshold": null,
            "production_activation": false
        })).unwrap();
        for (case, (count, width)) in [(256, 64), (4096, 64), (4096, 4093), (16384, 64)]
            .into_iter()
            .enumerate()
        {
            let db = database(count, width);
            let expected = reference(&db).unwrap();
            for pair in 0..4 {
                for arm in if pair % 2 == 0 {
                    ["baseline226", "streamed"]
                } else {
                    ["streamed", "baseline226"]
                } {
                    let start = std::time::Instant::now();
                    let result = if arm == "baseline226" {
                        baseline_226_cost(&db)
                    } else {
                        stored_delta_root(&db, [7; 32], &mut || Ok(()))
                    };
                    let elapsed = start.elapsed().as_nanos();
                    // Retain the raw failure or mismatching result before asserting.
                    writeln!(
                        output,
                        "{}",
                        serde_json::json!({
                            "case": case, "rows": count, "payload_width": width,
                            "pair": pair, "arm": arm, "wall_ns": elapsed.to_string(),
                            "root": result.as_ref().ok().map(|(_, root)| hex::encode(root)),
                            "count": result.as_ref().ok().map(|(count, _)| count),
                            "error": result.as_ref().err().map(ToString::to_string),
                            "equal": result.as_ref().is_ok_and(|actual| *actual == expected),
                        })
                    )
                    .unwrap();
                    output.flush().unwrap();
                    assert_eq!(result.unwrap(), expected);
                }
            }
        }
        writeln!(
            output,
            "{}",
            serde_json::json!({"completed": true, "pairs": 16,
            "observations": 32, "scope": "no timing threshold or performance qualification"})
        )
        .unwrap();
        output.sync_all().unwrap();
    }
}

#[cfg(test)]
mod cached_owner_read_tests {
    use super::*;
    use crate::Node;

    fn open(path: &std::path::Path) -> Node {
        let settings = Settings::development_with_profiles(
            Some(1),
            "native-public-evaluation-dev-v1",
            trnm_mvcc_fee::continuity_v1::PROFILE,
        )
        .unwrap();
        Node::open_with_authenticated_state(path, settings, 1).unwrap()
    }

    #[test]
    fn cached_block_reads_do_not_hide_genesis_damage_or_rollback() {
        let directory = tempfile::tempdir().unwrap();
        let node = open(directory.path());
        let id = node.settings.genesis();
        for capacity in [0, 1, 16] {
            node.db.set_prepared_statement_cache_capacity(capacity);
            let original = native_block(&node.db, &node.settings, id).unwrap();
            node.db.execute_batch("SAVEPOINT damaged_block").unwrap();
            node.db
                .execute("UPDATE blocks SET height=1 WHERE id=?", [id.as_slice()])
                .unwrap();
            let error = native_block(&node.db, &node.settings, id).err().unwrap();
            assert_eq!(error.to_string(), "NATIVE_STATE_GENESIS");
            assert!(error.requires_owner_stop());
            node.db
                .execute_batch("ROLLBACK TO damaged_block; RELEASE damaged_block")
                .unwrap();
            let recovered = native_block(&node.db, &node.settings, id).unwrap();
            assert_eq!(
                (
                    recovered.parent,
                    recovered.height,
                    recovered.root,
                    recovered.packet_digest
                ),
                (
                    original.parent,
                    original.height,
                    original.root,
                    original.packet_digest
                )
            );
        }
    }

    #[test]
    fn cached_parent_reads_observe_changed_work_then_exact_restore() {
        let directory = tempfile::tempdir().unwrap();
        let mut node = open(directory.path());
        let genesis = node.settings.genesis();
        let miner = crate::development_public(0).unwrap();
        let packet = node
            .make_consensus_maintenance(genesis, vec![], miner, 11, 4096)
            .unwrap();
        let id = node.admit(&packet, 100_000).unwrap();
        let expected = native_block(&node.db, &node.settings, id).unwrap();
        node.db.execute_batch("SAVEPOINT damaged_parent").unwrap();
        node.db
            .execute(
                "UPDATE blocks SET chainwork=? WHERE id=?",
                params![vec![255u8; 64], genesis.as_slice()],
            )
            .unwrap();
        assert!(native_block(&node.db, &node.settings, id)
            .err()
            .unwrap()
            .requires_owner_stop());
        node.db
            .execute_batch("ROLLBACK TO damaged_parent; RELEASE damaged_parent")
            .unwrap();
        let actual = native_block(&node.db, &node.settings, id).unwrap();
        assert_eq!(
            (
                actual.parent,
                actual.height,
                actual.root,
                actual.packet_digest
            ),
            (
                expected.parent,
                expected.height,
                expected.root,
                expected.packet_digest
            )
        );
    }

    #[test]
    fn cached_commitment_reads_preserve_limits_missing_and_rollback() {
        let directory = tempfile::tempdir().unwrap();
        let node = open(directory.path());
        let id = node.settings.genesis();
        let expected = load(&node.db, id).unwrap();
        for length in [MAX_RECORD_BYTES + 1, MAX_RECORD_BYTES * 8] {
            node.db.execute_batch("SAVEPOINT damaged_record").unwrap();
            node.db
                .execute(
                    "UPDATE native_state_commitments SET data=? WHERE block=?",
                    params![vec![b'x'; length], id.as_slice()],
                )
                .unwrap();
            let error = load(&node.db, id).unwrap_err();
            assert_eq!(error.to_string(), "NATIVE_STATE_RECORD_LIMIT");
            assert!(error.requires_owner_stop());
            node.db
                .execute_batch("ROLLBACK TO damaged_record; RELEASE damaged_record")
                .unwrap();
            assert_eq!(load(&node.db, id).unwrap(), expected);
        }
        node.db.execute_batch("SAVEPOINT removed_record").unwrap();
        node.db
            .execute(
                "DELETE FROM native_state_commitments WHERE block=?",
                [id.as_slice()],
            )
            .unwrap();
        let missing = load(&node.db, id).unwrap_err();
        assert_eq!(missing.to_string(), "NATIVE_STATE_MISSING");
        assert!(missing.requires_owner_stop());
        node.db
            .execute_batch("ROLLBACK TO removed_record; RELEASE removed_record")
            .unwrap();
        assert_eq!(load(&node.db, id).unwrap(), expected);
    }

    #[test]
    fn cached_genesis_snapshot_is_reread_and_survives_cold_reopen() {
        let directory = tempfile::tempdir().unwrap();
        let node = open(directory.path());
        let id = node.settings.genesis();
        let expected = node.read_active().unwrap();
        verify_history(&node.db, &node.settings, id, &mut || Ok(())).unwrap();
        node.db.execute_batch("SAVEPOINT damaged_snapshot").unwrap();
        node.db
            .execute(
                "UPDATE snapshots SET state=? WHERE block=?",
                params![b"{}".as_slice(), id.as_slice()],
            )
            .unwrap();
        let error = verify_history(&node.db, &node.settings, id, &mut || Ok(())).unwrap_err();
        assert_eq!(error.to_string(), "NATIVE_STATE_GENESIS");
        assert!(error.requires_owner_stop());
        node.db
            .execute_batch("ROLLBACK TO damaged_snapshot; RELEASE damaged_snapshot")
            .unwrap();
        verify_history(&node.db, &node.settings, id, &mut || Ok(())).unwrap();
        drop(node);
        let reopened = open(directory.path());
        assert_eq!(reopened.read_active().unwrap(), expected);
        verify_history(&reopened.db, &reopened.settings, id, &mut || Ok(())).unwrap();
    }
}
