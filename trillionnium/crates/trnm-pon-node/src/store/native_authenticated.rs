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
        let (parent, height, work, packet, state): StoredBlockRow = db.query_row(
            "SELECT parent,height,chainwork,packet,state_root FROM blocks WHERE id=?",
            [id.as_slice()],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )?;
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
        let (parent_height, parent_work): (u64, Vec<u8>) = db.query_row(
            "SELECT height,chainwork FROM blocks WHERE id=?",
            [h.parent.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
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

pub(crate) fn deltas(db: &Connection, id: Hash) -> Result<Vec<Delta>> {
    local((|| {
        let mut statement =
            db.prepare("SELECT key,before,after FROM deltas WHERE block=? ORDER BY key")?;
        let rows = statement.query_map([id.as_slice()], |row| {
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
        Ok(out)
    })())
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
            .query_row(
                "SELECT substr(data,1,?) FROM native_state_commitments WHERE block=?",
                params![MAX_RECORD_BYTES + 1, id.as_slice()],
                |row| row.get(0),
            )
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
    let rows = deltas(db, record.block)?;
    local(ensure(
        record.parent == native.parent
            && record.height == native.height
            && record.packet_digest == native.packet_digest
            && record.state.network == settings.network()
            && record.state.parameters == settings.parameters()
            && record.state.genesis == settings.genesis()
            && record.state.state_root == native.root
            && record.delta_count == rows.len() as u64
            && record.delta_root == delta_root_with_progress(&rows, progress)?,
        "NATIVE_STATE_BINDING",
    ))?;
    match record.parent {
        None => local(ensure(
            record.block == settings.genesis()
                && record.parent_commitment.is_none()
                && rows.is_empty(),
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
                    .query_row(
                        "SELECT state FROM snapshots WHERE block=?",
                        [current.as_slice()],
                        |row| row.get(0),
                    )
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
    let rows = deltas(db, block)?;
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
