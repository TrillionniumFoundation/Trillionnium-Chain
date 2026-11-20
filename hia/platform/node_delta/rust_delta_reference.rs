//! Test-only child module of the retained original store.rs.
//!
//! In an isolated complete source copy, append only:
//! #[cfg(test)]
//! #[path = "hia_delta_reference.rs"]
//! mod hia_delta_reference;
//! Place these bytes in the same src directory, then cargo test --locked
//! --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --lib --no-run.
//! Invoke exactly store::hia_delta_reference::evaluate with --nocapture.
//! No production function is replaced; the actual original private
//! Node::apply_delta_with_progress and SQLite transactions do the work.
//!
//! This isolates the per-delta primitive using a non-active slot. It does not
//! skip checks in a production Node path or claim that its arbitrary byte
//! values are valid State/blocks. Final continuity/root/owner publication and
//! reorg cancellation cleanup are separate original obligations.
use super::*;
use serde_json::json;
use std::io::BufRead;

const SLOT: u64 = 17;
const BLOCK: [u8; 32] = [117; 32];

fn word(raw: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(raw[at..at + 8].try_into().unwrap())
}
fn take<'a>(raw: &'a [u8], cursor: &mut usize, count: usize) -> &'a [u8] {
    let end = cursor.checked_add(count).unwrap();
    let result = &raw[*cursor..end];
    *cursor = end;
    result
}
fn integer(raw: &[u8], cursor: &mut usize) -> u64 {
    u64::from_le_bytes(take(raw, cursor, 8).try_into().unwrap())
}
fn optional(raw: &[u8], cursor: &mut usize, count: u64) -> Option<Vec<u8>> {
    if count == u64::MAX { None } else { Some(take(raw, cursor, usize::try_from(count).unwrap()).to_vec()) }
}
fn encode_rows(rows: &[(String, Vec<u8>)]) -> Vec<u8> {
    let mut result = b"NKV00001".to_vec();
    result.extend_from_slice(&(rows.len() as u64).to_le_bytes());
    for (key, value) in rows {
        result.extend_from_slice(&(key.len() as u64).to_le_bytes());
        result.extend_from_slice(&(value.len() as u64).to_le_bytes());
        result.extend_from_slice(key.as_bytes());
        result.extend_from_slice(value);
    }
    result
}
fn invoke(node: &Node, raw: &[u8], name: &str) {
    assert_eq!(&raw[..8], b"NDFIX001");
    assert_eq!(word(raw, 16), u64::MAX, "Synthetic read-error events are a separate native contract test");
    assert_eq!(word(raw, 56), 0);
    let cancel = word(raw, 8);
    let write_fault = word(raw, 24);
    let original_token = word(raw, 32);
    let kv_end = 64usize.checked_add(usize::try_from(word(raw, 40)).unwrap()).unwrap();
    let start_end = kv_end.checked_add(usize::try_from(word(raw, 48)).unwrap()).unwrap();
    assert_eq!(start_end, raw.len());
    let mut at = 64;
    assert_eq!(take(raw, &mut at, 8), b"NKV00001");
    let count = integer(raw, &mut at);
    let mut before = Vec::new();
    for _ in 0..count {
        let key_bytes = usize::try_from(integer(raw, &mut at)).unwrap();
        let value_bytes = usize::try_from(integer(raw, &mut at)).unwrap();
        let key = String::from_utf8(take(raw, &mut at, key_bytes).to_vec()).unwrap();
        let value = take(raw, &mut at, value_bytes).to_vec();
        before.push((key, value));
    }
    assert_eq!(at, kv_end);
    assert_eq!(take(raw, &mut at, 8), b"NDLEVT01");
    assert_eq!(integer(raw, &mut at), 1);
    assert_eq!(integer(raw, &mut at), 0);
    assert_eq!(integer(raw, &mut at), 0);
    let detach = integer(raw, &mut at);
    assert!(detach <= 1);
    let tape_length = usize::try_from(integer(raw, &mut at)).unwrap();
    assert_eq!(tape_length, raw.len() - at);
    assert_eq!(take(raw, &mut at, 8), b"NDLT0001");
    let delta_count = integer(raw, &mut at);
    assert_eq!(take(raw, &mut at, 32), BLOCK.as_slice());
    assert_eq!(integer(raw, &mut at), SLOT);
    let mut deltas: Vec<Delta> = Vec::new();
    for _ in 0..delta_count {
        let key_bytes = usize::try_from(integer(raw, &mut at)).unwrap();
        let before_bytes = integer(raw, &mut at);
        let after_bytes = integer(raw, &mut at);
        let key = String::from_utf8(take(raw, &mut at, key_bytes).to_vec()).unwrap();
        let prior = optional(raw, &mut at, before_bytes);
        let next = optional(raw, &mut at, after_bytes);
        deltas.push((key, prior, next));
    }
    assert_eq!(at, raw.len());

    node.db.execute_batch("DROP TRIGGER IF EXISTS temp.hia_delta_put; DROP TRIGGER IF EXISTS temp.hia_delta_delete;").unwrap();
    {
        let prepared = rusqlite::Transaction::new_unchecked(&node.db, rusqlite::TransactionBehavior::Immediate).unwrap();
        node.db.execute("DELETE FROM kv WHERE slot=?", [SLOT]).unwrap();
        node.db.execute("DELETE FROM deltas WHERE block=?", [BLOCK.as_slice()]).unwrap();
        for (key, value) in &before {
            node.db.execute("INSERT INTO kv(slot,key,value) VALUES(?,?,?)", params![SLOT, key, value]).unwrap();
        }
        for (key, prior, next) in &deltas {
            node.db.execute("INSERT INTO deltas(block,key,before,after) VALUES(?,?,?,?)", params![BLOCK.as_slice(), key, prior, next]).unwrap();
        }
        prepared.commit().unwrap();
    }
    if let Ok(index) = usize::try_from(write_fault) {
        if let Some((key, _, _)) = deltas.get(index) {
            // Real SQLite changed-row refusal, without altering the original
            // method. Hex is the sole interpolation and is encoded by hex::encode.
            let literal = hex::encode(key.as_bytes());
            node.db.execute_batch(&format!(
                "CREATE TEMP TRIGGER hia_delta_put BEFORE INSERT ON kv WHEN NEW.slot={SLOT} AND NEW.key=CAST(X'{literal}' AS TEXT) BEGIN SELECT RAISE(IGNORE); END;\
                 CREATE TEMP TRIGGER hia_delta_delete BEFORE DELETE ON kv WHEN OLD.slot={SLOT} AND OLD.key=CAST(X'{literal}' AS TEXT) BEGIN SELECT RAISE(IGNORE); END;"
            )).unwrap();
        }
    }
    let transaction = rusqlite::Transaction::new_unchecked(&node.db, rusqlite::TransactionBehavior::Immediate).unwrap();
    let mut progress_count = 0u64;
    let result = node.apply_delta_with_progress(BLOCK, SLOT, detach == 1, &mut || {
        let point = progress_count;
        progress_count += 1;
        if point == cancel { Err(Error::new(crate::ErrorCode::LegacyRequestCancelled)) } else { Ok(()) }
    });
    let (status, origin, token, kind, error) = match result {
        Ok(()) => {
            transaction.commit().unwrap();
            (256u64, 0u64, 0u64, 0u64, None)
        },
        Err(error) => {
            transaction.rollback().unwrap();
            let (origin, token, kind) = if error.is(crate::ErrorCode::LegacyRequestCancelled) {
                (1u64, original_token, 2u64)
            } else if error.kind() == crate::ErrorKind::LocalStructure && error.to_string() == "UNDO_ROOT" {
                (2, 1, 0)
            } else if error.kind() == crate::ErrorKind::LocalStructure && error.to_string() == "STORAGE_WRITE" {
                (2, 2, 0)
            } else { panic!("Unexpected original error: {error:?}"); };
            (512, origin, token, kind, Some(error.to_string()))
        }
    };
    let rows: Vec<(String, Vec<u8>)> = node.db.prepare("SELECT key,value FROM kv WHERE slot=? ORDER BY key").unwrap()
        .query_map([SLOT], |row| Ok((row.get(0)?, row.get(1)?))).unwrap()
        .collect::<rusqlite::Result<_>>().unwrap();
    println!("HIA_DELTA_ORACLE:{}", json!({"name":name,"status":status,"origin":origin,
        "token":token,"kind":kind,"progresses":progress_count,"original_error":error,
        "kv_hex":hex::encode(encode_rows(&rows))}));
}

#[test]
fn evaluate() {
    let directory = tempfile::tempdir().unwrap();
    let node = Node::open(directory.path(), Settings::development(Some(1)).unwrap(), 1).unwrap();
    assert!(matches!(node.state_backend, StateBackend::Legacy));
    let corpus = std::fs::File::open(std::env::var("TRNM_HIA_DELTA_ORACLE_CORPUS").unwrap()).unwrap();
    for line in std::io::BufReader::new(corpus).lines() {
        let item: Value = serde_json::from_str(&line.unwrap()).unwrap();
        let raw = std::fs::read(item["input_path"].as_str().unwrap()).unwrap();
        invoke(&node, &raw, item["name"].as_str().unwrap());
    }
}
