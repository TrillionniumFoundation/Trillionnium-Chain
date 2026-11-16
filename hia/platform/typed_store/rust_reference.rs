//! Isolated cfg(test) child of the exact retained original store.rs.
//! Invokes actual private Node apply/slot_state methods and original M06 root.
//! The only source edit in the isolated original is an appended cfg(test)
//! declaration; no production function or SQL statement is replaced.
use super::*;
use serde_json::json;
use std::io::BufRead;

const SLOT: u64 = 7;
const BLOCK: [u8; 32] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
];

fn take<'a>(raw: &'a [u8], at: &mut usize, count: usize) -> &'a [u8] {
    let end = at.checked_add(count).unwrap();
    let result = &raw[*at..end];
    *at = end;
    result
}
fn integer(raw: &[u8], at: &mut usize) -> u64 {
    u64::from_le_bytes(take(raw, at, 8).try_into().unwrap())
}
fn optional(raw: &[u8], at: &mut usize, count: u64) -> Option<Vec<u8>> {
    if count == u64::MAX {
        None
    } else {
        Some(take(raw, at, usize::try_from(count).unwrap()).to_vec())
    }
}
fn decode_base(raw: &[u8]) -> Vec<(String, Vec<u8>)> {
    let mut at = 0;
    assert_eq!(take(raw, &mut at, 8), b"TKVSTR01");
    let count = integer(raw, &mut at);
    let mut rows = Vec::new();
    for _ in 0..count {
        let kn = usize::try_from(integer(raw, &mut at)).unwrap();
        let vn = usize::try_from(integer(raw, &mut at)).unwrap();
        let key = String::from_utf8(take(raw, &mut at, kn).to_vec()).unwrap();
        let value = take(raw, &mut at, vn).to_vec();
        rows.push((key, value));
    }
    assert_eq!(at, raw.len());
    rows
}
fn decode_delta(raw: &[u8]) -> Vec<Delta> {
    let mut at = 0;
    assert_eq!(take(raw, &mut at, 8), b"NDLT0001");
    let count = integer(raw, &mut at);
    assert_eq!(take(raw, &mut at, 32), BLOCK.as_slice());
    assert_eq!(integer(raw, &mut at), SLOT);
    let mut rows = Vec::new();
    for _ in 0..count {
        let kn = usize::try_from(integer(raw, &mut at)).unwrap();
        let bn = integer(raw, &mut at);
        let an = integer(raw, &mut at);
        let key = String::from_utf8(take(raw, &mut at, kn).to_vec()).unwrap();
        let before = optional(raw, &mut at, bn);
        let after = optional(raw, &mut at, an);
        rows.push((key, before, after));
    }
    assert_eq!(at, raw.len());
    rows
}
fn encode_rows(rows: &[(String, Vec<u8>)]) -> Vec<u8> {
    let mut result = b"TKVSTR01".to_vec();
    result.extend_from_slice(&(rows.len() as u64).to_le_bytes());
    for (key, value) in rows {
        result.extend_from_slice(&(key.len() as u64).to_le_bytes());
        result.extend_from_slice(&(value.len() as u64).to_le_bytes());
        result.extend_from_slice(key.as_bytes());
        result.extend_from_slice(value);
    }
    result
}

fn invoke(node: &Node, item: &Value) {
    assert_eq!(item["profile"].as_u64().unwrap(), 0, "GSC2 has a separate owner/root obligation");
    let base_raw = hex::decode(item["base_hex"].as_str().unwrap()).unwrap();
    let delta_raw = hex::decode(item["delta_hex"].as_str().unwrap()).unwrap();
    let before = decode_base(&base_raw);
    let deltas = decode_delta(&delta_raw);
    let detach = item["detach"].as_bool().unwrap();
    let with_root = item["root"].as_bool().unwrap();
    let cancel = item["cancel"].as_u64();
    if cancel.is_some() {
        assert_eq!(item["cancel_class"].as_u64(), Some(2));
    }
    {
        let prepare = rusqlite::Transaction::new_unchecked(
            &node.db, rusqlite::TransactionBehavior::Immediate,
        ).unwrap();
        node.db.execute("DELETE FROM kv WHERE slot=?", [SLOT]).unwrap();
        node.db.execute("DELETE FROM deltas WHERE block=?", [BLOCK.as_slice()]).unwrap();
        for (key, value) in &before {
            node.db.execute("INSERT INTO kv(slot,key,value) VALUES(?,?,?)",
                params![SLOT, key, value]).unwrap();
        }
        for (key, prior, next) in &deltas {
            node.db.execute("INSERT INTO deltas(block,key,before,after) VALUES(?,?,?,?)",
                params![BLOCK.as_slice(), key, prior, next]).unwrap();
        }
        prepare.commit().unwrap();
    }
    let operation = rusqlite::Transaction::new_unchecked(
        &node.db, rusqlite::TransactionBehavior::Immediate,
    ).unwrap();
    let mut progresses = 0_u64;
    let mut progress = || {
        progresses += 1;
        if Some(progresses) == cancel {
            Err(Error::new(crate::ErrorCode::PublicRequestCancelled))
        } else {
            Ok(())
        }
    };
    let mut error_stage = "apply";
    let mut root = None;
    let result = node.apply_delta_with_progress(BLOCK, SLOT, detach, &mut progress).and_then(|()| {
        error_stage = "slot_state";
        let state = node.slot_state_with_progress(SLOT, &mut progress)?;
        if with_root {
            error_stage = "root";
            root = Some(trnm_mvcc_fee::pon_executor::root(&state)
                .map_err(|error| Error::from(error).local_integrity())?);
        }
        Ok(())
    });
    let (code, original_error, original_kind, requires_owner_stop) = match result {
        Ok(()) => {
            operation.commit().unwrap();
            (0_u64, None, None, false)
        }
        Err(error) => {
            operation.rollback().unwrap();
            let text = error.to_string();
            let code = if error.is(crate::ErrorCode::PublicRequestCancelled) {
                80
            } else {
                assert_eq!(error.kind(), crate::ErrorKind::LocalStructure, "{error:?}");
                match text.as_str() {
                    "UNDO_ROOT" => 81,
                    "STORAGE_WRITE" => 82,
                    "STATE_BYTES" => 84,
                    "RANGE" if error_stage == "root" => 85,
                    "NONCANONICAL" if error_stage == "root" => 86,
                    _ if error_stage == "slot_state" => 83,
                    _ => panic!("Unexpected original error at {error_stage}: {error:?}"),
                }
            };
            (code, Some(text), Some(format!("{:?}", error.kind())), error.requires_owner_stop())
        }
    };
    let rows: Vec<(String, Vec<u8>)> = node.db
        .prepare("SELECT key,value FROM kv WHERE slot=? ORDER BY key").unwrap()
        .query_map([SLOT], |row| Ok((row.get(0)?, row.get(1)?))).unwrap()
        .collect::<rusqlite::Result<_>>().unwrap();
    let observed = encode_rows(&rows);
    let rollback_exact = code == 0 || observed == base_raw;
    assert!(rollback_exact, "Actual SQLite rollback did not restore the exact original rows");
    println!("HIA_TYPED_STAGE_ORACLE:{}", json!({
        "name": item["name"], "code": code, "progresses": progresses,
        "result_hex": if code == 0 { Some(hex::encode(observed)) } else { None },
        "root_hex": root.map(hex::encode),
        "error_stage": if code == 0 { None } else { Some(error_stage) },
        "original_error": original_error, "original_kind": original_kind,
        "requires_owner_stop": requires_owner_stop, "rollback_exact": rollback_exact,
    }));
}

#[test]
fn evaluate() {
    let directory = tempfile::tempdir().unwrap();
    let node = Node::open(directory.path(), Settings::development(Some(1)).unwrap(), 1).unwrap();
    assert!(matches!(node.state_backend, StateBackend::Legacy));
    let corpus = std::fs::File::open(
        std::env::var("TRNM_HIA_TYPED_STAGE_CORPUS").unwrap(),
    ).unwrap();
    for line in std::io::BufReader::new(corpus).lines() {
        let item: Value = serde_json::from_str(&line.unwrap()).unwrap();
        invoke(&node, &item);
    }
}
