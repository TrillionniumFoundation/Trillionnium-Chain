//! Fixed-width retained block fields must be bounded before owned decoding.
use super::*;
use crate::Node;
use rusqlite::types::Value as SqlValue;

const ORIGINAL_BLOCK_SQL: &str = "SELECT parent,height,chainwork,CASE WHEN typeof(packet)='blob' THEN substr(packet,1,1048577) ELSE packet END AS packet,state_root FROM blocks WHERE id=?";
const ORIGINAL_PARENT_SQL: &str = "SELECT height,chainwork FROM blocks WHERE id=?";

fn open(path: &std::path::Path) -> Node {
    let settings = Settings::development_with_profiles(
        Some(1),
        "native-public-evaluation-dev-v1",
        trnm_mvcc_fee::continuity_v1::PROFILE,
    )
    .unwrap();
    Node::open_with_authenticated_state(path, settings, 1).unwrap()
}

// Independent copy of the original complete native block verifier. Only its
// original unbounded queries differ from production; no verdict is reused.
fn original(db: &Connection, settings: &Settings, id: Hash) -> Result<NativeBlock> {
    local((|| {
        let (parent, height, work, packet, state): StoredBlockRow = db
            .prepare_cached(ORIGINAL_BLOCK_SQL)?
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
            .prepare_cached(ORIGINAL_PARENT_SQL)?
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

fn identity(value: NativeBlock) -> (Option<Hash>, u64, Hash, Option<Hash>) {
    (value.parent, value.height, value.root, value.packet_digest)
}

fn compare_error(node: &Node, id: Hash) {
    let before = original(&node.db, &node.settings, id).err().unwrap();
    let after = native_block(&node.db, &node.settings, id).err().unwrap();
    assert_eq!(after.to_string(), before.to_string());
    assert_eq!(after.kind(), before.kind());
    assert_eq!(after.requires_owner_stop(), before.requires_owner_stop());
    assert!(after.requires_owner_stop());
}

fn attack_values(width: usize) -> Vec<SqlValue> {
    vec![
        SqlValue::Null,
        SqlValue::Integer(7),
        SqlValue::Real(7.5),
        SqlValue::Text("\u{03bb}\0not-a-blob".into()),
        SqlValue::Blob(vec![]),
        SqlValue::Blob(vec![255; width - 1]),
        SqlValue::Blob(vec![255; width]),
        SqlValue::Blob(vec![255; width + 1]),
        SqlValue::Blob(vec![255; 4 * 1024 * 1024]),
    ]
}

#[test]
fn fixed_blob_projection_bounds_owned_bytes_and_preserves_sql_types() {
    let db = Connection::open_in_memory().unwrap();
    db.execute_batch("CREATE TABLE blocks(id BLOB PRIMARY KEY,parent BLOB,height INTEGER,chainwork BLOB,packet BLOB,state_root BLOB)").unwrap();
    db.execute(
        "INSERT INTO blocks VALUES(?,NULL,0,?,NULL,?)",
        params![
            [7u8; 32].as_slice(),
            [0u8; 64].as_slice(),
            [0u8; 32].as_slice()
        ],
    )
    .unwrap();
    for (column, index, width) in [
        ("parent", 0, 32),
        ("chainwork", 2, 64),
        ("state_root", 4, 32),
    ] {
        for value in attack_values(width) {
            db.execute(&format!("UPDATE blocks SET {column}=?"), [&value])
                .unwrap();
            let actual: SqlValue = db
                .prepare_cached(NATIVE_BLOCK_SQL)
                .unwrap()
                .query_row([[7u8; 32].as_slice()], |row| row.get(index))
                .unwrap();
            let expected = match &value {
                SqlValue::Blob(bytes) => {
                    SqlValue::Blob(bytes[..bytes.len().min(width + 1)].to_vec())
                }
                _ => value.clone(),
            };
            assert_eq!(actual, expected);
            if column == "chainwork" {
                let parent: SqlValue = db
                    .prepare_cached(NATIVE_PARENT_SQL)
                    .unwrap()
                    .query_row([[7u8; 32].as_slice()], |row| row.get(1))
                    .unwrap();
                assert_eq!(parent, expected);
            }
        }
    }
    // This is the actual SQL-to-owned-payload bound, not SQLite page traffic,
    // allocator peak/RSS, complete Node throughput or an adversary-cost bound.
}

#[test]
fn fixed_block_fields_match_original_errors_after_warm_cache_and_rollback() {
    let directory = tempfile::tempdir().unwrap();
    let mut node = open(directory.path());
    let genesis = node.settings.genesis();
    let packet = node
        .make_consensus_maintenance(
            genesis,
            vec![],
            crate::development_public(0).unwrap(),
            11,
            4096,
        )
        .unwrap();
    let id = node.admit(&packet, 100_000).unwrap();
    let expected = identity(original(&node.db, &node.settings, id).unwrap());
    for capacity in [0, 1, 16] {
        node.db.set_prepared_statement_cache_capacity(capacity);
        for (column, width) in [("parent", 32), ("chainwork", 64), ("state_root", 32)] {
            for value in attack_values(width) {
                if column != "parent" && value == SqlValue::Null {
                    continue;
                }
                assert_eq!(
                    identity(native_block(&node.db, &node.settings, id).unwrap()),
                    expected
                );
                node.db.execute_batch("SAVEPOINT fixed_field").unwrap();
                node.db
                    .execute(
                        &format!("UPDATE blocks SET {column}=? WHERE id=?"),
                        params![value, id.as_slice()],
                    )
                    .unwrap();
                compare_error(&node, id);
                node.db
                    .execute_batch("ROLLBACK TO fixed_field; RELEASE fixed_field")
                    .unwrap();
                assert_eq!(
                    identity(native_block(&node.db, &node.settings, id).unwrap()),
                    expected
                );
            }
        }
    }
}

#[test]
fn fixed_parent_work_matches_original_and_rereads_after_restore() {
    let directory = tempfile::tempdir().unwrap();
    let mut node = open(directory.path());
    let genesis = node.settings.genesis();
    let packet = node
        .make_consensus_maintenance(
            genesis,
            vec![],
            crate::development_public(0).unwrap(),
            11,
            4096,
        )
        .unwrap();
    let id = node.admit(&packet, 100_000).unwrap();
    let expected = identity(original(&node.db, &node.settings, id).unwrap());
    for capacity in [0, 1, 16] {
        node.db.set_prepared_statement_cache_capacity(capacity);
        for value in attack_values(64) {
            if value == SqlValue::Null {
                continue;
            }
            assert_eq!(
                identity(native_block(&node.db, &node.settings, id).unwrap()),
                expected
            );
            node.db.execute_batch("SAVEPOINT fixed_parent").unwrap();
            node.db
                .execute(
                    "UPDATE blocks SET chainwork=? WHERE id=?",
                    params![value, genesis.as_slice()],
                )
                .unwrap();
            compare_error(&node, id);
            node.db
                .execute_batch("ROLLBACK TO fixed_parent; RELEASE fixed_parent")
                .unwrap();
            assert_eq!(
                identity(native_block(&node.db, &node.settings, id).unwrap()),
                expected
            );
        }
    }
}

#[test]
fn fixed_fields_genesis_failure_order_and_cold_reopen_keep_state() {
    let directory = tempfile::tempdir().unwrap();
    let node = open(directory.path());
    let id = node.settings.genesis();
    let expected = node.read_active().unwrap();
    for (column, width) in [("parent", 32), ("chainwork", 64), ("state_root", 32)] {
        for value in attack_values(width) {
            if value == SqlValue::Null {
                continue;
            }
            node.db.execute_batch("SAVEPOINT fixed_genesis").unwrap();
            node.db
                .execute(
                    &format!("UPDATE blocks SET {column}=? WHERE id=?"),
                    params![value, id.as_slice()],
                )
                .unwrap();
            compare_error(&node, id);
            node.db
                .execute_batch("ROLLBACK TO fixed_genesis; RELEASE fixed_genesis")
                .unwrap();
            verify_history(&node.db, &node.settings, id, &mut || Ok(())).unwrap();
        }
    }
    node.db.execute_batch("SAVEPOINT multiple_damage").unwrap();
    node.db.execute("UPDATE blocks SET parent=zeroblob(4096),state_root=zeroblob(4096),chainwork=zeroblob(4096) WHERE id=?", [id.as_slice()]).unwrap();
    compare_error(&node, id);
    node.db
        .execute_batch("ROLLBACK TO multiple_damage; RELEASE multiple_damage")
        .unwrap();
    drop(node);
    let reopened = open(directory.path());
    assert_eq!(reopened.read_active().unwrap(), expected);
    verify_history(&reopened.db, &reopened.settings, id, &mut || Ok(())).unwrap();
}
